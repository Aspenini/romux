//! # `romux::xbox`
//!
//! Xbox and Xbox 360 game images built on the XDVDFS filesystem:
//!
//! * `xbox.xiso` / `xbox.disc` — original Xbox filesystem-only images and XGD1 full discs
//!   (with `default.xbe` certificate metadata);
//! * `xbox360.xiso` / `xbox360.disc` — Xbox 360 filesystem-only images and XGD2/XGD3 full
//!   discs (with `default.xex` execution metadata);
//! * `xbox360.stfs` — `CON `/`LIVE`/`PIRS` content packages; Games on Demand (SVOD) data
//!   can be listed, extracted and exported as an XISO.
//!
//! Full discs also carry a small ISO9660 video partition; the XDVDFS formats refine
//! `disc.iso9660` so they are never mistaken for generic discs. Security sectors and
//! signatures are never reproduced.

pub(crate) mod stfs;
pub(crate) mod xbe;
pub(crate) mod xdvdfs;
pub(crate) mod xex;

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, FileSource, FormatDescriptor, FormatId, IoPolicy, JobContext, NodeTable,
    OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput, PlanOutput,
    PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Result, SharedSource, SubSource, Support, TransformPlan, VerifyLevel,
    VerifyReport,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const XBOX_XISO: FormatId = FormatId("xbox.xiso");
pub const XBOX_DISC: FormatId = FormatId("xbox.disc");
pub const XBOX360_XISO: FormatId = FormatId("xbox360.xiso");
pub const XBOX360_DISC: FormatId = FormatId("xbox360.disc");
pub const XBOX360_STFS: FormatId = FormatId("xbox360.stfs");
const ISO9660: FormatId = FormatId("disc.iso9660");

/// Game-partition offset of original Xbox XGD1 full-disc images.
pub(crate) const XGD1_OFFSET: u64 = 0x1830_0000;
/// Xbox 360 game-partition offsets.
pub(crate) const X360_OFFSETS: [(u64, &str); 2] = [(0x0FD9_0000, "XGD2"), (0x0208_0000, "XGD3")];

#[derive(Default)]
pub struct XboxBackend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    let fs_ops = |d: FormatDescriptor, meta: &str| {
        d.op(Inspect, Supported, meta)
            .op(List, Supported, "XDVDFS directory trees")
            .op(Extract, Supported, "files with sanitized paths")
            .op(Verify, Supported, "volume descriptor, tree structure, extents within image; signatures not checked")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, "title updates are separate packages, not part of disc images")
    };
    vec![
        fs_ops(
            FormatDescriptor::new(XBOX_XISO, Platform::Xbox, "Xbox XISO", &["iso", "xiso"], "original Xbox filesystem-only XDVDFS image")
                .op(Probe, Supported, "MICROSOFT*XBOX*MEDIA at sector 32 with default.xbe"),
            "volume and default.xbe certificate (title ID, name, region, version)",
        )
        .op(Repack, Supported, "deterministic filesystem-only image from a directory"),
        fs_ops(
            FormatDescriptor::new(XBOX_DISC, Platform::Xbox, "Xbox full disc", &["iso"], "XGD1 full-disc image (video + game partition)")
                .op(Probe, Supported, "XDVDFS descriptor at the XGD1 game-partition offset"),
            "as XISO plus layout",
        )
        .op(Convert, Supported, "to XISO (game partition only; video partition and security data not preserved)"),
        fs_ops(
            FormatDescriptor::new(
                XBOX360_XISO,
                Platform::Xbox360,
                "Xbox 360 XISO",
                &["iso", "xiso"],
                "Xbox 360 filesystem-only XDVDFS image",
            )
            .op(Probe, Supported, "XDVDFS at sector 32 with default.xex"),
            "default.xex execution info (title ID, media ID, version, disc)",
        ),
        fs_ops(
            FormatDescriptor::new(XBOX360_DISC, Platform::Xbox360, "Xbox 360 full disc", &["iso"], "XGD2/XGD3 full-disc image").op(
                Probe,
                Supported,
                "XDVDFS descriptor at the XGD2 (0xFD90000) or XGD3 (0x2080000) game partition",
            ),
            "default.xex execution info plus layout",
        )
        .op(Convert, Supported, "to Xbox 360 XISO (game partition only)"),
        FormatDescriptor::new(
            XBOX360_STFS,
            Platform::Xbox360,
            "Xbox 360 package",
            &["", "god"],
            "CON/LIVE/PIRS package; GoD/SVOD data parts",
        )
        .op(Probe, Supported, "CON / LIVE / PIRS magic")
        .op(Inspect, Supported, "content type, title ID, media ID, version, display and title names")
        .op(List, Conditional, "Games on Demand / SVOD packages with their .data folder; plain STFS (DLC, saves) is inspect-only")
        .op(Extract, Conditional, "as list")
        .op(Verify, Conditional, "header and XDVDFS structure; SVOD hash tables and signatures not checked")
        .op(Convert, Conditional, "GoD → Xbox 360 XISO (untested against real GoD packages)"),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

/// Find the XDVDFS partition offset of an Xbox 360 full disc.
pub(crate) fn x360_offset(s: &dyn DataSource) -> Option<(u64, &'static str)> {
    X360_OFFSETS.into_iter().find(|(o, _)| xdvdfs::has_descriptor(s, *o))
}

impl Backend for XboxBackend {
    fn name(&self) -> &'static str {
        "xbox"
    }
    fn platform(&self) -> Platform {
        Platform::Xbox
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        let g = [OutputGuarantee::ContentPreserved, OutputGuarantee::LayoutNotPreserved, OutputGuarantee::ContainerValid];
        vec![
            ConversionEdge::new(
                XBOX_DISC,
                XBOX_XISO,
                ConversionKind::PartitionExport,
                Support::Supported,
                "game partition trimmed to the last used sector",
            )
            .guarantees(&g),
            ConversionEdge::new(
                XBOX360_DISC,
                XBOX360_XISO,
                ConversionKind::PartitionExport,
                Support::Supported,
                "game partition trimmed to the last used sector",
            )
            .guarantees(&g),
            ConversionEdge::new(
                XBOX360_STFS,
                XBOX360_XISO,
                ConversionKind::PartitionExport,
                Support::Conditional,
                "Games on Demand data parts reassembled; untested against real GoD packages",
            )
            .guarantees(&[
                OutputGuarantee::ContentPreserved,
                OutputGuarantee::LayoutNotPreserved,
                OutputGuarantee::CompatibilityUnverified,
            ]),
        ]
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let fs_ev = |f: FormatId, what: String| ProbeEvidence::new(f, Confidence::High).matched(what).specificity(3).refines(ISO9660);
        if xdvdfs::has_descriptor(s, 0) {
            let names = xdvdfs::root_names(s, 0);
            if names.iter().any(|n| n.eq_ignore_ascii_case("default.xex")) {
                out.push(fs_ev(XBOX360_XISO, "XDVDFS descriptor at sector 32; root holds default.xex".into()));
            } else {
                out.push(fs_ev(XBOX_XISO, "XDVDFS descriptor at sector 32".into()));
            }
        } else if xdvdfs::has_descriptor(s, XGD1_OFFSET) {
            out.push(fs_ev(XBOX_DISC, "XDVDFS descriptor at XGD1 game partition (0x18300000)".into()));
        } else if let Some((off, name)) = x360_offset(s) {
            out.push(fs_ev(XBOX360_DISC, format!("XDVDFS descriptor at {name} game partition (0x{off:x})")));
        }
        if stfs::probe(s) {
            match stfs::StfsHeader::parse(s) {
                Ok(h) => out.push(ProbeEvidence::new(XBOX360_STFS, Confidence::High).matched(format!(
                    "{} package, {} ({:08X})",
                    h.magic,
                    h.content_type_name(),
                    h.title_id
                ))),
                Err(e) => out.push(ProbeEvidence::new(XBOX360_STFS, Confidence::Low).matched("STFS magic").warn(e.to_string())),
            }
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            XBOX_XISO | XBOX360_XISO => Ok(Box::new(XisoReader::open(source, 0, format, ctx)?)),
            XBOX_DISC => Ok(Box::new(XisoReader::open(source, XGD1_OFFSET, XBOX_DISC, ctx)?)),
            XBOX360_DISC => {
                let (off, _) = x360_offset(source.as_ref()).ok_or_else(|| Error::malformed("no XGD2/XGD3 game partition found"))?;
                Ok(Box::new(XisoReader::open(source, off, XBOX360_DISC, ctx)?))
            }
            XBOX360_STFS => Ok(Box::new(StfsReader::open(source, ctx)?)),
            _ => Err(Error::unsupported(format!("xbox backend cannot open {format}"))),
        }
    }
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let mut plan = TransformPlan::new(Operation::Convert);
        plan.inputs.push(PlanInput::capture(&req.input, "source", req.from)?);
        let (data, base, to): (SharedSource, u64, FormatId) = match req.from {
            XBOX_DISC => (req.source.clone(), XGD1_OFFSET, XBOX_XISO),
            XBOX360_DISC => {
                let (off, _) = x360_offset(req.source.as_ref()).ok_or_else(|| Error::malformed("no XGD2/XGD3 game partition found"))?;
                (req.source.clone(), off, XBOX360_XISO)
            }
            XBOX360_STFS => {
                let r = StfsReader::open(req.source.clone(), &req.ctx)?;
                let (data, base) =
                    r.data.clone().ok_or_else(|| Error::unsupported("only Games on Demand / SVOD packages hold a disc filesystem"))?;
                for p in &r.data_paths {
                    plan.inputs.push(PlanInput::capture(p, "data part", XBOX360_STFS)?);
                }
                (data, base, XBOX360_XISO)
            }
            _ => return Err(Error::unsupported("undeclared conversion")),
        };
        crate::check_output_target(&req.output, &IoPolicy::default(), &plan.input_paths())
            .or_else(|e| if e.code() == crate::ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
        let fs = xdvdfs::Xdvdfs::open(data.clone(), base, &req.ctx.limits)?;
        let used = fs.used_end()?;
        let entries = fs.entries.len();
        plan.outputs.push(PlanOutput {
            path: req.output.clone(),
            format: Some(to),
            kind: "file",
            category: "filesystem-only image".into(),
            estimated_size: Some(used),
        });
        let edge = self.conversions().into_iter().find(|e| e.from == req.from).ok_or_else(|| Error::internal("edge"))?;
        plan.guarantees = edge.guarantees.clone();
        plan.warnings.push(
            "only the XDVDFS game filesystem is kept; video partitions, security sectors and package signatures are not preserved".into(),
        );
        Ok(ClosurePlan::new(
            plan,
            Box::new(move |plan, job| {
                let part = SubSource::new(data.clone(), base, used)?;
                let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(used));
                crate::copy_all(&part, &mut f, &mut p)?;
                f.flush_for_verify()?;
                let back: SharedSource = Arc::new(FileSource::open(f.temp_path())?);
                if xdvdfs::Xdvdfs::open(back, 0, &job.limits)?.entries.len() != entries {
                    return Err(Error::new(crate::ErrorCode::VerificationFailed, "exported image lists a different file set"));
                }
                let out = f.finish()?;
                let mut rep = OperationReport::new(Operation::Convert, plan.input_paths());
                rep.outputs.push(OutputRecord::from_path(&out, Some(to), &plan.guarantees)?);
                Ok(rep)
            }),
        ))
    }
}

fn fs_table(fs: &xdvdfs::Xdvdfs) -> Result<NodeTable> {
    let mut table = NodeTable::new();
    for e in &fs.entries {
        if e.is_dir {
            table.push(ContentNode::dir(0, e.path.clone()), None);
        } else {
            table.push(ContentNode::file(0, e.path.clone(), e.size as u64).span(fs.abs(e.sector), e.size as u64), Some(fs.open_file(e)?));
        }
    }
    Ok(table)
}

fn find_file(fs: &xdvdfs::Xdvdfs, name: &str) -> Option<SharedSource> {
    fs.entries.iter().find(|e| e.path.eq_ignore_ascii_case(name)).and_then(|e| fs.open_file(e).ok())
}

/// Reader for XDVDFS images (original Xbox and Xbox 360, filesystem-only or full disc).
pub(crate) struct XisoReader {
    format: FormatId,
    source: SharedSource,
    pub fs: xdvdfs::Xdvdfs,
    table: NodeTable,
    xbe: Option<xbe::XbeInfo>,
    xex: Option<xex::XexInfo>,
}

impl XisoReader {
    pub fn open(source: SharedSource, base: u64, format: FormatId, ctx: &OpenContext) -> Result<Self> {
        let fs = xdvdfs::Xdvdfs::open(source.clone(), base, &ctx.limits)?;
        let table = fs_table(&fs)?;
        let xbe = find_file(&fs, "default.xbe").and_then(|s| xbe::XbeInfo::parse(s.as_ref()).ok());
        let xex = find_file(&fs, "default.xex").and_then(|s| xex::XexInfo::parse(s.as_ref()).ok());
        Ok(XisoReader { format, source, fs, table, xbe, xex })
    }
}

fn xex_fields(i: &mut PackageInfo, x: &xex::XexInfo) {
    i.title_id = Some(format!("{:08X}", x.title_id));
    i.product_code = Some(x.product_code());
    i.version = Some(x.version_string());
    i.family_id = i.title_id.clone();
    i.field("media_id", format!("{:08X}", x.media_id));
    i.field("disc", format!("{} of {}", x.disc_number, x.disc_count));
}

impl PackageReader for XisoReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let x360 = matches!(self.format, XBOX360_XISO | XBOX360_DISC);
        let mut i = PackageInfo::new(self.format, if x360 { Platform::Xbox360 } else { Platform::Xbox }, self.source.len()?);
        i.category = ContentCategory::DiscImage;
        i.field("partition_offset", self.fs.base);
        i.field("files", self.fs.entries.iter().filter(|e| !e.is_dir).count() as u64);
        if let Some(x) = &self.xbe {
            i.title = Some(x.title_name.clone()).filter(|s| !s.is_empty());
            i.title_id = Some(format!("{:08X}", x.title_id));
            i.product_code = Some(x.product_code());
            i.region = Some(x.region_names().join(", "));
            i.version = Some(format!("{}", x.version));
            i.family_id = i.title_id.clone();
        } else if let Some(x) = &self.xex {
            xex_fields(&mut i, x);
            i.limitations.push("Xbox 360 title names live in encrypted XEX resources and are not read".into());
        } else {
            i.warnings
                .push(format!("{} not found or unreadable; title identity unknown", if x360 { "default.xex" } else { "default.xbe" }));
        }
        if matches!(self.format, XBOX_DISC | XBOX360_DISC) {
            i.limitations.push("video partition and security data are outside the game filesystem".into());
        }
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(self.format, level);
        r.pass(CheckLevel::Structure, "volume descriptor", Some("both magic copies present".into()));
        r.pass(CheckLevel::Structure, "directory trees", Some(format!("{} entries, no loops", self.fs.entries.len())));
        for w in &self.fs.warnings {
            r.warn(CheckLevel::Structure, "filesystem", w.clone());
        }
        if level.wants_content() {
            r.skip(CheckLevel::Content, "content hashes", "XDVDFS declares no content hashes");
        }
        r.authenticity_unavailable("XBE/XEX signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(self.format))
    }
}

/// Reader for Xbox 360 STFS/SVOD packages.
pub(crate) struct StfsReader {
    source: SharedSource,
    pub header: stfs::StfsHeader,
    /// Logical SVOD data stream and XDVDFS base, when present.
    pub data: Option<(SharedSource, u64)>,
    pub data_paths: Vec<PathBuf>,
    fs: Option<xdvdfs::Xdvdfs>,
    table: NodeTable,
    problem: Option<String>,
}

impl StfsReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let header = stfs::StfsHeader::parse(source.as_ref())?;
        let mut r =
            StfsReader { source: source.clone(), header, data: None, data_paths: vec![], fs: None, table: NodeTable::new(), problem: None };
        if !r.header.is_svod() {
            r.problem = Some("plain STFS filesystems (DLC, saves, title updates) are inspect-only".into());
            return Ok(r);
        }
        let Some(path) = source.identity().path else {
            r.problem = Some("SVOD data parts can only be located when the header is opened from a file".into());
            return Ok(r);
        };
        match stfs::SvodSource::open_for_header(&path, r.header.data_file_count) {
            Ok((svod, paths)) => {
                let svod: SharedSource = Arc::new(svod);
                let base = [0u64, X360_OFFSETS[0].0, X360_OFFSETS[1].0].into_iter().find(|b| xdvdfs::has_descriptor(svod.as_ref(), *b));
                match base {
                    Some(b) => {
                        let fs = xdvdfs::Xdvdfs::open(svod.clone(), b, &ctx.limits)?;
                        r.table = fs_table(&fs)?;
                        r.fs = Some(fs);
                        r.data = Some((svod, b));
                        r.data_paths = paths;
                    }
                    None => r.problem = Some("no XDVDFS filesystem found in the SVOD data".into()),
                }
            }
            Err(e) => r.problem = Some(e.to_string()),
        }
        Ok(r)
    }
}

impl PackageReader for StfsReader {
    fn format(&self) -> FormatId {
        XBOX360_STFS
    }
    fn info(&self) -> Result<PackageInfo> {
        let h = &self.header;
        let mut i = PackageInfo::new(XBOX360_STFS, Platform::Xbox360, self.source.len()?);
        i.title = Some(if h.title_name.is_empty() { h.display_name.clone() } else { h.title_name.clone() }).filter(|s| !s.is_empty());
        i.title_id = Some(format!("{:08X}", h.title_id));
        i.family_id = i.title_id.clone();
        i.version = Some(h.version.to_string());
        i.category = match h.content_type {
            0x7000 | 0x4000 | 0xD0000 | 0x2000 => ContentCategory::Application,
            0x2 => ContentCategory::AddOn,
            0xB0000 => ContentCategory::Patch,
            _ => ContentCategory::Data,
        };
        i.field("package", h.magic.clone());
        i.field("content_type", h.content_type_name());
        i.field("descriptor", if h.is_svod() { "SVOD" } else { "STFS" });
        i.field("media_id", format!("{:08X}", h.media_id));
        if !h.display_name.is_empty() {
            i.field("display_name", h.display_name.clone());
        }
        if !h.publisher.is_empty() {
            i.field("publisher", h.publisher.clone());
        }
        if h.is_svod() {
            i.field("data_files", h.data_file_count);
            i.sizes.payload = Some(h.data_file_size);
        }
        if let Some(p) = &self.problem {
            i.limitations.push(p.clone());
        }
        i.limitations.push("package signatures and SVOD hash tables are not verified".into());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(XBOX360_STFS, level);
        r.pass(CheckLevel::Structure, "package header", Some(format!("{} {}", self.header.magic, self.header.content_type_name())));
        match &self.fs {
            Some(fs) => r.pass(CheckLevel::Structure, "XDVDFS in SVOD data", Some(format!("{} entries", fs.entries.len()))),
            None => r.skip(CheckLevel::Structure, "filesystem", self.problem.clone().unwrap_or_default()),
        }
        if level.wants_content() {
            r.not_checked(CheckLevel::Content, "SVOD hash tables", "hash tables are not verified by Romux");
        }
        r.authenticity_unavailable("package RSA signature");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = caps(XBOX360_STFS);
        if self.fs.is_none() {
            let why = self.problem.clone().unwrap_or_default();
            c.block(Operation::List, &why);
            c.block(Operation::Extract, &why);
            c.block(Operation::Convert, &why);
        }
        Ok(c)
    }
}

/// Plan building a filesystem-only XISO from a directory.
pub fn plan_repack_xiso(dir: &Path, output: &Path, policy: &IoPolicy) -> Result<Box<dyn PlannedOperation>> {
    if !dir.is_dir() {
        return Err(Error::invalid_arg(format!("{} is not a directory", dir.display())));
    }
    crate::check_output_target(output, policy, &[])?;
    let mut plan = TransformPlan::new(Operation::Repack);
    plan.outputs.push(PlanOutput {
        path: output.to_path_buf(),
        format: Some(XBOX_XISO),
        kind: "file",
        category: "filesystem-only image".into(),
        estimated_size: None,
    });
    plan.guarantees = vec![
        OutputGuarantee::ContainerValid,
        OutputGuarantee::ContentPreserved,
        OutputGuarantee::NotAuthentic,
        OutputGuarantee::CompatibilityUnverified,
    ];
    let dir = dir.to_path_buf();
    Ok(ClosurePlan::new(
        plan,
        Box::new(move |plan, job| {
            let mut b = xdvdfs::XisoBuilder::new();
            b.add_dir_tree(&dir)?;
            let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &[])?;
            let n = b.write(&mut f, job)?;
            f.flush_for_verify()?;
            let back: SharedSource = Arc::new(FileSource::open(f.temp_path())?);
            let fs = xdvdfs::Xdvdfs::open(back, 0, &job.limits)?;
            if fs.entries.iter().filter(|e| !e.is_dir).count() != n {
                return Err(Error::new(crate::ErrorCode::VerificationFailed, "rebuilt XISO lists a different file count"));
            }
            let out = f.finish()?;
            let mut rep = OperationReport::new(Operation::Repack, vec![]);
            rep.outputs.push(OutputRecord::from_path(&out, Some(XBOX_XISO), &plan.guarantees)?);
            Ok(rep)
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, Registry};

    #[test]
    fn build_read_and_export() {
        let mut b = xdvdfs::XisoBuilder::new();
        let xbe = xbe::testkit::build(0x4D530001, "Test Title");
        b.add_file("default.xbe", Arc::new(MemorySource::new(xbe))).unwrap();
        for i in 0..40 {
            b.add_file(&format!("media/file{i:02}.bin"), Arc::new(MemorySource::new(vec![i as u8; 3000 + i]))).unwrap();
        }
        b.add_file("Media/Sub/deep.txt", Arc::new(MemorySource::new(b"deep".to_vec()))).unwrap_err();
        b.add_file("media/sub/deep.txt", Arc::new(MemorySource::new(b"deep".to_vec()))).unwrap();
        let mut img = std::io::Cursor::new(Vec::new());
        assert_eq!(b.write(&mut img, &JobContext::default()).unwrap(), 42);
        let img = img.into_inner();
        let reg = Registry::new().with(XboxBackend);
        let src: SharedSource = Arc::new(MemorySource::new(img.clone()));
        assert_eq!(reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap().format, Some(XBOX_XISO));
        let r = reg.open(src, &OpenContext::default()).unwrap();
        let info = r.info().unwrap();
        assert_eq!(info.title.as_deref(), Some("Test Title"));
        assert_eq!(info.title_id.as_deref(), Some("4D530001"));
        let n = r.entries().unwrap().map(|n| n.unwrap()).find(|n| n.path == "media/file17.bin").unwrap();
        assert_eq!(crate::read_vec(r.open_entry(n.id).unwrap().as_ref(), 0, 3017, 4000).unwrap(), vec![17u8; 3017]);
        // Wrap as a full-disc image and confirm the XGD1 offset is recognised.
        let mut disc = vec![0u8; XGD1_OFFSET as usize];
        disc.extend_from_slice(&img);
        let ds: SharedSource = Arc::new(MemorySource::new(disc));
        assert_eq!(reg.probe(ds.as_ref(), &ProbeLimits::default()).unwrap().format, Some(XBOX_DISC));
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::xbox::stfs::layout_parts as svod_parts;
    pub use crate::xbox::xbe::testkit::build as xbe;
    pub use crate::xbox::xdvdfs::XisoBuilder;
    pub use crate::xbox::xex::testkit::build as xex;
}
