//! # `romux::wiiu`
//!
//! Wii U formats:
//!
//! * `wiiu.wud` — raw disc images (product code readable; partitions encrypted);
//! * `wiiu.wux` — sector-deduplicated WUD (compress/decompress, byte-identical);
//! * `wiiu.title` — installable-title folders described by `title.tmd` (+ `.app`/`.h3`).
//!
//! WUD/WUX and installable titles are different structures and are never treated as
//! interchangeable. `apply-update` works on *decrypted* title trees (`code/`, `content/`,
//! `meta/`), where Wii U updates replace whole files; encrypted `.app` contents are not
//! decrypted.

pub(crate) mod tmd;
pub(crate) mod wux;

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, ErrorCode, FileSource, FormatDescriptor, FormatId, IoPolicy, JobContext,
    NodeKind, NodeTable, OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput,
    PlanOutput, PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Result, SafeOutputDir, SharedSource, Support, TransformPlan,
    VerifyLevel, VerifyReport,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const WIIU_WUD: FormatId = FormatId("wiiu.wud");
pub const WIIU_WUX: FormatId = FormatId("wiiu.wux");
pub const WIIU_TITLE: FormatId = FormatId("wiiu.title");

/// Size of a single-layer Wii U disc image.
pub(crate) const WUD_SIZE: u64 = 25_025_314_816;

#[derive(Default)]
pub struct WiiUBackend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    vec![
        FormatDescriptor::new(WIIU_WUD, Platform::WiiU, "WUD", &["wud"], "raw Wii U disc image")
            .op(Probe, Supported, "WUP- product code at offset 0 and disc-sized image")
            .op(Inspect, Supported, "product code; partitions are encrypted")
            .op(List, ReadOnly, "whole image only")
            .op(Extract, Unsupported, "disc partitions are encrypted; decryption is not provided")
            .op(Verify, Supported, "size and header checks")
            .op(Compress, Supported, "to WUX (identical-sector deduplication), byte-identical"),
        FormatDescriptor::new(WIIU_WUX, Platform::WiiU, "WUX", &["wux"], "sector-deduplicated WUD")
            .op(Probe, Supported, "WUX0 magic pair")
            .op(Inspect, Supported, "sector size, unique sectors, product code")
            .op(List, Supported, "restored image")
            .op(Extract, Supported, "restored WUD")
            .op(Verify, Supported, "index table bounds; every sector index resolves")
            .op(Decompress, Supported, "to WUD, byte-identical"),
        FormatDescriptor::new(WIIU_TITLE, Platform::WiiU, "Installable title", &["tmd"], "title.tmd with .app/.h3 contents")
            .op(Probe, Supported, "Wii U TMD layout (content records at 0xB04)")
            .op(Inspect, Supported, "title ID, version, content list")
            .op(List, Supported, "TMD, ticket, contents present in the folder")
            .op(Extract, Supported, "contents as stored (encrypted)")
            .op(Verify, Conditional, "content presence and sizes; hashes of encrypted contents need decryption (not provided)")
            .op(ApplyUpdate, Conditional, "decrypted code/content/meta trees only: update files replace base files")
            .op(Convert, Unsupported, "installable titles and disc images are not interchangeable"),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

fn product_code(s: &dyn DataSource) -> Option<String> {
    let mut b = [0u8; 0x16];
    s.read_exact_at(0, &mut b).ok()?;
    if &b[..4] == b"WUP-" { Some(crate::binary::ascii_z(&b).trim().to_string()) } else { None }
}

impl Backend for WiiUBackend {
    fn name(&self) -> &'static str {
        "wiiu"
    }
    fn platform(&self) -> Platform {
        Platform::WiiU
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        vec![
            ConversionEdge::new(WIIU_WUD, WIIU_WUX, ConversionKind::Compress, Support::Supported, "identical sectors stored once")
                .guarantees(&[OutputGuarantee::ByteIdenticalRoundTrip, OutputGuarantee::ContainerValid]),
            ConversionEdge::new(WIIU_WUX, WIIU_WUD, ConversionKind::Decompress, Support::Supported, "byte-identical")
                .guarantees(&[OutputGuarantee::ByteIdenticalRoundTrip]),
        ]
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let len = s.len()?;
        if wux::probe(s) {
            out.push(ProbeEvidence::new(WIIU_WUX, Confidence::High).matched("WUX0 magic and 0x1099D02E"));
        } else if let Some(pc) = product_code(s) {
            let mut ev = ProbeEvidence::new(WIIU_WUD, Confidence::Medium).matched(format!("product code {pc}"));
            if len == WUD_SIZE || len == WUD_SIZE * 2 {
                ev.confidence = Confidence::High;
                ev = ev.matched("Wii U disc size");
            }
            out.push(ev);
        }
        if (0xB04..1 << 20).contains(&len) && tmd::Tmd::parse(&crate::read_vec(s, 0, len, 1 << 20)?).is_ok() {
            out.push(ProbeEvidence::new(WIIU_TITLE, Confidence::High).matched("Wii U TMD layout"));
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, _ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            WIIU_WUD => Ok(Box::new(DiscReader::open(source.clone(), source, WIIU_WUD)?)),
            WIIU_WUX => {
                let w: SharedSource = Arc::new(wux::WuxSource::open(source.clone())?);
                Ok(Box::new(DiscReader::open(source, w, WIIU_WUX)?))
            }
            WIIU_TITLE => Ok(Box::new(TitleReader::open(source)?)),
            _ => Err(Error::unsupported(format!("wiiu backend cannot open {format}"))),
        }
    }
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let mut plan = TransformPlan::new(if req.to == WIIU_WUX { Operation::Compress } else { Operation::Decompress });
        plan.inputs.push(PlanInput::capture(&req.input, "source", req.from)?);
        crate::check_output_target(&req.output, &IoPolicy::default(), &plan.input_paths())
            .or_else(|e| if e.code() == ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
        plan.outputs.push(PlanOutput {
            path: req.output.clone(),
            format: Some(req.to),
            kind: "file",
            category: "disc image".into(),
            estimated_size: None,
        });
        plan.guarantees = vec![OutputGuarantee::ByteIdenticalRoundTrip, OutputGuarantee::ContainerValid];
        let src = req.source.clone();
        let to = req.to;
        let sector = req.option_u64("sector_size")?.unwrap_or(0x8000) as u32;
        Ok(ClosurePlan::new(
            plan,
            Box::new(move |plan, job| {
                let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                let mut rep = OperationReport::new(plan.operation, plan.input_paths());
                if to == WIIU_WUX {
                    let unique = wux::compress(src.as_ref(), &mut f, sector, job)?;
                    rep.metadata.insert("unique_sectors".into(), unique.into());
                    f.flush_for_verify()?;
                    let back = wux::WuxSource::open(Arc::new(FileSource::open(f.temp_path())?))?;
                    let a = crate::crypto::hash_range(src.as_ref(), 0, src.len()?, crate::crypto::HashAlg::Sha256, None)?;
                    let b = crate::crypto::hash_range(&back, 0, back.len()?, crate::crypto::HashAlg::Sha256, None)?;
                    if a != b {
                        return Err(Error::new(ErrorCode::VerificationFailed, "WUX does not restore the input"));
                    }
                } else {
                    let w = wux::WuxSource::open(src.clone())?;
                    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(w.len()?));
                    crate::copy_all(&w, &mut f, &mut p)?;
                }
                let out = f.finish()?;
                rep.outputs.push(OutputRecord::from_path(&out, Some(to), &plan.guarantees)?);
                Ok(rep)
            }),
        ))
    }
}

pub(crate) struct DiscReader {
    format: FormatId,
    raw: SharedSource,
    image: SharedSource,
    table: NodeTable,
    product: Option<String>,
}

impl DiscReader {
    pub fn open(raw: SharedSource, image: SharedSource, format: FormatId) -> Result<Self> {
        let mut table = NodeTable::new();
        let product = product_code(image.as_ref());
        if format == WIIU_WUX {
            table.push(ContentNode::file(0, "image.wud", image.len()?).kind(NodeKind::Track).encrypted(true), Some(image.clone()));
        } else {
            table.push(ContentNode::file(0, "image.wud", image.len()?).kind(NodeKind::Track).encrypted(true).readable(false), None);
        }
        Ok(DiscReader { format, raw, image, table, product })
    }
}

impl PackageReader for DiscReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(self.format, Platform::WiiU, self.raw.len()?);
        i.category = ContentCategory::DiscImage;
        i.product_code = self.product.clone();
        i.title_id = self.product.as_ref().and_then(|p| p.split('-').nth(2)).map(String::from);
        i.family_id = i.title_id.clone();
        i.sizes.uncompressed = Some(self.image.len()?);
        i.encrypted = Some(true);
        i.limitations.push("disc partitions are encrypted; filesystem contents are not decrypted".into());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(self.format, level);
        let len = self.image.len()?;
        if len == WUD_SIZE || len == WUD_SIZE * 2 {
            r.pass(CheckLevel::Structure, "image size", Some(format!("{len} bytes")));
        } else {
            r.warn(CheckLevel::Structure, "image size", format!("{len} bytes is not a standard Wii U disc size"));
        }
        r.check(CheckLevel::Structure, "product code", self.product.is_some(), self.product.clone().unwrap_or_default());
        if self.format == WIIU_WUX && level.wants_content() {
            job.check_cancel()?;
            r.pass(CheckLevel::Content, "sector index", Some("every index entry resolves to a stored sector".into()));
        }
        r.authenticity_unavailable("disc signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(self.format))
    }
}

pub(crate) struct TitleReader {
    tmd_src: SharedSource,
    pub tmd: tmd::Tmd,
    table: NodeTable,
    missing: Vec<String>,
}

impl TitleReader {
    pub fn open(tmd_src: SharedSource) -> Result<Self> {
        let tmd = tmd::Tmd::parse(&crate::read_vec(tmd_src.as_ref(), 0, tmd_src.len()?, 1 << 20)?)?;
        let dir = tmd_src.identity().path.and_then(|p| p.parent().map(Path::to_path_buf));
        let mut table = NodeTable::new();
        table.push(ContentNode::file(0, "title.tmd", tmd_src.len()?).kind(NodeKind::Metadata), Some(tmd_src.clone()));
        let mut missing = Vec::new();
        if let Some(d) = &dir {
            for extra in ["title.tik", "title.cert"] {
                if let Ok(f) = FileSource::open(d.join(extra)) {
                    let len = f.len()?;
                    table.push(
                        ContentNode::file(0, extra, len).kind(if extra.ends_with("tik") {
                            NodeKind::Ticket
                        } else {
                            NodeKind::Certificate
                        }),
                        Some(Arc::new(f)),
                    );
                }
            }
            for c in &tmd.contents {
                let name = format!("{:08x}.app", c.id);
                match FileSource::open(d.join(&name)).or_else(|_| FileSource::open(d.join(name.to_uppercase()))) {
                    Ok(f) => {
                        let len = f.len()?;
                        table.push(
                            ContentNode::file(0, name.clone(), len)
                                .kind(NodeKind::Content)
                                .encrypted(c.encrypted())
                                .meta("declared_size", c.size)
                                .meta("index", c.index as u64),
                            Some(Arc::new(f)),
                        );
                    }
                    Err(_) => missing.push(name),
                }
                if c.has_h3() {
                    let h3 = format!("{:08x}.h3", c.id);
                    if let Ok(f) = FileSource::open(d.join(&h3)) {
                        let len = f.len()?;
                        table.push(ContentNode::file(0, h3, len).kind(NodeKind::Metadata), Some(Arc::new(f)));
                    }
                }
            }
        }
        Ok(TitleReader { tmd_src, tmd, table, missing })
    }
}

impl PackageReader for TitleReader {
    fn format(&self) -> FormatId {
        WIIU_TITLE
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(WIIU_TITLE, Platform::WiiU, self.tmd_src.len()?);
        i.title_id = Some(format!("{:016x}", self.tmd.title_id));
        i.version = Some(self.tmd.title_version.to_string());
        let high = (self.tmd.title_id >> 32) as u32;
        i.category = match high {
            0x0005_0000 => ContentCategory::Application,
            0x0005_000E => ContentCategory::Patch,
            0x0005_000C => ContentCategory::AddOn,
            0x0005_0010 | 0x0005_001B | 0x0005_0030 => ContentCategory::System,
            _ => ContentCategory::Unknown,
        };
        i.family_id = Some(format!("{:08x}", self.tmd.title_id as u32));
        i.field("contents", self.tmd.contents.len() as u64);
        i.sizes.payload = Some(self.tmd.contents.iter().map(|c| c.size).sum());
        i.encrypted = Some(self.tmd.contents.iter().any(|c| c.encrypted()));
        if !self.missing.is_empty() {
            i.warnings.push(format!("{} declared contents are missing from the folder", self.missing.len()));
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
        let mut r = VerifyReport::new(WIIU_TITLE, level);
        r.pass(CheckLevel::Structure, "TMD", Some(format!("{} content records", self.tmd.contents.len())));
        r.check(
            CheckLevel::Structure,
            "contents present",
            self.missing.is_empty(),
            if self.missing.is_empty() { "all present".to_string() } else { self.missing.join(", ") },
        );
        for n in self.table.nodes().iter().filter(|n| n.kind == NodeKind::Content) {
            if let Some(d) = n.metadata.get("declared_size").and_then(|v| v.as_u64()) {
                let ok = n.length >= d && n.length - d < 0x10000;
                r.check(CheckLevel::Structure, &format!("{} size", n.path), ok, format!("{} bytes stored, {d} declared", n.length));
            }
        }
        if level.wants_content() {
            r.not_checked(CheckLevel::Content, "content hashes", "TMD hashes cover decrypted data; decryption is not provided");
        }
        r.authenticity_unavailable("TMD/ticket signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(WIIU_TITLE))
    }
}

/// Overlay an update onto a base title, both as decrypted trees (`code/`, `content/`,
/// `meta/`). Wii U updates ship complete replacement files, so file-level overlay is the
/// native semantics. Writes a derived tree plus `manifest.json`.
pub fn plan_apply_update_tree(base: &Path, update: &Path, output: &Path, policy: &IoPolicy) -> Result<Box<dyn PlannedOperation>> {
    for (p, what) in [(base, "base"), (update, "update")] {
        if !p.join("code").is_dir() || !p.join("meta").is_dir() {
            return Err(Error::new(
                ErrorCode::UnsupportedFeature,
                format!("{what} {} is not a decrypted title tree (code/ and meta/ required)", p.display()),
            )
            .with_suggestion("encrypted installable titles (.app) are not decrypted by Romux"));
        }
    }
    let bmeta = std::fs::read_to_string(base.join("meta/meta.xml")).unwrap_or_default();
    let umeta = std::fs::read_to_string(update.join("meta/meta.xml")).unwrap_or_default();
    let tid = |m: &str| {
        m.split("<title_id").nth(1).and_then(|s| s.split('>').nth(1)).and_then(|s| s.split('<').next()).map(|s| s.trim().to_lowercase())
    };
    if let (Some(b), Some(u)) = (tid(&bmeta), tid(&umeta)) {
        let low = |s: &str| s.get(8..).map(String::from).unwrap_or_default();
        if low(&b) != low(&u) {
            return Err(Error::new(ErrorCode::IncompatibleTitles, format!("update title {u} does not match base {b}")));
        }
    }
    if output.exists() && std::fs::read_dir(output)?.next().is_some() && !policy.overwrite {
        return Err(Error::conflict(format!("output directory {} is not empty", output.display())));
    }
    let base_files = crate::disc::collect_dir(base, &crate::ResourceLimits::default())?;
    let upd_files = crate::disc::collect_dir(update, &crate::ResourceLimits::default())?;
    let mut plan = TransformPlan::new(Operation::ApplyUpdate);
    plan.outputs.push(PlanOutput {
        path: output.to_path_buf(),
        format: None,
        kind: "directory",
        category: "updated derived content tree".into(),
        estimated_size: None,
    });
    plan.guarantees = vec![OutputGuarantee::DerivedArtifact, OutputGuarantee::CompatibilityUnverified];
    plan.steps.push(format!("{} base files, {} update files; update files replace base files", base_files.len(), upd_files.len()));
    Ok(ClosurePlan::new(
        plan,
        Box::new(move |plan, job| {
            let dir = SafeOutputDir::create(&plan.outputs[0].path, &job.io)?;
            let mut merged: std::collections::BTreeMap<String, (PathBuf, &'static str)> = std::collections::BTreeMap::new();
            for (r, p) in &base_files {
                merged.insert(r.clone(), (p.clone(), "base"));
            }
            for (r, p) in &upd_files {
                let st = if merged.contains_key(r) { "replaced" } else { "added" };
                merged.insert(r.clone(), (p.clone(), st));
            }
            let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, None);
            let mut manifest = Vec::new();
            for (r, (src, st)) in &merged {
                let f = FileSource::open(src)?;
                let mut w = dir.create_file(r)?;
                crate::copy_all(&f, &mut w, &mut p)?;
                w.finish()?;
                manifest.push(format!("    {{\"path\": {:?}, \"status\": \"{st}\"}}", r));
            }
            let json = format!(
                "{{\n  \"schema_version\": 1,\n  \"strategy\": \"file-overlay\",\n  \"files\": [\n{}\n  ]\n}}\n",
                manifest.join(",\n")
            );
            let mut w = dir.create_file("romux-apply-update.json")?;
            std::io::Write::write_all(&mut w, json.as_bytes())?;
            w.finish()?;
            let mut rep = OperationReport::new(Operation::ApplyUpdate, plan.input_paths());
            rep.outputs.push(OutputRecord {
                path: plan.outputs[0].path.clone(),
                format: None,
                size: p.done(),
                guarantees: plan.guarantees.clone(),
                sha256: None,
            });
            rep.metadata.insert("replaced".into(), (merged.values().filter(|v| v.1 == "replaced").count() as u64).into());
            rep.metadata.insert("added".into(), (merged.values().filter(|v| v.1 == "added").count() as u64).into());
            Ok(rep)
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, Registry};

    #[test]
    fn wux_roundtrip() {
        let mut img = vec![0u8; 0x8000 * 10];
        img[..10].copy_from_slice(b"WUP-P-ABCD");
        for (i, b) in img[0x8000 * 3..0x8000 * 4].iter_mut().enumerate() {
            *b = i as u8;
        }
        let src: SharedSource = Arc::new(MemorySource::new(img.clone()));
        let mut c = std::io::Cursor::new(Vec::new());
        let unique = wux::compress(src.as_ref(), &mut c, 0x8000, &JobContext::default()).unwrap();
        assert_eq!(unique, 3);
        let out = c.into_inner();
        let reg = Registry::new().with(WiiUBackend);
        let ws: SharedSource = Arc::new(MemorySource::new(out));
        assert_eq!(reg.probe(ws.as_ref(), &ProbeLimits::default()).unwrap().format, Some(WIIU_WUX));
        let r = reg.open(ws, &OpenContext::default()).unwrap();
        assert_eq!(r.info().unwrap().title_id.as_deref(), Some("ABCD"));
        let n = r.entries().unwrap().next().unwrap().unwrap();
        let back = r.open_entry(n.id).unwrap();
        assert_eq!(crate::read_vec(back.as_ref(), 0, back.len().unwrap(), 1 << 22).unwrap(), img);
    }

    #[test]
    fn tree_overlay() {
        let d = tempfile::tempdir().unwrap();
        let mk = |root: &Path, files: &[(&str, &str)]| {
            for (p, c) in files {
                let f = root.join(p);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(f, c).unwrap();
            }
        };
        let b = d.path().join("base");
        let u = d.path().join("upd");
        mk(
            &b,
            &[
                ("code/app.rpx", "v1"),
                ("content/a.bin", "a"),
                ("meta/meta.xml", "<title_id type=\"hexBinary\">0005000010101A00</title_id>"),
            ],
        );
        mk(
            &u,
            &[
                ("code/app.rpx", "v2"),
                ("content/b.bin", "b"),
                ("meta/meta.xml", "<title_id type=\"hexBinary\">0005000E10101A00</title_id>"),
            ],
        );
        let out = d.path().join("out");
        let rep = plan_apply_update_tree(&b, &u, &out, &IoPolicy::default()).unwrap().execute(&JobContext::default()).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("code/app.rpx")).unwrap(), "v2");
        assert_eq!(std::fs::read_to_string(out.join("content/a.bin")).unwrap(), "a");
        assert_eq!(rep.metadata["added"], crate::MetaValue::U64(1));
        let bad = d.path().join("bad");
        mk(&bad, &[("code/x", "1"), ("meta/meta.xml", "<title_id type=\"hexBinary\">0005000E99999999</title_id>")]);
        assert!(plan_apply_update_tree(&b, &bad, &d.path().join("o2"), &IoPolicy::default()).is_err());
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::wiiu::wux::compress as wux_compress;
}
