//! # `romux::psp`
//!
//! PSP formats: UMD ISO images (ISO9660 + `PSP_GAME`), CSO (CISO v1, deflate) compressed
//! images, and `EBOOT.PBP` containers. `DATA.PSP` executables inside PBPs are often
//! encrypted (`~PSP`) and are reported, not decrypted.

pub(crate) mod cso;
pub(crate) mod pbp;

/// Build an `EBOOT.PBP` from its eight sections (in [`PBP_SECTIONS`] order; empty for absent).
pub use pbp::{SECTIONS as PBP_SECTIONS, write as write_pbp};

pub mod sfo {
    pub use crate::binary::psf::{Psf, PsfValue};
}

use crate::disc::iso9660::IsoFs;
use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, FormatDescriptor, FormatId, JobContext, NodeKind, NodeTable, OpenContext,
    Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput, PlanOutput, PlannedOperation,
    Platform, ProbeEvidence, ProbeLimits, Result, SharedSource, Support, TransformPlan, VerifyLevel, VerifyReport,
};
use std::sync::Arc;

pub const PSP_ISO: FormatId = FormatId("psp.iso");
pub const PSP_CSO: FormatId = FormatId("psp.cso");
pub const PSP_PBP: FormatId = FormatId("psp.pbp");
pub const PSP_SFO: FormatId = FormatId("psp.sfo");

#[derive(Default)]
pub struct PspBackend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    vec![
        FormatDescriptor::new(PSP_ISO, Platform::Psp, "PSP UMD ISO", &["iso"], "ISO9660 image with PSP_GAME / UMD_DATA.BIN")
            .op(Probe, Supported, "ISO9660 plus PSP_GAME/PARAM.SFO or UMD_DATA.BIN")
            .op(Inspect, Supported, "PARAM.SFO and UMD_DATA.BIN metadata")
            .op(List, Supported, "filesystem")
            .op(Extract, Supported, "filesystem files (EBOOT.BIN stays encrypted when encrypted)")
            .op(Verify, Supported, "ISO9660 structure")
            .op(Compress, Supported, "to CSO v1 (deflate), byte-identical")
            .op(Convert, Supported, "to CSO")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, "PSP updates are encrypted EBOOT replacements"),
        FormatDescriptor::new(PSP_CSO, Platform::Psp, "CSO", &["cso"], "CISO v1 block-compressed image")
            .op(Probe, Supported, "CISO magic, version 1, index table bounds")
            .op(Inspect, Supported, "block size, compression ratio, inner image")
            .op(List, Supported, "decompressed image and its filesystem")
            .op(Extract, Supported, "filesystem files")
            .op(Verify, Supported, "index monotonicity, every block decodes to its size")
            .op(Decompress, Supported, "to ISO, byte-identical"),
        FormatDescriptor::new(PSP_PBP, Platform::Psp, "PBP", &["pbp"], "EBOOT.PBP section container")
            .op(Probe, Supported, "\\0PBP magic with ordered section offsets")
            .op(Inspect, Supported, "PARAM.SFO and section sizes")
            .op(List, Supported, "eight sections")
            .op(Extract, Supported, "sections as stored (DATA.PSP may be encrypted)")
            .op(Verify, Supported, "section table ordering and bounds")
            .op(Repack, Supported, "build a PBP from section files (library API: romux::psp::write_pbp)"),
        FormatDescriptor::new(PSP_SFO, Platform::Psp, "PSP PARAM.SFO", &["sfo"], "PSF table with PSP keys")
            .op(Probe, Supported, "PSF with PSP keys")
            .op(Inspect, Supported, "")
            .op(List, Supported, "")
            .op(Verify, Supported, ""),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

fn is_psp_fs(fs: &IsoFs) -> bool {
    fs.find("PSP_GAME/PARAM.SFO").is_some() || fs.find("UMD_DATA.BIN").is_some()
}

impl Backend for PspBackend {
    fn name(&self) -> &'static str {
        "psp"
    }
    fn platform(&self) -> Platform {
        Platform::Psp
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        vec![
            ConversionEdge::new(PSP_ISO, PSP_CSO, ConversionKind::Compress, Support::Supported, "CSO v1, raw deflate per 2048-byte block")
                .guarantees(&[OutputGuarantee::ByteIdenticalRoundTrip, OutputGuarantee::ContainerValid]),
            ConversionEdge::new(crate::disc::ISO9660, PSP_CSO, ConversionKind::Compress, Support::Supported, "any 2048-sector ISO")
                .guarantees(&[OutputGuarantee::ByteIdenticalRoundTrip, OutputGuarantee::ContainerValid]),
            ConversionEdge::new(PSP_CSO, PSP_ISO, ConversionKind::Decompress, Support::Supported, "byte-identical")
                .guarantees(&[OutputGuarantee::ByteIdenticalRoundTrip]),
        ]
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let len = s.len()?;
        if len < 0x28 {
            return Ok(out);
        }
        let mut h = [0u8; 0x28];
        s.read_exact_at(0, &mut h)?;
        if &h[..4] == b"CISO" {
            match cso::CsoHeader::parse(s) {
                Ok(hd) => out.push(ProbeEvidence::new(PSP_CSO, Confidence::High).matched(format!(
                    "CISO v{} header, {} blocks",
                    hd.version,
                    hd.blocks()
                ))),
                Err(e) => out.push(ProbeEvidence::new(PSP_CSO, Confidence::Low).matched("CISO magic").warn(e.to_string())),
            }
        }
        if &h[..4] == pbp::MAGIC && pbp::Pbp::parse_table(s).is_ok() {
            out.push(ProbeEvidence::new(PSP_PBP, Confidence::High).matched("\\0PBP magic, section offsets ordered"));
        }
        if &h[..4] == crate::binary::psf::MAGIC && len < 1 << 20 {
            if let Ok(p) = crate::binary::psf::Psf::parse(&crate::read_vec(s, 0, len, 1 << 20)?) {
                if p.entries.contains_key("PSP_SYSTEM_VER") || p.entries.contains_key("DISC_ID") {
                    out.push(ProbeEvidence::new(PSP_SFO, Confidence::High).matched("PSF with PSP keys"));
                }
            }
        }
        if crate::disc::iso9660::probe(s) {
            // Read the root directory only (bounded) to look for PSP markers.
            let mut pvd = [0u8; 2048];
            s.read_exact_at(16 * 2048, &mut pvd)?;
            let id = crate::binary::ascii_z(&pvd[8..40]);
            let mut ev = None;
            if id.trim() == "PSP GAME" {
                ev = Some(ProbeEvidence::new(PSP_ISO, Confidence::High).matched("system identifier \"PSP GAME\""));
            }
            let root_lba = crate::binary::u32le(&pvd, 156 + 2)? as u64;
            let root_len = (crate::binary::u32le(&pvd, 156 + 10)? as u64).min(64 * 1024);
            if let Ok(dir) = crate::read_vec(s, root_lba * 2048, root_len, 64 * 1024) {
                let text = String::from_utf8_lossy(&dir);
                if text.contains("PSP_GAME") || text.contains("UMD_DATA.BIN") {
                    let e = ev.take().unwrap_or_else(|| ProbeEvidence::new(PSP_ISO, Confidence::High));
                    ev = Some(e.matched("root directory lists PSP_GAME/UMD_DATA.BIN"));
                }
            }
            if let Some(e) = ev {
                out.push(e.specificity(5).refines(crate::disc::ISO9660));
            }
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            PSP_ISO => Ok(Box::new(PspIsoReader::open(source, PSP_ISO, None, ctx)?)),
            PSP_CSO => {
                let cso = Arc::new(cso::CsoSource::open(source.clone())?);
                Ok(Box::new(PspIsoReader::open(cso.clone(), PSP_CSO, Some((source, cso)), ctx)?))
            }
            PSP_PBP => Ok(Box::new(PbpReader::open(source)?)),
            PSP_SFO => Ok(Box::new(crate::binary::psf::PsfReader::open(source, PSP_SFO, Platform::Psp)?)),
            _ => Err(Error::unsupported(format!("psp backend cannot open {format}"))),
        }
    }
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let mut plan = TransformPlan::new(if req.to == PSP_CSO { Operation::Compress } else { Operation::Decompress });
        plan.inputs.push(PlanInput::capture(&req.input, "source", req.from)?);
        crate::check_output_target(&req.output, &crate::IoPolicy::default(), &plan.input_paths())
            .or_else(|e| if e.code() == crate::ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
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
        let level = req.option_u64("level")?.unwrap_or(9) as u32;
        if to == PSP_CSO {
            let len = src.len()?;
            if len % 2048 != 0 {
                return Err(Error::invalid_arg("image length must be a multiple of 2048"));
            }
            plan.steps.push(format!("{} blocks of 2048 bytes, deflate level {level}", len / 2048));
            Ok(ClosurePlan::new(
                plan,
                Box::new(move |plan, job| {
                    let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                    cso::compress(src.as_ref(), &mut f, level, job)?;
                    f.flush_for_verify()?;
                    let back = cso::CsoSource::open(Arc::new(crate::FileSource::open(f.temp_path())?))?;
                    let a = crate::crypto::hash_range(src.as_ref(), 0, src.len()?, crate::crypto::HashAlg::Sha256, None)?;
                    let b = crate::crypto::hash_range(&back, 0, back.len()?, crate::crypto::HashAlg::Sha256, None)?;
                    if a != b {
                        return Err(Error::new(crate::ErrorCode::VerificationFailed, "CSO does not decompress to the input"));
                    }
                    let out = f.finish()?;
                    let mut rep = OperationReport::new(plan.operation, plan.input_paths());
                    rep.outputs.push(OutputRecord::from_path(&out, Some(PSP_CSO), &plan.guarantees)?);
                    rep.metadata.insert("sha256".into(), crate::hex(&a).into());
                    Ok(rep)
                }),
            ))
        } else {
            let cso = Arc::new(cso::CsoSource::open(src)?);
            Ok(ClosurePlan::new(
                plan,
                Box::new(move |plan, job| {
                    let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(cso.len()?));
                    crate::copy_all(cso.as_ref(), &mut f, &mut p)?;
                    let out = f.finish()?;
                    let mut rep = OperationReport::new(plan.operation, plan.input_paths());
                    rep.outputs.push(OutputRecord::from_path(&out, Some(PSP_ISO), &plan.guarantees)?);
                    Ok(rep)
                }),
            ))
        }
    }
}

/// Reader for PSP ISO images (directly or through CSO).
pub(crate) struct PspIsoReader {
    format: FormatId,
    image: SharedSource,
    cso: Option<(SharedSource, Arc<cso::CsoSource>)>,
    fs: Option<IsoFs>,
    table: NodeTable,
    sfo: Option<sfo::Psf>,
    umd: Option<String>,
}

impl PspIsoReader {
    pub fn open(
        image: SharedSource,
        format: FormatId,
        cso: Option<(SharedSource, Arc<cso::CsoSource>)>,
        ctx: &OpenContext,
    ) -> Result<Self> {
        let mut table = NodeTable::new();
        if cso.is_some() {
            table.push(ContentNode::file(0, "image.iso", image.len()?).kind(NodeKind::Track), Some(image.clone()));
        }
        let fs = if crate::disc::iso9660::probe(image.as_ref()) { Some(IsoFs::open(image.clone(), &ctx.limits)?) } else { None };
        if format == PSP_ISO && !fs.as_ref().is_some_and(is_psp_fs) {
            return Err(Error::malformed("not a PSP UMD image (no PSP_GAME/PARAM.SFO or UMD_DATA.BIN)"));
        }
        let (mut sfo, mut umd) = (None, None);
        if let Some(f) = &fs {
            crate::disc::add_iso_nodes(&mut table, f, if cso.is_some() { "data" } else { "" })?;
            if let Some(b) = f.read_file("PSP_GAME/PARAM.SFO", 1 << 20)? {
                sfo = crate::binary::psf::Psf::parse(&b).ok();
            }
            if let Some(b) = f.read_file("UMD_DATA.BIN", 4096)? {
                umd = Some(String::from_utf8_lossy(&b).split('|').next().unwrap_or("").to_string());
            }
        }
        Ok(PspIsoReader { format, image, cso, fs, table, sfo, umd })
    }
}

impl PackageReader for PspIsoReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let container = match &self.cso {
            Some((raw, _)) => raw.len()?,
            None => self.image.len()?,
        };
        let mut i = PackageInfo::new(self.format, Platform::Psp, container);
        i.category = ContentCategory::DiscImage;
        i.sizes.uncompressed = Some(self.image.len()?);
        if let Some((_, c)) = &self.cso {
            i.field("block_size", c.header.block_size);
            i.field("blocks", c.header.blocks());
            i.field("cso_version", c.header.version);
        }
        if let Some(s) = &self.sfo {
            i.title = s.get_str("TITLE").map(String::from);
            i.title_id = s.get_str("DISC_ID").map(String::from);
            i.version = s.get_str("DISC_VERSION").or_else(|| s.get_str("APP_VER")).map(String::from);
            for (k, v) in &s.entries {
                i.fields.insert(format!("sfo.{k}"), crate::MetaValue::Text(v.render()));
            }
        }
        if let Some(u) = &self.umd {
            i.product_code = Some(u.clone());
            if i.title_id.is_none() {
                i.title_id = Some(u.replace('-', ""));
            }
        }
        i.family_id = i.title_id.clone();
        if let Some(fs) = &self.fs {
            i.field("volume_id", fs.volume.volume_id.clone());
            if let Some(e) = fs.find("PSP_GAME/SYSDIR/EBOOT.BIN").filter(|e| e.size >= 4) {
                let s = fs.open_entry(e)?;
                i.field("eboot_encrypted", crate::read_vec(s.as_ref(), 0, 4, 4)? == b"~PSP");
            }
        }
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
        if let Some((_, c)) = &self.cso {
            r.pass(CheckLevel::Structure, "CSO index", Some(format!("{} blocks, offsets monotonic", c.header.blocks())));
            if level.wants_content() {
                match c.verify_all(job) {
                    Ok(()) => r.pass(CheckLevel::Content, "block decode", Some("every block decodes to its declared size".into())),
                    Err(e) if e.code() == crate::ErrorCode::Cancelled => return Err(e),
                    Err(e) => r.fail(CheckLevel::Content, "block decode", e.to_string()),
                }
            }
        }
        match &self.fs {
            Some(fs) => {
                let probs = fs.check_extents()?;
                r.check(CheckLevel::Structure, "ISO9660 extents", probs.iter().all(|p| p.contains("overlap")), probs.join("; "));
            }
            None => r.warn(CheckLevel::Structure, "filesystem", "no ISO9660 filesystem found"),
        }
        r.authenticity_unavailable("UMD/EBOOT signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(self.format))
    }
}

/// Reader for PBP containers.
pub(crate) struct PbpReader {
    pbp: pbp::Pbp,
    table: NodeTable,
}

impl PbpReader {
    pub fn open(source: SharedSource) -> Result<Self> {
        let pbp = pbp::Pbp::open(source)?;
        let mut table = NodeTable::new();
        for (i, (name, off, len)) in pbp.sections().into_iter().enumerate() {
            if len == 0 {
                continue;
            }
            let _ = i;
            table.push(ContentNode::file(0, name, len).span(off, len), Some(crate::SubSource::shared(pbp.source.clone(), off, len)?));
        }
        Ok(PbpReader { pbp, table })
    }
}

impl PackageReader for PbpReader {
    fn format(&self) -> FormatId {
        PSP_PBP
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(PSP_PBP, Platform::Psp, self.pbp.source.len()?);
        if let Some(s) = self.pbp.sfo()? {
            i.title = s.get_str("TITLE").map(String::from);
            i.title_id = s.get_str("DISC_ID").map(String::from);
            i.version = s.get_str("APP_VER").or_else(|| s.get_str("DISC_VERSION")).map(String::from);
            i.category = match s.get_str("CATEGORY") {
                Some("PG") => ContentCategory::Patch,
                Some("MG") | Some("ME") => ContentCategory::Homebrew,
                _ => ContentCategory::Application,
            };
            for (k, v) in &s.entries {
                i.fields.insert(format!("sfo.{k}"), crate::MetaValue::Text(v.render()));
            }
        }
        i.field("data_psp_encrypted", self.pbp.data_psp_encrypted()?);
        if self.pbp.data_psar_is_ps1()? {
            i.field("data_psar", "PS1 classic image (PSISOIMG/PSTITLEIMG)");
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
        let mut r = VerifyReport::new(PSP_PBP, level);
        r.pass(CheckLevel::Structure, "section table", Some("offsets ordered and within file".into()));
        r.check(CheckLevel::Structure, "PARAM.SFO", self.pbp.sfo().is_ok(), "parses when present");
        r.authenticity_unavailable("PRX/EBOOT signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(PSP_PBP))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, Registry};

    fn psp_iso() -> Vec<u8> {
        let mut psf = sfo::Psf::default();
        psf.entries.insert("TITLE".into(), sfo::PsfValue::Text("Test Game".into()));
        psf.entries.insert("DISC_ID".into(), sfo::PsfValue::Text("ULUS99999".into()));
        let mut b = crate::disc::iso9660::IsoBuilder::new("UMD");
        b.add_file("UMD_DATA.BIN", Arc::new(MemorySource::new(b"ULUS-99999|0000000000000000|0001|G".to_vec()))).unwrap();
        b.add_file("PSP_GAME/PARAM.SFO", Arc::new(MemorySource::new(psf.to_bytes()))).unwrap();
        b.add_file("PSP_GAME/SYSDIR/EBOOT.BIN", Arc::new(MemorySource::new(vec![0x7Fu8; 9000]))).unwrap();
        let mut out = Vec::new();
        b.write(&mut out, &JobContext::default()).unwrap();
        out
    }

    #[test]
    fn iso_refines_generic_and_cso_roundtrip() {
        let img = psp_iso();
        let reg = Registry::new().with(PspBackend).with(crate::disc::DiscBackend);
        let src: SharedSource = Arc::new(MemorySource::new(img.clone()));
        let pr = reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap();
        assert_eq!(pr.format, Some(PSP_ISO));
        let r = reg.open(src.clone(), &OpenContext::default()).unwrap();
        assert_eq!(r.info().unwrap().title_id.as_deref(), Some("ULUS99999"));
        let mut c = std::io::Cursor::new(Vec::new());
        cso::compress(src.as_ref(), &mut c, 9, &JobContext::default()).unwrap();
        let cso_bytes = c.into_inner();
        assert!(cso_bytes.len() < img.len());
        let cs: SharedSource = Arc::new(MemorySource::new(cso_bytes));
        assert_eq!(reg.probe(cs.as_ref(), &ProbeLimits::default()).unwrap().format, Some(PSP_CSO));
        let r = reg.open(cs, &OpenContext::default()).unwrap();
        assert!(r.verify(VerifyLevel::Content, &JobContext::default()).unwrap().no_failures());
        let n = r.entries().unwrap().map(|e| e.unwrap()).find(|e| e.path == "image.iso").unwrap();
        let back = r.open_entry(n.id).unwrap();
        assert_eq!(crate::read_vec(back.as_ref(), 0, back.len().unwrap(), 1 << 24).unwrap(), img);
    }

    #[test]
    fn pbp_pack_and_read() {
        let mut psf = sfo::Psf::default();
        psf.entries.insert("TITLE".into(), sfo::PsfValue::Text("HB".into()));
        psf.entries.insert("CATEGORY".into(), sfo::PsfValue::Text("MG".into()));
        let sections: Vec<Option<SharedSource>> = vec![
            Some(Arc::new(MemorySource::new(psf.to_bytes()))),
            Some(Arc::new(MemorySource::new(vec![0x89u8; 50]))),
            None,
            None,
            None,
            None,
            Some(Arc::new(MemorySource::new(b"\x7FELF....".to_vec()))),
            None,
        ];
        let mut out = Vec::new();
        pbp::write(&sections, &mut out, &JobContext::default()).unwrap();
        let r = PbpReader::open(Arc::new(MemorySource::new(out))).unwrap();
        assert_eq!(r.info().unwrap().title.as_deref(), Some("HB"));
        assert_eq!(r.entries().unwrap().count(), 3);
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::psp::cso::compress as cso_compress;
}
