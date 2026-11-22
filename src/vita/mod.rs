//! # `romux::vita`
//!
//! PS Vita formats: VPK homebrew packages (ZIP with `sce_sys/param.sfo`) — inspect, list,
//! extract, verify (CRC-32) and rebuild — and header-level inspection of PS3/PSP/Vita-family
//! `\x7FPKG` packages. Vita VPKs and protected retail PKGs are never treated as equivalent:
//! retail PKG contents are encrypted and are not decrypted.

pub(crate) mod pkg;
pub(crate) mod zip;

pub mod sfo {
    pub use crate::binary::psf::{Psf, PsfValue};
}

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, DataSource, EntryId, EntryIter,
    Error, FileSource, FormatDescriptor, FormatId, IoPolicy, JobContext, NodeTable, OpenContext, Operation, OperationReport,
    OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput, PlanOutput, PlannedOperation, Platform, ProbeEvidence,
    ProbeLimits, ResourceLimits, Result, SharedSource, Support, TransformPlan, VerifyLevel, VerifyReport,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const VITA_VPK: FormatId = FormatId("vita.vpk");
pub const VITA_PKG: FormatId = FormatId("vita.pkg");
pub const VITA_SFO: FormatId = FormatId("vita.sfo");

#[derive(Default)]
pub struct VitaBackend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    vec![
        FormatDescriptor::new(VITA_VPK, Platform::Vita, "VPK", &["vpk"], "ZIP-based homebrew package with sce_sys/param.sfo")
            .op(Probe, Supported, "ZIP structure containing sce_sys/param.sfo")
            .op(Inspect, Supported, "param.sfo")
            .op(List, Supported, "ZIP entries")
            .op(Extract, Supported, "stored and deflate entries")
            .op(Verify, Supported, "central directory structure and per-entry CRC-32")
            .op(Repack, Supported, "rebuild from a directory (requires sce_sys/param.sfo)")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, ""),
        FormatDescriptor::new(VITA_PKG, Platform::Vita, "PKG (PS3/PSP/Vita family)", &["pkg"], "\\x7FPKG package; contents encrypted")
            .op(Probe, Supported, "\\x7FPKG magic")
            .op(Inspect, Conditional, "header and unencrypted metadata entries only")
            .op(List, ReadOnly, "metadata entries; item table is encrypted")
            .op(Extract, Unsupported, "package items are encrypted; decryption is not provided")
            .op(Verify, Supported, "header bounds only")
            .op(Repack, Unsupported, ""),
        FormatDescriptor::new(VITA_SFO, Platform::Vita, "Vita param.sfo", &["sfo"], "PSF with PSP2 keys")
            .op(Probe, Supported, "")
            .op(Inspect, Supported, "")
            .op(List, Supported, "")
            .op(Verify, Supported, ""),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

impl Backend for VitaBackend {
    fn name(&self) -> &'static str {
        "vita"
    }
    fn platform(&self) -> Platform {
        Platform::Vita
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn probe(&self, s: &dyn DataSource, l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let len = s.len()?;
        if len >= 0x100 {
            let mut m = [0u8; 4];
            s.read_exact_at(0, &mut m)?;
            if &m == pkg::MAGIC {
                if let Ok(h) = pkg::Header::parse(s) {
                    out.push(
                        ProbeEvidence::new(VITA_PKG, Confidence::High).matched(format!("\\x7FPKG magic, platform type {}", h.pkg_platform)),
                    );
                }
            }
        }
        if zip::probe(s) {
            let limits = ResourceLimits { max_metadata: l.max_read, ..Default::default() };
            let src: SharedSource = Arc::new(BorrowCopy::new(s, l.max_read)?);
            let _ = limits;
            // Central directory names only (bounded read).
            if let Ok(z) = zip::ZipArchive::open(src, &ResourceLimits { max_metadata: l.max_read, ..Default::default() }) {
                if z.entries.iter().any(|e| e.name == "sce_sys/param.sfo") {
                    out.push(ProbeEvidence::new(VITA_VPK, Confidence::High).matched("ZIP with sce_sys/param.sfo"));
                }
            }
        }
        if (0x14..1 << 20).contains(&len) {
            let b = crate::read_vec(s, 0, len, 1 << 20)?;
            if let Ok(p) = crate::binary::psf::Psf::parse(&b) {
                if p.entries.keys().any(|k| k.starts_with("PSP2_")) {
                    out.push(ProbeEvidence::new(VITA_SFO, Confidence::High).matched("PSF with PSP2 keys"));
                }
            }
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            VITA_VPK => Ok(Box::new(VpkReader::open(source, ctx)?)),
            VITA_PKG => Ok(Box::new(pkg::PkgReader::open(source)?)),
            VITA_SFO => Ok(Box::new(crate::binary::psf::PsfReader::open(source, VITA_SFO, Platform::Vita)?)),
            _ => Err(Error::unsupported(format!("vita backend cannot open {format}"))),
        }
    }
}

/// A bounded probe view: the central directory and EOCD live at the end of the file, so we
/// expose the real length but serve reads directly (no ownership needed for probing).
struct BorrowCopy {
    len: u64,
    head: Vec<u8>,
    tail_off: u64,
    tail: Vec<u8>,
}

impl BorrowCopy {
    fn new(s: &dyn DataSource, max: u64) -> Result<Self> {
        let len = s.len()?;
        let hn = len.min(4096);
        let tn = len.min(max);
        Ok(BorrowCopy { len, head: crate::read_vec(s, 0, hn, hn)?, tail_off: len - tn, tail: crate::read_vec(s, len - tn, tn, tn)? })
    }
}

impl DataSource for BorrowCopy {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        let end = offset + out.len() as u64;
        if end <= self.head.len() as u64 {
            out.copy_from_slice(&self.head[offset as usize..end as usize]);
            Ok(())
        } else if offset >= self.tail_off {
            let o = (offset - self.tail_off) as usize;
            out.copy_from_slice(&self.tail[o..o + out.len()]);
            Ok(())
        } else {
            Err(Error::limit("probe read outside the bounded window"))
        }
    }
}

pub(crate) struct VpkReader {
    zip: zip::ZipArchive,
    table: NodeTable,
    sfo: Option<sfo::Psf>,
}

impl VpkReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let zip = zip::ZipArchive::open(source, &ctx.limits)?;
        let mut table = NodeTable::new();
        let mut sfo = None;
        for e in &zip.entries {
            crate::path::sanitize_components(&e.name, ctx.limits.max_name_len).map_err(|err| err.with_content_id(e.name.clone()))?;
            if e.is_dir {
                table.push(ContentNode::dir(0, e.name.trim_end_matches('/').to_string()), None);
                continue;
            }
            let data = zip.open_entry(e).ok();
            let n = ContentNode::file(0, e.name.clone(), e.size)
                .meta("method", if e.method == 8 { "deflate" } else { "stored" })
                .meta("crc32", format!("{:08x}", e.crc32))
                .encrypted(e.encrypted);
            if e.name == "sce_sys/param.sfo" {
                if let Some(d) = &data {
                    sfo = crate::binary::psf::Psf::parse(&crate::read_vec(d.as_ref(), 0, e.size, 1 << 20)?).ok();
                }
            }
            table.push(n, data);
        }
        Ok(VpkReader { zip, table, sfo })
    }
}

impl PackageReader for VpkReader {
    fn format(&self) -> FormatId {
        VITA_VPK
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(VITA_VPK, Platform::Vita, self.zip.source.len()?);
        i.category = ContentCategory::Homebrew;
        i.encrypted = Some(false);
        i.sizes.uncompressed = Some(self.zip.entries.iter().map(|e| e.size).sum());
        if let Some(s) = &self.sfo {
            i.title = s.get_str("TITLE").or_else(|| s.get_str("STITLE")).map(String::from);
            i.title_id = s.get_str("TITLE_ID").map(String::from);
            i.version = s.get_str("APP_VER").map(String::from);
            i.family_id = i.title_id.clone();
            for (k, v) in &s.entries {
                i.fields.insert(format!("sfo.{k}"), crate::MetaValue::Text(v.render()));
            }
        } else {
            i.warnings.push("sce_sys/param.sfo missing or unreadable".into());
        }
        i.field("entries", self.zip.entries.len() as u64);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(VITA_VPK, level);
        r.pass(CheckLevel::Structure, "central directory", Some(format!("{} entries", self.zip.entries.len())));
        r.check(CheckLevel::Structure, "param.sfo", self.sfo.is_some(), "sce_sys/param.sfo parses");
        if level.wants_content() {
            let crcs = self.zip.verify_crcs(job)?;
            let bad: Vec<_> = crcs.iter().filter(|(_, ok)| !ok).map(|(n, _)| n.clone()).collect();
            r.check(
                CheckLevel::Content,
                "entry CRC-32",
                bad.is_empty(),
                if bad.is_empty() { format!("{} entries", crcs.len()) } else { format!("mismatch: {}", bad.join(", ")) },
            );
        }
        r.skip(CheckLevel::Authenticity, "signature", "VPK archives are unsigned");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(VITA_VPK))
    }
}

/// Plan rebuilding a VPK from a directory (deterministic order, deflate where it helps).
pub fn plan_repack_vpk(dir: &Path, output: &Path, policy: &IoPolicy) -> Result<Box<dyn PlannedOperation>> {
    if !dir.join("sce_sys").join("param.sfo").is_file() {
        return Err(Error::invalid_arg("a VPK requires sce_sys/param.sfo in the source directory"));
    }
    crate::check_output_target(output, policy, &[])?;
    let files = collect(dir)?;
    let mut plan = TransformPlan::new(Operation::Repack);
    for (_, p) in &files {
        plan.inputs.push(PlanInput::capture(p, "file", VITA_VPK)?);
    }
    plan.outputs.push(PlanOutput {
        path: output.to_path_buf(),
        format: Some(VITA_VPK),
        kind: "file",
        category: "homebrew package".into(),
        estimated_size: None,
    });
    plan.guarantees = vec![OutputGuarantee::ContainerValid, OutputGuarantee::ContentPreserved, OutputGuarantee::CompatibilityUnverified];
    plan.steps.push(format!("{} files", files.len()));
    Ok(ClosurePlan::new(
        plan,
        Box::new(move |plan, job| {
            let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &[])?;
            {
                let mut z = zip::ZipWriter::new(&mut f);
                for (rel, p) in &files {
                    job.check_cancel()?;
                    let src = FileSource::open(p)?;
                    let deflate = !rel.ends_with(".png") && !rel.ends_with(".zip");
                    z.add(rel, &src, deflate, 6)?;
                }
                z.finish()?;
            }
            f.flush_for_verify()?;
            let back = zip::ZipArchive::open(Arc::new(FileSource::open(f.temp_path())?), &job.limits)?;
            if back.verify_crcs(job)?.iter().any(|(_, ok)| !ok) || back.entries.len() != files.len() {
                return Err(Error::new(crate::ErrorCode::VerificationFailed, "rebuilt VPK failed read-back verification"));
            }
            let out = f.finish()?;
            let mut rep = OperationReport::new(Operation::Repack, plan.input_paths());
            rep.outputs.push(OutputRecord::from_path(&out, Some(VITA_VPK), &plan.guarantees)?);
            Ok(rep)
        }),
    ))
}

fn collect(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((d, rel)) = stack.pop() {
        let mut items: Vec<_> = std::fs::read_dir(&d)?.collect::<std::io::Result<Vec<_>>>()?;
        items.sort_by_key(|e| e.file_name());
        for e in items {
            let ft = e.file_type()?;
            let name = e.file_name().to_string_lossy().into_owned();
            let r = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            if ft.is_symlink() {
                return Err(Error::unsafe_path(format!("symlink {r} is not followed")));
            } else if ft.is_dir() {
                stack.push((e.path(), r));
            } else {
                out.push((r, e.path()));
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Registry;

    #[test]
    fn vpk_repack_and_read() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(src.join("sce_sys")).unwrap();
        let mut psf = sfo::Psf::default();
        psf.entries.insert("TITLE".into(), sfo::PsfValue::Text("VitaHB".into()));
        psf.entries.insert("TITLE_ID".into(), sfo::PsfValue::Text("VHBB00001".into()));
        psf.entries.insert("PSP2_SYSTEM_VER".into(), sfo::PsfValue::Int(0));
        std::fs::write(src.join("sce_sys/param.sfo"), psf.to_bytes()).unwrap();
        std::fs::write(src.join("eboot.bin"), vec![0x41u8; 100_000]).unwrap();
        let out = d.path().join("hb.vpk");
        plan_repack_vpk(&src, &out, &IoPolicy::default()).unwrap().execute(&JobContext::default()).unwrap();
        let reg = Registry::new().with(VitaBackend);
        let s = crate::open_file(&out).unwrap();
        assert_eq!(reg.probe(s.as_ref(), &ProbeLimits::default()).unwrap().format, Some(VITA_VPK));
        let r = reg.open(s, &OpenContext::default()).unwrap();
        assert_eq!(r.info().unwrap().title_id.as_deref(), Some("VHBB00001"));
        assert!(r.verify(VerifyLevel::Content, &JobContext::default()).unwrap().no_failures());
        let n = r.entries().unwrap().map(|n| n.unwrap()).find(|n| n.path == "eboot.bin").unwrap();
        let data = r.open_entry(n.id).unwrap();
        let mut part = vec![0u8; 10];
        data.read_exact_at(99_990, &mut part).unwrap();
        assert_eq!(part, vec![0x41u8; 10]);
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::vita::zip::ZipWriter;
}
