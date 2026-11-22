//! ZArchive package reader and repack planning.

use crate::disc::{ZAR, caps_for, collect_dir, zar};
use crate::{
    AtomicFile, CapabilitySet, CheckLevel, ClosurePlan, ContentNode, DataSource, EntryId, EntryIter, Error, FileSource, FormatId,
    JobContext, NodeTable, OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput,
    PlanOutput, PlannedOperation, Platform, ResourceLimits, Result, SharedSource, TransformPlan, VerifyLevel, VerifyReport,
    check_output_target,
};
use std::path::Path;
use std::sync::Arc;

pub(crate) struct ZarReader {
    source: SharedSource,
    pub archive: Arc<zar::ZArchive>,
    table: NodeTable,
}

impl ZarReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let archive = Arc::new(zar::ZArchive::open(source.clone(), &ctx.limits)?);
        let mut table = NodeTable::new();
        for e in &archive.entries {
            if e.is_dir {
                table.push(ContentNode::dir(0, e.path.clone()), None);
            } else {
                table.push(ContentNode::file(0, e.path.clone(), e.size), Some(archive.open_entry(e)?));
            }
        }
        Ok(ZarReader { source, archive, table })
    }

    /// Guess which platform the archived file tree belongs to.
    fn content_platform(&self) -> Option<(Platform, &'static str)> {
        let has = |p: &str| self.archive.entries.iter().any(|e| e.path.eq_ignore_ascii_case(p));
        let any_suffix = |s: &str| self.archive.entries.iter().any(|e| e.path.to_ascii_lowercase().ends_with(s));
        if has("default.xex") {
            Some((Platform::Xbox360, "Xbox 360 title (default.xex)"))
        } else if has("meta/meta.xml") || any_suffix(".rpx") {
            Some((Platform::WiiU, "Wii U title (code/content/meta)"))
        } else if has("default.xbe") {
            Some((Platform::Xbox, "original Xbox title (default.xbe)"))
        } else {
            None
        }
    }
}

impl PackageReader for ZarReader {
    fn format(&self) -> FormatId {
        ZAR
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(ZAR, Platform::Generic, self.source.len()?);
        let files = self.archive.entries.iter().filter(|e| !e.is_dir).count();
        i.sizes.uncompressed = Some(self.archive.entries.iter().map(|e| e.size).sum());
        i.field("files", files as u64);
        i.field("blocks", self.archive.blocks());
        if let Some((p, what)) = self.content_platform() {
            i.platform = p;
            i.field("content", what);
        }
        if let Some(xex) = self.archive.entries.iter().find(|e| e.path.eq_ignore_ascii_case("default.xex")) {
            if let Ok(x) = self.archive.open_entry(xex).and_then(|s| read_xex_title(s.as_ref())) {
                i.title_id = Some(format!("{x:08X}"));
                i.family_id = i.title_id.clone();
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
        let mut r = VerifyReport::new(ZAR, level);
        r.pass(CheckLevel::Structure, "footer and sections", Some(format!("{} blocks", self.archive.blocks())));
        r.pass(CheckLevel::Structure, "file tree", Some(format!("{} entries within the data", self.archive.entries.len())));
        if level.wants_content() {
            let ok = self.archive.verify_integrity(job)?;
            r.check(CheckLevel::Content, "integrity hash", ok, "SHA-256 of the archive with the hash field zeroed");
        }
        r.skip(CheckLevel::Authenticity, "signature", "ZArchive carries a hash, not a signature");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps_for(ZAR))
    }
}

/// Title ID from an XEX execution-info header (minimal parse, no Xbox dependency).
fn read_xex_title(s: &dyn DataSource) -> Result<u32> {
    let h = crate::read_vec(s, 0, 0x18, 0x18)?;
    if &h[..3] != b"XEX" {
        return Err(Error::malformed("not an XEX"));
    }
    let n = crate::binary::u32be(&h, 0x14)? as u64;
    let t = crate::read_vec(s, 0x18, n.min(64) * 8, 64 * 8)?;
    for i in 0..n.min(64) as usize {
        if crate::binary::u32be(&t, i * 8)? == 0x0004_0006 {
            let off = crate::binary::u32be(&t, i * 8 + 4)? as u64;
            return crate::binary::u32be(&crate::read_vec(s, off + 0xC, 4, 4)?, 0);
        }
    }
    Err(Error::malformed("XEX has no execution info"))
}

/// Plan building a ZArchive from a directory.
pub fn plan_repack_zar(dir: &Path, output: &Path, level: i32, policy: &crate::IoPolicy) -> Result<Box<dyn PlannedOperation>> {
    if !dir.is_dir() {
        return Err(Error::invalid_arg(format!("{} is not a directory", dir.display())));
    }
    check_output_target(output, policy, &[])?;
    let files = collect_dir(dir, &ResourceLimits::default())?;
    let mut plan = TransformPlan::new(Operation::Repack);
    for (_, p) in &files {
        plan.inputs.push(PlanInput::capture(p, "file", ZAR)?);
    }
    plan.outputs.push(PlanOutput {
        path: output.to_path_buf(),
        format: Some(ZAR),
        kind: "file",
        category: "archive".into(),
        estimated_size: None,
    });
    plan.guarantees = vec![OutputGuarantee::ContainerValid, OutputGuarantee::ContentPreserved, OutputGuarantee::CompatibilityUnverified];
    plan.steps.push(format!("{} files, zstd level {level}, 64 KiB blocks", files.len()));
    Ok(ClosurePlan::new(
        plan,
        Box::new(move |plan, job| {
            let mut b = zar::ZarBuilder::new();
            for (rel, p) in &files {
                b.add_file(rel, Arc::new(FileSource::open(p)?))?;
            }
            let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &[])?;
            b.write(&mut f, level, job)?;
            f.flush_for_verify()?;
            zar::finalize_hash(f.temp_path())?;
            let back = zar::ZArchive::open(Arc::new(FileSource::open(f.temp_path())?), &job.limits)?;
            if !back.verify_integrity(job)? || back.entries.iter().filter(|e| !e.is_dir).count() != files.len() {
                return Err(Error::new(crate::ErrorCode::VerificationFailed, "rebuilt ZArchive failed read-back verification"));
            }
            let out = f.finish()?;
            let mut rep = OperationReport::new(Operation::Repack, plan.input_paths());
            rep.outputs.push(OutputRecord::from_path(&out, Some(ZAR), &plan.guarantees)?);
            Ok(rep)
        }),
    ))
}
