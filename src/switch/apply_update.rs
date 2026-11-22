//! `apply-update`: reconstruct an *updated derived content tree* from a base application
//! and its title update, using the update's native BKTR (indirect + AES-CTR-EX) patch
//! semantics. This is a different operation from [`crate::switch::bundle`]: the result is a
//! decrypted, extracted tree (`romfs/`, `exefs/`, manifest), not a signed installable
//! package. Repacking it is a separate request and cannot produce retail-valid content.

use crate::switch::bktr::{IndirectSource, parse_indirect};
use crate::switch::cnmt::Cnmt;
use crate::switch::nca::{FsType, Nca};
use crate::switch::reader::{OpenedPackage, open_package};
use crate::switch::title::{FileKind, content_id_of, read_cnmt_from_nca};
use crate::{
    ByteProgress, Error, ErrorCode, FileSource, JobContext, KeyProvider, OpenContext, Operation, OperationReport, OutputGuarantee,
    OutputRecord, Phase, PlanInput, PlanOutput, Result, SafeOutputDir, SharedSource, SubSource, TitleRole, TransformPlan, copy_all,
    read_vec,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How to interpret the update. Only the console's native semantics are implemented;
/// generic binary deltas are deliberately not offered as a substitute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PatchStrategy {
    /// Native BKTR indirect storage for RomFS; ExeFS replaced by the update's ExeFS.
    NativeBktr,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangedFile {
    pub path: String,
    pub size: u64,
    /// "added", "patched", "unchanged" (served entirely from base storage), "removed".
    pub status: &'static str,
    pub patched_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyManifest {
    pub schema_version: u32,
    pub strategy: PatchStrategy,
    pub base_title_id: String,
    pub base_version: u32,
    pub update_title_id: String,
    pub update_version: u32,
    pub romfs: Vec<ChangedFile>,
    pub exefs: Vec<String>,
    pub guarantees: Vec<OutputGuarantee>,
    pub notes: Vec<String>,
}

/// Builder for `apply-update`.
pub struct ApplyUpdateBuilder {
    base: PathBuf,
    update: PathBuf,
    output: Option<PathBuf>,
    ctx: OpenContext,
    strategy: PatchStrategy,
}

/// The validated plan.
pub struct ApplyUpdatePlan {
    pub plan: TransformPlan,
    base: OpenedPackage,
    update: OpenedPackage,
    base_cnmt: Cnmt,
    update_cnmt: Cnmt,
    ctx: OpenContext,
    strategy: PatchStrategy,
}

fn find_cnmt(pkg: &OpenedPackage, role: TitleRole, keys: &dyn KeyProvider, limits: &crate::ResourceLimits) -> Result<Cnmt> {
    for f in pkg.files.iter().filter(|f| f.kind == FileKind::MetaNca) {
        if let Ok(c) = read_cnmt_from_nca(f.source.clone(), keys, limits) {
            if c.meta_type.role() == role {
                return Ok(c);
            }
        }
    }
    Err(Error::new(ErrorCode::IncompatibleTitles, format!("{} has no readable {role:?} content metadata", pkg.origin_name())))
}

fn program_nca(pkg: &OpenedPackage, cnmt: &Cnmt, keys: &dyn KeyProvider) -> Result<Nca> {
    let rec = cnmt
        .contents
        .iter()
        .find(|c| c.content_type == 1 && c.id_offset == 0)
        .ok_or_else(|| Error::unsupported(format!("{} declares no Program content", cnmt.title_id_hex())))?;
    let f = pkg
        .files
        .iter()
        .find(|f| content_id_of(&f.name).as_deref() == Some(rec.id.as_str()))
        .ok_or_else(|| Error::new(ErrorCode::IncompatibleTitles, format!("Program content {} is missing", rec.id)))?;
    let src: SharedSource =
        if f.kind == FileKind::Ncz { Arc::new(crate::switch::ncz::NczSource::open(f.source.clone())?) } else { f.source.clone() };
    let raw = read_vec(src.as_ref(), 0, crate::switch::nca::HEADER_SIZE as u64, crate::switch::nca::HEADER_SIZE as u64)?;
    let hdr = crate::switch::nca::NcaHeader::decrypt(&raw, keys)?;
    let tk = pkg.titles.titlekey_for(&hdr, keys);
    let nca = Nca::open(src, keys, tk.as_deref())?;
    if !nca.has_section_keys() {
        return Err(Error::needs_keys(nca.key_error.clone().unwrap_or_default()));
    }
    Ok(nca)
}

impl ApplyUpdateBuilder {
    pub fn new(base: impl Into<PathBuf>, update: impl Into<PathBuf>) -> Self {
        ApplyUpdateBuilder {
            base: base.into(),
            update: update.into(),
            output: None,
            ctx: OpenContext::default(),
            strategy: PatchStrategy::NativeBktr,
        }
    }
    pub fn output_directory(mut self, p: impl Into<PathBuf>) -> Self {
        self.output = Some(p.into());
        self
    }
    pub fn context(mut self, ctx: OpenContext) -> Self {
        self.ctx = ctx;
        self
    }
    pub fn keys(mut self, k: Arc<dyn KeyProvider>) -> Self {
        self.ctx.keys = k;
        self
    }
    pub fn strategy(mut self, s: PatchStrategy) -> Self {
        self.strategy = s;
        self
    }

    pub fn plan(self) -> Result<ApplyUpdatePlan> {
        let output = self.output.clone().ok_or_else(|| Error::invalid_arg("apply-update needs an output directory"))?;
        let keys = self.ctx.keys.clone();
        if !crate::switch::keys::has_header_key(keys.as_ref()) {
            return Err(Error::needs_keys("apply-update decrypts both titles: header_key, key_area_key_* and titlekek_* are required"));
        }
        let mut plan = TransformPlan::new(Operation::ApplyUpdate);
        let base_src: SharedSource = Arc::new(FileSource::open(&self.base)?);
        let upd_src: SharedSource = Arc::new(FileSource::open(&self.update)?);
        let base = open_package(base_src, &self.ctx)?;
        let update = open_package(upd_src, &self.ctx)?;
        plan.inputs.push(PlanInput::capture(&self.base, "base", base.format)?);
        plan.inputs.push(PlanInput::capture(&self.update, "update", update.format)?);
        let base_cnmt = find_cnmt(&base, TitleRole::Base, keys.as_ref(), &self.ctx.limits)?;
        let update_cnmt = find_cnmt(&update, TitleRole::Update, keys.as_ref(), &self.ctx.limits)?;
        let expected = base_cnmt.title_id | 0x800;
        if update_cnmt.title_id != expected || update_cnmt.related_id.is_some_and(|r| r != base_cnmt.title_id) {
            return Err(Error::new(
                ErrorCode::IncompatibleTitles,
                format!("update {} does not belong to application {}", update_cnmt.title_id_hex(), base_cnmt.title_id_hex()),
            ));
        }
        if update_cnmt.version == 0 {
            return Err(Error::new(ErrorCode::IncompatibleVersions, "update has version 0"));
        }
        // Validate both program NCAs are decryptable before writing anything.
        let pnca = program_nca(&update, &update_cnmt, keys.as_ref())?;
        let bnca = program_nca(&base, &base_cnmt, keys.as_ref())?;
        let patch_romfs = pnca.header.sections.iter().find(|s| s.fs_type() == FsType::RomFs);
        match patch_romfs {
            Some(s) if !s.is_patch() => plan.warnings.push("update RomFS is not a BKTR patch; it replaces the base RomFS".into()),
            Some(_) => {
                if !bnca.header.sections.iter().any(|s| s.fs_type() == FsType::RomFs) {
                    return Err(Error::new(ErrorCode::IncompatibleTitles, "update patches a RomFS but the base program has none"));
                }
            }
            None => plan.warnings.push("update carries no RomFS; base RomFS is used unchanged".into()),
        }
        crate::check_output_target(&output.join("manifest.json"), &crate::IoPolicy::default(), &[]).ok();
        plan.outputs.push(PlanOutput {
            path: output,
            format: None,
            kind: "directory",
            category: "updated derived content tree (decrypted)".into(),
            estimated_size: None,
        });
        plan.guarantees = vec![
            OutputGuarantee::DerivedArtifact,
            OutputGuarantee::Decrypted,
            OutputGuarantee::NotAuthentic,
            OutputGuarantee::CompatibilityUnverified,
        ];
        plan.required_material =
            vec![crate::switch::keys::HEADER_KEY.into(), "key_area_key_application_XX".into(), "titlekek_XX (rights-ID titles)".into()];
        plan.steps.push(format!(
            "apply update {} v{} to {} v{} using native BKTR semantics",
            update_cnmt.title_id_hex(),
            update_cnmt.version,
            base_cnmt.title_id_hex(),
            base_cnmt.version
        ));
        plan.steps.push("write romfs/ (patched), exefs/ (from update) and manifest.json".into());
        plan.restrictions.push("output is an extracted tree, not an installable or signed package".into());
        Ok(ApplyUpdatePlan { plan, base, update, base_cnmt, update_cnmt, ctx: self.ctx, strategy: self.strategy })
    }
}

impl ApplyUpdatePlan {
    pub fn describe(&self) -> &TransformPlan {
        &self.plan
    }

    pub fn execute(self, job: &JobContext) -> Result<OperationReport> {
        self.plan.revalidate()?;
        let keys = self.ctx.keys.clone();
        let limits = self.ctx.limits;
        let out_dir = self.plan.outputs[0].path.clone();
        let dir = SafeOutputDir::create(&out_dir, &job.io)?;
        let pnca = program_nca(&self.update, &self.update_cnmt, keys.as_ref())?;
        let bnca = program_nca(&self.base, &self.base_cnmt, keys.as_ref())?;
        let mut notes = Vec::new();
        // RomFS
        let base_romfs_hdr = bnca.header.sections.iter().find(|s| s.fs_type() == FsType::RomFs).cloned();
        let patch_romfs_hdr = pnca.header.sections.iter().find(|s| s.fs_type() == FsType::RomFs).cloned();
        let (romfs_src, indirect): (Option<SharedSource>, Option<Arc<IndirectSource>>) = match (&patch_romfs_hdr, &base_romfs_hdr) {
            (Some(p), Some(b)) if p.is_patch() => {
                let (ind_off, ind_size, ind_hdr) = p.indirect_table();
                let count = u32::from_le_bytes(ind_hdr[8..12].try_into().unwrap_or([0; 4])) as u64;
                let plain = pnca.section_plain_ctr(p)?;
                let table = read_vec(plain.as_ref(), ind_off, ind_size, 256 << 20)?;
                let entries = parse_indirect(&table, count)?;
                let virt_len = u64::from_le_bytes(table[8..16].try_into().unwrap_or([0; 8]));
                let base_sec = bnca.section(b.index)?;
                let patch_sec = pnca.section(p.index)?;
                let ind = Arc::new(IndirectSource::new(base_sec, patch_sec, entries, virt_len)?);
                let (off, size) = p.ivfc_data_region().ok_or_else(|| Error::malformed("patch RomFS has no IVFC data level"))?;
                let ind_shared: SharedSource = ind.clone();
                (Some(SubSource::shared(ind_shared, off, size)?), Some(ind))
            }
            (Some(p), _) => (Some(pnca.romfs_source(p.index)?), None),
            (None, Some(b)) => (Some(bnca.romfs_source(b.index)?), None),
            (None, None) => (None, None),
        };
        let mut romfs_report = Vec::new();
        let mut bytes = 0u64;
        if let Some(src) = romfs_src {
            let fs = crate::switch::romfs::RomFs::open(src, &limits)?;
            let base_fs = match &base_romfs_hdr {
                Some(b) => bnca.romfs_source(b.index).ok().and_then(|s| crate::switch::romfs::RomFs::open(s, &limits).ok()),
                None => None,
            };
            let total: u64 = fs.files.iter().map(|f| f.size).sum();
            let mut p = ByteProgress::new(job, Phase::Writing, Some(total));
            let data_off = patch_romfs_hdr.as_ref().and_then(|h| h.ivfc_data_region()).map(|r| r.0).unwrap_or(0);
            for f in &fs.files {
                job.check_cancel()?;
                let mut w = dir.create_file(&format!("romfs/{}", f.path))?;
                copy_all(fs.open_file(f)?.as_ref(), &mut w, &mut p)?;
                w.finish()?;
                bytes += f.size;
                let in_base = base_fs.as_ref().and_then(|b| b.files.iter().find(|x| x.path == f.path));
                let (status, patched) = match (&indirect, in_base) {
                    (_, None) => ("added", f.size),
                    (Some(ind), Some(_)) => {
                        let pb = ind.patched_bytes_in(data_off + fs.data_offset + f.offset, f.size);
                        (if pb == 0 { "unchanged" } else { "patched" }, pb)
                    }
                    (None, Some(_)) => ("replaced", f.size),
                };
                romfs_report.push(ChangedFile { path: f.path.clone(), size: f.size, status, patched_bytes: patched });
            }
            if let Some(b) = &base_fs {
                for f in &b.files {
                    if !fs.files.iter().any(|x| x.path == f.path) {
                        romfs_report.push(ChangedFile { path: f.path.clone(), size: f.size, status: "removed", patched_bytes: 0 });
                    }
                }
            }
        } else {
            notes.push("neither title carries a RomFS".into());
        }
        // ExeFS: the update's program ExeFS supersedes the base.
        let mut exefs = Vec::new();
        if let Some(s) = pnca.header.sections.iter().find(|s| s.fs_type() == FsType::PartitionFs) {
            let pfs = pnca.pfs0(s.index, &limits)?;
            let mut p = ByteProgress::new(job, Phase::Writing, None);
            for (i, e) in pfs.entries.iter().enumerate() {
                let mut w = dir.create_file(&format!("exefs/{}", e.name))?;
                copy_all(pfs.open(i)?.as_ref(), &mut w, &mut p)?;
                w.finish()?;
                exefs.push(e.name.clone());
                bytes += e.size;
            }
        } else {
            notes.push("update program has no ExeFS section".into());
        }
        let manifest = ApplyManifest {
            schema_version: 1,
            strategy: self.strategy,
            base_title_id: self.base_cnmt.title_id_hex(),
            base_version: self.base_cnmt.version,
            update_title_id: self.update_cnmt.title_id_hex(),
            update_version: self.update_cnmt.version,
            romfs: romfs_report,
            exefs,
            guarantees: self.plan.guarantees.clone(),
            notes,
        };
        let json = serde_json::to_vec_pretty(&manifest).map_err(|e| Error::internal(e.to_string()))?;
        let mut w = dir.create_file("manifest.json")?;
        std::io::Write::write_all(&mut w, &json)?;
        let mpath = w.finish()?;
        let mut rep = OperationReport::new(Operation::ApplyUpdate, self.plan.input_paths());
        rep.outputs.push(OutputRecord { path: out_dir, format: None, size: bytes, guarantees: self.plan.guarantees.clone(), sha256: None });
        rep.outputs.push(OutputRecord::from_path(&mpath, None, &[])?);
        rep.metadata.insert("patched_files".into(), (manifest.romfs.iter().filter(|f| f.status == "patched").count() as u64).into());
        rep.metadata.insert("added_files".into(), (manifest.romfs.iter().filter(|f| f.status == "added").count() as u64).into());
        rep.warnings = self.plan.warnings.clone();
        Ok(rep)
    }

    pub fn output_dir(&self) -> &Path {
        &self.plan.outputs[0].path
    }
}
