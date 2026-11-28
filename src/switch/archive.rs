//! Decrypted archives: Switch packages (NSP/NSZ/XCI/XCZ, encrypted) → NX or NUP.
//!
//! Both targets hold *decrypted* content, so building them decrypts every NCA with the
//! user's key material (`header_key`, `key_area_key_*`, and `titlekek_*` plus the common
//! ticket for rights-ID titles). Roles and relationships come only from native records:
//! the CNMT meta type, its application/patch IDs and content records.
//!
//! * **NX**: one snapshot per content set. Each snapshot tree holds the content set's
//!   NCAs as decrypted DNCA units (`<content id>.nca`, `<content id>.cnmt.nca`); an
//!   update snapshot also contains its base units, so every snapshot is a complete view.
//!   Display metadata (titles, publisher, icons, NACP) comes from Control data.
//! * **NUP**: one package per content set with extracted `exefs/` and `romfs/` trees. An
//!   update package holds the complete updated tree (BKTR applied to the base RomFS).
//!
//! A NUP can also be packed from an already-decrypted dump folder (`base/`, `updates/<v>/`,
//! `dlc/<id>/<n>/`, see [`crate::switch::dump`]); that needs no keys.

use crate::switch::dump::{self, Dump};
use crate::switch::formats::{SWITCH_NUP, SWITCH_NX};
use crate::switch::native::{self, NativeContent, NativeTitle, Tree};
use crate::switch::reader::{OpenedPackage, open_package};
use crate::switch::{nup, nx};
use crate::{
    AtomicFile, CheckLevel, Error, ErrorCode, FileSource, FormatId, JobContext, KeyProvider, OpenContext, Operation, OperationReport,
    OutputGuarantee, OutputRecord, PlanInput, PlanOutput, Result, SharedSource, TitleRole, TransformPlan, VerifyLevel, parse_hex,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Decrypted archive family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ArchiveFormat {
    /// NX archive (`.nx`): decrypted NCAs as complete snapshots, block-deduplicated.
    Nx,
    /// NUP container (`.nup`): extracted ExeFS/RomFS trees per package.
    Nup,
}

impl ArchiveFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "nx" | "switch.nx" => Some(ArchiveFormat::Nx),
            "nup" | "switch.nup" => Some(ArchiveFormat::Nup),
            _ => None,
        }
    }
    pub fn format_id(&self) -> FormatId {
        match self {
            ArchiveFormat::Nx => SWITCH_NX,
            ArchiveFormat::Nup => SWITCH_NUP,
        }
    }
    pub fn from_format_id(f: FormatId) -> Option<Self> {
        match f {
            SWITCH_NX => Some(ArchiveFormat::Nx),
            SWITCH_NUP => Some(ArchiveFormat::Nup),
            _ => None,
        }
    }
    pub fn extension(&self) -> &'static str {
        match self {
            ArchiveFormat::Nx => "nx",
            ArchiveFormat::Nup => "nup",
        }
    }
}

/// Builder: one or more Switch packages → one NX/NUP archive.
pub struct ArchiveBuilder {
    inputs: Vec<PathBuf>,
    format: ArchiveFormat,
    ctx: OpenContext,
    level: Option<i32>,
    title_id: Option<u64>,
    progress: Option<Arc<dyn crate::ProgressSink>>,
}

/// The validated plan.
pub struct ArchivePlan {
    pub plan: TransformPlan,
    format: ArchiveFormat,
    // Kept alive for the decrypted views held by `titles`.
    _packages: Vec<OpenedPackage>,
    titles: Vec<NativeTitle>,
    /// Set when packing an already-decrypted dump folder.
    dump: Option<Dump>,
    ctx: OpenContext,
    level: Option<i32>,
}

impl ArchiveBuilder {
    pub fn new(format: ArchiveFormat) -> Self {
        ArchiveBuilder { inputs: Vec::new(), format, ctx: OpenContext::default(), level: None, title_id: None, progress: None }
    }
    /// Add an input package (base, update, DLC or a bundle; roles come from its CNMTs), or,
    /// for NUP, one already-decrypted dump folder.
    pub fn input(mut self, p: impl Into<PathBuf>) -> Self {
        self.inputs.push(p.into());
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
    /// Zstandard level (default 3; `0` stores everything uncompressed).
    pub fn level(mut self, l: i32) -> Self {
        self.level = Some(l);
        self
    }
    /// Progress while planning (scanning a dump folder can take a while).
    pub fn progress(mut self, sink: Arc<dyn crate::ProgressSink>) -> Self {
        self.progress = Some(sink);
        self
    }
    /// Dump folders only: the base title ID, overriding the one read from `main.npdm`.
    pub fn title_id(mut self, id: u64) -> Self {
        self.title_id = Some(id);
        self
    }

    pub fn plan(self) -> Result<ArchivePlan> {
        if self.inputs.is_empty() {
            return Err(Error::invalid_arg("no input packages"));
        }
        if self.inputs.iter().any(|p| dump::is_dump_dir(p)) {
            return self.plan_dump();
        }
        if self.title_id.is_some() {
            return Err(Error::invalid_arg("a title ID override applies only to dump folders; packages carry their own IDs"));
        }
        let mut plan = TransformPlan::new(Operation::Convert);
        let mut packages = Vec::new();
        for (i, p) in self.inputs.iter().enumerate() {
            let src: SharedSource = Arc::new(FileSource::open(p)?);
            let pkg = open_package(src, &self.ctx).map_err(|e| e.with_file(p.display().to_string()))?;
            plan.inputs.push(PlanInput::capture(p, if i == 0 { "source" } else { "additional source" }, pkg.format)?);
            packages.push(pkg);
        }
        let refs: Vec<&OpenedPackage> = packages.iter().collect();
        let (titles, warnings) = native::collect(&refs, self.ctx.keys.as_ref(), &self.ctx.limits)?;
        plan.warnings.extend(warnings);
        match self.format {
            ArchiveFormat::Nx => describe_nx(&mut plan, &titles)?,
            ArchiveFormat::Nup => describe_nup(&mut plan, &titles)?,
        }
        plan.guarantees = vec![
            OutputGuarantee::Decrypted,
            OutputGuarantee::DerivedArtifact,
            OutputGuarantee::NotAuthentic,
            OutputGuarantee::CompatibilityUnverified,
        ];
        plan.required_material = vec![
            crate::switch::keys::HEADER_KEY.into(),
            "key_area_key_application_XX".into(),
            "titlekek_XX (rights-ID titles, with their common tickets)".into(),
        ];
        plan.restrictions.push("output holds decrypted content; it is not an installable or signed package".into());
        if titles.iter().any(|t| t.cnmt.platform != 0) {
            plan.warnings.push("CNMT declares Switch 2 content; Switch 2 association rules are not verified".into());
        }
        let level = self.level.or(Some(3)).filter(|&l| l > 0);
        Ok(ArchivePlan { plan, format: self.format, _packages: packages, titles, dump: None, ctx: self.ctx, level })
    }

    fn plan_dump(self) -> Result<ArchivePlan> {
        let root = match self.inputs.as_slice() {
            [one] => one.clone(),
            _ => return Err(Error::invalid_arg("pack one dump folder at a time (it may hold base/, updates/ and dlc/)")),
        };
        if self.format != ArchiveFormat::Nup {
            return Err(Error::new(
                ErrorCode::InvalidOutputFormat,
                "an extracted dump folder has no CNMT or Control records, so its NX snapshot types and versions cannot be established; pack it as NUP",
            ));
        }
        let d = dump::discover(&root, self.title_id, self.progress.as_deref())?;
        let mut plan = TransformPlan::new(Operation::Repack);
        plan.warnings.extend(d.warnings.iter().cloned());
        for p in &d.packages {
            plan.steps.push(format!(
                "package {} {:016x} version {}{}: {} files, {} bytes",
                match p.kind {
                    nup::KIND_BASE => "base",
                    nup::KIND_UPDATE => "update",
                    _ => "addon",
                },
                p.title_id,
                p.version,
                if p.flags & nup::FLAG_STANDALONE_UPDATE != 0 { " (standalone update)" } else { "" },
                p.tree.files.len(),
                p.tree.files.iter().map(|f| f.size).sum::<u64>()
            ));
        }
        plan.steps.push("store files as found (already decrypted), deduplicate by SHA-256, compress with zstd".into());
        plan.details.insert("source_directory".into(), root.display().to_string().into());
        plan.details.insert("files".into(), (d.file_count as u64).into());
        plan.details.insert("logical_bytes".into(), d.logical_size().into());
        plan.guarantees =
            vec![OutputGuarantee::ContentPreserved, OutputGuarantee::DerivedArtifact, OutputGuarantee::CompatibilityUnverified];
        plan.restrictions
            .push("package roles, title IDs and versions come from the folder layout and main.npdm, not from signed metadata".into());
        let level = self.level.or(Some(3)).filter(|&l| l > 0);
        Ok(ArchivePlan { plan, format: self.format, _packages: Vec::new(), titles: Vec::new(), dump: Some(d), ctx: self.ctx, level })
    }
}

fn group_by_application(titles: &[NativeTitle]) -> Vec<(u64, u8, Vec<&NativeTitle>)> {
    let mut groups: Vec<(u64, u8, Vec<&NativeTitle>)> = Vec::new();
    for t in titles {
        let key = (t.application_id(), t.cnmt.platform);
        match groups.iter_mut().find(|g| (g.0, g.1) == key) {
            Some(g) => g.2.push(t),
            None => groups.push((key.0, key.1, vec![t])),
        }
    }
    groups
}

fn single_base<'a>(app: u64, ts: &[&'a NativeTitle]) -> Result<Option<&'a NativeTitle>> {
    let bases: Vec<_> = ts.iter().copied().filter(|t| t.role() == TitleRole::Base).collect();
    match bases.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        _ => Err(Error::new(
            ErrorCode::IncompatibleVersions,
            format!("application {app:016x} has several base versions; the required base is ambiguous"),
        )),
    }
}

fn describe_nx(plan: &mut TransformPlan, titles: &[NativeTitle]) -> Result<()> {
    for (app, platform, ts) in group_by_application(titles) {
        let base = single_base(app, &ts)?;
        for t in &ts {
            if t.role() == TitleRole::Update && base.is_none() {
                return Err(Error::new(
                    ErrorCode::IncompatibleTitles,
                    format!(
                        "update {} needs its base application {app:016x} among the inputs (NX snapshots are complete views)",
                        t.label()
                    ),
                ));
            }
            if t.role() != TitleRole::AddOn && t.primary_program().is_none() {
                return Err(Error::new(ErrorCode::IncompatibleTitles, format!("{} has no primary Program content", t.label())));
            }
            plan.steps.push(format!(
                "snapshot {} ({} units) for application {app:016x} ({})",
                t.label(),
                t.units().count(),
                nx::platform_name(platform_byte(platform))
            ));
        }
    }
    plan.steps.push("decrypt every NCA into a DNCA unit, deduplicate 256 KiB blocks, compress with zstd".into());
    Ok(())
}

fn describe_nup(plan: &mut TransformPlan, titles: &[NativeTitle]) -> Result<()> {
    let groups = group_by_application(titles);
    if groups.len() > 1 {
        return Err(Error::new(
            ErrorCode::IncompatibleTitles,
            format!(
                "a NUP container holds one game; the inputs contain applications {}",
                groups.iter().map(|g| format!("{:016x}", g.0)).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let (app, _, ts) = &groups[0];
    let base = single_base(*app, ts)?;
    for t in ts {
        if t.role() == TitleRole::Update
            && base.is_none()
            && t.program_nca().is_some_and(|p| p.nca.header.sections.iter().any(|s| s.is_patch()))
        {
            return Err(Error::new(
                ErrorCode::IncompatibleTitles,
                format!("update {} is a BKTR patch; add its base application to the inputs", t.label()),
            ));
        }
        plan.steps.push(format!("package {}", t.label()));
    }
    plan.steps.push("extract ExeFS/RomFS (updates applied to the base RomFS), deduplicate by SHA-256, compress with zstd".into());
    Ok(())
}

fn platform_byte(cnmt_platform: u8) -> u8 {
    match cnmt_platform {
        0 => 1,
        1 => 2,
        _ => 0,
    }
}

fn content_id_bytes(hex_id: &str) -> [u8; 16] {
    parse_hex(hex_id).and_then(|v| v.try_into().ok()).unwrap_or([0; 16])
}

fn dnca_file(c: &NativeContent, t: &NativeTitle) -> Result<nx::WFile> {
    Ok(nx::WFile { name: c.name.clone(), size: c.size(), source: c.dnca()?, reuse_key: Some(format!("{}:{}", t.input, c.content_id)) })
}

fn nx_metadata(t: &NativeTitle) -> Option<nx::WMetadata> {
    let c = t.control.as_ref()?;
    let default = c.default_title();
    Some(nx::WMetadata {
        title: default.map(|d| d.1.clone()),
        publisher: default.map(|d| d.2.clone()),
        icon: default.and_then(|d| c.icon(&d.0)).map(|b| b.to_vec()),
        nacp: Some(c.nacp_raw.clone()),
        localized: native::localized(c)
            .into_iter()
            .map(|(tag, title, icon)| (tag.to_string(), title.map(String::from), icon.map(|b| b.to_vec())))
            .collect(),
    })
}

fn nx_applications(titles: &[NativeTitle]) -> Result<Vec<nx::WApplication>> {
    let mut apps = Vec::new();
    for (app, platform, ts) in group_by_application(titles) {
        let base = single_base(app, &ts)?;
        let mut snaps: Vec<nx::WSnapshot> = Vec::new();
        let mut programs: Vec<(u64, u8)> = Vec::new();
        // Base and updates first so DLC can name a target index.
        let mut ordered: Vec<&NativeTitle> = ts.clone();
        ordered.sort_by_key(|t| (t.role() == TitleRole::AddOn, t.role() as u8, t.cnmt.version));
        let mut index_of: Vec<(*const NativeTitle, usize)> = Vec::new();
        for t in &ordered {
            let mut root = Vec::new();
            let mut names = std::collections::HashSet::new();
            for u in t.units() {
                names.insert(u.name.clone());
                root.push(nx::WEntry::File(dnca_file(u, t)?));
            }
            let (snapshot_type, program_id, requires) = match t.role() {
                TitleRole::Base => (nx::SNAPSHOT_BASE, t.primary_program().map(|p| p.program_id), None),
                TitleRole::Update => {
                    let b = base.ok_or_else(|| Error::new(ErrorCode::IncompatibleTitles, format!("update {} has no base", t.label())))?;
                    if b.cnmt.related_id.is_some_and(|p| p != 0 && p != t.cnmt.title_id) {
                        return Err(Error::new(
                            ErrorCode::IncompatibleTitles,
                            format!("update {} disagrees with the base's patch ID", t.label()),
                        ));
                    }
                    let bp = b.primary_program().map(|p| p.program_id);
                    let up = t.primary_program().map(|p| p.program_id);
                    if bp != up {
                        return Err(Error::new(
                            ErrorCode::IncompatibleTitles,
                            format!("update {} program ID differs from its base", t.label()),
                        ));
                    }
                    // Complete view: the update's units plus the base units it builds on.
                    for u in b.units() {
                        if names.insert(u.name.clone()) {
                            root.push(nx::WEntry::File(dnca_file(u, b)?));
                        }
                    }
                    let target = index_of
                        .iter()
                        .find(|(p, _)| std::ptr::eq(*p, b))
                        .map(|x| x.1)
                        .ok_or_else(|| Error::internal("base snapshot index"))?;
                    (nx::SNAPSHOT_UPDATE, up, Some((target, nx::DEP_REQUIRED_BASE)))
                }
                TitleRole::AddOn => {
                    let minimum = t.cnmt.required_application_version.unwrap_or(0);
                    let target = snaps
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.snapshot_type != nx::SNAPSHOT_DLC && s.version >= minimum)
                        .min_by_key(|(_, s)| (s.version, s.snapshot_type))
                        .map(|(i, _)| (i, nx::DEP_REQUIRES));
                    (nx::SNAPSHOT_DLC, None, target)
                }
                _ => continue,
            };
            if let Some(p) = program_id {
                if !programs.iter().any(|x| x.0 == p) {
                    programs.push((p, 0));
                }
            }
            index_of.push((*t as *const NativeTitle, snaps.len()));
            snaps.push(nx::WSnapshot {
                program_id,
                snapshot_type,
                version: t.cnmt.version,
                content_id: content_id_bytes(&t.meta.content_id),
                build_id: t.primary_program().and_then(|p| p.build_id),
                display_version: t.control.as_ref().and_then(|c| c.display_version().map(String::from)),
                requires,
                metadata: if t.role() == TitleRole::AddOn { None } else { nx_metadata(t) },
                required_firmware: if t.role() == TitleRole::AddOn { None } else { t.cnmt.required_system_version },
                root,
            });
        }
        apps.push(nx::WApplication { application_id: app, platform: platform_byte(platform), programs, snapshots: snaps });
    }
    Ok(apps)
}

fn nup_packages(titles: &[NativeTitle], limits: &crate::ResourceLimits) -> Result<Vec<nup::PackageInput>> {
    let groups = group_by_application(titles);
    let (app, _, ts) = &groups[0];
    let base = single_base(*app, ts)?;
    let newest_control = ts.iter().filter(|t| t.role() != TitleRole::AddOn && t.control.is_some()).max_by_key(|t| t.cnmt.version);
    let mut out = Vec::new();
    let mut ordered: Vec<&NativeTitle> = ts.clone();
    ordered.sort_by_key(|t| (t.role() as u8, t.cnmt.title_id, t.cnmt.version));
    for t in ordered {
        let mut tree = Tree::default();
        let (kind, flags, title_id) = match t.role() {
            TitleRole::Base => {
                let p = t
                    .program_nca()
                    .ok_or_else(|| Error::new(ErrorCode::IncompatibleTitles, format!("{} has no Program content", t.label())))?;
                tree.add_exefs(p, limits)?;
                if let Some(img) = native::romfs_image(p, None)? {
                    tree.add_romfs(img, limits)?;
                }
                (nup::KIND_BASE, 0, t.primary_program().map(|p| p.program_id).unwrap_or(t.cnmt.title_id))
            }
            TitleRole::Update => {
                let p = t
                    .program_nca()
                    .ok_or_else(|| Error::new(ErrorCode::IncompatibleTitles, format!("{} has no Program content", t.label())))?;
                let bp = base.and_then(|b| b.program_nca());
                tree.add_exefs(p, limits)?;
                if let Some(img) = native::romfs_image(p, bp)? {
                    tree.add_romfs(img, limits)?;
                }
                let flags = if base.is_none() { nup::FLAG_STANDALONE_UPDATE } else { 0 };
                (nup::KIND_UPDATE, flags, t.primary_program().map(|p| p.program_id).unwrap_or(t.application_id()))
            }
            TitleRole::AddOn => {
                let d =
                    t.data_nca().ok_or_else(|| Error::new(ErrorCode::IncompatibleTitles, format!("{} has no Data content", t.label())))?;
                if let Some(img) = native::romfs_image(d, None)? {
                    tree.add_romfs(img, limits)?;
                }
                (nup::KIND_ADDON, 0, t.cnmt.title_id)
            }
            _ => continue,
        };
        let mut meta: Vec<(u16, Vec<u8>)> = Vec::new();
        if let Some(p) = t.primary_program() {
            if let Some(n) = &p.npdm {
                meta.push((nup::TLV_NPDM, n.clone()));
            }
            if let Some(b) = p.build_id {
                meta.push((nup::TLV_BUILD_ID, b.to_vec()));
            }
        }
        if let Some(c) = &t.control {
            meta.push((nup::TLV_NACP, c.nacp_raw.clone()));
            if let Some(v) = c.display_version() {
                meta.push((nup::TLV_DISPLAY_VERSION, v.as_bytes().to_vec()));
            }
        }
        let origin = Path::new(&t.origin).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| t.origin.clone());
        meta.push((nup::TLV_SOURCE_DUMP, origin.into_bytes()));
        out.push(nup::PackageInput { kind, flags, title_id, version: t.cnmt.version, tree, meta });
    }
    // Application metadata rides on the base package (or the first one).
    if let Some(c) = newest_control.and_then(|t| t.control.as_ref()) {
        let target = out.iter().position(|p| p.kind == nup::KIND_BASE).unwrap_or(0);
        let m = &mut out[target].meta;
        if let Some(d) = c.default_title() {
            m.push((nup::TLV_TITLE_NAME, d.1.as_bytes().to_vec()));
            if !d.2.is_empty() {
                m.push((nup::TLV_PUBLISHER, d.2.as_bytes().to_vec()));
            }
            if let Some(i) = c.icon(&d.0) {
                m.push((nup::TLV_ICON, i.to_vec()));
            }
        }
        let loc = native::localized(c);
        let titles: Vec<(&str, &[u8])> = loc.iter().filter_map(|(t, n, _)| n.map(|n| (*t, n.as_bytes()))).collect();
        let icons: Vec<(&str, &[u8])> = loc.iter().filter_map(|(t, _, i)| i.map(|i| (*t, i))).collect();
        if !titles.is_empty() {
            m.push((nup::TLV_LOCALIZED_TITLES, nup::encode_localized(&titles)));
        }
        if !icons.is_empty() {
            m.push((nup::TLV_LOCALIZED_ICONS, nup::encode_localized(&icons)));
        }
    }
    Ok(out)
}

impl ArchivePlan {
    pub fn describe(&self) -> &TransformPlan {
        &self.plan
    }

    pub fn execute(self, output: impl AsRef<Path>, job: &JobContext) -> Result<OperationReport> {
        self.plan.revalidate()?;
        let output = output.as_ref().to_path_buf();
        let inputs = self.plan.input_paths();
        if let Some(d) = &self.dump {
            // Each dump file is checked against its scanned size and timestamp when opened.
            d.check_output(&output)?;
        }
        let mut out = AtomicFile::create(&output, &job.io, &inputs)?;
        let mut rep = OperationReport::new(
            self.plan.operation,
            self.dump.as_ref().map(|d| vec![d.root.clone()]).unwrap_or_else(|| self.plan.input_paths()),
        );
        match self.format {
            ArchiveFormat::Nup if self.dump.is_some() => {
                let pkgs = &self.dump.as_ref().map(|d| &d.packages).ok_or_else(|| Error::internal("dump packages"))?;
                let stats = nup::write(&mut out, pkgs, self.level, job)?;
                rep.metadata.insert("packages".into(), (pkgs.len() as u64).into());
                rep.metadata.insert("files".into(), (stats.files as u64).into());
                rep.metadata.insert("unique_extents".into(), (stats.unique_extents as u64).into());
                rep.metadata.insert("logical_bytes".into(), stats.logical_bytes.into());
                rep.metadata.insert("stored_bytes".into(), stats.stored_bytes.into());
            }
            ArchiveFormat::Nx => {
                let mut apps = nx_applications(&self.titles)?;
                let opts = nx::WriteOptions { level: self.level, ..Default::default() };
                let stats = nx::write(&mut out, &mut apps, opts, job)?;
                rep.metadata.insert("snapshots".into(), (apps.iter().map(|a| a.snapshots.len()).sum::<usize>() as u64).into());
                rep.metadata.insert("files".into(), (stats.files as u64).into());
                rep.metadata.insert("blocks".into(), (stats.blocks as u64).into());
                rep.metadata.insert("deduplicated_chunks".into(), stats.deduplicated_chunks.into());
                rep.metadata.insert("logical_bytes".into(), stats.logical_bytes.into());
                rep.metadata.insert("stored_bytes".into(), stats.stored_bytes.into());
                let _ = stats.size;
            }
            ArchiveFormat::Nup => {
                let pkgs = nup_packages(&self.titles, &self.ctx.limits)?;
                let stats = nup::write(&mut out, &pkgs, self.level, job)?;
                rep.metadata.insert("packages".into(), (pkgs.len() as u64).into());
                rep.metadata.insert("files".into(), (stats.files as u64).into());
                rep.metadata.insert("unique_extents".into(), (stats.unique_extents as u64).into());
                rep.metadata.insert("logical_bytes".into(), stats.logical_bytes.into());
                rep.metadata.insert("stored_bytes".into(), stats.stored_bytes.into());
                let _ = stats.size;
            }
        }
        // Structural read-back of the staged file before it is published.
        let staged: SharedSource = Arc::new(FileSource::open(out.temp_path())?);
        let ctx = OpenContext::default();
        let verification = match self.format {
            ArchiveFormat::Nx => crate::PackageReader::verify(&nx::NxReader::open(staged, &ctx)?, VerifyLevel::Structure, job)?,
            ArchiveFormat::Nup => crate::PackageReader::verify(&nup::NupReader::open(staged, &ctx)?, VerifyLevel::Structure, job)?,
        };
        if !verification.no_failures() {
            let failed: Vec<String> =
                verification.checks.iter().filter(|c| c.status == crate::CheckStatus::Failed).map(|c| c.name.clone()).collect();
            return Err(Error::new(
                ErrorCode::VerificationFailed,
                format!("written archive failed read-back checks: {}", failed.join(", ")),
            ));
        }
        let path = out.finish()?;
        rep.outputs.push(OutputRecord::from_path(&path, Some(self.format.format_id()), &self.plan.guarantees)?);
        rep.verification = Some(verification);
        rep.warnings = self.plan.warnings.clone();
        let _ = CheckLevel::Structure;
        Ok(rep)
    }

    pub fn into_planned(mut self, output: PathBuf) -> Box<dyn crate::PlannedOperation> {
        self.plan.outputs.push(PlanOutput {
            path: output.clone(),
            format: Some(self.format.format_id()),
            kind: "file",
            category: format!(
                "{} {} archive",
                if self.dump.is_some() { "packed" } else { "decrypted" },
                self.format.extension().to_uppercase()
            ),
            estimated_size: None,
        });
        Box::new(PlannedArchive { plan: self, output })
    }
}

struct PlannedArchive {
    plan: ArchivePlan,
    output: PathBuf,
}

impl crate::PlannedOperation for PlannedArchive {
    fn plan(&self) -> &TransformPlan {
        &self.plan.plan
    }
    fn execute(self: Box<Self>, job: &JobContext) -> Result<OperationReport> {
        let PlannedArchive { plan, output } = *self;
        let mut rep = plan.execute(output, job)?;
        rep.diagnostics.extend(job.take_diagnostics());
        Ok(rep)
    }
}
