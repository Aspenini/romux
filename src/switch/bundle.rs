//! Repackaging core plus the `bundle` operation.
//!
//! `bundle` preserves distinct base / update / DLC content sets inside one NSP/NSZ/XCI/XCZ
//! container: every title keeps its own metadata, identifiers and content archives. It
//! never applies an update to the base (see [`crate::switch::apply_update`]) and never claims the
//! result is a signed, installable or authentic gamecard image.

use crate::switch::formats::*;
#[cfg(feature = "zstd")]
use crate::switch::nca::Nca;
use crate::switch::nca::NcaHeader;
use crate::switch::ncz::{CompressOptions, NczSource};
use crate::switch::package::{Member, MemberData, write_nsp, write_xci};
use crate::switch::reader::{OpenedPackage, open_package};
use crate::switch::title::{ContentFile, FileKind, TitleEntry, content_id_of};
use crate::{
    AtomicFile, CheckLevel, ConcatSource, Error, ErrorCode, FileSource, FormatId, JobContext, KeyProvider, MemorySource, OpenContext,
    Operation, OperationReport, OutputGuarantee, OutputRecord, PlanInput, PlanOutput, Result, SharedSource, SubSource, TitleRole,
    TransformPlan, VerifyLevel, VerifyReport, hex,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Output container family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PackageFormat {
    Nsp,
    Xci,
    Nsz,
    Xcz,
}

impl PackageFormat {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "nsp" => PackageFormat::Nsp,
            "xci" => PackageFormat::Xci,
            "nsz" => PackageFormat::Nsz,
            "xcz" => PackageFormat::Xcz,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidOutputFormat,
                    format!("unknown Switch package format {s:?} (nsp, xci, nsz, xcz)"),
                ));
            }
        })
    }
    pub fn format_id(&self) -> FormatId {
        match self {
            PackageFormat::Nsp => SWITCH_NSP,
            PackageFormat::Xci => SWITCH_XCI,
            PackageFormat::Nsz => SWITCH_NSZ,
            PackageFormat::Xcz => SWITCH_XCZ,
        }
    }
    pub fn from_format_id(f: FormatId) -> Option<Self> {
        Some(match f {
            SWITCH_NSP => PackageFormat::Nsp,
            SWITCH_XCI => PackageFormat::Xci,
            SWITCH_NSZ => PackageFormat::Nsz,
            SWITCH_XCZ => PackageFormat::Xcz,
            _ => return None,
        })
    }
    pub fn is_gamecard(&self) -> bool {
        matches!(self, PackageFormat::Xci | PackageFormat::Xcz)
    }
    pub fn is_compressed(&self) -> bool {
        matches!(self, PackageFormat::Nsz | PackageFormat::Xcz)
    }
    pub fn extension(&self) -> &'static str {
        match self {
            PackageFormat::Nsp => "nsp",
            PackageFormat::Xci => "xci",
            PackageFormat::Nsz => "nsz",
            PackageFormat::Xcz => "xcz",
        }
    }
}

/// Options shared by bundle / convert / compress / decompress / split.
#[derive(Debug, Clone, Copy)]
pub struct RepackOptions {
    pub target: PackageFormat,
    /// Allow converting rights-ID NCAs to standard crypto (modifies NCA headers).
    pub convert_rights: bool,
    /// Compress eligible NCAs to NCZ (requires keys).
    pub compress: Option<CompressOptions>,
    /// Decompress NCZ members even for compressed targets.
    pub force_decompress: bool,
}

impl RepackOptions {
    pub fn new(target: PackageFormat) -> Self {
        RepackOptions { target, convert_rights: false, compress: None, force_decompress: false }
    }
}

/// What will happen to each member.
#[derive(Debug, Clone, Serialize)]
pub struct MemberPlan {
    pub source_name: String,
    pub output_name: String,
    pub origin: String,
    pub action: &'static str,
    pub size: Option<u64>,
}

/// A validated selection of members ready to be written.
pub struct Repack {
    pub selection: Vec<ContentFile>,
    pub opts: RepackOptions,
    pub members: Vec<MemberPlan>,
    pub warnings: Vec<String>,
    pub guarantees: Vec<OutputGuarantee>,
    pub required_material: Vec<String>,
    pub titlekeys: std::collections::BTreeMap<String, [u8; 16]>,
}

fn header_of(f: &ContentFile, keys: &dyn KeyProvider) -> Result<NcaHeader> {
    let raw = crate::read_vec(f.source.as_ref(), 0, crate::switch::nca::HEADER_SIZE as u64, crate::switch::nca::HEADER_SIZE as u64)?;
    NcaHeader::decrypt(&raw, keys)
}

fn is_compress_candidate(f: &ContentFile, inputs: &[&OpenedPackage], min_size: u64) -> bool {
    if f.kind != FileKind::Nca || f.source.len().unwrap_or(0) < min_size.max(0x4000) {
        return false;
    }
    let summary = inputs.iter().find_map(|p| p.titles.nca.get(&f.name));
    !matches!(summary.map(|s| s.content_type), Some(crate::switch::nca::ContentType::Meta) | None)
}

impl Repack {
    /// Validate a member selection against the target format.
    pub fn new(inputs: &[&OpenedPackage], selection: Vec<ContentFile>, opts: RepackOptions, keys: &dyn KeyProvider) -> Result<Self> {
        let mut members = Vec::new();
        let mut warnings = Vec::new();
        let mut required = Vec::new();
        let mut titlekeys = std::collections::BTreeMap::new();
        let mut g = vec![OutputGuarantee::ContainerValid, OutputGuarantee::CompatibilityUnverified];
        if opts.target.is_gamecard() {
            g.push(OutputGuarantee::NotAuthentic);
        }
        let mut payload_preserved = true;
        let mut dropped = Vec::new();
        let mut seen: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        let mut kept = Vec::new();
        for f in selection {
            let size = f.source.len()?;
            if let Some(prev) = seen.get(&f.name) {
                if *prev == size {
                    warnings.push(format!("{} appears in more than one input; identical size, keeping one copy", f.name));
                    continue;
                }
                return Err(Error::conflict(format!("{} appears in several inputs with different sizes", f.name)));
            }
            seen.insert(f.name.clone(), size);
            let decompress = f.kind == FileKind::Ncz && (!opts.target.is_compressed() || opts.force_decompress);
            let mut action = "copy";
            let mut out_name = f.name.clone();
            match f.kind {
                FileKind::Ticket | FileKind::Certificate | FileKind::CnmtXml | FileKind::Other if opts.target.is_gamecard() => {
                    dropped.push(f.name.clone());
                    continue;
                }
                FileKind::Nca | FileKind::MetaNca | FileKind::Ncz => {
                    if decompress {
                        out_name = format!("{}.nca", f.name.trim_end_matches(".ncz"));
                        action = "decompress";
                        payload_preserved = false;
                    }
                    let needs_header = opts.target.is_gamecard()
                        || (opts.compress.is_some() && is_compress_candidate(&f, inputs, opts.compress.map(|c| c.min_size).unwrap_or(0)));
                    let hdr = if needs_header {
                        match header_of(&f, keys) {
                            Ok(h) => Some(h),
                            Err(e) if e.code() == ErrorCode::NeedsKeyMaterial => {
                                let has_tickets = inputs.iter().any(|p| !p.titles.tickets.is_empty());
                                if opts.compress.is_some() || (opts.target.is_gamecard() && has_tickets) {
                                    return Err(Error::needs_keys(format!(
                                        "{}: NCA header is encrypted; header_key is required for this conversion",
                                        f.name
                                    )));
                                }
                                None
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        None
                    };
                    if let (true, Some(h)) = (opts.target.is_gamecard(), &hdr) {
                        if h.has_rights_id() {
                            if !opts.convert_rights {
                                return Err(Error::new(
                                    ErrorCode::UnsupportedFeature,
                                    format!("{} uses a rights ID (ticket-based crypto); gamecard images carry no tickets", f.name),
                                )
                                .with_suggestion(
                                    "pass --convert-rights to rewrite NCA headers to standard crypto (signatures become invalid)",
                                ));
                            }
                            let tk = inputs.iter().find_map(|p| p.titles.titlekey_for(h, keys)).ok_or_else(|| {
                                Error::needs_keys(format!(
                                    "{}: no usable common ticket / titlekek for rights ID {}",
                                    f.name,
                                    h.rights_id_hex()
                                ))
                            })?;
                            titlekeys.insert(f.name.clone(), *tk);
                            required.push(crate::switch::keys::titlekek_name(h.key_generation()));
                            required.push(crate::switch::keys::key_area_key_name(h.kaek_index, h.key_generation()));
                            action = if decompress { "decompress+convert-rights" } else { "convert-rights" };
                            if !g.contains(&OutputGuarantee::ModifiedUnsigned) {
                                g.push(OutputGuarantee::ModifiedUnsigned);
                            }
                        }
                    }
                    if opts.compress.is_some() && is_compress_candidate(&f, inputs, opts.compress.map(|c| c.min_size).unwrap_or(0)) {
                        out_name = format!("{}.ncz", f.name.trim_end_matches(".nca"));
                        action = "compress";
                        payload_preserved = false;
                        if let Some(h) = &hdr {
                            if h.has_rights_id() && !titlekeys.contains_key(&f.name) {
                                let tk = inputs
                                    .iter()
                                    .find_map(|p| p.titles.titlekey_for(h, keys))
                                    .ok_or_else(|| Error::needs_keys(format!("{}: title key unavailable", f.name)))?;
                                titlekeys.insert(format!("{}#compress", f.name), *tk);
                            }
                            required.push(crate::switch::keys::key_area_key_name(h.kaek_index, h.key_generation()));
                        }
                    }
                }
                _ => {}
            }
            members.push(MemberPlan {
                source_name: f.name.clone(),
                output_name: out_name,
                origin: f.origin.clone(),
                action,
                size: if action == "copy" { Some(size) } else { None },
            });
            kept.push(f);
        }
        if !dropped.is_empty() {
            warnings.push(format!("{} non-NCA members (tickets, certificates, XML) are not carried in gamecard images", dropped.len()));
        }
        if payload_preserved && !g.contains(&OutputGuarantee::ModifiedUnsigned) {
            g.push(OutputGuarantee::PayloadBytesPreserved);
        } else {
            g.push(OutputGuarantee::ContentPreserved);
        }
        if opts.compress.is_some() || members.iter().any(|m| m.action.starts_with("decompress")) {
            required.push(crate::switch::keys::HEADER_KEY.into());
        }
        required.sort();
        required.dedup();
        if opts.compress.is_none() {
            required.retain(|r| r != crate::switch::keys::HEADER_KEY || members.iter().any(|m| m.action.contains("convert")));
        }
        Ok(Repack { selection: kept, opts, members, warnings, guarantees: g, required_material: required, titlekeys })
    }

    fn build_members(&self, keys: Arc<dyn KeyProvider>, limits: crate::ResourceLimits) -> Result<Vec<Member>> {
        let _ = limits;
        let mut out = Vec::new();
        for (f, mp) in self.selection.iter().zip(&self.members) {
            let mut src: SharedSource = f.source.clone();
            if mp.action.starts_with("decompress") {
                src = Arc::new(NczSource::open(f.source.clone())?);
            }
            if let Some(tk) = self.titlekeys.get(&f.name) {
                let mut h = header_of(f, keys.as_ref())?;
                h.convert_to_standard_crypto(tk, keys.as_ref())?;
                let new_hdr = h.encrypt(keys.as_ref())?;
                let rest_len = src.len()? - crate::switch::nca::HEADER_SIZE as u64;
                src = Arc::new(ConcatSource::new(vec![
                    Arc::new(MemorySource::new(new_hdr)),
                    SubSource::shared(src.clone(), crate::switch::nca::HEADER_SIZE as u64, rest_len)?,
                ])?);
            }
            if mp.action == "compress" {
                let opts = self.opts.compress.unwrap_or_default();
                let tk = self.titlekeys.get(&format!("{}#compress", f.name)).copied();
                let keys2 = keys.clone();
                let s2 = src.clone();
                let prefix = crate::read_vec(src.as_ref(), 0, src.len()?.min(0x200), 0x200)?;
                #[cfg(feature = "zstd")]
                let produce: crate::switch::package::Producer = Box::new(move |w, job| {
                    let nca = Nca::open(s2, keys2.as_ref(), tk.as_ref())?;
                    crate::switch::ncz::compress(&nca, w, opts, job)
                });
                #[cfg(not(feature = "zstd"))]
                let produce: crate::switch::package::Producer = {
                    let _ = (opts, tk, keys2, s2);
                    Box::new(|_, _| Err(Error::unsupported("built without zstd")))
                };
                out.push(Member { name: mp.output_name.clone(), data: MemberData::Produce(produce), prefix });
            } else {
                out.push(Member::from_source(&mp.output_name, src)?);
            }
        }
        Ok(out)
    }

    /// Write the package to `output` (atomically) and verify it.
    pub fn write(
        &self,
        output: &Path,
        inputs: &[PathBuf],
        keys: Arc<dyn KeyProvider>,
        job: &JobContext,
    ) -> Result<(PathBuf, VerifyReport)> {
        let members = self.build_members(keys.clone(), job.limits)?;
        let mut f = AtomicFile::create(output, &job.io, inputs)?;
        if self.opts.target.is_gamecard() {
            write_xci(&mut f, vec![("update".into(), vec![]), ("normal".into(), vec![]), ("secure".into(), members)], job)?;
        } else {
            write_nsp(&mut f, members, job)?;
        }
        job.progress(crate::Phase::Verifying, 0, None);
        f.flush_for_verify()?;
        let report = verify_written(f.temp_path(), &self.members, self.opts.target, job)?;
        if !report.no_failures() {
            return Err(Error::new(ErrorCode::VerificationFailed, "written package failed verification; output discarded"));
        }
        Ok((f.finish()?, report))
    }
}

/// Re-open a written package and check its members; content IDs are re-hashed for
/// members that were transformed (decompressed/compressed).
fn verify_written(path: &Path, plan: &[MemberPlan], target: PackageFormat, job: &JobContext) -> Result<VerifyReport> {
    let src: SharedSource = Arc::new(FileSource::open(path)?);
    let pkg = open_package(src, &OpenContext::default())?;
    let mut r = VerifyReport::new(target.format_id(), VerifyLevel::Content);
    let names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
    r.check(CheckLevel::Structure, "member table", names.len() == plan.len(), format!("{} members", names.len()));
    if let Some(x) = &pkg.xci {
        let hashes = x.verify_hashes()?;
        r.check(CheckLevel::Structure, "HFS0 hashes", hashes.iter().all(|(_, ok)| *ok), format!("{} hashes", hashes.len()));
    }
    for m in plan {
        let f = match pkg.files.iter().find(|f| f.name == m.output_name) {
            Some(f) => f,
            None => {
                r.fail(CheckLevel::Structure, &m.output_name, "missing from output");
                continue;
            }
        };
        if let Some(s) = m.size {
            r.check(CheckLevel::Structure, &format!("{} size", m.output_name), f.source.len()? == s, format!("{s} bytes"));
        }
        if m.action == "copy" || m.action.contains("convert") {
            continue;
        }
        let id = match content_id_of(&m.source_name) {
            Some(id) => id,
            None => {
                r.skip(CheckLevel::Reproducibility, &m.output_name, "name is not a content ID");
                continue;
            }
        };
        let restored: SharedSource = if f.kind == FileKind::Ncz { Arc::new(NczSource::open(f.source.clone())?) } else { f.source.clone() };
        let len = restored.len()?;
        let h = hex(&crate::crypto::hash_range(restored.as_ref(), 0, len, crate::crypto::HashAlg::Sha256, None)?);
        r.check(
            CheckLevel::Reproducibility,
            &format!("{} restores original NCA", m.output_name),
            h.starts_with(&id),
            format!("sha256 {}", &h[..32]),
        );
        job.check_cancel()?;
    }
    Ok(r)
}

/// Shared plan wrapper.
pub struct PackagePlan {
    pub plan: TransformPlan,
    pub repack: Repack,
    pub keys: Arc<dyn KeyProvider>,
}

impl PackagePlan {
    pub fn describe(&self) -> &TransformPlan {
        &self.plan
    }
    /// Execute, writing to `output`.
    pub fn execute(self, output: impl AsRef<Path>, job: &JobContext) -> Result<OperationReport> {
        self.plan.revalidate()?;
        let output = output.as_ref();
        let inputs = self.plan.input_paths();
        let (path, verification) = self.repack.write(output, &inputs, self.keys.clone(), job)?;
        let mut rep = OperationReport::new(self.plan.operation, inputs);
        rep.outputs.push(OutputRecord::from_path(&path, Some(self.repack.opts.target.format_id()), &self.repack.guarantees)?);
        rep.warnings = self.plan.warnings.clone();
        rep.verification = Some(verification);
        rep.metadata = self.plan.details.clone();
        rep.diagnostics = job.take_diagnostics();
        Ok(rep)
    }
    /// Adapt to the generic planned-operation interface with a fixed output path.
    pub fn into_planned(mut self, output: PathBuf) -> Box<dyn crate::PlannedOperation> {
        self.plan.outputs = vec![PlanOutput {
            path: output.clone(),
            format: Some(self.repack.opts.target.format_id()),
            kind: "file",
            category: self.plan.outputs.first().map(|o| o.category.clone()).unwrap_or_default(),
            estimated_size: self.plan.outputs.first().and_then(|o| o.estimated_size),
        }];
        Box::new(Fixed { inner: self, output })
    }
}

struct Fixed {
    inner: PackagePlan,
    output: PathBuf,
}

impl crate::PlannedOperation for Fixed {
    fn plan(&self) -> &TransformPlan {
        &self.inner.plan
    }
    fn execute(self: Box<Self>, job: &JobContext) -> Result<OperationReport> {
        let Fixed { inner, output } = *self;
        inner.execute(output, job)
    }
}

pub(crate) fn describe(plan: &mut TransformPlan, repack: &Repack, category: &str, output: Option<&Path>) {
    plan.guarantees = repack.guarantees.clone();
    plan.warnings.extend(repack.warnings.iter().cloned());
    plan.required_material = repack.required_material.clone();
    let est: u64 = repack.members.iter().filter_map(|m| m.size).sum();
    plan.outputs.push(PlanOutput {
        path: output.map(Path::to_path_buf).unwrap_or_default(),
        format: Some(repack.opts.target.format_id()),
        kind: "file",
        category: category.into(),
        estimated_size: Some(est),
    });
    for m in &repack.members {
        plan.steps.push(format!("{} {} -> {} ({})", m.action, m.source_name, m.output_name, m.origin));
    }
    if repack.opts.target.is_gamecard() {
        plan.restrictions
            .push("rebuilt gamecard-style container: header signature, certificate and initial data are not reproducible".into());
    }
    plan.restrictions.push("emulator/installer compatibility is not tested by this operation".into());
}

// ------------------------------------------------------------------------------------------
// Bundle
// ------------------------------------------------------------------------------------------

/// Builder for the `bundle` operation.
pub struct BundleBuilder {
    base: PathBuf,
    updates: Vec<PathBuf>,
    dlcs: Vec<PathBuf>,
    format: PackageFormat,
    ctx: OpenContext,
    allow_unverified: bool,
    convert_rights: bool,
}

impl BundleBuilder {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        BundleBuilder {
            base: base.into(),
            updates: vec![],
            dlcs: vec![],
            format: PackageFormat::Nsp,
            ctx: OpenContext::default(),
            allow_unverified: false,
            convert_rights: false,
        }
    }
    pub fn update(mut self, p: impl Into<PathBuf>) -> Self {
        self.updates.push(p.into());
        self
    }
    pub fn dlc(mut self, p: impl Into<PathBuf>) -> Self {
        self.dlcs.push(p.into());
        self
    }
    pub fn output_format(mut self, f: PackageFormat) -> Self {
        self.format = f;
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
    /// Accept roles inferred from ticket IDs only (no CNMT/XML evidence).
    pub fn allow_unverified_relationships(mut self, b: bool) -> Self {
        self.allow_unverified = b;
        self
    }
    /// Permit rewriting rights-ID NCA headers when targeting XCI/XCZ.
    pub fn convert_rights(mut self, b: bool) -> Self {
        self.convert_rights = b;
        self
    }

    /// Inspect and validate every input; returns an immutable plan.
    pub fn plan(self) -> Result<PackagePlan> {
        let mut plan = TransformPlan::new(Operation::Bundle);
        let open = |p: &Path, role: &str, plan: &mut TransformPlan| -> Result<OpenedPackage> {
            let src: SharedSource = Arc::new(FileSource::open(p)?);
            let pkg = open_package(src, &self.ctx).map_err(|e| e.with_file(p.display().to_string()))?;
            plan.inputs.push(PlanInput::capture(p, role, pkg.format)?);
            Ok(pkg)
        };
        let base = open(&self.base, "base", &mut plan)?;
        let updates: Vec<OpenedPackage> = self.updates.iter().map(|p| open(p, "update", &mut plan)).collect::<Result<_>>()?;
        let dlcs: Vec<OpenedPackage> = self.dlcs.iter().map(|p| open(p, "dlc", &mut plan)).collect::<Result<_>>()?;

        let weak = |t: &TitleEntry| !t.strong();
        let pick = |pkg: &OpenedPackage, role: TitleRole, what: &str| -> Result<Vec<TitleEntry>> {
            let v: Vec<TitleEntry> = pkg.titles.titles.iter().filter(|t| t.role == role).cloned().collect();
            if v.is_empty() {
                if pkg.titles.titles.is_empty() {
                    return Err(Error::needs_keys(format!(
                        "{}: no title metadata found (no CNMT readable, no .cnmt.xml, no tickets) — cannot verify it is a {what}",
                        pkg.origin_name()
                    )));
                }
                return Err(Error::new(ErrorCode::IncompatibleTitles, format!("{} does not contain a {what}", pkg.origin_name())));
            }
            Ok(v)
        };
        let base_titles = pick(&base, TitleRole::Base, "base application")?;
        let base_ids: Vec<u64> = base_titles.iter().map(|t| t.title_id).collect();
        if base_ids.len() > 1 {
            return Err(Error::new(ErrorCode::IncompatibleTitles, "base input contains more than one application"));
        }
        let base_id = base_ids[0];
        let mut all: Vec<TitleEntry> = base.titles.titles.clone();
        let mut chosen_updates: Vec<TitleEntry> = all.iter().filter(|t| t.role == TitleRole::Update).cloned().collect();
        for u in &updates {
            for t in pick(u, TitleRole::Update, "title update")? {
                if t.base_id() != base_id {
                    return Err(Error::new(
                        ErrorCode::IncompatibleTitles,
                        format!("update {} belongs to application {:016x}, not {:016x}", t.title_id_hex(), t.base_id(), base_id),
                    ));
                }
                if t.version == Some(0) {
                    return Err(Error::new(ErrorCode::IncompatibleVersions, format!("update {} has version 0", t.title_id_hex())));
                }
                chosen_updates.push(t.clone());
                all.push(t);
            }
        }
        if chosen_updates.len() > 1 {
            let vs: Vec<String> = chosen_updates.iter().map(|t| t.version.map(|v| v.to_string()).unwrap_or("?".into())).collect();
            return Err(Error::new(
                ErrorCode::IncompatibleVersions,
                format!("multiple updates supplied for {:016x} (versions {}); select exactly one", base_id, vs.join(", ")),
            ));
        }
        let mut dlc_ids = std::collections::BTreeMap::new();
        for t in all.iter().filter(|t| t.role == TitleRole::AddOn) {
            dlc_ids.insert(t.title_id, t.version);
        }
        for d in &dlcs {
            for t in pick(d, TitleRole::AddOn, "DLC / add-on")? {
                if t.base_id() != base_id {
                    return Err(Error::new(
                        ErrorCode::IncompatibleTitles,
                        format!("DLC {} belongs to application {:016x}, not {:016x}", t.title_id_hex(), t.base_id(), base_id),
                    ));
                }
                if let Some(v) = dlc_ids.get(&t.title_id) {
                    if *v != t.version {
                        return Err(Error::new(
                            ErrorCode::IncompatibleVersions,
                            format!("DLC {} supplied twice with different versions", t.title_id_hex()),
                        ));
                    }
                    plan.warnings.push(format!("DLC {} supplied twice; keeping one copy", t.title_id_hex()));
                }
                dlc_ids.insert(t.title_id, t.version);
                all.push(t);
            }
        }
        if all.iter().any(weak) {
            let msg = "some roles were inferred from ticket rights IDs only (no CNMT or .cnmt.xml); versions and content membership are unverified";
            if !self.allow_unverified {
                return Err(
                    Error::needs_keys(msg).with_suggestion("supply a key file so CNMT metadata can be read, or pass --allow-unverified")
                );
            }
            plan.warnings.push(msg.into());
        }
        let mut selection: Vec<ContentFile> = Vec::new();
        for pkg in std::iter::once(&base).chain(updates.iter()).chain(dlcs.iter()) {
            selection.extend(pkg.files.iter().cloned());
        }
        let inputs: Vec<&OpenedPackage> = std::iter::once(&base).chain(updates.iter()).chain(dlcs.iter()).collect();
        let mut opts = RepackOptions::new(self.format);
        opts.convert_rights = self.convert_rights;
        let repack = Repack::new(&inputs, selection, opts, self.ctx.keys.as_ref())?;
        describe(&mut plan, &repack, "multi-content bundle", None);
        plan.steps.insert(
            0,
            format!(
                "bundle {} content sets of application {:016x} into one {} (each title kept separate)",
                all.len(),
                base_id,
                self.format.extension()
            ),
        );
        let titles: Vec<crate::MetaValue> = all
            .iter()
            .map(|t| {
                crate::MetaValue::Text(format!(
                    "{} {:?} {}",
                    t.title_id_hex(),
                    t.role,
                    t.version.map(|v| v.to_string()).unwrap_or("?".into())
                ))
            })
            .collect();
        plan.details.insert("titles".into(), crate::MetaValue::List(titles));
        plan.details.insert("bundled_content".into(), "detected".into());
        plan.details.insert("emulator_compatibility".into(), "not tested".into());
        Ok(PackagePlan { plan, repack, keys: self.ctx.keys.clone() })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::switch::nca::ContentType;
    use crate::switch::nca::testkit::*;

    pub struct Fixture {
        pub dir: tempfile::TempDir,
        pub keys: TestKeys,
        pub base: PathBuf,
        pub update: PathBuf,
        pub dlc: PathBuf,
    }

    fn title_nsp(dir: &Path, name: &str, tid: u64, mt: u8, version: u32, related: u64, keys: &TestKeys, ticket: bool) -> PathBuf {
        let tk = [0x42u8; 16];
        let data_pfs = pfs0_image(&[("payload.bin", vec![tid as u8; 0x3000])]);
        let content = build(
            &Spec {
                content_type: if mt == 0x82 { ContentType::PublicData } else { ContentType::Program },
                program_id: tid,
                sections: vec![Section::Pfs0(data_pfs)],
                titlekey: if ticket { Some(tk) } else { None },
                distribution: 0,
            },
            keys,
        );
        let cname = content_name(&content, false);
        let cid = cname.trim_end_matches(".nca").to_string();
        let chash = hex(&crate::crypto::sha256(&content));
        let cnmt = crate::switch::cnmt::build_binary(
            tid,
            version,
            mt,
            related,
            &[(cid, chash, content.len() as u64, if mt == 0x82 { 2 } else { 1 })],
        );
        let kind = match mt {
            0x80 => "Application",
            0x81 => "Patch",
            _ => "AddOnContent",
        };
        let meta_pfs = pfs0_image(&[(&format!("{kind}_{tid:016x}.cnmt"), cnmt)]);
        let meta = build(
            &Spec {
                content_type: ContentType::Meta,
                program_id: tid,
                sections: vec![Section::Pfs0(meta_pfs)],
                titlekey: None,
                distribution: 0,
            },
            keys,
        );
        let mut files = vec![(content_name(&meta, true), meta), (cname, content)];
        if ticket {
            let (tn, t) = crate::switch::nca::testkit::ticket(tid, &tk, keys);
            files.push((tn.replace(".tik", ".cert"), vec![0xCCu8; 0x700]));
            files.push((tn, t));
        }
        let refs: Vec<(&str, Vec<u8>)> = files.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
        let nsp = pfs0_image(&refs);
        let p = dir.join(name);
        std::fs::write(&p, nsp).unwrap();
        p
    }

    pub fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let keys = TestKeys::sample();
        let base_id = 0x0100_AAAA_BBBB_0000u64;
        let base = title_nsp(dir.path(), "base.nsp", base_id, 0x80, 0, base_id | 0x800, &keys, false);
        let update = title_nsp(dir.path(), "update.nsp", base_id | 0x800, 0x81, 0x10000, base_id, &keys, true);
        let dlc = title_nsp(dir.path(), "dlc.nsp", base_id + 0x1001, 0x82, 0, base_id, &keys, false);
        Fixture { dir, keys, base, update, dlc }
    }

    fn ctx(k: &TestKeys) -> OpenContext {
        OpenContext::default().with_keys(Arc::new(k.provider()))
    }

    #[test]
    fn bundle_nsp_keeps_titles_separate() {
        let fx = fixture();
        let plan = BundleBuilder::new(&fx.base).update(&fx.update).dlc(&fx.dlc).context(ctx(&fx.keys)).plan().unwrap();
        assert_eq!(plan.describe().inputs.len(), 3);
        let out = fx.dir.path().join("all.nsp");
        let rep = plan.execute(&out, &JobContext::default()).unwrap();
        assert!(rep.verification.as_ref().unwrap().no_failures());
        let pkg = open_package(Arc::new(FileSource::open(&out).unwrap()), &ctx(&fx.keys)).unwrap();
        let roles: Vec<_> = pkg.titles.titles.iter().map(|t| t.role).collect();
        assert_eq!(roles, vec![TitleRole::Base, TitleRole::Update, TitleRole::AddOn]);
        assert!(pkg.files.iter().any(|f| f.kind == FileKind::Ticket));
    }

    #[test]
    fn bundle_rejects_mismatched_titles_and_missing_keys() {
        let fx = fixture();
        let e = BundleBuilder::new(&fx.update).context(ctx(&fx.keys)).plan().err().unwrap();
        assert_eq!(e.code(), ErrorCode::IncompatibleTitles);
        let e = BundleBuilder::new(&fx.base).update(&fx.dlc).context(ctx(&fx.keys)).plan().err().unwrap();
        assert_eq!(e.code(), ErrorCode::IncompatibleTitles);
        let e = BundleBuilder::new(&fx.base).update(&fx.update).plan().err().unwrap();
        assert_eq!(e.code(), ErrorCode::NeedsKeyMaterial);
        let e = BundleBuilder::new(&fx.base).update(&fx.update).update(&fx.update).context(ctx(&fx.keys)).plan().err().unwrap();
        assert!(matches!(e.code(), ErrorCode::IncompatibleVersions | ErrorCode::ConflictingOutput), "{e}");
    }

    #[test]
    fn bundle_xci_requires_explicit_rights_conversion() {
        let fx = fixture();
        let e =
            BundleBuilder::new(&fx.base).update(&fx.update).output_format(PackageFormat::Xci).context(ctx(&fx.keys)).plan().err().unwrap();
        assert_eq!(e.code(), ErrorCode::UnsupportedFeature);
        let plan = BundleBuilder::new(&fx.base)
            .update(&fx.update)
            .dlc(&fx.dlc)
            .output_format(PackageFormat::Xci)
            .convert_rights(true)
            .context(ctx(&fx.keys))
            .plan()
            .unwrap();
        assert!(plan.describe().guarantees.contains(&OutputGuarantee::ModifiedUnsigned));
        let out = fx.dir.path().join("all.xci");
        plan.execute(&out, &JobContext::default()).unwrap();
        let pkg = open_package(Arc::new(FileSource::open(&out).unwrap()), &ctx(&fx.keys)).unwrap();
        assert_eq!(pkg.format, SWITCH_XCI);
        assert_eq!(pkg.titles.titles.len(), 3);
        assert!(pkg.titles.nca.values().all(|s| s.rights_id.is_none()));
    }
}
