//! `convert`, `compress`, `decompress` and `split` for Switch packages.
//!
//! * convert: NSP ⇄ XCI and NSZ ⇄ XCZ container changes (NCZ members restored when the
//!   target is uncompressed). NSP→XCI requires rights-ID titles to be converted to standard
//!   crypto, which modifies NCA headers and is only done on explicit request.
//! * compress: NSP→NSZ, XCI→XCZ (eligible NCAs become NCZ; requires keys).
//! * decompress: NSZ→NSP, XCZ→XCI; every restored NCA is re-hashed against its content ID.
//! * split: one package per content set (requires CNMT metadata).

use crate::switch::bundle::{PackageFormat, PackagePlan, Repack, RepackOptions, describe};
use crate::switch::formats::*;
use crate::switch::ncz::CompressOptions;
use crate::switch::reader::{OpenedPackage, open_package};
use crate::switch::title::ContentFile;
use crate::{
    Error, ErrorCode, FileSource, JobContext, KeyProvider, OpenContext, Operation, OperationReport, OutputRecord, PlanInput, PlanOutput,
    Result, SafeOutputDir, SharedSource, TransformPlan,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn open_input(p: &Path, ctx: &OpenContext, plan: &mut TransformPlan, role: &str) -> Result<OpenedPackage> {
    let src: SharedSource = Arc::new(FileSource::open(p)?);
    let pkg = open_package(src, ctx).map_err(|e| e.with_file(p.display().to_string()))?;
    plan.inputs.push(PlanInput::capture(p, role, pkg.format)?);
    Ok(pkg)
}

/// Builder for container conversion.
pub struct ConvertBuilder {
    input: PathBuf,
    target: PackageFormat,
    ctx: OpenContext,
    convert_rights: bool,
}

impl ConvertBuilder {
    pub fn new(input: impl Into<PathBuf>, target: PackageFormat) -> Self {
        ConvertBuilder { input: input.into(), target, ctx: OpenContext::default(), convert_rights: false }
    }
    pub fn context(mut self, ctx: OpenContext) -> Self {
        self.ctx = ctx;
        self
    }
    pub fn keys(mut self, k: Arc<dyn KeyProvider>) -> Self {
        self.ctx.keys = k;
        self
    }
    pub fn convert_rights(mut self, b: bool) -> Self {
        self.convert_rights = b;
        self
    }
    pub fn plan(self) -> Result<PackagePlan> {
        let mut plan = TransformPlan::new(Operation::Convert);
        let pkg = open_input(&self.input, &self.ctx, &mut plan, "source")?;
        let from = PackageFormat::from_format_id(pkg.format).ok_or_else(|| Error::internal("unexpected package format"))?;
        if from == self.target {
            return Err(Error::new(ErrorCode::InvalidOutputFormat, format!("input is already {}", self.target.extension())));
        }
        if from.is_compressed() != self.target.is_compressed() && self.target.is_compressed() {
            return Err(Error::new(ErrorCode::InvalidOutputFormat, "use `compress` to produce NSZ/XCZ from uncompressed packages"));
        }
        let mut opts = RepackOptions::new(self.target);
        opts.convert_rights = self.convert_rights;
        let files: Vec<ContentFile> = pkg.files.clone();
        let repack = Repack::new(&[&pkg], files, opts, self.ctx.keys.as_ref())?;
        describe(&mut plan, &repack, "repackaged container", None);
        if from.is_gamecard() && !self.target.is_gamecard() {
            plan.warnings.push("gamecard NCAs keep distribution type 'gamecard'; some installers may reject them".into());
        }
        Ok(PackagePlan { plan, repack, keys: self.ctx.keys.clone() })
    }
}

/// Builder for NSP→NSZ / XCI→XCZ compression.
pub struct CompressBuilder {
    input: PathBuf,
    target: Option<PackageFormat>,
    ctx: OpenContext,
    opts: CompressOptions,
}

impl CompressBuilder {
    pub fn new(input: impl Into<PathBuf>) -> Self {
        CompressBuilder { input: input.into(), target: None, ctx: OpenContext::default(), opts: CompressOptions::default() }
    }
    pub fn target(mut self, f: PackageFormat) -> Self {
        self.target = Some(f);
        self
    }
    pub fn level(mut self, l: i32) -> Self {
        self.opts.level = l;
        self
    }
    /// Block mode with 2^exp-byte blocks (default solid).
    /// Minimum NCA size to compress (default 1 MiB).
    pub fn min_size(mut self, n: u64) -> Self {
        self.opts.min_size = n;
        self
    }
    pub fn block_exponent(mut self, e: Option<u8>) -> Self {
        self.opts.block_exponent = e;
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
    pub fn plan(self) -> Result<PackagePlan> {
        if !cfg!(feature = "zstd") {
            return Err(Error::unsupported("compression requires the `zstd` feature"));
        }
        let mut plan = TransformPlan::new(Operation::Compress);
        let pkg = open_input(&self.input, &self.ctx, &mut plan, "source")?;
        let from = PackageFormat::from_format_id(pkg.format).ok_or_else(|| Error::internal("unexpected package format"))?;
        if from.is_compressed() {
            return Err(Error::new(ErrorCode::InvalidOutputFormat, "input is already compressed"));
        }
        let target = self.target.unwrap_or(if from.is_gamecard() { PackageFormat::Xcz } else { PackageFormat::Nsz });
        if !target.is_compressed() || target.is_gamecard() != from.is_gamecard() {
            return Err(Error::new(ErrorCode::InvalidOutputFormat, "compress maps NSP→NSZ and XCI→XCZ"));
        }
        if !crate::switch::keys::has_header_key(self.ctx.keys.as_ref()) {
            return Err(Error::needs_keys("compression decrypts NCA sections: header_key and key_area_key_* are required"));
        }
        let mut opts = RepackOptions::new(target);
        let mut c = self.opts;
        if target.is_gamecard() && c.block_exponent.is_none() {
            c.block_exponent = Some(20);
        }
        opts.compress = Some(c);
        let repack = Repack::new(&[&pkg], pkg.files.clone(), opts, self.ctx.keys.as_ref())?;
        describe(&mut plan, &repack, "compressed package", None);
        plan.steps.push(format!(
            "zstd level {}, {}",
            c.level,
            c.block_exponent.map(|e| format!("block mode 2^{e}")).unwrap_or_else(|| "solid".into())
        ));
        plan.guarantees.push(crate::OutputGuarantee::ByteIdenticalRoundTrip);
        plan.temp_space_estimate = 0;
        Ok(PackagePlan { plan, repack, keys: self.ctx.keys.clone() })
    }
}

/// Builder for NSZ→NSP / XCZ→XCI restoration.
pub struct DecompressBuilder {
    input: PathBuf,
    ctx: OpenContext,
}

impl DecompressBuilder {
    pub fn new(input: impl Into<PathBuf>) -> Self {
        DecompressBuilder { input: input.into(), ctx: OpenContext::default() }
    }
    pub fn context(mut self, ctx: OpenContext) -> Self {
        self.ctx = ctx;
        self
    }
    pub fn plan(self) -> Result<PackagePlan> {
        if !cfg!(feature = "zstd") {
            return Err(Error::unsupported("decompression requires the `zstd` feature"));
        }
        let mut plan = TransformPlan::new(Operation::Decompress);
        let pkg = open_input(&self.input, &self.ctx, &mut plan, "source")?;
        let target = match pkg.format {
            SWITCH_NSZ => PackageFormat::Nsp,
            SWITCH_XCZ => PackageFormat::Xci,
            _ => return Err(Error::new(ErrorCode::InvalidOutputFormat, "input is not compressed (NSZ/XCZ)")),
        };
        let opts = RepackOptions { force_decompress: true, ..RepackOptions::new(target) };
        let repack = Repack::new(&[&pkg], pkg.files.clone(), opts, self.ctx.keys.as_ref())?;
        describe(&mut plan, &repack, "restored package", None);
        plan.guarantees.push(crate::OutputGuarantee::ByteIdenticalRoundTrip);
        Ok(PackagePlan { plan, repack, keys: self.ctx.keys.clone() })
    }
}

/// Plan of a split: one package per content set.
pub struct SplitPlan {
    pub plan: TransformPlan,
    parts: Vec<(String, Repack)>,
    keys: Arc<dyn KeyProvider>,
}

impl SplitPlan {
    pub fn describe(&self) -> &TransformPlan {
        &self.plan
    }
    pub fn execute(self, output_dir: impl AsRef<Path>, job: &JobContext) -> Result<OperationReport> {
        self.plan.revalidate()?;
        let dir = SafeOutputDir::create(output_dir.as_ref(), &job.io)?;
        let inputs = self.plan.input_paths();
        let mut rep = OperationReport::new(Operation::Split, inputs.clone());
        for (name, repack) in &self.parts {
            let target = dir.resolve(name, false)?;
            let (path, v) = repack.write(&target, &inputs, self.keys.clone(), job)?;
            rep.outputs.push(OutputRecord::from_path(&path, Some(repack.opts.target.format_id()), &repack.guarantees)?);
            if let Some(prev) = rep.verification.as_mut() {
                prev.merge_prefixed(name, v);
            } else {
                let mut all = crate::VerifyReport::new(repack.opts.target.format_id(), crate::VerifyLevel::Content);
                all.merge_prefixed(name, v);
                rep.verification = Some(all);
            }
        }
        rep.warnings = self.plan.warnings.clone();
        Ok(rep)
    }
}

/// Builder for `split`.
pub struct SplitBuilder {
    input: PathBuf,
    ctx: OpenContext,
    target: Option<PackageFormat>,
}

impl SplitBuilder {
    pub fn new(input: impl Into<PathBuf>) -> Self {
        SplitBuilder { input: input.into(), ctx: OpenContext::default(), target: None }
    }
    pub fn context(mut self, ctx: OpenContext) -> Self {
        self.ctx = ctx;
        self
    }
    /// Output format of each part (default: NSP, or NSZ for compressed inputs).
    pub fn target(mut self, f: PackageFormat) -> Self {
        self.target = Some(f);
        self
    }
    pub fn plan(self) -> Result<SplitPlan> {
        let mut plan = TransformPlan::new(Operation::Split);
        let pkg = open_input(&self.input, &self.ctx, &mut plan, "source")?;
        if pkg.titles.titles.is_empty() {
            return Err(Error::needs_keys("no title metadata: split needs CNMT (key file) or .cnmt.xml to assign files to titles"));
        }
        if pkg.titles.titles.iter().any(|t| !t.strong()) {
            return Err(Error::needs_keys(
                "content membership is only known from tickets; split needs CNMT metadata (key file) or .cnmt.xml",
            ));
        }
        let target = self.target.unwrap_or(if pkg.is_compressed() { PackageFormat::Nsz } else { PackageFormat::Nsp });
        let mut assigned = std::collections::BTreeSet::new();
        let mut parts = Vec::new();
        for t in &pkg.titles.titles {
            let files: Vec<ContentFile> = pkg.files.iter().filter(|f| t.members.contains(&f.name)).cloned().collect();
            for f in &files {
                assigned.insert(f.name.clone());
            }
            let missing: Vec<_> =
                t.declared_contents.iter().filter(|c| !files.iter().any(|f| f.name.starts_with(c.as_str()))).cloned().collect();
            if !missing.is_empty() {
                plan.warnings.push(format!("{}: {} declared contents are not present in the package", t.title_id_hex(), missing.len()));
            }
            let name = format!(
                "{}_v{}_{}.{}",
                t.title_id_hex(),
                t.version.unwrap_or(0),
                format!("{:?}", t.role).to_lowercase(),
                target.extension()
            );
            let repack = Repack::new(&[&pkg], files, RepackOptions::new(target), self.ctx.keys.as_ref())?;
            plan.outputs.push(PlanOutput {
                path: PathBuf::from(&name),
                format: Some(target.format_id()),
                kind: "file",
                category: format!("{:?} content set", t.role),
                estimated_size: None,
            });
            plan.steps.push(format!("{name}: {} members", repack.members.len()));
            plan.guarantees = repack.guarantees.clone();
            parts.push((name, repack));
        }
        let unassigned: Vec<_> = pkg.files.iter().filter(|f| !assigned.contains(&f.name)).map(|f| f.name.clone()).collect();
        if !unassigned.is_empty() {
            plan.warnings.push(format!(
                "{} members belong to no content set and are not exported: {}",
                unassigned.len(),
                unassigned.join(", ")
            ));
        }
        Ok(SplitPlan { plan, parts, keys: self.ctx.keys.clone() })
    }
}

/// Plan an NCA→NCZ or NCZ→NCA conversion of a single archive.
pub fn plan_single_archive(
    input: &Path,
    output: &Path,
    to: crate::FormatId,
    ctx: &OpenContext,
    level: i32,
    block: Option<u8>,
) -> Result<Box<dyn crate::PlannedOperation>> {
    let src: SharedSource = Arc::new(FileSource::open(input)?);
    let op = if to == SWITCH_NCZ { Operation::Compress } else { Operation::Decompress };
    let mut plan = TransformPlan::new(op);
    plan.inputs.push(PlanInput::capture(input, "source", if to == SWITCH_NCZ { SWITCH_NCA } else { SWITCH_NCZ })?);
    crate::check_output_target(output, &crate::IoPolicy::default(), &plan.input_paths())
        .or_else(|e| if e.code() == ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
    plan.outputs.push(PlanOutput {
        path: output.to_path_buf(),
        format: Some(to),
        kind: "file",
        category: "content archive".into(),
        estimated_size: None,
    });
    plan.guarantees = vec![crate::OutputGuarantee::ByteIdenticalRoundTrip, crate::OutputGuarantee::ContainerValid];
    let keys = ctx.keys.clone();
    if to == SWITCH_NCZ {
        let nca = crate::switch::nca::Nca::open(src.clone(), keys.as_ref(), None)?;
        if !nca.has_section_keys() {
            return Err(Error::needs_keys(nca.key_error.clone().unwrap_or_default()));
        }
        plan.required_material = vec![
            crate::switch::keys::HEADER_KEY.into(),
            crate::switch::keys::key_area_key_name(nca.header.kaek_index, nca.header.key_generation()),
        ];
    } else if !crate::switch::ncz::probe(src.as_ref()) {
        return Err(Error::malformed("input is not an NCZ"));
    }
    Ok(crate::ClosurePlan::new(
        plan,
        Box::new(move |plan, job| {
            let out_path = plan.outputs[0].path.clone();
            let mut f = crate::AtomicFile::create(&out_path, &job.io, &plan.input_paths())?;
            if to == SWITCH_NCZ {
                #[cfg(not(feature = "zstd"))]
                {
                    let _ = (level, block, &mut f);
                    return Err(Error::unsupported("built without zstd"));
                }
                #[cfg(feature = "zstd")]
                {
                    let nca = crate::switch::nca::Nca::open(src.clone(), keys.as_ref(), None)?;
                    crate::switch::ncz::compress(
                        &nca,
                        &mut f,
                        crate::switch::ncz::CompressOptions { level, block_exponent: block, min_size: 0 },
                        job,
                    )?;
                    let orig_hash = crate::crypto::hash_range(src.as_ref(), 0, src.len()?, crate::crypto::HashAlg::Sha256, None)?;
                    f.flush_for_verify()?;
                    let back: SharedSource = Arc::new(crate::switch::ncz::NczSource::open(Arc::new(FileSource::open(f.temp_path())?))?);
                    let h = crate::crypto::hash_range(back.as_ref(), 0, back.len()?, crate::crypto::HashAlg::Sha256, None)?;
                    if h != orig_hash {
                        return Err(Error::new(ErrorCode::VerificationFailed, "NCZ does not restore the original NCA"));
                    }
                }
            } else {
                let ncz = crate::switch::ncz::NczSource::open(src.clone())?;
                let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(ncz.len()?));
                crate::copy_all(&ncz, &mut f, &mut p)?;
            }
            let path = f.finish()?;
            let mut rep = OperationReport::new(plan.operation, plan.input_paths());
            rep.outputs.push(OutputRecord::from_path(&path, Some(to), &plan.guarantees)?);
            Ok(rep)
        }),
    ))
}

use crate::DataSource;
