//! # Romux
//!
//! A library-first toolkit for **inspecting, extracting, validating, rebuilding,
//! converting, compressing and bundling** console game packages, with every operation
//! available as a typed Rust API (and as the `romux` CLI, which contains no format logic).
//!
//! ```no_run
//! # fn main() -> romux::Result<()> {
//! let source = romux::open("game.xci")?;
//! let probe = romux::probe(&source)?;
//! let report = romux::inspect(&source, &romux::InspectOptions::default())?;
//! let caps = romux::capabilities(&source, &romux::OperationContext::default())?;
//! println!("{:?} {:?} {}", probe.format, report.info.title, caps.entries.len());
//! # Ok(()) }
//! ```
//!
//! Console modules are feature-gated (`switch`, `ps4`, `3ds` (module `n3ds`), `wii`, `wiiu`,
//! `psp`, `vita`, `xbox`, `n64`, `snes`, `disc`); selecting one never pulls in another
//! platform backend. The console-agnostic core (sources, errors, model, capabilities,
//! registry, safe output, `binary`, `crypto`, `compression`) lives at the crate root.
//!
//! Every mutation has a `plan()` step returning an immutable [`TransformPlan`] (suitable for
//! dry runs) before anything is written. Outputs are staged next to the target and renamed
//! into place only after verification; inputs are never modified.

// Shared byte-level toolkit; which helpers a build uses depends on the enabled consoles.
#[cfg_attr(not(feature = "all-formats"), allow(dead_code))]
mod binary;
mod capability;
pub mod compression;
mod copy;
pub mod crypto;
mod error;
mod filter;
mod format;
mod job;
mod keys;
mod model;
mod output;
#[doc(hidden)]
pub mod path;
mod plan;
mod reader;
mod registry;
mod source;
mod verify;

pub use capability::{
    Availability, CapabilityEntry, CapabilitySet, ConversionEdge, ConversionKind, FormatDescriptor, Operation, OperationSupport,
    OutputGuarantee, Requirement, Support,
};
pub use copy::{ExtractReport, SkippedEntry, copy_all, copy_range, extract_to_dir};
pub use error::{Diagnostic, Error, ErrorCode, ErrorContext, Result, ResultExt, Severity, exit};
pub use format::{Confidence, FormatId, NestedProbe, Platform, ProbeEvidence, ProbeLimits, ProbeResult};
pub use job::{ByteProgress, CancelToken, IoPolicy, JobContext, NoProgress, Phase, ProgressEvent, ProgressSink, ResourceLimits};
pub use keys::{KeyProvider, NoKeys, SecretBytes};
pub use model::{
    ContentCategory, ContentGraph, ContentNode, EntryId, HashValue, MetaValue, Metadata, NodeKind, PackageInfo, Relation, RelationKind,
    Sizes, Span, TitleRecord, TitleRole, hex, parse_hex,
};
pub use output::{AtomicFile, ExtractedFile, SafeOutputDir, check_output_target};
pub use plan::{ClosurePlan, OperationReport, OutputRecord, PlanFn, PlanInput, PlanOutput, PlannedOperation, TransformPlan};
pub use reader::{Backend, ConvertRequest, EntryIter, NodeTable, OpenContext, PackageReader};
pub use registry::Registry;
pub use source::{
    ConcatSource, DataSource, FileSource, MemorySource, SharedSource, SourceIdentity, SourceReader, SubSource, ZeroSource, check_range,
    open_file, read_array, read_prefix, read_vec,
};
pub use verify::{Check, CheckLevel, CheckStatus, VerifyLevel, VerifyReport, VerifySummary};

// Console backends (feature-gated).
#[cfg(feature = "disc")]
pub mod disc;
#[cfg(feature = "3ds")]
pub mod n3ds;
#[cfg(feature = "n64")]
pub mod n64;
#[cfg(feature = "ps4")]
pub mod ps4;
#[cfg(feature = "psp")]
pub mod psp;
#[cfg(feature = "snes")]
pub mod snes;
#[cfg(feature = "switch")]
pub mod switch;
#[cfg(feature = "vita")]
pub mod vita;
#[cfg(feature = "wii")]
pub mod wii;
#[cfg(feature = "wiiu")]
pub mod wiiu;
#[cfg(feature = "xbox")]
pub mod xbox;

/// Alias used in API docs: the context passed to capability and open calls.
pub type OperationContext = OpenContext;

pub mod matrix;
mod scan;

pub use filter::glob_match;
pub use scan::{ScanOptions, ScanReport, scan};

use serde::Serialize;
use std::path::Path;
use std::sync::OnceLock;

/// Build a registry containing every backend compiled into this build.
pub fn build_registry() -> Registry {
    #[allow(unused_mut)]
    let mut r = Registry::new();
    #[cfg(feature = "switch")]
    r.register(Box::new(switch::SwitchBackend));
    #[cfg(feature = "ps4")]
    r.register(Box::new(ps4::Ps4Backend));
    #[cfg(feature = "3ds")]
    r.register(Box::new(n3ds::N3dsBackend));
    #[cfg(feature = "wii")]
    r.register(Box::new(wii::WiiBackend));
    #[cfg(feature = "wiiu")]
    r.register(Box::new(wiiu::WiiUBackend));
    #[cfg(feature = "psp")]
    r.register(Box::new(psp::PspBackend));
    #[cfg(feature = "vita")]
    r.register(Box::new(vita::VitaBackend));
    #[cfg(feature = "xbox")]
    r.register(Box::new(xbox::XboxBackend));
    #[cfg(feature = "n64")]
    r.register(Box::new(n64::N64Backend));
    #[cfg(feature = "snes")]
    r.register(Box::new(snes::SnesBackend));
    #[cfg(feature = "disc")]
    r.register(Box::new(disc::DiscBackend));
    r
}

/// The process-wide registry of compiled backends.
pub fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(build_registry)
}

/// Open a file as a read-only random-access source.
pub fn open(path: impl AsRef<Path>) -> Result<SharedSource> {
    open_file(path)
}

/// Identify the format(s) of a source (bounded, non-destructive, never decrypts).
pub fn probe(source: &SharedSource) -> Result<ProbeResult> {
    registry().probe(source.as_ref(), &ProbeLimits::default())
}

/// Probe including recognised child formats up to `limits.max_depth`.
pub fn probe_nested(source: &SharedSource, limits: &ProbeLimits, ctx: &OpenContext) -> Result<ProbeResult> {
    registry().probe_nested(source.clone(), limits, ctx)
}

/// Open the best-matching reader.
pub fn open_reader(source: &SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
    registry().open(source.clone(), ctx)
}

/// Capabilities of this source in this context.
pub fn capabilities(source: &SharedSource, ctx: &OpenContext) -> Result<CapabilitySet> {
    registry().capabilities(source.clone(), ctx)
}

/// Every format compiled into this build.
pub fn supported_formats() -> Vec<FormatDescriptor> {
    registry().supported_formats()
}

/// Options for [`inspect`].
#[derive(Clone, Default)]
pub struct InspectOptions {
    pub context: OpenContext,
    /// Also probe nested formats.
    pub deep: bool,
    /// Force a format instead of probing.
    pub format: Option<FormatId>,
}

/// Result of [`inspect`].
#[derive(Debug, Clone, Serialize)]
pub struct InspectReport {
    pub probe: ProbeResult,
    pub info: PackageInfo,
    pub graph: ContentGraph,
    pub entry_count: usize,
    pub capabilities: CapabilitySet,
}

/// Inspect a source: probe, open, and collect metadata, content graph and capabilities.
pub fn inspect(source: &SharedSource, opts: &InspectOptions) -> Result<InspectReport> {
    let limits = ProbeLimits::default();
    let probe = if opts.deep { probe_nested(source, &limits, &opts.context)? } else { probe(source)? };
    let reader = match opts.format {
        Some(f) => registry().open_as(f, source.clone(), &opts.context)?,
        None => registry().open(source.clone(), &opts.context)?,
    };
    let entry_count = reader.entries()?.count();
    Ok(InspectReport { info: reader.info()?, graph: reader.content_graph()?, entry_count, capabilities: reader.capabilities()?, probe })
}

/// Extract entries of a source into a sandboxed directory.
pub fn extract(
    source: &SharedSource,
    ctx: &OpenContext,
    output: impl AsRef<Path>,
    filters: &[String],
    job: &JobContext,
) -> Result<ExtractReport> {
    let reader = registry().open(source.clone(), ctx)?;
    let out = SafeOutputDir::create(output, &job.io)?;
    extract_to_dir(reader.as_ref(), &out, filters, job)
}

/// Verify a source at the requested level.
pub fn verify(source: &SharedSource, ctx: &OpenContext, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
    registry().open(source.clone(), ctx)?.verify(level, job)
}

/// Plan a conversion along a declared edge of the conversion graph.
pub fn plan_convert(
    input: impl AsRef<Path>,
    to: FormatId,
    output: impl AsRef<Path>,
    ctx: &OpenContext,
    options: std::collections::BTreeMap<String, String>,
) -> Result<Box<dyn PlannedOperation>> {
    let input = input.as_ref().to_path_buf();
    let source = open(&input)?;
    let from = probe(&source)?.format.ok_or_else(|| Error::new(ErrorCode::UnknownFormat, "input format not recognised"))?;
    registry().plan_convert(ConvertRequest { input, source, from, to, output: output.as_ref().to_path_buf(), ctx: ctx.clone(), options })
}

/// Load a key file into a shareable provider.
pub fn load_keys(path: impl AsRef<Path>) -> Result<std::sync::Arc<dyn KeyProvider>> {
    Ok(std::sync::Arc::new(crypto::KeyFile::load(path)?))
}

/// Serialize any report to pretty JSON (feature `json`).
#[cfg(feature = "json")]
pub fn to_json<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string_pretty(v).map_err(|e| Error::internal(format!("JSON serialization failed: {e}")))
}
