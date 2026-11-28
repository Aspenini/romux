//! `romux` command-line interface. Argument parsing, policy selection, progress display
//! and output formatting only — all format logic lives in the library crates.

mod output;

use clap::{Args, Parser, Subcommand, ValueEnum};
use output::{Envelope, Printer};
use romux::{CancelToken, Error, ErrorCode, FormatId, IoPolicy, JobContext, OpenContext, PlannedOperation, Result, VerifyLevel, exit};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "romux", version, about = "Inspect, extract, verify, bundle, convert and compress console game packages", long_about = None)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct Global {
    /// Emit a machine-readable JSON result on stdout (progress stays on stderr).
    #[arg(long, global = true)]
    json: bool,
    /// Suppress progress and non-essential output.
    #[arg(long, short, global = true)]
    quiet: bool,
    /// More detail in human-readable output.
    #[arg(long, short, global = true)]
    verbose: bool,
    /// Colour output.
    #[arg(long, value_enum, default_value_t = ColorMode::Auto, global = true)]
    color: ColorMode,
    /// Plan and report without writing anything.
    #[arg(long, global = true)]
    dry_run: bool,
    /// Allow replacing existing outputs (inputs are never overwritten).
    #[arg(long, global = true)]
    overwrite: bool,
    /// Worker threads for parallel chunk work.
    #[arg(long, global = true, default_value_t = 1)]
    jobs: usize,
    /// Scratch directory for temporary data.
    #[arg(long, global = true)]
    temp_dir: Option<PathBuf>,
    /// Memory budget, e.g. 512M or 2G.
    #[arg(long, global = true)]
    max_memory: Option<String>,
    /// User-supplied key file (`name = hex` lines). Only consulted by operations that need keys.
    #[arg(long, global = true)]
    key_file: Option<PathBuf>,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Copy, Clone, ValueEnum)]
enum Level {
    Structure,
    Content,
    Authenticity,
    All,
}

impl From<Level> for VerifyLevel {
    fn from(l: Level) -> Self {
        match l {
            Level::Structure => VerifyLevel::Structure,
            Level::Content => VerifyLevel::Content,
            Level::Authenticity => VerifyLevel::Authenticity,
            Level::All => VerifyLevel::All,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// List compiled formats and their capabilities.
    Formats {
        /// Render the capability matrix as Markdown (docs/format-support.md).
        #[arg(long)]
        markdown: bool,
        /// Show the conversion graph.
        #[arg(long)]
        conversions: bool,
    },
    /// Identify formats with evidence.
    Probe {
        input: PathBuf,
        /// Also detect nested formats.
        #[arg(long)]
        deep: bool,
    },
    /// Show container, title, versions and relationships.
    Inspect(InspectArgs),
    /// Enumerate files, partitions and embedded content.
    List {
        input: PathBuf,
        /// Include nested formats' entries (as reported by nested probing).
        #[arg(long)]
        recursive: bool,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long)]
        limit: Option<usize>,
        /// Force a format ID instead of probing.
        #[arg(long = "as")]
        as_format: Option<String>,
    },
    /// Write selected content to an output directory.
    Extract(ExtractArgs),
    /// Check structure, hashes and (when possible) signatures.
    Verify {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Level::Content)]
        level: Level,
        #[arg(long = "as")]
        as_format: Option<String>,
    },
    /// Show operations available for a file in the current context.
    Capabilities { input: PathBuf },
    /// Inspect a folder and group recognised files (report only).
    Scan {
        directory: PathBuf,
        #[arg(long)]
        recursive: bool,
        /// Hash files for deduplication.
        #[arg(long)]
        hash: bool,
    },
    /// Convert along a declared edge of the conversion graph.
    Convert {
        input: PathBuf,
        /// Target format ID (see `romux formats --conversions`).
        #[arg(long)]
        format: String,
        #[arg(long, short)]
        output: PathBuf,
        /// Edge-specific options, e.g. --option level=19
        #[arg(long = "option")]
        options: Vec<String>,
    },
    /// Nintendo Switch operations.
    #[command(subcommand)]
    Switch(SwitchCmd),
    /// PlayStation 4 operations.
    #[command(subcommand)]
    Ps4(SimpleCmd),
    /// Nintendo 3DS operations.
    #[command(name = "3ds", subcommand)]
    N3ds(ConvCmd),
    /// GameCube / Wii operations.
    #[command(subcommand)]
    Wii(ConvCmd),
    /// Wii U operations.
    #[command(subcommand)]
    Wiiu(WiiuCmd),
    /// PSP operations.
    #[command(subcommand)]
    Psp(ConvCmd),
    /// PS Vita operations.
    #[command(subcommand)]
    Vita(ConvCmd),
    /// Original Xbox and Xbox 360 operations.
    #[command(subcommand)]
    Xbox(ConvCmd),
    /// Nintendo 64 operations.
    #[command(subcommand)]
    N64(ConvCmd),
    /// Super Nintendo operations.
    #[command(subcommand)]
    Snes(ConvCmd),
    /// Generic disc operations (ISO9660, CUE/BIN, CHD).
    #[command(subcommand)]
    Disc(ConvCmd),
}

#[derive(Args)]
struct InspectArgs {
    input: PathBuf,
    #[arg(long)]
    deep: bool,
    #[arg(long = "as")]
    as_format: Option<String>,
}

#[derive(Args)]
struct ExtractArgs {
    input: PathBuf,
    #[arg(long, short)]
    output: PathBuf,
    /// Glob filter on logical paths (repeatable): `*`, `?`, `**`.
    #[arg(long)]
    filter: Vec<String>,
    #[arg(long = "as")]
    as_format: Option<String>,
}

#[derive(Subcommand)]
enum SimpleCmd {
    Inspect(InspectArgs),
    Extract(ExtractArgs),
    Verify {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Level::Content)]
        level: Level,
    },
}

#[derive(Subcommand)]
enum ConvCmd {
    Inspect(InspectArgs),
    Extract(ExtractArgs),
    Verify {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Level::Content)]
        level: Level,
    },
    /// Convert to a target (short name such as `rvz`, `wbfs`, `iso`, `cso`, `chd`, `cue`, `cia`, `xiso`, or a format ID).
    Convert {
        input: PathBuf,
        #[arg(long)]
        format: String,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long = "option")]
        options: Vec<String>,
    },
    /// Compress (CSO, CHD, RVZ, WUX ...).
    Compress {
        input: PathBuf,
        #[arg(long)]
        format: Option<String>,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long = "option")]
        options: Vec<String>,
    },
    /// Restore a compressed image.
    Decompress {
        input: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long)]
        format: Option<String>,
    },
    /// Build a container from a directory (ISO9660, XISO, VPK, U8 as supported).
    Repack {
        directory: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
        /// Volume label (ISO9660).
        #[arg(long, default_value = "ROMUX")]
        label: String,
        /// Container format where a platform offers several (`iso` or `zar` for disc, `u8` for wii).
        #[arg(long)]
        format: Option<String>,
    },
}

#[derive(Subcommand)]
enum WiiuCmd {
    Inspect(InspectArgs),
    Extract(ExtractArgs),
    Verify {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Level::Content)]
        level: Level,
    },
    Compress {
        input: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
    },
    Decompress {
        input: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Overlay a decrypted update tree onto a decrypted base tree.
    ApplyUpdate {
        base: PathBuf,
        update: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum SwitchCmd {
    Inspect(InspectArgs),
    Extract(ExtractArgs),
    Verify {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Level::Content)]
        level: Level,
    },
    /// Keep base, update and DLC as separate content sets in one container
    /// (nsp, xci, nsz, xcz), or decrypt them into one NX / NUP archive (nx, nup; keys required).
    Bundle {
        base: PathBuf,
        #[arg(long)]
        update: Vec<PathBuf>,
        #[arg(long)]
        dlc: Vec<PathBuf>,
        /// nsp, xci, nsz, xcz, nx or nup.
        #[arg(long, default_value = "nsp")]
        format: String,
        /// Zstandard level for nx/nup (default 3; 0 stores uncompressed).
        #[arg(long)]
        level: Option<i32>,
        #[arg(long, short)]
        output: PathBuf,
        /// Rewrite rights-ID NCA headers to standard crypto for XCI/XCZ (signatures become invalid).
        #[arg(long)]
        convert_rights: bool,
        /// Accept roles inferred only from ticket IDs.
        #[arg(long)]
        allow_unverified: bool,
    },
    /// Pack an already-decrypted dump folder (base/, updates/<version>/, dlc/<id>/<n>/,
    /// or a folder holding exefs/ and romfs/) into a NUP container. No keys needed.
    PackNup {
        directory: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
        /// Zstandard level (default 3; 0 stores uncompressed).
        #[arg(long)]
        level: Option<i32>,
        /// Base title ID (16 hex digits), overriding the one read from exefs/main.npdm.
        #[arg(long)]
        title_id: Option<String>,
    },
    /// Reconstruct an updated derived content tree (BKTR), not a package.
    ApplyUpdate {
        base: PathBuf,
        update: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Export each content set as its own package.
    Split {
        bundle: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
    },
    /// NSP ⇄ XCI, NSZ ⇄ XCZ, or any of them → decrypted NX / NUP (nx, nup; keys required).
    Convert {
        input: PathBuf,
        /// nsp, xci, nsz, xcz, nx or nup.
        #[arg(long)]
        format: String,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long)]
        convert_rights: bool,
        /// Zstandard level for nx/nup (default 3; 0 stores uncompressed).
        #[arg(long)]
        level: Option<i32>,
    },
    /// NSP→NSZ, XCI→XCZ.
    Compress {
        input: PathBuf,
        #[arg(long)]
        format: Option<String>,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long, default_value_t = 18)]
        level: i32,
        /// Block mode with 2^N-byte blocks.
        #[arg(long)]
        block: Option<u8>,
        /// Minimum NCA size to compress (bytes).
        #[arg(long, default_value_t = 1 << 20)]
        min_size: u64,
    },
    /// NSZ→NSP, XCZ→XCI.
    Decompress {
        input: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
    },
}

struct App {
    g: Global,
    printer: Printer,
    ctx: OpenContext,
    cancel: CancelToken,
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') => (&s[..s.len() - 1], 1 << 20),
        Some('G') => (&s[..s.len() - 1], 1 << 30),
        Some('T') => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().map(|n| n * mult).map_err(|_| Error::invalid_arg(format!("invalid size {s:?}")))
}

fn parse_options(opts: &[String]) -> Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    for o in opts {
        let (k, v) = o.split_once('=').ok_or_else(|| Error::invalid_arg(format!("option {o:?} must be key=value")))?;
        m.insert(k.trim().to_string(), v.trim().to_string());
    }
    Ok(m)
}

impl App {
    fn job(&self) -> Result<JobContext> {
        let mut limits = romux::ResourceLimits::default();
        if let Some(m) = &self.g.max_memory {
            limits.max_memory = parse_size(m)?;
        }
        Ok(JobContext::new()
            .with_cancel(self.cancel.clone())
            .with_progress(self.printer.progress_sink())
            .with_threads(self.g.jobs)
            .with_limits(limits)
            .with_io(IoPolicy { overwrite: self.g.overwrite, temp_dir: self.g.temp_dir.clone(), no_sync: false }))
    }

    fn resolve_format(&self, s: &str) -> Result<FormatId> {
        romux::registry().find_format(s).ok_or_else(|| {
            Error::new(ErrorCode::InvalidOutputFormat, format!("unknown or uncompiled format {s:?}"))
                .with_suggestion("run `romux formats` for the list")
        })
    }

    fn open_reader(&self, input: &Path, as_format: Option<&str>) -> Result<(romux::SharedSource, Box<dyn romux::PackageReader>)> {
        let src = romux::open(input)?;
        let r = match as_format {
            Some(f) => romux::registry().open_as(self.resolve_format(f)?, src.clone(), &self.ctx)?,
            None => romux::registry().open(src.clone(), &self.ctx)?,
        };
        Ok((src, r))
    }

    /// Run or describe a planned operation (dry run).
    fn run_plan(&self, name: &str, plan: Box<dyn PlannedOperation>) -> Result<i32> {
        let mut env = Envelope::new(name);
        env.inputs = plan.plan().input_paths();
        if self.g.dry_run {
            env.status = "dry-run".into();
            env.outputs = plan.plan().outputs.iter().map(|o| serde_json::json!({"path": o.path, "format": o.format, "kind": o.kind, "category": o.category, "estimated_size": o.estimated_size})).collect();
            env.metadata.insert("plan".into(), serde_json::to_value(plan.plan()).unwrap_or_default());
            env.warnings = plan.plan().warnings.clone();
            self.printer.plan(plan.plan(), &env);
            return Ok(exit::SUCCESS);
        }
        let job = self.job()?;
        let rep = plan.execute(&job)?;
        env.outputs = rep.outputs.iter().map(|o| serde_json::to_value(o).unwrap_or_default()).collect();
        env.warnings = rep.warnings.clone();
        env.verification = rep.verification.as_ref().map(|v| serde_json::to_value(v).unwrap_or_default());
        for (k, v) in &rep.metadata {
            env.metadata.insert(k.clone(), serde_json::to_value(v).unwrap_or_default());
        }
        env.diagnostics = rep.diagnostics.iter().map(|d| serde_json::to_value(d).unwrap_or_default()).collect();
        self.printer.report(&rep, &env);
        Ok(exit::SUCCESS)
    }

    fn inspect(&self, a: &InspectArgs, platform: Option<romux::Platform>) -> Result<i32> {
        let src = romux::open(&a.input)?;
        let opts = romux::InspectOptions {
            context: self.ctx.clone(),
            deep: a.deep,
            format: a.as_format.as_deref().map(|f| self.resolve_format(f)).transpose()?,
        };
        let rep = romux::inspect(&src, &opts)?;
        check_platform(rep.info.platform, platform)?;
        let mut env = Envelope::new("inspect");
        env.inputs = vec![a.input.clone()];
        env.format = Some(rep.info.format.to_string());
        env.metadata.insert("probe".into(), serde_json::to_value(&rep.probe).unwrap_or_default());
        env.metadata.insert("package".into(), serde_json::to_value(&rep.info).unwrap_or_default());
        env.metadata.insert("content_graph".into(), serde_json::to_value(&rep.graph).unwrap_or_default());
        env.metadata.insert("capabilities".into(), serde_json::to_value(&rep.capabilities).unwrap_or_default());
        env.metadata.insert("entry_count".into(), rep.entry_count.into());
        env.warnings = rep.info.warnings.clone();
        self.printer.inspect(&rep, &env);
        Ok(exit::SUCCESS)
    }

    fn extract(&self, a: &ExtractArgs, platform: Option<romux::Platform>) -> Result<i32> {
        let (_, r) = self.open_reader(&a.input, a.as_format.as_deref())?;
        check_platform(r.info()?.platform, platform)?;
        let mut env = Envelope::new("extract");
        env.inputs = vec![a.input.clone()];
        env.format = Some(r.format().to_string());
        if self.g.dry_run {
            let mut n = 0u64;
            let mut bytes = 0u64;
            let mut skipped = 0u64;
            for e in r.entries()? {
                let e = e?;
                if !a.filter.is_empty() && !a.filter.iter().any(|f| romux::glob_match(f, &e.path)) {
                    continue;
                }
                if matches!(e.kind, romux::NodeKind::Directory | romux::NodeKind::Partition) {
                    continue;
                }
                if e.readable {
                    n += 1;
                    bytes += e.length;
                } else {
                    skipped += 1;
                }
            }
            env.status = "dry-run".into();
            env.metadata.insert("files".into(), n.into());
            env.metadata.insert("bytes".into(), bytes.into());
            env.metadata.insert("skipped".into(), skipped.into());
            env.outputs = vec![serde_json::json!({"path": a.output, "kind": "directory"})];
            self.printer.message(
                &format!("would extract {n} files ({bytes} bytes) to {}; {skipped} entries not accessible", a.output.display()),
                &env,
            );
            return Ok(exit::SUCCESS);
        }
        let job = self.job()?;
        let out = romux::SafeOutputDir::create(&a.output, &job.io)?;
        let rep = romux::extract_to_dir(r.as_ref(), &out, &a.filter, &job)?;
        env.outputs = vec![serde_json::json!({"path": a.output, "kind": "directory", "files": rep.files, "bytes": rep.bytes})];
        env.metadata.insert("skipped".into(), serde_json::to_value(&rep.skipped).unwrap_or_default());
        for s in &rep.skipped {
            env.warnings.push(format!("skipped {}: {}", s.path, s.reason));
        }
        self.printer.message(
            &format!(
                "extracted {} files ({} bytes) to {}{}",
                rep.files,
                rep.bytes,
                a.output.display(),
                if rep.skipped.is_empty() { String::new() } else { format!("; {} skipped (see warnings)", rep.skipped.len()) }
            ),
            &env,
        );
        Ok(exit::SUCCESS)
    }

    fn verify(&self, input: &Path, level: Level, as_format: Option<&str>, platform: Option<romux::Platform>) -> Result<i32> {
        let (_, r) = self.open_reader(input, as_format)?;
        check_platform(r.info()?.platform, platform)?;
        let job = self.job()?;
        let rep = r.verify(level.into(), &job)?;
        let mut env = Envelope::new("verify");
        env.inputs = vec![input.to_path_buf()];
        env.format = Some(r.format().to_string());
        env.verification = Some(serde_json::to_value(&rep).unwrap_or_default());
        env.metadata.insert("summary".into(), serde_json::to_value(rep.summary()).unwrap_or_default());
        let ok = rep.no_failures();
        if !ok {
            env.status = "verification_failed".into();
        }
        self.printer.verify(&rep, &env);
        Ok(if ok { exit::SUCCESS } else { exit::VERIFICATION_FAILED })
    }

    fn convert_generic(&self, input: &Path, to: &str, output: &Path, options: &[String]) -> Result<i32> {
        let mut opts = parse_options(options)?;
        if self.g.overwrite {
            opts.insert("overwrite".into(), "true".into());
        }
        let to = self.resolve_format(to)?;
        let plan = romux::plan_convert(input, to, output, &self.ctx, opts)?;
        self.run_plan("convert", plan)
    }

    fn short_target(&self, input: &Path, short: &str, compress: bool) -> Result<String> {
        if short.contains('.') {
            return Ok(short.to_string());
        }
        let src = romux::open(input)?;
        let from = romux::probe(&src)?.format.ok_or_else(|| Error::new(ErrorCode::UnknownFormat, "input format not recognised"))?;
        let edges: Vec<_> = romux::registry().conversions().into_iter().filter(|e| e.from == from).collect();
        let m: Vec<_> = edges
            .iter()
            .filter(|e| e.to.as_str().rsplit('.').next() == Some(short) || (short == "iso" && e.to.as_str().ends_with("iso9660")))
            .filter(|e| !compress || e.kind == romux::ConversionKind::Compress)
            .collect();
        match m.as_slice() {
            [one] => Ok(one.to.to_string()),
            [] => Err(Error::new(ErrorCode::InvalidOutputFormat, format!("no declared conversion from {from} to {short:?}"))
                .with_suggestion(format!("valid targets: {}", edges.iter().map(|e| e.to.to_string()).collect::<Vec<_>>().join(", ")))),
            _ => Err(Error::new(ErrorCode::AmbiguousFormat, format!("{short:?} matches several targets; use a format ID"))),
        }
    }

    fn conv(&self, c: &ConvCmd, platform: romux::Platform) -> Result<i32> {
        match c {
            ConvCmd::Inspect(a) => self.inspect(a, Some(platform)),
            ConvCmd::Extract(a) => self.extract(a, Some(platform)),
            ConvCmd::Verify { input, level } => self.verify(input, *level, None, Some(platform)),
            ConvCmd::Convert { input, format, output, options } => {
                let t = self.short_target(input, format, false)?;
                self.convert_generic(input, &t, output, options)
            }
            ConvCmd::Compress { input, format, output, options } => {
                let src = romux::open(input)?;
                let from = romux::probe(&src)?.format.ok_or_else(|| Error::new(ErrorCode::UnknownFormat, "input format not recognised"))?;
                let t = match format {
                    Some(f) => self.short_target(input, f, true)?,
                    None => {
                        let mut e: Vec<_> = romux::registry()
                            .conversions()
                            .into_iter()
                            .filter(|e| e.from == from && e.kind == romux::ConversionKind::Compress)
                            .collect();
                        if e.len() > 1 {
                            let own: Vec<_> = e
                                .iter()
                                .filter(|x| platform_prefixes(platform).iter().any(|p| x.to.as_str().starts_with(p)))
                                .cloned()
                                .collect();
                            if !own.is_empty() {
                                e = own;
                            }
                        }
                        match e.as_slice() {
                            [one] => one.to.to_string(),
                            [] => return Err(Error::unsupported(format!("{from} has no declared compression"))),
                            many => {
                                return Err(Error::new(
                                    ErrorCode::AmbiguousFormat,
                                    format!(
                                        "choose --format among {}",
                                        many.iter().map(|e| e.to.to_string()).collect::<Vec<_>>().join(", ")
                                    ),
                                ));
                            }
                        }
                    }
                };
                self.convert_generic(input, &t, output, options)
            }
            ConvCmd::Decompress { input, output, format } => {
                let src = romux::open(input)?;
                let from = romux::probe(&src)?.format.ok_or_else(|| Error::new(ErrorCode::UnknownFormat, "input format not recognised"))?;
                let edges: Vec<_> = romux::registry()
                    .conversions()
                    .into_iter()
                    .filter(|e| e.from == from && e.kind == romux::ConversionKind::Decompress)
                    .collect();
                let t = match (format, edges.as_slice()) {
                    (Some(f), _) => self.short_target(input, f, false)?,
                    (None, [one]) => one.to.to_string(),
                    (None, []) => return Err(Error::unsupported(format!("{from} has no declared decompression"))),
                    (None, many) => {
                        // Prefer the target matching the disc content (e.g. CD → CUE).
                        let r = romux::registry().open(src.clone(), &self.ctx)?;
                        let media = r.info()?.fields.get("media").and_then(|m| m.as_str().map(String::from));
                        let pick = many
                            .iter()
                            .find(|e| media.as_deref() == Some("cd") && e.to.as_str() == "disc.cue")
                            .or_else(|| many.iter().find(|e| media.as_deref() != Some("cd") && e.to.as_str() != "disc.cue"));
                        pick.map(|e| e.to.to_string()).ok_or_else(|| Error::new(ErrorCode::AmbiguousFormat, "choose --format"))?
                    }
                };
                self.convert_generic(input, &t, output, &[])
            }
            ConvCmd::Repack { directory, output, label, format } => {
                let policy = IoPolicy { overwrite: self.g.overwrite, ..Default::default() };
                let plan: Box<dyn PlannedOperation> = match platform {
                    romux::Platform::Generic if format.as_deref() == Some("zar") => {
                        romux::disc::plan_repack_zar(directory, output, 19, &policy)?
                    }
                    romux::Platform::Generic | romux::Platform::Psp => romux::disc::plan_repack_iso(directory, output, label, &policy)?,
                    romux::Platform::Xbox => romux::xbox::plan_repack_xiso(directory, output, &policy)?,
                    romux::Platform::Vita => romux::vita::plan_repack_vpk(directory, output, &policy)?,
                    romux::Platform::Wii if format.as_deref().unwrap_or("u8") == "u8" => {
                        romux::wii::plan_repack_u8(directory, output, &policy)?
                    }
                    _ => return Err(Error::unsupported("repack is not offered for this platform")),
                };
                self.run_plan("repack", plan)
            }
        }
    }

    fn switch(&self, c: &SwitchCmd) -> Result<i32> {
        use romux::switch::*;
        match c {
            SwitchCmd::Inspect(a) => self.inspect(a, Some(romux::Platform::Switch)),
            SwitchCmd::Extract(a) => self.extract(a, Some(romux::Platform::Switch)),
            SwitchCmd::Verify { input, level } => self.verify(input, *level, None, Some(romux::Platform::Switch)),
            SwitchCmd::Bundle { base, update, dlc, format, output, level, .. } if ArchiveFormat::parse(format).is_some() => {
                let mut b =
                    ArchiveBuilder::new(ArchiveFormat::parse(format).unwrap_or(ArchiveFormat::Nx)).input(base).context(self.ctx.clone());
                for p in update.iter().chain(dlc) {
                    b = b.input(p);
                }
                if let Some(l) = level {
                    b = b.level(*l);
                }
                self.run_plan("bundle", b.plan()?.into_planned(output.clone()))
            }
            SwitchCmd::Bundle { base, update, dlc, format, output, convert_rights, allow_unverified, .. } => {
                let mut b = BundleBuilder::new(base)
                    .output_format(PackageFormat::parse(format)?)
                    .context(self.ctx.clone())
                    .convert_rights(*convert_rights)
                    .allow_unverified_relationships(*allow_unverified);
                for u in update {
                    b = b.update(u);
                }
                for d in dlc {
                    b = b.dlc(d);
                }
                self.run_plan("bundle", b.plan()?.into_planned(output.clone()))
            }
            SwitchCmd::PackNup { directory, output, level, title_id } => {
                let mut b = ArchiveBuilder::new(ArchiveFormat::Nup)
                    .input(directory)
                    .context(self.ctx.clone())
                    .progress(self.printer.progress_sink());
                if let Some(l) = level {
                    b = b.level(*l);
                }
                if let Some(t) = title_id {
                    let t = t.trim_start_matches("0x");
                    let id = u64::from_str_radix(t, 16)
                        .ok()
                        .filter(|_| t.len() == 16)
                        .ok_or_else(|| Error::invalid_arg(format!("title ID {t:?} must be 16 hex digits")))?;
                    b = b.title_id(id);
                }
                self.run_plan("pack-nup", b.plan()?.into_planned(output.clone()))
            }
            SwitchCmd::ApplyUpdate { base, update, output } => {
                let plan = ApplyUpdateBuilder::new(base, update).output_directory(output).context(self.ctx.clone()).plan()?;
                self.run_plan("apply-update", Box::new(ApplyAdapter(plan)))
            }
            SwitchCmd::Split { bundle, output } => {
                let plan = SplitBuilder::new(bundle).context(self.ctx.clone()).plan()?;
                self.run_plan("split", Box::new(SplitAdapter(plan, output.clone())))
            }
            SwitchCmd::Convert { input, format, output, level, .. } if ArchiveFormat::parse(format).is_some() => {
                let mut b =
                    ArchiveBuilder::new(ArchiveFormat::parse(format).unwrap_or(ArchiveFormat::Nx)).input(input).context(self.ctx.clone());
                if let Some(l) = level {
                    b = b.level(*l);
                }
                self.run_plan("convert", b.plan()?.into_planned(output.clone()))
            }
            SwitchCmd::Convert { input, format, output, convert_rights, .. } => {
                let plan = ConvertBuilder::new(input, PackageFormat::parse(format)?)
                    .convert_rights(*convert_rights)
                    .context(self.ctx.clone())
                    .plan()?;
                self.run_plan("convert", plan.into_planned(output.clone()))
            }
            SwitchCmd::Compress { input, format, output, level, block, min_size } => {
                let mut b = CompressBuilder::new(input).level(*level).block_exponent(*block).min_size(*min_size).context(self.ctx.clone());
                if let Some(f) = format {
                    b = b.target(PackageFormat::parse(f)?);
                }
                self.run_plan("compress", b.plan()?.into_planned(output.clone()))
            }
            SwitchCmd::Decompress { input, output } => {
                let plan = DecompressBuilder::new(input).context(self.ctx.clone()).plan()?;
                self.run_plan("decompress", plan.into_planned(output.clone()))
            }
        }
    }

    fn wiiu(&self, c: &WiiuCmd) -> Result<i32> {
        let p = Some(romux::Platform::WiiU);
        match c {
            WiiuCmd::Inspect(a) => self.inspect(a, p),
            WiiuCmd::Extract(a) => self.extract(a, p),
            WiiuCmd::Verify { input, level } => self.verify(input, *level, None, p),
            WiiuCmd::Compress { input, output } => self.convert_generic(input, "wiiu.wux", output, &[]),
            WiiuCmd::Decompress { input, output } => self.convert_generic(input, "wiiu.wud", output, &[]),
            WiiuCmd::ApplyUpdate { base, update, output } => {
                let policy = IoPolicy { overwrite: self.g.overwrite, ..Default::default() };
                self.run_plan("apply-update", romux::wiiu::plan_apply_update_tree(base, update, output, &policy)?)
            }
        }
    }

    fn run(&self, cmd: &Command) -> Result<i32> {
        match cmd {
            Command::Formats { markdown, conversions } => {
                let formats = romux::supported_formats();
                let conv = romux::registry().conversions();
                if *markdown {
                    print!("{}", romux::matrix::markdown(&formats, &conv));
                    return Ok(exit::SUCCESS);
                }
                let mut env = Envelope::new("formats");
                env.metadata.insert("formats".into(), serde_json::to_value(&formats).unwrap_or_default());
                env.metadata.insert("conversions".into(), serde_json::to_value(&conv).unwrap_or_default());
                env.metadata.insert("codecs".into(), serde_json::to_value(romux::compression::available_codecs()).unwrap_or_default());
                self.printer.formats(&formats, if *conversions { Some(&conv) } else { None }, &env);
                Ok(exit::SUCCESS)
            }
            Command::Probe { input, deep } => {
                let src = romux::open(input)?;
                let pr = if *deep { romux::probe_nested(&src, &romux::ProbeLimits::default(), &self.ctx)? } else { romux::probe(&src)? };
                let mut env = Envelope::new("probe");
                env.inputs = vec![input.clone()];
                env.format = pr.format.map(|f| f.to_string());
                env.metadata.insert("probe".into(), serde_json::to_value(&pr).unwrap_or_default());
                env.warnings = pr.warnings.clone();
                if pr.format.is_none() {
                    env.status = "unrecognized".into();
                }
                self.printer.probe(&pr, &env);
                Ok(if pr.format.is_some() { exit::SUCCESS } else { exit::UNSUPPORTED })
            }
            Command::Inspect(a) => self.inspect(a, None),
            Command::List { input, recursive, offset, limit, as_format } => {
                let (src, r) = self.open_reader(input, as_format.as_deref())?;
                let mut env = Envelope::new("list");
                env.inputs = vec![input.clone()];
                env.format = Some(r.format().to_string());
                let mut nodes = Vec::new();
                for (i, n) in r.entries()?.enumerate() {
                    if i < *offset {
                        continue;
                    }
                    if limit.is_some_and(|l| nodes.len() >= l) {
                        env.metadata.insert("truncated".into(), true.into());
                        break;
                    }
                    nodes.push(n?);
                }
                if *recursive {
                    let pr = romux::probe_nested(&src, &romux::ProbeLimits::default(), &self.ctx)?;
                    env.metadata.insert("nested".into(), serde_json::to_value(&pr.children).unwrap_or_default());
                }
                env.metadata.insert("entries".into(), serde_json::to_value(&nodes).unwrap_or_default());
                self.printer.list(&nodes, &env);
                Ok(exit::SUCCESS)
            }
            Command::Extract(a) => self.extract(a, None),
            Command::Verify { input, level, as_format } => self.verify(input, *level, as_format.as_deref(), None),
            Command::Capabilities { input } => {
                let src = romux::open(input)?;
                let caps = romux::capabilities(&src, &self.ctx)?;
                let mut env = Envelope::new("capabilities");
                env.inputs = vec![input.clone()];
                env.format = Some(caps.format.to_string());
                env.metadata.insert("capabilities".into(), serde_json::to_value(&caps).unwrap_or_default());
                self.printer.capabilities(&caps, &env);
                Ok(exit::SUCCESS)
            }
            Command::Scan { directory, recursive, hash } => {
                let job = self.job()?;
                let rep = romux::scan(
                    directory,
                    &romux::ScanOptions { recursive: *recursive, hash: *hash, context: self.ctx.clone(), max_hash_size: 0 },
                    &job,
                )?;
                let mut env = Envelope::new("scan");
                env.inputs = vec![directory.clone()];
                env.metadata.insert("scan".into(), serde_json::to_value(&rep).unwrap_or_default());
                self.printer.scan(&rep, &env);
                Ok(exit::SUCCESS)
            }
            Command::Convert { input, format, output, options } => self.convert_generic(input, format, output, options),
            Command::Switch(c) => self.switch(c),
            Command::Ps4(c) => match c {
                SimpleCmd::Inspect(a) => self.inspect(a, Some(romux::Platform::Ps4)),
                SimpleCmd::Extract(a) => self.extract(a, Some(romux::Platform::Ps4)),
                SimpleCmd::Verify { input, level } => self.verify(input, *level, None, Some(romux::Platform::Ps4)),
            },
            Command::N3ds(c) => self.conv(c, romux::Platform::N3ds),
            Command::Wii(c) => self.conv(c, romux::Platform::Wii),
            Command::Wiiu(c) => self.wiiu(c),
            Command::Psp(c) => self.conv(c, romux::Platform::Psp),
            Command::Vita(c) => self.conv(c, romux::Platform::Vita),
            Command::Xbox(c) => self.conv(c, romux::Platform::Xbox),
            Command::N64(c) => self.conv(c, romux::Platform::N64),
            Command::Snes(c) => self.conv(c, romux::Platform::Snes),
            Command::Disc(c) => self.conv(c, romux::Platform::Generic),
        }
    }
}

fn platform_prefixes(p: romux::Platform) -> &'static [&'static str] {
    match p {
        romux::Platform::Generic => &["disc."],
        romux::Platform::Psp => &["psp."],
        romux::Platform::Wii | romux::Platform::GameCube => &["wii.", "gamecube."],
        romux::Platform::WiiU => &["wiiu."],
        romux::Platform::N3ds => &["3ds."],
        romux::Platform::Vita => &["vita."],
        romux::Platform::Xbox | romux::Platform::Xbox360 => &["xbox.", "xbox360."],
        romux::Platform::N64 => &["n64."],
        romux::Platform::Snes => &["snes."],
        romux::Platform::Ps4 => &["ps4."],
        romux::Platform::Switch => &["switch."],
        _ => &[],
    }
}

fn check_platform(actual: romux::Platform, wanted: Option<romux::Platform>) -> Result<()> {
    match wanted {
        Some(w)
            if w != actual
                && !(w == romux::Platform::Wii && actual == romux::Platform::GameCube)
                && !(w == romux::Platform::Xbox && actual == romux::Platform::Xbox360) =>
        {
            Err(Error::invalid_arg(format!("input is a {actual} format, not {w}"))
                .with_suggestion("use the matching subcommand or the generic command"))
        }
        _ => Ok(()),
    }
}

struct ApplyAdapter(romux::switch::ApplyUpdatePlan);
impl PlannedOperation for ApplyAdapter {
    fn plan(&self) -> &romux::TransformPlan {
        self.0.describe()
    }
    fn execute(self: Box<Self>, job: &JobContext) -> Result<romux::OperationReport> {
        self.0.execute(job)
    }
}

struct SplitAdapter(romux::switch::SplitPlan, PathBuf);
impl PlannedOperation for SplitAdapter {
    fn plan(&self) -> &romux::TransformPlan {
        self.0.describe()
    }
    fn execute(self: Box<Self>, job: &JobContext) -> Result<romux::OperationReport> {
        let SplitAdapter(p, out) = *self;
        p.execute(out, job)
    }
}

fn main() {
    let cli = Cli::parse();
    let color = match cli.global.color {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => std::io::IsTerminal::is_terminal(&std::io::stdout()) && std::env::var_os("NO_COLOR").is_none(),
    };
    let printer = Printer::new(cli.global.json, cli.global.quiet, cli.global.verbose, color);
    let cancel = CancelToken::new();
    {
        let c = cancel.clone();
        let _ = ctrlc::set_handler(move || c.cancel());
    }
    let mut ctx = OpenContext::default();
    let code = (|| -> Result<i32> {
        if let Some(k) = &cli.global.key_file {
            ctx.keys = romux::load_keys(k)?;
        }
        if let Some(m) = &cli.global.max_memory {
            ctx.limits.max_memory = parse_size(m)?;
        }
        let app = App { g: cli.global.clone(), printer: printer.clone(), ctx, cancel };
        app.run(&cli.command)
    })();
    let code = match code {
        Ok(c) => c,
        Err(e) => {
            printer.error(&e, &command_name(&cli.command));
            e.code().exit_code()
        }
    };
    std::process::exit(code);
}

fn command_name(c: &Command) -> String {
    match c {
        Command::Formats { .. } => "formats",
        Command::Probe { .. } => "probe",
        Command::Inspect(_) => "inspect",
        Command::List { .. } => "list",
        Command::Extract(_) => "extract",
        Command::Verify { .. } => "verify",
        Command::Capabilities { .. } => "capabilities",
        Command::Scan { .. } => "scan",
        Command::Convert { .. } => "convert",
        Command::Switch(_) => "switch",
        Command::Ps4(_) => "ps4",
        Command::N3ds(_) => "3ds",
        Command::Wii(_) => "wii",
        Command::Wiiu(_) => "wiiu",
        Command::Psp(_) => "psp",
        Command::Vita(_) => "vita",
        Command::Xbox(_) => "xbox",
        Command::N64(_) => "n64",
        Command::Snes(_) => "snes",
        Command::Disc(_) => "disc",
    }
    .to_string()
}
