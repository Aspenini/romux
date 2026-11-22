//! Output formatting: stable JSON envelope on stdout, human text, progress on stderr.

use romux::{
    CapabilitySet, CheckStatus, ContentNode, ConversionEdge, Error, FormatDescriptor, InspectReport, OperationReport, ProbeResult,
    ProgressEvent, ProgressSink, ScanReport, TransformPlan, VerifyReport,
};
use serde::Serialize;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// JSON schema version of the CLI envelope. Bump on incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct Envelope {
    pub schema_version: u32,
    pub operation: String,
    pub status: String,
    pub inputs: Vec<PathBuf>,
    pub outputs: Vec<serde_json::Value>,
    pub format: Option<String>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub warnings: Vec<String>,
    pub verification: Option<serde_json::Value>,
    pub diagnostics: Vec<serde_json::Value>,
}

impl Envelope {
    pub fn new(op: &str) -> Self {
        Envelope {
            schema_version: SCHEMA_VERSION,
            operation: op.to_string(),
            status: "ok".into(),
            inputs: vec![],
            outputs: vec![],
            format: None,
            metadata: serde_json::Map::new(),
            warnings: vec![],
            verification: None,
            diagnostics: vec![],
        }
    }
}

#[derive(Clone)]
pub struct Printer {
    json: bool,
    quiet: bool,
    verbose: bool,
    color: bool,
    progress: Arc<StderrProgress>,
}

pub struct StderrProgress {
    enabled: bool,
    last: Mutex<Option<Instant>>,
}

impl ProgressSink for StderrProgress {
    fn report(&self, e: &ProgressEvent) {
        if !self.enabled {
            return;
        }
        let mut last = match self.last.lock() {
            Ok(l) => l,
            Err(_) => return,
        };
        let now = Instant::now();
        let done = e.total.is_some_and(|t| e.completed >= t);
        if !done && last.is_some_and(|t| now.duration_since(t) < Duration::from_millis(150)) {
            return;
        }
        *last = Some(now);
        let pct = match e.total {
            Some(t) if t > 0 => format!("{:>5.1}%", e.completed as f64 * 100.0 / t as f64),
            _ => "  ... ".into(),
        };
        let item = e.item.as_deref().map(|s| format!(" {}", truncate(s, 50))).unwrap_or_default();
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[2K[{}] {} {}{}", e.phase.as_str(), pct, human_bytes(e.completed), item);
        if done {
            let _ = writeln!(err);
        }
        let _ = err.flush();
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("…{}", s.chars().rev().take(n - 1).collect::<Vec<_>>().into_iter().rev().collect::<String>())
    }
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.2} {}", U[i]) }
}

impl Printer {
    pub fn new(json: bool, quiet: bool, verbose: bool, color: bool) -> Self {
        let enabled = !quiet && std::io::stderr().is_terminal();
        Printer { json, quiet, verbose, color, progress: Arc::new(StderrProgress { enabled, last: Mutex::new(None) }) }
    }

    pub fn progress_sink(&self) -> Arc<dyn ProgressSink> {
        self.progress.clone()
    }

    fn paint(&self, s: &str, code: &str) -> String {
        if self.color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }

    fn emit_json(&self, env: &Envelope) {
        if let Ok(s) = serde_json::to_string_pretty(env) {
            println!("{s}");
        }
    }

    fn warnings(&self, w: &[String]) {
        if self.quiet {
            return;
        }
        for x in w {
            eprintln!("{} {x}", self.paint("warning:", "33"));
        }
    }

    pub fn message(&self, msg: &str, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        if !self.quiet {
            println!("{msg}");
        }
        self.warnings(&env.warnings);
    }

    pub fn error(&self, e: &Error, op: &str) {
        if self.json {
            let mut env = Envelope::new(op);
            env.status = "error".into();
            env.diagnostics.push(serde_json::to_value(e.to_diagnostic()).unwrap_or_default());
            self.emit_json(&env);
            return;
        }
        eprintln!("{} {e}", self.paint("error:", "31;1"));
        if let Some(s) = e.suggestion() {
            eprintln!("  {} {s}", self.paint("hint:", "36"));
        }
    }

    pub fn probe(&self, pr: &ProbeResult, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        match pr.format {
            Some(f) => println!("{} {}", self.paint("format:", "1"), f),
            None if !pr.ambiguity.is_empty() => println!("{} ambiguous — {}", self.paint("format:", "1"), pr.ambiguity.join("; ")),
            None => println!("{} not recognised by any compiled backend", self.paint("format:", "1")),
        }
        for c in &pr.candidates {
            println!("  candidate {} ({:?}): {}", c.format, c.confidence, c.matched.join("; "));
            for w in &c.warnings {
                println!("    note: {w}");
            }
        }
        fn kids(c: &[romux::NestedProbe], depth: usize) {
            for k in c {
                println!("{}└ {} → {} ({:?})", "  ".repeat(depth + 1), k.path, k.format, k.confidence);
                kids(&k.children, depth + 1);
            }
        }
        kids(&pr.children, 0);
        self.warnings(&env.warnings);
    }

    pub fn inspect(&self, r: &InspectReport, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        let i = &r.info;
        let row = |k: &str, v: Option<String>| {
            if let Some(v) = v {
                println!("{:<14} {v}", self.paint(&format!("{k}:"), "1"));
            }
        };
        row("Format", Some(i.format.to_string()));
        row("Platform", Some(i.platform.to_string()));
        row("Title", i.title.clone());
        row("Title ID", i.title_id.clone());
        row("Product code", i.product_code.clone());
        row("Version", i.version.clone());
        row("Category", Some(format!("{:?}", i.category)));
        row("Region", i.region.clone());
        row("Size", Some(human_bytes(i.sizes.container)));
        row("Uncompressed", i.sizes.uncompressed.map(human_bytes));
        row("Encrypted", i.encrypted.map(|b| b.to_string()));
        row("Entries", Some(r.entry_count.to_string()));
        for (k, v) in &i.fields {
            if !self.verbose && k.starts_with("sfo.") {
                continue;
            }
            match v {
                romux::MetaValue::List(l) => {
                    println!("{:<14}", self.paint(&format!("{k}:"), "1"));
                    for x in l {
                        println!("    - {}", x.render());
                    }
                }
                _ => println!("{:<14} {}", self.paint(&format!("{k}:"), "1"), v.render()),
            }
        }
        if !r.graph.titles.is_empty() {
            println!("{}", self.paint("Content graph:", "1"));
            for t in &r.graph.titles {
                println!(
                    "    {} {:?} v{} ({} contents)",
                    t.title_id,
                    t.role,
                    t.version.map(|v| v.to_string()).unwrap_or("?".into()),
                    t.content_ids.len()
                );
            }
            for rel in &r.graph.relations {
                println!("    {} {:?} {}", rel.from, rel.kind, rel.to);
            }
            for u in &r.graph.unresolved {
                println!("    unresolved: {u}");
            }
        }
        for l in &i.limitations {
            println!("{} {l}", self.paint("limitation:", "35"));
        }
        if self.verbose {
            println!("{}", self.paint("Capabilities:", "1"));
            self.cap_rows(&r.capabilities);
        }
        self.warnings(&i.warnings);
    }

    fn cap_rows(&self, c: &CapabilitySet) {
        for e in &c.entries {
            let a = match e.availability {
                romux::Availability::Available => self.paint("available", "32"),
                romux::Availability::NeedsInput => self.paint("needs input", "33"),
                romux::Availability::Unavailable => self.paint("unavailable", "31"),
            };
            println!(
                "    {:<13} {:<11} [{}] {}{}",
                e.operation.as_str(),
                a,
                e.declared.as_str(),
                e.reason.clone().unwrap_or_default(),
                if e.missing.is_empty() { String::new() } else { format!(" (missing: {})", e.missing.join(", ")) }
            );
        }
    }

    pub fn capabilities(&self, c: &CapabilitySet, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        println!("{} {}", self.paint("format:", "1"), c.format);
        self.cap_rows(c);
    }

    pub fn list(&self, nodes: &[ContentNode], env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        for n in nodes {
            let flags = format!("{}{}", if n.encrypted == Some(true) { "E" } else { "-" }, if n.readable { "R" } else { "-" });
            let kind = format!("{:?}", n.kind).to_lowercase();
            println!(
                "{flags} {:<11} {:>14}  {}",
                kind,
                if matches!(n.kind, romux::NodeKind::Directory | romux::NodeKind::Partition) {
                    String::new()
                } else {
                    n.length.to_string()
                },
                n.path
            );
        }
    }

    pub fn verify(&self, r: &VerifyReport, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        for c in &r.checks {
            let (tag, code) = match c.status {
                CheckStatus::Passed => ("pass", "32"),
                CheckStatus::Failed => ("FAIL", "31;1"),
                CheckStatus::Warning => ("warn", "33"),
                CheckStatus::Skipped => ("skip", "90"),
                CheckStatus::NotChecked => ("not checked", "35"),
            };
            println!(
                "[{}] {:?}: {}{}",
                self.paint(tag, code),
                c.level,
                c.name,
                c.detail.as_ref().map(|d| format!(" — {d}")).unwrap_or_default()
            );
        }
        for l in &r.limitations {
            println!("{} {l}", self.paint("limitation:", "35"));
        }
        let s = r.summary();
        println!("{} passed, {} failed, {} warnings, {} skipped, {} not checked", s.passed, s.failed, s.warnings, s.skipped, s.not_checked);
    }

    pub fn formats(&self, f: &[FormatDescriptor], conv: Option<&[ConversionEdge]>, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        for d in f {
            println!("{:<16} {:<9} {} — {}", self.paint(d.id.as_str(), "1"), d.platform, d.name, d.description);
            if self.verbose {
                for o in &d.operations {
                    println!("    {:<13} {:<12} {}", o.operation.as_str(), o.support.as_str(), o.note);
                }
            }
        }
        if let Some(c) = conv {
            println!("\n{}", self.paint("Conversions:", "1"));
            for e in c {
                println!("  {} → {} [{:?}, {}] {}", e.from, e.to, e.kind, e.support.as_str(), e.note);
            }
        }
    }

    pub fn plan(&self, p: &TransformPlan, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        println!("{} {} (dry run — nothing written)", self.paint("plan:", "1"), p.operation);
        for i in &p.inputs {
            println!("  input  [{}] {} ({}, {})", i.role, i.path.display(), i.format, human_bytes(i.identity.len));
        }
        for o in &p.outputs {
            println!(
                "  output {} ({}{}{})",
                o.path.display(),
                o.category,
                o.format.map(|f| format!(", {f}")).unwrap_or_default(),
                o.estimated_size.map(|s| format!(", ~{}", human_bytes(s))).unwrap_or_default()
            );
        }
        for s in &p.steps {
            println!("  step   {s}");
        }
        if !p.guarantees.is_empty() {
            println!("  guarantees: {}", p.guarantees.iter().map(|g| g.describe()).collect::<Vec<_>>().join("; "));
        }
        for r in &p.restrictions {
            println!("  restriction: {r}");
        }
        if !p.required_material.is_empty() {
            println!("  required key material: {}", p.required_material.join(", "));
        }
        if p.temp_space_estimate > 0 {
            println!("  temporary space: {}", human_bytes(p.temp_space_estimate));
        }
        self.warnings(&p.warnings);
    }

    pub fn report(&self, r: &OperationReport, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        if !self.quiet {
            for o in &r.outputs {
                println!("{} {} ({})", self.paint("wrote", "32"), o.path.display(), human_bytes(o.size));
                if !o.guarantees.is_empty() {
                    println!("  guarantees: {}", o.guarantees.iter().map(|g| g.describe()).collect::<Vec<_>>().join("; "));
                }
            }
            if let Some(v) = &r.verification {
                let s = v.summary();
                println!("  verification: {} passed, {} failed, {} skipped", s.passed, s.failed, s.skipped);
            }
        }
        self.warnings(&r.warnings);
    }

    pub fn scan(&self, r: &ScanReport, env: &Envelope) {
        if self.json {
            return self.emit_json(env);
        }
        for g in &r.groups {
            println!("{} {} {}", self.paint(&g.platform.to_string(), "1"), g.family_id, g.title.clone().unwrap_or_default());
            for m in &g.members {
                if let Some(f) = r.files.iter().find(|f| &f.path == m) {
                    println!(
                        "    {:<14} {:?} {} {}",
                        f.format.clone().unwrap_or_default(),
                        f.category.unwrap_or(romux::ContentCategory::Unknown),
                        f.version.clone().unwrap_or_default(),
                        m.display()
                    );
                }
            }
        }
        for f in r.files.iter().filter(|f| f.family_id.is_none()) {
            println!(
                "  {:<14} {} {}",
                f.format.clone().unwrap_or_else(|| "?".into()),
                f.path.display(),
                f.error.clone().map(|e| format!("({e})")).unwrap_or_default()
            );
        }
        for d in &r.duplicates {
            println!("{} {}", self.paint("duplicates:", "33"), d.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "));
        }
        if !r.unrecognized.is_empty() {
            println!("{} unrecognised files", r.unrecognized.len());
        }
    }
}
