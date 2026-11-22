//! Job context: cancellation, progress, resource budget, I/O policy and diagnostics.

use crate::error::{Diagnostic, Error, Result};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Cooperative cancellation token (cheap to clone).
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst)
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Standard job phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Phase {
    Probing,
    Validating,
    Planning,
    Reading,
    Transforming,
    Writing,
    Verifying,
    Finalizing,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Probing => "Probing",
            Phase::Validating => "Validating",
            Phase::Planning => "Planning",
            Phase::Reading => "Reading",
            Phase::Transforming => "Transforming",
            Phase::Writing => "Writing",
            Phase::Verifying => "Verifying",
            Phase::Finalizing => "Finalizing",
        }
    }
}

/// A progress update. `total == None` means indeterminate.
#[derive(Debug, Clone, Serialize)]
pub struct ProgressEvent {
    pub phase: Phase,
    pub completed: u64,
    pub total: Option<u64>,
    pub item: Option<String>,
}

/// Receives progress events. Implementations must be cheap and thread-safe.
pub trait ProgressSink: Send + Sync {
    fn report(&self, event: &ProgressEvent);
}

/// Discards progress.
pub struct NoProgress;
impl ProgressSink for NoProgress {
    fn report(&self, _: &ProgressEvent) {}
}

/// Configurable resource limits applied while parsing and transforming.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ResourceLimits {
    /// Approximate cap on buffers held simultaneously.
    pub max_memory: u64,
    /// Max entries accepted in any single table.
    pub max_entries: u64,
    /// Max bytes of any metadata block (string tables, FSTs...).
    pub max_metadata: u64,
    /// Max filename length in bytes.
    pub max_name_len: usize,
    /// Max directory nesting / recursion depth.
    pub max_depth: u32,
    /// Max ratio of decompressed to compressed bytes before a stream is treated as a bomb.
    pub max_expansion_ratio: u64,
    /// Max output size of any single decompressed stream.
    pub max_output: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            max_memory: 512 * 1024 * 1024,
            max_entries: 1_000_000,
            max_metadata: 256 * 1024 * 1024,
            max_name_len: 1024,
            max_depth: 64,
            max_expansion_ratio: 100_000,
            max_output: 1 << 42,
        }
    }
}

/// Output policy.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IoPolicy {
    /// Allow replacing existing outputs (never inputs).
    pub overwrite: bool,
    /// Scratch directory for temporary data (outputs are still staged next to the target).
    pub temp_dir: Option<PathBuf>,
    /// Skip fsync before rename (faster, less durable).
    pub no_sync: bool,
}

/// Context passed to every long-running operation.
pub struct JobContext {
    pub cancel: CancelToken,
    pub progress: Arc<dyn ProgressSink>,
    pub limits: ResourceLimits,
    pub io: IoPolicy,
    /// Worker threads for parallelisable chunk work (1 = sequential).
    pub threads: usize,
    diagnostics: Mutex<Vec<Diagnostic>>,
}

impl Default for JobContext {
    fn default() -> Self {
        JobContext {
            cancel: CancelToken::new(),
            progress: Arc::new(NoProgress),
            limits: ResourceLimits::default(),
            io: IoPolicy::default(),
            threads: 1,
            diagnostics: Mutex::new(Vec::new()),
        }
    }
}

impl JobContext {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_progress(mut self, p: Arc<dyn ProgressSink>) -> Self {
        self.progress = p;
        self
    }
    pub fn with_cancel(mut self, c: CancelToken) -> Self {
        self.cancel = c;
        self
    }
    pub fn with_io(mut self, io: IoPolicy) -> Self {
        self.io = io;
        self
    }
    pub fn with_limits(mut self, l: ResourceLimits) -> Self {
        self.limits = l;
        self
    }
    pub fn with_threads(mut self, n: usize) -> Self {
        self.threads = n.max(1);
        self
    }
    /// Return `Cancelled` if cancellation was requested.
    pub fn check_cancel(&self) -> Result<()> {
        if self.cancel.is_cancelled() { Err(Error::cancelled()) } else { Ok(()) }
    }
    pub fn progress(&self, phase: Phase, completed: u64, total: Option<u64>) {
        self.progress.report(&ProgressEvent { phase, completed, total, item: None });
    }
    pub fn progress_item(&self, phase: Phase, completed: u64, total: Option<u64>, item: &str) {
        self.progress.report(&ProgressEvent { phase, completed, total, item: Some(item.to_string()) });
    }
    pub fn warn(&self, code: &str, message: impl Into<String>) {
        if let Ok(mut d) = self.diagnostics.lock() {
            d.push(Diagnostic::warning(code, message));
        }
    }
    pub fn take_diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics.lock().map(|mut d| std::mem::take(&mut *d)).unwrap_or_default()
    }
}

/// Tracks byte progress for a phase.
pub struct ByteProgress<'a> {
    job: &'a JobContext,
    phase: Phase,
    total: Option<u64>,
    done: u64,
    last: u64,
}

impl<'a> ByteProgress<'a> {
    pub fn new(job: &'a JobContext, phase: Phase, total: Option<u64>) -> Self {
        job.progress(phase, 0, total);
        ByteProgress { job, phase, total, done: 0, last: 0 }
    }
    /// Advance and check cancellation.
    pub fn advance(&mut self, n: u64) -> Result<()> {
        self.done += n;
        if self.done - self.last >= 4 * 1024 * 1024 || Some(self.done) == self.total {
            self.last = self.done;
            self.job.progress(self.phase, self.done, self.total);
        }
        self.job.check_cancel()
    }
    pub fn done(&self) -> u64 {
        self.done
    }
}
