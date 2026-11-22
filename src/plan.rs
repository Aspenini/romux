//! Immutable transformation plans and operation reports.

use crate::capability::{Operation, OutputGuarantee};
use crate::error::{Diagnostic, Error, Result};
use crate::format::FormatId;
use crate::job::JobContext;
use crate::model::Metadata;
use crate::source::{FileSource, SourceIdentity};
use crate::verify::VerifyReport;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// One input of a plan, with the identity captured at planning time.
#[derive(Debug, Clone, Serialize)]
pub struct PlanInput {
    pub path: PathBuf,
    pub role: String,
    pub format: FormatId,
    pub identity: SourceIdentity,
    /// Cheap content fingerprint (head and tail bytes), catching same-size rewrites that
    /// land within the filesystem's timestamp granularity.
    #[serde(skip)]
    pub fingerprint: u64,
}

/// FNV-1a over the first and last 64 KiB of a file.
fn fingerprint(f: &FileSource) -> Result<u64> {
    use crate::source::DataSource;
    let len = f.len()?;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |b: &[u8]| {
        for x in b {
            h ^= *x as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    let n = len.min(64 * 1024);
    let mut buf = vec![0u8; n as usize];
    f.read_exact_at(0, &mut buf)?;
    feed(&buf);
    if len > n {
        f.read_exact_at(len - n, &mut buf)?;
        feed(&buf);
    }
    feed(&len.to_le_bytes());
    Ok(h)
}

impl PlanInput {
    pub fn capture(path: &Path, role: &str, format: FormatId) -> Result<Self> {
        let f = FileSource::open(path)?;
        Ok(PlanInput {
            path: path.to_path_buf(),
            role: role.to_string(),
            format,
            identity: crate::source::DataSource::identity(&f),
            fingerprint: fingerprint(&f)?,
        })
    }
    /// Re-check that the file has not changed since planning (TOCTOU protection).
    pub fn revalidate(&self) -> Result<()> {
        let f = FileSource::open(&self.path)?;
        let now = crate::source::DataSource::identity(&f);
        if now.len != self.identity.len || now.modified_ns != self.identity.modified_ns || fingerprint(&f)? != self.fingerprint {
            return Err(Error::conflict(format!("input {} changed after planning", self.path.display()))
                .with_suggestion("re-run the operation to create a fresh plan"));
        }
        Ok(())
    }
}

/// Expected output of a plan.
#[derive(Debug, Clone, Serialize)]
pub struct PlanOutput {
    pub path: PathBuf,
    pub format: Option<FormatId>,
    /// e.g. "file", "directory".
    pub kind: &'static str,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_size: Option<u64>,
}

/// Immutable description of a mutation, returned by every `plan()` API.
#[derive(Debug, Clone, Serialize)]
pub struct TransformPlan {
    pub operation: Operation,
    pub inputs: Vec<PlanInput>,
    pub outputs: Vec<PlanOutput>,
    pub guarantees: Vec<OutputGuarantee>,
    pub warnings: Vec<String>,
    pub restrictions: Vec<String>,
    pub required_material: Vec<String>,
    pub temp_space_estimate: u64,
    pub steps: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub details: Metadata,
}

impl TransformPlan {
    pub fn new(operation: Operation) -> Self {
        TransformPlan {
            operation,
            inputs: Vec::new(),
            outputs: Vec::new(),
            guarantees: Vec::new(),
            warnings: Vec::new(),
            restrictions: Vec::new(),
            required_material: Vec::new(),
            temp_space_estimate: 0,
            steps: Vec::new(),
            details: Metadata::new(),
        }
    }
    pub fn input_paths(&self) -> Vec<PathBuf> {
        self.inputs.iter().map(|i| i.path.clone()).collect()
    }
    /// Revalidate every input immediately before execution.
    pub fn revalidate(&self) -> Result<()> {
        for i in &self.inputs {
            i.revalidate()?;
        }
        Ok(())
    }
}

/// Something that has been planned and can be executed once.
pub trait PlannedOperation: Send {
    fn plan(&self) -> &TransformPlan;
    fn execute(self: Box<Self>, job: &JobContext) -> Result<OperationReport>;
}

/// Execution closure of a [`ClosurePlan`].
pub type PlanFn = Box<dyn FnOnce(&TransformPlan, &JobContext) -> Result<OperationReport> + Send>;

/// A plan whose execution is a closure. Inputs are revalidated before the closure runs.
pub struct ClosurePlan {
    plan: TransformPlan,
    run: PlanFn,
}

impl ClosurePlan {
    pub fn new(plan: TransformPlan, run: PlanFn) -> Box<Self> {
        Box::new(ClosurePlan { plan, run })
    }
}

impl PlannedOperation for ClosurePlan {
    fn plan(&self) -> &TransformPlan {
        &self.plan
    }
    fn execute(self: Box<Self>, job: &JobContext) -> Result<OperationReport> {
        self.plan.revalidate()?;
        job.check_cancel()?;
        let ClosurePlan { plan, run } = *self;
        let mut rep = run(&plan, job)?;
        rep.diagnostics.extend(job.take_diagnostics());
        Ok(rep)
    }
}

/// Description of one written output.
#[derive(Debug, Clone, Serialize)]
pub struct OutputRecord {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<FormatId>,
    pub size: u64,
    pub guarantees: Vec<OutputGuarantee>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Result of an executed operation.
#[derive(Debug, Clone, Serialize)]
pub struct OperationReport {
    pub operation: Operation,
    pub inputs: Vec<PathBuf>,
    pub outputs: Vec<OutputRecord>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerifyReport>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metadata: Metadata,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

impl OutputRecord {
    /// Describe a written file (size read from disk).
    pub fn from_path(path: &Path, format: Option<FormatId>, guarantees: &[OutputGuarantee]) -> Result<Self> {
        let size = std::fs::metadata(path)?.len();
        Ok(OutputRecord { path: path.to_path_buf(), format, size, guarantees: guarantees.to_vec(), sha256: None })
    }
}

impl OperationReport {
    pub fn new(operation: Operation, inputs: Vec<PathBuf>) -> Self {
        OperationReport {
            operation,
            inputs,
            outputs: Vec::new(),
            warnings: Vec::new(),
            verification: None,
            metadata: Metadata::new(),
            diagnostics: Vec::new(),
        }
    }
}
