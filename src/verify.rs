//! Verification reports: checks performed, skipped and their evidence — never one boolean.

use crate::format::FormatId;
use serde::Serialize;

/// Requested verification depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifyLevel {
    Structure,
    Content,
    Authenticity,
    All,
}

impl VerifyLevel {
    pub fn includes(&self, level: CheckLevel) -> bool {
        match self {
            VerifyLevel::All => true,
            VerifyLevel::Structure => level == CheckLevel::Structure,
            VerifyLevel::Content => matches!(level, CheckLevel::Structure | CheckLevel::Content | CheckLevel::Reproducibility),
            VerifyLevel::Authenticity => level != CheckLevel::Compatibility,
        }
    }
    pub fn wants_content(&self) -> bool {
        self.includes(CheckLevel::Content)
    }
    pub fn wants_authenticity(&self) -> bool {
        self.includes(CheckLevel::Authenticity)
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "structure" => VerifyLevel::Structure,
            "content" => VerifyLevel::Content,
            "authenticity" => VerifyLevel::Authenticity,
            "all" => VerifyLevel::All,
            _ => return None,
        })
    }
}

/// The class a check belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckLevel {
    Structure,
    Content,
    Authenticity,
    Reproducibility,
    Compatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    Warning,
    /// Not performed because of the requested level or a limit.
    Skipped,
    /// Could not be performed (e.g. verification material unavailable). Never means "valid".
    NotChecked,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub level: CheckLevel,
    pub status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub format: FormatId,
    pub requested: VerifyLevel,
    pub checks: Vec<Check>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct VerifySummary {
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub skipped: usize,
    pub not_checked: usize,
}

impl VerifyReport {
    pub fn new(format: FormatId, requested: VerifyLevel) -> Self {
        VerifyReport { format, requested, checks: Vec::new(), limitations: Vec::new() }
    }
    fn push(&mut self, level: CheckLevel, name: &str, status: CheckStatus, detail: Option<String>) {
        self.checks.push(Check { name: name.to_string(), level, status, detail });
    }
    pub fn pass(&mut self, level: CheckLevel, name: &str, detail: impl Into<Option<String>>) {
        self.push(level, name, CheckStatus::Passed, detail.into())
    }
    pub fn fail(&mut self, level: CheckLevel, name: &str, detail: impl Into<String>) {
        self.push(level, name, CheckStatus::Failed, Some(detail.into()))
    }
    pub fn warn(&mut self, level: CheckLevel, name: &str, detail: impl Into<String>) {
        self.push(level, name, CheckStatus::Warning, Some(detail.into()))
    }
    pub fn skip(&mut self, level: CheckLevel, name: &str, detail: impl Into<String>) {
        self.push(level, name, CheckStatus::Skipped, Some(detail.into()))
    }
    pub fn not_checked(&mut self, level: CheckLevel, name: &str, detail: impl Into<String>) {
        self.push(level, name, CheckStatus::NotChecked, Some(detail.into()))
    }
    /// Record a boolean outcome.
    pub fn check(&mut self, level: CheckLevel, name: &str, ok: bool, detail: impl Into<String>) {
        if ok { self.pass(level, name, Some(detail.into())) } else { self.fail(level, name, detail) }
    }
    pub fn limitation(&mut self, s: impl Into<String>) {
        self.limitations.push(s.into());
    }
    /// The standard "authenticity not checked" entry for formats without public verification material.
    pub fn authenticity_unavailable(&mut self, what: &str) {
        if self.requested.wants_authenticity() {
            self.not_checked(
                CheckLevel::Authenticity,
                "signature",
                format!("{what}: verification material is not available to Romux; signature not checked"),
            );
        } else {
            self.skip(CheckLevel::Authenticity, "signature", "authenticity level not requested");
        }
    }
    pub fn summary(&self) -> VerifySummary {
        let mut s = VerifySummary { passed: 0, failed: 0, warnings: 0, skipped: 0, not_checked: 0 };
        for c in &self.checks {
            match c.status {
                CheckStatus::Passed => s.passed += 1,
                CheckStatus::Failed => s.failed += 1,
                CheckStatus::Warning => s.warnings += 1,
                CheckStatus::Skipped => s.skipped += 1,
                CheckStatus::NotChecked => s.not_checked += 1,
            }
        }
        s
    }
    /// True when no performed check failed. Says nothing about skipped checks.
    pub fn no_failures(&self) -> bool {
        self.checks.iter().all(|c| c.status != CheckStatus::Failed)
    }
    pub fn merge_prefixed(&mut self, prefix: &str, other: VerifyReport) {
        for mut c in other.checks {
            c.name = format!("{prefix}: {}", c.name);
            self.checks.push(c);
        }
        for l in other.limitations {
            self.limitations.push(format!("{prefix}: {l}"));
        }
    }
}
