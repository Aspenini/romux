//! Format identifiers, platforms and probe evidence.

use serde::{Serialize, Serializer};
use std::fmt;

/// Stable machine-readable format identifier such as `switch.nsp` or `disc.chd`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FormatId(pub &'static str);

impl FormatId {
    pub const fn new(id: &'static str) -> Self {
        FormatId(id)
    }
    pub fn as_str(&self) -> &'static str {
        self.0
    }
    /// The platform prefix (`switch` for `switch.nsp`).
    pub fn platform_prefix(&self) -> &'static str {
        self.0.split('.').next().unwrap_or(self.0)
    }
}

impl fmt::Display for FormatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Debug for FormatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FormatId({})", self.0)
    }
}

impl Serialize for FormatId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0)
    }
}

/// Console / platform families.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Switch,
    Ps4,
    #[serde(rename = "3ds")]
    N3ds,
    #[serde(rename = "gamecube")]
    GameCube,
    Wii,
    #[serde(rename = "wiiu")]
    WiiU,
    Psp,
    Vita,
    Xbox,
    #[serde(rename = "xbox360")]
    Xbox360,
    #[serde(rename = "n64")]
    N64,
    #[serde(rename = "snes")]
    Snes,
    /// Generic, console-agnostic formats (ISO9660, CUE/BIN, CHD).
    Generic,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Switch => "switch",
            Platform::Ps4 => "ps4",
            Platform::N3ds => "3ds",
            Platform::GameCube => "gamecube",
            Platform::Wii => "wii",
            Platform::WiiU => "wiiu",
            Platform::Psp => "psp",
            Platform::Vita => "vita",
            Platform::Xbox => "xbox",
            Platform::Xbox360 => "xbox360",
            Platform::N64 => "n64",
            Platform::Snes => "snes",
            Platform::Generic => "generic",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confidence of a probe match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A heuristic match (e.g. plausible layout without a magic number).
    Low,
    /// Magic matched but secondary structure only partially validated.
    Medium,
    /// Magic and structure validated.
    High,
    /// Magic, structure and internal checksums validated.
    Certain,
}

/// Bounds applied while probing.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ProbeLimits {
    /// Maximum bytes a single probe may read.
    pub max_read: u64,
    /// Maximum recursive nesting depth for child-format detection.
    pub max_depth: u32,
    /// Maximum number of children examined per container during nested probing.
    pub max_children: usize,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        ProbeLimits { max_read: 4 * 1024 * 1024, max_depth: 3, max_children: 64 }
    }
}

/// Evidence for one candidate format.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeEvidence {
    pub format: FormatId,
    pub confidence: Confidence,
    /// Higher values refine more generic formats (e.g. a PSP UMD image refines ISO9660).
    pub specificity: u8,
    /// Signatures and structural facts that matched.
    pub matched: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Formats this evidence refines (suppresses ambiguity against them).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refines: Vec<FormatId>,
}

impl ProbeEvidence {
    pub fn new(format: FormatId, confidence: Confidence) -> Self {
        ProbeEvidence { format, confidence, specificity: 0, matched: Vec::new(), warnings: Vec::new(), refines: Vec::new() }
    }
    pub fn matched(mut self, s: impl Into<String>) -> Self {
        self.matched.push(s.into());
        self
    }
    pub fn warn(mut self, s: impl Into<String>) -> Self {
        self.warnings.push(s.into());
        self
    }
    pub fn specificity(mut self, s: u8) -> Self {
        self.specificity = s;
        self
    }
    pub fn refines(mut self, f: FormatId) -> Self {
        self.refines.push(f);
        self
    }
}

/// A recognised child format found inside a container.
#[derive(Debug, Clone, Serialize)]
pub struct NestedProbe {
    pub path: String,
    pub format: FormatId,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<NestedProbe>,
}

/// Overall probe outcome for a source.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub size: u64,
    /// The selected format, when unambiguous.
    pub format: Option<FormatId>,
    pub candidates: Vec<ProbeEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ambiguity: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<NestedProbe>,
}

impl ProbeResult {
    pub fn best(&self) -> Option<&ProbeEvidence> {
        let f = self.format?;
        self.candidates.iter().find(|c| c.format == f)
    }
}
