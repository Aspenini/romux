//! Operation capabilities, output guarantees and the conversion graph.

use crate::format::{FormatId, Platform};
use serde::Serialize;
use std::fmt;

/// Every operation in the product surface. Each has its own contract; none aliases another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Operation {
    Probe,
    Inspect,
    List,
    Extract,
    Bundle,
    ApplyUpdate,
    Convert,
    Compress,
    Decompress,
    Split,
    Repack,
    Verify,
    Scan,
}

impl Operation {
    pub const ALL: [Operation; 13] = [
        Operation::Probe,
        Operation::Inspect,
        Operation::List,
        Operation::Extract,
        Operation::Verify,
        Operation::Bundle,
        Operation::ApplyUpdate,
        Operation::Convert,
        Operation::Compress,
        Operation::Decompress,
        Operation::Split,
        Operation::Repack,
        Operation::Scan,
    ];
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Probe => "probe",
            Operation::Inspect => "inspect",
            Operation::List => "list",
            Operation::Extract => "extract",
            Operation::Bundle => "bundle",
            Operation::ApplyUpdate => "apply-update",
            Operation::Convert => "convert",
            Operation::Compress => "compress",
            Operation::Decompress => "decompress",
            Operation::Split => "split",
            Operation::Repack => "repack",
            Operation::Verify => "verify",
            Operation::Scan => "scan",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Declared support level of an operation for a format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Support {
    /// Works for every valid instance of the format.
    Supported,
    /// Works when a deterministic, detectable condition holds (keys, plaintext content, ...).
    Conditional,
    /// Data can be read but the format cannot be produced by this operation.
    ReadOnly,
    /// Not available. Requests fail with `UnsupportedFeature`.
    Unsupported,
}

impl Support {
    pub fn as_str(&self) -> &'static str {
        match self {
            Support::Supported => "supported",
            Support::Conditional => "conditional",
            Support::ReadOnly => "read-only",
            Support::Unsupported => "unsupported",
        }
    }
}

/// Inputs an operation may need beyond the source itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
#[non_exhaustive]
pub enum Requirement {
    /// Named key material supplied through a key provider.
    KeyMaterial(String),
    /// A compression codec compiled in through a Cargo feature.
    Codec(String),
    /// Content must be stored unencrypted.
    PlaintextContent,
    /// Additional input files (e.g. a base title).
    AdditionalInput(String),
    Other(String),
}

/// Composable statement about what an output guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputGuarantee {
    /// Decoding the output reproduces the input byte for byte.
    ByteIdenticalRoundTrip,
    /// The output parses as a structurally valid container of the declared format.
    ContainerValid,
    /// Every payload file/content is preserved exactly (container metadata may differ).
    ContentPreserved,
    /// Payload bytes were copied without decryption or re-encoding.
    PayloadBytesPreserved,
    /// Content was modified; any original signatures are no longer valid.
    ModifiedUnsigned,
    /// Signatures in headers were not (and cannot be) regenerated.
    NotAuthentic,
    /// Compatibility with consuming software has not been tested.
    CompatibilityUnverified,
    /// Filler/padding or non-preserved regions were dropped; the original image may not be recoverable.
    LayoutNotPreserved,
    /// The output is a derived artifact (e.g. base with an update applied).
    DerivedArtifact,
    /// Output contains decrypted data.
    Decrypted,
}

impl OutputGuarantee {
    pub fn describe(&self) -> &'static str {
        match self {
            OutputGuarantee::ByteIdenticalRoundTrip => "byte-identical round trip",
            OutputGuarantee::ContainerValid => "container structurally valid",
            OutputGuarantee::ContentPreserved => "content preserved",
            OutputGuarantee::PayloadBytesPreserved => "payload bytes copied unchanged",
            OutputGuarantee::ModifiedUnsigned => "modified; original signatures invalidated",
            OutputGuarantee::NotAuthentic => "rebuilt container; not an authentic signed original",
            OutputGuarantee::CompatibilityUnverified => "compatibility with consuming software not verified",
            OutputGuarantee::LayoutNotPreserved => "original layout/filler not preserved",
            OutputGuarantee::DerivedArtifact => "derived artifact",
            OutputGuarantee::Decrypted => "contains decrypted data",
        }
    }
}

/// Static support declaration for one operation on one format.
#[derive(Debug, Clone, Serialize)]
pub struct OperationSupport {
    pub operation: Operation,
    pub support: Support,
    pub note: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Requirement>,
}

/// Static description of a format registered by a backend.
#[derive(Debug, Clone, Serialize)]
pub struct FormatDescriptor {
    pub id: FormatId,
    pub platform: Platform,
    pub name: &'static str,
    pub extensions: &'static [&'static str],
    pub description: &'static str,
    pub operations: Vec<OperationSupport>,
}

impl FormatDescriptor {
    pub fn new(
        id: FormatId,
        platform: Platform,
        name: &'static str,
        extensions: &'static [&'static str],
        description: &'static str,
    ) -> Self {
        FormatDescriptor { id, platform, name, extensions, description, operations: Vec::new() }
    }
    /// Declare an operation's support level.
    pub fn op(mut self, operation: Operation, support: Support, note: &str) -> Self {
        self.operations.push(OperationSupport { operation, support, note: note.to_string(), requires: Vec::new() });
        self
    }
    /// Declare a conditional operation with explicit requirements.
    pub fn op_req(mut self, operation: Operation, support: Support, note: &str, requires: Vec<Requirement>) -> Self {
        self.operations.push(OperationSupport { operation, support, note: note.to_string(), requires });
        self
    }
    pub fn support(&self, op: Operation) -> Support {
        self.operations.iter().find(|o| o.operation == op).map(|o| o.support).unwrap_or(Support::Unsupported)
    }
    pub fn get(&self, op: Operation) -> Option<&OperationSupport> {
        self.operations.iter().find(|o| o.operation == op)
    }
}

/// Kind of a conversion edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConversionKind {
    /// Payload bytes copied into a different outer container.
    ContainerRepack,
    /// Payload compressed into a format-specific representation.
    Compress,
    /// Compressed representation restored.
    Decompress,
    /// Metadata/partitions rebuilt (payload may be re-laid out).
    Rebuild,
    /// A sub-range or partition is exported as its own image.
    PartitionExport,
}

/// A declared edge in the directed conversion graph.
#[derive(Debug, Clone, Serialize)]
pub struct ConversionEdge {
    pub from: FormatId,
    pub to: FormatId,
    pub kind: ConversionKind,
    pub support: Support,
    pub guarantees: Vec<OutputGuarantee>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Requirement>,
    pub note: String,
}

impl ConversionEdge {
    pub fn new(from: FormatId, to: FormatId, kind: ConversionKind, support: Support, note: &str) -> Self {
        ConversionEdge { from, to, kind, support, guarantees: Vec::new(), requires: Vec::new(), note: note.to_string() }
    }
    pub fn guarantees(mut self, g: &[OutputGuarantee]) -> Self {
        self.guarantees.extend_from_slice(g);
        self
    }
    pub fn requires(mut self, r: Requirement) -> Self {
        self.requires.push(r);
        self
    }
}

/// Availability of an operation for a concrete source in a concrete context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    /// Possible once missing inputs (keys, codecs, other files) are provided.
    NeedsInput,
    /// Cannot be performed for this source.
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityEntry {
    pub operation: Operation,
    pub availability: Availability,
    pub declared: Support,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub guarantees: Vec<OutputGuarantee>,
}

/// Operations supported by *this* source in *this* context.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilitySet {
    pub format: FormatId,
    pub entries: Vec<CapabilityEntry>,
}

impl CapabilitySet {
    /// Derive a baseline capability set from a static descriptor.
    pub fn from_descriptor(d: &FormatDescriptor) -> Self {
        let entries = d
            .operations
            .iter()
            .map(|o| CapabilityEntry {
                operation: o.operation,
                availability: match o.support {
                    Support::Supported => Availability::Available,
                    Support::Conditional => Availability::Available,
                    Support::ReadOnly => Availability::Available,
                    Support::Unsupported => Availability::Unavailable,
                },
                declared: o.support,
                reason: if o.note.is_empty() { None } else { Some(o.note.clone()) },
                missing: Vec::new(),
                guarantees: Vec::new(),
            })
            .collect();
        CapabilitySet { format: d.id, entries }
    }
    pub fn get(&self, op: Operation) -> Option<&CapabilityEntry> {
        self.entries.iter().find(|e| e.operation == op)
    }
    pub fn get_mut(&mut self, op: Operation) -> Option<&mut CapabilityEntry> {
        self.entries.iter_mut().find(|e| e.operation == op)
    }
    /// Mark an operation as needing additional input.
    pub fn needs(&mut self, op: Operation, missing: &str, reason: &str) {
        if let Some(e) = self.get_mut(op) {
            if e.availability == Availability::Available {
                e.availability = Availability::NeedsInput;
            }
            e.missing.push(missing.to_string());
            e.reason = Some(reason.to_string());
        }
    }
    /// Mark an operation unavailable for this source.
    pub fn block(&mut self, op: Operation, reason: &str) {
        if let Some(e) = self.get_mut(op) {
            e.availability = Availability::Unavailable;
            e.reason = Some(reason.to_string());
        }
    }
    pub fn guarantee(&mut self, op: Operation, g: &[OutputGuarantee]) {
        if let Some(e) = self.get_mut(op) {
            e.guarantees.extend_from_slice(g);
        }
    }
}
