//! Backend and package-reader traits implemented by every console module.

use crate::capability::{CapabilitySet, ConversionEdge, FormatDescriptor};
use crate::error::{Error, Result};
use crate::format::{FormatId, Platform, ProbeEvidence, ProbeLimits};
use crate::job::{JobContext, ResourceLimits};
use crate::keys::{KeyProvider, NoKeys};
use crate::model::{ContentGraph, ContentNode, EntryId, PackageInfo};
use crate::plan::PlannedOperation;
use crate::source::{DataSource, SharedSource};
use crate::verify::{VerifyLevel, VerifyReport};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Context for opening readers.
#[derive(Clone)]
pub struct OpenContext {
    pub keys: Arc<dyn KeyProvider>,
    pub limits: ResourceLimits,
    /// Strict parsing (default). Permissive modes are documented per format.
    pub strict: bool,
}

impl Default for OpenContext {
    fn default() -> Self {
        OpenContext { keys: Arc::new(NoKeys), limits: ResourceLimits::default(), strict: true }
    }
}

impl OpenContext {
    pub fn with_keys(mut self, keys: Arc<dyn KeyProvider>) -> Self {
        self.keys = keys;
        self
    }
    pub fn has_key(&self, name: &str) -> bool {
        self.keys.get(name).is_some()
    }
}

/// Entry iterator type.
pub type EntryIter<'a> = Box<dyn Iterator<Item = Result<ContentNode>> + 'a>;

/// Read access to an opened package/container.
pub trait PackageReader: Send + Sync {
    fn format(&self) -> FormatId;
    /// Normalised package information (cheap; metadata-proportional).
    fn info(&self) -> Result<PackageInfo>;
    /// Streaming traversal of all entries.
    fn entries(&self) -> Result<EntryIter<'_>>;
    /// Random-access view of an entry's data (decrypted when possible and declared so).
    fn open_entry(&self, id: EntryId) -> Result<SharedSource>;
    /// Run verification checks at the requested level.
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport>;
    /// Title/content relationships declared by this package.
    fn content_graph(&self) -> Result<ContentGraph> {
        Ok(ContentGraph::default())
    }
    /// Capabilities of this concrete source in the current context.
    fn capabilities(&self) -> Result<CapabilitySet>;
}

/// Simple id-indexed table of nodes and their data views, used by most readers.
#[derive(Default)]
pub struct NodeTable {
    nodes: Vec<ContentNode>,
    data: Vec<Option<SharedSource>>,
}

impl NodeTable {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a node; its id is reassigned to its index. Returns the id.
    pub fn push(&mut self, mut node: ContentNode, data: Option<SharedSource>) -> EntryId {
        let id = EntryId(self.nodes.len() as u64);
        node.id = id;
        if data.is_none() && !matches!(node.kind, crate::model::NodeKind::Directory | crate::model::NodeKind::Partition) {
            node.readable = false;
        }
        self.nodes.push(node);
        self.data.push(data);
        id
    }
    pub fn nodes(&self) -> &[ContentNode] {
        &self.nodes
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    pub fn iter(&self) -> EntryIter<'_> {
        Box::new(self.nodes.iter().cloned().map(Ok))
    }
    pub fn open(&self, id: EntryId) -> Result<SharedSource> {
        let i = id.0 as usize;
        match self.data.get(i) {
            Some(Some(s)) => Ok(s.clone()),
            Some(None) => {
                let n = &self.nodes[i];
                if n.encrypted == Some(true) {
                    Err(Error::needs_keys(format!("{} is encrypted", n.path)))
                } else {
                    Err(Error::unsupported(format!("{} has no readable data", n.path)))
                }
            }
            None => Err(Error::invalid_arg(format!("no entry with id {}", id.0))),
        }
    }
    pub fn find(&self, path: &str) -> Option<&ContentNode> {
        self.nodes.iter().find(|n| n.path == path)
    }
}

/// Request for a conversion edge.
pub struct ConvertRequest {
    pub input: PathBuf,
    pub source: SharedSource,
    pub from: FormatId,
    pub to: FormatId,
    pub output: PathBuf,
    pub ctx: OpenContext,
    /// Free-form, edge-specific options (documented per edge, e.g. `level=19`).
    pub options: BTreeMap<String, String>,
}

impl ConvertRequest {
    pub fn option(&self, k: &str) -> Option<&str> {
        self.options.get(k).map(|s| s.as_str())
    }
    pub fn option_u64(&self, k: &str) -> Result<Option<u64>> {
        match self.options.get(k) {
            None => Ok(None),
            Some(v) => v.parse().map(Some).map_err(|_| Error::invalid_arg(format!("option {k} must be an integer"))),
        }
    }
}

/// A console/format backend.
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    fn platform(&self) -> Platform;
    fn formats(&self) -> Vec<FormatDescriptor>;
    /// Declared conversion graph edges originating in this backend.
    fn conversions(&self) -> Vec<ConversionEdge> {
        Vec::new()
    }
    /// Bounded, non-destructive structural probe. Must never attempt decryption.
    fn probe(&self, source: &dyn DataSource, limits: &ProbeLimits) -> Result<Vec<ProbeEvidence>>;
    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>>;
    /// Plan a declared conversion edge.
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        Err(Error::unsupported(format!("conversion {} -> {} is not declared by backend {}", req.from, req.to, self.name())))
    }
}
