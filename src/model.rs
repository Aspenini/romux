//! Shared domain model: content nodes, package information and content graphs.

use crate::format::{FormatId, Platform};
use serde::Serialize;
use std::collections::BTreeMap;

/// Structured metadata value (kept independent of any JSON library).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum MetaValue {
    Bool(bool),
    U64(u64),
    I64(i64),
    Text(String),
    List(Vec<MetaValue>),
    Map(BTreeMap<String, MetaValue>),
}

impl From<&str> for MetaValue {
    fn from(s: &str) -> Self {
        MetaValue::Text(s.to_string())
    }
}
impl From<String> for MetaValue {
    fn from(s: String) -> Self {
        MetaValue::Text(s)
    }
}
impl From<u64> for MetaValue {
    fn from(v: u64) -> Self {
        MetaValue::U64(v)
    }
}
impl From<u32> for MetaValue {
    fn from(v: u32) -> Self {
        MetaValue::U64(v as u64)
    }
}
impl From<u16> for MetaValue {
    fn from(v: u16) -> Self {
        MetaValue::U64(v as u64)
    }
}
impl From<u8> for MetaValue {
    fn from(v: u8) -> Self {
        MetaValue::U64(v as u64)
    }
}
impl From<bool> for MetaValue {
    fn from(v: bool) -> Self {
        MetaValue::Bool(v)
    }
}
impl<T: Into<MetaValue>> From<Vec<T>> for MetaValue {
    fn from(v: Vec<T>) -> Self {
        MetaValue::List(v.into_iter().map(Into::into).collect())
    }
}

impl MetaValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MetaValue::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            MetaValue::U64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn render(&self) -> String {
        match self {
            MetaValue::Bool(b) => b.to_string(),
            MetaValue::U64(v) => v.to_string(),
            MetaValue::I64(v) => v.to_string(),
            MetaValue::Text(s) => s.clone(),
            MetaValue::List(l) => format!("[{}]", l.iter().map(|v| v.render()).collect::<Vec<_>>().join(", ")),
            MetaValue::Map(m) => format!("{{{}}}", m.iter().map(|(k, v)| format!("{k}: {}", v.render())).collect::<Vec<_>>().join(", ")),
        }
    }
}

/// Ordered metadata map.
pub type Metadata = BTreeMap<String, MetaValue>;

/// Format a byte slice as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse hex (whitespace tolerant).
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Identifier of an entry within a package reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct EntryId(pub u64);

/// Kind of a content node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NodeKind {
    Directory,
    File,
    Partition,
    /// A self-contained content archive (e.g. an NCA or NCCH).
    Content,
    Metadata,
    Ticket,
    Certificate,
    /// A raw track or data stream that is not a traversable filesystem.
    Track,
}

/// Byte span inside the outer source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub offset: u64,
    pub len: u64,
}

/// A content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HashValue {
    pub algorithm: &'static str,
    pub hex: String,
    /// What the hash covers (e.g. "first 0x200 bytes").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// A hierarchical entity inside a package.
#[derive(Debug, Clone, Serialize)]
pub struct ContentNode {
    pub id: EntryId,
    /// Logical path using `/` separators, never starting with `/`.
    pub path: String,
    pub kind: NodeKind,
    pub length: u64,
    /// Location in the outer source when stored contiguously and unencrypted-as-stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
    /// Whether the stored bytes are encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    /// Whether `open_entry` can return this node's data in the current context.
    pub readable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_hint: Option<FormatId>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<HashValue>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

impl ContentNode {
    pub fn file(id: u64, path: impl Into<String>, length: u64) -> Self {
        ContentNode {
            id: EntryId(id),
            path: path.into(),
            kind: NodeKind::File,
            length,
            span: None,
            encrypted: None,
            readable: true,
            format_hint: None,
            hashes: Vec::new(),
            metadata: Metadata::new(),
        }
    }
    pub fn dir(id: u64, path: impl Into<String>) -> Self {
        ContentNode { kind: NodeKind::Directory, ..ContentNode::file(id, path, 0) }
    }
    pub fn kind(mut self, k: NodeKind) -> Self {
        self.kind = k;
        self
    }
    pub fn span(mut self, offset: u64, len: u64) -> Self {
        self.span = Some(Span { offset, len });
        self
    }
    pub fn encrypted(mut self, e: bool) -> Self {
        self.encrypted = Some(e);
        self
    }
    pub fn readable(mut self, r: bool) -> Self {
        self.readable = r;
        self
    }
    pub fn hint(mut self, f: FormatId) -> Self {
        self.format_hint = Some(f);
        self
    }
    pub fn meta(mut self, k: &str, v: impl Into<MetaValue>) -> Self {
        self.metadata.insert(k.to_string(), v.into());
        self
    }
    pub fn hash(mut self, algorithm: &'static str, hex: String, scope: Option<String>) -> Self {
        self.hashes.push(HashValue { algorithm, hex, scope });
        self
    }
}

/// High-level classification of a package's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContentCategory {
    Application,
    Patch,
    AddOn,
    Delta,
    System,
    Data,
    Homebrew,
    DiscImage,
    MultiContent,
    Unknown,
}

/// Size summary.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Sizes {
    pub container: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncompressed: Option<u64>,
}

/// Normalised package information.
#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub format: FormatId,
    pub platform: Platform,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub category: ContentCategory,
    /// Grouping key for related titles (base/update/DLC of one game).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub sizes: Sizes,
    /// Whether some content is encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: Metadata,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

impl PackageInfo {
    pub fn new(format: FormatId, platform: Platform, container_size: u64) -> Self {
        PackageInfo {
            format,
            platform,
            title: None,
            title_id: None,
            product_code: None,
            version: None,
            category: ContentCategory::Unknown,
            family_id: None,
            region: None,
            sizes: Sizes { container: container_size, payload: None, uncompressed: None },
            encrypted: None,
            fields: Metadata::new(),
            warnings: Vec::new(),
            limitations: Vec::new(),
        }
    }
    pub fn field(&mut self, k: &str, v: impl Into<MetaValue>) {
        self.fields.insert(k.to_string(), v.into());
    }
}

/// Role of a title within a content graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TitleRole {
    Base,
    Update,
    AddOn,
    Delta,
    System,
    Unknown,
}

/// A title (content set) inside a graph.
#[derive(Debug, Clone, Serialize)]
pub struct TitleRecord {
    pub key: String,
    pub title_id: String,
    pub role: TitleRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// Where the record came from (file path / inner entry).
    pub provenance: String,
    pub content_ids: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

/// Relationship between two titles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelationKind {
    UpdateOf,
    AddOnOf,
    DeltaOf,
    Contains,
    Requires,
}

#[derive(Debug, Clone, Serialize)]
pub struct Relation {
    pub from: String,
    pub to: String,
    pub kind: RelationKind,
}

/// Links base titles, updates, add-ons and their contents.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ContentGraph {
    pub titles: Vec<TitleRecord>,
    pub relations: Vec<Relation>,
    /// Declared references that could not be resolved.
    pub unresolved: Vec<String>,
}

impl ContentGraph {
    pub fn merge(&mut self, other: ContentGraph) {
        self.titles.extend(other.titles);
        self.relations.extend(other.relations);
        self.unresolved.extend(other.unresolved);
    }
}
