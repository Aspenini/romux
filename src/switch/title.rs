//! Title analysis: derives title identities, roles, versions and content membership from
//! the files of a package, using the strongest evidence available:
//!
//! 1. binary CNMT inside meta NCAs (requires `header_key` and key-area keys);
//! 2. `.cnmt.xml` sidecars;
//! 3. common-ticket rights IDs (title ID only; role inferred from the ID pattern).

use crate::switch::cnmt::{Cnmt, MetaType, base_application_id, role_from_id};
use crate::switch::nca::{ContentType, Nca, NcaHeader, decrypt_titlekey};
use crate::switch::ticket::Ticket;
use crate::{ContentGraph, KeyProvider, Relation, RelationKind, ResourceLimits, Result, SharedSource, TitleRecord, TitleRole, read_vec};
use serde::Serialize;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Nca,
    MetaNca,
    Ncz,
    Ticket,
    Certificate,
    CnmtXml,
    Other,
}

pub fn classify(name: &str) -> FileKind {
    let l = name.to_ascii_lowercase();
    if l.ends_with(".cnmt.nca") {
        FileKind::MetaNca
    } else if l.ends_with(".nca") {
        FileKind::Nca
    } else if l.ends_with(".ncz") {
        FileKind::Ncz
    } else if l.ends_with(".tik") {
        FileKind::Ticket
    } else if l.ends_with(".cert") {
        FileKind::Certificate
    } else if l.ends_with(".cnmt.xml") {
        FileKind::CnmtXml
    } else {
        FileKind::Other
    }
}

/// Content ID encoded in a member name (`<32 hex>.nca` / `.cnmt.nca` / `.ncz`).
pub fn content_id_of(name: &str) -> Option<String> {
    let stem = name.split('.').next()?;
    if stem.len() == 32 && stem.chars().all(|c| c.is_ascii_hexdigit()) { Some(stem.to_ascii_lowercase()) } else { None }
}

/// A member file of a package.
#[derive(Clone)]
pub struct ContentFile {
    pub name: String,
    pub kind: FileKind,
    /// Raw stored bytes.
    pub source: SharedSource,
    /// Input file / partition the member came from.
    pub origin: String,
}

/// Summary of a decrypted NCA header.
#[derive(Debug, Clone, Serialize)]
pub struct NcaSummary {
    pub content_type: ContentType,
    pub program_id: String,
    pub key_generation: u8,
    pub rights_id: Option<String>,
    pub distribution: &'static str,
    pub sdk_version: String,
    pub content_size: u64,
}

impl NcaSummary {
    pub fn from_header(h: &NcaHeader) -> Self {
        NcaSummary {
            content_type: h.content_type,
            program_id: h.title_id(),
            key_generation: h.key_generation(),
            rights_id: if h.has_rights_id() { Some(h.rights_id_hex()) } else { None },
            distribution: if h.distribution == 1 { "gamecard" } else { "download" },
            sdk_version: h.sdk_version_string(),
            content_size: h.content_size,
        }
    }
}

/// One title (content set).
#[derive(Debug, Clone, Serialize)]
pub struct TitleEntry {
    pub title_id: u64,
    pub role: TitleRole,
    pub meta_type: Option<MetaType>,
    pub version: Option<u32>,
    pub related_id: Option<u64>,
    /// Member names that belong to this title (contents + meta NCA + tickets/certs + xml).
    pub members: Vec<String>,
    /// Content IDs declared by the CNMT (may reference files not present).
    pub declared_contents: Vec<String>,
    /// Delta fragments declared by an update CNMT. Distributed updates normally omit them,
    /// so they are counted here instead of being reported as missing content.
    pub omitted_delta_fragments: usize,
    /// (content id, sha256) pairs declared by the CNMT.
    #[serde(skip)]
    pub declared_hashes: Vec<(String, String)>,
    /// "cnmt", "cnmt.xml" or "ticket".
    pub evidence: &'static str,
    pub origin: String,
    pub name: Option<String>,
    pub display_version: Option<String>,
}

impl TitleEntry {
    pub fn title_id_hex(&self) -> String {
        format!("{:016x}", self.title_id)
    }
    pub fn base_id(&self) -> u64 {
        match (self.role, self.related_id) {
            (TitleRole::Update | TitleRole::AddOn | TitleRole::Delta, Some(r)) if r != 0 => r,
            _ => base_application_id(self.title_id, self.role),
        }
    }
    pub fn strong(&self) -> bool {
        self.evidence != "ticket"
    }
}

/// Result of analysing a package's members.
#[derive(Debug, Clone, Serialize, Default)]
pub struct TitleSet {
    pub titles: Vec<TitleEntry>,
    pub nca: BTreeMap<String, NcaSummary>,
    #[serde(skip)]
    pub tickets: BTreeMap<String, Ticket>,
    pub warnings: Vec<String>,
    /// Whether NCA headers could be read (header_key available).
    pub headers_readable: bool,
}

impl TitleSet {
    /// Decrypted title key for an NCA header, when a matching common ticket and titlekek exist.
    pub fn titlekey_for(&self, h: &NcaHeader, keys: &dyn KeyProvider) -> Option<Zeroizing<[u8; 16]>> {
        if !h.has_rights_id() {
            return None;
        }
        let t = self.tickets.get(&h.rights_id_hex())?;
        let enc = t.encrypted_titlekey().ok()?;
        decrypt_titlekey(&enc, h.key_generation(), keys).ok()
    }

    pub fn title_of_member(&self, name: &str) -> Option<&TitleEntry> {
        self.titles.iter().find(|t| t.members.iter().any(|m| m == name))
    }

    pub fn graph(&self) -> ContentGraph {
        let mut g = ContentGraph::default();
        for t in &self.titles {
            let key = format!("{}:{}", t.title_id_hex(), t.version.map(|v| v.to_string()).unwrap_or_else(|| "?".into()));
            let mut md = crate::Metadata::new();
            md.insert("evidence".into(), t.evidence.into());
            if let Some(n) = &t.name {
                md.insert("name".into(), n.clone().into());
            }
            g.titles.push(TitleRecord {
                key: key.clone(),
                title_id: t.title_id_hex(),
                role: t.role,
                version: t.version.map(|v| v as u64),
                provenance: t.origin.clone(),
                content_ids: t.declared_contents.clone(),
                metadata: md,
            });
            let kind = match t.role {
                TitleRole::Update => Some(RelationKind::UpdateOf),
                TitleRole::AddOn => Some(RelationKind::AddOnOf),
                TitleRole::Delta => Some(RelationKind::DeltaOf),
                _ => None,
            };
            if let Some(kind) = kind {
                let base = format!("{:016x}", t.base_id());
                match self.titles.iter().find(|b| b.title_id == t.base_id()) {
                    Some(b) => g.relations.push(Relation {
                        from: key.clone(),
                        to: format!("{}:{}", b.title_id_hex(), b.version.map(|v| v.to_string()).unwrap_or_else(|| "?".into())),
                        kind,
                    }),
                    None => g.unresolved.push(format!("{key} {kind:?} {base} (base title not in this package)")),
                }
            }
            for c in &t.declared_contents {
                if !t.members.iter().any(|m| content_id_of(m).as_deref() == Some(c.as_str())) {
                    g.unresolved.push(format!("{key} declares content {c} which is not present"));
                }
            }
        }
        g
    }
}

/// Analyse package members.
pub fn analyze(files: &[ContentFile], keys: &dyn KeyProvider, limits: &ResourceLimits) -> Result<TitleSet> {
    let mut ts = TitleSet { headers_readable: crate::switch::keys::has_header_key(keys), ..Default::default() };
    for f in files.iter().filter(|f| f.kind == FileKind::Ticket) {
        let data = read_vec(f.source.as_ref(), 0, f.source.len()?.min(0x1000), 0x1000)?;
        match Ticket::parse(&data) {
            Ok(t) => {
                ts.tickets.insert(t.rights_id.clone(), t);
            }
            Err(e) => ts.warnings.push(format!("{}: {e}", f.name)),
        }
    }
    // NCA header summaries (cheap: 0xC00 bytes each).
    if ts.headers_readable {
        for f in files.iter().filter(|f| matches!(f.kind, FileKind::Nca | FileKind::MetaNca | FileKind::Ncz)) {
            let raw = read_vec(f.source.as_ref(), 0, crate::switch::nca::HEADER_SIZE as u64, crate::switch::nca::HEADER_SIZE as u64);
            match raw.and_then(|r| NcaHeader::decrypt(&r, keys)) {
                Ok(h) => {
                    ts.nca.insert(f.name.clone(), NcaSummary::from_header(&h));
                }
                Err(e) => ts.warnings.push(format!("{}: header unreadable: {e}", f.name)),
            }
        }
    }
    let mut cnmts: Vec<(Cnmt, String, String)> = Vec::new();
    // 1. Binary CNMT from meta NCAs.
    if ts.headers_readable {
        for f in
            files.iter().filter(|f| f.kind == FileKind::MetaNca || ts.nca.get(&f.name).is_some_and(|s| s.content_type == ContentType::Meta))
        {
            match read_cnmt_from_nca(f.source.clone(), keys, limits) {
                Ok(c) => cnmts.push((c, f.name.clone(), f.origin.clone())),
                Err(e) => ts.warnings.push(format!("{}: CNMT unreadable: {e}", f.name)),
            }
        }
    }
    // 2. cnmt.xml sidecars for titles not already covered.
    for f in files.iter().filter(|f| f.kind == FileKind::CnmtXml) {
        let data = read_vec(f.source.as_ref(), 0, f.source.len()?, 4 << 20)?;
        match Cnmt::parse_xml(&String::from_utf8_lossy(&data)) {
            Ok(c) => {
                if !cnmts.iter().any(|(x, ..)| x.title_id == c.title_id && x.version == c.version) {
                    let meta_name = files
                        .iter()
                        .find(|m| m.kind == FileKind::MetaNca && f.name.starts_with(m.name.trim_end_matches(".cnmt.nca")))
                        .map(|m| m.name.clone())
                        .unwrap_or_default();
                    cnmts.push((c, meta_name, f.origin.clone()));
                }
            }
            Err(e) => ts.warnings.push(format!("{}: {e}", f.name)),
        }
    }
    for (c, meta_name, origin) in cnmts {
        let mut members: Vec<String> = Vec::new();
        if !meta_name.is_empty() {
            members.push(meta_name.clone());
        }
        for rec in &c.contents {
            for f in files {
                if content_id_of(&f.name).as_deref() == Some(rec.id.as_str()) && !members.contains(&f.name) {
                    members.push(f.name.clone());
                }
            }
        }
        let tid_prefix = format!("{:016x}", c.title_id);
        for f in files {
            let l = f.name.to_ascii_lowercase();
            let is_tik_cert = matches!(f.kind, FileKind::Ticket | FileKind::Certificate) && l.starts_with(&tid_prefix);
            let is_xml = f.kind == FileKind::CnmtXml && !meta_name.is_empty() && l.starts_with(meta_name.trim_end_matches(".cnmt.nca"));
            if (is_tik_cert || is_xml) && !members.contains(&f.name) {
                members.push(f.name.clone());
            }
        }
        ts.titles.push(TitleEntry {
            title_id: c.title_id,
            role: c.meta_type.role(),
            meta_type: Some(c.meta_type),
            version: Some(c.version),
            related_id: c.related_id,
            members,
            // Delta fragments (type 6) are optional in distributed packages.
            declared_contents: c.contents.iter().filter(|r| r.content_type != 6).map(|r| r.id.clone()).collect(),
            omitted_delta_fragments: c
                .contents
                .iter()
                .filter(|r| r.content_type == 6 && !files.iter().any(|f| content_id_of(&f.name).as_deref() == Some(r.id.as_str())))
                .count(),
            // The hash a CNMT records for its own Meta content is not the stored file's SHA-256
            // (observed in real packages), so it is not used for verification.
            declared_hashes: c.contents.iter().filter(|r| r.content_type != 0).map(|r| (r.id.clone(), r.hash.clone())).collect(),
            evidence: c.evidence,
            origin,
            name: None,
            display_version: None,
        });
    }
    // 3. Tickets for titles without metadata.
    for t in ts.tickets.values() {
        let tid = t.title_id();
        if ts.titles.iter().any(|x| x.title_id == tid) {
            continue;
        }
        let prefix = t.rights_id.clone();
        let members = files.iter().filter(|f| f.name.to_ascii_lowercase().starts_with(&prefix)).map(|f| f.name.clone()).collect();
        let origin = files.iter().find(|f| f.name.to_ascii_lowercase().starts_with(&prefix)).map(|f| f.origin.clone()).unwrap_or_default();
        ts.titles.push(TitleEntry {
            title_id: tid,
            role: role_from_id(tid),
            meta_type: None,
            version: None,
            related_id: None,
            members,
            declared_contents: vec![],
            omitted_delta_fragments: 0,
            declared_hashes: vec![],
            evidence: "ticket",
            origin,
            name: None,
            display_version: None,
        });
    }
    ts.titles.sort_by_key(|t| (t.base_id(), t.role as u8, t.title_id, t.version));
    Ok(ts)
}

/// Read and parse the CNMT stored in a meta NCA.
pub fn read_cnmt_from_nca(src: SharedSource, keys: &dyn KeyProvider, limits: &ResourceLimits) -> Result<Cnmt> {
    let nca = Nca::open(src, keys, None)?;
    let idx = nca.header.sections.first().map(|s| s.index).ok_or_else(|| crate::Error::malformed("meta NCA has no sections"))?;
    let pfs = nca.pfs0(idx, limits)?;
    let i =
        pfs.entries.iter().position(|e| e.name.ends_with(".cnmt")).ok_or_else(|| crate::Error::malformed("meta NCA contains no .cnmt"))?;
    let s = pfs.open(i)?;
    let data = read_vec(s.as_ref(), 0, s.len()?, 16 << 20)?;
    Cnmt::parse(&data)
}

/// Read `control.nacp` from a control NCA (title name and display version).
pub fn read_nacp(
    src: SharedSource,
    keys: &dyn KeyProvider,
    titlekey: Option<&[u8; 16]>,
    limits: &ResourceLimits,
) -> Result<crate::switch::nacp::Nacp> {
    let nca = Nca::open(src, keys, titlekey)?;
    let idx = nca
        .header
        .sections
        .iter()
        .find(|s| s.fs_type() == crate::switch::nca::FsType::RomFs)
        .map(|s| s.index)
        .ok_or_else(|| crate::Error::malformed("control NCA has no RomFS"))?;
    let fs = crate::switch::romfs::RomFs::open(nca.romfs_source(idx)?, limits)?;
    let f = fs.files.iter().find(|f| f.path == "control.nacp").ok_or_else(|| crate::Error::malformed("control.nacp missing"))?;
    let s = fs.open_file(f)?;
    crate::switch::nacp::Nacp::parse(&read_vec(s.as_ref(), 0, f.size, 1 << 20)?)
}

/// Fill in names from control NCAs (deep inspection).
pub fn enrich_names(ts: &mut TitleSet, files: &[ContentFile], keys: &dyn KeyProvider, limits: &ResourceLimits) {
    let controls: Vec<(String, SharedSource)> = files
        .iter()
        .filter(|f| ts.nca.get(&f.name).is_some_and(|s| s.content_type == ContentType::Control))
        .map(|f| (f.name.clone(), f.source.clone()))
        .collect();
    for (name, src) in controls {
        let hdr = match read_vec(src.as_ref(), 0, crate::switch::nca::HEADER_SIZE as u64, crate::switch::nca::HEADER_SIZE as u64)
            .and_then(|r| NcaHeader::decrypt(&r, keys))
        {
            Ok(h) => h,
            Err(_) => continue,
        };
        let tk = ts.titlekey_for(&hdr, keys);
        match read_nacp(src, keys, tk.as_deref(), limits) {
            Ok(n) => {
                if let Some(t) = ts.titles.iter_mut().find(|t| t.members.contains(&name)) {
                    t.name = n.name().map(String::from);
                    t.display_version = Some(n.display_version.clone()).filter(|s| !s.is_empty());
                }
            }
            Err(e) => ts.warnings.push(format!("{name}: control data unreadable: {e}")),
        }
    }
}
