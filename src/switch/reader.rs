//! Package readers for NSP/NSZ/XCI/XCZ, single NCA/NCZ archives, bare PFS0 and RomFS.

use crate::switch::formats::*;
use crate::switch::nca::{ContentType, FsType, Nca};
use crate::switch::ncz::NczSource;
use crate::switch::partition::{Kind, PartitionFs};
use crate::switch::title::{ContentFile, FileKind, TitleSet, analyze, classify, content_id_of, enrich_names};
use crate::switch::xci::{Xci, rom_size_name};
use crate::{
    CapabilitySet, CheckLevel, ContentCategory, ContentGraph, ContentNode, EntryId, EntryIter, FormatId, JobContext, NodeKind, NodeTable,
    OpenContext, Operation, PackageInfo, PackageReader, Platform, Result, SharedSource, TitleRole, VerifyLevel, VerifyReport, hex,
};
use std::sync::Arc;

/// An opened Switch package (NSP/NSZ/XCI/XCZ) with its title analysis.
pub struct OpenedPackage {
    pub format: FormatId,
    pub source: SharedSource,
    /// Content members used for title analysis (NSP: all; XCI: secure partition).
    pub files: Vec<ContentFile>,
    pub xci: Option<Xci>,
    pub pfs: Option<PartitionFs>,
    pub titles: TitleSet,
}

impl OpenedPackage {
    pub fn origin_name(&self) -> String {
        self.source.identity().path.map(|p| p.display().to_string()).unwrap_or_else(|| "<memory>".into())
    }
    pub fn is_compressed(&self) -> bool {
        self.files.iter().any(|f| f.kind == FileKind::Ncz)
    }
}

pub fn open_package(source: SharedSource, ctx: &OpenContext) -> Result<OpenedPackage> {
    let origin = source.identity().path.map(|p| p.display().to_string()).unwrap_or_else(|| "<memory>".into());
    let mut m = [0u8; 4];
    source.read_exact_at(0, &mut m)?;
    let (format, files, xci, pfs) = if &m == b"PFS0" {
        let pfs = PartitionFs::parse(source.clone(), Kind::Pfs0, &ctx.limits)?;
        let mut files = Vec::new();
        for (i, e) in pfs.entries.iter().enumerate() {
            files.push(ContentFile { name: e.name.clone(), kind: classify(&e.name), source: pfs.open(i)?, origin: origin.clone() });
        }
        let f = if files.iter().any(|f| f.kind == FileKind::Ncz) { SWITCH_NSZ } else { SWITCH_NSP };
        (f, files, None, Some(pfs))
    } else {
        let x = Xci::open(source.clone(), &ctx.limits)?;
        let mut files = Vec::new();
        if let Some(sec) = x.partition("secure") {
            for (i, e) in sec.entries.iter().enumerate() {
                files.push(ContentFile {
                    name: e.name.clone(),
                    kind: classify(&e.name),
                    source: sec.open(i)?,
                    origin: format!("{origin}:secure"),
                });
            }
        }
        let f = if files.iter().any(|f| f.kind == FileKind::Ncz) { SWITCH_XCZ } else { SWITCH_XCI };
        (f, files, Some(x), None)
    };
    let titles = analyze(&files, ctx.keys.as_ref(), &ctx.limits)?;
    Ok(OpenedPackage { format, source, files, xci, pfs, titles })
}

fn node_for(f: &ContentFile, path: String, titles: &TitleSet) -> ContentNode {
    let len = f.source.len().unwrap_or(0);
    let mut n = ContentNode::file(0, path, len);
    n = match f.kind {
        FileKind::Nca | FileKind::MetaNca | FileKind::Ncz => {
            n.kind(NodeKind::Content).encrypted(true).hint(if f.kind == FileKind::Ncz { SWITCH_NCZ } else { SWITCH_NCA })
        }
        FileKind::Ticket => n.kind(NodeKind::Ticket),
        FileKind::Certificate => n.kind(NodeKind::Certificate),
        FileKind::CnmtXml => n.kind(NodeKind::Metadata),
        FileKind::Other => n,
    };
    if let Some(s) = titles.nca.get(&f.name) {
        n = n
            .meta("content_type", format!("{:?}", s.content_type))
            .meta("program_id", s.program_id.clone())
            .meta("key_generation", s.key_generation);
        if let Some(r) = &s.rights_id {
            n = n.meta("rights_id", r.clone());
        }
    }
    if let Some(t) = titles.title_of_member(&f.name) {
        n = n.meta("title_id", t.title_id_hex());
    }
    n
}

/// PackageReader for NSP/NSZ/XCI/XCZ.
pub struct SwitchPackage {
    pub pkg: OpenedPackage,
    table: NodeTable,
    ctx: OpenContext,
}

impl SwitchPackage {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let mut pkg = open_package(source, ctx)?;
        enrich_names(&mut pkg.titles, &pkg.files, ctx.keys.as_ref(), &ctx.limits);
        let mut table = NodeTable::new();
        if let Some(x) = &pkg.xci {
            for (name, p) in &x.partitions {
                table.push(ContentNode::dir(0, name.clone()).kind(NodeKind::Partition).meta("files", p.entries.len() as u64), None);
                for (i, e) in p.entries.iter().enumerate() {
                    let cf = ContentFile { name: e.name.clone(), kind: classify(&e.name), source: p.open(i)?, origin: name.clone() };
                    let mut n = node_for(&cf, format!("{name}/{}", e.name), &pkg.titles);
                    if name == "update" {
                        n = n.meta("note", "gamecard update partition: system software, not a title update");
                    }
                    table.push(n, Some(cf.source));
                }
            }
        } else {
            for f in &pkg.files {
                table.push(node_for(f, f.name.clone(), &pkg.titles), Some(f.source.clone()));
            }
        }
        Ok(SwitchPackage { pkg, table, ctx: ctx.clone() })
    }

    fn content_check(&self, r: &mut VerifyReport, job: &JobContext) -> Result<()> {
        let total: u64 = self
            .pkg
            .files
            .iter()
            .filter(|f| matches!(f.kind, FileKind::Nca | FileKind::MetaNca | FileKind::Ncz))
            .map(|f| f.source.len().unwrap_or(0))
            .sum();
        let mut p = crate::ByteProgress::new(job, crate::Phase::Verifying, Some(total));
        for f in &self.pkg.files {
            if !matches!(f.kind, FileKind::Nca | FileKind::MetaNca | FileKind::Ncz) {
                continue;
            }
            let id = match content_id_of(&f.name) {
                Some(id) => id,
                None => {
                    r.skip(CheckLevel::Content, &format!("{} content id", f.name), "member name is not a content ID");
                    continue;
                }
            };
            let src: SharedSource = if f.kind == FileKind::Ncz {
                match NczSource::open(f.source.clone()) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        r.fail(CheckLevel::Content, &format!("{} NCZ", f.name), e.to_string());
                        continue;
                    }
                }
            } else {
                f.source.clone()
            };
            let len = src.len()?;
            match crate::crypto::hash_range(src.as_ref(), 0, len, crate::crypto::HashAlg::Sha256, Some(&mut p)) {
                Ok(h) => {
                    let full = hex(&h);
                    r.check(
                        CheckLevel::Content,
                        &format!("{} content id", f.name),
                        full.starts_with(&id),
                        format!("sha256 {}", &full[..32]),
                    );
                    if let Some(t) = self.pkg.titles.title_of_member(&f.name) {
                        if let Some((_, want)) = t.declared_hashes.iter().find(|(cid, _)| *cid == id) {
                            if !want.is_empty() {
                                r.check(
                                    CheckLevel::Content,
                                    &format!("{} CNMT hash", f.name),
                                    *want == full,
                                    "matches the hash declared by the title's CNMT",
                                );
                            }
                        }
                    }
                }
                Err(e) if e.code() == crate::ErrorCode::Cancelled => return Err(e),
                Err(e) => r.fail(CheckLevel::Content, &format!("{} read", f.name), e.to_string()),
            }
        }
        Ok(())
    }
}

impl PackageReader for SwitchPackage {
    fn format(&self) -> FormatId {
        self.pkg.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(self.pkg.format, Platform::Switch, self.pkg.source.len()?);
        i.encrypted = Some(true);
        let t = &self.pkg.titles;
        let apps: Vec<_> = t.titles.iter().collect();
        match apps.as_slice() {
            [] => {
                i.category = ContentCategory::Unknown;
                i.limitations
                    .push("no title metadata available: supply a key file (header_key, key_area_key_*) or include .cnmt.xml".into());
            }
            [one] => {
                i.title_id = Some(one.title_id_hex());
                i.version = one.version.map(|v| v.to_string());
                i.category = match one.role {
                    TitleRole::Base => ContentCategory::Application,
                    TitleRole::Update => ContentCategory::Patch,
                    TitleRole::AddOn => ContentCategory::AddOn,
                    TitleRole::Delta => ContentCategory::Delta,
                    TitleRole::System => ContentCategory::System,
                    TitleRole::Unknown => ContentCategory::Unknown,
                };
                i.title = one.name.clone();
                i.family_id = Some(format!("{:016x}", one.base_id()));
            }
            many => {
                i.category = ContentCategory::MultiContent;
                let bases: Vec<_> = many.iter().map(|t| t.base_id()).collect();
                if bases.windows(2).all(|w| w[0] == w[1]) {
                    i.family_id = Some(format!("{:016x}", bases[0]));
                    i.title_id = Some(format!("{:016x}", bases[0]));
                }
                i.title = many.iter().find_map(|t| t.name.clone());
                i.field("bundled_content", "detected: multiple content sets (base/update/DLC kept separate)");
            }
        }
        let list: Vec<crate::MetaValue> = t
            .titles
            .iter()
            .map(|x| {
                crate::MetaValue::Text(format!(
                    "{} {:?} {} [{} members, evidence: {}{}]{}",
                    x.title_id_hex(),
                    x.role,
                    x.version.map(crate::switch::cnmt::version_string).unwrap_or_else(|| "version unknown".into()),
                    x.members.len(),
                    x.evidence,
                    if x.omitted_delta_fragments > 0 {
                        format!(", {} delta fragments not included", x.omitted_delta_fragments)
                    } else {
                        String::new()
                    },
                    x.name.as_ref().map(|n| format!(" \"{n}\"")).unwrap_or_default()
                ))
            })
            .collect();
        i.fields.insert("titles".into(), crate::MetaValue::List(list));
        i.field("members", self.pkg.files.len() as u64);
        i.field("tickets", t.tickets.len() as u64);
        if t.tickets.values().any(|x| !x.is_common()) {
            i.warnings.push("personalized tickets present: their title keys cannot be used".into());
        }
        if !t.headers_readable {
            i.limitations.push("NCA headers are encrypted and header_key was not supplied; NCA metadata is opaque".into());
        }
        if let Some(x) = &self.pkg.xci {
            i.field("rom_size", rom_size_name(x.header.rom_size));
            i.field("package_id", format!("{:016x}", x.header.package_id));
            i.field("partitions", x.partitions.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>());
            i.warnings.extend(x.warnings.iter().cloned());
            i.limitations.push("XCI header signature and gamecard certificate cannot be verified (authenticity not checked)".into());
        }
        if self.pkg.is_compressed() {
            i.field("compressed_members", self.pkg.files.iter().filter(|f| f.kind == FileKind::Ncz).count() as u64);
        }
        i.warnings.extend(t.warnings.iter().cloned());
        i.sizes.payload = Some(self.pkg.files.iter().map(|f| f.source.len().unwrap_or(0)).sum());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(self.pkg.format, level);
        r.pass(CheckLevel::Structure, "partition table", Some(format!("{} members, bounds and overlaps checked", self.pkg.files.len())));
        if let Some(x) = &self.pkg.xci {
            for (name, ok) in x.verify_hashes()? {
                r.check(CheckLevel::Structure, &name, ok, "SHA-256");
            }
            for w in &x.warnings {
                r.warn(CheckLevel::Structure, "image", w.clone());
            }
        }
        if self.pkg.titles.headers_readable {
            for f in &self.pkg.files {
                if !matches!(f.kind, FileKind::Nca | FileKind::MetaNca) {
                    continue;
                }
                let hdr = match crate::read_vec(f.source.as_ref(), 0, 0xC00, 0xC00)
                    .and_then(|b| crate::switch::nca::NcaHeader::decrypt(&b, self.ctx.keys.as_ref()))
                {
                    Ok(h) => h,
                    Err(e) => {
                        r.fail(CheckLevel::Structure, &format!("{} header", f.name), e.to_string());
                        continue;
                    }
                };
                let tk = self.pkg.titles.titlekey_for(&hdr, self.ctx.keys.as_ref());
                match Nca::open(f.source.clone(), self.ctx.keys.as_ref(), tk.as_deref()) {
                    Ok(n) => {
                        if !n.has_section_keys() {
                            r.skip(CheckLevel::Structure, &format!("{} sections", f.name), n.key_error.clone().unwrap_or_default());
                        }
                        for (name, ok, detail) in n.verify_structure() {
                            if !n.has_section_keys() && name.contains("master") {
                                continue;
                            }
                            r.check(CheckLevel::Structure, &format!("{} {name}", f.name), ok, detail);
                        }
                    }
                    Err(e) => r.fail(CheckLevel::Structure, &format!("{} header", f.name), e.to_string()),
                }
            }
        } else {
            r.skip(CheckLevel::Structure, "NCA headers", "header_key not supplied; NCA internals not checked");
        }
        if level.wants_content() {
            self.content_check(&mut r, job)?;
        }
        r.authenticity_unavailable("NCA/XCI RSA signatures");
        r.limitation("compatibility with consuming software is a separate, test-backed property and is not asserted");
        Ok(r)
    }
    fn content_graph(&self) -> Result<ContentGraph> {
        Ok(self.pkg.titles.graph())
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = crate::switch::capabilities_for(self.pkg.format);
        let keys = &self.ctx.keys;
        if !crate::switch::keys::has_header_key(keys.as_ref()) {
            c.needs(Operation::Split, "header_key", "per-title grouping needs CNMT metadata (key file) or .cnmt.xml");
            c.needs(Operation::Compress, "header_key + key_area_key_*", "compression decrypts NCA sections");
            c.needs(Operation::ApplyUpdate, "header_key + key_area_key_* + titlekek_*", "update reconstruction decrypts both titles");
            if !self.pkg.titles.tickets.is_empty() {
                c.needs(Operation::Convert, "header_key + key_area_key_*", "NSP→XCI needs rights-ID titles converted to standard crypto");
            }
        }
        if self.pkg.is_compressed() {
            c.block(Operation::Compress, "already compressed");
        } else {
            c.block(Operation::Decompress, "not compressed");
        }
        if !cfg!(feature = "zstd") {
            c.block(Operation::Compress, "built without the zstd feature");
            c.block(Operation::Decompress, "built without the zstd feature");
        }
        if self.pkg.titles.titles.len() < 2 {
            c.block(Operation::Split, "package holds at most one content set");
        }
        Ok(c)
    }
}

/// Reader for a single NCA (or NCZ restored on the fly).
pub struct NcaReader {
    format: FormatId,
    raw: SharedSource,
    nca: Option<Nca>,
    error: Option<String>,
    table: NodeTable,
    ncz: Option<crate::switch::ncz::NczHeader>,
}

impl NcaReader {
    pub fn open(raw: SharedSource, format: FormatId, ctx: &OpenContext) -> Result<Self> {
        let (restored, ncz): (SharedSource, _) = if format == SWITCH_NCZ {
            let s = NczSource::open(raw.clone())?;
            let h = s.header.clone();
            (Arc::new(s), Some(h))
        } else {
            (raw.clone(), None)
        };
        let mut table = NodeTable::new();
        let (nca, error) = match Nca::open(restored.clone(), ctx.keys.as_ref(), None) {
            Ok(n) => (Some(n), None),
            Err(e) if e.code() == crate::ErrorCode::NeedsKeyMaterial => (None, Some(e.to_string())),
            Err(e) => return Err(e),
        };
        if format == SWITCH_NCZ {
            table.push(
                ContentNode::file(0, "restored.nca", restored.len()?).kind(NodeKind::Content).encrypted(true),
                Some(restored.clone()),
            );
        }
        if let Some(n) = &nca {
            for s in &n.header.sections {
                let base = format!("section{}", s.index);
                let sec = n.section(s.index).ok();
                table.push(
                    ContentNode::file(0, format!("{base}.bin"), s.size())
                        .kind(NodeKind::Partition)
                        .encrypted(true)
                        .meta("fs_type", format!("{:?}", s.fs_type()))
                        .meta("encryption", format!("{:?}", s.encryption())),
                    None,
                );
                let _ = sec;
                match s.fs_type() {
                    FsType::PartitionFs => {
                        if let Ok(p) = n.pfs0(s.index, &ctx.limits) {
                            for (i, e) in p.entries.iter().enumerate() {
                                table.push(ContentNode::file(0, format!("{base}/{}", e.name), e.size), Some(p.open(i)?));
                            }
                        }
                    }
                    FsType::RomFs => {
                        if let Ok(src) = n.romfs_source(s.index) {
                            if let Ok(fs) = crate::switch::romfs::RomFs::open(src, &ctx.limits) {
                                for f in &fs.files {
                                    table.push(ContentNode::file(0, format!("{base}/{}", f.path), f.size), Some(fs.open_file(f)?));
                                }
                            }
                        }
                    }
                    FsType::Unknown => {}
                }
            }
        }
        Ok(NcaReader { format, raw, nca, error, table, ncz })
    }
}

impl PackageReader for NcaReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(self.format, Platform::Switch, self.raw.len()?);
        i.encrypted = Some(true);
        if let Some(z) = &self.ncz {
            i.sizes.uncompressed = Some(z.nca_size);
            i.field("ncz_mode", if z.block.is_some() { "block" } else { "solid" });
            i.field("ncz_sections", z.sections.len() as u64);
        }
        match &self.nca {
            Some(n) => {
                let h = &n.header;
                i.title_id = Some(h.title_id());
                i.category = match h.content_type {
                    ContentType::Program => ContentCategory::Application,
                    ContentType::Meta | ContentType::Control => ContentCategory::Data,
                    _ => ContentCategory::Data,
                };
                i.field("magic", String::from_utf8_lossy(&h.magic).into_owned());
                i.field("content_type", format!("{:?}", h.content_type));
                i.field("distribution", if h.distribution == 1 { "gamecard" } else { "download" });
                i.field("key_generation", h.key_generation());
                i.field("sdk_version", h.sdk_version_string());
                i.field("content_size", h.content_size);
                if h.has_rights_id() {
                    i.field("rights_id", h.rights_id_hex());
                }
                i.field("sections", h.sections.len() as u64);
                if !n.has_section_keys() {
                    i.limitations.push(n.key_error.clone().unwrap_or_else(|| "section keys unavailable".into()));
                }
            }
            None => i.limitations.push(self.error.clone().unwrap_or_else(|| "NCA header unavailable".into())),
        }
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(self.format, level);
        match &self.nca {
            Some(n) => {
                r.pass(CheckLevel::Structure, "header", Some(format!("{} decrypted", String::from_utf8_lossy(&n.header.magic))));
                for (name, ok, d) in n.verify_structure() {
                    if !n.has_section_keys() && name.contains("master") {
                        r.skip(CheckLevel::Structure, &name, "section keys unavailable");
                        continue;
                    }
                    r.check(CheckLevel::Structure, &name, ok, d);
                }
                if level.wants_content() {
                    let src = n.source.clone();
                    let len = src.len()?;
                    let mut p = crate::ByteProgress::new(job, crate::Phase::Verifying, Some(len));
                    let h = hex(&crate::crypto::hash_range(src.as_ref(), 0, len, crate::crypto::HashAlg::Sha256, Some(&mut p))?);
                    let name =
                        self.raw.identity().path.and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned())).unwrap_or_default();
                    match content_id_of(&name) {
                        Some(id) => r.check(CheckLevel::Content, "content id", h.starts_with(&id), format!("sha256 {h}")),
                        None => r.skip(CheckLevel::Content, "content id", format!("file name is not a content ID; sha256 {h}")),
                    }
                }
            }
            None => r.skip(CheckLevel::Structure, "header", self.error.clone().unwrap_or_default()),
        }
        r.authenticity_unavailable("NCA header RSA signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = crate::switch::capabilities_for(self.format);
        if self.nca.is_none() {
            c.needs(Operation::Inspect, "header_key", "NCA header is encrypted");
            c.needs(Operation::List, "header_key", "NCA header is encrypted");
            c.needs(Operation::Extract, "header_key + key_area_key_*", "sections are encrypted");
        }
        Ok(c)
    }
}

/// Reader for a bare PFS0 (e.g. an ExeFS) or HFS0.
pub struct PartitionReader {
    format: FormatId,
    fs: PartitionFs,
    table: NodeTable,
}

impl PartitionReader {
    pub fn open(source: SharedSource, format: FormatId, ctx: &OpenContext) -> Result<Self> {
        let kind = if format == SWITCH_HFS0 { Kind::Hfs0 } else { Kind::Pfs0 };
        let fs = PartitionFs::parse(source, kind, &ctx.limits)?;
        let mut table = NodeTable::new();
        for (i, e) in fs.entries.iter().enumerate() {
            table.push(ContentNode::file(0, e.name.clone(), e.size).span(fs.abs_offset(i), e.size), Some(fs.open(i)?));
        }
        Ok(PartitionReader { format, fs, table })
    }
}

impl PackageReader for PartitionReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(self.format, Platform::Switch, self.fs.source().len()?);
        i.field("entries", self.fs.entries.len() as u64);
        if self.fs.find("main.npdm").is_some() {
            i.field("layout", "ExeFS");
            i.category = ContentCategory::Data;
        }
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(self.format, level);
        r.pass(CheckLevel::Structure, "entry table", Some(format!("{} entries, bounds and overlaps checked", self.fs.entries.len())));
        for (n, ok) in self.fs.verify_hashes()? {
            r.check(CheckLevel::Structure, &format!("{n} hashed region"), ok, "SHA-256");
        }
        if level.wants_content() && self.format == SWITCH_PFS0 {
            r.skip(CheckLevel::Content, "content hashes", "PFS0 declares no per-file hashes");
        }
        r.skip(CheckLevel::Authenticity, "signature", "partition filesystems carry no signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(crate::switch::capabilities_for(self.format))
    }
}

/// Reader for a bare RomFS image.
pub struct RomfsReader {
    source: SharedSource,
    fs: crate::switch::romfs::RomFs,
    table: NodeTable,
}

impl RomfsReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let fs = crate::switch::romfs::RomFs::open(source.clone(), &ctx.limits)?;
        let mut table = NodeTable::new();
        for f in &fs.files {
            table.push(ContentNode::file(0, f.path.clone(), f.size), Some(fs.open_file(f)?));
        }
        Ok(RomfsReader { source, fs, table })
    }
}

impl PackageReader for RomfsReader {
    fn format(&self) -> FormatId {
        SWITCH_ROMFS
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(SWITCH_ROMFS, Platform::Switch, self.source.len()?);
        i.field("files", self.fs.files.len() as u64);
        i.field("directories", self.fs.dirs.len() as u64);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(SWITCH_ROMFS, level);
        r.pass(CheckLevel::Structure, "directory and file tables", Some(format!("{} files", self.fs.files.len())));
        r.skip(CheckLevel::Content, "content hashes", "level-3 RomFS has no hashes (IVFC lives in the NCA)");
        r.skip(CheckLevel::Authenticity, "signature", "no signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(crate::switch::capabilities_for(SWITCH_ROMFS))
    }
}
