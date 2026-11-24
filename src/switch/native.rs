//! Decrypted native content sets shared by the NX and NUP writers.
//!
//! Every Application, Patch and AddOnContent CNMT of the input packages becomes a
//! [`NativeTitle`]: its meta NCA, the NCAs its CNMT lists (opened with the user's keys),
//! the Control data (`control.nacp`, `icon_{Language}.dat`) and, for executables, the
//! ExeFS facts (NPDM, NSO build ID). Content is associated only through native records
//! (CNMT content IDs and meta types), never through file names or input order.

use crate::switch::cnmt::{Cnmt, MetaType, base_application_id};
use crate::switch::nacp::{LANGUAGES, Nacp};
use crate::switch::nca::{FsType, HEADER_SIZE, Nca, NcaHeader};
use crate::switch::ncz::NczSource;
use crate::switch::reader::OpenedPackage;
use crate::switch::romfs::RomFs;
use crate::switch::title::{ContentFile, FileKind, content_id_of};
use crate::{Error, ErrorCode, KeyProvider, ResourceLimits, Result, SharedSource, TitleRole, read_vec};
use std::sync::Arc;

/// CNMT content record types.
pub(crate) const RECORD_META: u8 = 0;
pub(crate) const RECORD_PROGRAM: u8 = 1;
pub(crate) const RECORD_DATA: u8 = 2;
pub(crate) const RECORD_CONTROL: u8 = 3;
pub(crate) const RECORD_DELTA: u8 = 6;

/// One NCA of a content set, opened with section keys.
pub(crate) struct NativeContent {
    /// Native unit name: `<content id>.nca`, or `<content id>.cnmt.nca` for the meta NCA.
    /// NCZ members are named `.nca` because the restored NCA is what is stored.
    pub name: String,
    pub content_id: String,
    pub record_type: u8,
    pub id_offset: u8,
    pub nca: Arc<Nca>,
}

impl NativeContent {
    pub fn size(&self) -> u64 {
        self.nca.header.content_size
    }
    /// The decrypted NCA (DNCA) bytes.
    pub fn dnca(&self) -> Result<SharedSource> {
        self.nca.dnca_view().map_err(|e| e.with_content_id(self.content_id.clone()))
    }
    fn section_of(&self, fs: FsType) -> Option<usize> {
        self.nca.header.sections.iter().find(|s| s.fs_type() == fs).map(|s| s.index)
    }
}

/// Control (application metadata) of a content set.
pub(crate) struct ControlData {
    pub nacp_raw: Vec<u8>,
    pub nacp: Nacp,
    /// `(native language name, image bytes)` from `icon_{Language}.dat`, NACP order.
    pub icons: Vec<(String, Vec<u8>)>,
}

impl ControlData {
    /// Default display entry: the first populated NACP language.
    pub fn default_title(&self) -> Option<&(String, String, String)> {
        self.nacp.titles.first()
    }
    pub fn icon(&self, language: &str) -> Option<&[u8]> {
        self.icons.iter().find(|(l, _)| l == language).map(|(_, b)| b.as_slice())
    }
    pub fn display_version(&self) -> Option<&str> {
        Some(self.nacp.display_version.as_str()).filter(|s| !s.is_empty())
    }
}

/// ExeFS facts of a Program NCA.
pub(crate) struct ProgramInfo {
    pub program_id: u64,
    pub id_offset: u8,
    pub npdm: Option<Vec<u8>>,
    /// NSO ModuleId (`main` bytes 0x40..0x60) when `main` is an NSO0/NRO0.
    pub build_id: Option<[u8; 32]>,
}

/// A native content set: one CNMT and the NCAs it lists.
pub(crate) struct NativeTitle {
    /// Index of the input package.
    pub input: usize,
    pub origin: String,
    pub cnmt: Cnmt,
    pub meta: NativeContent,
    /// Contents listed by the CNMT (meta and absent delta fragments excluded), CNMT order.
    pub contents: Vec<NativeContent>,
    pub control: Option<ControlData>,
    pub programs: Vec<ProgramInfo>,
}

impl NativeTitle {
    pub fn role(&self) -> TitleRole {
        self.cnmt.meta_type.role()
    }
    pub fn application_id(&self) -> u64 {
        match (self.role(), self.cnmt.related_id) {
            (TitleRole::Update | TitleRole::AddOn, Some(r)) if r != 0 => r,
            (role, _) => base_application_id(self.cnmt.title_id, role),
        }
    }
    pub fn primary_program(&self) -> Option<&ProgramInfo> {
        self.programs.iter().find(|p| p.id_offset == 0)
    }
    pub fn content(&self, record_type: u8, id_offset: u8) -> Option<&NativeContent> {
        self.contents.iter().find(|c| c.record_type == record_type && c.id_offset == id_offset)
    }
    /// The primary Program NCA (ID offset 0).
    pub fn program_nca(&self) -> Option<&NativeContent> {
        self.content(RECORD_PROGRAM, 0)
    }
    /// The AddOnContent Data NCA.
    pub fn data_nca(&self) -> Option<&NativeContent> {
        self.contents.iter().find(|c| c.record_type == RECORD_DATA)
    }
    /// Meta NCA first, then the listed contents.
    pub fn units(&self) -> impl Iterator<Item = &NativeContent> {
        std::iter::once(&self.meta).chain(self.contents.iter())
    }
    pub fn label(&self) -> String {
        format!("{:016x} {:?} v{}", self.cnmt.title_id, self.role(), self.cnmt.version)
    }
}

fn restored(f: &ContentFile) -> Result<SharedSource> {
    if f.kind == FileKind::Ncz { Ok(Arc::new(NczSource::open(f.source.clone())?)) } else { Ok(f.source.clone()) }
}

fn open_nca(pkg: &OpenedPackage, f: &ContentFile, keys: &dyn KeyProvider) -> Result<Arc<Nca>> {
    let src = restored(f)?;
    let raw = read_vec(src.as_ref(), 0, HEADER_SIZE as u64, HEADER_SIZE as u64)?;
    let hdr = NcaHeader::decrypt(&raw, keys)?;
    let tk = pkg.titles.titlekey_for(&hdr, keys);
    let nca = Nca::open(src, keys, tk.as_deref())?;
    if !nca.has_section_keys() && nca.header.sections.iter().any(|s| s.encryption() != crate::switch::nca::EncryptionType::None) {
        return Err(Error::needs_keys(format!(
            "{}: {}",
            f.name,
            nca.key_error.clone().unwrap_or_else(|| "section keys unavailable".into())
        ))
        .with_suggestion("supply key_area_key_application_XX, and titlekek_XX plus the ticket for rights-ID titles"));
    }
    Ok(Arc::new(nca))
}

fn unit_name(content_id: &str, meta: bool) -> String {
    if meta { format!("{content_id}.cnmt.nca") } else { format!("{content_id}.nca") }
}

fn read_control(c: &NativeContent, limits: &ResourceLimits) -> Result<ControlData> {
    let idx = c.section_of(FsType::RomFs).ok_or_else(|| Error::malformed("control NCA has no RomFS"))?;
    let fs = RomFs::open(c.nca.romfs_source(idx)?, limits)?;
    let file = |name: &str| fs.files.iter().find(|f| f.path == name);
    let nf = file("control.nacp").ok_or_else(|| Error::malformed("control.nacp missing"))?;
    let nacp_raw = read_vec(fs.open_file(nf)?.as_ref(), 0, nf.size, 1 << 20)?;
    let nacp = Nacp::parse(&nacp_raw)?;
    let mut icons = Vec::new();
    for lang in LANGUAGES {
        if let Some(f) = file(&format!("icon_{lang}.dat")) {
            if f.size > 0 {
                icons.push((lang.to_string(), read_vec(fs.open_file(f)?.as_ref(), 0, f.size, 4 << 20)?));
            }
        }
    }
    Ok(ControlData { nacp_raw, nacp, icons })
}

fn read_program(c: &NativeContent, limits: &ResourceLimits) -> Result<ProgramInfo> {
    let mut info = ProgramInfo { program_id: c.nca.header.program_id, id_offset: c.id_offset, npdm: None, build_id: None };
    let Some(idx) = c.section_of(FsType::PartitionFs) else { return Ok(info) };
    let pfs = c.nca.pfs0(idx, limits)?;
    if let Some(i) = pfs.find("main.npdm") {
        let s = pfs.open(i)?;
        info.npdm = Some(read_vec(s.as_ref(), 0, s.len()?, 1 << 20)?);
    }
    if let Some(i) = pfs.find("main") {
        let s = pfs.open(i)?;
        if s.len()? >= 0x60 {
            let h = read_vec(s.as_ref(), 0, 0x60, 0x60)?;
            if &h[..4] == b"NSO0" || &h[0x10..0x14] == b"NRO0" {
                let id: [u8; 32] = h[0x40..0x60].try_into().map_err(|_| Error::internal("build id slice"))?;
                if id != [0; 32] {
                    info.build_id = Some(id);
                }
            }
        }
    }
    Ok(info)
}

/// Decrypt the native content sets of every input package. Requires `header_key`,
/// key-area keys and, for rights-ID titles, `titlekek_XX` plus the common ticket.
pub(crate) fn collect(pkgs: &[&OpenedPackage], keys: &dyn KeyProvider, limits: &ResourceLimits) -> Result<(Vec<NativeTitle>, Vec<String>)> {
    if !crate::switch::keys::has_header_key(keys) {
        return Err(Error::needs_keys("decrypting Switch content requires header_key, key_area_key_* and titlekek_* (rights-ID titles)")
            .with_suggestion("pass --key-file with your console's keys (prod.keys format)"));
    }
    let mut titles: Vec<NativeTitle> = Vec::new();
    let mut warnings = Vec::new();
    for (input, pkg) in pkgs.iter().enumerate() {
        let origin = pkg.origin_name();
        for mf in pkg.files.iter().filter(|f| {
            f.kind == FileKind::MetaNca
                || pkg.titles.nca.get(&f.name).is_some_and(|s| s.content_type == crate::switch::nca::ContentType::Meta)
        }) {
            let meta_nca = open_nca(pkg, mf, keys).map_err(|e| e.with_file(format!("{origin}: {}", mf.name)))?;
            let meta_cid = content_id_of(&mf.name).unwrap_or_else(|| crate::hex(&[0; 16]));
            let idx = meta_nca.header.sections.first().map(|s| s.index).ok_or_else(|| Error::malformed("meta NCA has no sections"))?;
            let pfs = meta_nca.pfs0(idx, limits)?;
            let ci = pfs
                .entries
                .iter()
                .position(|e| e.name.ends_with(".cnmt"))
                .ok_or_else(|| Error::malformed(format!("{}: meta NCA contains no .cnmt", mf.name)))?;
            let cs = pfs.open(ci)?;
            let cnmt = Cnmt::parse(&read_vec(cs.as_ref(), 0, cs.len()?, 16 << 20)?)?;
            if !matches!(cnmt.meta_type, MetaType::Application | MetaType::Patch | MetaType::AddOnContent) {
                warnings.push(format!("{}: content meta type {:?} is not packed", mf.name, cnmt.meta_type));
                continue;
            }
            let meta = NativeContent {
                name: unit_name(&meta_cid, true),
                content_id: meta_cid,
                record_type: RECORD_META,
                id_offset: 0,
                nca: meta_nca,
            };
            let mut contents = Vec::new();
            for rec in &cnmt.contents {
                if rec.content_type == RECORD_META {
                    continue;
                }
                let mut candidates: Vec<&ContentFile> = pkg
                    .files
                    .iter()
                    .filter(|f| {
                        matches!(f.kind, FileKind::Nca | FileKind::Ncz) && content_id_of(&f.name).as_deref() == Some(rec.id.as_str())
                    })
                    .collect();
                candidates.sort_by_key(|f| f.kind == FileKind::Ncz);
                let Some(f) = candidates.first() else {
                    if rec.content_type == RECORD_DELTA {
                        continue;
                    }
                    return Err(Error::new(
                        ErrorCode::IncompatibleTitles,
                        format!(
                            "{origin}: {:016x} lists content {} (type {}) which is not in the package",
                            cnmt.title_id, rec.id, rec.content_type
                        ),
                    ));
                };
                let nca = open_nca(pkg, f, keys).map_err(|e| e.with_file(format!("{origin}: {}", f.name)))?;
                contents.push(NativeContent {
                    name: unit_name(&rec.id, false),
                    content_id: rec.id.clone(),
                    record_type: rec.content_type,
                    id_offset: rec.id_offset,
                    nca,
                });
            }
            let mut t = NativeTitle { input, origin: origin.clone(), cnmt, meta, contents, control: None, programs: Vec::new() };
            if let Some(c) = t.content(RECORD_CONTROL, 0) {
                match read_control(c, limits) {
                    Ok(cd) => t.control = Some(cd),
                    Err(e) => warnings.push(format!("{}: control data unreadable: {e}", t.label())),
                }
            }
            for c in t.contents.iter().filter(|c| c.record_type == RECORD_PROGRAM) {
                t.programs.push(read_program(c, limits).map_err(|e| e.with_content_id(c.content_id.clone()))?);
            }
            if let Some(prev) = titles
                .iter()
                .find(|x| x.cnmt.title_id == t.cnmt.title_id && x.cnmt.version == t.cnmt.version && x.cnmt.meta_type == t.cnmt.meta_type)
            {
                if prev.meta.content_id != t.meta.content_id {
                    return Err(Error::new(
                        ErrorCode::IncompatibleVersions,
                        format!("{} appears twice with different content ({} and {})", t.label(), prev.origin, t.origin),
                    ));
                }
                warnings.push(format!("{} appears in several inputs; the copy from {} is used", t.label(), prev.origin));
                continue;
            }
            titles.push(t);
        }
    }
    if titles.is_empty() {
        return Err(Error::new(ErrorCode::IncompatibleTitles, "no Application, Patch or AddOnContent metadata found in the inputs"));
    }
    titles.sort_by_key(|t| (t.application_id(), t.role() as u8, t.cnmt.title_id, t.cnmt.version));
    Ok((titles, warnings))
}

/// Native NACP language names mapped to lowercase BCP 47 tags (NUP Appendix B, NX).
pub(crate) const LANGUAGE_TAGS: [(&str, &str); 16] = [
    ("AmericanEnglish", "en-us"),
    ("BritishEnglish", "en-gb"),
    ("Japanese", "ja"),
    ("French", "fr"),
    ("German", "de"),
    ("LatinAmericanSpanish", "es-419"),
    ("Spanish", "es"),
    ("Italian", "it"),
    ("Dutch", "nl"),
    ("CanadianFrench", "fr-ca"),
    ("Portuguese", "pt"),
    ("Russian", "ru"),
    ("Korean", "ko"),
    ("TraditionalChinese", "zh-hant"),
    ("SimplifiedChinese", "zh-hans"),
    ("BrazilianPortuguese", "pt-br"),
];

/// `(tag, title, icon)` for each language with a title or icon, in NACP order.
pub(crate) fn localized(c: &ControlData) -> Vec<(&'static str, Option<&str>, Option<&[u8]>)> {
    let mut out = Vec::new();
    for (native, tag) in LANGUAGE_TAGS {
        let title = c.nacp.titles.iter().find(|t| t.0 == native).map(|t| t.1.as_str());
        let icon = c.icon(native);
        if title.is_some() || icon.is_some() {
            out.push((tag, title, icon));
        }
    }
    out
}

/// A file of an extracted content tree.
pub(crate) struct TreeFile {
    /// Path relative to the package root, `/`-separated (e.g. `romfs/data/a.bin`).
    pub path: String,
    pub size: u64,
    pub source: SharedSource,
}

/// An extracted ExeFS/RomFS tree.
#[derive(Default)]
pub(crate) struct Tree {
    /// Directories relative to the root (parents implied), including empty ones.
    pub dirs: Vec<String>,
    pub files: Vec<TreeFile>,
}

impl Tree {
    /// Add the ExeFS of a Program NCA under `exefs/`.
    pub fn add_exefs(&mut self, prog: &NativeContent, limits: &ResourceLimits) -> Result<()> {
        let Some(idx) = prog.section_of(FsType::PartitionFs) else { return Ok(()) };
        let pfs = prog.nca.pfs0(idx, limits)?;
        if pfs.entries.is_empty() {
            return Ok(());
        }
        self.dirs.push("exefs".into());
        for (i, e) in pfs.entries.iter().enumerate() {
            self.files.push(TreeFile { path: format!("exefs/{}", e.name), size: e.size, source: pfs.open(i)? });
        }
        Ok(())
    }
    /// Add a RomFS level-3 image under `romfs/`.
    pub fn add_romfs(&mut self, image: SharedSource, limits: &ResourceLimits) -> Result<()> {
        let fs = RomFs::open(image, limits)?;
        if fs.files.is_empty() && fs.dirs.is_empty() {
            return Ok(());
        }
        self.dirs.push("romfs".into());
        self.dirs.extend(fs.dirs.iter().map(|d| format!("romfs/{d}")));
        for f in &fs.files {
            self.files.push(TreeFile { path: format!("romfs/{}", f.path), size: f.size, source: fs.open_file(f)? });
        }
        Ok(())
    }
}

fn romfs_section(c: &NativeContent) -> Option<&crate::switch::nca::FsHeader> {
    c.nca.header.sections.iter().find(|s| s.fs_type() == FsType::RomFs)
}

fn check_plain_storage(c: &NativeContent, s: &crate::switch::nca::FsHeader) -> Result<()> {
    if s.has_compression_info() || s.has_sparse_info() {
        return Err(Error::unsupported(format!("{}: RomFS uses compressed or sparse storage, which romux cannot extract yet", c.name)));
    }
    Ok(())
}

/// The RomFS image of a content NCA. For a BKTR patch (update Program, DLC update) the
/// base NCA supplies the unchanged bytes; the result is the complete updated image.
pub(crate) fn romfs_image(content: &NativeContent, base: Option<&NativeContent>) -> Result<Option<SharedSource>> {
    let Some(p) = romfs_section(content) else {
        // An update without a RomFS keeps the base RomFS unchanged.
        return match base.and_then(|b| romfs_section(b).map(|s| (b, s))) {
            Some((b, s)) => {
                check_plain_storage(b, s)?;
                Ok(Some(b.nca.romfs_source(s.index)?))
            }
            None => Ok(None),
        };
    };
    check_plain_storage(content, p)?;
    if !p.is_patch() {
        return Ok(Some(content.nca.romfs_source(p.index)?));
    }
    let b = base.ok_or_else(|| {
        Error::new(ErrorCode::IncompatibleTitles, format!("{} is a BKTR patch; its base title must be among the inputs", content.name))
    })?;
    let bs = romfs_section(b)
        .ok_or_else(|| Error::new(ErrorCode::IncompatibleTitles, "update patches a RomFS but the base program has none"))?;
    check_plain_storage(b, bs)?;
    let (ind_off, ind_size, ind_hdr) = p.indirect_table();
    let count = u32::from_le_bytes(ind_hdr[8..12].try_into().unwrap_or([0; 4])) as u64;
    let plain = content.nca.section_plain_ctr(p)?;
    let table = read_vec(plain.as_ref(), ind_off, ind_size, 256 << 20)?;
    let entries = crate::switch::bktr::parse_indirect(&table, count)?;
    let virt_len = u64::from_le_bytes(table.get(8..16).and_then(|b| b.try_into().ok()).unwrap_or([0; 8]));
    let ind: SharedSource =
        Arc::new(crate::switch::bktr::IndirectSource::new(b.nca.section(bs.index)?, content.nca.section(p.index)?, entries, virt_len)?);
    let (off, size) = p.ivfc_data_region().ok_or_else(|| Error::malformed("patch RomFS has no IVFC data level"))?;
    Ok(Some(crate::SubSource::shared(ind, off, size)?))
}
