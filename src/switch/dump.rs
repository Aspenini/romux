//! Already-decrypted dump folders → NUP packages.
//!
//! Recognises the directory layout used by Switch 1/2 dump tools and the NUP reference
//! packer (no keys are involved; the files are stored as they are):
//!
//! | directory | package |
//! |---|---|
//! | `base/` with `exefs/` and/or `romfs/` | base |
//! | `updates/<decimal version>/` | one update per version (`standalone_update` without a base) |
//! | `dlc/<16-hex title id>/<index>/` | one add-on per index |
//! | a folder that itself holds `exefs/` or `romfs/` | a single base |
//!
//! Each package stores its whole folder tree. Title IDs come from `exefs/main.npdm` (ACI0
//! program ID), the build ID from the NSO/NRO header of `exefs/main`. Dump-tool `.listing`
//! files are excluded (NUP §6.3). Symbolic links are refused.

use crate::switch::native::{Tree, TreeFile};
use crate::switch::nup;
use crate::{Error, ErrorCode, FileSource, Result, SharedSource};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Reserved dump-tool artifacts (NUP §6.3).
const ARTIFACTS: &[&str] = &[".listing"];

/// A discovered dump: packages plus the opened files (re-checked before writing).
pub(crate) struct Dump {
    pub root: PathBuf,
    pub packages: Vec<nup::PackageInput>,
    pub files: Vec<Arc<FileSource>>,
    pub warnings: Vec<String>,
}

impl Dump {
    pub fn verify_unchanged(&self) -> Result<()> {
        for f in &self.files {
            f.verify_unchanged().map_err(|e| e.with_suggestion("the dump folder changed after planning; run the command again"))?;
        }
        Ok(())
    }
    pub fn file_paths(&self) -> Vec<PathBuf> {
        self.files.iter().map(|f| f.path().to_path_buf()).collect()
    }
    pub fn logical_size(&self) -> u64 {
        self.packages.iter().flat_map(|p| p.tree.files.iter()).map(|f| f.size).sum()
    }
}

/// True when `dir` looks like a dump folder (rather than a package file).
pub(crate) fn is_dump_dir(dir: &Path) -> bool {
    dir.is_dir()
}

fn has_content_dirs(d: &Path) -> bool {
    d.join("exefs").is_dir() || d.join("romfs").is_dir()
}

fn name_of(p: &Path) -> Result<String> {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(String::from)
        .ok_or_else(|| Error::unsafe_path(format!("{} has a name that is not valid UTF-8", p.display())))
}

/// Walk a package folder into a tree (sorted, artifacts skipped).
fn walk(dir: &Path, rel: &str, tree: &mut Tree, opened: &mut Vec<Arc<FileSource>>, depth: u32) -> Result<()> {
    if depth > 64 {
        return Err(Error::limit(format!("{} is nested too deeply", dir.display())));
    }
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(dir).map_err(|e| Error::from(e).with_file(dir.display().to_string()))?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let name = name_of(&path)?;
        let child = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let ft = e.file_type()?;
        if ft.is_symlink() {
            return Err(Error::unsafe_path(format!("{} is a symbolic link; copy the real files into the dump", path.display())));
        }
        if ft.is_dir() {
            tree.dirs.push(child.clone());
            walk(&path, &child, tree, opened, depth + 1)?;
        } else if ft.is_file() {
            if ARTIFACTS.contains(&name.as_str()) {
                continue;
            }
            let f = Arc::new(FileSource::open(&path)?);
            let size = crate::DataSource::len(f.as_ref())?;
            let source: SharedSource = f.clone();
            opened.push(f);
            tree.files.push(TreeFile { path: child, size, source });
        }
    }
    Ok(())
}

/// Program ID from an NPDM (ACI0 at the offset the header names, else the first ACI0).
pub(crate) fn npdm_program_id(npdm: &[u8]) -> Option<u64> {
    let at = if npdm.len() >= 0x80 && &npdm[..4] == b"META" {
        let off = u32::from_le_bytes(npdm[0x70..0x74].try_into().ok()?) as usize;
        if npdm.get(off..off + 4) == Some(b"ACI0") { Some(off) } else { None }
    } else {
        None
    };
    let at = at.or_else(|| npdm.windows(4).position(|w| w == b"ACI0"))?;
    let id = u64::from_le_bytes(npdm.get(at + 0x10..at + 0x18)?.try_into().ok()?);
    (id != 0).then_some(id)
}

/// Build ID (ModuleId): bytes 0x40..0x60 of an NSO0/NRO0 `main`.
pub(crate) fn build_id(main: &[u8]) -> Option<[u8; 32]> {
    if main.len() >= 0x60 && (&main[..4] == b"NSO0" || &main[0x10..0x14] == b"NRO0") {
        let id: [u8; 32] = main[0x40..0x60].try_into().ok()?;
        (id != [0; 32]).then_some(id)
    } else {
        None
    }
}

struct Found {
    kind: u8,
    flags: u8,
    title_id: u64,
    version: u32,
    dir: PathBuf,
}

/// The whole file when it is at most `max` bytes.
fn read_small(tree: &Tree, path: &str, max: u64) -> Result<Option<Vec<u8>>> {
    match tree.files.iter().find(|f| f.path == path) {
        Some(f) if f.size <= max => Ok(Some(crate::read_vec(f.source.as_ref(), 0, f.size, max)?)),
        _ => Ok(None),
    }
}

/// The first `n` bytes (fewer for a shorter file).
fn read_head(tree: &Tree, path: &str, n: u64) -> Result<Option<Vec<u8>>> {
    match tree.files.iter().find(|f| f.path == path) {
        Some(f) => Ok(Some(crate::read_vec(f.source.as_ref(), 0, f.size.min(n), n)?)),
        None => Ok(None),
    }
}

/// Discover the packages of a dump folder. `title_id` overrides the base title ID.
pub(crate) fn discover(root: &Path, title_id: Option<u64>) -> Result<Dump> {
    if !root.is_dir() {
        return Err(Error::invalid_arg(format!("{} is not a directory", root.display())));
    }
    let mut found: Vec<Found> = Vec::new();
    let mut warnings = Vec::new();
    let updates = root.join("updates");
    let collect_updates = |flags: u8, found: &mut Vec<Found>, warnings: &mut Vec<String>| -> Result<()> {
        if !updates.is_dir() {
            return Ok(());
        }
        let mut list: Vec<(u32, PathBuf)> = Vec::new();
        for e in std::fs::read_dir(&updates)? {
            let p = e?.path();
            let name = name_of(&p)?;
            if !p.is_dir() {
                continue;
            }
            match name.parse::<u32>() {
                Ok(v) if name.bytes().all(|b| b.is_ascii_digit()) => list.push((v, p)),
                _ => warnings.push(format!("updates/{name} skipped: the folder name is not a decimal version")),
            }
        }
        list.sort();
        for (v, p) in list {
            found.push(Found { kind: nup::KIND_UPDATE, flags, title_id: 0, version: v, dir: p });
        }
        Ok(())
    };
    let collect_dlc = |found: &mut Vec<Found>, warnings: &mut Vec<String>| -> Result<()> {
        let dlc = root.join("dlc");
        if !dlc.is_dir() {
            return Ok(());
        }
        let mut titles: Vec<PathBuf> = std::fs::read_dir(&dlc)?.map(|e| e.map(|e| e.path())).collect::<std::io::Result<_>>()?;
        titles.sort();
        for t in titles {
            let name = name_of(&t)?;
            let tid = (name.len() == 16).then(|| u64::from_str_radix(&name, 16).ok()).flatten();
            let (Some(tid), true) = (tid, t.is_dir()) else {
                warnings.push(format!("dlc/{name} skipped: expected a 16-hex-digit add-on title ID folder"));
                continue;
            };
            let mut idx: Vec<PathBuf> = std::fs::read_dir(&t)?.map(|e| e.map(|e| e.path())).collect::<std::io::Result<_>>()?;
            idx.sort();
            for i in idx.into_iter().filter(|i| i.is_dir()) {
                found.push(Found { kind: nup::KIND_ADDON, flags: 0, title_id: tid, version: 0, dir: i });
            }
        }
        Ok(())
    };
    let base = root.join("base");
    if base.is_dir() {
        found.push(Found { kind: nup::KIND_BASE, flags: 0, title_id: 0, version: 0, dir: base });
        collect_updates(0, &mut found, &mut warnings)?;
        collect_dlc(&mut found, &mut warnings)?;
    } else if updates.is_dir() {
        collect_updates(nup::FLAG_STANDALONE_UPDATE, &mut found, &mut warnings)?;
        collect_dlc(&mut found, &mut warnings)?;
    } else if has_content_dirs(root) {
        found.push(Found { kind: nup::KIND_BASE, flags: 0, title_id: 0, version: 0, dir: root.to_path_buf() });
    } else {
        return Err(Error::new(
            ErrorCode::UnknownFormat,
            format!("{} is neither a dump bundle (base/, updates/, dlc/) nor a content folder (exefs/ or romfs/)", root.display()),
        ));
    }
    let label = name_of(root).unwrap_or_else(|_| "dump".into());
    let mut files = Vec::new();
    let mut packages: Vec<nup::PackageInput> = Vec::new();
    for f in found {
        let mut tree = Tree::default();
        walk(&f.dir, "", &mut tree, &mut files, 0)?;
        let rel = f.dir.strip_prefix(root).map(|p| p.display().to_string()).unwrap_or_default();
        if tree.files.is_empty() {
            warnings.push(format!("{} skipped: it holds no files", if rel.is_empty() { "." } else { &rel }));
            continue;
        }
        let npdm = read_small(&tree, "exefs/main.npdm", 1 << 20)?.or(read_small(&tree, "main.npdm", 1 << 20)?);
        let main = read_head(&tree, "exefs/main", 0x60)?.or(read_head(&tree, "main", 0x60)?);
        let mut title = f.title_id;
        if f.kind != nup::KIND_ADDON {
            if let Some(id) = npdm.as_deref().and_then(npdm_program_id) {
                title = id;
            }
        }
        if f.kind == nup::KIND_BASE {
            if let Some(t) = title_id {
                title = t;
            }
        }
        let mut meta: Vec<(u16, Vec<u8>)> = Vec::new();
        if let Some(n) = npdm {
            meta.push((nup::TLV_NPDM, n));
        }
        if let Some(b) = main.as_deref().and_then(build_id) {
            meta.push((nup::TLV_BUILD_ID, b.to_vec()));
        }
        meta.push((nup::TLV_SOURCE_DUMP, label.clone().into_bytes()));
        packages.push(nup::PackageInput { kind: f.kind, flags: f.flags, title_id: title, version: f.version, tree, meta });
    }
    if packages.is_empty() {
        return Err(Error::new(ErrorCode::IncompatibleTitles, format!("no packages with files found in {}", root.display())));
    }
    // A base folder without files: its updates become standalone (NUP §3.1.2).
    let has_base = packages.iter().any(|p| p.kind == nup::KIND_BASE);
    let base_tid = packages.iter().find(|p| p.kind == nup::KIND_BASE).map(|p| p.title_id).or(title_id).unwrap_or(0);
    for p in packages.iter_mut().filter(|p| p.kind == nup::KIND_UPDATE) {
        if !has_base {
            p.flags |= nup::FLAG_STANDALONE_UPDATE;
        }
        if p.title_id == 0 {
            p.title_id = base_tid;
        }
    }
    if packages.iter().any(|p| p.title_id == 0 && p.kind != nup::KIND_ADDON) {
        warnings.push("no exefs/main.npdm found; the title ID is recorded as 0 (pass a title ID to set it)".into());
    }
    Ok(Dump { root: root.to_path_buf(), packages, files, warnings })
}
