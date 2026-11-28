//! NUP (NX Package Format v1, `.nup`): a container for unencrypted Switch 1/2 game
//! content. One file holds ExeFS program files and complete RomFS trees for a base game,
//! its updates and its add-ons, each file stored raw or as one Zstandard frame and
//! deduplicated by SHA-256.
//!
//! Layout (all little-endian): a 0x80-byte superblock, a SHA-256-protected table of
//! contents (package records, directory and file records, a flat child-slot array and a
//! string pool), then a blob region of 16-byte-aligned extents and per-package metadata
//! TLV blocks. See the NUP specification (`SPEC.md` of the NUP project).

use crate::switch::formats::SWITCH_NUP;
use crate::switch::native::TreeFile;
use crate::{
    CapabilitySet, CheckLevel, ContentCategory, ContentNode, EntryId, EntryIter, Error, FormatId, JobContext, NodeKind, NodeTable,
    OpenContext, PackageInfo, PackageReader, Platform, Result, SharedSource, SubSource, VerifyLevel, VerifyReport, hex, read_vec,
};
use std::collections::{BTreeMap, HashMap};
use std::io::{Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

pub const MAGIC: &[u8; 4] = b"NUP\x01";
pub const TOC_MAGIC: &[u8; 4] = b"TOC\x01";
pub const HEADER_SIZE: u64 = 0x80;
const TOC_HEAD: u64 = 0x30;
const PKG_SIZE: u64 = 0x40;
const DIR_SIZE: u64 = 0x18;
const FILE_SIZE: u64 = 0x50;
const ALIGN: u64 = 16;
const NONE: u32 = 0xFFFF_FFFF;

pub const CODEC_RAW: u8 = 0;
pub const CODEC_ZSTD: u8 = 1;

pub const KIND_BASE: u8 = 0;
pub const KIND_UPDATE: u8 = 1;
pub const KIND_ADDON: u8 = 2;
pub const FLAG_STANDALONE_UPDATE: u8 = 1;

pub const TLV_NPDM: u16 = 0x0001;
pub const TLV_NACP: u16 = 0x0002;
pub const TLV_ICON: u16 = 0x0003;
pub const TLV_DISPLAY_VERSION: u16 = 0x0004;
pub const TLV_TITLE_NAME: u16 = 0x0005;
pub const TLV_PUBLISHER: u16 = 0x0006;
pub const TLV_BUILD_ID: u16 = 0x0007;
pub const TLV_SOURCE_DUMP: u16 = 0x0008;
pub const TLV_LOCALIZED_TITLES: u16 = 0x0009;
pub const TLV_LOCALIZED_ICONS: u16 = 0x000A;

fn kind_name(k: u8) -> &'static str {
    match k {
        0 => "base",
        1 => "update",
        2 => "addon",
        3 => "addon_update",
        4 => "system",
        _ => "unknown",
    }
}

fn align16(v: u64) -> Result<u64> {
    crate::binary::align_up(v, ALIGN)
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap_or([0; 4]))
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]))
}

// ---------------------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NupPackage {
    pub title_id: u64,
    pub root_dir: u32,
    pub exefs_dir: u32,
    pub romfs_dir: u32,
    pub version: u32,
    pub kind: u8,
    pub flags: u8,
    pub meta_offset: u64,
    pub meta_size: u32,
    /// Parsed meta TLVs (first occurrence of each type).
    pub meta: BTreeMap<u16, Vec<u8>>,
}

impl NupPackage {
    pub fn kind_name(&self) -> &'static str {
        kind_name(self.kind)
    }
    pub fn text(&self, t: u16) -> Option<String> {
        self.meta.get(&t).map(|b| String::from_utf8_lossy(b).into_owned())
    }
    /// Localized records (TLV 0x0009 / 0x000A): `(language tag, data)`.
    pub fn localized(&self, t: u16) -> Result<Vec<(String, Vec<u8>)>> {
        let Some(p) = self.meta.get(&t) else { return Ok(Vec::new()) };
        decode_localized(p)
    }
}

pub fn decode_localized(p: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut at = 0usize;
    while at < p.len() {
        let ll = p[at] as usize;
        at += 1;
        let lang = p.get(at..at + ll).ok_or_else(|| Error::malformed("localized record language overruns TLV"))?;
        at += ll;
        let dl = p.get(at..at + 4).ok_or_else(|| Error::malformed("localized record overruns TLV"))?;
        let dl = u32::from_le_bytes(dl.try_into().unwrap_or([0; 4])) as usize;
        at += 4;
        let data = p.get(at..at + dl).ok_or_else(|| Error::malformed("localized record data overruns TLV"))?;
        at += dl;
        if lang.is_empty() {
            return Err(Error::malformed("localized record with an empty language tag"));
        }
        let tag = String::from_utf8_lossy(lang).to_ascii_lowercase();
        if out.iter().any(|(t, _)| *t == tag) {
            return Err(Error::malformed(format!("duplicate localized language tag {tag}")));
        }
        out.push((tag, data.to_vec()));
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct NupDir {
    pub name: String,
    pub first_child: u32,
    pub child_count: u32,
}

#[derive(Debug, Clone)]
pub struct NupFile {
    pub name: String,
    pub size: u64,
    pub extent_offset: u64,
    pub extent_size: u64,
    pub sha256: [u8; 32],
    pub codec: u8,
}

/// A parsed, validated NUP container.
pub struct Nup {
    pub source: SharedSource,
    pub toc_size: u64,
    pub toc_sha256: [u8; 32],
    pub blob_offset: u64,
    pub file_size: u64,
    pub uuid: [u8; 16],
    pub packages: Vec<NupPackage>,
    pub dirs: Vec<NupDir>,
    pub files: Vec<NupFile>,
    pub children: Vec<u32>,
    /// Problems that do not prevent reading (reported by verify).
    pub warnings: Vec<String>,
}

pub fn probe(s: &dyn crate::DataSource) -> bool {
    let mut m = [0u8; 4];
    s.len().is_ok_and(|l| l >= HEADER_SIZE) && s.read_exact_at(0, &mut m).is_ok() && &m == MAGIC
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n != "." && n != ".." && !n.contains(['/', '\\', '\0'])
}

impl Nup {
    pub fn open(source: SharedSource, limits: &crate::ResourceLimits) -> Result<Self> {
        let len = source.len()?;
        let sb = read_vec(source.as_ref(), 0, HEADER_SIZE, HEADER_SIZE)?;
        if &sb[..4] != MAGIC {
            return Err(Error::malformed("not a NUP v1 container (magic)"));
        }
        let header_size = u16_at(&sb, 4) as u64;
        let header_version = u16_at(&sb, 6);
        let toc_offset = u64_at(&sb, 8);
        let toc_size = u64_at(&sb, 0x10);
        let toc_sha256: [u8; 32] = sb[0x18..0x38].try_into().map_err(|_| Error::internal("sha slice"))?;
        let blob_offset = u64_at(&sb, 0x38);
        let file_size = u64_at(&sb, 0x40);
        let package_count = u32_at(&sb, 0x48);
        let flags = u32_at(&sb, 0x4C);
        let uuid: [u8; 16] = sb[0x50..0x60].try_into().map_err(|_| Error::internal("uuid slice"))?;
        if header_size < HEADER_SIZE {
            return Err(Error::malformed(format!("NUP header_size 0x{header_size:x} is below 0x80")));
        }
        if toc_offset != header_size {
            return Err(Error::malformed("NUP toc_offset must equal header_size"));
        }
        if flags != 0 {
            return Err(Error::unsupported(format!("NUP superblock flags 0x{flags:x} are not defined in v1")));
        }
        if package_count == 0 {
            return Err(Error::malformed("NUP container declares no packages"));
        }
        if file_size != len {
            return Err(Error::malformed(format!("NUP file_size {file_size} differs from the stream length {len}")));
        }
        let toc_end = toc_offset.checked_add(toc_size).ok_or_else(|| Error::bounds("TOC range overflows"))?;
        if !blob_offset.is_multiple_of(ALIGN) || blob_offset < toc_end || blob_offset > len {
            return Err(Error::malformed("NUP blob_offset is misaligned or overlaps the TOC"));
        }
        if toc_size > limits.max_metadata.max(64 << 20) {
            return Err(Error::limit("NUP TOC exceeds the metadata limit"));
        }
        let toc = read_vec(source.as_ref(), toc_offset, toc_size, toc_size)?;
        if crate::crypto::sha256(&toc) != toc_sha256 {
            return Err(Error::integrity("NUP TOC SHA-256 does not match the superblock"));
        }
        if toc.len() < TOC_HEAD as usize || &toc[..4] != TOC_MAGIC {
            return Err(Error::malformed("NUP TOC magic is missing"));
        }
        if u32_at(&toc, 4) != package_count {
            return Err(Error::malformed("NUP TOC package count disagrees with the superblock"));
        }
        let dir_count = u64_at(&toc, 8);
        let file_count = u64_at(&toc, 0x10);
        let pool_off = u64_at(&toc, 0x18);
        let pool_size = u64_at(&toc, 0x20);
        if dir_count > limits.max_entries || file_count > limits.max_entries {
            return Err(Error::limit("NUP declares too many nodes"));
        }
        let arrays_end = TOC_HEAD
            .checked_add(package_count as u64 * PKG_SIZE)
            .and_then(|v| v.checked_add(dir_count * DIR_SIZE))
            .and_then(|v| v.checked_add(file_count * FILE_SIZE))
            .ok_or_else(|| Error::bounds("NUP TOC arrays overflow"))?;
        let pool_end = pool_off.checked_add(pool_size).ok_or_else(|| Error::bounds("string pool overflows"))?;
        if arrays_end > pool_off || pool_end > toc_size {
            return Err(Error::bounds("NUP TOC arrays or string pool exceed the TOC"));
        }
        let pool = &toc[pool_off as usize..pool_end as usize];
        let string = |off: u32, l: u32| -> Result<String> {
            let e = (off as usize).checked_add(l as usize).ok_or_else(|| Error::bounds("name overflows"))?;
            let b = pool.get(off as usize..e).ok_or_else(|| Error::bounds("name outside the string pool"))?;
            String::from_utf8(b.to_vec()).map_err(|_| Error::malformed("NUP name is not UTF-8"))
        };
        let mut at = TOC_HEAD as usize;
        let mut raw_packages = Vec::new();
        for _ in 0..package_count {
            let r = &toc[at..at + PKG_SIZE as usize];
            raw_packages.push(NupPackage {
                title_id: u64_at(r, 0),
                root_dir: u32_at(r, 8),
                exefs_dir: u32_at(r, 0x0C),
                romfs_dir: u32_at(r, 0x10),
                version: u32_at(r, 0x14),
                kind: r[0x18],
                flags: r[0x19],
                meta_offset: u64_at(r, 0x20),
                meta_size: u32_at(r, 0x28),
                meta: BTreeMap::new(),
            });
            at += PKG_SIZE as usize;
        }
        let mut dirs = Vec::with_capacity(dir_count as usize);
        for _ in 0..dir_count {
            let r = &toc[at..at + DIR_SIZE as usize];
            dirs.push(NupDir { name: string(u32_at(r, 0), u32_at(r, 4))?, first_child: u32_at(r, 8), child_count: u32_at(r, 0x0C) });
            at += DIR_SIZE as usize;
        }
        let mut files = Vec::with_capacity(file_count as usize);
        for _ in 0..file_count {
            let r = &toc[at..at + FILE_SIZE as usize];
            files.push(NupFile {
                name: string(u32_at(r, 0), u32_at(r, 4))?,
                size: u64_at(r, 8),
                extent_offset: u64_at(r, 0x10),
                extent_size: u64_at(r, 0x18),
                sha256: r[0x20..0x40].try_into().map_err(|_| Error::internal("sha slice"))?,
                codec: r[0x40],
            });
            at += FILE_SIZE as usize;
        }
        let slots: u64 = dirs.iter().map(|d| d.child_count as u64).sum();
        let children_end = (at as u64).checked_add(slots * 4).ok_or_else(|| Error::bounds("child slots overflow"))?;
        if children_end > pool_off {
            return Err(Error::bounds("NUP child slots overlap the string pool"));
        }
        let children: Vec<u32> = (0..slots as usize).map(|i| u32_at(&toc, at + i * 4)).collect();
        let node_count = dir_count + file_count;
        if children.iter().any(|&c| c as u64 >= node_count) {
            return Err(Error::bounds("NUP child slot references a missing node"));
        }
        for d in &dirs {
            if d.first_child as u64 + d.child_count as u64 > slots {
                return Err(Error::bounds("NUP directory child range exceeds the child array"));
            }
        }
        let spec = format!("NUP v1, header_version {header_version}");
        let mut warnings = Vec::new();
        let mut packages = Vec::new();
        for (pi, p) in raw_packages.into_iter().enumerate() {
            if p.kind >= 5 {
                return Err(Error::unsupported(format!("NUP package kind {} is not defined in v1", p.kind)));
            }
            if p.flags & !FLAG_STANDALONE_UPDATE != 0 {
                warnings.push(format!("package {:016x} has undefined flag bits 0x{:02x}", p.title_id, p.flags));
            }
            for d in [p.root_dir, p.exefs_dir, p.romfs_dir] {
                if d != NONE && d as u64 >= dir_count {
                    return Err(Error::bounds("NUP package references a missing directory"));
                }
            }
            if p.root_dir == NONE {
                return Err(Error::malformed("NUP package has no root directory"));
            }
            if p.meta_size > 0 {
                // §3.1/§5: meta_offset is an absolute file offset. The specification places no
                // meta block inside the blob region specifically (producers may write them
                // between the TOC and blob_offset); it must lie after the superblock and TOC,
                // inside the file, and overlap no extent or other meta block (checked below).
                let end = p.meta_offset.checked_add(p.meta_size as u64).ok_or_else(|| {
                    Error::bounds(format!(
                        "{spec}: package {pi} ({:016x}) meta block at 0x{:x} + 0x{:x} bytes overflows",
                        p.title_id, p.meta_offset, p.meta_size
                    ))
                    .with_offset(p.meta_offset)
                })?;
                if p.meta_offset < toc_end || end > len {
                    return Err(Error::bounds(format!(
                        "{spec}: package {pi} ({:016x}) meta block [0x{:x}, 0x{end:x}) (0x{:x} bytes) is outside the region it may occupy, \
                         [0x{toc_end:x}, 0x{len:x}) after the superblock and TOC (blob region starts at 0x{blob_offset:x})",
                        p.title_id, p.meta_offset, p.meta_size
                    ))
                    .with_offset(p.meta_offset));
                }
            }
            packages.push(p);
        }
        if packages.iter().filter(|p| p.kind == KIND_BASE).count() > 1 {
            warnings.push("container holds more than one base package (v1 allows one)".into());
        }
        for f in &files {
            if f.codec > CODEC_ZSTD {
                return Err(Error::unsupported(format!("NUP codec {} for {} is not supported", f.codec, f.name)));
            }
            if f.size == 0 {
                if f.extent_size != 0 {
                    warnings.push(format!("zero-length file {} has a non-empty extent", f.name));
                }
                continue;
            }
            let end = f.extent_offset.checked_add(f.extent_size).ok_or_else(|| {
                Error::bounds(format!("{spec}: extent of {} at 0x{:x} + 0x{:x} bytes overflows", f.name, f.extent_offset, f.extent_size))
                    .with_offset(f.extent_offset)
            })?;
            if f.extent_offset < blob_offset || end > len {
                return Err(Error::bounds(format!(
                    "{spec}: extent of {} [0x{:x}, 0x{end:x}) (0x{:x} bytes) is outside the blob region [0x{blob_offset:x}, 0x{len:x})",
                    f.name, f.extent_offset, f.extent_size
                ))
                .with_offset(f.extent_offset));
            }
            if f.extent_offset % ALIGN != 0 {
                warnings.push(format!("extent of {} is not 16-byte aligned", f.name));
            }
            if f.codec == CODEC_RAW && f.extent_size != f.size {
                return Err(Error::malformed(format!("raw extent of {} differs from its size", f.name)));
            }
        }
        check_overlaps(&spec, &packages, &files)?;
        // Only now that every region is known to be in bounds and disjoint, read the TLVs.
        for (pi, p) in packages.iter_mut().enumerate() {
            if p.meta_size == 0 {
                continue;
            }
            let block = read_vec(source.as_ref(), p.meta_offset, p.meta_size as u64, 64 << 20)?;
            let mut o = 0usize;
            while o + 8 <= block.len() {
                let t = u16_at(&block, o);
                let size = u32_at(&block, o + 4) as usize;
                let payload = (o + 8).checked_add(size).and_then(|e| block.get(o + 8..e)).ok_or_else(|| {
                    Error::malformed(format!(
                        "{spec}: package {pi} ({:016x}) meta TLV 0x{t:04x} at block offset 0x{o:x} declares 0x{size:x} payload bytes,                          past the end of its 0x{:x}-byte meta block at 0x{:x}",
                        p.title_id, p.meta_size, p.meta_offset
                    ))
                    .with_offset(p.meta_offset + o as u64)
                })?;
                p.meta.entry(t).or_insert_with(|| payload.to_vec());
                o += 8 + size;
            }
        }
        let nup = Nup { source, toc_size, toc_sha256, blob_offset, file_size, uuid, packages, dirs, files, children, warnings };
        // Walk every package tree once: names, cycles and depth.
        for p in &nup.packages {
            nup.walk(p.root_dir, limits, &mut |_, _| Ok(()))?;
        }
        Ok(nup)
    }

    /// Pre-order walk of a directory tree: `visit(path, node id)`; the root has path "".
    pub fn walk(&self, root: u32, limits: &crate::ResourceLimits, visit: &mut dyn FnMut(&str, u32) -> Result<()>) -> Result<()> {
        let dc = self.dirs.len() as u32;
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![(root, String::new(), 0u32)];
        while let Some((d, path, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(Error::limit("NUP tree nesting too deep"));
            }
            if !seen.insert(d) {
                return Err(Error::malformed("NUP directory reached twice (cycle or shared subtree)"));
            }
            visit(&path, d)?;
            let dir = &self.dirs[d as usize];
            let mut names: Vec<&str> = Vec::new();
            let mut sub = Vec::new();
            for slot in dir.first_child..dir.first_child + dir.child_count {
                let id = self.children[slot as usize];
                let name = if id < dc { self.dirs[id as usize].name.as_str() } else { self.files[(id - dc) as usize].name.as_str() };
                if !valid_name(name) {
                    return Err(Error::unsafe_path(format!("NUP node name {name:?} is not a valid path component")));
                }
                if names.contains(&name) {
                    return Err(Error::malformed(format!("duplicate name {name:?} in one NUP directory")));
                }
                names.push(name);
                let child = if path.is_empty() { name.to_string() } else { format!("{path}/{name}") };
                if id < dc {
                    sub.push((id, child, depth + 1));
                } else {
                    visit(&child, id)?;
                }
            }
            stack.extend(sub.into_iter().rev());
        }
        Ok(())
    }

    pub fn is_dir(&self, node: u32) -> bool {
        (node as usize) < self.dirs.len()
    }
    pub fn file(&self, node: u32) -> &NupFile {
        &self.files[node as usize - self.dirs.len()]
    }

    /// Uncompressed view of a file.
    pub fn open_file(&self, f: &NupFile) -> Result<SharedSource> {
        if f.size == 0 {
            return Ok(Arc::new(crate::MemorySource::new(Vec::new())));
        }
        let extent = SubSource::shared(self.source.clone(), f.extent_offset, f.extent_size)?;
        match f.codec {
            CODEC_RAW => Ok(extent),
            _ => Ok(Arc::new(ZstdFileSource::new(extent, f.size))),
        }
    }

    /// UUID per §2.1 from the package identities.
    pub fn expected_uuid(&self) -> [u8; 16] {
        derive_uuid(self.packages.iter().map(|p| (p.title_id, p.version, p.kind)))
    }

    /// Package whose meta block carries application metadata: base, else the first.
    pub fn app_package(&self) -> &NupPackage {
        self.packages.iter().find(|p| p.kind == KIND_BASE).unwrap_or(&self.packages[0])
    }
}

/// §6.1.2: no two regions may overlap. Deduplicated files legitimately share one identical
/// extent (§3.6), and identical ranges of the same kind are accepted; any other overlap,
/// including a meta block over an extent, is rejected.
fn check_overlaps(spec: &str, packages: &[NupPackage], files: &[NupFile]) -> Result<()> {
    // (start, end, is_meta, owner description)
    let mut extents: Vec<(u64, u64)> =
        files.iter().filter(|f| f.size > 0 && f.extent_size > 0).map(|f| (f.extent_offset, f.extent_offset + f.extent_size)).collect();
    extents.sort_unstable();
    extents.dedup();
    let mut metas: Vec<(u64, u64, usize)> = packages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.meta_size > 0)
        .map(|(i, p)| (p.meta_offset, p.meta_offset + p.meta_size as u64, i))
        .collect();
    metas.sort_unstable();
    metas.dedup_by_key(|m| (m.0, m.1));
    let mut regions: Vec<(u64, u64, Option<usize>)> = extents.into_iter().map(|(a, b)| (a, b, None)).collect();
    regions.extend(metas.into_iter().map(|(a, b, i)| (a, b, Some(i))));
    regions.sort_unstable_by_key(|r| (r.0, r.1));
    let describe = |r: &(u64, u64, Option<usize>)| match r.2 {
        Some(i) => format!("package {i} ({:016x}) meta block [0x{:x}, 0x{:x})", packages[i].title_id, r.0, r.1),
        None => format!("extent [0x{:x}, 0x{:x})", r.0, r.1),
    };
    let mut widest: Option<&(u64, u64, Option<usize>)> = None;
    for r in &regions {
        if let Some(w) = widest {
            if r.0 < w.1 {
                return Err(Error::bounds(format!("{spec}: {} overlaps {}", describe(r), describe(w))).with_offset(r.0));
            }
        }
        if widest.is_none_or(|w| r.1 > w.1) {
            widest = Some(r);
        }
    }
    Ok(())
}

pub(crate) fn derive_uuid(ids: impl Iterator<Item = (u64, u32, u8)>) -> [u8; 16] {
    let mut buf = Vec::new();
    for (t, v, k) in ids {
        buf.extend_from_slice(&t.to_le_bytes());
        buf.extend_from_slice(&v.to_le_bytes());
        buf.push(k);
    }
    let h = crate::crypto::sha256(&buf);
    h[..16].try_into().unwrap_or([0; 16])
}

/// One Zstandard frame decoded on demand (sequential reads stream; seeking backwards
/// restarts the frame).
pub(crate) struct ZstdFileSource {
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    extent: SharedSource,
    size: u64,
    state: Mutex<(Option<Box<dyn std::io::Read + Send>>, u64)>,
}

impl ZstdFileSource {
    pub fn new(extent: SharedSource, size: u64) -> Self {
        ZstdFileSource { extent, size, state: Mutex::new((None, 0)) }
    }
    fn restart(&self) -> Result<Box<dyn std::io::Read + Send>> {
        #[cfg(feature = "zstd")]
        {
            let r = crate::SourceReader::new(self.extent.clone())?;
            Ok(Box::new(crate::compression::ZstdReader::new(std::io::BufReader::new(r), self.size)?))
        }
        #[cfg(not(feature = "zstd"))]
        Err(Error::unsupported("reading zstd NUP extents requires the `zstd` feature"))
    }
}

impl crate::DataSource for ZstdFileSource {
    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        use std::io::Read;
        crate::check_range(offset, out.len() as u64, self.size)?;
        let mut st = self.state.lock().map_err(|_| Error::internal("zstd state poisoned"))?;
        if st.0.is_none() || st.1 > offset {
            st.0 = Some(self.restart()?);
            st.1 = 0;
        }
        let mut skip = offset - st.1;
        let pos = st.1;
        let r = st.0.as_mut().ok_or_else(|| Error::internal("no decoder"))?;
        let mut junk = vec![0u8; (1 << 16).min(skip.max(1) as usize)];
        while skip > 0 {
            let n = skip.min(junk.len() as u64) as usize;
            r.read_exact(&mut junk[..n]).map_err(|e| Error::codec(format!("zstd extent: {e}")))?;
            skip -= n as u64;
        }
        r.read_exact(out).map_err(|e| Error::codec(format!("zstd extent ended early: {e}")))?;
        st.1 = pos.max(offset) + out.len() as u64;
        Ok(())
    }
}

/// PackageReader for `.nup`.
pub struct NupReader {
    nup: Nup,
    table: NodeTable,
    /// (package index, entry path prefix)
    labels: Vec<String>,
    limits: crate::ResourceLimits,
}

fn package_labels(pkgs: &[NupPackage]) -> Vec<String> {
    let base: Vec<String> = pkgs
        .iter()
        .map(|p| match p.kind {
            KIND_BASE => "base".to_string(),
            KIND_UPDATE => format!("update-v{}", p.version),
            KIND_ADDON => format!("addon-{:016x}", p.title_id),
            k => format!("{}-{:016x}-v{}", kind_name(k), p.title_id, p.version),
        })
        .collect();
    base.iter().enumerate().map(|(i, l)| if base.iter().filter(|x| *x == l).count() > 1 { format!("{l}-{i}") } else { l.clone() }).collect()
}

impl NupReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let nup = Nup::open(source, &ctx.limits)?;
        let labels = package_labels(&nup.packages);
        let mut table = NodeTable::new();
        for (pi, p) in nup.packages.iter().enumerate() {
            let label = &labels[pi];
            let mut nodes: Vec<(String, u32)> = Vec::new();
            nup.walk(p.root_dir, &ctx.limits, &mut |path, id| {
                nodes.push((path.to_string(), id));
                Ok(())
            })?;
            for (path, id) in nodes {
                let full = if path.is_empty() { label.clone() } else { format!("{label}/{path}") };
                if nup.is_dir(id) {
                    let mut n = ContentNode::dir(0, full);
                    if path.is_empty() {
                        n = n
                            .kind(NodeKind::Partition)
                            .meta("kind", p.kind_name())
                            .meta("title_id", format!("{:016x}", p.title_id))
                            .meta("version", p.version as u64);
                    }
                    table.push(n, None);
                } else {
                    let f = nup.file(id);
                    let n = ContentNode::file(0, full, f.size)
                        .encrypted(false)
                        .meta("codec", if f.codec == CODEC_ZSTD { "zstd" } else { "raw" })
                        .meta("stored_size", f.extent_size)
                        .hash("sha256", hex(&f.sha256), None);
                    let n = if f.codec == CODEC_RAW && f.size > 0 { n.span(f.extent_offset, f.size) } else { n };
                    let data = nup.open_file(f)?;
                    table.push(n, Some(data));
                }
            }
        }
        Ok(NupReader { nup, table, labels, limits: ctx.limits })
    }
}

impl PackageReader for NupReader {
    fn format(&self) -> FormatId {
        SWITCH_NUP
    }
    fn info(&self) -> Result<PackageInfo> {
        let n = &self.nup;
        let mut i = PackageInfo::new(SWITCH_NUP, Platform::Switch, n.file_size);
        i.encrypted = Some(false);
        let app = n.app_package();
        i.title = app.text(TLV_TITLE_NAME);
        i.title_id = Some(format!("{:016x}", app.title_id));
        i.family_id = i.title_id.clone();
        i.version = app.text(TLV_DISPLAY_VERSION).or_else(|| Some(app.version.to_string()));
        i.category = if n.packages.len() > 1 {
            ContentCategory::MultiContent
        } else {
            match app.kind {
                KIND_BASE => ContentCategory::Application,
                KIND_UPDATE => ContentCategory::Patch,
                KIND_ADDON => ContentCategory::AddOn,
                _ => ContentCategory::Unknown,
            }
        };
        if let Some(p) = app.text(TLV_PUBLISHER) {
            i.field("publisher", p);
        }
        i.field("uuid", hex(&n.uuid));
        let list: Vec<crate::MetaValue> = n
            .packages
            .iter()
            .zip(&self.labels)
            .map(|(p, l)| {
                crate::MetaValue::Text(format!(
                    "{l}: {} {:016x} version {}{}{}",
                    p.kind_name(),
                    p.title_id,
                    p.version,
                    p.text(TLV_DISPLAY_VERSION).map(|v| format!(" ({v})")).unwrap_or_default(),
                    if p.flags & FLAG_STANDALONE_UPDATE != 0 { " [standalone update]" } else { "" }
                ))
            })
            .collect();
        i.fields.insert("packages".into(), crate::MetaValue::List(list));
        if let Some(b) = app.meta.get(&TLV_BUILD_ID) {
            i.field("build_id", hex(b));
        }
        if let Some(src) = app.text(TLV_SOURCE_DUMP) {
            i.field("source_dump", src);
        }
        if let Ok(names) = app.localized(TLV_LOCALIZED_TITLES) {
            if !names.is_empty() {
                i.field("localized_titles", names.iter().map(|(l, t)| format!("{l}: {}", String::from_utf8_lossy(t))).collect::<Vec<_>>());
            }
        }
        i.field("files", n.files.len() as u64);
        i.sizes.uncompressed = Some(n.files.iter().map(|f| f.size).sum());
        i.sizes.payload = Some(n.files.iter().map(|f| f.extent_size).sum());
        i.warnings.extend(n.warnings.iter().cloned());
        i.limitations.push("NUP carries no generation marker; Switch 1 and Switch 2 content are not distinguished".into());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let n = &self.nup;
        let mut r = VerifyReport::new(SWITCH_NUP, level);
        r.pass(CheckLevel::Structure, "superblock", Some(format!("{} packages, file size {}", n.packages.len(), n.file_size)));
        r.pass(
            CheckLevel::Structure,
            "TOC SHA-256",
            Some(format!("{} ({} bytes, blob region at 0x{:x})", hex(&n.toc_sha256), n.toc_size, n.blob_offset)),
        );
        r.pass(
            CheckLevel::Structure,
            "trees",
            Some(format!("{} directories, {} files; names, ranges and cycles checked", n.dirs.len(), n.files.len())),
        );
        r.check(CheckLevel::Structure, "UUID", n.expected_uuid() == n.uuid, "derived from package identities (§2.1)");
        for w in &n.warnings {
            r.warn(CheckLevel::Structure, "container", w.clone());
        }
        for (p, l) in n.packages.iter().zip(&self.labels) {
            for (t, name) in [(TLV_LOCALIZED_TITLES, "localized titles"), (TLV_LOCALIZED_ICONS, "localized icons")] {
                if let Err(e) = p.localized(t) {
                    r.fail(CheckLevel::Structure, &format!("{l} {name}"), e.to_string());
                }
            }
        }
        let _ = self.limits;
        if level.wants_content() {
            let total: u64 = n.files.iter().map(|f| f.size).sum();
            let mut prog = crate::ByteProgress::new(job, crate::Phase::Verifying, Some(total));
            let mut done: HashMap<(u64, u64, u8, u64, [u8; 32]), bool> = HashMap::new();
            let mut bad = 0usize;
            for f in &n.files {
                job.check_cancel()?;
                let key = (f.extent_offset, f.extent_size, f.codec, f.size, f.sha256);
                let ok = if f.size == 0 {
                    f.sha256 == crate::crypto::sha256(b"")
                } else if let Some(v) = done.get(&key) {
                    *v
                } else {
                    let v = match n
                        .open_file(f)
                        .and_then(|s| crate::crypto::hash_range(s.as_ref(), 0, f.size, crate::crypto::HashAlg::Sha256, Some(&mut prog)))
                    {
                        Ok(h) => h == f.sha256,
                        Err(e) if e.code() == crate::ErrorCode::Cancelled => return Err(e),
                        Err(_) => false,
                    };
                    done.insert(key, v);
                    v
                };
                if !ok {
                    bad += 1;
                    r.fail(CheckLevel::Content, &format!("{} SHA-256", f.name), "content does not match the recorded SHA-256");
                }
            }
            if bad == 0 {
                r.pass(CheckLevel::Content, "file SHA-256", Some(format!("{} files recomputed", n.files.len())));
            }
        }
        r.authenticity_unavailable("NUP has no signatures");
        r.limitation("compatibility with consuming emulators is not asserted");
        Ok(r)
    }
    fn content_graph(&self) -> Result<crate::ContentGraph> {
        let n = &self.nup;
        let mut g = crate::ContentGraph::default();
        let base = n.packages.iter().position(|p| p.kind == KIND_BASE);
        for (i, (p, l)) in n.packages.iter().zip(&self.labels).enumerate() {
            let role = match p.kind {
                KIND_BASE => crate::TitleRole::Base,
                KIND_UPDATE => crate::TitleRole::Update,
                KIND_ADDON | 3 => crate::TitleRole::AddOn,
                4 => crate::TitleRole::System,
                _ => crate::TitleRole::Unknown,
            };
            let mut md = crate::Metadata::new();
            if let Some(d) = p.text(TLV_DISPLAY_VERSION) {
                md.insert("display_version".into(), d.into());
            }
            if let Some(t) = p.text(TLV_TITLE_NAME) {
                md.insert("name".into(), t.into());
            }
            g.titles.push(crate::TitleRecord {
                key: l.clone(),
                title_id: format!("{:016x}", p.title_id),
                role,
                version: Some(p.version as u64),
                provenance: "nup package".into(),
                content_ids: Vec::new(),
                metadata: md,
            });
            let kind = match role {
                crate::TitleRole::Update => Some(crate::RelationKind::UpdateOf),
                crate::TitleRole::AddOn => Some(crate::RelationKind::AddOnOf),
                _ => None,
            };
            if let Some(kind) = kind {
                match base {
                    Some(b) if b != i => g.relations.push(crate::Relation { from: l.clone(), to: self.labels[b].clone(), kind }),
                    _ => g.unresolved.push(format!("{l} has no base package in this container")),
                }
            }
        }
        Ok(g)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(crate::switch::capabilities_for(SWITCH_NUP))
    }
}

// ---------------------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------------------

/// One package to write.
pub(crate) struct PackageInput {
    pub kind: u8,
    pub flags: u8,
    pub title_id: u64,
    pub version: u32,
    pub tree: crate::switch::native::Tree,
    /// Meta TLVs `(type, payload)`; written sorted by type.
    pub meta: Vec<(u16, Vec<u8>)>,
}

pub(crate) fn encode_localized(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut sorted: Vec<&(&str, &[u8])> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::new();
    for (tag, data) in sorted {
        out.push(tag.len() as u8);
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

enum Node {
    Dir(DirNode),
    File(usize),
}

#[derive(Default)]
struct DirNode {
    name: String,
    children: BTreeMap<String, Node>,
}

impl DirNode {
    fn dir_mut(&mut self, path: &str) -> Result<&mut DirNode> {
        let mut d = self;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if !valid_name(comp) {
                return Err(Error::unsafe_path(format!("invalid path component {comp:?}")));
            }
            let e =
                d.children.entry(comp.to_string()).or_insert_with(|| Node::Dir(DirNode { name: comp.to_string(), ..Default::default() }));
            d = match e {
                Node::Dir(x) => x,
                Node::File(_) => return Err(Error::conflict(format!("{path}: a file and a directory share a name"))),
            };
        }
        Ok(d)
    }
}

/// Serialized TOC model.
#[derive(Default)]
struct TocModel {
    dirs: Vec<(String, u32, u32)>,
    /// Global file index per TOC file record (into the flat input file list).
    files: Vec<usize>,
    children: Vec<u32>,
    /// Children slots referencing files are tagged until dir_count is known.
    pool: Vec<u8>,
    interned: HashMap<String, u32>,
}

const FILE_TAG: u32 = 0x8000_0000;

impl TocModel {
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&o) = self.interned.get(s) {
            return o;
        }
        let o = self.pool.len() as u32;
        self.pool.extend_from_slice(s.as_bytes());
        self.interned.insert(s.to_string(), o);
        o
    }
    /// Pre-order directories; per directory, file children numbered first (in name order),
    /// then subdirectories recursed (matching the reference packer's layout).
    fn assign(&mut self, d: &DirNode) -> u32 {
        let id = self.dirs.len() as u32;
        self.dirs.push((d.name.clone(), 0, 0));
        let base = self.children.len();
        self.children.extend(std::iter::repeat_n(0, d.children.len()));
        for (i, c) in d.children.values().enumerate() {
            if let Node::File(g) = c {
                self.children[base + i] = FILE_TAG | self.files.len() as u32;
                self.files.push(*g);
            }
        }
        for (i, c) in d.children.values().enumerate() {
            if let Node::Dir(x) = c {
                let cid = self.assign(x);
                self.children[base + i] = cid;
            }
        }
        self.dirs[id as usize].1 = base as u32;
        self.dirs[id as usize].2 = d.children.len() as u32;
        id
    }
}

/// Extent record for a written file.
#[derive(Clone, Copy)]
struct Extent {
    offset: u64,
    stored: u64,
    codec: u8,
    sha256: [u8; 32],
    size: u64,
}

#[cfg(feature = "zstd")]
struct Counting<'a, W: Write> {
    inner: &'a mut W,
    n: u64,
}
#[cfg(feature = "zstd")]
impl<W: Write> Write for Counting<'_, W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let k = self.inner.write(b)?;
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// Small under test so the streaming (bail-to-raw) path is exercised by fixtures.
#[cfg(feature = "zstd")]
const IN_MEMORY_LIMIT: u64 = if cfg!(test) { 1 << 16 } else { 64 << 20 };
#[cfg(feature = "zstd")]
const CHUNK: usize = if cfg!(test) { 1 << 14 } else { 4 << 20 };

fn write_zeros<W: Write>(w: &mut W, n: u64) -> Result<()> {
    let z = [0u8; 4096];
    let mut left = n;
    while left > 0 {
        let k = left.min(z.len() as u64) as usize;
        w.write_all(&z[..k])?;
        left -= k as u64;
    }
    Ok(())
}

/// Write one extent at `at` (already aligned and positioned). Returns (stored size, codec).
fn write_extent<W: Write + Seek>(out: &mut W, at: u64, f: &TreeFile, level: Option<i32>, job: &JobContext) -> Result<(u64, u8)> {
    let size = f.size;
    #[cfg(feature = "zstd")]
    if let Some(level) = level {
        if size <= IN_MEMORY_LIMIT {
            let data = read_vec(f.source.as_ref(), 0, size, size)?;
            job.check_cancel()?;
            let comp = crate::compression::compress(crate::compression::Codec::Zstd, &data, level)?;
            if (comp.len() as u64) < size {
                out.write_all(&comp)?;
                return Ok((comp.len() as u64, CODEC_ZSTD));
            }
            out.write_all(&data)?;
            return Ok((size, CODEC_RAW));
        }
        // Stream: bail to raw as soon as the output catches up with the input.
        let mut stored = 0u64;
        let mut bailed = false;
        {
            let mut cw = Counting { inner: out, n: 0 };
            let mut enc = zstd::stream::write::Encoder::new(&mut cw, level).map_err(|e| Error::codec(e.to_string()))?;
            enc.set_pledged_src_size(Some(size)).map_err(|e| Error::codec(e.to_string()))?;
            enc.include_contentsize(true).map_err(|e| Error::codec(e.to_string()))?;
            let mut buf = vec![0u8; CHUNK];
            let mut done = 0u64;
            while done < size {
                job.check_cancel()?;
                let n = ((size - done) as usize).min(CHUNK);
                f.source.read_exact_at(done, &mut buf[..n])?;
                enc.write_all(&buf[..n])?;
                done += n as u64;
                if enc.get_ref().n >= done {
                    bailed = true;
                    break;
                }
            }
            if !bailed {
                enc.finish().map_err(|e| Error::codec(e.to_string()))?;
            }
            stored = stored.max(cw.n);
            if !bailed && cw.n >= size {
                bailed = true;
            }
        }
        if !bailed {
            return Ok((stored, CODEC_ZSTD));
        }
        out.seek(SeekFrom::Start(at))?;
        crate::copy_range(f.source.as_ref(), 0, size, out, &mut crate::ByteProgress::new(job, crate::Phase::Writing, None))?;
        if stored > size {
            // Zero what the abandoned frame wrote past the raw extent (alignment gaps are zero).
            write_zeros(out, stored - size)?;
            out.seek(SeekFrom::Start(at + size))?;
        }
        return Ok((size, CODEC_RAW));
    }
    let _ = (level, at);
    crate::copy_range(f.source.as_ref(), 0, size, out, &mut crate::ByteProgress::new(job, crate::Phase::Writing, None))?;
    Ok((size, CODEC_RAW))
}

/// Statistics of a written container.
pub(crate) struct WriteStats {
    pub size: u64,
    pub files: usize,
    pub unique_extents: usize,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
}

/// Write a NUP container. `level` is the zstd level (`None` stores every file raw).
pub(crate) fn write(out: &mut crate::AtomicFile, packages: &[PackageInput], level: Option<i32>, job: &JobContext) -> Result<WriteStats> {
    if packages.is_empty() {
        return Err(Error::invalid_arg("a NUP container needs at least one package"));
    }
    // Flat file list across packages.
    let files: Vec<&TreeFile> = packages.iter().flat_map(|p| p.tree.files.iter()).collect();
    let mut toc = TocModel::default();
    let mut roots = Vec::new();
    let mut offset = 0usize;
    for p in packages {
        let mut root = DirNode::default();
        for d in &p.tree.dirs {
            root.dir_mut(d)?;
        }
        for (i, f) in p.tree.files.iter().enumerate() {
            let (parent, name) = f.path.rsplit_once('/').unwrap_or(("", f.path.as_str()));
            if !valid_name(name) {
                return Err(Error::unsafe_path(format!("invalid file name in {}", f.path)));
            }
            let d = root.dir_mut(parent)?;
            if d.children.insert(name.to_string(), Node::File(offset + i)).is_some() {
                return Err(Error::conflict(format!("duplicate path {}", f.path)));
            }
        }
        offset += p.tree.files.len();
        roots.push(root);
    }
    let mut root_ids = Vec::new();
    for r in &roots {
        root_ids.push(toc.assign(r));
    }
    let dir_count = toc.dirs.len() as u32;
    for c in toc.children.iter_mut() {
        if *c & FILE_TAG != 0 {
            *c = dir_count + (*c & !FILE_TAG);
        }
    }
    let names: Vec<String> = toc
        .dirs
        .iter()
        .map(|d| d.0.clone())
        .chain(toc.files.iter().map(|&g| {
            let p = &files[g].path;
            p.rsplit_once('/').map(|(_, n)| n).unwrap_or(p).to_string()
        }))
        .collect();
    for n in &names {
        toc.intern(n);
    }
    // Content directories: root children named exefs/romfs that hold at least one file.
    let mut has_files = vec![false; toc.dirs.len()];
    for i in (0..toc.dirs.len()).rev() {
        let (_, first, count) = toc.dirs[i];
        has_files[i] = (first..first + count).any(|s| {
            let c = toc.children[s as usize];
            c >= dir_count || has_files[c as usize]
        });
    }
    let content_dir = |root: u32, name: &str| -> u32 {
        let (_, first, count) = toc.dirs[root as usize];
        (first..first + count)
            .map(|s| toc.children[s as usize])
            .find(|&c| c < dir_count && toc.dirs[c as usize].0 == name && has_files[c as usize])
            .unwrap_or(NONE)
    };
    let toc_size = TOC_HEAD
        + packages.len() as u64 * PKG_SIZE
        + toc.dirs.len() as u64 * DIR_SIZE
        + toc.files.len() as u64 * FILE_SIZE
        + toc.children.len() as u64 * 4
        + toc.pool.len() as u64;
    let blob_offset = align16(HEADER_SIZE + toc_size)?;
    out.seek(SeekFrom::Start(0))?;
    write_zeros(out, blob_offset)?;
    // Extents, deduplicated by SHA-256 (plus size).
    let total: u64 = files.iter().map(|f| f.size).sum();
    let mut prog = crate::ByteProgress::new(job, crate::Phase::Writing, Some(total * 2));
    let mut cursor = blob_offset;
    let mut seen: HashMap<([u8; 32], u64), Extent> = HashMap::new();
    let mut extents: Vec<Extent> = Vec::with_capacity(files.len());
    for f in &files {
        job.check_cancel()?;
        let h = crate::crypto::hash_range(f.source.as_ref(), 0, f.size, crate::crypto::HashAlg::Sha256, Some(&mut prog))?;
        let sha: [u8; 32] = h.as_slice().try_into().map_err(|_| Error::internal("sha256 length"))?;
        if f.size == 0 {
            extents.push(Extent { offset: 0, stored: 0, codec: CODEC_RAW, sha256: sha, size: 0 });
            continue;
        }
        if let Some(e) = seen.get(&(sha, f.size)) {
            extents.push(*e);
            prog.advance(f.size)?;
            continue;
        }
        let at = align16(cursor)?;
        write_zeros(out, at - cursor)?;
        let (stored, codec) = write_extent(out, at, f, level, job)?;
        prog.advance(f.size)?;
        cursor = at + stored;
        let e = Extent { offset: at, stored, codec, sha256: sha, size: f.size };
        seen.insert((sha, f.size), e);
        extents.push(e);
    }
    // Meta blocks follow the extents.
    let mut metas = Vec::new();
    for p in packages {
        let mut recs: Vec<&(u16, Vec<u8>)> = p.meta.iter().collect();
        recs.sort_by_key(|r| r.0);
        recs.dedup_by_key(|r| r.0);
        let mut block = Vec::new();
        for (t, payload) in recs {
            block.extend_from_slice(&t.to_le_bytes());
            block.extend_from_slice(&0u16.to_le_bytes());
            block.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            block.extend_from_slice(payload);
        }
        if block.is_empty() {
            metas.push((0u64, 0u32));
        } else {
            out.write_all(&block)?;
            metas.push((cursor, block.len() as u32));
            cursor += block.len() as u64;
        }
    }
    let file_size = cursor;
    // TOC.
    let mut t = Vec::with_capacity(toc_size as usize);
    t.extend_from_slice(TOC_MAGIC);
    t.extend_from_slice(&(packages.len() as u32).to_le_bytes());
    t.extend_from_slice(&(toc.dirs.len() as u64).to_le_bytes());
    t.extend_from_slice(&(toc.files.len() as u64).to_le_bytes());
    let pool_off = toc_size - toc.pool.len() as u64;
    t.extend_from_slice(&pool_off.to_le_bytes());
    t.extend_from_slice(&(toc.pool.len() as u64).to_le_bytes());
    t.extend_from_slice(&0u64.to_le_bytes());
    for ((p, &root), &(mo, ms)) in packages.iter().zip(&root_ids).zip(&metas) {
        t.extend_from_slice(&p.title_id.to_le_bytes());
        t.extend_from_slice(&root.to_le_bytes());
        t.extend_from_slice(&content_dir(root, "exefs").to_le_bytes());
        t.extend_from_slice(&content_dir(root, "romfs").to_le_bytes());
        t.extend_from_slice(&p.version.to_le_bytes());
        t.push(p.kind);
        t.push(p.flags);
        t.extend_from_slice(&[0u8; 6]);
        t.extend_from_slice(&mo.to_le_bytes());
        t.extend_from_slice(&ms.to_le_bytes());
        t.extend_from_slice(&[0u8; 20]);
    }
    for (name, first, count) in &toc.dirs {
        let off = toc.interned[name];
        t.extend_from_slice(&off.to_le_bytes());
        t.extend_from_slice(&(name.len() as u32).to_le_bytes());
        t.extend_from_slice(&first.to_le_bytes());
        t.extend_from_slice(&count.to_le_bytes());
        t.extend_from_slice(&0u64.to_le_bytes());
    }
    for (i, &g) in toc.files.iter().enumerate() {
        let name = &names[toc.dirs.len() + i];
        let e = &extents[g];
        t.extend_from_slice(&toc.interned[name].to_le_bytes());
        t.extend_from_slice(&(name.len() as u32).to_le_bytes());
        t.extend_from_slice(&e.size.to_le_bytes());
        t.extend_from_slice(&e.offset.to_le_bytes());
        t.extend_from_slice(&e.stored.to_le_bytes());
        t.extend_from_slice(&e.sha256);
        t.push(e.codec);
        t.push(0);
        t.extend_from_slice(&[0u8; 14]);
    }
    for c in &toc.children {
        t.extend_from_slice(&c.to_le_bytes());
    }
    t.extend_from_slice(&toc.pool);
    if t.len() as u64 != toc_size {
        return Err(Error::internal(format!("NUP TOC size {} differs from the plan {toc_size}", t.len())));
    }
    let uuid = derive_uuid(packages.iter().map(|p| (p.title_id, p.version, p.kind)));
    let mut sb = Vec::with_capacity(HEADER_SIZE as usize);
    sb.extend_from_slice(MAGIC);
    sb.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    sb.extend_from_slice(&1u16.to_le_bytes());
    sb.extend_from_slice(&HEADER_SIZE.to_le_bytes());
    sb.extend_from_slice(&toc_size.to_le_bytes());
    sb.extend_from_slice(&crate::crypto::sha256(&t));
    sb.extend_from_slice(&blob_offset.to_le_bytes());
    sb.extend_from_slice(&file_size.to_le_bytes());
    sb.extend_from_slice(&(packages.len() as u32).to_le_bytes());
    sb.extend_from_slice(&0u32.to_le_bytes());
    sb.extend_from_slice(&uuid);
    sb.extend_from_slice(&[0u8; 32]);
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&sb)?;
    out.write_all(&t)?;
    out.seek(SeekFrom::Start(file_size))?;
    // An abandoned compression attempt at the very end may have written past file_size.
    out.flush_for_verify()?.set_len(file_size)?;
    Ok(WriteStats {
        size: file_size,
        files: files.len(),
        unique_extents: seen.len(),
        logical_bytes: total,
        stored_bytes: seen.values().map(|e| e.stored).sum(),
    })
}
