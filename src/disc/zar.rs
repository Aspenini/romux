//! ZArchive (`.zar`): a read-optimised archive of zstd-compressed 64 KiB blocks plus a
//! sorted file tree, used to store extracted game trees (for example Wii U titles for Cemu
//! and Xbox 360 titles for Xenia).
//!
//! Layout (all big-endian): compressed blocks, offset records (one base offset and sixteen
//! `size - 1` values per record), a name table, a file tree of 16-byte entries, optional
//! meta sections, and a 0x90-byte footer ending in version `0x61BF3A01` and magic
//! `0x169F52D6`. The footer carries a SHA-256 integrity hash over the whole file computed
//! with the hash field zeroed.

use crate::binary::{u16be, u32be, u64be};
use crate::compression::{Codec, compress, decompress};
use crate::disc::DataSource;
use crate::{ByteProgress, Error, JobContext, Phase, ResourceLimits, Result, SharedSource, read_vec};
use std::io::{Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

pub const MAGIC: u32 = 0x169F_52D6;
pub const VERSION1: u32 = 0x61BF_3A01;
pub const BLOCK: u64 = 64 * 1024;
pub const FOOTER: u64 = 0x90;
const PER_RECORD: u64 = 16;
const RECORD: u64 = 8 + PER_RECORD * 2;

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Section {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Footer {
    pub compressed_data: Section,
    pub offset_records: Section,
    pub names: Section,
    pub file_tree: Section,
    pub meta_directory: Section,
    pub meta_data: Section,
    #[serde(skip)]
    pub integrity_hash: [u8; 32],
    pub total_size: u64,
    pub version: u32,
}

pub fn probe(s: &dyn DataSource) -> bool {
    let len = s.len().unwrap_or(0);
    if len < FOOTER {
        return false;
    }
    let mut t = [0u8; 8];
    s.read_exact_at(len - 8, &mut t).is_ok()
        && u32::from_be_bytes([t[4], t[5], t[6], t[7]]) == MAGIC
        && u32::from_be_bytes([t[0], t[1], t[2], t[3]]) == VERSION1
}

impl Footer {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let len = s.len()?;
        if len < FOOTER {
            return Err(Error::malformed("file too small for a ZArchive footer"));
        }
        let f = read_vec(s, len - FOOTER, FOOTER, FOOTER)?;
        let sec = |i: usize| -> Result<Section> { Ok(Section { offset: u64be(&f, i * 16)?, size: u64be(&f, i * 16 + 8)? }) };
        let footer = Footer {
            compressed_data: sec(0)?,
            offset_records: sec(1)?,
            names: sec(2)?,
            file_tree: sec(3)?,
            meta_directory: sec(4)?,
            meta_data: sec(5)?,
            integrity_hash: crate::binary::array(&f, 0x60)?,
            total_size: u64be(&f, 0x80)?,
            version: u32be(&f, 0x88)?,
        };
        if u32be(&f, 0x8C)? != MAGIC || footer.version != VERSION1 {
            return Err(Error::malformed("missing ZArchive magic/version"));
        }
        if footer.total_size != len {
            return Err(Error::bounds(format!("ZArchive declares {} bytes but the file has {len}", footer.total_size)));
        }
        for (n, s) in
            [("data", footer.compressed_data), ("offsets", footer.offset_records), ("names", footer.names), ("tree", footer.file_tree)]
        {
            if s.offset.checked_add(s.size).is_none_or(|e| e > len - FOOTER) {
                return Err(Error::bounds(format!("ZArchive {n} section exceeds the file")));
            }
        }
        Ok(footer)
    }
}

#[derive(Debug, Clone)]
pub struct ZarEntry {
    pub path: String,
    pub is_dir: bool,
    pub offset: u64,
    pub size: u64,
}

pub struct ZArchive {
    src: SharedSource,
    pub footer: Footer,
    records: Vec<u8>,
    blocks: u64,
    pub entries: Vec<ZarEntry>,
    cache: Mutex<Option<(u64, Arc<Vec<u8>>)>>,
}

fn read_name(names: &[u8], off: usize, limits: &ResourceLimits) -> Result<String> {
    let b0 = *names.get(off).ok_or_else(|| Error::malformed("name offset beyond name table"))? as usize;
    let (len, start) = if b0 & 0x80 != 0 {
        let b1 = *names.get(off + 1).ok_or_else(|| Error::malformed("truncated name length"))? as usize;
        ((b0 & 0x7F) | (b1 << 7), off + 2)
    } else {
        (b0, off + 1)
    };
    if len > limits.max_name_len {
        return Err(Error::limit("ZArchive name too long"));
    }
    let b = crate::binary::slice(names, start, len)?;
    String::from_utf8(b.to_vec()).map_err(|_| Error::malformed("ZArchive name is not UTF-8"))
}

impl ZArchive {
    pub fn open(src: SharedSource, limits: &ResourceLimits) -> Result<Self> {
        let footer = Footer::parse(src.as_ref())?;
        let records = read_vec(src.as_ref(), footer.offset_records.offset, footer.offset_records.size, limits.max_metadata)?;
        let names = read_vec(src.as_ref(), footer.names.offset, footer.names.size, limits.max_metadata)?;
        let tree = read_vec(src.as_ref(), footer.file_tree.offset, footer.file_tree.size, limits.max_metadata)?;
        if tree.len() < 16 || tree.len() % 16 != 0 {
            return Err(Error::malformed("ZArchive file tree is empty or misaligned"));
        }
        let n = tree.len() / 16;
        if n as u64 > limits.max_entries {
            return Err(Error::limit("too many ZArchive entries"));
        }
        let blocks = records.len() as u64 / RECORD * PER_RECORD;
        let uncompressed = blocks * BLOCK;
        let mut entries = Vec::new();
        let mut stack: Vec<(usize, String, u32)> = vec![(0, String::new(), 0)];
        let mut visited = vec![false; n];
        while let Some((idx, prefix, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(Error::limit("ZArchive nesting too deep"));
            }
            if std::mem::replace(&mut visited[idx], true) {
                return Err(Error::malformed("ZArchive file tree contains a loop"));
            }
            let e = &tree[idx * 16..idx * 16 + 16];
            let tn = u32be(e, 0)?;
            if tn & 0x8000_0000 != 0 {
                return Err(Error::malformed("ZArchive directory entry expected"));
            }
            let start = u32be(e, 4)? as usize;
            let count = u32be(e, 8)? as usize;
            if start.checked_add(count).is_none_or(|end| end > n) {
                return Err(Error::bounds("ZArchive directory children exceed the tree"));
            }
            for c in start..start + count {
                let ce = &tree[c * 16..c * 16 + 16];
                let ctn = u32be(ce, 0)?;
                let name = read_name(&names, (ctn & 0x7FFF_FFFF) as usize, limits)?;
                if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
                    return Err(Error::unsafe_path(format!("invalid ZArchive entry name {name:?}")));
                }
                let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
                if ctn & 0x8000_0000 != 0 {
                    let offset = u32be(ce, 4)? as u64 | ((u16be(ce, 14)? as u64) << 32);
                    let size = u32be(ce, 8)? as u64 | ((u16be(ce, 12)? as u64) << 32);
                    if offset.checked_add(size).is_none_or(|end| end > uncompressed) {
                        return Err(Error::bounds(format!("ZArchive file {path} exceeds the data")));
                    }
                    entries.push(ZarEntry { path, is_dir: false, offset, size });
                } else {
                    entries.push(ZarEntry { path: path.clone(), is_dir: true, offset: 0, size: 0 });
                    stack.push((c, path, depth + 1));
                }
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(ZArchive { src, footer, records, blocks, entries, cache: Mutex::new(None) })
    }

    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    fn block_location(&self, i: u64) -> Result<(u64, u64)> {
        let r = (i / PER_RECORD * RECORD) as usize;
        let k = (i % PER_RECORD) as usize;
        let mut off = self.footer.compressed_data.offset + u64be(&self.records, r)?;
        for j in 0..k {
            off += u16be(&self.records, r + 8 + j * 2)? as u64 + 1;
        }
        Ok((off, u16be(&self.records, r + 8 + k * 2)? as u64 + 1))
    }

    /// Decompressed bytes of block `i`.
    pub fn block(&self, i: u64) -> Result<Arc<Vec<u8>>> {
        if let Some((b, d)) = self.cache.lock().map_err(|_| Error::internal("poisoned"))?.as_ref() {
            if *b == i {
                return Ok(d.clone());
            }
        }
        if i >= self.blocks {
            return Err(Error::bounds("ZArchive block index beyond the offset records"));
        }
        let (off, size) = self.block_location(i)?;
        let raw = read_vec(self.src.as_ref(), off, size, BLOCK)?;
        let d = Arc::new(if size == BLOCK {
            raw
        } else {
            decompress(Codec::Zstd, &raw, None, BLOCK as usize).map_err(|e| e.with_offset(off))?
        });
        *self.cache.lock().map_err(|_| Error::internal("poisoned"))? = Some((i, d.clone()));
        Ok(d)
    }

    pub fn open_entry(self: &Arc<Self>, e: &ZarEntry) -> Result<SharedSource> {
        if e.is_dir {
            return Err(Error::invalid_arg("cannot open a directory"));
        }
        Ok(Arc::new(ZarFile { archive: self.clone(), offset: e.offset, size: e.size }))
    }

    /// Recompute the footer integrity hash (SHA-256 of the file with the hash field zeroed).
    pub fn verify_integrity(&self, job: &JobContext) -> Result<bool> {
        let len = self.src.len()?;
        let hash_at = len - FOOTER + 0x60;
        let mut h = crate::crypto::StreamHasher::new(crate::crypto::HashAlg::Sha256);
        let mut p = ByteProgress::new(job, Phase::Verifying, Some(len));
        let mut buf = vec![0u8; 1 << 20];
        let mut pos = 0u64;
        while pos < len {
            let n = ((len - pos) as usize).min(buf.len());
            self.src.read_exact_at(pos, &mut buf[..n])?;
            for (k, b) in buf[..n].iter_mut().enumerate() {
                let at = pos + k as u64;
                if at >= hash_at && at < hash_at + 32 {
                    *b = 0;
                }
            }
            h.update(&buf[..n]);
            pos += n as u64;
            p.advance(n as u64)?;
        }
        Ok(h.finish()[..] == self.footer.integrity_hash)
    }
}

struct ZarFile {
    archive: Arc<ZArchive>,
    offset: u64,
    size: u64,
}

impl DataSource for ZarFile {
    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }
    fn read_exact_at(&self, offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.size)?;
        let mut pos = self.offset + offset;
        while !out.is_empty() {
            let b = self.archive.block(pos / BLOCK)?;
            let within = (pos % BLOCK) as usize;
            if within >= b.len() {
                return Err(Error::bounds("ZArchive block shorter than expected"));
            }
            let n = (b.len() - within).min(out.len());
            out[..n].copy_from_slice(&b[within..within + n]);
            out = &mut out[n..];
            pos += n as u64;
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------
// Writer
// ------------------------------------------------------------------------------------------

#[derive(Default)]
struct WDir {
    dirs: std::collections::BTreeMap<String, WDir>,
    files: std::collections::BTreeMap<String, SharedSource>,
}

/// Deterministic ZArchive writer.
#[derive(Default)]
pub struct ZarBuilder {
    root: WDir,
    count: usize,
}

fn sort_key(s: &str) -> String {
    s.to_lowercase()
}

impl ZarBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: &str, data: SharedSource) -> Result<()> {
        let comps = crate::path::sanitize_components(path, 0x7FFF)?;
        let mut cur = &mut self.root;
        for c in &comps[..comps.len() - 1] {
            cur = cur.dirs.entry(c.clone()).or_default();
        }
        let last = comps[comps.len() - 1].clone();
        if cur.files.keys().chain(cur.dirs.keys()).any(|k| sort_key(k) == sort_key(&last)) {
            return Err(Error::conflict(format!("duplicate (case-insensitive) path {path}")));
        }
        cur.files.insert(last, data);
        self.count += 1;
        Ok(())
    }

    /// Write the archive. Returns the number of files.
    pub fn write<W: Write + Seek>(self, out: &mut W, level: i32, job: &JobContext) -> Result<usize> {
        // Flatten breadth-first: each directory's children are contiguous and sorted
        // case-insensitively (readers binary-search them).
        struct Node<'a> {
            name: String,
            dir: Option<&'a WDir>,
            file: Option<SharedSource>,
        }
        let mut nodes: Vec<Node> = vec![Node { name: String::new(), dir: Some(&self.root), file: None }];
        let mut children: Vec<(u32, u32)> = vec![(0, 0)];
        let mut i = 0;
        while i < nodes.len() {
            if let Some(d) = nodes[i].dir {
                let mut kids: Vec<Node> = d
                    .dirs
                    .iter()
                    .map(|(n, sub)| Node { name: n.clone(), dir: Some(sub), file: None })
                    .chain(d.files.iter().map(|(n, s)| Node { name: n.clone(), dir: None, file: Some(s.clone()) }))
                    .collect();
                kids.sort_by_key(|k| sort_key(&k.name));
                children[i] = (nodes.len() as u32, kids.len() as u32);
                for k in kids {
                    nodes.push(k);
                    children.push((0, 0));
                }
            }
            i += 1;
        }
        // Stream file data through 64 KiB blocks.
        let total: u64 = nodes.iter().filter_map(|n| n.file.as_ref()).map(|s| s.len().unwrap_or(0)).sum();
        let mut p = ByteProgress::new(job, Phase::Writing, Some(total));
        let mut file_offsets = vec![(0u64, 0u64); nodes.len()];
        let mut block = Vec::with_capacity(BLOCK as usize);
        let mut sizes: Vec<u16> = Vec::new();
        let mut written = 0u64;
        let mut logical = 0u64;
        let flush = |block: &mut Vec<u8>, out: &mut W, sizes: &mut Vec<u16>, written: &mut u64| -> Result<()> {
            if block.is_empty() {
                return Ok(());
            }
            let c = compress(Codec::Zstd, block, level)?;
            // Blocks that do not shrink are stored raw as a full 64 KiB block (size field 0xFFFF).
            if (c.len() as u64) >= BLOCK {
                block.resize(BLOCK as usize, 0);
            }
            let data: &[u8] = if (c.len() as u64) < BLOCK { &c } else { block };
            out.write_all(data)?;
            sizes.push((data.len() - 1) as u16);
            *written += data.len() as u64;
            block.clear();
            Ok(())
        };
        let mut buf = vec![0u8; BLOCK as usize];
        for (idx, n) in nodes.iter().enumerate() {
            let Some(src) = &n.file else { continue };
            let len = src.len()?;
            file_offsets[idx] = (logical, len);
            let mut pos = 0u64;
            while pos < len {
                job.check_cancel()?;
                let room = BLOCK as usize - block.len();
                let k = ((len - pos) as usize).min(room);
                src.read_exact_at(pos, &mut buf[..k])?;
                block.extend_from_slice(&buf[..k]);
                pos += k as u64;
                if block.len() as u64 == BLOCK {
                    flush(&mut block, out, &mut sizes, &mut written)?;
                }
                p.advance(k as u64)?;
            }
            logical += len;
        }
        flush(&mut block, out, &mut sizes, &mut written)?;
        let data_size = written;
        // Offset records.
        let mut rec = Vec::new();
        let mut base = 0u64;
        for chunk in sizes.chunks(PER_RECORD as usize) {
            rec.extend_from_slice(&base.to_be_bytes());
            for k in 0..PER_RECORD as usize {
                rec.extend_from_slice(&chunk.get(k).copied().unwrap_or(0).to_be_bytes());
            }
            base += chunk.iter().map(|s| *s as u64 + 1).sum::<u64>();
        }
        // Names.
        let mut names = Vec::new();
        let mut name_offs = vec![0x7FFF_FFFFu32; nodes.len()];
        for (i, n) in nodes.iter().enumerate().skip(1) {
            name_offs[i] = names.len() as u32;
            let b = n.name.as_bytes();
            if b.len() >= 0x80 {
                names.push(0x80 | (b.len() & 0x7F) as u8);
                names.push((b.len() >> 7) as u8);
            } else {
                names.push(b.len() as u8);
            }
            names.extend_from_slice(b);
        }
        // Tree.
        let mut tree = Vec::with_capacity(nodes.len() * 16);
        for (i, n) in nodes.iter().enumerate() {
            if n.file.is_some() {
                let (o, s) = file_offsets[i];
                tree.extend_from_slice(&(name_offs[i] | 0x8000_0000).to_be_bytes());
                tree.extend_from_slice(&(o as u32).to_be_bytes());
                tree.extend_from_slice(&(s as u32).to_be_bytes());
                tree.extend_from_slice(&((s >> 32) as u16).to_be_bytes());
                tree.extend_from_slice(&((o >> 32) as u16).to_be_bytes());
            } else {
                tree.extend_from_slice(&name_offs[i].to_be_bytes());
                tree.extend_from_slice(&children[i].0.to_be_bytes());
                tree.extend_from_slice(&children[i].1.to_be_bytes());
                tree.extend_from_slice(&0u32.to_be_bytes());
            }
        }
        let rec_off = data_size;
        let names_off = rec_off + rec.len() as u64;
        let tree_off = names_off + names.len() as u64;
        let meta_off = tree_off + tree.len() as u64;
        out.write_all(&rec)?;
        out.write_all(&names)?;
        out.write_all(&tree)?;
        let total_size = meta_off + FOOTER;
        let mut f = Vec::with_capacity(FOOTER as usize);
        for (o, s) in [
            (0, data_size),
            (rec_off, rec.len() as u64),
            (names_off, names.len() as u64),
            (tree_off, tree.len() as u64),
            (meta_off, 0),
            (meta_off, 0),
        ] {
            f.extend_from_slice(&o.to_be_bytes());
            f.extend_from_slice(&s.to_be_bytes());
        }
        f.extend_from_slice(&[0u8; 32]);
        f.extend_from_slice(&total_size.to_be_bytes());
        f.extend_from_slice(&VERSION1.to_be_bytes());
        f.extend_from_slice(&MAGIC.to_be_bytes());
        out.write_all(&f)?;
        out.flush()?;
        // The integrity hash is filled in by [`finalize_hash`] once the bytes are on disk.
        Ok(self.count)
    }
}

/// Write the integrity hash into a finished archive (needs read access to the bytes).
pub fn finalize_hash(file: &std::path::Path) -> Result<()> {
    let src = crate::FileSource::open(file)?;
    let len = src.len()?;
    let hash_at = len - FOOTER + 0x60;
    let mut h = crate::crypto::StreamHasher::new(crate::crypto::HashAlg::Sha256);
    let mut buf = vec![0u8; 1 << 20];
    let mut pos = 0;
    while pos < len {
        let n = ((len - pos) as usize).min(buf.len());
        src.read_exact_at(pos, &mut buf[..n])?;
        h.update(&buf[..n]);
        pos += n as u64;
    }
    drop(src);
    let hash = h.finish();
    let mut f = std::fs::OpenOptions::new().write(true).open(file)?;
    f.seek(SeekFrom::Start(hash_at))?;
    f.write_all(&hash)?;
    f.sync_all()?;
    Ok(())
}
