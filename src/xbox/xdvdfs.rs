//! XDVDFS reader and builder.
//!
//! Directory tables are binary search trees of entries (left/right child offsets in
//! dwords). Entries never cross 2048-byte sector boundaries; unused bytes are 0xFF.

use crate::binary::{ByteWriter, u16le, u32le};
use crate::{DataSource, Error, JobContext, ResourceLimits, Result, SharedSource, SubSource, read_vec};
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::Path;

pub const SECTOR: u64 = 2048;
pub const MAGIC: &[u8; 20] = b"MICROSOFT*XBOX*MEDIA";
pub const ATTR_DIR: u8 = 0x10;

pub fn has_descriptor(s: &dyn DataSource, base: u64) -> bool {
    let mut m = [0u8; 20];
    s.read_exact_at(base + 32 * SECTOR, &mut m).is_ok() && &m == MAGIC
}

#[derive(Debug, Clone)]
pub struct XEntry {
    pub path: String,
    pub is_dir: bool,
    pub sector: u32,
    pub size: u32,
}

pub struct Xdvdfs {
    source: SharedSource,
    pub base: u64,
    pub root_sector: u32,
    pub root_size: u32,
    pub entries: Vec<XEntry>,
    pub warnings: Vec<String>,
}

impl Xdvdfs {
    pub fn open(source: SharedSource, base: u64, limits: &ResourceLimits) -> Result<Self> {
        let d = read_vec(source.as_ref(), base + 32 * SECTOR, SECTOR, SECTOR)?;
        if &d[..20] != MAGIC || &d[0x7EC..0x800] != MAGIC {
            return Err(Error::malformed("XDVDFS volume descriptor magic missing"));
        }
        let root_sector = u32le(&d, 20)?;
        let root_size = u32le(&d, 24)?;
        let mut fs = Xdvdfs { source, base, root_sector, root_size, entries: Vec::new(), warnings: Vec::new() };
        let mut visited = HashSet::new();
        fs.walk_dir(root_sector, root_size, String::new(), 0, &mut visited, limits)?;
        fs.entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(fs)
    }

    pub fn abs(&self, sector: u32) -> u64 {
        self.base + sector as u64 * SECTOR
    }

    fn walk_dir(
        &mut self,
        sector: u32,
        size: u32,
        prefix: String,
        depth: u32,
        visited: &mut HashSet<u32>,
        limits: &ResourceLimits,
    ) -> Result<()> {
        if depth > limits.max_depth {
            return Err(Error::limit("XDVDFS nesting too deep"));
        }
        if size == 0 {
            return Ok(());
        }
        if !visited.insert(sector) {
            self.warnings.push(format!("directory at sector {sector} visited twice (loop ignored)"));
            return Ok(());
        }
        let table = read_vec(self.source.as_ref(), self.abs(sector), size as u64, limits.max_metadata)?;
        let mut stack = vec![0usize];
        let mut seen = HashSet::new();
        let mut subdirs = Vec::new();
        while let Some(off) = stack.pop() {
            if off + 14 > table.len() || !seen.insert(off) {
                continue;
            }
            if table[off..off + 4] == [0xFF; 4] {
                continue;
            }
            let left = u16le(&table, off)? as usize * 4;
            let right = u16le(&table, off + 2)? as usize * 4;
            let start = u32le(&table, off + 4)?;
            let fsize = u32le(&table, off + 8)?;
            let attr = table[off + 12];
            let nl = table[off + 13] as usize;
            let name_b = crate::binary::slice(&table, off + 14, nl)?;
            let name = String::from_utf8_lossy(name_b).into_owned();
            if left != 0 {
                stack.push(left);
            }
            if right != 0 {
                stack.push(right);
            }
            if name.is_empty() {
                continue;
            }
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            let is_dir = attr & ATTR_DIR != 0;
            if !is_dir && self.abs(start) + fsize as u64 > self.source.len()? {
                self.warnings.push(format!("{path} extends beyond the image"));
            }
            self.entries.push(XEntry { path: path.clone(), is_dir, sector: start, size: fsize });
            if self.entries.len() as u64 > limits.max_entries {
                return Err(Error::limit("too many XDVDFS entries"));
            }
            if is_dir {
                subdirs.push((start, fsize, path));
            }
        }
        for (s, z, p) in subdirs {
            self.walk_dir(s, z, p, depth + 1, visited, limits)?;
        }
        Ok(())
    }

    pub fn open_file(&self, e: &XEntry) -> Result<SharedSource> {
        SubSource::shared(self.source.clone(), self.abs(e.sector), e.size as u64)
    }

    /// Bytes from the partition start to the end of the last used sector.
    pub fn used_end(&self) -> Result<u64> {
        let mut end = 33 * SECTOR;
        let root_end = self.root_sector as u64 * SECTOR + (self.root_size as u64).div_ceil(SECTOR) * SECTOR;
        end = end.max(root_end);
        for e in &self.entries {
            end = end.max(e.sector as u64 * SECTOR + (e.size as u64).div_ceil(SECTOR) * SECTOR);
        }
        Ok(end.min(self.source.len()? - self.base))
    }
}

enum BNode {
    Dir(BTreeMap<String, BNode>),
    File(SharedSource),
}

/// Deterministic XISO builder.
#[derive(Default)]
pub struct XisoBuilder {
    root: BTreeMap<String, BNode>,
    count: usize,
}

fn key(n: &str) -> String {
    n.to_ascii_uppercase()
}

impl XisoBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file. Names compare case-insensitively (XDVDFS lookups are case-insensitive).
    pub fn add_file(&mut self, path: &str, data: SharedSource) -> Result<()> {
        let comps = crate::path::sanitize_components(path, 255)?;
        if data.len()? > u32::MAX as u64 {
            return Err(Error::unsupported(format!("{path} exceeds the 4 GiB XDVDFS file limit")));
        }
        let mut cur = &mut self.root;
        for c in &comps[..comps.len() - 1] {
            if let Some((k, _)) = cur.iter().find(|(k, _)| key(k) == key(c) && *k != c) {
                return Err(Error::conflict(format!("{c} collides case-insensitively with {k}")));
            }
            let e = cur.entry(c.clone()).or_insert_with(|| BNode::Dir(BTreeMap::new()));
            cur = match e {
                BNode::Dir(d) => d,
                BNode::File(_) => return Err(Error::conflict(format!("{c} is both a file and a directory"))),
            };
        }
        let last = &comps[comps.len() - 1];
        if cur.keys().any(|k| key(k) == key(last)) {
            return Err(Error::conflict(format!("duplicate (case-insensitive) path {path}")));
        }
        if last.len() > 255 {
            return Err(Error::invalid_arg("XDVDFS names are limited to 255 bytes"));
        }
        cur.insert(last.clone(), BNode::File(data));
        self.count += 1;
        Ok(())
    }

    pub fn add_dir_tree(&mut self, dir: &Path) -> Result<()> {
        let mut stack = vec![(dir.to_path_buf(), String::new())];
        while let Some((d, rel)) = stack.pop() {
            let mut items: Vec<_> = std::fs::read_dir(&d)?.collect::<std::io::Result<Vec<_>>>()?;
            items.sort_by_key(|e| e.file_name());
            for e in items {
                let ft = e.file_type()?;
                let name = e.file_name().to_string_lossy().into_owned();
                let r = if rel.is_empty() { name } else { format!("{rel}/{name}") };
                if ft.is_symlink() {
                    return Err(Error::unsafe_path(format!("symlink {r} is not followed")));
                } else if ft.is_dir() {
                    stack.push((e.path(), r));
                } else {
                    self.add_file(&r, std::sync::Arc::new(crate::FileSource::open(e.path())?))?;
                }
            }
        }
        Ok(())
    }

    /// Write the image; returns the number of files.
    pub fn write(self, out: &mut dyn Write, job: &JobContext) -> Result<usize> {
        // Assign sectors: directories breadth-first after the descriptor, then files.
        struct Dir<'a> {
            map: &'a BTreeMap<String, BNode>,
            sector: u32,
            size: u32,
        }
        let mut dirs: Vec<Dir> = vec![Dir { map: &self.root, sector: 0, size: 0 }];
        let mut i = 0;
        while i < dirs.len() {
            let m = dirs[i].map;
            for n in m.values() {
                if let BNode::Dir(d) = n {
                    dirs.push(Dir { map: d, sector: 0, size: 0 });
                }
            }
            i += 1;
        }
        let mut next = 33u32;
        let mut tables: Vec<Vec<u8>> = Vec::new();
        // Table sizes depend only on names; compute layout per directory.
        let mut layouts = Vec::new();
        for d in dirs.iter_mut() {
            let (offsets, size) = Self::layout(d.map);
            d.sector = next;
            d.size = size.max(SECTOR as u32);
            next += d.size.div_ceil(SECTOR as u32);
            layouts.push(offsets);
        }
        let mut files: Vec<(&SharedSource, u32)> = Vec::new();
        let mut file_sector: BTreeMap<*const BNode, u32> = BTreeMap::new();
        for d in &dirs {
            for n in d.map.values() {
                if let BNode::File(s) = n {
                    let len = s.len()?;
                    file_sector.insert(n as *const BNode, if len == 0 { 0 } else { next });
                    if len > 0 {
                        files.push((s, next));
                        next += len.div_ceil(SECTOR) as u32;
                    }
                }
            }
        }
        // Map dir node pointers to sectors (child dirs appear in BFS order).
        let mut dir_info: BTreeMap<*const BTreeMap<String, BNode>, (u32, u32)> = BTreeMap::new();
        for d in &dirs {
            dir_info.insert(d.map as *const _, (d.sector, d.size));
        }
        for (di, d) in dirs.iter().enumerate() {
            let mut t = vec![0xFFu8; d.size as usize];
            let order: Vec<(&String, &BNode)> = d.map.iter().collect();
            let mut sorted = order.clone();
            sorted.sort_by_key(|(k, _)| key(k));
            let offs = &layouts[di];
            let tree = build_tree(sorted.len());
            for (idx, (name, node)) in sorted.iter().enumerate() {
                let o = offs[idx];
                let (left, right) = tree[idx];
                let (sector, size, attr) = match node {
                    BNode::Dir(m) => {
                        let (s, z) = dir_info[&(m as *const _)];
                        (s, if m.is_empty() { 0 } else { z }, ATTR_DIR)
                    }
                    BNode::File(s) => (file_sector[&(*node as *const BNode)], s.len()? as u32, 0x20),
                };
                let mut e = ByteWriter::new();
                e.u16le(left.map(|l| (offs[l] / 4) as u16).unwrap_or(0))
                    .u16le(right.map(|r| (offs[r] / 4) as u16).unwrap_or(0))
                    .u32le(sector)
                    .u32le(size)
                    .u8(attr)
                    .u8(name.len() as u8)
                    .bytes(name.as_bytes());
                t[o..o + e.len()].copy_from_slice(&e.buf);
            }
            if sorted.is_empty() {
                t.fill(0xFF);
            }
            tables.push(t);
        }
        // Emit.
        out.write_all(&vec![0u8; 32 * SECTOR as usize])?;
        let mut vd = vec![0u8; SECTOR as usize];
        vd[..20].copy_from_slice(MAGIC);
        let root = &dirs[0];
        vd[20..24].copy_from_slice(&root.sector.to_le_bytes());
        vd[24..28].copy_from_slice(&(if self.root.is_empty() { 0 } else { root.size }).to_le_bytes());
        vd[0x7EC..0x800].copy_from_slice(MAGIC);
        out.write_all(&vd)?;
        for t in &tables {
            out.write_all(t)?;
            let pad = (SECTOR - t.len() as u64 % SECTOR) % SECTOR;
            out.write_all(&vec![0xFFu8; pad as usize])?;
        }
        let total: u64 = files.iter().map(|(s, _)| s.len().unwrap_or(0)).sum();
        let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(total));
        for (s, _) in &files {
            crate::copy_all(s.as_ref(), out, &mut p)?;
            let len = s.len()?;
            crate::copy::write_zeros(out, (SECTOR - len % SECTOR) % SECTOR)?;
        }
        Ok(self.count)
    }

    /// Entry offsets (sorted order) and total table size for one directory.
    fn layout(map: &BTreeMap<String, BNode>) -> (Vec<usize>, u32) {
        let mut names: Vec<&String> = map.keys().collect();
        names.sort_by_key(|k| key(k));
        let mut offs = Vec::new();
        let mut pos = 0usize;
        for n in names {
            let len = (14 + n.len() + 3) & !3;
            if pos % SECTOR as usize + len > SECTOR as usize {
                pos = (pos / SECTOR as usize + 1) * SECTOR as usize;
            }
            offs.push(pos);
            pos += len;
        }
        (offs, pos as u32)
    }
}

/// BST over sorted indices whose root is index 0 (readers start at table offset 0, which
/// holds the smallest name): the root has only a right subtree, which is balanced.
fn build_tree(n: usize) -> Vec<(Option<usize>, Option<usize>)> {
    let mut v = vec![(None, None); n];
    fn bal(lo: usize, hi: usize, v: &mut Vec<(Option<usize>, Option<usize>)>) -> Option<usize> {
        if lo >= hi {
            return None;
        }
        let mid = (lo + hi) / 2;
        let l = bal(lo, mid, v);
        let r = bal(mid + 1, hi, v);
        v[mid] = (l, r);
        Some(mid)
    }
    if n > 0 {
        let r = bal(1, n, &mut v);
        v[0] = (None, r);
    }
    v
}

/// Names in the root directory (bounded read), for probing without a shared source.
pub fn root_names(s: &dyn DataSource, base: u64) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(d) = read_vec(s, base + 32 * SECTOR, SECTOR, SECTOR) else { return out };
    if &d[..20] != MAGIC {
        return out;
    }
    let (Ok(sector), Ok(size)) = (u32le(&d, 20), u32le(&d, 24)) else { return out };
    let size = (size as u64).min(64 * 1024);
    let Ok(table) = read_vec(s, base + sector as u64 * SECTOR, size, 64 * 1024) else { return out };
    let mut stack = vec![0usize];
    let mut seen = HashSet::new();
    while let Some(off) = stack.pop() {
        if off + 14 > table.len() || !seen.insert(off) || table[off..off + 4] == [0xFF; 4] {
            continue;
        }
        let (Ok(l), Ok(r)) = (u16le(&table, off), u16le(&table, off + 2)) else { continue };
        let nl = table[off + 13] as usize;
        if let Some(n) = table.get(off + 14..off + 14 + nl) {
            out.push(String::from_utf8_lossy(n).into_owned());
        }
        for c in [l as usize * 4, r as usize * 4] {
            if c != 0 {
                stack.push(c);
            }
        }
        if out.len() > 4096 {
            break;
        }
    }
    out
}
