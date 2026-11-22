//! Switch RomFS (level-3 hashed directory/file tables, UTF-8 names): reader and builder.

use crate::binary::{ByteWriter, u32le, u64le};
use crate::{DataSource, Error, ResourceLimits, Result, SharedSource, SubSource, read_vec};
use std::collections::BTreeMap;
use std::io::Write;

const NONE: u32 = 0xFFFF_FFFF;
pub const HEADER_SIZE: u64 = 0x50;

#[derive(Debug, Clone)]
pub struct RomfsFile {
    pub path: String,
    /// Offset relative to the data region.
    pub offset: u64,
    pub size: u64,
}

pub struct RomFs {
    source: SharedSource,
    pub data_offset: u64,
    pub files: Vec<RomfsFile>,
    pub dirs: Vec<String>,
}

pub fn probe(source: &dyn DataSource) -> bool {
    let mut h = [0u8; 0x50];
    if source.read_exact_at(0, &mut h).is_err() {
        return false;
    }
    let len = source.len().unwrap_or(0);
    u64le(&h, 0).ok() == Some(HEADER_SIZE)
        && (0..5).all(|i| {
            let o = u64le(&h, 8 + i * 16).unwrap_or(u64::MAX);
            let s = if i < 4 { u64le(&h, 16 + i * 16).unwrap_or(u64::MAX) } else { 0 };
            o.checked_add(s).is_some_and(|e| e <= len) && o >= HEADER_SIZE
        })
}

fn name_at(meta: &[u8], off: usize, len: usize, limits: &ResourceLimits) -> Result<String> {
    if len > limits.max_name_len {
        return Err(Error::limit("RomFS name too long"));
    }
    let b = crate::binary::slice(meta, off, len)?;
    String::from_utf8(b.to_vec()).map_err(|_| Error::malformed("RomFS name is not UTF-8"))
}

impl RomFs {
    pub fn open(source: SharedSource, limits: &ResourceLimits) -> Result<Self> {
        let h = read_vec(source.as_ref(), 0, HEADER_SIZE, HEADER_SIZE)?;
        if u64le(&h, 0)? != HEADER_SIZE {
            return Err(Error::malformed("RomFS header size is not 0x50"));
        }
        let dir_meta_off = u64le(&h, 0x18)?;
        let dir_meta_size = u64le(&h, 0x20)?;
        let file_meta_off = u64le(&h, 0x38)?;
        let file_meta_size = u64le(&h, 0x40)?;
        let data_offset = u64le(&h, 0x48)?;
        let total = source.len()?;
        if data_offset > total {
            return Err(Error::bounds("RomFS data offset beyond source"));
        }
        let dmeta = read_vec(source.as_ref(), dir_meta_off, dir_meta_size, limits.max_metadata)?;
        let fmeta = read_vec(source.as_ref(), file_meta_off, file_meta_size, limits.max_metadata)?;
        let mut fs = RomFs { source, data_offset, files: Vec::new(), dirs: Vec::new() };
        let mut stack = vec![(0u32, String::new(), 0u32)];
        let mut visited_dirs = std::collections::HashSet::new();
        let mut visited_files = std::collections::HashSet::new();
        while let Some((d, prefix, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(Error::limit("RomFS nesting too deep"));
            }
            if !visited_dirs.insert(d) {
                return Err(Error::malformed("RomFS directory loop"));
            }
            let e = d as usize;
            let mut file = u32le(&dmeta, e + 12)?;
            let mut child = u32le(&dmeta, e + 8)?;
            while file != NONE {
                if !visited_files.insert(file) {
                    return Err(Error::malformed("RomFS file loop"));
                }
                let f = file as usize;
                let offset = u64le(&fmeta, f + 8)?;
                let size = u64le(&fmeta, f + 16)?;
                let nl = u32le(&fmeta, f + 28)? as usize;
                let name = name_at(&fmeta, f + 32, nl, limits)?;
                let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
                if crate::binary::add(crate::binary::add(data_offset, offset)?, size)? > total {
                    return Err(Error::bounds(format!("RomFS file {path} extends beyond the image")));
                }
                fs.files.push(RomfsFile { path, offset, size });
                if fs.files.len() as u64 > limits.max_entries {
                    return Err(Error::limit("too many RomFS files"));
                }
                file = u32le(&fmeta, f + 4)?;
            }
            while child != NONE {
                let c = child as usize;
                let nl = u32le(&dmeta, c + 20)? as usize;
                let name = name_at(&dmeta, c + 24, nl, limits)?;
                let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
                fs.dirs.push(path.clone());
                stack.push((child, path, depth + 1));
                child = u32le(&dmeta, c + 4)?;
                if fs.dirs.len() as u64 > limits.max_entries {
                    return Err(Error::limit("too many RomFS directories"));
                }
            }
        }
        fs.files.sort_by(|a, b| a.path.cmp(&b.path));
        fs.dirs.sort();
        Ok(fs)
    }

    pub fn open_file(&self, f: &RomfsFile) -> Result<SharedSource> {
        SubSource::shared(self.source.clone(), self.data_offset + f.offset, f.size)
    }
}

/// Path hash used by RomFS hash tables.
pub fn path_hash(parent: u32, name: &[u8]) -> u32 {
    let mut h = parent ^ 123_456_789;
    for &c in name {
        h = h.rotate_right(5);
        h ^= c as u32;
    }
    h
}

/// Bucket count for a hash table with `n` entries.
pub fn hash_table_count(n: usize) -> usize {
    if n < 3 {
        3
    } else if n < 19 {
        n | 1
    } else {
        let mut c = n;
        while [2, 3, 5, 7, 11, 13, 17].iter().any(|p| c.is_multiple_of(*p)) {
            c += 1;
        }
        c
    }
}

#[derive(Default)]
struct BDir {
    dirs: BTreeMap<String, BDir>,
    files: BTreeMap<String, SharedSource>,
}

/// Deterministic RomFS builder.
#[derive(Default)]
pub struct RomfsBuilder {
    root: BDir,
}

/// A laid-out RomFS ready to be written.
pub struct RomfsLayout {
    pub header: Vec<u8>,
    /// (absolute offset, source) of each file's data.
    pub files: Vec<(u64, SharedSource)>,
    pub tables_offset: u64,
    pub tables: Vec<u8>,
    pub total: u64,
}

impl RomfsBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_file(&mut self, path: &str, data: SharedSource) -> Result<()> {
        let comps = crate::path::sanitize_components(path, 768)?;
        let mut cur = &mut self.root;
        for c in &comps[..comps.len() - 1] {
            cur = cur.dirs.entry(c.clone()).or_default();
        }
        let last = comps[comps.len() - 1].clone();
        if cur.files.insert(last, data).is_some() {
            return Err(Error::conflict(format!("duplicate RomFS path {path}")));
        }
        Ok(())
    }

    pub fn layout(&self) -> Result<RomfsLayout> {
        // Flatten breadth-first so siblings are contiguous.
        struct D {
            parent: usize,
            name: String,
            children: Vec<usize>,
            files: Vec<usize>,
            off: u32,
        }
        struct F {
            parent: usize,
            name: String,
            src: SharedSource,
            off: u32,
            data_off: u64,
        }
        let mut dirs: Vec<D> = vec![D { parent: 0, name: String::new(), children: vec![], files: vec![], off: 0 }];
        let mut files: Vec<F> = Vec::new();
        let mut queue: std::collections::VecDeque<(usize, &BDir)> = std::collections::VecDeque::new();
        queue.push_back((0, &self.root));
        while let Some((di, bd)) = queue.pop_front() {
            for (n, src) in &bd.files {
                files.push(F { parent: di, name: n.clone(), src: src.clone(), off: 0, data_off: 0 });
                let fi = files.len() - 1;
                dirs[di].files.push(fi);
            }
            for (n, sub) in &bd.dirs {
                dirs.push(D { parent: di, name: n.clone(), children: vec![], files: vec![], off: 0 });
                let ci = dirs.len() - 1;
                dirs[di].children.push(ci);
                queue.push_back((ci, sub));
            }
        }
        let entry_len = |base: usize, name: &str| base + name.len().div_ceil(4) * 4;
        let mut off = 0u32;
        for d in dirs.iter_mut() {
            d.off = off;
            off += entry_len(0x18, &d.name) as u32;
        }
        let dir_meta_size = off;
        let mut off = 0u32;
        let mut data = 0u64;
        for f in files.iter_mut() {
            f.off = off;
            off += entry_len(0x20, &f.name) as u32;
            f.data_off = data;
            data = crate::binary::align_up(data + f.src.len()?, 0x10)?;
        }
        let file_meta_size = off;
        let dcount = hash_table_count(dirs.len());
        let fcount = hash_table_count(files.len());
        let mut dhash = vec![NONE; dcount];
        let mut fhash = vec![NONE; fcount];
        let mut dmeta = ByteWriter::with_capacity(dir_meta_size as usize);
        let mut dnext = vec![NONE; dirs.len()];
        for (i, d) in dirs.iter().enumerate() {
            let parent_off = dirs[d.parent].off;
            let hsh = path_hash(parent_off, d.name.as_bytes()) as usize % dcount;
            dnext[i] = dhash[hsh];
            dhash[hsh] = d.off;
        }
        let mut fnext = vec![NONE; files.len()];
        for (i, f) in files.iter().enumerate() {
            let parent_off = dirs[f.parent].off;
            let hsh = path_hash(parent_off, f.name.as_bytes()) as usize % fcount;
            fnext[i] = fhash[hsh];
            fhash[hsh] = f.off;
        }
        for (i, d) in dirs.iter().enumerate() {
            let sibling = if i == 0 {
                NONE
            } else {
                let p = &dirs[d.parent];
                let pos = p.children.iter().position(|c| *c == i).unwrap_or(0);
                p.children.get(pos + 1).map(|c| dirs[*c].off).unwrap_or(NONE)
            };
            dmeta
                .u32le(dirs[d.parent].off)
                .u32le(sibling)
                .u32le(d.children.first().map(|c| dirs[*c].off).unwrap_or(NONE))
                .u32le(d.files.first().map(|f| files[*f].off).unwrap_or(NONE))
                .u32le(dnext[i])
                .u32le(d.name.len() as u32)
                .bytes(d.name.as_bytes())
                .align(4);
        }
        let mut fmeta = ByteWriter::with_capacity(file_meta_size as usize);
        for (i, f) in files.iter().enumerate() {
            let p = &dirs[f.parent];
            let pos = p.files.iter().position(|x| *x == i).unwrap_or(0);
            let sibling = p.files.get(pos + 1).map(|x| files[*x].off).unwrap_or(NONE);
            fmeta
                .u32le(p.off)
                .u32le(sibling)
                .u64le(f.data_off)
                .u64le(f.src.len()?)
                .u32le(fnext[i])
                .u32le(f.name.len() as u32)
                .bytes(f.name.as_bytes())
                .align(4);
        }
        let data_offset = 0x200u64;
        let tables_offset = crate::binary::align_up(data_offset + data, 4)?;
        let mut tables = ByteWriter::new();
        let dh_off = tables_offset;
        for v in &dhash {
            tables.u32le(*v);
        }
        let dm_off = tables_offset + tables.len() as u64;
        tables.bytes(&dmeta.buf);
        let fh_off = tables_offset + tables.len() as u64;
        for v in &fhash {
            tables.u32le(*v);
        }
        let fm_off = tables_offset + tables.len() as u64;
        tables.bytes(&fmeta.buf);
        let mut h = ByteWriter::with_capacity(0x200);
        h.u64le(HEADER_SIZE)
            .u64le(dh_off)
            .u64le(dcount as u64 * 4)
            .u64le(dm_off)
            .u64le(dmeta.len() as u64)
            .u64le(fh_off)
            .u64le(fcount as u64 * 4)
            .u64le(fm_off)
            .u64le(fmeta.len() as u64)
            .u64le(data_offset);
        h.pad_to(data_offset as usize);
        let total = tables_offset + tables.len() as u64;
        Ok(RomfsLayout {
            header: h.into_inner(),
            files: files.iter().map(|f| (data_offset + f.data_off, f.src.clone())).collect(),
            tables_offset,
            tables: tables.into_inner(),
            total,
        })
    }
}

impl RomfsLayout {
    pub fn write(&self, out: &mut dyn Write, job: &crate::JobContext) -> Result<()> {
        out.write_all(&self.header)?;
        let mut pos = self.header.len() as u64;
        let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(self.total));
        for (off, src) in &self.files {
            crate::copy::write_zeros(out, off - pos)?;
            crate::copy_all(src.as_ref(), out, &mut p)?;
            pos = off + src.len()?;
        }
        crate::copy::write_zeros(out, self.tables_offset - pos)?;
        out.write_all(&self.tables)?;
        Ok(())
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut v = Vec::with_capacity(self.total as usize);
        self.write(&mut v, &crate::JobContext::default())?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySource;
    use std::sync::Arc;

    #[test]
    fn build_and_read() {
        let mut b = RomfsBuilder::new();
        let files = [
            ("a.txt", b"alpha".to_vec()),
            ("dir/b.bin", vec![1u8; 33]),
            ("dir/sub/c", vec![]),
            ("dir/d", b"dd".to_vec()),
            ("z/y/x", b"xyz".to_vec()),
        ];
        for (p, d) in &files {
            b.add_file(p, Arc::new(MemorySource::new(d.clone()))).unwrap();
        }
        let img = b.layout().unwrap().to_vec().unwrap();
        let src: SharedSource = Arc::new(MemorySource::new(img));
        assert!(probe(src.as_ref()));
        let fs = RomFs::open(src, &ResourceLimits::default()).unwrap();
        let mut expect: Vec<_> = files.iter().map(|(p, _)| p.to_string()).collect();
        expect.sort();
        assert_eq!(fs.files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(), expect);
        for f in &fs.files {
            let want = &files.iter().find(|(p, _)| *p == f.path).unwrap().1;
            let s = fs.open_file(f).unwrap();
            assert_eq!(&read_vec(s.as_ref(), 0, f.size, 1 << 20).unwrap(), want);
        }
    }
}
