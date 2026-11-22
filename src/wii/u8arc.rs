//! U8 archives (big-endian node table + string table + data).

use crate::binary::{ByteWriter, u32be};
use crate::{DataSource, Error, JobContext, ResourceLimits, Result, SharedSource, read_vec};
use std::collections::BTreeMap;
use std::io::Write;

pub const MAGIC: u32 = 0x55AA_382D;

#[derive(Debug, Clone)]
pub struct U8Entry {
    pub path: String,
    pub is_dir: bool,
    pub offset: u64,
    pub size: u64,
}

pub fn probe(s: &dyn DataSource) -> bool {
    let mut b = [0u8; 4];
    s.read_exact_at(0, &mut b).is_ok() && u32::from_be_bytes(b) == MAGIC
}

pub fn parse(s: &dyn DataSource, limits: &ResourceLimits) -> Result<Vec<U8Entry>> {
    let h = read_vec(s, 0, 0x20, 0x20)?;
    if u32be(&h, 0)? != MAGIC {
        return Err(Error::malformed("missing U8 magic"));
    }
    let root = u32be(&h, 4)? as u64;
    let size = u32be(&h, 8)? as u64;
    let len = s.len()?;
    let tbl = read_vec(s, root, size, limits.max_metadata)?;
    if tbl.len() < 12 || tbl[0] != 1 {
        return Err(Error::malformed("U8 root node is not a directory"));
    }
    let count = u32be(&tbl, 8)? as usize;
    if count * 12 > tbl.len() || count as u64 > limits.max_entries {
        return Err(Error::malformed("U8 node count out of range"));
    }
    let strings = &tbl[count * 12..];
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = vec![(count, String::new())];
    for i in 1..count {
        while stack.last().is_some_and(|(end, _)| i >= *end) {
            stack.pop();
        }
        let prefix = stack.last().map(|s| s.1.clone()).unwrap_or_default();
        let n = &tbl[i * 12..i * 12 + 12];
        let name_off = ((n[1] as usize) << 16) | ((n[2] as usize) << 8) | n[3] as usize;
        let name = crate::binary::table_string(strings, name_off, limits.max_name_len)?;
        let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let a = u32be(n, 4)? as u64;
        let b = u32be(n, 8)? as u64;
        if n[0] == 1 {
            if (b as usize) <= i || b as usize > count {
                return Err(Error::malformed("U8 directory end index invalid"));
            }
            out.push(U8Entry { path: path.clone(), is_dir: true, offset: 0, size: 0 });
            stack.push((b as usize, path));
        } else {
            if a + b > len {
                return Err(Error::bounds(format!("U8 file {path} extends beyond the archive")));
            }
            out.push(U8Entry { path, is_dir: false, offset: a, size: b });
        }
    }
    Ok(out)
}

#[derive(Default)]
struct Dir {
    dirs: BTreeMap<String, Dir>,
    files: BTreeMap<String, SharedSource>,
}

/// Deterministic U8 writer.
#[derive(Default)]
pub struct U8Builder {
    root: Dir,
}

impl U8Builder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_file(&mut self, path: &str, data: SharedSource) -> Result<()> {
        let comps = crate::path::sanitize_components(path, 255)?;
        let mut cur = &mut self.root;
        for c in &comps[..comps.len() - 1] {
            cur = cur.dirs.entry(c.clone()).or_default();
        }
        if cur.files.insert(comps[comps.len() - 1].clone(), data).is_some() {
            return Err(Error::conflict(format!("duplicate path {path}")));
        }
        Ok(())
    }

    pub fn write(&self, out: &mut dyn Write, job: &JobContext) -> Result<u64> {
        // Flatten depth-first: files before subdirectories within a directory.
        struct N {
            name: String,
            dir: bool,
            parent_or_offset: u32,
            size_or_next: u32,
            src: Option<SharedSource>,
        }
        let mut nodes = vec![N { name: String::new(), dir: true, parent_or_offset: 0, size_or_next: 0, src: None }];
        fn walk(d: &Dir, parent: usize, nodes: &mut Vec<N>) {
            for (n, s) in &d.files {
                nodes.push(N {
                    name: n.clone(),
                    dir: false,
                    parent_or_offset: 0,
                    size_or_next: s.len().unwrap_or(0) as u32,
                    src: Some(s.clone()),
                });
            }
            for (n, sub) in &d.dirs {
                let me = nodes.len();
                nodes.push(N { name: n.clone(), dir: true, parent_or_offset: parent as u32, size_or_next: 0, src: None });
                walk(sub, me, nodes);
                nodes[me].size_or_next = nodes.len() as u32;
            }
        }
        walk(&self.root, 0, &mut nodes);
        nodes[0].size_or_next = nodes.len() as u32;
        let mut strings = vec![0u8];
        let mut name_offs = vec![0u32];
        for n in nodes.iter().skip(1) {
            name_offs.push(strings.len() as u32);
            strings.extend_from_slice(n.name.as_bytes());
            strings.push(0);
        }
        let table_size = nodes.len() * 12 + strings.len();
        let data_start = crate::binary::align_up(0x20 + table_size as u64, 0x40)?;
        let mut cur = data_start;
        for n in nodes.iter_mut() {
            if !n.dir {
                n.parent_or_offset = cur as u32;
                cur = crate::binary::align_up(cur + n.size_or_next as u64, 0x20)?;
            }
        }
        let mut w = ByteWriter::new();
        w.u32be(MAGIC).u32be(0x20).u32be(table_size as u32).u32be(data_start as u32).zeros(16);
        for (i, n) in nodes.iter().enumerate() {
            w.u8(if n.dir { 1 } else { 0 }).bytes(&name_offs[i].to_be_bytes()[1..]).u32be(n.parent_or_offset).u32be(n.size_or_next);
        }
        w.bytes(&strings);
        w.pad_to(data_start as usize);
        out.write_all(&w.buf)?;
        let mut pos = data_start;
        let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(cur - data_start));
        for n in &nodes {
            if let Some(s) = &n.src {
                crate::copy::write_zeros(out, n.parent_or_offset as u64 - pos)?;
                crate::copy_all(s.as_ref(), out, &mut p)?;
                pos = n.parent_or_offset as u64 + n.size_or_next as u64;
            }
        }
        crate::copy::write_zeros(out, cur - pos)?;
        Ok(cur)
    }
}
