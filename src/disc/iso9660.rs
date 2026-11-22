//! ISO9660 (ECMA-119) filesystem reader and deterministic builder, with Joliet names.
//!
//! The reader operates on a *cooked* source of 2048-byte logical sectors. Raw 2352-byte
//! CD layouts are adapted by [`crate::disc::rawcd::CookedSource`].

use crate::binary::{ByteWriter, both_endian_u32, put_both_u16, put_both_u32, u16le, utf16be_z};
use crate::{ByteProgress, DataSource, Error, JobContext, Phase, ResourceLimits, Result, SharedSource, SubSource, copy_all, read_vec};
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::sync::Arc;

pub const SECTOR: u64 = 2048;

/// Volume information from the primary (or Joliet supplementary) descriptor.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct VolumeInfo {
    pub system_id: String,
    pub volume_id: String,
    pub volume_set_id: String,
    pub publisher: String,
    pub preparer: String,
    pub application: String,
    pub volume_blocks: u32,
    pub block_size: u16,
    pub creation_date: String,
    pub joliet: bool,
}

/// One filesystem entry.
#[derive(Debug, Clone)]
pub struct IsoEntry {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// (lba, byte length) extents; multi-extent files have several.
    pub extents: Vec<(u32, u64)>,
}

/// A parsed ISO9660 filesystem.
pub struct IsoFs {
    source: SharedSource,
    pub volume: VolumeInfo,
    entries: Vec<IsoEntry>,
    pub warnings: Vec<String>,
}

fn dstr(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches([' ', '\0']).to_string()
}

fn date17(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(&b[..16]).to_string();
    if s.chars().all(|c| c == '0' || c == '\0' || c == ' ') {
        return String::new();
    }
    if s.len() >= 14 { format!("{}-{}-{} {}:{}:{}", &s[0..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14]) } else { s }
}

/// Quick check for an ISO9660 primary volume descriptor at sector 16.
pub fn probe(source: &dyn DataSource) -> bool {
    let mut b = [0u8; 6];
    source.read_exact_at(16 * SECTOR, &mut b).is_ok() && &b[1..6] == b"CD001" && (b[0] == 1 || b[0] == 2)
}

struct DirRec {
    lba: u32,
    len: u32,
    flags: u8,
    name: Vec<u8>,
}

fn parse_record(rec: &[u8]) -> Result<DirRec> {
    if rec.len() < 34 {
        return Err(Error::malformed("directory record too short"));
    }
    let lba = both_endian_u32(rec, 2)?;
    let len = both_endian_u32(rec, 10)?;
    let flags = rec[25];
    let nl = rec[32] as usize;
    if 33 + nl > rec.len() {
        return Err(Error::malformed("directory record name exceeds record"));
    }
    Ok(DirRec { lba, len, flags, name: rec[33..33 + nl].to_vec() })
}

impl IsoFs {
    pub fn open(source: SharedSource, limits: &ResourceLimits) -> Result<Self> {
        let total = source.len()?;
        let mut pvd: Option<Vec<u8>> = None;
        let mut joliet: Option<Vec<u8>> = None;
        for i in 16..(16 + 64) {
            let off = i * SECTOR;
            if off + SECTOR > total {
                break;
            }
            let d = read_vec(source.as_ref(), off, SECTOR, SECTOR)?;
            if &d[1..6] != b"CD001" {
                return Err(Error::malformed(format!("bad volume descriptor signature at sector {i}")));
            }
            match d[0] {
                1 if pvd.is_none() => pvd = Some(d),
                2 => {
                    let esc = &d[88..91];
                    if esc == b"%/@" || esc == b"%/C" || esc == b"%/E" {
                        joliet = Some(d);
                    }
                }
                255 => break,
                _ => {}
            }
        }
        let pvd = pvd.ok_or_else(|| Error::malformed("no primary volume descriptor"))?;
        let block_size = u16le(&pvd, 128)?;
        if block_size != 2048 {
            return Err(Error::unsupported(format!("logical block size {block_size} is not supported")));
        }
        let mut volume = VolumeInfo {
            system_id: dstr(&pvd[8..40]),
            volume_id: dstr(&pvd[40..72]),
            volume_set_id: dstr(&pvd[190..318]),
            publisher: dstr(&pvd[318..446]),
            preparer: dstr(&pvd[446..574]),
            application: dstr(&pvd[574..702]),
            volume_blocks: both_endian_u32(&pvd, 80)?,
            block_size,
            creation_date: date17(&pvd[813..830]),
            joliet: joliet.is_some(),
        };
        let (desc, is_joliet) = match &joliet {
            Some(j) => (j.clone(), true),
            None => (pvd.clone(), false),
        };
        if is_joliet {
            let jid = utf16be_z(&desc[40..72]);
            if !jid.trim().is_empty() {
                volume.volume_id = jid.trim().to_string();
            }
        }
        let root = parse_record(&desc[156..190])?;
        let mut fs = IsoFs { source, volume, entries: Vec::new(), warnings: Vec::new() };
        if (volume_blocks_bytes(&fs.volume)) > total {
            fs.warnings
                .push(format!("volume declares {} blocks but image holds {} bytes (truncated image?)", fs.volume.volume_blocks, total));
        }
        fs.walk(root.lba, root.len, is_joliet, limits)?;
        Ok(fs)
    }

    fn walk(&mut self, root_lba: u32, root_len: u32, joliet: bool, limits: &ResourceLimits) -> Result<()> {
        let mut visited = HashSet::new();
        let mut stack: Vec<(String, u32, u32, u32)> = vec![(String::new(), root_lba, root_len, 0)];
        let total = self.source.len()?;
        while let Some((prefix, lba, len, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(Error::limit("directory nesting exceeds limit"));
            }
            if !visited.insert(lba) {
                self.warnings.push(format!("directory loop at LBA {lba} ignored"));
                continue;
            }
            let off = lba as u64 * SECTOR;
            if off + len as u64 > total {
                return Err(Error::bounds(format!("directory extent at LBA {lba} beyond image")).with_offset(off));
            }
            let data = read_vec(self.source.as_ref(), off, len as u64, limits.max_metadata)?;
            let mut pos = 0usize;
            let mut pending: BTreeMap<String, IsoEntry> = BTreeMap::new();
            let mut order: Vec<String> = Vec::new();
            while pos < data.len() {
                let rl = data[pos] as usize;
                if rl == 0 {
                    // Records never cross sectors: skip to next sector.
                    pos = (pos / 2048 + 1) * 2048;
                    continue;
                }
                if pos + rl > data.len() {
                    return Err(Error::malformed("directory record crosses extent end"));
                }
                let rec = parse_record(&data[pos..pos + rl])?;
                pos += rl;
                if rec.name == [0] || rec.name == [1] {
                    continue;
                }
                let mut name = if joliet { utf16be_z(&rec.name) } else { String::from_utf8_lossy(&rec.name).into_owned() };
                if let Some(i) = name.rfind(';') {
                    name.truncate(i);
                }
                if !joliet && name.ends_with('.') && !(rec.flags & 2 != 0) {
                    name.pop();
                }
                if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                    self.warnings.push(format!("skipped entry with unusable name in {prefix:?}"));
                    continue;
                }
                let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
                if rec.flags & 2 != 0 {
                    self.entries.push(IsoEntry { path: path.clone(), is_dir: true, size: 0, extents: vec![] });
                    stack.push((path, rec.lba, rec.len, depth + 1));
                } else {
                    let e = pending.entry(path.clone()).or_insert_with(|| {
                        order.push(path.clone());
                        IsoEntry { path: path.clone(), is_dir: false, size: 0, extents: vec![] }
                    });
                    e.extents.push((rec.lba, rec.len as u64));
                    e.size += rec.len as u64;
                }
                if self.entries.len() + pending.len() > limits.max_entries as usize {
                    return Err(Error::limit("filesystem entry count exceeds limit"));
                }
            }
            for p in order {
                if let Some(e) = pending.remove(&p) {
                    for (l, n) in &e.extents {
                        let end = *l as u64 * SECTOR + n;
                        if end > total {
                            self.warnings.push(format!("file {} extends beyond image end", e.path));
                        }
                    }
                    self.entries.push(e);
                }
            }
        }
        self.entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(())
    }

    pub fn entries(&self) -> &[IsoEntry] {
        &self.entries
    }

    /// Case-insensitive lookup of a path.
    #[cfg_attr(not(feature = "psp"), allow(dead_code))]
    pub fn find(&self, path: &str) -> Option<&IsoEntry> {
        let p = path.trim_start_matches('/');
        self.entries.iter().find(|e| e.path.eq_ignore_ascii_case(p))
    }

    /// Data view of a file entry.
    pub fn open_entry(&self, e: &IsoEntry) -> Result<SharedSource> {
        if e.is_dir {
            return Err(Error::invalid_arg("cannot open a directory"));
        }
        let total = self.source.len()?;
        let mut parts: Vec<SharedSource> = Vec::new();
        for (lba, len) in &e.extents {
            let off = *lba as u64 * SECTOR;
            if off + len > total {
                return Err(Error::bounds(format!("file {} extends beyond image", e.path)));
            }
            parts.push(SubSource::shared(self.source.clone(), off, *len)?);
        }
        if parts.len() == 1 {
            Ok(parts.pop().unwrap_or_else(|| Arc::new(crate::ZeroSource(0))))
        } else {
            Ok(Arc::new(crate::ConcatSource::new(parts)?))
        }
    }

    #[cfg_attr(not(feature = "psp"), allow(dead_code))]
    pub fn read_file(&self, path: &str, limit: u64) -> Result<Option<Vec<u8>>> {
        match self.find(path) {
            Some(e) if !e.is_dir => {
                let s = self.open_entry(e)?;
                Ok(Some(read_vec(s.as_ref(), 0, s.len()?, limit)?))
            }
            _ => Ok(None),
        }
    }

    /// Structural checks: extents inside the image and no overlapping file extents.
    pub fn check_extents(&self) -> Result<Vec<String>> {
        let total = self.source.len()?;
        let mut problems = Vec::new();
        let mut spans: Vec<(u64, u64, usize)> = Vec::new();
        for (i, e) in self.entries.iter().enumerate() {
            for (lba, len) in &e.extents {
                let off = *lba as u64 * SECTOR;
                if off.saturating_add(*len) > total {
                    problems.push(format!("{}: extent beyond image end", e.path));
                }
                if *len > 0 {
                    spans.push((off, *len, i));
                }
            }
        }
        if let Some((a, b)) = crate::binary::find_overlap(&mut spans) {
            // Hard-linked/shared extents exist on real discs; report rather than fail.
            problems.push(format!("extents of {} and {} overlap (shared data or corruption)", self.entries[a].path, self.entries[b].path));
        }
        Ok(problems)
    }
}

fn volume_blocks_bytes(v: &VolumeInfo) -> u64 {
    v.volume_blocks as u64 * v.block_size as u64
}

// ------------------------------------------------------------------------------------------
// Builder
// ------------------------------------------------------------------------------------------

enum BNode {
    Dir(BTreeMap<String, BNode>),
    File(SharedSource),
}

/// Deterministic ISO9660 image builder (relaxed names, no Joliet/Rock Ridge).
///
/// Names are written as given (upper/lower case preserved) with `;1` version suffixes,
/// as produced by common "relaxed" mastering tools. Dates are fixed for reproducibility.
pub struct IsoBuilder {
    volume_id: String,
    root: BTreeMap<String, BNode>,
    /// Minimum LBA for the first file (some consoles expect fixed layouts).
    pub first_file_lba: u32,
}

struct DirLayout {
    path: String,
    parent_index: usize,
    name: String,
    lba: u32,
    size: u32,
    children: Vec<(String, bool, usize)>, // name, is_dir, index into dirs/files
}

impl IsoBuilder {
    pub fn new(volume_id: &str) -> Self {
        IsoBuilder { volume_id: volume_id.to_string(), root: BTreeMap::new(), first_file_lba: 0 }
    }

    /// Add a file at a `/`-separated path. Parent directories are created implicitly.
    pub fn add_file(&mut self, path: &str, data: SharedSource) -> Result<()> {
        let comps = crate::path::sanitize_components(path, 255)?;
        let mut cur = &mut self.root;
        for c in &comps[..comps.len() - 1] {
            let e = cur.entry(c.clone()).or_insert_with(|| BNode::Dir(BTreeMap::new()));
            cur = match e {
                BNode::Dir(d) => d,
                BNode::File(_) => return Err(Error::conflict(format!("{c} is both a file and a directory"))),
            };
        }
        let last = comps[comps.len() - 1].clone();
        if cur.contains_key(&last) {
            return Err(Error::conflict(format!("duplicate path {path}")));
        }
        cur.insert(last, BNode::File(data));
        Ok(())
    }

    #[cfg(any(test, feature = "testkit"))]
    pub fn add_dir(&mut self, path: &str) -> Result<()> {
        let comps = crate::path::sanitize_components(path, 255)?;
        let mut cur = &mut self.root;
        for c in &comps {
            let e = cur.entry(c.clone()).or_insert_with(|| BNode::Dir(BTreeMap::new()));
            cur = match e {
                BNode::Dir(d) => d,
                BNode::File(_) => return Err(Error::conflict(format!("{c} is both a file and a directory"))),
            };
        }
        Ok(())
    }

    fn record(lba: u32, size: u32, is_dir: bool, name: &[u8]) -> Vec<u8> {
        let nl = name.len();
        let mut len = 33 + nl;
        if len % 2 == 1 {
            len += 1;
        }
        let mut w = ByteWriter::with_capacity(len);
        w.u8(len as u8).u8(0);
        put_both_u32(&mut w, lba);
        put_both_u32(&mut w, size);
        w.bytes(&[100, 1, 1, 0, 0, 0, 0]); // 2000-01-01 00:00:00 GMT
        w.u8(if is_dir { 2 } else { 0 }).u8(0).u8(0);
        put_both_u16(&mut w, 1);
        w.u8(nl as u8).bytes(name);
        w.pad_to(len);
        w.into_inner()
    }

    fn dir_size(children: &[(Vec<u8>, bool)]) -> u32 {
        let mut size = 0u32;
        let mut in_sector = 0u32;
        let mut recs: Vec<u32> = vec![34, 34];
        for (n, _) in children {
            let mut l = 33 + n.len() as u32;
            if l % 2 == 1 {
                l += 1;
            }
            recs.push(l);
        }
        for l in recs {
            if in_sector + l > 2048 {
                size += 2048;
                in_sector = 0;
            }
            in_sector += l;
        }
        size + 2048 // final (partial) sector, rounded
    }

    /// Write the image. Returns total bytes written.
    #[allow(clippy::needless_range_loop)]
    pub fn write(self, out: &mut dyn Write, job: &JobContext) -> Result<u64> {
        // Flatten directories breadth-first (path-table order).
        let mut dirs: Vec<DirLayout> = Vec::new();
        let mut files: Vec<(String, SharedSource, u32, u64)> = Vec::new();
        let mut queue: std::collections::VecDeque<(&BTreeMap<String, BNode>, String, usize, String)> = std::collections::VecDeque::new();
        queue.push_back((&self.root, String::new(), 0, String::new()));
        let mut dir_maps: Vec<&BTreeMap<String, BNode>> = Vec::new();
        while let Some((map, path, parent, name)) = queue.pop_front() {
            let idx = dirs.len();
            dirs.push(DirLayout { path: path.clone(), parent_index: parent, name, lba: 0, size: 0, children: vec![] });
            dir_maps.push(map);
            for (n, node) in map {
                if let BNode::Dir(d) = node {
                    let p = if path.is_empty() { n.clone() } else { format!("{path}/{n}") };
                    queue.push_back((d, p, idx, n.clone()));
                }
            }
        }
        // Children lists.
        let mut dir_index_by_path: BTreeMap<String, usize> = BTreeMap::new();
        for (i, d) in dirs.iter().enumerate() {
            dir_index_by_path.insert(d.path.clone(), i);
        }
        for i in 0..dirs.len() {
            let map = dir_maps[i];
            let mut children = Vec::new();
            for (n, node) in map {
                let p = if dirs[i].path.is_empty() { n.clone() } else { format!("{}/{n}", dirs[i].path) };
                match node {
                    BNode::Dir(_) => children.push((n.clone(), true, dir_index_by_path[&p])),
                    BNode::File(s) => {
                        files.push((p, s.clone(), 0, s.len()?));
                        children.push((n.clone(), false, files.len() - 1));
                    }
                }
            }
            // ISO9660 requires records sorted by name bytes (with version suffix for files).
            children.sort_by_key(|a| rec_name(&a.0, a.1));
            dirs[i].children = children;
        }
        // Path tables.
        let mut pt_size = 0u32;
        for d in &dirs {
            let nl = if d.path.is_empty() { 1 } else { d.name.len() as u32 };
            pt_size += 8 + nl + (nl % 2);
        }
        let pt_sectors = (pt_size as u64).div_ceil(SECTOR).max(1) as u32;
        let l_pt = 18u32;
        let m_pt = l_pt + pt_sectors;
        let mut next = m_pt + pt_sectors;
        for i in 0..dirs.len() {
            let ch: Vec<(Vec<u8>, bool)> = dirs[i].children.iter().map(|(n, d, _)| (rec_name(n, *d), *d)).collect();
            let size = Self::dir_size(&ch);
            dirs[i].lba = next;
            dirs[i].size = size;
            next += size / 2048;
        }
        next = next.max(self.first_file_lba);
        for f in files.iter_mut() {
            f.2 = next;
            let sectors = f.3.div_ceil(SECTOR) as u32;
            if f.3 > u32::MAX as u64 {
                return Err(Error::unsupported(format!("{} exceeds ISO9660 single-extent size", f.0)));
            }
            next = next.checked_add(sectors.max(if f.3 == 0 { 0 } else { 1 })).ok_or_else(|| Error::limit("image too large"))?;
        }
        let total_blocks = next;

        out.write_all(&vec![0u8; 16 * 2048])?;
        // PVD
        let root = &dirs[0];
        let mut p = ByteWriter::with_capacity(2048);
        p.u8(1).bytes(b"CD001").u8(1).u8(0);
        p.fixed(&[b' '; 32], 32);
        let mut vid = self.volume_id.as_bytes().to_vec();
        vid.resize(32, b' ');
        p.bytes(&vid[..32]);
        p.zeros(8);
        put_both_u32(&mut p, total_blocks);
        p.zeros(32);
        put_both_u16(&mut p, 1);
        put_both_u16(&mut p, 1);
        put_both_u16(&mut p, 2048);
        put_both_u32(&mut p, pt_size);
        p.u32le(l_pt).u32le(0).u32be(m_pt).u32be(0);
        p.bytes(&Self::record(root.lba, root.size, true, &[0])[..34]);
        for _ in 0..4 {
            p.fixed(&[b' '; 128], 128);
        }
        for _ in 0..3 {
            p.fixed(&[b' '; 37], 37);
        }
        let date = b"2000010100000000\0";
        p.bytes(date).bytes(date).bytes(b"0000000000000000\0").bytes(date);
        p.u8(1).u8(0);
        p.pad_to(2048);
        // Application identifier for provenance.
        let app = b"ROMUX";
        p.buf[574..574 + app.len()].copy_from_slice(app);
        out.write_all(&p.buf)?;
        // Terminator
        let mut t = vec![0u8; 2048];
        t[0] = 255;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 1;
        out.write_all(&t)?;
        // Path tables
        for big in [false, true] {
            let mut w = ByteWriter::new();
            for d in &dirs {
                let name: Vec<u8> = if d.path.is_empty() { vec![0] } else { d.name.as_bytes().to_vec() };
                w.u8(name.len() as u8).u8(0);
                if big {
                    w.u32be(d.lba).u16be(d.parent_index as u16 + 1);
                } else {
                    w.u32le(d.lba).u16le(d.parent_index as u16 + 1);
                }
                w.bytes(&name);
                if name.len() % 2 == 1 {
                    w.u8(0);
                }
            }
            w.pad_to(pt_sectors as usize * 2048);
            out.write_all(&w.buf)?;
        }
        // Directories
        for d in &dirs {
            let parent = &dirs[d.parent_index];
            let mut recs: Vec<Vec<u8>> = vec![Self::record(d.lba, d.size, true, &[0]), Self::record(parent.lba, parent.size, true, &[1])];
            for (n, is_dir, idx) in &d.children {
                if *is_dir {
                    let c = &dirs[*idx];
                    recs.push(Self::record(c.lba, c.size, true, &rec_name(n, true)));
                } else {
                    let f = &files[*idx];
                    recs.push(Self::record(f.2, f.3 as u32, false, &rec_name(n, false)));
                }
            }
            let mut w = ByteWriter::with_capacity(d.size as usize);
            for r in recs {
                let in_sector = w.len() % 2048;
                if in_sector + r.len() > 2048 {
                    w.pad_to((w.len() / 2048 + 1) * 2048);
                }
                w.bytes(&r);
            }
            w.pad_to(d.size as usize);
            out.write_all(&w.buf)?;
        }
        let mut cur_lba = dirs.last().map(|d| d.lba + d.size / 2048).unwrap_or(0);
        let total_file_bytes: u64 = files.iter().map(|f| f.3).sum();
        let mut prog = ByteProgress::new(job, Phase::Writing, Some(total_file_bytes));
        for f in &files {
            if f.3 == 0 {
                continue;
            }
            while cur_lba < f.2 {
                out.write_all(&[0u8; 2048])?;
                cur_lba += 1;
            }
            let mut counted = CountingWriter { inner: &mut *out, n: 0 };
            copy_all(f.1.as_ref(), &mut counted, &mut prog)?;
            let pad = (SECTOR - f.3 % SECTOR) % SECTOR;
            counted.write_all(&vec![0u8; pad as usize])?;
            let n = counted.n;
            cur_lba += (n / SECTOR) as u32;
        }
        Ok(total_blocks as u64 * SECTOR)
    }
}

fn rec_name(n: &str, is_dir: bool) -> Vec<u8> {
    if is_dir { n.as_bytes().to_vec() } else { format!("{n};1").into_bytes() }
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    n: u64,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySource;

    pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = IsoBuilder::new("TESTVOL");
        for (p, d) in files {
            b.add_file(p, Arc::new(MemorySource::new(d.to_vec()))).unwrap();
        }
        let mut out = Vec::new();
        b.write(&mut out, &JobContext::default()).unwrap();
        out
    }

    #[test]
    fn roundtrip() {
        let big = vec![7u8; 5000];
        let img = build(&[("A.TXT", b"hello"), ("DIR/SUB/B.BIN", &big), ("DIR/C", b"")]);
        assert_eq!(img.len() % 2048, 0);
        let src: SharedSource = Arc::new(MemorySource::new(img));
        assert!(probe(src.as_ref()));
        let fs = IsoFs::open(src, &ResourceLimits::default()).unwrap();
        assert_eq!(fs.volume.volume_id, "TESTVOL");
        let paths: Vec<_> = fs.entries().iter().map(|e| e.path.clone()).collect();
        assert_eq!(paths, vec!["A.TXT", "DIR", "DIR/C", "DIR/SUB", "DIR/SUB/B.BIN"]);
        assert_eq!(fs.read_file("dir/sub/b.bin", 1 << 20).unwrap().unwrap(), big);
        assert_eq!(fs.read_file("A.TXT", 100).unwrap().unwrap(), b"hello");
        assert!(fs.check_extents().unwrap().is_empty());
    }

    #[test]
    fn many_entries_cross_sectors() {
        let names: Vec<String> = (0..200).map(|i| format!("FILE_WITH_A_LONG_NAME_{i:04}.DAT")).collect();
        let mut b = IsoBuilder::new("X");
        for n in &names {
            b.add_file(n, Arc::new(MemorySource::new(n.as_bytes().to_vec()))).unwrap();
        }
        let mut out = Vec::new();
        b.write(&mut out, &JobContext::default()).unwrap();
        let fs = IsoFs::open(Arc::new(MemorySource::new(out)), &ResourceLimits::default()).unwrap();
        assert_eq!(fs.entries().len(), 200);
        let e = fs.find("FILE_WITH_A_LONG_NAME_0150.DAT").unwrap();
        assert_eq!(fs.read_file(&e.path.clone(), 100).unwrap().unwrap(), b"FILE_WITH_A_LONG_NAME_0150.DAT");
    }
}
