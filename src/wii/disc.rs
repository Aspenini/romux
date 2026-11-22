//! Nintendo optical disc structures shared by GameCube and Wii: disc header, FST,
//! apploader and DOL sizing. These are *not* ISO9660.

use crate::binary::u32be;
use crate::{ContentNode, Error, NodeTable, ResourceLimits, Result, SharedSource, SubSource, read_vec};
use serde::Serialize;

pub const WII_MAGIC: u32 = 0x5D1C_9EA3;
pub const GC_MAGIC: u32 = 0xC233_9F3D;

#[derive(Debug, Clone, Serialize)]
pub struct DiscHeader {
    pub game_id: String,
    pub maker: String,
    pub disc_number: u8,
    pub version: u8,
    pub title: String,
    pub is_wii: bool,
    pub is_gc: bool,
    pub dol_offset: u64,
    pub fst_offset: u64,
    pub fst_size: u64,
}

impl DiscHeader {
    /// Parse the 0x440-byte boot block. `shift` is 2 for Wii partitions (offsets >> 2).
    pub fn parse(b: &[u8], shift: u32) -> Result<Self> {
        if b.len() < 0x440 {
            return Err(Error::bounds("disc header truncated"));
        }
        let is_wii = u32be(b, 0x18)? == WII_MAGIC;
        let is_gc = u32be(b, 0x1C)? == GC_MAGIC;
        Ok(DiscHeader {
            game_id: crate::binary::ascii_z(&b[0..4]),
            maker: crate::binary::ascii_z(&b[4..6]),
            disc_number: b[6],
            version: b[7],
            title: crate::binary::utf8_z(&b[0x20..0x400]).trim().to_string(),
            is_wii,
            is_gc,
            dol_offset: (u32be(b, 0x420)? as u64) << shift,
            fst_offset: (u32be(b, 0x424)? as u64) << shift,
            fst_size: (u32be(b, 0x428)? as u64) << shift,
        })
    }
    pub fn product_code(&self) -> String {
        format!("{}{}", self.game_id, self.maker)
    }
    pub fn region(&self) -> &'static str {
        match self.game_id.as_bytes().get(3) {
            Some(b'E') => "NTSC-U",
            Some(b'J') => "NTSC-J",
            Some(b'K') => "NTSC-K",
            Some(b'P') | Some(b'D') | Some(b'F') | Some(b'S') | Some(b'I') | Some(b'X') | Some(b'Y') => "PAL",
            _ => "unknown",
        }
    }
}

/// FST file entry.
#[derive(Debug, Clone)]
pub struct FstEntry {
    pub path: String,
    pub is_dir: bool,
    pub offset: u64,
    pub size: u64,
}

/// Parse an FST. File offsets are shifted by `shift` (Wii: 2).
pub fn parse_fst(fst: &[u8], shift: u32, limits: &ResourceLimits) -> Result<Vec<FstEntry>> {
    if fst.len() < 12 || fst[0] != 1 {
        return Err(Error::malformed("FST root entry is not a directory"));
    }
    let count = u32be(fst, 8)? as usize;
    if count == 0 || count as u64 > limits.max_entries || count * 12 > fst.len() {
        return Err(Error::malformed("FST entry count out of range"));
    }
    let strings = &fst[count * 12..];
    let mut out = Vec::with_capacity(count);
    // Stack of (end index, path prefix).
    let mut stack: Vec<(usize, String)> = vec![(count, String::new())];
    let mut i = 1usize;
    while i < count {
        while stack.last().is_some_and(|(end, _)| i >= *end) {
            stack.pop();
        }
        let prefix = stack.last().map(|s| s.1.clone()).unwrap_or_default();
        let e = &fst[i * 12..i * 12 + 12];
        let is_dir = e[0] == 1;
        let name_off = ((e[1] as usize) << 16) | ((e[2] as usize) << 8) | e[3] as usize;
        let name = crate::binary::table_string(strings, name_off, limits.max_name_len).unwrap_or_else(|_| format!("entry{i}"));
        let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let a = u32be(e, 4)? as u64;
        let b = u32be(e, 8)? as u64;
        if is_dir {
            let end = b as usize;
            if end <= i || end > count {
                return Err(Error::malformed(format!("FST directory {path} has an invalid end index")));
            }
            if stack.len() as u32 > limits.max_depth {
                return Err(Error::limit("FST nesting too deep"));
            }
            out.push(FstEntry { path: path.clone(), is_dir: true, offset: 0, size: 0 });
            stack.push((end, path));
        } else {
            out.push(FstEntry { path, is_dir: false, offset: a << shift, size: b });
        }
        i += 1;
    }
    Ok(out)
}

/// Size of a DOL executable from its header.
pub fn dol_size(h: &[u8]) -> Result<u64> {
    let mut end = 0x100u64;
    for i in 0..18 {
        let off = u32be(h, i * 4)? as u64;
        let size = u32be(h, 0x90 + i * 4)? as u64;
        if off != 0 {
            end = end.max(off + size);
        }
    }
    Ok(end)
}

/// Add `sys/` and `files/` nodes of a GameCube-layout filesystem (a whole GC disc, or a
/// decrypted Wii partition) to a node table.
pub fn add_filesystem(
    t: &mut NodeTable,
    data: SharedSource,
    shift: u32,
    prefix: &str,
    limits: &ResourceLimits,
) -> Result<(DiscHeader, usize)> {
    let len = data.len()?;
    let boot = read_vec(data.as_ref(), 0, 0x440, 0x440)?;
    let h = DiscHeader::parse(&boot, shift)?;
    let p = |s: &str| if prefix.is_empty() { s.to_string() } else { format!("{prefix}/{s}") };
    t.push(ContentNode::file(0, p("sys/boot.bin"), 0x440), Some(SubSource::shared(data.clone(), 0, 0x440)?));
    t.push(ContentNode::file(0, p("sys/bi2.bin"), 0x2000), Some(SubSource::shared(data.clone(), 0x440, 0x2000)?));
    let ah = read_vec(data.as_ref(), 0x2440, 0x20, 0x20)?;
    let app_size = 0x20 + u32be(&ah, 0x14)? as u64 + u32be(&ah, 0x18)? as u64;
    if 0x2440 + app_size <= len {
        t.push(ContentNode::file(0, p("sys/apploader.img"), app_size), Some(SubSource::shared(data.clone(), 0x2440, app_size)?));
    }
    if h.dol_offset > 0 && h.dol_offset + 0x100 <= len {
        let dh = read_vec(data.as_ref(), h.dol_offset, 0x100, 0x100)?;
        let ds = dol_size(&dh)?;
        if h.dol_offset + ds <= len {
            t.push(ContentNode::file(0, p("sys/main.dol"), ds), Some(SubSource::shared(data.clone(), h.dol_offset, ds)?));
        }
    }
    if h.fst_offset + h.fst_size > len || h.fst_size > limits.max_metadata {
        return Err(Error::bounds("FST lies beyond the disc data"));
    }
    t.push(ContentNode::file(0, p("sys/fst.bin"), h.fst_size), Some(SubSource::shared(data.clone(), h.fst_offset, h.fst_size)?));
    let fst = read_vec(data.as_ref(), h.fst_offset, h.fst_size, limits.max_metadata)?;
    let entries = parse_fst(&fst, shift, limits)?;
    let mut files = 0;
    for e in &entries {
        let path = p(&format!("files/{}", e.path));
        if e.is_dir {
            t.push(ContentNode::dir(0, path), None);
        } else if e.offset + e.size <= len {
            t.push(
                ContentNode::file(0, path, e.size).meta("disc_offset", e.offset),
                Some(SubSource::shared(data.clone(), e.offset, e.size)?),
            );
            files += 1;
        } else {
            t.push(ContentNode::file(0, path, e.size).readable(false).meta("problem", "extends beyond disc data"), None);
        }
    }
    Ok((h, files))
}

#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    //! Build a small synthetic GameCube disc image.
    //!
    //! Synthetic-fixture builder (feature `testkit`; not part of the stable API).
    use super::*;
    use crate::binary::ByteWriter;

    pub fn gc_disc(game_id: &str, title: &str, files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut d = vec![0u8; 0x2440 + 0x20];
        d[..4].copy_from_slice(game_id.as_bytes());
        d[4..6].copy_from_slice(b"01");
        d[0x1C..0x20].copy_from_slice(&GC_MAGIC.to_be_bytes());
        d[0x20..0x20 + title.len()].copy_from_slice(title.as_bytes());
        // apploader header: size 0x10, trailer 0
        d[0x2440 + 0x14..0x2440 + 0x18].copy_from_slice(&0x10u32.to_be_bytes());
        d.resize(0x2440 + 0x30, 0);
        // DOL at 0x3000 with one text section
        d.resize(0x3000, 0);
        let mut dol = vec![0u8; 0x100];
        dol[0..4].copy_from_slice(&0x100u32.to_be_bytes());
        dol[0x90..0x94].copy_from_slice(&0x20u32.to_be_bytes());
        dol.extend(vec![0xAAu8; 0x20]);
        let dol_off = d.len();
        d.extend(dol);
        // FST
        let mut strings = Vec::new();
        let mut ents = ByteWriter::new();
        ents.u8(1).bytes(&[0, 0, 0]).u32be(0).u32be(files.len() as u32 + 1);
        let mut data_off = 0x8000u64;
        let mut placements = Vec::new();
        for (name, data) in files {
            let no = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            ents.u8(0).bytes(&no.to_be_bytes()[1..]).u32be(data_off as u32).u32be(data.len() as u32);
            placements.push(data_off);
            data_off = crate::binary::align_up(data_off + data.len() as u64, 4).unwrap_or(data_off);
        }
        let mut fst = ents.into_inner();
        fst.extend(strings);
        let fst_off = crate::binary::align_up(d.len() as u64, 4).unwrap_or(0) as usize;
        d.resize(fst_off, 0);
        d.extend(&fst);
        d[0x420..0x424].copy_from_slice(&(dol_off as u32).to_be_bytes());
        d[0x424..0x428].copy_from_slice(&(fst_off as u32).to_be_bytes());
        d[0x428..0x42C].copy_from_slice(&(fst.len() as u32).to_be_bytes());
        d[0x42C..0x430].copy_from_slice(&(fst.len() as u32).to_be_bytes());
        for ((_, data), off) in files.iter().zip(placements) {
            if d.len() < off as usize + data.len() {
                d.resize(off as usize + data.len(), 0);
            }
            d[off as usize..off as usize + data.len()].copy_from_slice(data);
        }
        let l = crate::binary::align_up(d.len() as u64, 0x8000).unwrap_or(0) as usize;
        d.resize(l.max(0x40000), 0);
        d
    }
}
