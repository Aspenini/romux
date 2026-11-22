//! Xbox 360 STFS/SVOD content packages (`CON `, `LIVE`, `PIRS`), including Games on
//! Demand (GoD) containers.
//!
//! Header metadata is read for every package. For SVOD packages (GoD, installed games) the
//! data lives in `<header>.data/Data0000`, `Data0001`, ...; each data part starts with a
//! master hash block, followed by sub-parts of one hash block plus 0xCC data blocks.
//! Romux reads the data blocks as one logical stream, which holds an XDVDFS filesystem.
//! Hash blocks are not verified, and plain STFS filesystems (DLC, saves) are inspected only.

use crate::binary::{u32be, u64be, utf16be_z};
use crate::{DataSource, Error, FileSource, Result, SharedSource, read_vec};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const BLOCK: u64 = 0x1000;
pub const BLOCKS_PER_SUBPART: u64 = 0xCC;
pub const SUBPARTS_PER_PART: u64 = 0xCB;
pub const DATA_BLOCKS_PER_PART: u64 = BLOCKS_PER_SUBPART * SUBPARTS_PER_PART;

#[derive(Debug, Clone, serde::Serialize)]
pub struct StfsHeader {
    pub magic: String,
    pub content_type: u32,
    pub content_size: u64,
    pub media_id: u32,
    pub version: u32,
    pub base_version: u32,
    pub title_id: u32,
    pub disc_number: u8,
    pub disc_count: u8,
    pub descriptor_type: u32,
    pub data_file_count: u32,
    pub data_file_size: u64,
    pub display_name: String,
    pub title_name: String,
    pub publisher: String,
}

pub fn probe(s: &dyn DataSource) -> bool {
    let mut m = [0u8; 4];
    s.len().unwrap_or(0) >= 0x1800 && s.read_exact_at(0, &mut m).is_ok() && matches!(&m, b"CON " | b"LIVE" | b"PIRS")
}

impl StfsHeader {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        if !probe(s) {
            return Err(Error::malformed("missing CON/LIVE/PIRS magic"));
        }
        let h = read_vec(s, 0, 0x1712, 0x1712)?;
        Ok(StfsHeader {
            magic: String::from_utf8_lossy(&h[..4]).trim().to_string(),
            content_type: u32be(&h, 0x344)?,
            content_size: u64be(&h, 0x34C)?,
            media_id: u32be(&h, 0x354)?,
            version: u32be(&h, 0x358)?,
            base_version: u32be(&h, 0x35C)?,
            title_id: u32be(&h, 0x360)?,
            disc_number: h[0x366],
            disc_count: h[0x367],
            descriptor_type: u32be(&h, 0x3A9)?,
            data_file_count: u32be(&h, 0x39D)?,
            data_file_size: u64be(&h, 0x3A1)?,
            display_name: utf16be_z(&h[0x411..0x491]),
            title_name: utf16be_z(&h[0x1691..0x1711]),
            publisher: utf16be_z(&h[0x1611..0x1691]),
        })
    }

    pub fn content_type_name(&self) -> &'static str {
        match self.content_type {
            0x0000_0001 => "saved game",
            0x0000_0002 => "marketplace content (DLC)",
            0x0000_1000 => "Xbox Original game",
            0x0000_2000 => "game demo",
            0x0000_4000 => "installed game",
            0x0000_7000 => "Games on Demand",
            0x000B_0000 => "title update",
            0x000D_0000 => "Xbox LIVE Arcade",
            0x0009_0000 => "video",
            0x0001_0000 => "profile",
            0x0002_0000 => "gamer picture",
            0x0003_0000 => "theme",
            _ => "other",
        }
    }

    pub fn is_svod(&self) -> bool {
        self.descriptor_type == 1
    }
}

/// Logical view over the data blocks of SVOD `DataNNNN` parts.
pub struct SvodSource {
    parts: Vec<(SharedSource, u64)>,
    len: u64,
}

/// Data blocks stored in one part file of `file_len` bytes.
fn data_blocks_in(file_len: u64) -> u64 {
    let blocks = file_len / BLOCK;
    if blocks <= 1 {
        return 0;
    }
    let rest = blocks - 1;
    let subparts = rest.div_ceil(BLOCKS_PER_SUBPART + 1);
    (rest - subparts).min(DATA_BLOCKS_PER_PART)
}

impl SvodSource {
    /// Open the `<header>.data` directory next to an SVOD header file.
    pub fn open_for_header(header_path: &Path, count: u32) -> Result<(Self, Vec<PathBuf>)> {
        let mut dir = header_path.as_os_str().to_owned();
        dir.push(".data");
        let dir = PathBuf::from(dir);
        if !dir.is_dir() {
            return Err(Error::invalid_arg(format!("data folder {} not found next to the package header", dir.display())));
        }
        if count == 0 || count > 10_000 {
            return Err(Error::malformed("implausible SVOD data file count"));
        }
        let mut parts = Vec::new();
        let mut paths = Vec::new();
        for i in 0..count {
            let p = dir.join(format!("Data{i:04}"));
            let f: SharedSource = Arc::new(FileSource::open(&p).map_err(|e| e.with_suggestion("all DataNNNN parts must be present"))?);
            parts.push(f);
            paths.push(p);
        }
        Ok((Self::from_parts(parts)?, paths))
    }

    pub fn from_parts(parts: Vec<SharedSource>) -> Result<Self> {
        let mut v = Vec::new();
        let mut len = 0u64;
        for p in parts {
            let n = data_blocks_in(p.len()?);
            v.push((p, n));
            len += n * BLOCK;
        }
        Ok(SvodSource { parts: v, len })
    }
}

impl DataSource for SvodSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        while !out.is_empty() {
            let block = offset / BLOCK;
            let part = (block / DATA_BLOCKS_PER_PART) as usize;
            let within = block % DATA_BLOCKS_PER_PART;
            let sub = within / BLOCKS_PER_SUBPART;
            let b = within % BLOCKS_PER_SUBPART;
            let phys = (2 + sub * (BLOCKS_PER_SUBPART + 1) + b) * BLOCK + offset % BLOCK;
            let n = ((BLOCK - offset % BLOCK) as usize).min(out.len());
            let (src, _) = self.parts.get(part).ok_or_else(|| Error::bounds("SVOD offset beyond the data parts"))?;
            src.read_exact_at(phys, &mut out[..n])?;
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

/// Lay a logical stream out as SVOD data parts (inverse of [`SvodSource`]; used by tests).
/// Synthetic-fixture builder (feature `testkit`; not part of the stable API).
#[cfg(any(test, feature = "testkit"))]
pub fn layout_parts(data: &[u8]) -> Vec<Vec<u8>> {
    let blocks = (data.len() as u64).div_ceil(BLOCK);
    let mut parts = Vec::new();
    let mut b = 0u64;
    while b < blocks {
        let n = (blocks - b).min(DATA_BLOCKS_PER_PART);
        let subparts = n.div_ceil(BLOCKS_PER_SUBPART);
        let mut part = vec![0u8; ((1 + subparts + n) * BLOCK) as usize];
        for k in 0..n {
            let sub = k / BLOCKS_PER_SUBPART;
            let phys = ((2 + sub * (BLOCKS_PER_SUBPART + 1) + k % BLOCKS_PER_SUBPART) * BLOCK) as usize;
            let src = ((b + k) * BLOCK) as usize;
            let end = (src + BLOCK as usize).min(data.len());
            part[phys..phys + (end - src)].copy_from_slice(&data[src..end]);
        }
        parts.push(part);
        b += n;
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySource;

    #[test]
    fn svod_layout_roundtrip() {
        let data: Vec<u8> = (0..(BLOCK * 500) as usize).map(|i| (i / 4096) as u8 ^ (i as u8)).collect();
        let parts: Vec<SharedSource> = layout_parts(&data).into_iter().map(|p| Arc::new(MemorySource::new(p)) as SharedSource).collect();
        let s = SvodSource::from_parts(parts).unwrap();
        assert_eq!(s.len().unwrap(), data.len() as u64);
        let mut out = vec![0u8; data.len()];
        s.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out, data);
    }
}
