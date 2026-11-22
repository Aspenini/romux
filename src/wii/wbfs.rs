//! WBFS container (one or more Wii discs stored as sparse 2^n-byte blocks).
//!
//! Blocks a writer considered unused are omitted; restoring them yields zeros, so a
//! WBFS image is *not* guaranteed to reconstruct the original disc's filler data.

use crate::binary::{u16be, u32be};
use crate::{DataSource, Error, JobContext, Result, SharedSource, read_vec};
use std::io::Write;

pub const MAGIC: &[u8; 4] = b"WBFS";
pub const WII_SECTORS_DL: u64 = 143_432 * 2;
pub const WII_SECTOR: u64 = 0x8000;
pub const SINGLE_LAYER: u64 = 0x1_1824_0000;

#[derive(Debug, Clone, serde::Serialize)]
pub struct WbfsHeader {
    pub hd_sectors: u32,
    pub hd_sector_shift: u8,
    pub wbfs_sector_shift: u8,
    pub discs: Vec<usize>,
}

impl WbfsHeader {
    pub fn hd_sector(&self) -> u64 {
        1 << self.hd_sector_shift
    }
    pub fn wbfs_sector(&self) -> u64 {
        1 << self.wbfs_sector_shift
    }
    pub fn sectors_per_disc(&self) -> u64 {
        WII_SECTORS_DL >> (self.wbfs_sector_shift - 15)
    }
    pub fn disc_info_size(&self) -> u64 {
        let raw = 0x100 + self.sectors_per_disc() * 2;
        raw.div_ceil(self.hd_sector()) * self.hd_sector()
    }

    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h = read_vec(s, 0, 0x200, 0x200)?;
        if &h[..4] != MAGIC {
            return Err(Error::malformed("missing WBFS magic"));
        }
        let hd_sectors = u32be(&h, 4)?;
        let hs = h[8];
        let ws = h[9];
        if !(9..=12).contains(&hs) || !(15..=30).contains(&ws) {
            return Err(Error::malformed("implausible WBFS sector sizes"));
        }
        let slots = ((1usize << hs) - 0xC).min(0x200 - 0xC);
        let discs = (0..slots).filter(|i| h[0xC + i] != 0).collect();
        Ok(WbfsHeader { hd_sectors, hd_sector_shift: hs, wbfs_sector_shift: ws, discs })
    }
}

/// Reconstructed view of one disc.
pub struct WbfsDisc {
    src: SharedSource,
    pub header: WbfsHeader,
    table: Vec<u16>,
    len: u64,
}

impl WbfsDisc {
    pub fn open(src: SharedSource, slot: usize) -> Result<Self> {
        let header = WbfsHeader::parse(src.as_ref())?;
        if !header.discs.contains(&slot) {
            return Err(Error::invalid_arg(format!("WBFS slot {slot} is empty")));
        }
        let off = header.hd_sector() + slot as u64 * header.disc_info_size();
        let info = read_vec(src.as_ref(), off, header.disc_info_size(), 1 << 22)?;
        let n = header.sectors_per_disc() as usize;
        let mut table = Vec::with_capacity(n);
        for i in 0..n {
            table.push(u16be(&info, 0x100 + i * 2)?);
        }
        let ws = header.wbfs_sector();
        let flen = src.len()?;
        for (i, b) in table.iter().enumerate() {
            if *b != 0 && (*b as u64 + 1) * ws > flen + ws {
                return Err(Error::bounds(format!("WBFS block {i} points beyond the file")));
            }
        }
        // The final block may overhang the layer boundary, so compare block counts.
        let used_blocks = table.iter().rposition(|b| *b != 0).map(|i| i as u64 + 1).unwrap_or(0);
        let len = if used_blocks > SINGLE_LAYER.div_ceil(ws) { WII_SECTORS_DL * WII_SECTOR } else { SINGLE_LAYER };
        Ok(WbfsDisc { src, header, table, len })
    }
}

impl DataSource for WbfsDisc {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        let ws = self.header.wbfs_sector();
        let flen = self.src.len()?;
        while !out.is_empty() {
            let blk = (offset / ws) as usize;
            let within = offset % ws;
            let n = ((ws - within) as usize).min(out.len());
            match self.table.get(blk).copied().unwrap_or(0) {
                0 => out[..n].fill(0),
                b => {
                    let phys = b as u64 * ws + within;
                    let avail = flen.saturating_sub(phys).min(n as u64) as usize;
                    self.src.read_exact_at(phys, &mut out[..avail])?;
                    out[avail..n].fill(0);
                }
            }
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

/// Write a single-disc WBFS file. Blocks that are entirely zero are omitted (so the
/// restored image is byte-identical to `src` padded/truncated to a Wii layer size).
#[allow(clippy::needless_range_loop)]
pub fn write(src: &dyn DataSource, out: &mut dyn Write, job: &JobContext) -> Result<(u64, u64)> {
    let hs = 9u8;
    let ws_shift = 21u8;
    let ws = 1u64 << ws_shift;
    let len = src.len()?;
    if len > WII_SECTORS_DL * WII_SECTOR {
        return Err(Error::invalid_arg("image larger than a dual-layer Wii disc"));
    }
    let hdr = WbfsHeader { hd_sectors: 0, hd_sector_shift: hs, wbfs_sector_shift: ws_shift, discs: vec![0] };
    let n = hdr.sectors_per_disc() as usize;
    let blocks = len.div_ceil(ws) as usize;
    let mut table = vec![0u16; n];
    let mut used = Vec::new();
    let mut buf = vec![0u8; ws as usize];
    let mut p = crate::ByteProgress::new(job, crate::Phase::Reading, Some(len));
    for b in 0..blocks {
        let k = (len - b as u64 * ws).min(ws) as usize;
        src.read_exact_at(b as u64 * ws, &mut buf[..k])?;
        if buf[..k].iter().any(|x| *x != 0) {
            used.push(b);
            table[b] = used.len() as u16;
        }
        p.advance(k as u64)?;
    }
    let total_wbfs = used.len() as u64 + 1;
    let mut head = vec![0u8; ws as usize];
    head[..4].copy_from_slice(MAGIC);
    head[4..8].copy_from_slice(&((total_wbfs * ws) >> hs).min(u32::MAX as u64).to_be_bytes()[4..]);
    head[8] = hs;
    head[9] = ws_shift;
    head[0xC] = 1;
    let info = (1u64 << hs) as usize;
    let mut dh = vec![0u8; 0x100];
    src.read_exact_at(0, &mut dh)?;
    head[info..info + 0x100].copy_from_slice(&dh);
    for (i, b) in table.iter().enumerate() {
        head[info + 0x100 + i * 2..info + 0x102 + i * 2].copy_from_slice(&b.to_be_bytes());
    }
    // Free-block bitmap at the end of block 0 (1 = free).
    let bitmap_len = (total_wbfs as usize).div_ceil(8);
    let bm_off = ws as usize - bitmap_len.max(1);
    for i in 0..total_wbfs as usize {
        let used_block = i == 0 || i <= used.len();
        if !used_block {
            head[bm_off + i / 8] |= 1 << (7 - i % 8);
        }
    }
    out.write_all(&head)?;
    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(used.len() as u64 * ws));
    for b in &used {
        let k = (len - *b as u64 * ws).min(ws) as usize;
        buf.fill(0);
        src.read_exact_at(*b as u64 * ws, &mut buf[..k])?;
        out.write_all(&buf)?;
        p.advance(ws)?;
    }
    Ok((blocks as u64, used.len() as u64))
}
