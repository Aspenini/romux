//! WUX: WUD with identical sectors stored once.
//!
//! Header (little-endian, 0x20 bytes): `WUX0`, 0x1099D02E, sector size, padding,
//! uncompressed size (u64), flags. Then one u32 per logical sector giving the index of
//! its stored sector; stored sectors start at the next sector-aligned offset.

use crate::{ByteProgress, DataSource, Error, JobContext, Phase, Result, SharedSource, read_vec};
use std::collections::HashMap;
use std::io::Write;

pub const MAGIC0: &[u8; 4] = b"WUX0";
pub const MAGIC1: u32 = 0x1099_D02E;

pub fn probe(s: &dyn DataSource) -> bool {
    let mut h = [0u8; 8];
    s.read_exact_at(0, &mut h).is_ok() && &h[..4] == MAGIC0 && u32::from_le_bytes([h[4], h[5], h[6], h[7]]) == MAGIC1
}

pub struct WuxSource {
    src: SharedSource,
    pub sector_size: u64,
    pub size: u64,
    index: Vec<u32>,
    data_offset: u64,
}

impl WuxSource {
    pub fn open(src: SharedSource) -> Result<Self> {
        let h = read_vec(src.as_ref(), 0, 0x20, 0x20)?;
        if !probe(src.as_ref()) {
            return Err(Error::malformed("missing WUX magic"));
        }
        let sector_size = crate::binary::u32le(&h, 8)? as u64;
        let size = crate::binary::u64le(&h, 0x10)?;
        if !(0x100..=0x10_0000).contains(&sector_size) || !sector_size.is_power_of_two() {
            return Err(Error::malformed("implausible WUX sector size"));
        }
        let count = size.div_ceil(sector_size);
        if count > 1 << 26 {
            return Err(Error::limit("WUX index too large"));
        }
        let raw = read_vec(src.as_ref(), 0x20, count * 4, 1 << 28)?;
        let index: Vec<u32> = raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        let data_offset = crate::binary::align_up(0x20 + count * 4, sector_size)?;
        let stored = (src.len()?.saturating_sub(data_offset)) / sector_size;
        if index.iter().any(|i| *i as u64 >= stored) {
            return Err(Error::bounds("WUX index references a sector beyond the file"));
        }
        Ok(WuxSource { src, sector_size, size, index, data_offset })
    }
}

impl DataSource for WuxSource {
    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.size)?;
        while !out.is_empty() {
            let s = offset / self.sector_size;
            let within = offset % self.sector_size;
            let n = ((self.sector_size - within) as usize).min(out.len());
            let phys = self.data_offset + self.index[s as usize] as u64 * self.sector_size + within;
            self.src.read_exact_at(phys, &mut out[..n])?;
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

/// Compress a WUD. Returns the number of unique sectors. Duplicate detection uses SHA-256
/// and then a byte comparison, so collisions cannot corrupt output.
pub fn compress(src: &dyn DataSource, out: &mut dyn Write, sector_size: u32, job: &JobContext) -> Result<u64> {
    let size = src.len()?;
    let ss = sector_size as u64;
    if !sector_size.is_power_of_two() || ss < 0x100 {
        return Err(Error::invalid_arg("sector size must be a power of two >= 256"));
    }
    let count = size.div_ceil(ss);
    // Pass 1: build the index.
    let mut seen: HashMap<[u8; 32], Vec<(u32, u64)>> = HashMap::new();
    let mut index = Vec::with_capacity(count as usize);
    let mut order: Vec<u64> = Vec::new();
    let mut buf = vec![0u8; ss as usize];
    let mut cmp = vec![0u8; ss as usize];
    let mut p = ByteProgress::new(job, Phase::Transforming, Some(size));
    for s in 0..count {
        let n = (size - s * ss).min(ss) as usize;
        buf[n..].fill(0);
        src.read_exact_at(s * ss, &mut buf[..n])?;
        let h = crate::crypto::sha256(&buf);
        let cands = seen.entry(h).or_default();
        let mut found = None;
        for (idx, logical) in cands.iter() {
            let ln = (size - logical * ss).min(ss) as usize;
            cmp[ln..].fill(0);
            src.read_exact_at(logical * ss, &mut cmp[..ln])?;
            if cmp == buf {
                found = Some(*idx);
                break;
            }
        }
        let idx = match found {
            Some(i) => i,
            None => {
                let i = order.len() as u32;
                order.push(s);
                cands.push((i, s));
                i
            }
        };
        index.push(idx);
        p.advance(n as u64)?;
    }
    let mut h = crate::binary::ByteWriter::new();
    h.bytes(MAGIC0).u32le(MAGIC1).u32le(sector_size).u32le(0).u64le(size).u32le(0).u32le(0);
    out.write_all(&h.buf)?;
    for i in &index {
        out.write_all(&i.to_le_bytes())?;
    }
    let header_end = 0x20 + count * 4;
    crate::copy::write_zeros(out, crate::binary::align_up(header_end, ss)? - header_end)?;
    let mut p = ByteProgress::new(job, Phase::Writing, Some(order.len() as u64 * ss));
    for s in &order {
        let n = (size - s * ss).min(ss) as usize;
        buf[n..].fill(0);
        src.read_exact_at(s * ss, &mut buf[..n])?;
        out.write_all(&buf)?;
        p.advance(ss)?;
    }
    Ok(order.len() as u64)
}
