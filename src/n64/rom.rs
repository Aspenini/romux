//! N64 ROM byte orders, header, CIC identification and header checksums.

use crate::binary::u32be;
use crate::{ByteProgress, DataSource, Error, JobContext, Phase, Result, SharedSource};
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ByteOrder {
    /// `.z64`: native order.
    BigEndian,
    /// `.v64`: each 16-bit pair swapped.
    ByteSwapped,
    /// `.n64`: each 32-bit word reversed.
    LittleEndian,
}

impl ByteOrder {
    pub fn detect(first: &[u8; 4]) -> Option<Self> {
        match first {
            [0x80, 0x37, 0x12, 0x40] => Some(ByteOrder::BigEndian),
            [0x37, 0x80, 0x40, 0x12] => Some(ByteOrder::ByteSwapped),
            [0x40, 0x12, 0x37, 0x80] => Some(ByteOrder::LittleEndian),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            ByteOrder::BigEndian => "big-endian (z64)",
            ByteOrder::ByteSwapped => "byte-swapped (v64)",
            ByteOrder::LittleEndian => "little-endian (n64)",
        }
    }
    /// Convert a 4-byte group between this order and native (the mapping is its own inverse).
    pub fn swap(&self, w: &mut [u8]) {
        match self {
            ByteOrder::BigEndian => {}
            ByteOrder::ByteSwapped => {
                for p in w.chunks_exact_mut(2) {
                    p.swap(0, 1);
                }
            }
            ByteOrder::LittleEndian => {
                for p in w.chunks_exact_mut(4) {
                    p.reverse();
                }
            }
        }
    }
}

/// Native (big-endian) view of a ROM in any byte order.
pub struct NativeView {
    inner: SharedSource,
    order: ByteOrder,
    len: u64,
}

impl NativeView {
    pub fn new(inner: SharedSource) -> Result<Self> {
        let mut m = [0u8; 4];
        inner.read_exact_at(0, &mut m)?;
        let order = ByteOrder::detect(&m).ok_or_else(|| Error::malformed("not an N64 ROM (unknown PI header word)"))?;
        let len = inner.len()?;
        Ok(NativeView { inner, order, len })
    }
}

impl DataSource for NativeView {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        if self.order == ByteOrder::BigEndian {
            return self.inner.read_exact_at(offset, out);
        }
        // Read whole aligned 4-byte groups, swap, then copy the requested window.
        let start = offset & !3;
        let end = (offset + out.len() as u64).div_ceil(4).saturating_mul(4).min(self.len);
        let mut buf = vec![0u8; (end - start) as usize];
        self.inner.read_exact_at(start, &mut buf)?;
        let whole = buf.len() / 4 * 4;
        self.order.swap(&mut buf[..whole]);
        let s = (offset - start) as usize;
        out.copy_from_slice(&buf[s..s + out.len()]);
        Ok(())
    }
}

/// Write a native-order ROM in the requested byte order.
pub fn write_order(native: &dyn DataSource, to: ByteOrder, out: &mut dyn Write, job: &JobContext) -> Result<()> {
    let len = native.len()?;
    let mut p = ByteProgress::new(job, Phase::Writing, Some(len));
    let mut buf = vec![0u8; 1 << 20];
    let mut pos = 0u64;
    while pos < len {
        let n = ((len - pos) as usize).min(buf.len());
        native.read_exact_at(pos, &mut buf[..n])?;
        to.swap(&mut buf[..n / 4 * 4]);
        out.write_all(&buf[..n])?;
        pos += n as u64;
        p.advance(n as u64)?;
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RomHeader {
    pub clock_rate: u32,
    pub entry_point: u32,
    pub release: u32,
    pub crc1: u32,
    pub crc2: u32,
    pub title: String,
    /// Four-character game code: media type, two-letter ID, region (e.g. `NSME`).
    pub game_code: String,
    pub version: u8,
}

impl RomHeader {
    pub fn parse(h: &[u8]) -> Result<Self> {
        if h.len() < 0x40 {
            return Err(Error::bounds("N64 header truncated"));
        }
        let title: String = h[0x20..0x34].iter().map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { ' ' }).collect();
        let code: String = h[0x3B..0x3F].iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '?' }).collect();
        Ok(RomHeader {
            clock_rate: u32be(h, 0x04)?,
            entry_point: u32be(h, 0x08)?,
            release: u32be(h, 0x0C)?,
            crc1: u32be(h, 0x10)?,
            crc2: u32be(h, 0x14)?,
            title: title.trim().to_string(),
            game_code: code,
            version: h[0x3F],
        })
    }

    /// Catalogue-style product code, e.g. `NUS-NSME-USA`.
    pub fn product_code(&self) -> String {
        format!("NUS-{}-{}", self.game_code, self.region_short())
    }

    pub fn media(&self) -> &'static str {
        match self.game_code.as_bytes().first() {
            Some(b'N') => "cartridge",
            Some(b'C') => "cartridge (64DD expandable)",
            Some(b'D') => "64DD disk",
            Some(b'E') => "64DD expansion",
            Some(b'Z') => "Aleck64 arcade",
            _ => "unknown",
        }
    }

    pub fn region(&self) -> &'static str {
        match self.game_code.as_bytes().get(3) {
            Some(b'A') => "all regions",
            Some(b'B') => "Brazil",
            Some(b'C') => "China",
            Some(b'D') => "Germany",
            Some(b'E') => "North America",
            Some(b'F') => "France",
            Some(b'G') => "Gateway 64 (NTSC)",
            Some(b'H') => "Netherlands",
            Some(b'I') => "Italy",
            Some(b'J') => "Japan",
            Some(b'K') => "Korea",
            Some(b'L') => "Gateway 64 (PAL)",
            Some(b'N') => "Canada",
            Some(b'P') | Some(b'X') | Some(b'Y') | Some(b'Z') => "Europe",
            Some(b'S') => "Spain",
            Some(b'U') => "Australia",
            Some(b'W') => "Scandinavia",
            _ => "unknown",
        }
    }

    fn region_short(&self) -> &'static str {
        match self.game_code.as_bytes().get(3) {
            Some(b'E') | Some(b'N') => "USA",
            Some(b'J') => "JPN",
            Some(b'P') | Some(b'D') | Some(b'F') | Some(b'I') | Some(b'S') | Some(b'X') | Some(b'Y') | Some(b'U') => "EUR",
            _ => "ZZZ",
        }
    }
}

/// CIC boot chip families (identified by the IPL3 boot code they expect).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Cic {
    C6101,
    C6102,
    C6103,
    C6105,
    C6106,
    C7102,
}

impl Cic {
    /// Identify from the IPL3 bytes at 0x40..0x1000 (CRC-32 of the boot code).
    pub fn identify(ipl3: &[u8]) -> Option<Self> {
        Some(match crate::crypto::crc32(ipl3) {
            0x6170_A4A1 => Cic::C6101,
            0x90BB_6CB5 => Cic::C6102,
            0x0B05_0EE0 => Cic::C6103,
            0x98BC_2C86 => Cic::C6105,
            0xACC8_580A => Cic::C6106,
            0x009E_9EA3 => Cic::C7102,
            _ => return None,
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Cic::C6101 => "CIC-NUS-6101",
            Cic::C6102 => "CIC-NUS-6102 / 7101",
            Cic::C6103 => "CIC-NUS-6103 / 7103",
            Cic::C6105 => "CIC-NUS-6105 / 7105",
            Cic::C6106 => "CIC-NUS-6106 / 7106",
            Cic::C7102 => "CIC-NUS-7102",
        }
    }
    fn seed(&self) -> u32 {
        match self {
            Cic::C6101 | Cic::C6102 | Cic::C7102 => 0xF8CA_4DDC,
            Cic::C6103 => 0xA388_6759,
            Cic::C6105 => 0xDF26_F436,
            Cic::C6106 => 0x1FEA_617A,
        }
    }
}

/// Recompute CRC1/CRC2 over the 1 MiB at 0x1000 (native order source).
pub fn checksum(native: &dyn DataSource, cic: Cic) -> Result<(u32, u32)> {
    const START: u64 = 0x1000;
    const LEN: u64 = 0x10_0000;
    let mut data = vec![0u8; LEN as usize];
    native.read_exact_at(START, &mut data)?;
    let mut ipl = vec![0u8; 0x1000];
    native.read_exact_at(0, &mut ipl)?;
    let seed = cic.seed();
    let (mut t1, mut t2, mut t3, mut t4, mut t5, mut t6) = (seed, seed, seed, seed, seed, seed);
    for i in (0..LEN as usize).step_by(4) {
        let d = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let (sum, carry) = t6.overflowing_add(d);
        if carry {
            t4 = t4.wrapping_add(1);
        }
        t6 = sum;
        t3 ^= d;
        let r = d.rotate_left(d & 0x1F);
        t5 = t5.wrapping_add(r);
        if t2 > d {
            t2 ^= r;
        } else {
            t2 ^= t6 ^ d;
        }
        if cic == Cic::C6105 {
            let k = 0x0750 + (i & 0xFF);
            let b = u32::from_be_bytes([ipl[k], ipl[k + 1], ipl[k + 2], ipl[k + 3]]);
            t1 = t1.wrapping_add(b ^ d);
        } else {
            t1 = t1.wrapping_add(t5 ^ d);
        }
    }
    Ok(match cic {
        Cic::C6103 => ((t6 ^ t4).wrapping_add(t3), (t5 ^ t2).wrapping_add(t1)),
        Cic::C6106 => (t6.wrapping_mul(t4).wrapping_add(t3), t5.wrapping_mul(t2).wrapping_add(t1)),
        _ => (t6 ^ t4 ^ t3, t5 ^ t2 ^ t1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySource;
    use std::sync::Arc;

    #[test]
    fn byte_orders_roundtrip() {
        let mut z = vec![0u8; 0x2000];
        z[..4].copy_from_slice(&[0x80, 0x37, 0x12, 0x40]);
        for (i, b) in z.iter_mut().enumerate().skip(4) {
            *b = i as u8;
        }
        for order in [ByteOrder::ByteSwapped, ByteOrder::LittleEndian] {
            let mut other = Vec::new();
            write_order(&MemorySource::new(z.clone()), order, &mut other, &JobContext::default()).unwrap();
            assert_eq!(ByteOrder::detect(&other[..4].try_into().unwrap()), Some(order));
            let v = NativeView::new(Arc::new(MemorySource::new(other))).unwrap();
            let mut back = vec![0u8; z.len()];
            v.read_exact_at(0, &mut back).unwrap();
            assert_eq!(back, z);
            let mut part = [0u8; 7];
            v.read_exact_at(0x101, &mut part).unwrap();
            assert_eq!(&part, &z[0x101..0x108]);
        }
    }
}
