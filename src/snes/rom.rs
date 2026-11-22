//! SNES cartridge images: copier headers, internal header detection, and the header
//! checksum.
//!
//! The internal header sits in the last 0x40 bytes of the first bank, which is 0x7FC0 for
//! LoROM, 0xFFC0 for HiROM and 0x40FFC0 for ExHiROM. Nothing marks it, so each candidate is
//! scored on evidence and the best one wins: checksum and complement summing to 0xFFFF, a
//! map-mode byte that fits the location, a plausible reset vector, a printable title and
//! sane size fields.

use crate::{DataSource, Error, Result, read_vec};
use serde::Serialize;

/// Size of the optional copier (SMC/SWC/FIG) header.
pub const COPIER_HEADER: u64 = 512;

/// ROM data offset: 512 when a copier header is present (`len % 1024 == 512`).
pub fn copier_offset(len: u64) -> u64 {
    if len % 1024 == COPIER_HEADER { COPIER_HEADER } else { 0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
// LoROM, HiROM and ExHiROM are the established names for SNES memory maps.
#[allow(clippy::enum_variant_names)]
pub enum Mapping {
    LoRom,
    HiRom,
    ExHiRom,
}

impl Mapping {
    /// Offset of the internal header in the (headerless) ROM.
    pub fn header_offset(self) -> u64 {
        match self {
            Mapping::LoRom => 0x7FC0,
            Mapping::HiRom => 0xFFC0,
            Mapping::ExHiRom => 0x40_FFC0,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Mapping::LoRom => "LoROM",
            Mapping::HiRom => "HiROM",
            Mapping::ExHiRom => "ExHiROM",
        }
    }
    /// Whether a map-mode byte (speed bit masked off) is consistent with this location.
    fn accepts(self, mode: u8) -> bool {
        match self {
            // 0x20 LoROM, 0x22 S-DD1/ExLoROM, 0x23 SA-1.
            Mapping::LoRom => matches!(mode, 0x20 | 0x22 | 0x23),
            // 0x21 HiROM, 0x2A SPC7110.
            Mapping::HiRom => matches!(mode, 0x21 | 0x2A),
            Mapping::ExHiRom => mode == 0x25,
        }
    }
}

/// Parsed internal header.
#[derive(Debug, Clone, Serialize)]
pub struct SnesHeader {
    pub mapping: Mapping,
    pub title: String,
    pub map_mode: u8,
    pub chipset: u8,
    pub rom_size_code: u8,
    pub sram_size_code: u8,
    pub country: u8,
    pub licensee: u8,
    pub version: u8,
    pub complement: u16,
    pub checksum: u16,
    pub reset_vector: u16,
    /// From the extended header (licensee 0x33): maker code and 4-letter game code.
    pub maker_code: Option<String>,
    pub game_code: Option<String>,
    pub chipset_subtype: Option<u8>,
    pub expansion_ram_code: Option<u8>,
    /// Detection score (higher is more certain).
    pub score: i32,
}

/// Decode a header title: ASCII plus JIS X 0201 half-width katakana.
fn decode_title(b: &[u8]) -> String {
    b.iter()
        .map(|&c| match c {
            0x20..=0x7E => c as char,
            0xA1..=0xDF => char::from_u32(0xFF61 + (c as u32 - 0xA1)).unwrap_or('?'),
            0x00 => ' ',
            _ => '?',
        })
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

impl SnesHeader {
    /// Parse and score the header at `mapping` in the headerless ROM `rom`.
    fn candidate(rom: &dyn DataSource, mapping: Mapping) -> Result<Option<Self>> {
        let at = mapping.header_offset();
        let len = rom.len()?;
        if at + 0x40 > len {
            return Ok(None);
        }
        // Extended header (0x10 bytes) + header (0x30) + vectors (0x10).
        let b = read_vec(rom, at - 0x10, 0x50, 0x50)?;
        let h = &b[0x10..];
        let mode = h[0x15];
        let complement = u16le(h, 0x1C);
        let checksum = u16le(h, 0x1E);
        let reset = u16le(h, 0x3C);
        let mut score = 0;
        if complement ^ checksum == 0xFFFF {
            score += 4;
            if checksum != 0 && checksum != 0xFFFF {
                score += 1;
            }
        }
        if mapping.accepts(mode & !0x10) {
            score += 3;
        }
        if reset >= 0x8000 {
            score += 2;
        }
        if h[..21].iter().all(|c| matches!(c, 0x20..=0x7E | 0xA1..=0xDF | 0)) {
            score += 1;
        }
        if (0x07..=0x0D).contains(&h[0x17]) {
            score += 1;
        }
        if h[0x18] <= 0x08 {
            score += 1;
        }
        if h[0x19] <= 0x14 {
            score += 1;
        }
        let ext = h[0x1A] == 0x33;
        let ascii = |s: &[u8]| -> Option<String> {
            s.iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b' ')
                .then(|| String::from_utf8_lossy(s).trim().to_string())
                .filter(|s| !s.is_empty())
        };
        Ok(Some(SnesHeader {
            mapping,
            title: decode_title(&h[..21]),
            map_mode: mode,
            chipset: h[0x16],
            rom_size_code: h[0x17],
            sram_size_code: h[0x18],
            country: h[0x19],
            licensee: h[0x1A],
            version: h[0x1B],
            complement,
            checksum,
            reset_vector: reset,
            maker_code: if ext { ascii(&b[0..2]) } else { None },
            game_code: if ext { ascii(&b[2..6]) } else { None },
            chipset_subtype: ext.then_some(b[0x0F]),
            expansion_ram_code: ext.then_some(b[0x0D]),
            score,
        }))
    }

    /// Find the most plausible internal header in a headerless ROM.
    pub fn detect(rom: &dyn DataSource) -> Result<Self> {
        let mut best: Option<SnesHeader> = None;
        for m in [Mapping::LoRom, Mapping::HiRom, Mapping::ExHiRom] {
            if let Some(c) = Self::candidate(rom, m)? {
                if best.as_ref().is_none_or(|b| c.score > b.score) {
                    best = Some(c);
                }
            }
        }
        best.filter(|b| b.score >= 6).ok_or_else(|| Error::malformed("no plausible SNES internal header"))
    }

    /// Whether checksum and complement agree.
    pub fn complement_ok(&self) -> bool {
        self.checksum ^ self.complement == 0xFFFF
    }

    pub fn fast_rom(&self) -> bool {
        self.map_mode & 0x10 != 0
    }

    pub fn rom_size_bytes(&self) -> Option<u64> {
        (self.rom_size_code <= 0x0D).then(|| 1024u64 << self.rom_size_code)
    }

    pub fn sram_size_bytes(&self) -> u64 {
        if self.sram_size_code == 0 || self.sram_size_code > 0x0D { 0 } else { 1024u64 << self.sram_size_code }
    }

    pub fn region(&self) -> &'static str {
        match self.country {
            0x00 => "Japan",
            0x01 => "USA",
            0x02 => "Europe",
            0x03 => "Sweden/Scandinavia",
            0x04 => "Finland",
            0x05 => "Denmark",
            0x06 => "France",
            0x07 => "Netherlands",
            0x08 => "Spain",
            0x09 => "Germany",
            0x0A => "Italy",
            0x0B => "China",
            0x0C => "Indonesia",
            0x0D => "South Korea",
            0x0E => "International",
            0x0F => "Canada",
            0x10 => "Brazil",
            0x11 => "Australia",
            _ => "unknown",
        }
    }

    pub fn video(&self) -> &'static str {
        match self.country {
            0x00 | 0x01 | 0x0D | 0x0F | 0x10 => "NTSC",
            0x02..=0x0C | 0x11 => "PAL",
            _ => "unknown",
        }
    }

    /// Cartridge hardware from the chipset byte (and the extended-header subtype).
    pub fn chipset_name(&self) -> String {
        let c = self.chipset;
        let mem = match c & 0x0F {
            0x00 => "ROM",
            0x01 => "ROM+RAM",
            0x02 => "ROM+RAM+battery",
            0x03 => "ROM+coprocessor",
            0x04 => "ROM+coprocessor+RAM",
            0x05 => "ROM+coprocessor+RAM+battery",
            0x06 => "ROM+coprocessor+battery",
            _ => "unknown",
        };
        if c & 0x0F < 3 {
            return mem.into();
        }
        let co = match c >> 4 {
            0x0 => "DSP".to_string(),
            0x1 => "Super FX (GSU)".into(),
            0x2 => "OBC1".into(),
            0x3 => "SA-1".into(),
            0x4 => "S-DD1".into(),
            0x5 => "S-RTC".into(),
            0xE => "Super Game Boy / Satellaview".into(),
            0xF => match self.chipset_subtype {
                Some(0x00) => "SPC7110".into(),
                Some(0x01) => "ST010/ST011".into(),
                Some(0x02) => "ST018".into(),
                Some(0x10) => "CX4".into(),
                _ => "custom".into(),
            },
            _ => "unknown".into(),
        };
        format!("{mem} ({co})")
    }

    /// Product code such as `SNS-AYKE-USA` when the extended header has a game code.
    pub fn product_code(&self) -> Option<String> {
        let g = self.game_code.as_ref()?;
        let r = match self.country {
            0x00 => "JPN",
            0x01 => "USA",
            0x0F => "CAN",
            0x02 => "EUR",
            _ => "",
        };
        Some(if r.is_empty() { format!("SNS-{g}") } else { format!("SNS-{g}-{r}") })
    }
}

/// Header checksum: 16-bit sum of all ROM bytes. Sizes that are not a power of two are
/// summed as the hardware sees them, with the remainder mirrored up to the next power of
/// two (for example 3 MiB = 2 MiB + the last 1 MiB twice).
pub fn checksum(rom: &dyn DataSource, job: &crate::JobContext) -> Result<u16> {
    fn sum(rom: &dyn DataSource, off: u64, len: u64, job: &crate::JobContext) -> Result<u16> {
        let mut s = 0u16;
        let mut buf = vec![0u8; 1 << 20];
        let mut p = 0;
        while p < len {
            job.check_cancel()?;
            let n = (len - p).min(buf.len() as u64) as usize;
            rom.read_exact_at(off + p, &mut buf[..n])?;
            for b in &buf[..n] {
                s = s.wrapping_add(*b as u16);
            }
            p += n as u64;
        }
        Ok(s)
    }
    fn mirror(rom: &dyn DataSource, off: u64, len: u64, mut mask: u64, job: &crate::JobContext) -> Result<u16> {
        while mask != 0 && len & mask == 0 {
            mask >>= 1;
        }
        let part1 = sum(rom, off, mask, job)?;
        let mut rest = len - mask;
        if rest == 0 {
            return Ok(part1);
        }
        let mut part2 = mirror(rom, off + mask, rest, mask >> 1, job)?;
        while rest < mask {
            rest += rest;
            part2 = part2.wrapping_add(part2);
        }
        Ok(part1.wrapping_add(part2))
    }
    let len = rom.len()?;
    if len == 0 {
        return Ok(0);
    }
    mirror(rom, 0, len, 1 << 62, job)
}

/// A minimal copier (SWC/SMC-style) header for `rom_len` bytes of ROM.
pub fn copier_header(rom_len: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    let blocks = (rom_len / 8192).min(0xFFFF) as u16;
    h[..2].copy_from_slice(&blocks.to_le_bytes());
    h[8] = 0xAA;
    h[9] = 0xBB;
    h[10] = 0x04;
    h
}

/// Synthetic ROM builder (feature `testkit`; not part of the stable API).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    use super::Mapping;

    /// Build a ROM of `size` bytes with a valid header at `mapping` and a correct checksum.
    pub fn rom(size: usize, mapping: Mapping, title: &str, game_code: Option<&str>) -> Vec<u8> {
        let mut r: Vec<u8> = (0..size).map(|i| (i * 7 + i / 251) as u8).collect();
        let at = mapping.header_offset() as usize;
        r[at..at + 21].fill(b' ');
        r[at..at + title.len()].copy_from_slice(title.as_bytes());
        r[at + 0x15] = match mapping {
            Mapping::LoRom => 0x20,
            Mapping::HiRom => 0x31,
            Mapping::ExHiRom => 0x35,
        };
        r[at + 0x16] = 0x02;
        r[at + 0x17] = (size as u64 / 1024).next_power_of_two().trailing_zeros() as u8;
        r[at + 0x18] = 0x03;
        r[at + 0x19] = 0x01;
        r[at + 0x1A] = if game_code.is_some() { 0x33 } else { 0x01 };
        r[at + 0x1B] = 0x00;
        if let Some(g) = game_code {
            r[at - 0x10..at - 0x0E].copy_from_slice(b"01");
            r[at - 0x0E..at - 0x0A].copy_from_slice(g.as_bytes());
        }
        r[at + 0x3C..at + 0x3E].copy_from_slice(&0x8000u16.to_le_bytes());
        // Checksum with the checksum/complement fields set to 0xFFFF/0x0000 (they sum to
        // 0x1FE either way), then store the real values.
        r[at + 0x1C..at + 0x1E].copy_from_slice(&0xFFFFu16.to_le_bytes());
        r[at + 0x1E..at + 0x20].copy_from_slice(&0u16.to_le_bytes());
        let src = crate::MemorySource::new(r.clone());
        let c = super::checksum(&src, &crate::JobContext::default()).unwrap();
        r[at + 0x1C..at + 0x1E].copy_from_slice(&(!c).to_le_bytes());
        r[at + 0x1E..at + 0x20].copy_from_slice(&c.to_le_bytes());
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JobContext, MemorySource};

    #[test]
    fn detects_each_mapping() {
        for (m, size) in [(Mapping::LoRom, 0x10_0000), (Mapping::HiRom, 0x40_0000), (Mapping::ExHiRom, 0x60_0000)] {
            let r = testkit::rom(size, m, "ROMUX TEST", Some("ARXE"));
            let h = SnesHeader::detect(&MemorySource::new(r.clone())).unwrap();
            assert_eq!(h.mapping, m);
            assert_eq!(h.title, "ROMUX TEST");
            assert_eq!(h.game_code.as_deref(), Some("ARXE"));
            assert!(h.complement_ok());
            assert_eq!(checksum(&MemorySource::new(r), &JobContext::default()).unwrap(), h.checksum);
        }
    }

    #[test]
    fn mirrored_checksum() {
        // 3 MiB: 2 MiB + 1 MiB counted twice.
        let r: Vec<u8> = (0..0x30_0000).map(|i| (i % 253) as u8).collect();
        let plain = |s: &[u8]| s.iter().fold(0u16, |a, b| a.wrapping_add(*b as u16));
        let want = plain(&r[..0x20_0000]).wrapping_add(plain(&r[0x20_0000..]).wrapping_mul(2));
        assert_eq!(checksum(&MemorySource::new(r), &JobContext::default()).unwrap(), want);
    }

    #[test]
    fn rejects_non_snes_data() {
        assert!(SnesHeader::detect(&MemorySource::new(vec![0u8; 0x20000])).is_err());
        let noise: Vec<u8> = (0..0x20000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        assert!(SnesHeader::detect(&MemorySource::new(noise)).is_err());
    }

    #[test]
    fn katakana_title() {
        assert_eq!(decode_title(&[0xBD, 0xB0, 0xCA, 0xDF, b' ']), "\u{FF7D}\u{FF70}\u{FF8A}\u{FF9F}");
    }
}
