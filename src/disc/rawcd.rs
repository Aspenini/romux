//! Raw CD sector layouts (2352-byte frames), user-data views, EDC/ECC.

use crate::{DataSource, Error, Result, SharedSource};

pub const SYNC: [u8; 12] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Track/sector modes as written in CUE sheets and CHD metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TrackMode {
    Audio,
    /// MODE1/2048 (cooked)
    Mode1Cooked,
    /// MODE1/2352
    Mode1Raw,
    /// MODE2/2336 (form-mix without sync/header)
    Mode2_2336,
    /// MODE2/2352
    Mode2Raw,
    /// MODE2/2048 form 1 cooked
    Mode2Form1,
    /// MODE2/2324 form 2 cooked
    Mode2Form2,
    /// CD+G (2448 with subcode)
    Cdg,
}

impl TrackMode {
    pub fn sector_size(&self) -> u64 {
        match self {
            TrackMode::Audio | TrackMode::Mode1Raw | TrackMode::Mode2Raw => 2352,
            TrackMode::Mode1Cooked | TrackMode::Mode2Form1 => 2048,
            TrackMode::Mode2_2336 => 2336,
            TrackMode::Mode2Form2 => 2324,
            TrackMode::Cdg => 2448,
        }
    }
    pub fn is_data(&self) -> bool {
        !matches!(self, TrackMode::Audio | TrackMode::Cdg)
    }
    pub fn from_cue(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "AUDIO" => TrackMode::Audio,
            "MODE1/2048" => TrackMode::Mode1Cooked,
            "MODE1/2352" => TrackMode::Mode1Raw,
            "MODE2/2336" => TrackMode::Mode2_2336,
            "MODE2/2352" => TrackMode::Mode2Raw,
            "MODE2/2048" => TrackMode::Mode2Form1,
            "MODE2/2324" => TrackMode::Mode2Form2,
            "CDG" => TrackMode::Cdg,
            _ => return None,
        })
    }
    pub fn cue_name(&self) -> &'static str {
        match self {
            TrackMode::Audio => "AUDIO",
            TrackMode::Mode1Cooked => "MODE1/2048",
            TrackMode::Mode1Raw => "MODE1/2352",
            TrackMode::Mode2_2336 => "MODE2/2336",
            TrackMode::Mode2Raw => "MODE2/2352",
            TrackMode::Mode2Form1 => "MODE2/2048",
            TrackMode::Mode2Form2 => "MODE2/2324",
            TrackMode::Cdg => "CDG",
        }
    }
    /// CHD metadata type string.
    pub fn chd_name(&self) -> &'static str {
        match self {
            TrackMode::Audio => "AUDIO",
            TrackMode::Mode1Cooked => "MODE1",
            TrackMode::Mode1Raw => "MODE1_RAW",
            TrackMode::Mode2_2336 => "MODE2",
            TrackMode::Mode2Raw => "MODE2_RAW",
            TrackMode::Mode2Form1 => "MODE2_FORM1",
            TrackMode::Mode2Form2 => "MODE2_FORM2",
            TrackMode::Cdg => "AUDIO",
        }
    }
    pub fn from_chd(s: &str) -> Option<Self> {
        Some(match s {
            "AUDIO" => TrackMode::Audio,
            "MODE1" => TrackMode::Mode1Cooked,
            "MODE1_RAW" => TrackMode::Mode1Raw,
            "MODE2" | "MODE2_FORM_MIX" => TrackMode::Mode2_2336,
            "MODE2_RAW" => TrackMode::Mode2Raw,
            "MODE2_FORM1" => TrackMode::Mode2Form1,
            "MODE2_FORM2" => TrackMode::Mode2Form2,
            _ => return None,
        })
    }
    /// Offset of 2048-byte user data inside one stored sector, if the mode carries it.
    pub fn user_data_offset(&self) -> Option<u64> {
        match self {
            TrackMode::Mode1Raw => Some(16),
            TrackMode::Mode2Raw => Some(24),
            TrackMode::Mode1Cooked | TrackMode::Mode2Form1 => Some(0),
            TrackMode::Mode2_2336 => Some(8),
            _ => None,
        }
    }
}

/// View of the 2048-byte user data of each sector in a track.
pub struct CookedSource {
    inner: SharedSource,
    sector_size: u64,
    data_offset: u64,
    sectors: u64,
}

impl CookedSource {
    pub fn new(inner: SharedSource, mode: TrackMode) -> Result<Self> {
        let data_offset = mode
            .user_data_offset()
            .ok_or_else(|| Error::unsupported(format!("track mode {} has no 2048-byte user data", mode.cue_name())))?;
        let sector_size = mode.sector_size();
        let sectors = inner.len()? / sector_size;
        Ok(CookedSource { inner, sector_size, data_offset, sectors })
    }
}

impl DataSource for CookedSource {
    fn len(&self) -> Result<u64> {
        Ok(self.sectors * 2048)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.sectors * 2048)?;
        while !out.is_empty() {
            let s = offset / 2048;
            let within = offset % 2048;
            let n = ((2048 - within) as usize).min(out.len());
            self.inner.read_exact_at(s * self.sector_size + self.data_offset + within, &mut out[..n])?;
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
    fn identity(&self) -> crate::SourceIdentity {
        self.inner.identity()
    }
}

/// Detect the mode of a raw 2352-byte data sector.
pub fn detect_raw_mode(sector: &[u8]) -> Option<TrackMode> {
    if sector.len() < 16 || sector[..12] != SYNC {
        return None;
    }
    match sector[15] {
        1 => Some(TrackMode::Mode1Raw),
        2 => Some(TrackMode::Mode2Raw),
        _ => None,
    }
}

// --- EDC / ECC ------------------------------------------------------------------------

fn edc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, e) in t.iter_mut().enumerate() {
        let mut edc = i as u32;
        for _ in 0..8 {
            edc = (edc >> 1) ^ if edc & 1 != 0 { 0xD801_8001 } else { 0 };
        }
        *e = edc;
    }
    t
}

/// CD-ROM EDC (CRC-32 variant, reflected polynomial 0xD8018001, init 0).
pub fn edc(data: &[u8]) -> u32 {
    let t = edc_table();
    data.iter().fold(0u32, |edc, &b| (edc >> 8) ^ t[((edc ^ b as u32) & 0xFF) as usize])
}

fn ecc_luts() -> ([u8; 256], [u8; 256]) {
    let mut f = [0u8; 256];
    let mut b = [0u8; 256];
    for i in 0..256usize {
        let j = ((i << 1) ^ if i & 0x80 != 0 { 0x11D } else { 0 }) as u8;
        f[i] = j;
        b[i ^ j as usize] = i as u8;
    }
    (f, b)
}

fn ecc_block(
    src: &[u8],
    major_count: usize,
    minor_count: usize,
    major_mult: usize,
    minor_inc: usize,
    dest: &mut [u8],
    luts: &([u8; 256], [u8; 256]),
) {
    let size = major_count * minor_count;
    for major in 0..major_count {
        let mut index = (major >> 1) * major_mult + (major & 1);
        let mut a = 0u8;
        let mut b = 0u8;
        for _ in 0..minor_count {
            let t = src[index];
            index += minor_inc;
            if index >= size {
                index -= size;
            }
            a ^= t;
            b ^= t;
            a = luts.0[a as usize];
        }
        a = luts.1[(luts.0[a as usize] ^ b) as usize];
        dest[major] = a;
        dest[major + major_count] = a ^ b;
    }
}

/// Regenerate P and Q ECC parity for a 2352-byte sector in place (Mode 1 layout).
pub fn ecc_generate(sector: &mut [u8]) {
    let luts = ecc_luts();
    let mut p = [0u8; 172];
    ecc_block(&sector[0xC..0xC + 2236], 86, 24, 2, 86, &mut p, &luts);
    sector[0x81C..0x81C + 172].copy_from_slice(&p);
    let mut q = [0u8; 104];
    ecc_block(&sector[0xC..0xC + 2236], 52, 43, 86, 88, &mut q, &luts);
    sector[0x8C8..0x8C8 + 104].copy_from_slice(&q);
}

/// Check the EDC of a Mode 1 raw sector.
pub fn mode1_edc_ok(sector: &[u8]) -> bool {
    sector.len() >= 0x814 && edc(&sector[..0x810]) == u32::from_le_bytes([sector[0x810], sector[0x811], sector[0x812], sector[0x813]])
}

/// Build a valid raw Mode 1 sector from user data (used for fixtures and tests).
#[cfg(any(test, feature = "testkit"))]
pub fn make_mode1_sector(lba: u32, user: &[u8; 2048]) -> Vec<u8> {
    let mut s = vec![0u8; 2352];
    s[..12].copy_from_slice(&SYNC);
    let abs = lba + 150;
    let bcd = |v: u32| (((v / 10) << 4) | (v % 10)) as u8;
    s[12] = bcd(abs / 75 / 60);
    s[13] = bcd((abs / 75) % 60);
    s[14] = bcd(abs % 75);
    s[15] = 1;
    s[16..16 + 2048].copy_from_slice(user);
    let e = edc(&s[..0x810]);
    s[0x810..0x814].copy_from_slice(&e.to_le_bytes());
    ecc_generate(&mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_regeneration_is_stable() {
        let user = [0x5Au8; 2048];
        let s = make_mode1_sector(16, &user);
        assert!(mode1_edc_ok(&s));
        let mut t = s.clone();
        t[0x81C..].fill(0);
        ecc_generate(&mut t);
        assert_eq!(s, t);
        assert_eq!(detect_raw_mode(&s), Some(TrackMode::Mode1Raw));
    }
}
