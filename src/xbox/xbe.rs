//! XBE executable certificate metadata (title ID, name, region, version).

use crate::binary::u32le;
use crate::{DataSource, Error, Result, read_vec};

#[derive(Debug, Clone, serde::Serialize)]
pub struct XbeInfo {
    pub title_id: u32,
    pub title_name: String,
    pub region: u32,
    pub disc_number: u32,
    pub version: u32,
}

impl XbeInfo {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h = read_vec(s, 0, 0x180.min(s.len()?), 0x180)?;
        if h.len() < 0x180 || &h[..4] != b"XBEH" {
            return Err(Error::malformed("missing XBEH magic"));
        }
        let base = u32le(&h, 0x104)?;
        let cert_addr = u32le(&h, 0x118)?;
        let off = cert_addr.checked_sub(base).ok_or_else(|| Error::malformed("certificate address below base"))? as u64;
        let c = read_vec(s, off, 0xB0, 0xB0)?;
        Ok(XbeInfo {
            title_id: u32le(&c, 0x08)?,
            title_name: crate::binary::utf16le_z(&c[0x0C..0x5C]),
            region: u32le(&c, 0xA0)?,
            disc_number: u32le(&c, 0xA8)?,
            version: u32le(&c, 0xAC)?,
        })
    }

    /// Publisher code + number, e.g. `MS-001`.
    pub fn product_code(&self) -> String {
        let a = ((self.title_id >> 24) & 0xFF) as u8 as char;
        let b = ((self.title_id >> 16) & 0xFF) as u8 as char;
        format!("{a}{b}-{:03}", self.title_id & 0xFFFF)
    }

    pub fn region_names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.region & 1 != 0 {
            v.push("NA");
        }
        if self.region & 2 != 0 {
            v.push("JP");
        }
        if self.region & 4 != 0 {
            v.push("EU/AU");
        }
        if self.region & 0x8000_0000 != 0 {
            v.push("debug");
        }
        v
    }
}

/// Synthetic-fixture builder (feature `testkit`; not part of the stable API).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    pub fn build(title_id: u32, name: &str) -> Vec<u8> {
        let mut x = vec![0u8; 0x400];
        x[..4].copy_from_slice(b"XBEH");
        x[0x104..0x108].copy_from_slice(&0x10000u32.to_le_bytes());
        x[0x118..0x11C].copy_from_slice(&(0x10000u32 + 0x200).to_le_bytes());
        let c = 0x200;
        x[c + 8..c + 12].copy_from_slice(&title_id.to_le_bytes());
        for (i, u) in name.encode_utf16().take(40).enumerate() {
            x[c + 0x0C + i * 2..c + 0x0E + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        x[c + 0xA0..c + 0xA4].copy_from_slice(&7u32.to_le_bytes());
        x
    }
}
