//! Xbox 360 XEX executable metadata (`default.xex`): title ID, media ID, version, disc.

use crate::binary::u32be;
use crate::{DataSource, Error, Result, read_vec};

/// Optional-header key of the execution info block.
const EXECUTION_INFO: u32 = 0x0004_0006;

#[derive(Debug, Clone, serde::Serialize)]
pub struct XexInfo {
    pub magic: String,
    pub media_id: u32,
    pub version: u32,
    pub base_version: u32,
    pub title_id: u32,
    pub disc_number: u8,
    pub disc_count: u8,
}

impl XexInfo {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let len = s.len()?;
        let h = read_vec(s, 0, len.min(0x18), 0x18)?;
        if h.len() < 0x18 || !matches!(&h[..4], b"XEX2" | b"XEX1" | b"XEX%" | b"XEX-") {
            return Err(Error::malformed("missing XEX magic"));
        }
        let count = u32be(&h, 0x14)? as u64;
        if count > 64 {
            return Err(Error::malformed("implausible XEX optional header count"));
        }
        let table = read_vec(s, 0x18, count * 8, 64 * 8)?;
        for i in 0..count as usize {
            let key = u32be(&table, i * 8)?;
            if key == EXECUTION_INFO {
                let off = u32be(&table, i * 8 + 4)? as u64;
                let e = read_vec(s, off, 0x18, 0x18)?;
                return Ok(XexInfo {
                    magic: String::from_utf8_lossy(&h[..4]).into_owned(),
                    media_id: u32be(&e, 0)?,
                    version: u32be(&e, 4)?,
                    base_version: u32be(&e, 8)?,
                    title_id: u32be(&e, 0xC)?,
                    disc_number: e[0x12],
                    disc_count: e[0x13],
                });
            }
        }
        Err(Error::malformed("XEX has no execution info header"))
    }

    /// `major.minor.build.qfe`.
    pub fn version_string(&self) -> String {
        let v = self.version;
        format!("{}.{}.{}.{}", v >> 28, (v >> 24) & 0xF, (v >> 8) & 0xFFFF, v & 0xFF)
    }

    /// Publisher letters + number, e.g. `EA-2226`.
    pub fn product_code(&self) -> String {
        let a = ((self.title_id >> 24) & 0xFF) as u8;
        let b = ((self.title_id >> 16) & 0xFF) as u8;
        if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
            format!("{}{}-{}", a as char, b as char, self.title_id & 0xFFFF)
        } else {
            format!("{:08X}", self.title_id)
        }
    }
}

/// Synthetic-fixture builder (feature `testkit`; not part of the stable API).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    /// Minimal XEX2 with an execution info block.
    pub fn build(title_id: u32, media_id: u32) -> Vec<u8> {
        let mut x = vec![0u8; 0x100];
        x[..4].copy_from_slice(b"XEX2");
        x[0x14..0x18].copy_from_slice(&1u32.to_be_bytes());
        x[0x18..0x1C].copy_from_slice(&0x0004_0006u32.to_be_bytes());
        x[0x1C..0x20].copy_from_slice(&0x40u32.to_be_bytes());
        x[0x40..0x44].copy_from_slice(&media_id.to_be_bytes());
        x[0x44..0x48].copy_from_slice(&0x2000_0100u32.to_be_bytes());
        x[0x4C..0x50].copy_from_slice(&title_id.to_be_bytes());
        x[0x52] = 1;
        x[0x53] = 1;
        x
    }
}
