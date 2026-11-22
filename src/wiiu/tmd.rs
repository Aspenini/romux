//! Wii U title metadata (TMD).

use crate::binary::{u16be, u32be, u64be};
use crate::{Error, Result};

#[derive(Debug, Clone, serde::Serialize)]
pub struct TmdContent {
    pub id: u32,
    pub index: u16,
    pub content_type: u16,
    pub size: u64,
    pub hash: String,
}

impl TmdContent {
    pub fn encrypted(&self) -> bool {
        self.content_type & 0x0001 != 0
    }
    /// Hashed (H3-protected) content.
    pub fn has_h3(&self) -> bool {
        self.content_type & 0x0002 != 0
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Tmd {
    pub title_id: u64,
    pub title_version: u16,
    pub contents: Vec<TmdContent>,
}

impl Tmd {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 0xB04 || u32be(b, 0)? != 0x0001_0004 {
            return Err(Error::malformed("not an RSA-2048 signed Wii U TMD"));
        }
        let version = b[0x180];
        if version != 1 {
            return Err(Error::malformed("TMD version is not the Wii U layout"));
        }
        let title_id = u64be(b, 0x18C)?;
        if title_id >> 48 != 0x0005 {
            return Err(Error::malformed("title ID is not a Wii U title"));
        }
        let count = u16be(b, 0x1DE)? as usize;
        if b.len() < 0xB04 + count * 0x30 {
            return Err(Error::bounds("TMD content records truncated"));
        }
        let mut contents = Vec::with_capacity(count);
        for i in 0..count {
            let o = 0xB04 + i * 0x30;
            contents.push(TmdContent {
                id: u32be(b, o)?,
                index: u16be(b, o + 4)?,
                content_type: u16be(b, o + 6)?,
                size: u64be(b, o + 8)?,
                hash: crate::hex(&b[o + 16..o + 0x30]),
            });
        }
        Ok(Tmd { title_id, title_version: u16be(b, 0x1DC)?, contents })
    }
}
