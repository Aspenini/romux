//! Wii WAD installable archives: certificates, ticket, TMD, contents and footer.

use crate::binary::{u16be, u32be, u64be};
use crate::{DataSource, Error, KeyProvider, Result, SharedSource, SubSource, read_vec};
use zeroize::Zeroizing;

#[derive(Debug, Clone, serde::Serialize)]
pub struct WadContent {
    pub id: u32,
    pub index: u16,
    pub content_type: u16,
    pub size: u64,
    pub sha1: String,
    pub offset: u64,
}

pub struct Wad {
    pub src: SharedSource,
    pub wad_type: u16,
    pub cert: (u64, u64),
    pub ticket: (u64, u64),
    pub tmd: (u64, u64),
    pub footer: (u64, u64),
    pub title_id: u64,
    pub title_version: u16,
    pub contents: Vec<WadContent>,
    pub common_key_index: u8,
    encrypted_titlekey: [u8; 16],
}

fn align(v: u64) -> u64 {
    v.div_ceil(0x40) * 0x40
}

pub fn probe(s: &dyn DataSource) -> bool {
    let mut h = [0u8; 8];
    s.read_exact_at(0, &mut h).is_ok() && u32::from_be_bytes([h[0], h[1], h[2], h[3]]) == 0x20 && matches!(&h[4..6], b"Is" | b"ib" | b"Bk")
}

impl Wad {
    pub fn open(src: SharedSource) -> Result<Self> {
        let h = read_vec(src.as_ref(), 0, 0x20, 0x20)?;
        if !probe(src.as_ref()) {
            return Err(Error::malformed("not a WAD header"));
        }
        let hs = u32be(&h, 0)? as u64;
        let cert_size = u32be(&h, 8)? as u64;
        let tik_size = u32be(&h, 16)? as u64;
        let tmd_size = u32be(&h, 20)? as u64;
        let data_size = u32be(&h, 24)? as u64;
        let footer_size = u32be(&h, 28)? as u64;
        let cert = align(hs);
        let tik = align(cert + cert_size);
        let tmd = align(tik + tik_size);
        let data = align(tmd + tmd_size);
        let footer = align(data + data_size);
        let len = src.len()?;
        if data + data_size > len || tmd_size < 0x1E4 || tik_size < 0x2A4 {
            return Err(Error::bounds("WAD sections exceed the file"));
        }
        let tm = read_vec(src.as_ref(), tmd, tmd_size, 1 << 20)?;
        let tk = read_vec(src.as_ref(), tik, tik_size, 0x1000)?;
        let count = u16be(&tm, 0x1DE)? as usize;
        if tm.len() < 0x1E4 + count * 0x24 {
            return Err(Error::bounds("WAD TMD content table truncated"));
        }
        let mut contents = Vec::new();
        let mut off = data;
        for i in 0..count {
            let o = 0x1E4 + i * 0x24;
            let size = u64be(&tm, o + 8)?;
            contents.push(WadContent {
                id: u32be(&tm, o)?,
                index: u16be(&tm, o + 4)?,
                content_type: u16be(&tm, o + 6)?,
                size,
                sha1: crate::hex(&tm[o + 0x10..o + 0x24]),
                offset: off,
            });
            off = align(off + size);
        }
        if contents.last().is_some_and(|c| c.offset + c.size > data + data_size) {
            return Err(Error::bounds("WAD contents exceed the data section"));
        }
        Ok(Wad {
            wad_type: u16be(&h, 4)?,
            cert: (cert, cert_size),
            ticket: (tik, tik_size),
            tmd: (tmd, tmd_size),
            footer: (footer, footer_size.min(len.saturating_sub(footer))),
            title_id: u64be(&tm, 0x18C)?,
            title_version: u16be(&tm, 0x1DC)?,
            common_key_index: tk[0x1F1],
            encrypted_titlekey: crate::binary::array(&tk, 0x1BF)?,
            contents,
            src,
        })
    }

    pub fn section(&self, s: (u64, u64)) -> Result<SharedSource> {
        SubSource::shared(self.src.clone(), s.0, s.1)
    }

    /// Stored (encrypted) bytes of a content, padded to 16 bytes as stored.
    pub fn content_raw(&self, c: &WadContent) -> Result<SharedSource> {
        let stored = c.size.div_ceil(16) * 16;
        SubSource::shared(self.src.clone(), c.offset, stored.min(self.src.len()? - c.offset))
    }

    /// Decrypt a content with the user-supplied common key; returns plaintext bytes.
    pub fn decrypt_content(&self, c: &WadContent, keys: &dyn KeyProvider, limit: u64) -> Result<Vec<u8>> {
        let name = crate::wii::partition::common_key_name(self.common_key_index);
        let ck = crate::crypto::key16(keys, name).ok_or_else(|| Error::needs_keys(format!("key material `{name}` is required")))?;
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&self.title_id.to_be_bytes());
        let mut tk = Zeroizing::new(self.encrypted_titlekey);
        crate::crypto::cbc_decrypt(&ck, &iv, &mut tk[..])?;
        let raw = self.content_raw(c)?;
        let mut d = read_vec(raw.as_ref(), 0, raw.len()?, limit)?;
        let mut civ = [0u8; 16];
        civ[..2].copy_from_slice(&c.index.to_be_bytes());
        crate::crypto::cbc_decrypt(&tk, &civ, &mut d)?;
        d.truncate(c.size as usize);
        Ok(d)
    }
}
