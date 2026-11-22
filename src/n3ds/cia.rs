//! CIA installable title archives: header, ticket, TMD, contents, meta; plus an unsigned
//! CIA writer used for CCI→CIA repackaging of plaintext (NoCrypto) or already-decrypted
//! content.

use crate::binary::{ByteWriter, u16be, u32be, u32le, u64be, u64le};
use crate::{DataSource, Error, KeyProvider, Result, SharedSource, SubSource, read_vec};
use serde::Serialize;
use std::io::Write;
use zeroize::Zeroizing;

fn align64(v: u64) -> u64 {
    v.div_ceil(64) * 64
}

fn sig_size(t: u32) -> Option<usize> {
    Some(match t {
        0x10000 | 0x10003 => 0x200 + 0x3C,
        0x10001 | 0x10004 => 0x100 + 0x3C,
        0x10002 | 0x10005 => 0x3C + 0x40,
        _ => return None,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentChunk {
    pub id: u32,
    pub index: u16,
    pub content_type: u16,
    pub size: u64,
    pub hash: String,
    pub offset: u64,
}

impl ContentChunk {
    pub fn encrypted(&self) -> bool {
        self.content_type & 1 != 0
    }
}

pub struct Cia {
    pub src: SharedSource,
    pub cert: (u64, u64),
    pub ticket: (u64, u64),
    pub tmd: (u64, u64),
    pub meta: (u64, u64),
    pub title_id: u64,
    pub title_version: u16,
    pub contents: Vec<ContentChunk>,
    pub common_key_index: u8,
    encrypted_titlekey: [u8; 16],
    pub ticket_title_id: u64,
}

pub fn probe(s: &dyn DataSource) -> bool {
    let mut h = [0u8; 0x20];
    s.read_exact_at(0, &mut h).is_ok() && u32::from_le_bytes([h[0], h[1], h[2], h[3]]) == 0x2020 && u16::from_le_bytes([h[4], h[5]]) == 0
}

impl Cia {
    pub fn open(src: SharedSource) -> Result<Self> {
        let h = read_vec(src.as_ref(), 0, 0x2020, 0x2020)?;
        let hs = u32le(&h, 0)? as u64;
        if hs != 0x2020 {
            return Err(Error::malformed("CIA header size is not 0x2020"));
        }
        let cert_size = u32le(&h, 8)? as u64;
        let tik_size = u32le(&h, 12)? as u64;
        let tmd_size = u32le(&h, 16)? as u64;
        let meta_size = u32le(&h, 20)? as u64;
        let content_size = u64le(&h, 24)?;
        let cert = align64(hs);
        let tik = align64(cert + cert_size);
        let tmd = align64(tik + tik_size);
        let content = align64(tmd + tmd_size);
        let meta = align64(content + content_size);
        let len = src.len()?;
        if content + content_size > len || tmd_size < 0x140 || tik_size < 0x140 {
            return Err(Error::bounds("CIA sections exceed the file"));
        }
        let tm = read_vec(src.as_ref(), tmd, tmd_size, 1 << 20)?;
        let st = u32be(&tm, 0)?;
        let so = 4 + sig_size(st).ok_or_else(|| Error::malformed(format!("unknown TMD signature type 0x{st:x}")))?;
        let title_id = u64be(&tm, so + 0x4C)?;
        let title_version = u16be(&tm, so + 0x9C)?;
        let count = u16be(&tm, so + 0x9E)? as usize;
        let chunks = so + 0xC4 + 64 * 0x24;
        if tm.len() < chunks + count * 0x30 {
            return Err(Error::bounds("TMD content chunks truncated"));
        }
        let index = &h[0x20..0x2020];
        let mut contents = Vec::new();
        let mut off = content;
        for i in 0..count {
            let c = &tm[chunks + i * 0x30..];
            let idx = u16be(c, 4)?;
            let present = index.get(idx as usize / 8).is_some_and(|b| b & (0x80 >> (idx % 8)) != 0);
            if !present {
                continue;
            }
            let size = u64be(c, 8)?;
            contents.push(ContentChunk {
                id: u32be(c, 0)?,
                index: idx,
                content_type: u16be(c, 6)?,
                size,
                hash: crate::hex(&c[16..48]),
                offset: off,
            });
            off = align64(off + size);
        }
        if contents.last().is_some_and(|c| c.offset + c.size > content + content_size) {
            return Err(Error::bounds("CIA contents exceed the content section"));
        }
        let tk = read_vec(src.as_ref(), tik, tik_size, 0x2000)?;
        let ts = u32be(&tk, 0)?;
        let to = 4 + sig_size(ts).ok_or_else(|| Error::malformed(format!("unknown ticket signature type 0x{ts:x}")))?;
        Ok(Cia {
            cert: (cert, cert_size),
            ticket: (tik, tik_size),
            tmd: (tmd, tmd_size),
            meta: (meta, meta_size.min(len.saturating_sub(meta))),
            title_id,
            title_version,
            contents,
            encrypted_titlekey: crate::binary::array(&tk, to + 0x7F)?,
            ticket_title_id: u64be(&tk, to + 0x9C)?,
            common_key_index: tk[to + 0xB1],
            src,
        })
    }

    pub fn section(&self, s: (u64, u64)) -> Result<SharedSource> {
        SubSource::shared(self.src.clone(), s.0, s.1)
    }

    pub fn raw_content(&self, c: &ContentChunk) -> Result<SharedSource> {
        SubSource::shared(self.src.clone(), c.offset, c.size)
    }

    /// Plaintext content: as stored when unencrypted; AES-CBC with the title key otherwise
    /// (requires `ctr_common_key_<index>` — the *normal* common key supplied by the user).
    pub fn content_plain(&self, c: &ContentChunk, keys: &dyn KeyProvider, limit: u64) -> Result<SharedSource> {
        if !c.encrypted() {
            return self.raw_content(c);
        }
        let name = format!("ctr_common_key_{}", self.common_key_index);
        let ck = crate::crypto::key16(keys, &name)
            .ok_or_else(|| Error::needs_keys(format!("key material `{name}` is required to decrypt CIA contents")))?;
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&self.ticket_title_id.to_be_bytes());
        let mut tk = Zeroizing::new(self.encrypted_titlekey);
        crate::crypto::cbc_decrypt(&ck, &iv, &mut tk[..])?;
        let mut d = read_vec(self.src.as_ref(), c.offset, c.size, limit)?;
        let mut civ = [0u8; 16];
        civ[..2].copy_from_slice(&c.index.to_be_bytes());
        crate::crypto::cbc_decrypt(&tk, &civ, &mut d)?;
        Ok(std::sync::Arc::new(crate::MemorySource::new(d)))
    }
}

/// Write an unsigned CIA from plaintext NCCH contents (index, data). Signatures are zero;
/// contents are marked unencrypted; the result is NOT installable on retail systems.
pub fn write_unsigned(
    title_id: u64,
    version: u16,
    contents: &[(u16, SharedSource)],
    out: &mut dyn Write,
    job: &crate::JobContext,
) -> Result<u64> {
    let mut hashes = Vec::new();
    for (_, s) in contents {
        let h = crate::crypto::hash_range(s.as_ref(), 0, s.len()?, crate::crypto::HashAlg::Sha256, None)?;
        hashes.push(h);
        job.check_cancel()?;
    }
    // Ticket
    let mut tk = ByteWriter::new();
    tk.u32be(0x10004).zeros(0x100 + 0x3C);
    let mut issuer = b"Root-CA00000003-XS0000000c".to_vec();
    issuer.resize(0x40, 0);
    tk.bytes(&issuer)
        .zeros(0x3C)
        .u8(1)
        .u8(0)
        .u8(0)
        .zeros(16)
        .u8(0)
        .u64be(0)
        .u32be(0)
        .u64be(title_id)
        .u16be(0)
        .u16be(version)
        .zeros(8)
        .u8(0)
        .u8(0);
    tk.pad_to(0x350);
    // TMD
    let mut chunks = ByteWriter::new();
    for ((idx, s), h) in contents.iter().zip(&hashes) {
        chunks.u32be(*idx as u32).u16be(*idx).u16be(0).u64be(s.len()?).bytes(h);
    }
    let mut info = ByteWriter::new();
    info.u16be(0).u16be(contents.len() as u16).bytes(&crate::crypto::sha256(&chunks.buf));
    info.pad_to(64 * 0x24);
    let mut tmd = ByteWriter::new();
    tmd.u32be(0x10004).zeros(0x100 + 0x3C);
    let mut tissuer = b"Root-CA00000003-CP0000000b".to_vec();
    tissuer.resize(0x40, 0);
    tmd.bytes(&tissuer)
        .u8(1)
        .u8(0)
        .u8(0)
        .u8(0)
        .u64be(0)
        .u64be(title_id)
        .u32be(0x40)
        .u16be(0)
        .u32be(0)
        .u32be(0)
        .u32be(0)
        .u8(0)
        .zeros(0x31)
        .u32be(0)
        .u16be(version)
        .u16be(contents.len() as u16)
        .u16be(0)
        .u16be(0);
    tmd.bytes(&crate::crypto::sha256(&info.buf));
    tmd.bytes(&info.buf).bytes(&chunks.buf);
    let content_size: u64 = {
        let mut t = 0u64;
        for (_, s) in contents {
            t = align64(t + s.len()?);
        }
        t
    };
    let mut h = ByteWriter::new();
    h.u32le(0x2020).u16le(0).u16le(0).u32le(0).u32le(tk.len() as u32).u32le(tmd.len() as u32).u32le(0).u64le(content_size);
    let mut bitmap = vec![0u8; 0x2000];
    for (idx, _) in contents {
        bitmap[*idx as usize / 8] |= 0x80 >> (idx % 8);
    }
    h.bytes(&bitmap);
    let mut written = 0u64;
    let emit = |out: &mut dyn Write, b: &[u8], written: &mut u64| -> Result<()> {
        out.write_all(b)?;
        *written += b.len() as u64;
        let pad = align64(*written) - *written;
        out.write_all(&vec![0u8; pad as usize])?;
        *written += pad;
        Ok(())
    };
    emit(out, &h.buf, &mut written)?;
    emit(out, &tk.buf, &mut written)?;
    emit(out, &tmd.buf, &mut written)?;
    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(content_size));
    for (_, s) in contents {
        crate::copy_all(s.as_ref(), out, &mut p)?;
        let len = s.len()?;
        written += len;
        let pad = align64(written) - written;
        out.write_all(&vec![0u8; pad as usize])?;
        written += pad;
    }
    Ok(written)
}
