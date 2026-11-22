//! Minimal, strict ZIP reader/writer (stored + deflate, ZIP64 reading) for VPK packages.

use crate::binary::{u16le, u32le, u64le};
use crate::{DataSource, Error, ResourceLimits, Result, SharedSource, SubSource, read_vec};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    pub local_header_offset: u64,
    pub is_dir: bool,
    pub encrypted: bool,
}

pub struct ZipArchive {
    pub source: SharedSource,
    pub entries: Vec<ZipEntry>,
}

fn find_eocd(s: &dyn DataSource) -> Result<u64> {
    let len = s.len()?;
    if len < 22 {
        return Err(Error::malformed("file too small for a ZIP end record"));
    }
    let tail = (len).min(22 + 0xFFFF);
    let buf = read_vec(s, len - tail, tail, tail)?;
    for i in (0..=buf.len() - 22).rev() {
        if &buf[i..i + 4] == b"PK\x05\x06" {
            return Ok(len - tail + i as u64);
        }
    }
    Err(Error::malformed("ZIP end of central directory not found"))
}

pub fn probe(s: &dyn DataSource) -> bool {
    let mut m = [0u8; 4];
    s.read_exact_at(0, &mut m).is_ok() && &m == b"PK\x03\x04" && find_eocd(s).is_ok()
}

impl ZipArchive {
    pub fn open(source: SharedSource, limits: &ResourceLimits) -> Result<Self> {
        let eocd_off = find_eocd(source.as_ref())?;
        let e = read_vec(source.as_ref(), eocd_off, 22, 22)?;
        let mut count = u16le(&e, 10)? as u64;
        let mut cd_size = u32le(&e, 12)? as u64;
        let mut cd_off = u32le(&e, 16)? as u64;
        if count == 0xFFFF || cd_off == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF {
            if eocd_off < 20 {
                return Err(Error::malformed("ZIP64 locator missing"));
            }
            let loc = read_vec(source.as_ref(), eocd_off - 20, 20, 20)?;
            if &loc[..4] != b"PK\x06\x07" {
                return Err(Error::malformed("ZIP64 locator missing"));
            }
            let z64 = u64le(&loc, 8)?;
            let r = read_vec(source.as_ref(), z64, 56, 56)?;
            if &r[..4] != b"PK\x06\x06" {
                return Err(Error::malformed("ZIP64 end record missing"));
            }
            count = u64le(&r, 32)?;
            cd_size = u64le(&r, 40)?;
            cd_off = u64le(&r, 48)?;
        }
        if count > limits.max_entries {
            return Err(Error::limit("too many ZIP entries"));
        }
        let cd = read_vec(source.as_ref(), cd_off, cd_size, limits.max_metadata)?;
        let mut entries = Vec::with_capacity(count as usize);
        let mut p = 0usize;
        let total = source.len()?;
        for _ in 0..count {
            if crate::binary::slice(&cd, p, 4)? != b"PK\x01\x02" {
                return Err(Error::malformed("bad central directory signature"));
            }
            let flags = u16le(&cd, p + 8)?;
            let method = u16le(&cd, p + 10)?;
            let crc32 = u32le(&cd, p + 16)?;
            let mut csize = u32le(&cd, p + 20)? as u64;
            let mut usize_ = u32le(&cd, p + 24)? as u64;
            let nlen = u16le(&cd, p + 28)? as usize;
            let xlen = u16le(&cd, p + 30)? as usize;
            let klen = u16le(&cd, p + 32)? as usize;
            let mut lho = u32le(&cd, p + 42)? as u64;
            let name_b = crate::binary::slice(&cd, p + 46, nlen)?;
            if nlen > limits.max_name_len {
                return Err(Error::limit("ZIP entry name too long"));
            }
            let name = String::from_utf8_lossy(name_b).into_owned();
            let extra = crate::binary::slice(&cd, p + 46 + nlen, xlen)?;
            let mut x = 0usize;
            while x + 4 <= extra.len() {
                let id = u16le(extra, x)?;
                let sz = u16le(extra, x + 2)? as usize;
                if id == 1 {
                    let mut q = x + 4;
                    if usize_ == 0xFFFF_FFFF {
                        usize_ = u64le(extra, q)?;
                        q += 8;
                    }
                    if csize == 0xFFFF_FFFF {
                        csize = u64le(extra, q)?;
                        q += 8;
                    }
                    if lho == 0xFFFF_FFFF {
                        lho = u64le(extra, q)?;
                    }
                }
                x += 4 + sz;
            }
            if lho + 30 > total || lho.saturating_add(csize) > total {
                return Err(Error::bounds(format!("ZIP entry {name} exceeds the archive")));
            }
            entries.push(ZipEntry {
                is_dir: name.ends_with('/'),
                name,
                method,
                crc32,
                compressed_size: csize,
                size: usize_,
                local_header_offset: lho,
                encrypted: flags & 1 != 0,
            });
            p += 46 + nlen + xlen + klen;
        }
        Ok(ZipArchive { source, entries })
    }

    fn data_offset(&self, e: &ZipEntry) -> Result<u64> {
        let lh = read_vec(self.source.as_ref(), e.local_header_offset, 30, 30)?;
        if &lh[..4] != b"PK\x03\x04" {
            return Err(Error::malformed(format!("bad local header for {}", e.name)));
        }
        Ok(e.local_header_offset + 30 + u16le(&lh, 26)? as u64 + u16le(&lh, 28)? as u64)
    }

    /// Decompressed view of an entry.
    pub fn open_entry(&self, e: &ZipEntry) -> Result<SharedSource> {
        if e.encrypted {
            return Err(Error::unsupported(format!("{} is encrypted (ZIP encryption is not supported)", e.name)));
        }
        let off = self.data_offset(e)?;
        let raw = SubSource::shared(self.source.clone(), off, e.compressed_size)?;
        match e.method {
            0 => {
                if e.compressed_size != e.size {
                    return Err(Error::malformed(format!("stored entry {} has mismatched sizes", e.name)));
                }
                Ok(raw)
            }
            8 => Ok(Arc::new(InflateSource { raw, size: e.size, state: Mutex::new(None) })),
            m => Err(Error::unsupported(format!("ZIP compression method {m} is not supported"))),
        }
    }

    /// Verify the CRC-32 of every file entry.
    pub fn verify_crcs(&self, job: &crate::JobContext) -> Result<Vec<(String, bool)>> {
        let mut out = Vec::new();
        for e in self.entries.iter().filter(|e| !e.is_dir) {
            job.check_cancel()?;
            let s = self.open_entry(e)?;
            let crc = crate::crypto::hash_range(s.as_ref(), 0, s.len()?, crate::crypto::HashAlg::Crc32, None)?;
            out.push((e.name.clone(), u32::from_be_bytes([crc[0], crc[1], crc[2], crc[3]]) == e.crc32));
        }
        Ok(out)
    }
}

struct InflateState {
    dec: flate2::read::DeflateDecoder<std::io::BufReader<crate::SourceReader>>,
    pos: u64,
}

/// Sequential inflate with restart on backward seeks.
struct InflateSource {
    raw: SharedSource,
    size: u64,
    state: Mutex<Option<InflateState>>,
}

impl DataSource for InflateSource {
    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.size)?;
        let mut g = self.state.lock().map_err(|_| Error::internal("poisoned"))?;
        if g.as_ref().is_none_or(|s| s.pos > offset) {
            let r = crate::SourceReader::new(self.raw.clone())?;
            *g = Some(InflateState { dec: flate2::read::DeflateDecoder::new(std::io::BufReader::new(r)), pos: 0 });
        }
        let st = g.as_mut().ok_or_else(|| Error::internal("no state"))?;
        let mut skip = offset - st.pos;
        let mut junk = vec![0u8; 1 << 16];
        while skip > 0 {
            let n = skip.min(junk.len() as u64) as usize;
            st.dec.read_exact(&mut junk[..n]).map_err(|e| Error::codec(format!("inflate: {e}")))?;
            skip -= n as u64;
        }
        st.dec.read_exact(out).map_err(|e| Error::codec(format!("inflate: {e}")))?;
        st.pos = offset + out.len() as u64;
        Ok(())
    }
}

/// Streaming ZIP writer (deterministic: fixed timestamps, sorted input order preserved).
pub struct ZipWriter<'a, W: Write + Seek> {
    out: &'a mut W,
    central: Vec<u8>,
    count: u64,
}

impl<'a, W: Write + Seek> ZipWriter<'a, W> {
    pub fn new(out: &'a mut W) -> Self {
        ZipWriter { out, central: Vec::new(), count: 0 }
    }

    /// Add a file; `deflate` selects method 8 (falls back to stored if larger).
    pub fn add(&mut self, name: &str, data: &dyn DataSource, deflate: bool, level: u32) -> Result<()> {
        let size = data.len()?;
        if size >= 0xFFFF_FFFF {
            return Err(Error::unsupported("entries of 4 GiB or more are not supported by the writer"));
        }
        let start = self.out.stream_position()?;
        if start >= 0xFFFF_FFFF {
            return Err(Error::unsupported("archives beyond 4 GiB are not supported by the writer"));
        }
        let nb = name.as_bytes();
        let mut lh = crate::binary::ByteWriter::new();
        lh.bytes(b"PK\x03\x04")
            .u16le(20)
            .u16le(0x0800)
            .u16le(0)
            .u16le(0)
            .u16le(0x21)
            .u32le(0)
            .u32le(0)
            .u32le(0)
            .u16le(nb.len() as u16)
            .u16le(0)
            .bytes(nb);
        self.out.write_all(&lh.buf)?;
        let data_start = self.out.stream_position()?;
        let mut crc = crc32fast::Hasher::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut method = 0u16;
        if deflate && size > 0 {
            let mut enc = flate2::write::DeflateEncoder::new(&mut *self.out, flate2::Compression::new(level.min(9)));
            let mut pos = 0u64;
            while pos < size {
                let n = ((size - pos) as usize).min(buf.len());
                data.read_exact_at(pos, &mut buf[..n])?;
                crc.update(&buf[..n]);
                enc.write_all(&buf[..n])?;
                pos += n as u64;
            }
            enc.finish()?;
            method = 8;
        }
        let mut csize = self.out.stream_position()? - data_start;
        if method == 8 && csize >= size {
            // Not worth it: rewrite stored.
            self.out.seek(SeekFrom::Start(data_start))?;
            method = 0;
        }
        if method == 0 {
            crc = crc32fast::Hasher::new();
            let mut pos = 0u64;
            while pos < size {
                let n = ((size - pos) as usize).min(buf.len());
                data.read_exact_at(pos, &mut buf[..n])?;
                crc.update(&buf[..n]);
                self.out.write_all(&buf[..n])?;
                pos += n as u64;
            }
            csize = size;
        }
        let end = data_start + csize;
        let crc = crc.finalize();
        self.out.seek(SeekFrom::Start(start + 8))?;
        let mut fix = crate::binary::ByteWriter::new();
        fix.u16le(method).u16le(0).u16le(0x21).u32le(crc).u32le(csize as u32).u32le(size as u32);
        self.out.write_all(&fix.buf)?;
        self.out.seek(SeekFrom::Start(end))?;
        let mut c = crate::binary::ByteWriter::new();
        c.bytes(b"PK\x01\x02")
            .u16le(20)
            .u16le(20)
            .u16le(0x0800)
            .u16le(method)
            .u16le(0)
            .u16le(0x21)
            .u32le(crc)
            .u32le(csize as u32)
            .u32le(size as u32);
        c.u16le(nb.len() as u16).u16le(0).u16le(0).u16le(0).u16le(0).u32le(0).u32le(start as u32).bytes(nb);
        self.central.extend_from_slice(&c.buf);
        self.count += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<u64> {
        let cd_off = self.out.stream_position()?;
        self.out.write_all(&self.central)?;
        if self.count > 0xFFFF {
            return Err(Error::unsupported("more than 65535 entries are not supported by the writer"));
        }
        let mut e = crate::binary::ByteWriter::new();
        e.bytes(b"PK\x05\x06")
            .u16le(0)
            .u16le(0)
            .u16le(self.count as u16)
            .u16le(self.count as u16)
            .u32le(self.central.len() as u32)
            .u32le(cd_off as u32)
            .u16le(0);
        self.out.write_all(&e.buf)?;
        Ok(self.out.stream_position()?)
    }
}
