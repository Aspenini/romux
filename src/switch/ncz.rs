//! NCZ: an NCA whose body is stored decrypted and Zstandard-compressed, with the section
//! crypto parameters recorded so the original encrypted NCA can be restored byte for byte.
//!
//! Layout: the first 0x4000 bytes of the original NCA, then `NCZSECTN` + section table,
//! then either one Zstandard stream ("solid") or an `NCZBLOCK` header and independently
//! compressed blocks. Decompression never needs user keys (the section keys are stored);
//! compression does (sections must be decrypted).

use crate::binary::{u32le, u64le};
use crate::crypto::ctr_apply;
use crate::{DataSource, Error, Result, SharedSource, read_vec};
use std::io::Write;
use std::sync::{Arc, Mutex};

pub const NCZ_HEADER_OFFSET: u64 = 0x4000;
pub const SECTION_MAGIC: &[u8; 8] = b"NCZSECTN";
pub const BLOCK_MAGIC: &[u8; 8] = b"NCZBLOCK";

#[derive(Debug, Clone, serde::Serialize)]
pub struct NczSection {
    pub offset: u64,
    pub size: u64,
    pub crypto_type: u64,
    #[serde(skip)]
    pub key: [u8; 16],
    #[serde(skip)]
    pub counter: [u8; 16],
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockInfo {
    pub version: u8,
    pub block_type: u8,
    pub size_exponent: u8,
    pub decompressed_size: u64,
    pub compressed_sizes: Vec<u32>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NczHeader {
    pub sections: Vec<NczSection>,
    pub block: Option<BlockInfo>,
    /// Offset of compressed data in the NCZ file.
    pub data_offset: u64,
    /// Size of the restored NCA.
    pub nca_size: u64,
}

pub fn probe(source: &dyn DataSource) -> bool {
    let mut m = [0u8; 8];
    source.read_exact_at(NCZ_HEADER_OFFSET, &mut m).is_ok() && &m == SECTION_MAGIC
}

impl NczHeader {
    pub fn parse(source: &dyn DataSource) -> Result<Self> {
        let h = read_vec(source, NCZ_HEADER_OFFSET, 16, 16)?;
        if &h[..8] != SECTION_MAGIC {
            return Err(Error::malformed("missing NCZSECTN magic"));
        }
        let count = u64le(&h, 8)?;
        if count == 0 || count > 64 {
            return Err(Error::malformed(format!("NCZ declares {count} sections")));
        }
        let t = read_vec(source, NCZ_HEADER_OFFSET + 16, count * 0x40, 64 * 0x40)?;
        let mut sections = Vec::new();
        for i in 0..count as usize {
            let e = &t[i * 0x40..(i + 1) * 0x40];
            sections.push(NczSection {
                offset: u64le(e, 0)?,
                size: u64le(e, 8)?,
                crypto_type: u64le(e, 16)?,
                key: crate::binary::array(e, 0x20)?,
                counter: crate::binary::array(e, 0x30)?,
            });
        }
        let mut pos = NCZ_HEADER_OFFSET + 16 + count * 0x40;
        let mut block = None;
        let mut m = [0u8; 8];
        if source.read_exact_at(pos, &mut m).is_ok() && &m == BLOCK_MAGIC {
            let b = read_vec(source, pos, 24, 24)?;
            let version = b[8];
            let block_type = b[9];
            let exp = b[11];
            let nblocks = u32le(&b, 12)? as u64;
            let dsize = u64le(&b, 16)?;
            if !(14..=32).contains(&exp) {
                return Err(Error::malformed(format!("NCZ block size exponent {exp} out of range")));
            }
            if nblocks != dsize.div_ceil(1u64 << exp) {
                return Err(Error::malformed("NCZ block count does not match decompressed size"));
            }
            let sizes_raw = read_vec(source, pos + 24, nblocks * 4, 64 << 20)?;
            let compressed_sizes = sizes_raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
            pos += 24 + nblocks * 4;
            block = Some(BlockInfo { version, block_type, size_exponent: exp, decompressed_size: dsize, compressed_sizes });
        }
        let nca_size = match &block {
            Some(b) => NCZ_HEADER_OFFSET + b.decompressed_size,
            None => sections.iter().map(|s| s.offset + s.size).max().unwrap_or(NCZ_HEADER_OFFSET).max(NCZ_HEADER_OFFSET),
        };
        if pos > source.len()? {
            return Err(Error::bounds("NCZ header exceeds file"));
        }
        Ok(NczHeader { sections, block, data_offset: pos, nca_size })
    }

    /// Re-encrypt plaintext `data` that sits at absolute NCA offset `abs`.
    pub fn reencrypt(&self, abs: u64, data: &mut [u8]) {
        let end = abs + data.len() as u64;
        for s in &self.sections {
            if s.crypto_type != 3 && s.crypto_type != 4 {
                continue;
            }
            let a = s.offset.max(abs);
            let b = (s.offset + s.size).min(end);
            if a >= b {
                continue;
            }
            let mut ctr = [0u8; 16];
            ctr[..8].copy_from_slice(&s.counter[..8]);
            ctr_apply(&s.key, ctr, a, &mut data[(a - abs) as usize..(b - abs) as usize]);
        }
    }
}

struct SolidState {
    reader: Option<Box<dyn std::io::Read + Send>>,
    pos: u64,
}

/// Random-access view of the restored (encrypted) NCA.
pub struct NczSource {
    src: SharedSource,
    pub header: NczHeader,
    solid: Mutex<SolidState>,
    block_cache: Mutex<Option<(u64, Arc<Vec<u8>>)>>,
    block_offsets: Vec<u64>,
}

impl NczSource {
    pub fn open(src: SharedSource) -> Result<Self> {
        let header = NczHeader::parse(src.as_ref())?;
        let mut block_offsets = Vec::new();
        if let Some(b) = &header.block {
            let mut o = header.data_offset;
            for s in &b.compressed_sizes {
                block_offsets.push(o);
                o += *s as u64;
            }
            if o > src.len()? {
                return Err(Error::bounds("NCZ blocks exceed file size"));
            }
        }
        Ok(NczSource { src, header, solid: Mutex::new(SolidState { reader: None, pos: 0 }), block_cache: Mutex::new(None), block_offsets })
    }

    fn restart_solid(&self) -> Result<Box<dyn std::io::Read + Send>> {
        #[cfg(feature = "zstd")]
        {
            let len = self.src.len()? - self.header.data_offset;
            let sub: SharedSource = Arc::new(crate::SubSource::new(self.src.clone(), self.header.data_offset, len)?);
            let r = crate::SourceReader::new(sub)?;
            let d = crate::compression::ZstdReader::new(std::io::BufReader::new(r), self.header.nca_size)?;
            Ok(Box::new(d))
        }
        #[cfg(not(feature = "zstd"))]
        Err(Error::unsupported("NCZ decompression requires the `zstd` feature"))
    }

    fn read_plain_solid(&self, rel: u64, out: &mut [u8]) -> Result<()> {
        let mut st = self.solid.lock().map_err(|_| Error::internal("NCZ state poisoned"))?;
        if st.reader.is_none() || st.pos > rel {
            st.reader = Some(self.restart_solid()?);
            st.pos = 0;
        }
        let mut skip = rel - st.pos;
        let mut junk = vec![0u8; 1 << 16];
        let r = st.reader.as_mut().ok_or_else(|| Error::internal("no reader"))?;
        while skip > 0 {
            let n = skip.min(junk.len() as u64) as usize;
            r.read_exact(&mut junk[..n]).map_err(|e| Error::codec(format!("NCZ stream: {e}")))?;
            skip -= n as u64;
        }
        r.read_exact(out).map_err(|e| Error::codec(format!("NCZ stream ended early: {e}")))?;
        st.pos = rel + out.len() as u64;
        Ok(())
    }

    fn block(&self, i: u64) -> Result<Arc<Vec<u8>>> {
        if let Some((bi, d)) = self.block_cache.lock().map_err(|_| Error::internal("poisoned"))?.as_ref() {
            if *bi == i {
                return Ok(d.clone());
            }
        }
        let b = self.header.block.as_ref().ok_or_else(|| Error::internal("not block mode"))?;
        let bs = 1u64 << b.size_exponent;
        let dlen = (b.decompressed_size - i * bs).min(bs) as usize;
        let clen = b.compressed_sizes[i as usize] as u64;
        let raw = read_vec(self.src.as_ref(), self.block_offsets[i as usize], clen, bs + 4096)?;
        let d = if (clen as usize) < dlen {
            crate::compression::decompress(crate::compression::Codec::Zstd, &raw, Some(dlen), dlen)?
        } else {
            raw
        };
        let d = Arc::new(d);
        *self.block_cache.lock().map_err(|_| Error::internal("poisoned"))? = Some((i, d.clone()));
        Ok(d)
    }

    fn read_plain(&self, rel: u64, out: &mut [u8]) -> Result<()> {
        match &self.header.block {
            None => self.read_plain_solid(rel, out),
            Some(b) => {
                let bs = 1u64 << b.size_exponent;
                let mut done = 0usize;
                while done < out.len() {
                    let p = rel + done as u64;
                    let d = self.block(p / bs)?;
                    let within = (p % bs) as usize;
                    let n = (d.len() - within).min(out.len() - done);
                    out[done..done + n].copy_from_slice(&d[within..within + n]);
                    done += n;
                }
                Ok(())
            }
        }
    }
}

impl DataSource for NczSource {
    fn len(&self) -> Result<u64> {
        Ok(self.header.nca_size)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.header.nca_size)?;
        let mut done = 0usize;
        if offset < NCZ_HEADER_OFFSET {
            let n = ((NCZ_HEADER_OFFSET - offset) as usize).min(out.len());
            self.src.read_exact_at(offset, &mut out[..n])?;
            done = n;
        }
        if done < out.len() {
            let abs = offset + done as u64;
            let rest = &mut out[done..];
            self.read_plain(abs - NCZ_HEADER_OFFSET, rest)?;
            self.header.reencrypt(abs, rest);
        }
        Ok(())
    }
}

/// Compression options.
#[derive(Debug, Clone, Copy)]
pub struct CompressOptions {
    pub level: i32,
    /// `Some(exp)` selects block mode with 2^exp-byte blocks (random-access friendly).
    pub block_exponent: Option<u8>,
    /// NCAs smaller than this are stored uncompressed.
    pub min_size: u64,
}

impl Default for CompressOptions {
    fn default() -> Self {
        CompressOptions { level: 18, block_exponent: None, min_size: 1 << 20 }
    }
}

/// Plaintext view of an NCA body: CTR sections decrypted with their base counter,
/// everything else copied raw — exactly the inverse of [`NczHeader::reencrypt`].
#[cfg(feature = "zstd")]
struct PlainBody<'a> {
    nca: &'a crate::switch::nca::Nca,
    sections: Vec<NczSection>,
}

#[cfg(feature = "zstd")]
impl PlainBody<'_> {
    fn read(&self, abs: u64, out: &mut [u8]) -> Result<()> {
        self.nca.source.read_exact_at(abs, out)?;
        let h = NczHeader { sections: self.sections.clone(), block: None, data_offset: 0, nca_size: 0 };
        h.reencrypt(abs, out); // CTR is an involution
        Ok(())
    }
}

/// Section table for compressing `nca` (fails for section types NCZ cannot represent).
#[cfg_attr(not(feature = "zstd"), allow(dead_code))]
pub fn section_table(nca: &crate::switch::nca::Nca) -> Result<Vec<NczSection>> {
    use crate::switch::nca::EncryptionType::*;
    let keys = nca.section_keys().ok_or_else(|| Error::needs_keys("NCA section keys are required to compress"))?;
    let mut v = Vec::new();
    for s in &nca.header.sections {
        let ct = match s.encryption() {
            None => 1,
            AesCtr | AesCtrSkipLayerHash | Auto => 3,
            AesCtrEx | AesCtrExSkipLayerHash => 4,
            other => return Err(Error::unsupported(format!("NCZ cannot represent {other:?} sections"))),
        };
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&s.ctr_upper());
        v.push(NczSection { offset: s.start, size: s.size(), crypto_type: ct, key: if ct == 1 { [0; 16] } else { *keys.ctr }, counter });
    }
    v.sort_by_key(|s| s.offset);
    Ok(v)
}

/// Compress an opened NCA into NCZ form. Returns bytes written.
#[cfg(feature = "zstd")]
pub fn compress(nca: &crate::switch::nca::Nca, out: &mut dyn WriteSeek, opts: CompressOptions, job: &crate::JobContext) -> Result<u64> {
    let sections = section_table(nca)?;
    let total = nca.source.len()?;
    if total < NCZ_HEADER_OFFSET {
        return Err(Error::invalid_arg("NCA too small to compress"));
    }
    let mut written = 0u64;
    let head = read_vec(nca.source.as_ref(), 0, NCZ_HEADER_OFFSET, NCZ_HEADER_OFFSET)?;
    out.write_all(&head)?;
    written += head.len() as u64;
    let mut t = crate::binary::ByteWriter::new();
    t.bytes(SECTION_MAGIC).u64le(sections.len() as u64);
    for s in &sections {
        t.u64le(s.offset).u64le(s.size).u64le(s.crypto_type).u64le(0).bytes(&s.key).bytes(&s.counter);
    }
    out.write_all(&t.buf)?;
    written += t.len() as u64;
    let body = PlainBody { nca, sections };
    let body_len = total - NCZ_HEADER_OFFSET;
    let mut prog = crate::ByteProgress::new(job, crate::Phase::Transforming, Some(body_len));
    match opts.block_exponent {
        None => {
            let mut counter = Counting { inner: out, n: 0 };
            let mut enc = crate::compression::ZstdWriter::new(&mut counter, opts.level, job.threads as u32)?;
            let mut buf = vec![0u8; 1 << 20];
            let mut pos = NCZ_HEADER_OFFSET;
            while pos < total {
                let n = ((total - pos) as usize).min(buf.len());
                body.read(pos, &mut buf[..n])?;
                enc.write_all(&buf[..n])?;
                pos += n as u64;
                prog.advance(n as u64)?;
            }
            enc.finish()?;
            written += counter.n;
        }
        Some(exp) => {
            if !(14..=32).contains(&exp) {
                return Err(Error::invalid_arg("block exponent must be 14..=32"));
            }
            let bs = 1u64 << exp;
            let nblocks = body_len.div_ceil(bs);
            let mut sizes = Vec::with_capacity(nblocks as usize);
            // The sizes table precedes the data: write a placeholder, stream the blocks, then
            // seek back and patch it, so memory stays bounded by one batch of blocks.
            let header_pos = out.stream_position()?;
            let mut bh = crate::binary::ByteWriter::new();
            bh.bytes(BLOCK_MAGIC).u8(2).u8(1).u8(0).u8(exp).u32le(nblocks as u32).u64le(body_len);
            bh.zeros(nblocks as usize * 4);
            out.write_all(&bh.buf)?;
            written += bh.len() as u64;
            // Blocks are compressed in parallel batches; output order is deterministic.
            let batch = job.threads.max(1) as u64;
            let mut b = 0u64;
            while b < nblocks {
                let n = batch.min(nblocks - b);
                let mut plain = Vec::new();
                for k in 0..n {
                    let start = NCZ_HEADER_OFFSET + (b + k) * bs;
                    let len = (total - start).min(bs) as usize;
                    let mut d = vec![0u8; len];
                    body.read(start, &mut d)?;
                    plain.push(d);
                }
                let comp: Vec<Result<Vec<u8>>> = std::thread::scope(|s| {
                    let hs: Vec<_> = plain
                        .iter()
                        .map(|d| s.spawn(move || crate::compression::compress(crate::compression::Codec::Zstd, d, opts.level)))
                        .collect();
                    hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(Error::internal("worker panicked")))).collect()
                });
                for (d, c) in plain.into_iter().zip(comp) {
                    let c = c?;
                    prog.advance(d.len() as u64)?;
                    let blk = if c.len() < d.len() { c } else { d };
                    sizes.push(blk.len() as u32);
                    out.write_all(&blk)?;
                    written += blk.len() as u64;
                }
                b += n;
            }
            let end = out.stream_position()?;
            let mut table = Vec::with_capacity(sizes.len() * 4);
            for s in &sizes {
                table.extend_from_slice(&s.to_le_bytes());
            }
            out.seek(std::io::SeekFrom::Start(header_pos + 24))?;
            out.write_all(&table)?;
            out.seek(std::io::SeekFrom::Start(end))?;
        }
    }
    Ok(written)
}

/// A seekable writer (outputs are staged in seekable temporary files).
pub trait WriteSeek: Write + std::io::Seek {}
impl<T: Write + std::io::Seek + ?Sized> WriteSeek for T {}

#[cfg(feature = "zstd")]
struct Counting<'a> {
    inner: &'a mut dyn WriteSeek,
    n: u64,
}

#[cfg(feature = "zstd")]
impl Write for Counting<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
    use super::*;
    use crate::switch::nca::testkit::*;
    use crate::switch::nca::{ContentType, Nca};
    use crate::{JobContext, MemorySource};

    #[test]
    fn solid_and_block_roundtrip() {
        let keys = TestKeys::sample();
        let kp = keys.provider();
        let pfs = pfs0_image(&[("big", (0..200_000u32).map(|i| (i / 100) as u8).collect())]);
        let raw = build(
            &Spec {
                content_type: ContentType::Program,
                program_id: 0x0100_0000_0000_3000,
                sections: vec![Section::Pfs0(pfs)],
                titlekey: None,
                distribution: 0,
            },
            &keys,
        );
        let nca = Nca::open(Arc::new(MemorySource::new(raw.clone())), &kp, None).unwrap();
        for opts in [
            CompressOptions { level: 3, block_exponent: None, min_size: 0 },
            CompressOptions { level: 3, block_exponent: Some(14), min_size: 0 },
        ] {
            let mut cur = std::io::Cursor::new(Vec::new());
            compress(&nca, &mut cur, opts, &JobContext::default().with_threads(2)).unwrap();
            let out = cur.into_inner();
            assert!(out.len() < raw.len());
            let src: SharedSource = Arc::new(MemorySource::new(out));
            assert!(probe(src.as_ref()));
            let ncz = NczSource::open(src).unwrap();
            assert_eq!(ncz.len().unwrap(), raw.len() as u64);
            let mut back = vec![0u8; raw.len()];
            ncz.read_exact_at(0, &mut back).unwrap();
            assert_eq!(back, raw);
            // random access
            let mut part = vec![0u8; 777];
            ncz.read_exact_at(0x5123, &mut part).unwrap();
            assert_eq!(&part[..], &raw[0x5123..0x5123 + 777]);
        }
    }
}
