//! CSO (CISO v1): block index + raw-deflate blocks. Bit 31 of an index entry marks a
//! stored (uncompressed) block; offsets are shifted by `align`.

use crate::binary::{u32le, u64le};
use crate::compression::{Codec, compress as zcompress, decompress};
use crate::{ByteProgress, DataSource, Error, JobContext, Phase, Result, SharedSource, read_vec};
use std::io::Write;
use std::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CsoHeader {
    pub header_size: u32,
    pub total_bytes: u64,
    pub block_size: u32,
    pub version: u8,
    pub align: u8,
}

impl CsoHeader {
    pub fn blocks(&self) -> u64 {
        self.total_bytes.div_ceil(self.block_size as u64)
    }
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h = read_vec(s, 0, 0x18, 0x18)?;
        if &h[..4] != b"CISO" {
            return Err(Error::malformed("missing CISO magic"));
        }
        let hdr =
            CsoHeader { header_size: u32le(&h, 4)?, total_bytes: u64le(&h, 8)?, block_size: u32le(&h, 16)?, version: h[20], align: h[21] };
        if hdr.version > 1 {
            return Err(Error::unsupported(format!("CSO version {} (LZ4/CSOv2) is not supported", hdr.version)));
        }
        if hdr.block_size == 0 || hdr.block_size > 1 << 20 || hdr.align > 16 {
            return Err(Error::malformed("implausible CSO block size or alignment"));
        }
        Ok(hdr)
    }
}

/// Decompressed view of a CSO.
pub struct CsoSource {
    src: SharedSource,
    pub header: CsoHeader,
    index: Vec<u32>,
    cache: Mutex<Option<(u64, Vec<u8>)>>,
}

impl CsoSource {
    pub fn open(src: SharedSource) -> Result<Self> {
        let header = CsoHeader::parse(src.as_ref())?;
        let n = header.blocks() + 1;
        if n > 1 << 28 {
            return Err(Error::limit("CSO index too large"));
        }
        let raw = read_vec(src.as_ref(), 0x18, n * 4, 1 << 30)?;
        let index: Vec<u32> = raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        let len = src.len()?;
        for w in index.windows(2) {
            let a = ((w[0] & 0x7FFF_FFFF) as u64) << header.align;
            let b = ((w[1] & 0x7FFF_FFFF) as u64) << header.align;
            if b < a || b > len {
                return Err(Error::malformed("CSO index is not monotonic or exceeds the file"));
            }
        }
        Ok(CsoSource { src, header, index, cache: Mutex::new(None) })
    }

    fn block(&self, i: u64) -> Result<Vec<u8>> {
        if let Some((bi, d)) = self.cache.lock().map_err(|_| Error::internal("poisoned"))?.as_ref() {
            if *bi == i {
                return Ok(d.clone());
            }
        }
        let bs = self.header.block_size as usize;
        let e = self.index[i as usize];
        let start = ((e & 0x7FFF_FFFF) as u64) << self.header.align;
        let end = ((self.index[i as usize + 1] & 0x7FFF_FFFF) as u64) << self.header.align;
        let want = ((self.header.total_bytes - i * bs as u64).min(bs as u64)) as usize;
        let raw = read_vec(self.src.as_ref(), start, end - start, bs as u64 * 2 + 1024)?;
        let d = if e & 0x8000_0000 != 0 {
            if raw.len() < want {
                return Err(Error::bounds(format!("stored CSO block {i} is short")));
            }
            raw[..want].to_vec()
        } else {
            let mut d = decompress(Codec::Deflate, &raw, None, bs).map_err(|e| e.with_offset(start))?;
            if d.len() < want {
                return Err(Error::codec(format!("CSO block {i} decoded to {} bytes, expected {want}", d.len())));
            }
            d.truncate(want);
            d
        };
        *self.cache.lock().map_err(|_| Error::internal("poisoned"))? = Some((i, d.clone()));
        Ok(d)
    }

    /// Decode every block (content verification).
    pub fn verify_all(&self, job: &JobContext) -> Result<()> {
        let mut p = ByteProgress::new(job, Phase::Verifying, Some(self.header.total_bytes));
        for i in 0..self.header.blocks() {
            let d = self.block(i)?;
            p.advance(d.len() as u64)?;
        }
        Ok(())
    }
}

impl DataSource for CsoSource {
    fn len(&self) -> Result<u64> {
        Ok(self.header.total_bytes)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.header.total_bytes)?;
        let bs = self.header.block_size as u64;
        while !out.is_empty() {
            let b = self.block(offset / bs)?;
            let within = (offset % bs) as usize;
            let n = (b.len() - within).min(out.len());
            out[..n].copy_from_slice(&b[within..within + n]);
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

/// Compress an image to CSO v1 (block size 2048; index alignment chosen to fit). Blocks that do not shrink
/// are stored. Compression is parallelised in batches; output is deterministic.
///
/// The index precedes the data and `out` is not seekable, so blocks are compressed twice
/// (a sizing pass, then a writing pass); memory stays bounded by one batch.
pub fn compress(src: &dyn DataSource, out: &mut dyn Write, level: u32, job: &JobContext) -> Result<u64> {
    let total = src.len()?;
    let bs = 2048u64;
    let blocks = total.div_ceil(bs);
    let batch = (job.threads.max(1) * 64) as u64;
    let mut sizes: Vec<(u32, bool)> = Vec::with_capacity(blocks as usize);
    let mut b = 0u64;
    while b < blocks {
        job.check_cancel()?;
        let n = batch.min(blocks - b);
        for (c, stored) in compress_batch(src, b, n, total, level)? {
            sizes.push((c.len() as u32, stored));
        }
        b += n;
    }
    // Index entries hold 31-bit offsets shifted by `align`; pick the smallest alignment that
    // makes every block start (and the end marker) representable.
    let index_end = 0x18 + (blocks + 1) * 4;
    let layout = |align: u8| -> Option<Vec<u64>> {
        let a = 1u64 << align;
        let mut pos = crate::binary::align_up(index_end, a).ok()?;
        let mut starts = Vec::with_capacity(sizes.len() + 1);
        for (s, _) in &sizes {
            if pos >> align > 0x7FFF_FFFF {
                return None;
            }
            starts.push(pos);
            pos = crate::binary::align_up(pos + *s as u64, a).ok()?;
        }
        if pos >> align > 0x7FFF_FFFF {
            return None;
        }
        starts.push(pos);
        Some(starts)
    };
    let (align, starts) =
        (0u8..=12).find_map(|a| layout(a).map(|s| (a, s))).ok_or_else(|| Error::unsupported("image too large for CSO v1"))?;
    let mut index = Vec::with_capacity(blocks as usize + 1);
    for (i, (_, stored)) in sizes.iter().enumerate() {
        index.push(((starts[i] >> align) as u32) | if *stored { 0x8000_0000 } else { 0 });
    }
    index.push((starts[sizes.len()] >> align) as u32);
    let mut header = crate::binary::ByteWriter::new();
    header.bytes(b"CISO").u32le(0x18).u64le(total).u32le(bs as u32).u8(1).u8(align).u16le(0);
    out.write_all(&header.buf)?;
    for e in &index {
        out.write_all(&e.to_le_bytes())?;
    }
    let mut written = index_end;
    let mut p = ByteProgress::new(job, Phase::Writing, Some(total));
    let mut b = 0u64;
    while b < blocks {
        job.check_cancel()?;
        let n = batch.min(blocks - b);
        for (k, (c, _)) in compress_batch(src, b, n, total, level)?.into_iter().enumerate() {
            let i = b as usize + k;
            if c.len() as u32 != sizes[i].0 {
                return Err(Error::internal("non-deterministic block compression"));
            }
            crate::copy::write_zeros(out, starts[i] - written)?;
            out.write_all(&c)?;
            written = starts[i] + c.len() as u64;
            p.advance(bs)?;
        }
        b += n;
    }
    crate::copy::write_zeros(out, starts[sizes.len()] - written)?;
    Ok(starts[sizes.len()])
}

fn compress_batch(src: &dyn DataSource, first: u64, n: u64, total: u64, level: u32) -> Result<Vec<(Vec<u8>, bool)>> {
    let bs = 2048u64;
    let mut plain = Vec::with_capacity(n as usize);
    for k in 0..n {
        let off = (first + k) * bs;
        let len = (total - off).min(bs) as usize;
        let mut d = vec![0u8; len];
        src.read_exact_at(off, &mut d)?;
        plain.push(d);
    }
    let comp: Vec<Result<Vec<u8>>> = std::thread::scope(|s| {
        let hs: Vec<_> = plain
            .chunks(16)
            .map(|chunk| s.spawn(move || chunk.iter().map(|d| zcompress(Codec::Deflate, d, level as i32)).collect::<Vec<_>>()))
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_else(|_| vec![Err(Error::internal("worker panicked"))])).collect()
    });
    plain
        .into_iter()
        .zip(comp)
        .map(|(d, c)| {
            let c = c?;
            Ok(if c.len() < d.len() { (c, false) } else { (d, true) })
        })
        .collect()
}
