//! Compression (formerly the `romux-compression` crate)
//!
//! Codec abstraction with bounded output (decompression-bomb protection) and streaming
//! adapters. Heavy codecs are feature-gated: `zstd` and `lzma`. Deflate/zlib are always
//! available through a pure-Rust backend.

use crate::{Error, ErrorCode, Result};
use std::io::{self, Read, Write};

/// Codecs known to Romux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Codec {
    /// Stored / no compression.
    Store,
    /// Raw DEFLATE (RFC 1951).
    Deflate,
    /// zlib-wrapped DEFLATE (RFC 1950).
    Zlib,
    /// Zstandard frames.
    Zstd,
    /// Raw LZMA1 stream (no header) with explicit properties.
    Lzma { lc: u8, lp: u8, pb: u8, dict_size: u32 },
    /// Raw LZMA2 chunk stream.
    Lzma2,
}

impl Codec {
    pub fn name(&self) -> &'static str {
        match self {
            Codec::Store => "store",
            Codec::Deflate => "deflate",
            Codec::Zlib => "zlib",
            Codec::Zstd => "zstd",
            Codec::Lzma { .. } => "lzma",
            Codec::Lzma2 => "lzma2",
        }
    }
    /// Whether decoding support is compiled in.
    pub fn can_decode(&self) -> bool {
        match self {
            Codec::Store | Codec::Deflate | Codec::Zlib => true,
            Codec::Zstd => cfg!(feature = "zstd"),
            Codec::Lzma { .. } | Codec::Lzma2 => cfg!(feature = "lzma"),
        }
    }
    /// Whether encoding support is compiled in (LZMA encoding is not offered).
    pub fn can_encode(&self) -> bool {
        match self {
            Codec::Store | Codec::Deflate | Codec::Zlib => true,
            Codec::Zstd => cfg!(feature = "zstd"),
            Codec::Lzma { .. } | Codec::Lzma2 => false,
        }
    }
}

/// Names of compiled codecs (decode).
pub fn available_codecs() -> Vec<&'static str> {
    let mut v = vec!["store", "deflate", "zlib"];
    if cfg!(feature = "zstd") {
        v.push("zstd");
    }
    if cfg!(feature = "lzma") {
        v.push("lzma");
        v.push("lzma2");
    }
    v
}

#[allow(dead_code)]
fn missing(c: Codec) -> Error {
    Error::unsupported(format!("codec {} is not compiled into this build", c.name()))
        .with_suggestion("rebuild with the corresponding romux compression feature")
}

/// A writer that refuses to grow beyond a limit.
#[allow(dead_code)]
struct LimitedVec {
    v: Vec<u8>,
    limit: usize,
}

impl Write for LimitedVec {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.v.len() + buf.len() > self.limit {
            return Err(io::Error::other("decompressed output exceeds limit"));
        }
        self.v.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_bounded(mut r: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).map_err(|e| Error::codec(format!("decode failed: {e}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > limit {
            return Err(Error::limit(format!("decompressed output exceeds limit of {limit} bytes")));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Decompress `input` fully, refusing to produce more than `limit` bytes. When
/// `expected` is given, the output length must match exactly.
pub fn decompress(codec: Codec, input: &[u8], expected: Option<usize>, limit: usize) -> Result<Vec<u8>> {
    let limit = expected.map(|e| e.min(limit)).unwrap_or(limit);
    if let Some(e) = expected {
        if e > limit {
            return Err(Error::limit("expected output exceeds limit"));
        }
    }
    let out = match codec {
        Codec::Store => {
            if input.len() > limit {
                return Err(Error::limit("stored data exceeds limit"));
            }
            input.to_vec()
        }
        Codec::Deflate => read_bounded(flate2::read::DeflateDecoder::new(input), limit)?,
        Codec::Zlib => read_bounded(flate2::read::ZlibDecoder::new(input), limit)?,
        Codec::Zstd => {
            #[cfg(feature = "zstd")]
            {
                let d = zstd::stream::read::Decoder::new(input).map_err(|e| Error::codec(e.to_string()))?;
                read_bounded(d, limit)?
            }
            #[cfg(not(feature = "zstd"))]
            return Err(missing(codec));
        }
        Codec::Lzma { lc, lp, pb, dict_size } => {
            #[cfg(feature = "lzma")]
            {
                if lc > 8 || lp > 4 || pb > 4 {
                    return Err(Error::codec("invalid LZMA properties"));
                }
                let props = (pb as u32 * 5 + lp as u32) * 9 + lc as u32;
                let mut hdr = Vec::with_capacity(13 + input.len());
                hdr.push(props as u8);
                hdr.extend_from_slice(&dict_size.max(4096).to_le_bytes());
                let unpacked = expected.map(|e| e as u64).unwrap_or(u64::MAX);
                hdr.extend_from_slice(&unpacked.to_le_bytes());
                hdr.extend_from_slice(input);
                let mut out = LimitedVec { v: Vec::new(), limit };
                let mut rd = io::BufReader::new(&hdr[..]);
                lzma_rs::lzma_decompress_with_options(
                    &mut rd,
                    &mut out,
                    &lzma_rs::decompress::Options { memlimit: Some(limit.max(1 << 16)), ..Default::default() },
                )
                .map_err(|e| Error::codec(format!("lzma: {e:?}")))?;
                out.v
            }
            #[cfg(not(feature = "lzma"))]
            {
                let _ = (lc, lp, pb, dict_size);
                return Err(missing(codec));
            }
        }
        Codec::Lzma2 => {
            #[cfg(feature = "lzma")]
            {
                let mut out = LimitedVec { v: Vec::new(), limit };
                let mut rd = io::BufReader::new(input);
                lzma_rs::lzma2_decompress(&mut rd, &mut out).map_err(|e| Error::codec(format!("lzma2: {e:?}")))?;
                out.v
            }
            #[cfg(not(feature = "lzma"))]
            return Err(missing(codec));
        }
    };
    if let Some(e) = expected {
        if out.len() != e {
            return Err(Error::new(ErrorCode::CodecFailure, format!("decompressed {} bytes, expected {e}", out.len())));
        }
    }
    Ok(out)
}

/// Decompress into a caller-provided buffer that must be filled exactly.
pub fn decompress_into(codec: Codec, input: &[u8], out: &mut [u8]) -> Result<()> {
    let v = decompress(codec, input, Some(out.len()), out.len())?;
    out.copy_from_slice(&v);
    Ok(())
}

/// Compress a buffer. `level` is codec specific (deflate 0-9, zstd 1-22).
pub fn compress(codec: Codec, input: &[u8], level: i32) -> Result<Vec<u8>> {
    match codec {
        Codec::Store => Ok(input.to_vec()),
        Codec::Deflate => {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(level.clamp(0, 9) as u32));
            e.write_all(input)?;
            Ok(e.finish()?)
        }
        Codec::Zlib => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(level.clamp(0, 9) as u32));
            e.write_all(input)?;
            Ok(e.finish()?)
        }
        Codec::Zstd => {
            #[cfg(feature = "zstd")]
            {
                zstd::bulk::compress(input, level).map_err(|e| Error::codec(e.to_string()))
            }
            #[cfg(not(feature = "zstd"))]
            {
                let _ = level;
                Err(missing(codec))
            }
        }
        Codec::Lzma { .. } | Codec::Lzma2 => Err(Error::unsupported("LZMA encoding is not provided; use zstd or zlib")),
    }
}

/// A streaming Zstandard encoder writing into `W`.
#[cfg(feature = "zstd")]
pub struct ZstdWriter<W: Write> {
    inner: zstd::stream::write::Encoder<'static, W>,
}

#[cfg(feature = "zstd")]
impl<W: Write> ZstdWriter<W> {
    pub fn new(w: W, level: i32, threads: u32) -> Result<Self> {
        // Output is deterministic: libzstd is built single-threaded here, so `threads` is
        // accepted for API stability but chunk-level parallelism happens in callers.
        let _ = threads;
        let inner = zstd::stream::write::Encoder::new(w, level).map_err(|e| Error::codec(e.to_string()))?;
        Ok(ZstdWriter { inner })
    }
    pub fn finish(self) -> Result<W> {
        self.inner.finish().map_err(|e| Error::codec(e.to_string()))
    }
}

#[cfg(feature = "zstd")]
impl<W: Write> Write for ZstdWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A streaming Zstandard decoder with an output byte limit.
#[cfg(feature = "zstd")]
pub struct ZstdReader<R: io::BufRead> {
    inner: zstd::stream::read::Decoder<'static, R>,
    produced: u64,
    limit: u64,
}

#[cfg(feature = "zstd")]
impl<R: io::BufRead> ZstdReader<R> {
    pub fn new(r: R, limit: u64) -> Result<Self> {
        let inner = zstd::stream::read::Decoder::with_buffer(r).map_err(|e| Error::codec(e.to_string()))?;
        Ok(ZstdReader { inner, produced: 0, limit })
    }
}

#[cfg(feature = "zstd")]
impl<R: io::BufRead> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.produced += n as u64;
        if self.produced > self.limit {
            return Err(io::Error::other("zstd output exceeds limit"));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        for c in [Codec::Deflate, Codec::Zlib] {
            let z = compress(c, &data, 6).unwrap();
            assert_eq!(decompress(c, &z, Some(data.len()), 1 << 20).unwrap(), data);
        }
        #[cfg(feature = "zstd")]
        {
            let z = compress(Codec::Zstd, &data, 3).unwrap();
            assert_eq!(decompress(Codec::Zstd, &z, None, 1 << 20).unwrap(), data);
        }
    }

    #[test]
    fn bomb_limit() {
        let data = vec![0u8; 1 << 20];
        let z = compress(Codec::Zlib, &data, 9).unwrap();
        assert!(decompress(Codec::Zlib, &z, None, 1000).is_err());
    }
}
