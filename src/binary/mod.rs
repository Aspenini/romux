//! Binary parsing (formerly the `romux-binary` crate)
//!
//! Checked binary parsing primitives. All size/offset arithmetic is `u64` with overflow
//! checks; nothing is cast blindly to `usize`. Every failure is a typed
//! [`crate::Error`] carrying the absolute offset where possible.

use crate::{Error, Result};

pub(crate) mod psf;

/// Checked `a + b`.
pub fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| Error::bounds(format!("offset overflow: 0x{a:x} + 0x{b:x}")))
}

/// Checked `a * b`.
pub fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(|| Error::bounds(format!("size overflow: 0x{a:x} * 0x{b:x}")))
}

/// Round `v` up to a multiple of `align` (power of two or not).
pub fn align_up(v: u64, align: u64) -> Result<u64> {
    if align <= 1 {
        return Ok(v);
    }
    let r = v % align;
    if r == 0 { Ok(v) } else { add(v, align - r) }
}

/// Validate a list of spans for overlap. Returns the first overlapping pair index.
pub fn find_overlap(spans: &mut [(u64, u64, usize)]) -> Option<(usize, usize)> {
    spans.sort_by_key(|s| (s.0, s.1));
    for w in spans.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a.1 > 0 && b.1 > 0 && a.0.saturating_add(a.1) > b.0 {
            return Some((a.2, b.2));
        }
    }
    None
}

macro_rules! rd {
    ($name:ident, $t:ty, $n:expr, $conv:ident) => {
        #[inline]
        pub fn $name(buf: &[u8], off: usize) -> Result<$t> {
            let end = off.checked_add($n).ok_or_else(|| Error::bounds("offset overflow"))?;
            let s = buf.get(off..end).ok_or_else(|| {
                Error::bounds(format!("read of {} bytes at 0x{:x} exceeds buffer of 0x{:x}", $n, off, buf.len())).with_offset(off as u64)
            })?;
            let mut a = [0u8; $n];
            a.copy_from_slice(s);
            Ok(<$t>::$conv(a))
        }
    };
}

rd!(u16le, u16, 2, from_le_bytes);
rd!(u16be, u16, 2, from_be_bytes);
rd!(u32le, u32, 4, from_le_bytes);
rd!(u32be, u32, 4, from_be_bytes);
rd!(u64le, u64, 8, from_le_bytes);
rd!(u64be, u64, 8, from_be_bytes);

/// Borrow `len` bytes at `off`.
pub fn slice(buf: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off.checked_add(len).ok_or_else(|| Error::bounds("offset overflow"))?;
    buf.get(off..end)
        .ok_or_else(|| Error::bounds(format!("slice 0x{off:x}+0x{len:x} beyond buffer of 0x{:x}", buf.len())).with_offset(off as u64))
}

/// Copy a fixed array at `off`.
pub fn array<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N]> {
    let s = slice(buf, off, N)?;
    let mut a = [0u8; N];
    a.copy_from_slice(s);
    Ok(a)
}

/// Read a 24-bit or 40/48-bit little-endian integer.
pub fn uint_le(buf: &[u8], off: usize, n: usize) -> Result<u64> {
    let s = slice(buf, off, n)?;
    Ok(s.iter().rev().fold(0u64, |acc, b| (acc << 8) | *b as u64))
}

/// Read a big-endian integer of `n` bytes (n <= 8).
pub fn uint_be(buf: &[u8], off: usize, n: usize) -> Result<u64> {
    let s = slice(buf, off, n)?;
    Ok(s.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
}

/// Decode an ASCII/Latin-1-ish NUL-terminated string (lossy, non-printables replaced).
pub fn ascii_z(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    buf[..end].iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '\u{fffd}' }).collect()
}

/// Decode a UTF-8 NUL-terminated string (lossy).
pub fn utf8_z(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Decode a UTF-16LE string terminated by NUL or the end of the buffer.
pub fn utf16le_z(buf: &[u8]) -> String {
    let units: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|u| *u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// Decode a UTF-16BE string terminated by NUL or the end of the buffer.
pub fn utf16be_z(buf: &[u8]) -> String {
    let units: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).take_while(|u| *u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// Read a NUL-terminated UTF-8 name from a string table, bounded by `max_len`.
pub fn table_string(table: &[u8], off: usize, max_len: usize) -> Result<String> {
    if off >= table.len() {
        return Err(Error::malformed(format!("string offset 0x{off:x} outside table of 0x{:x}", table.len())));
    }
    let rest = &table[off..];
    let end = rest.iter().position(|b| *b == 0).ok_or_else(|| Error::malformed("unterminated string in table"))?;
    if end > max_len {
        return Err(Error::limit(format!("name longer than {max_len} bytes")));
    }
    String::from_utf8(rest[..end].to_vec()).map_err(|_| Error::malformed("name is not valid UTF-8"))
}

/// Growable little/big-endian byte writer with deterministic padding.
#[derive(Default, Clone)]
pub struct ByteWriter {
    pub buf: Vec<u8>,
}

impl ByteWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_capacity(n: usize) -> Self {
        ByteWriter { buf: Vec::with_capacity(n) }
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u16le(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u16be(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32le(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32be(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64le(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64be(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn zeros(&mut self, n: usize) -> &mut Self {
        self.buf.resize(self.buf.len() + n, 0);
        self
    }
    /// Pad with zeros to a multiple of `align`.
    pub fn align(&mut self, align: usize) -> &mut Self {
        if align > 1 {
            let r = self.buf.len() % align;
            if r != 0 {
                self.zeros(align - r);
            }
        }
        self
    }
    /// Pad with zeros to an absolute length.
    pub fn pad_to(&mut self, len: usize) -> &mut Self {
        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }
        self
    }
    /// Fixed-width field: copy `s` truncated/zero-padded to `n` bytes.
    pub fn fixed(&mut self, s: &[u8], n: usize) -> &mut Self {
        let k = s.len().min(n);
        self.buf.extend_from_slice(&s[..k]);
        self.zeros(n - k)
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

/// Little-endian/big-endian helper used by both-endian formats (ISO9660).
pub fn both_endian_u32(buf: &[u8], off: usize) -> Result<u32> {
    let le = u32le(buf, off)?;
    let be = u32be(buf, off + 4)?;
    if le != be {
        return Err(Error::malformed(format!("both-endian field mismatch at 0x{off:x}: {le} vs {be}")));
    }
    Ok(le)
}

/// Encode a both-endian u32.
pub fn put_both_u32(w: &mut ByteWriter, v: u32) {
    w.u32le(v).u32be(v);
}

/// Encode a both-endian u16.
pub fn put_both_u16(w: &mut ByteWriter, v: u16) {
    w.u16le(v).u16be(v);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_math() {
        assert!(add(u64::MAX, 1).is_err());
        assert_eq!(align_up(5, 4).unwrap(), 8);
        assert!(align_up(u64::MAX, 16).is_err());
    }

    #[test]
    fn overlap() {
        let mut s = vec![(0, 10, 0), (5, 2, 1), (20, 1, 2)];
        assert_eq!(find_overlap(&mut s), Some((0, 1)));
    }
}
