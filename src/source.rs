//! Random-access data sources.
//!
//! Every parser in Romux reads through [`DataSource`], a length-known, positional
//! (cursor-free) reader. There are no global mutable file handles: readers can be shared
//! between threads and sub-ranges can be created cheaply with [`SubSource`].

use crate::error::{Error, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

/// A random-access, length-known source of bytes.
pub trait DataSource: Send + Sync {
    /// Total length in bytes.
    fn len(&self) -> Result<u64>;
    /// Fill `out` completely with bytes starting at `offset`, or fail with `BoundsViolation`.
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()>;
    /// Identity information used for TOCTOU checks and deduplication.
    fn identity(&self) -> SourceIdentity {
        SourceIdentity { path: None, len: self.len().unwrap_or(0), modified_ns: None }
    }
    /// Whether the source is empty.
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Reference-counted, shareable data source.
pub type SharedSource = Arc<dyn DataSource>;

/// Identity of an input, recorded in plans and re-checked before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    pub len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_ns: Option<u128>,
}

/// Check that `[offset, offset+len)` lies inside a source of `total` bytes.
pub fn check_range(offset: u64, len: u64, total: u64) -> Result<()> {
    match offset.checked_add(len) {
        Some(end) if end <= total => Ok(()),
        _ => Err(Error::bounds(format!("range 0x{offset:x}+0x{len:x} exceeds source length 0x{total:x}")).with_offset(offset)),
    }
}

/// A file opened read-only.
pub struct FileSource {
    file: File,
    path: PathBuf,
    len: u64,
    modified_ns: Option<u128>,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|e| Error::from(e).with_file(path.display().to_string()))?;
        let meta = file.metadata()?;
        if meta.is_dir() {
            return Err(Error::invalid_arg("input is a directory, expected a file").with_file(path.display().to_string()));
        }
        let modified_ns = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos());
        Ok(FileSource { file, path: path.to_path_buf(), len: meta.len(), modified_ns })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify that the file on disk still matches the identity captured when opened.
    pub fn verify_unchanged(&self) -> Result<()> {
        let meta = std::fs::metadata(&self.path)?;
        let modified_ns = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos());
        if meta.len() != self.len || modified_ns != self.modified_ns {
            return Err(Error::conflict("input file changed since it was opened").with_file(self.path.display().to_string()));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn pread(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(out, offset)
    }

    #[cfg(windows)]
    fn pread(&self, mut offset: u64, mut out: &mut [u8]) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !out.is_empty() {
            match self.file.seek_read(out, offset) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read")),
                Ok(n) => {
                    out = &mut out[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn pread(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let mut f = &self.file;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(out)
    }
}

impl DataSource for FileSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        check_range(offset, out.len() as u64, self.len)?;
        self.pread(offset, out).map_err(|e| Error::from(e).with_offset(offset).with_file(self.path.display().to_string()))
    }
    fn identity(&self) -> SourceIdentity {
        SourceIdentity { path: Some(self.path.clone()), len: self.len, modified_ns: self.modified_ns }
    }
}

/// An in-memory source.
#[derive(Clone)]
pub struct MemorySource {
    data: Arc<[u8]>,
}

impl MemorySource {
    pub fn new(data: impl Into<Arc<[u8]>>) -> Self {
        MemorySource { data: data.into() }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl DataSource for MemorySource {
    fn len(&self) -> Result<u64> {
        Ok(self.data.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        check_range(offset, out.len() as u64, self.data.len() as u64)?;
        let o = offset as usize;
        out.copy_from_slice(&self.data[o..o + out.len()]);
        Ok(())
    }
}

/// A checked sub-range of another source; offsets are relative to the parent range.
#[derive(Clone)]
pub struct SubSource {
    parent: SharedSource,
    offset: u64,
    len: u64,
}

impl SubSource {
    pub fn new(parent: SharedSource, offset: u64, len: u64) -> Result<Self> {
        check_range(offset, len, parent.len()?)?;
        Ok(SubSource { parent, offset, len })
    }
    pub fn shared(parent: SharedSource, offset: u64, len: u64) -> Result<SharedSource> {
        Ok(Arc::new(Self::new(parent, offset, len)?))
    }
    pub fn parent_offset(&self) -> u64 {
        self.offset
    }
}

impl DataSource for SubSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        check_range(offset, out.len() as u64, self.len)?;
        self.parent.read_exact_at(self.offset + offset, out)
    }
    fn identity(&self) -> SourceIdentity {
        let mut id = self.parent.identity();
        id.len = self.len;
        id
    }
}

/// A source of zero bytes (used for sparse regions and padding).
#[derive(Clone, Copy)]
pub struct ZeroSource(pub u64);

impl DataSource for ZeroSource {
    fn len(&self) -> Result<u64> {
        Ok(self.0)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        check_range(offset, out.len() as u64, self.0)?;
        out.fill(0);
        Ok(())
    }
}

/// Several sources concatenated end to end (split files, sparse layouts).
pub struct ConcatSource {
    parts: Vec<(u64, SharedSource)>,
    len: u64,
}

impl ConcatSource {
    pub fn new(parts: Vec<SharedSource>) -> Result<Self> {
        let mut acc = 0u64;
        let mut v = Vec::with_capacity(parts.len());
        for p in parts {
            let l = p.len()?;
            v.push((acc, p));
            acc = acc.checked_add(l).ok_or_else(|| Error::bounds("concatenated length overflow"))?;
        }
        Ok(ConcatSource { parts: v, len: acc })
    }
}

impl DataSource for ConcatSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        check_range(offset, out.len() as u64, self.len)?;
        let mut idx = match self.parts.binary_search_by(|(s, _)| s.cmp(&offset)) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        while !out.is_empty() {
            let (start, part) = &self.parts[idx];
            let plen = part.len()?;
            let rel = offset - start;
            if rel >= plen {
                idx += 1;
                continue;
            }
            let n = ((plen - rel) as usize).min(out.len());
            part.read_exact_at(rel, &mut out[..n])?;
            out = &mut out[n..];
            offset += n as u64;
            idx += 1;
        }
        Ok(())
    }
    fn identity(&self) -> SourceIdentity {
        match self.parts.first() {
            Some((_, p)) => SourceIdentity { len: self.len, ..p.identity() },
            None => SourceIdentity { path: None, len: 0, modified_ns: None },
        }
    }
}

/// Read a bounded byte vector from a source.
pub fn read_vec(source: &dyn DataSource, offset: u64, len: u64, limit: u64) -> Result<Vec<u8>> {
    if len > limit {
        return Err(Error::limit(format!("requested read of {len} bytes exceeds limit of {limit} bytes")).with_offset(offset));
    }
    check_range(offset, len, source.len()?)?;
    let mut v = vec![0u8; len as usize];
    source.read_exact_at(offset, &mut v)?;
    Ok(v)
}

/// Read a fixed-size array.
pub fn read_array<const N: usize>(source: &dyn DataSource, offset: u64) -> Result<[u8; N]> {
    let mut a = [0u8; N];
    source.read_exact_at(offset, &mut a)?;
    Ok(a)
}

/// Read up to `max` bytes from the start of a source (for probing).
pub fn read_prefix(source: &dyn DataSource, max: u64) -> Result<Vec<u8>> {
    let len = source.len()?.min(max);
    read_vec(source, 0, len, max)
}

/// `std::io::Read + Seek` adapter over a data source with an internal buffer.
pub struct SourceReader {
    source: SharedSource,
    pos: u64,
    len: u64,
    buf: Vec<u8>,
    buf_start: u64,
    buf_len: usize,
}

impl SourceReader {
    pub fn new(source: SharedSource) -> Result<Self> {
        let len = source.len()?;
        Ok(SourceReader { source, pos: 0, len, buf: vec![0; 256 * 1024], buf_start: 0, buf_len: 0 })
    }
}

impl Read for SourceReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || out.is_empty() {
            return Ok(0);
        }
        if self.pos < self.buf_start || self.pos >= self.buf_start + self.buf_len as u64 {
            let n = ((self.len - self.pos) as usize).min(self.buf.len());
            self.source.read_exact_at(self.pos, &mut self.buf[..n]).map_err(|e| io::Error::other(e.to_string()))?;
            self.buf_start = self.pos;
            self.buf_len = n;
        }
        let rel = (self.pos - self.buf_start) as usize;
        let n = (self.buf_len - rel).min(out.len());
        out[..n].copy_from_slice(&self.buf[rel..rel + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SourceReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match new {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek")),
        }
    }
}

/// Open a path as a shared file source.
pub fn open_file(path: impl AsRef<Path>) -> Result<SharedSource> {
    Ok(Arc::new(FileSource::open(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_and_concat() {
        let m: SharedSource = Arc::new(MemorySource::new(b"0123456789".to_vec()));
        let s = SubSource::new(m.clone(), 2, 5).unwrap();
        let mut b = [0u8; 3];
        s.read_exact_at(1, &mut b).unwrap();
        assert_eq!(&b, b"345");
        assert!(s.read_exact_at(4, &mut b).is_err());
        let c = ConcatSource::new(vec![m.clone(), Arc::new(ZeroSource(3)), m]).unwrap();
        assert_eq!(c.len().unwrap(), 23);
        let mut b = [0u8; 6];
        c.read_exact_at(8, &mut b).unwrap();
        assert_eq!(&b, b"89\0\0\x000");
    }

    #[test]
    fn overflow_is_rejected() {
        assert!(check_range(u64::MAX, 2, 10).is_err());
    }
}
