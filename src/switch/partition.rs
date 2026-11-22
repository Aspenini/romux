//! Nintendo partition filesystems: PFS0 (packages, ExeFS) and HFS0 (gamecard partitions).
//!
//! Both share a header + entry table + string table layout and differ in entry size and
//! the per-entry SHA-256 of HFS0. One implementation serves both because their semantics
//! match exactly.

use crate::binary::{ByteWriter, table_string, u32le, u64le};
use crate::{DataSource, Error, ResourceLimits, Result, SharedSource, SubSource, read_vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Pfs0,
    Hfs0,
}

impl Kind {
    pub fn magic(&self) -> &'static [u8; 4] {
        match self {
            Kind::Pfs0 => b"PFS0",
            Kind::Hfs0 => b"HFS0",
        }
    }
    pub fn entry_size(&self) -> u64 {
        match self {
            Kind::Pfs0 => 0x18,
            Kind::Hfs0 => 0x40,
        }
    }
}

/// One file entry.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    /// Offset relative to the data region.
    pub offset: u64,
    pub size: u64,
    /// HFS0 only: bytes covered by `hash`.
    pub hashed_region: u32,
    /// HFS0 only.
    pub hash: [u8; 32],
}

/// A parsed partition filesystem.
pub struct PartitionFs {
    pub kind: Kind,
    source: SharedSource,
    /// Size of header + entry table + string table (= data region start).
    pub header_size: u64,
    pub entries: Vec<Entry>,
}

impl PartitionFs {
    pub fn parse(source: SharedSource, kind: Kind, limits: &ResourceLimits) -> Result<Self> {
        let (header_size, entries) = read_table(source.as_ref(), 0, source.len()?, kind, limits)?;
        Ok(PartitionFs { kind, source, header_size, entries })
    }
}

/// Parse and validate a partition table located at `base` inside `source`, where the
/// partition spans `total` bytes from `base`. Returns (header size, entries).
pub fn read_table(source: &dyn DataSource, base: u64, total: u64, kind: Kind, limits: &ResourceLimits) -> Result<(u64, Vec<Entry>)> {
    {
        let h = read_vec(source, base, 0x10, 0x10)?;
        if &h[..4] != kind.magic() {
            return Err(Error::malformed(format!("missing {} magic", String::from_utf8_lossy(kind.magic()))));
        }
        let count = u32le(&h, 4)? as u64;
        let st_size = u32le(&h, 8)? as u64;
        if count > limits.max_entries.min(0x10000) {
            return Err(Error::limit(format!("partition declares {count} entries")));
        }
        let table_len = crate::binary::add(crate::binary::mul(count, kind.entry_size())?, st_size)?;
        let header_size = crate::binary::add(0x10, table_len)?;
        if header_size > total {
            return Err(Error::bounds("partition header exceeds source"));
        }
        let table = read_vec(source, base + 0x10, table_len, limits.max_metadata)?;
        let strings = &table[(count * kind.entry_size()) as usize..];
        let mut entries = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let e = &table[i * kind.entry_size() as usize..];
            let offset = u64le(e, 0)?;
            let size = u64le(e, 8)?;
            let name_off = u32le(e, 16)? as usize;
            let (hashed_region, hash) = match kind {
                Kind::Pfs0 => (0, [0u8; 32]),
                Kind::Hfs0 => (u32le(e, 20)?, crate::binary::array(e, 0x20)?),
            };
            let name = table_string(strings, name_off, limits.max_name_len)?;
            if name.is_empty() {
                return Err(Error::malformed(format!("entry {i} has an empty name")));
            }
            let abs = crate::binary::add(header_size, offset)?;
            if crate::binary::add(abs, size)? > total {
                return Err(Error::bounds(format!("entry {name} extends beyond the partition")).with_offset(abs));
            }
            if kind == Kind::Hfs0 && hashed_region as u64 > size {
                return Err(Error::malformed(format!("entry {name} hashed region exceeds its size")));
            }
            entries.push(Entry { name, offset, size, hashed_region, hash });
        }
        let mut spans: Vec<(u64, u64, usize)> = entries.iter().enumerate().map(|(i, e)| (e.offset, e.size, i)).collect();
        if let Some((a, b)) = crate::binary::find_overlap(&mut spans) {
            return Err(Error::malformed(format!("entries {} and {} overlap", entries[a].name, entries[b].name)));
        }
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        if names.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::malformed("duplicate entry names"));
        }
        Ok((header_size, entries))
    }
}

impl PartitionFs {
    pub fn source(&self) -> &SharedSource {
        &self.source
    }

    /// Absolute offset (within this partition's source) of an entry.
    pub fn abs_offset(&self, i: usize) -> u64 {
        self.header_size + self.entries[i].offset
    }

    pub fn open(&self, i: usize) -> Result<SharedSource> {
        let e = &self.entries[i];
        SubSource::shared(self.source.clone(), self.header_size + e.offset, e.size)
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.name == name)
    }

    /// Raw header bytes (for hashing by a parent HFS0/XCI).
    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        read_vec(self.source.as_ref(), 0, self.header_size, 64 << 20)
    }

    /// Verify HFS0 entry hashes.
    pub fn verify_hashes(&self) -> Result<Vec<(String, bool)>> {
        let mut out = Vec::new();
        if self.kind != Kind::Hfs0 {
            return Ok(out);
        }
        for (i, e) in self.entries.iter().enumerate() {
            let d = read_vec(self.source.as_ref(), self.abs_offset(i), e.hashed_region as u64, 64 << 20)?;
            out.push((e.name.clone(), crate::crypto::sha256(&d) == e.hash));
        }
        Ok(out)
    }
}

/// An entry to be written.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub name: String,
    pub size: u64,
    pub hashed_region: u32,
    pub hash: [u8; 32],
}

/// Layout result: header bytes and per-entry data offsets (relative to data start).
pub struct Layout {
    pub header: Vec<u8>,
    pub offsets: Vec<u64>,
    /// Padding after each entry.
    pub padding: Vec<u64>,
    pub total: u64,
}

/// Build a deterministic header.
///
/// * PFS0: string table padded so the header is a multiple of 0x20; entries packed.
/// * HFS0: header padded to 0x200; each entry aligned to 0x200.
pub fn layout(kind: Kind, entries: &[NewEntry]) -> Result<Layout> {
    let mut strings = Vec::new();
    let mut name_offs = Vec::new();
    for e in entries {
        if e.name.is_empty() || e.name.contains('\0') {
            return Err(Error::invalid_arg("invalid partition entry name"));
        }
        name_offs.push(strings.len() as u32);
        strings.extend_from_slice(e.name.as_bytes());
        strings.push(0);
    }
    let (header_align, entry_align) = match kind {
        Kind::Pfs0 => (0x20u64, 1u64),
        Kind::Hfs0 => (0x200u64, 0x200u64),
    };
    let base = 0x10 + kind.entry_size() * entries.len() as u64;
    let unpadded = base + strings.len() as u64;
    let padded = crate::binary::align_up(unpadded, header_align)?;
    strings.resize(strings.len() + (padded - unpadded) as usize, 0);
    let mut offsets = Vec::new();
    let mut padding = Vec::new();
    let mut cur = 0u64;
    for e in entries {
        offsets.push(cur);
        let end = crate::binary::add(cur, e.size)?;
        let aligned = if entry_align > 1 { crate::binary::align_up(end, entry_align)? } else { end };
        padding.push(aligned - end);
        cur = aligned;
    }
    let mut w = ByteWriter::with_capacity(padded as usize);
    w.bytes(kind.magic()).u32le(entries.len() as u32).u32le(strings.len() as u32).u32le(0);
    for (i, e) in entries.iter().enumerate() {
        w.u64le(offsets[i]).u64le(e.size).u32le(name_offs[i]);
        match kind {
            Kind::Pfs0 => {
                w.u32le(0);
            }
            Kind::Hfs0 => {
                w.u32le(e.hashed_region).u64le(0).bytes(&e.hash);
            }
        }
    }
    w.bytes(&strings);
    Ok(Layout { header: w.into_inner(), offsets, padding, total: padded + cur })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySource;
    use std::sync::Arc;

    fn build(kind: Kind, files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let entries: Vec<NewEntry> = files
            .iter()
            .map(|(n, d)| {
                let hr = d.len().min(0x200) as u32;
                NewEntry { name: n.to_string(), size: d.len() as u64, hashed_region: hr, hash: crate::crypto::sha256(&d[..hr as usize]) }
            })
            .collect();
        let l = layout(kind, &entries).unwrap();
        let mut out = l.header.clone();
        for (i, (_, d)) in files.iter().enumerate() {
            out.extend_from_slice(d);
            out.resize(out.len() + l.padding[i] as usize, 0);
        }
        assert_eq!(out.len() as u64, l.total);
        out
    }

    #[test]
    fn roundtrip_both_kinds() {
        for kind in [Kind::Pfs0, Kind::Hfs0] {
            let files = vec![("a.nca", vec![1u8; 0x300]), ("b.tik", vec![2u8; 0x2c0]), ("c", vec![])];
            let img = build(kind, &files);
            let fs = PartitionFs::parse(Arc::new(MemorySource::new(img)), kind, &ResourceLimits::default()).unwrap();
            assert_eq!(fs.entries.len(), 3);
            for (i, (n, d)) in files.iter().enumerate() {
                assert_eq!(&fs.entries[i].name, n);
                let s = fs.open(i).unwrap();
                assert_eq!(read_vec(s.as_ref(), 0, s.len().unwrap(), 1 << 20).unwrap(), *d);
            }
            assert!(fs.verify_hashes().unwrap().iter().all(|(_, ok)| *ok));
        }
    }

    #[test]
    fn rejects_overlap_and_bounds() {
        let mut img = build(Kind::Pfs0, &[("a", vec![0; 16]), ("b", vec![0; 16])]);
        // make entry b overlap a
        let e1 = 0x10 + 0x18;
        img[e1..e1 + 8].copy_from_slice(&8u64.to_le_bytes());
        assert!(PartitionFs::parse(Arc::new(MemorySource::new(img.clone())), Kind::Pfs0, &ResourceLimits::default()).is_err());
        img[e1 + 8..e1 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(PartitionFs::parse(Arc::new(MemorySource::new(img)), Kind::Pfs0, &ResourceLimits::default()).is_err());
    }
}
