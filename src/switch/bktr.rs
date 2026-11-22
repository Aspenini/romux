//! BKTR bucket trees and indirect (patch) storage used by Switch title updates.
//!
//! A patch RomFS section is a *virtual* storage: an indirect table maps virtual ranges
//! either to the base title's section (storage 0) or to the patch section (storage 1),
//! and an AES-CTR-EX table assigns counter generations to ranges of the patch section.

use crate::binary::{u32le, u64le};
use crate::{DataSource, Error, Result, SharedSource};

pub const NODE_SIZE: usize = 0x4000;

/// Parse a bucket tree (header node + entry-set nodes) into raw entry slices.
pub fn parse_bucket_tree(table: &[u8], entry_size: usize, expected: u64) -> Result<Vec<&[u8]>> {
    if table.len() < NODE_SIZE {
        return Err(Error::malformed("bucket tree shorter than one node"));
    }
    let bucket_count = u32le(table, 4)? as usize;
    if bucket_count == 0 || (1 + bucket_count) * NODE_SIZE > table.len() {
        return Err(Error::malformed(format!("bucket tree declares {bucket_count} buckets beyond its table")));
    }
    let per_bucket = (NODE_SIZE - 0x10) / entry_size;
    let mut out = Vec::new();
    for b in 0..bucket_count {
        let node = &table[(1 + b) * NODE_SIZE..(2 + b) * NODE_SIZE];
        let n = u32le(node, 4)? as usize;
        if n > per_bucket {
            return Err(Error::malformed("bucket entry count exceeds node capacity"));
        }
        for i in 0..n {
            out.push(&node[0x10 + i * entry_size..0x10 + (i + 1) * entry_size]);
        }
    }
    if expected != 0 && out.len() as u64 != expected {
        return Err(Error::malformed(format!("bucket tree has {} entries, header declares {expected}", out.len())));
    }
    Ok(out)
}

/// Build a bucket tree (used by the tests; documents the layout).
#[cfg(test)]
pub fn build_bucket_tree(entries: &[Vec<u8>], entry_size: usize, end_offset: u64, first_offset: impl Fn(&[u8]) -> u64) -> Vec<u8> {
    let per_bucket = (NODE_SIZE - 0x10) / entry_size;
    let buckets: Vec<&[Vec<u8>]> = entries.chunks(per_bucket.max(1)).collect();
    let mut out = vec![0u8; NODE_SIZE * (1 + buckets.len())];
    out[4..8].copy_from_slice(&(buckets.len() as u32).to_le_bytes());
    out[8..16].copy_from_slice(&end_offset.to_le_bytes());
    for (b, chunk) in buckets.iter().enumerate() {
        let off = first_offset(&chunk[0]);
        out[0x10 + b * 8..0x18 + b * 8].copy_from_slice(&off.to_le_bytes());
        let node = &mut out[(1 + b) * NODE_SIZE..(2 + b) * NODE_SIZE];
        node[0..4].copy_from_slice(&(b as u32).to_le_bytes());
        node[4..8].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        let end = if b + 1 < buckets.len() { first_offset(&buckets[b + 1][0]) } else { end_offset };
        node[8..16].copy_from_slice(&end.to_le_bytes());
        for (i, e) in chunk.iter().enumerate() {
            node[0x10 + i * entry_size..0x10 + i * entry_size + e.len()].copy_from_slice(e);
        }
    }
    out
}

/// One indirect mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectEntry {
    pub virtual_offset: u64,
    pub physical_offset: u64,
    /// 0 = base storage, 1 = patch storage.
    pub storage: u32,
}

pub fn parse_indirect(table: &[u8], expected: u64) -> Result<Vec<IndirectEntry>> {
    let raw = parse_bucket_tree(table, 0x14, expected)?;
    let mut v = Vec::with_capacity(raw.len());
    for e in raw {
        let storage = u32le(e, 0x10)?;
        if storage > 1 {
            return Err(Error::malformed(format!("indirect entry references storage {storage}")));
        }
        v.push(IndirectEntry { virtual_offset: u64le(e, 0)?, physical_offset: u64le(e, 8)?, storage });
    }
    if v.windows(2).any(|w| w[1].virtual_offset <= w[0].virtual_offset) {
        return Err(Error::malformed("indirect entries are not strictly increasing"));
    }
    Ok(v)
}

/// The virtual patched storage.
pub struct IndirectSource {
    base: SharedSource,
    patch: SharedSource,
    entries: Vec<IndirectEntry>,
    len: u64,
}

impl IndirectSource {
    pub fn new(base: SharedSource, patch: SharedSource, entries: Vec<IndirectEntry>, len: u64) -> Result<Self> {
        if entries.first().map(|e| e.virtual_offset) != Some(0) {
            return Err(Error::malformed("indirect table must start at virtual offset 0"));
        }
        Ok(IndirectSource { base, patch, entries, len })
    }
    /// Bytes of the virtual range [off, off+len) served from the patch storage.
    pub fn patched_bytes_in(&self, off: u64, len: u64) -> u64 {
        let end = off + len;
        let mut total = 0;
        for (i, e) in self.entries.iter().enumerate() {
            let e_end = self.entries.get(i + 1).map(|n| n.virtual_offset).unwrap_or(self.len);
            if e.storage == 1 {
                let s = e.virtual_offset.max(off);
                let t = e_end.min(end);
                if t > s {
                    total += t - s;
                }
            }
        }
        total
    }
}

impl DataSource for IndirectSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        let mut done = 0usize;
        while done < out.len() {
            let v = offset + done as u64;
            let idx = match self.entries.binary_search_by(|e| e.virtual_offset.cmp(&v)) {
                Ok(i) => i,
                Err(i) => i - 1,
            };
            let e = self.entries[idx];
            let end = self.entries.get(idx + 1).map(|n| n.virtual_offset).unwrap_or(self.len);
            let n = ((end - v) as usize).min(out.len() - done);
            let phys = e.physical_offset + (v - e.virtual_offset);
            let src = if e.storage == 0 { &self.base } else { &self.patch };
            src.read_exact_at(phys, &mut out[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySource;
    use std::sync::Arc;

    fn ent(v: u64, p: u64, s: u32) -> Vec<u8> {
        let mut e = vec![0u8; 0x14];
        e[0..8].copy_from_slice(&v.to_le_bytes());
        e[8..16].copy_from_slice(&p.to_le_bytes());
        e[16..20].copy_from_slice(&s.to_le_bytes());
        e
    }

    #[test]
    fn indirect_mapping() {
        let base: SharedSource = Arc::new(MemorySource::new(b"AAAAAAAAAABBBBBBBBBB".to_vec()));
        let patch: SharedSource = Arc::new(MemorySource::new(b"xyz".to_vec()));
        let entries = vec![ent(0, 0, 0), ent(5, 0, 1), ent(8, 8, 0)];
        let table = build_bucket_tree(&entries, 0x14, 20, |e| u64::from_le_bytes(e[0..8].try_into().unwrap()));
        let parsed = parse_indirect(&table, 3).unwrap();
        let s = IndirectSource::new(base, patch, parsed, 20).unwrap();
        let mut out = vec![0u8; 20];
        s.read_exact_at(0, &mut out).unwrap();
        assert_eq!(&out, b"AAAAAxyzAABBBBBBBBBB");
        assert_eq!(s.patched_bytes_in(0, 20), 3);
        assert_eq!(s.patched_bytes_in(6, 1), 1);
    }
}
