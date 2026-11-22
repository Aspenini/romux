//! Package writers: PFS0-based NSP/NSZ and HFS0-based XCI/XCZ assembled from members.
//!
//! Members are streamed in order; headers are written as placeholders and patched once
//! member sizes are known (header sizes depend only on names), so memory stays bounded.

use crate::switch::ncz::WriteSeek;
use crate::switch::partition::{Kind, NewEntry, layout};
use crate::switch::xci::{PAGE, ROOT_HFS0_OFFSET, rom_size_for};
use crate::{ByteProgress, Error, JobContext, Phase, Result, SharedSource, copy_all};
use std::io::SeekFrom;

/// Producer closure for members whose size is only known after writing.
pub type Producer = Box<dyn FnOnce(&mut dyn WriteSeek, &JobContext) -> Result<u64> + Send>;

pub enum MemberData {
    Source(SharedSource),
    Produce(Producer),
}

/// One file to place in a package.
pub struct Member {
    pub name: String,
    pub data: MemberData,
    /// First (up to) 0x200 bytes of the stored member, for HFS0 hashes.
    pub prefix: Vec<u8>,
}

impl Member {
    pub fn from_source(name: &str, src: SharedSource) -> Result<Self> {
        let n = src.len()?.min(0x200);
        let prefix = crate::read_vec(src.as_ref(), 0, n, 0x200)?;
        Ok(Member { name: name.to_string(), data: MemberData::Source(src), prefix })
    }
    pub fn known_size(&self) -> Option<u64> {
        match &self.data {
            MemberData::Source(s) => s.len().ok(),
            MemberData::Produce(_) => None,
        }
    }
}

fn entries_for(members: &[Member], sizes: &[u64]) -> Vec<NewEntry> {
    members
        .iter()
        .zip(sizes)
        .map(|(m, s)| {
            let hr = (*s).min(0x200).min(m.prefix.len() as u64) as u32;
            NewEntry { name: m.name.clone(), size: *s, hashed_region: hr, hash: crate::crypto::sha256(&m.prefix[..hr as usize]) }
        })
        .collect()
}

fn check_names(members: &[Member]) -> Result<()> {
    let mut names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
    names.sort_unstable();
    for w in names.windows(2) {
        if w[0] == w[1] {
            return Err(Error::conflict(format!("duplicate member name {}", w[0])));
        }
    }
    Ok(())
}

/// Write a partition (PFS0 or HFS0) at the current position. Returns (header, total size).
pub fn write_partition(
    kind: Kind,
    out: &mut dyn WriteSeek,
    members: Vec<Member>,
    job: &JobContext,
    progress: &mut ByteProgress<'_>,
) -> Result<(Vec<u8>, u64)> {
    check_names(&members)?;
    let start = out.stream_position()?;
    let placeholder = layout(kind, &entries_for(&members, &vec![0; members.len()]))?;
    out.write_all(&placeholder.header)?;
    let mut sizes = Vec::with_capacity(members.len());
    let mut prefixes = Vec::with_capacity(members.len());
    let mut names = Vec::with_capacity(members.len());
    for m in members {
        job.check_cancel()?;
        let size = match m.data {
            MemberData::Source(s) => {
                copy_all(s.as_ref(), out, progress)?;
                s.len()?
            }
            MemberData::Produce(f) => f(out, job)?,
        };
        if kind == Kind::Hfs0 {
            let pad = (PAGE - size % PAGE) % PAGE;
            crate::copy::write_zeros(out, pad)?;
        }
        sizes.push(size);
        prefixes.push(m.prefix);
        names.push(m.name);
    }
    let end = out.stream_position()?;
    let fake: Vec<Member> = names
        .into_iter()
        .zip(prefixes)
        .map(|(name, prefix)| Member { name, data: MemberData::Produce(Box::new(|_, _| Ok(0))), prefix })
        .collect();
    let real = layout(kind, &entries_for(&fake, &sizes))?;
    if real.header.len() != placeholder.header.len() {
        return Err(Error::internal("partition header size changed after writing"));
    }
    if start + real.total != end {
        return Err(Error::internal(format!("partition layout mismatch: expected {} bytes, wrote {}", real.total, end - start)));
    }
    out.seek(SeekFrom::Start(start))?;
    out.write_all(&real.header)?;
    out.seek(SeekFrom::Start(end))?;
    Ok((real.header, real.total))
}

/// Write an NSP/NSZ (PFS0) package.
pub fn write_nsp(out: &mut dyn WriteSeek, members: Vec<Member>, job: &JobContext) -> Result<u64> {
    let total: u64 = members.iter().filter_map(|m| m.known_size()).sum();
    let mut p = ByteProgress::new(job, Phase::Writing, Some(total));
    out.seek(SeekFrom::Start(0))?;
    let (_, size) = write_partition(Kind::Pfs0, out, members, job, &mut p)?;
    Ok(size)
}

/// Write an XCI/XCZ image. `partitions` are written in order (conventionally
/// `update`, `normal`, `secure`); the secure partition must be present.
pub fn write_xci(out: &mut dyn WriteSeek, partitions: Vec<(String, Vec<Member>)>, job: &JobContext) -> Result<u64> {
    if !partitions.iter().any(|(n, _)| n == "secure") {
        return Err(Error::invalid_arg("an XCI requires a secure partition"));
    }
    let total: u64 = partitions.iter().flat_map(|(_, m)| m.iter()).filter_map(|m| m.known_size()).sum();
    let mut p = ByteProgress::new(job, Phase::Writing, Some(total));
    out.seek(SeekFrom::Start(0))?;
    let mut pre = vec![0u8; ROOT_HFS0_OFFSET as usize];
    pre[0x7000..0x7200].fill(0xFF); // certificate area is not reproducible
    out.write_all(&pre)?;
    let root_placeholder: Vec<NewEntry> =
        partitions.iter().map(|(n, _)| NewEntry { name: n.clone(), size: 0, hashed_region: 0, hash: [0; 32] }).collect();
    let root_layout = layout(Kind::Hfs0, &root_placeholder)?;
    out.write_all(&root_layout.header)?;
    let data_start = ROOT_HFS0_OFFSET + root_layout.header.len() as u64;
    let mut root_entries = Vec::new();
    let mut secure_abs = 0u64;
    for (name, members) in partitions {
        let abs = out.stream_position()?;
        if name == "secure" {
            secure_abs = abs;
        }
        let (hdr, size) = write_partition(Kind::Hfs0, out, members, job, &mut p)?;
        root_entries.push((name, abs - data_start, size, hdr));
    }
    let end = out.stream_position()?;
    // Root header with real offsets, sizes and partition-header hashes.
    let mut w = crate::binary::ByteWriter::new();
    let mut strings = Vec::new();
    let mut name_offs = Vec::new();
    for (n, ..) in &root_entries {
        name_offs.push(strings.len() as u32);
        strings.extend_from_slice(n.as_bytes());
        strings.push(0);
    }
    let unpadded = 0x10 + 0x40 * root_entries.len() + strings.len();
    let padded = crate::binary::align_up(unpadded as u64, PAGE)? as usize;
    strings.resize(strings.len() + padded - unpadded, 0);
    w.bytes(b"HFS0").u32le(root_entries.len() as u32).u32le(strings.len() as u32).u32le(0);
    for (i, (_, off, size, hdr)) in root_entries.iter().enumerate() {
        w.u64le(*off).u64le(*size).u32le(name_offs[i]).u32le(hdr.len() as u32).u64le(0).bytes(&crate::crypto::sha256(hdr));
    }
    w.bytes(&strings);
    let root_hdr = w.into_inner();
    if root_hdr.len() != root_layout.header.len() {
        return Err(Error::internal("root header size changed"));
    }
    out.seek(SeekFrom::Start(ROOT_HFS0_OFFSET))?;
    out.write_all(&root_hdr)?;
    // Card header (unsigned; signature and encrypted area left zero).
    let mut h = vec![0u8; 0x200];
    h[0x100..0x104].copy_from_slice(b"HEAD");
    let secure_page = (secure_abs / PAGE) as u32;
    h[0x104..0x108].copy_from_slice(&secure_page.to_le_bytes());
    h[0x108..0x10C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    h[0x10D] = rom_size_for(end);
    let pkg = crate::crypto::sha256(&root_hdr);
    h[0x110..0x118].copy_from_slice(&pkg[..8]);
    h[0x118..0x120].copy_from_slice(&((end / PAGE).saturating_sub(1)).to_le_bytes());
    h[0x130..0x138].copy_from_slice(&ROOT_HFS0_OFFSET.to_le_bytes());
    h[0x138..0x140].copy_from_slice(&(root_hdr.len() as u64).to_le_bytes());
    h[0x140..0x160].copy_from_slice(&crate::crypto::sha256(&root_hdr));
    h[0x180..0x184].copy_from_slice(&1u32.to_le_bytes());
    h[0x184..0x188].copy_from_slice(&2u32.to_le_bytes());
    h[0x18C..0x190].copy_from_slice(&secure_page.saturating_sub(1).to_le_bytes());
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&h)?;
    out.seek(SeekFrom::Start(end))?;
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::switch::xci::Xci;
    use crate::{MemorySource, ResourceLimits};
    use std::io::Cursor;
    use std::sync::Arc;

    #[test]
    fn xci_roundtrip_hashes() {
        let mut c = Cursor::new(Vec::new());
        let a: SharedSource = Arc::new(MemorySource::new(vec![1u8; 0x900]));
        let b: SharedSource = Arc::new(MemorySource::new(vec![2u8; 0x123]));
        let produced = Member {
            name: "p.ncz".into(),
            data: MemberData::Produce(Box::new(|w, _| {
                w.write_all(&[9u8; 1000])?;
                Ok(1000)
            })),
            prefix: vec![9u8; 0x200],
        };
        write_xci(
            &mut c,
            vec![
                ("update".into(), vec![]),
                ("normal".into(), vec![]),
                ("secure".into(), vec![Member::from_source("a.nca", a).unwrap(), produced, Member::from_source("b.nca", b).unwrap()]),
            ],
            &JobContext::default(),
        )
        .unwrap();
        let x = Xci::open(Arc::new(MemorySource::new(c.into_inner())), &ResourceLimits::default()).unwrap();
        assert!(x.warnings.is_empty(), "{:?}", x.warnings);
        let s = x.partition("secure").unwrap();
        assert_eq!(s.entries.len(), 3);
        assert_eq!(s.entries[1].size, 1000);
        assert!(x.verify_hashes().unwrap().iter().all(|(_, ok)| *ok));
    }
}
