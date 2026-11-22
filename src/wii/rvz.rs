//! WIA and RVZ compressed disc images.
//!
//! Reading: full restoration of GameCube and Wii images (all RVZ codecs Romux can decode,
//! RVZ junk-data packing via the lagged Fibonacci generator). Wii partitions are stored
//! decrypted; restoration regenerates the H0-H2 hash blocks, applies hash exceptions and
//! re-encrypts with the stored title key.
//!
//! Writing: GameCube images ([`write_rvz_gc`]) and Wii images ([`write_rvz_wii`], which
//! needs the common key to decrypt partition title keys), with Zstandard groups and
//! junk packing (see [`crate::wii::junk`]). Both are verified by read-back in the conversion plan.

use crate::binary::{ByteWriter, u32be, u64be};
use crate::compression::{Codec, decompress};
use crate::{ByteProgress, DataSource, Error, JobContext, Phase, Result, SharedSource, read_vec};
use std::io::{Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

pub const WIA_MAGIC: &[u8; 4] = b"WIA\x01";
pub const RVZ_MAGIC: &[u8; 4] = b"RVZ\x01";
pub const BLOCK: u64 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Compression {
    None,
    Purge,
    Bzip2,
    Lzma,
    Lzma2,
    Zstd,
}

impl Compression {
    fn from_u32(v: u32) -> Result<Self> {
        Ok(match v {
            0 => Compression::None,
            1 => Compression::Purge,
            2 => Compression::Bzip2,
            3 => Compression::Lzma,
            4 => Compression::Lzma2,
            5 => Compression::Zstd,
            _ => return Err(Error::malformed(format!("unknown WIA compression type {v}"))),
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WiaHeader {
    pub rvz: bool,
    pub version: u32,
    pub iso_size: u64,
    pub file_size: u64,
    pub disc_type: u32,
    pub compression: Compression,
    pub compression_level: i32,
    pub chunk_size: u32,
    #[serde(skip)]
    pub disc_header: Vec<u8>,
    pub partitions: u32,
    part_entry_size: u32,
    part_off: u64,
    pub raw_data_entries: u32,
    pub group_entries: u32,
    #[serde(skip)]
    compressor_data: Vec<u8>,
    raw_off: u64,
    raw_size: u32,
    group_off: u64,
    group_size: u32,
}

#[derive(Debug, Clone, Copy)]
struct RawEntry {
    offset: u64,
    size: u64,
    group_index: u32,
    groups: u32,
}

#[derive(Debug, Clone, Copy)]
struct Group {
    offset: u64,
    size: u32,
    compressed: bool,
    packed_size: u32,
}

pub fn probe(s: &dyn DataSource) -> Option<bool> {
    let mut m = [0u8; 4];
    s.read_exact_at(0, &mut m).ok()?;
    if &m == RVZ_MAGIC {
        Some(true)
    } else if &m == WIA_MAGIC {
        Some(false)
    } else {
        None
    }
}

impl WiaHeader {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h1 = read_vec(s, 0, 0x48, 0x48)?;
        let rvz = match &h1[..4] {
            m if m == RVZ_MAGIC => true,
            m if m == WIA_MAGIC => false,
            _ => return Err(Error::malformed("missing WIA/RVZ magic")),
        };
        if crate::crypto::sha1(&h1[..0x34])[..] != h1[0x34..0x48] {
            return Err(Error::integrity("WIA header 1 SHA-1 mismatch"));
        }
        let h2_size = u32be(&h1, 0x0C)? as u64;
        if !(0xDC..=0x1000).contains(&h2_size) {
            return Err(Error::malformed("WIA header 2 size implausible"));
        }
        let h2 = read_vec(s, 0x48, h2_size, 0x1000)?;
        if crate::crypto::sha1(&h2)[..] != h1[0x10..0x24] {
            return Err(Error::integrity("WIA header 2 SHA-1 mismatch"));
        }
        let cds = (h2[0xD4] as usize).min(7);
        Ok(WiaHeader {
            rvz,
            version: u32be(&h1, 4)?,
            iso_size: u64be(&h1, 0x24)?,
            file_size: u64be(&h1, 0x2C)?,
            disc_type: u32be(&h2, 0)?,
            compression: Compression::from_u32(u32be(&h2, 4)?)?,
            compression_level: u32be(&h2, 8)? as i32,
            chunk_size: u32be(&h2, 0x0C)?,
            disc_header: h2[0x10..0x90].to_vec(),
            partitions: u32be(&h2, 0x90)?,
            part_entry_size: u32be(&h2, 0x94)?,
            part_off: u64be(&h2, 0x98)?,
            raw_data_entries: u32be(&h2, 0xB4)?,
            raw_off: u64be(&h2, 0xB8)?,
            raw_size: u32be(&h2, 0xC0)?,
            group_entries: u32be(&h2, 0xC4)?,
            group_off: u64be(&h2, 0xC8)?,
            group_size: u32be(&h2, 0xD0)?,
            compressor_data: h2[0xD5..0xD5 + cds].to_vec(),
        })
    }
    pub fn is_wii(&self) -> bool {
        self.disc_type == 2
    }

    fn codec(&self) -> Result<Option<Codec>> {
        Ok(match self.compression {
            Compression::None => None,
            Compression::Zstd => Some(Codec::Zstd),
            Compression::Lzma => {
                let d = &self.compressor_data;
                if d.len() < 5 {
                    return Err(Error::malformed("LZMA properties missing"));
                }
                let p = d[0];
                Some(Codec::Lzma { lc: p % 9, lp: (p / 9) % 5, pb: p / 45, dict_size: u32::from_le_bytes([d[1], d[2], d[3], d[4]]) })
            }
            Compression::Lzma2 => Some(Codec::Lzma2),
            Compression::Bzip2 | Compression::Purge => {
                return Err(Error::unsupported(format!("{:?} compression is not supported", self.compression)));
            }
        })
    }

    fn decode_table(&self, s: &dyn DataSource, off: u64, size: u32, out_len: usize) -> Result<Vec<u8>> {
        let raw = read_vec(s, off, size as u64, 1 << 28)?;
        match self.codec()? {
            None => Ok(raw),
            Some(c) => decompress(c, &raw, Some(out_len), out_len),
        }
    }
}

/// Lagged Fibonacci generator used by RVZ to reproduce Nintendo's pseudo-random padding.
pub struct Lfg {
    buf: [u32; 521],
    pos: usize,
}

impl Lfg {
    const K: usize = 521;
    const J: usize = 32;

    pub fn new(seed: &[u8; 68]) -> Self {
        let mut buf = [0u32; 521];
        for (i, b) in buf.iter_mut().take(17).enumerate() {
            *b = u32::from_be_bytes([seed[i * 4], seed[i * 4 + 1], seed[i * 4 + 2], seed[i * 4 + 3]]);
        }
        for i in 17..Self::K {
            buf[i] = (buf[i - 17] << 23) ^ (buf[i - 16] >> 9) ^ buf[i - 1];
        }
        for x in buf.iter_mut() {
            *x = (*x & 0xFF00_FFFF) | ((*x >> 2) & 0x00FF_0000);
        }
        let mut l = Lfg { buf, pos: 0 };
        for _ in 0..4 {
            l.forward_block();
        }
        l
    }

    fn forward_block(&mut self) {
        for i in 0..Self::J {
            self.buf[i] ^= self.buf[i + Self::K - Self::J];
        }
        for i in Self::J..Self::K {
            self.buf[i] ^= self.buf[i - Self::J];
        }
    }

    pub fn skip(&mut self, mut n: usize) {
        n += self.pos;
        while n >= Self::K * 4 {
            self.forward_block();
            n -= Self::K * 4;
        }
        self.pos = n;
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let word = self.buf[self.pos / 4].to_be_bytes();
            out[i] = word[self.pos % 4];
            i += 1;
            self.pos += 1;
            if self.pos == Self::K * 4 {
                self.forward_block();
                self.pos = 0;
            }
        }
    }
}

/// Restored GameCube disc view.
pub struct WiaSource {
    src: SharedSource,
    pub header: WiaHeader,
    raws: Vec<RawEntry>,
    groups: Vec<Group>,
    pub parts: Vec<PartEntry>,
    cache: Mutex<Option<(u32, Vec<u8>)>>,
    pgroup_cache: Mutex<Option<(u32, Arc<DecodedGroup>)>>,
    hgroup_cache: Mutex<Option<((usize, u64), Arc<Vec<u8>>)>>,
}

impl WiaSource {
    pub fn open(src: SharedSource) -> Result<Self> {
        let header = WiaHeader::parse(src.as_ref())?;
        if header.chunk_size == 0 || header.chunk_size > 1 << 27 {
            return Err(Error::malformed("implausible chunk size"));
        }
        let rn = header.raw_data_entries as usize;
        let gn = header.group_entries as usize;
        if rn > 1 << 16 || gn > 1 << 24 {
            return Err(Error::limit("WIA tables too large"));
        }
        let rt = header.decode_table(src.as_ref(), header.raw_off, header.raw_size, rn * 0x18)?;
        let gsz = if header.rvz { 0x0C } else { 0x08 };
        let gt = header.decode_table(src.as_ref(), header.group_off, header.group_size, gn * gsz)?;
        let mut raws = Vec::with_capacity(rn);
        for i in 0..rn {
            let e = &rt[i * 0x18..];
            raws.push(RawEntry { offset: u64be(e, 0)?, size: u64be(e, 8)?, group_index: u32be(e, 16)?, groups: u32be(e, 20)? });
        }
        let len = src.len()?;
        let mut groups = Vec::with_capacity(gn);
        for i in 0..gn {
            let e = &gt[i * gsz..];
            let ds = u32be(e, 4)?;
            let g = if header.rvz {
                Group {
                    offset: (u32be(e, 0)? as u64) << 2,
                    size: ds & 0x7FFF_FFFF,
                    compressed: ds & 0x8000_0000 != 0,
                    packed_size: u32be(e, 8)?,
                }
            } else {
                Group { offset: (u32be(e, 0)? as u64) << 2, size: ds, compressed: header.compression != Compression::None, packed_size: 0 }
            };
            if g.offset + g.size as u64 > len {
                return Err(Error::bounds(format!("group {i} exceeds the file")));
            }
            groups.push(g);
        }
        for r in &raws {
            if r.group_index as usize + r.groups as usize > groups.len() {
                return Err(Error::malformed("raw data entry references missing groups"));
            }
        }
        let parts = read_partition_entries(src.as_ref(), &header, groups.len())?;
        Ok(WiaSource {
            src,
            header,
            raws,
            groups,
            parts,
            cache: Mutex::new(None),
            pgroup_cache: Mutex::new(None),
            hgroup_cache: Mutex::new(None),
        })
    }

    fn group_data(&self, gi: u32, group_disc_offset: u64, out_len: usize) -> Result<Vec<u8>> {
        if let Some((g, d)) = self.cache.lock().map_err(|_| Error::internal("poisoned"))?.as_ref() {
            if *g == gi {
                return Ok(d.clone());
            }
        }
        let g = self.groups[gi as usize];
        let d = if g.size == 0 {
            vec![0u8; out_len]
        } else {
            let raw = read_vec(self.src.as_ref(), g.offset, g.size as u64, 1 << 28)?;
            let plain = if g.compressed {
                let c = self.header.codec()?.ok_or_else(|| Error::malformed("compressed group without a codec"))?;
                let want = if g.packed_size != 0 { g.packed_size as usize } else { out_len };
                decompress(c, &raw, Some(want), want)?
            } else {
                raw
            };
            if g.packed_size != 0 {
                unpack(&plain, group_disc_offset, out_len)?
            } else {
                if plain.len() < out_len {
                    return Err(Error::codec(format!("group {gi} holds {} bytes, expected {out_len}", plain.len())));
                }
                plain[..out_len].to_vec()
            }
        };
        *self.cache.lock().map_err(|_| Error::internal("poisoned"))? = Some((gi, d.clone()));
        Ok(d)
    }
}

/// Expand RVZ-packed data (literal runs and LFG junk runs).
pub(crate) fn unpack(packed: &[u8], disc_offset: u64, out_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(out_len);
    let mut p = 0usize;
    while out.len() < out_len {
        let sz = u32be(packed, p)?;
        p += 4;
        let n = (sz & 0x7FFF_FFFF) as usize;
        if out.len() + n > out_len {
            return Err(Error::codec("RVZ packed run exceeds the group"));
        }
        if sz & 0x8000_0000 != 0 {
            let seed: [u8; 68] = crate::binary::array(packed, p)?;
            p += 68;
            let mut lfg = Lfg::new(&seed);
            lfg.skip(((disc_offset + out.len() as u64) % BLOCK) as usize);
            let start = out.len();
            out.resize(start + n, 0);
            lfg.fill(&mut out[start..]);
        } else {
            out.extend_from_slice(crate::binary::slice(packed, p, n)?);
            p += n;
        }
    }
    Ok(out)
}

impl DataSource for WiaSource {
    fn len(&self) -> Result<u64> {
        Ok(self.header.iso_size)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.header.iso_size)?;
        let cs = self.header.chunk_size as u64;
        while !out.is_empty() {
            if offset < 0x80 {
                let n = ((0x80 - offset) as usize).min(out.len());
                out[..n].copy_from_slice(&self.header.disc_header[offset as usize..offset as usize + n]);
                out = &mut out[n..];
                offset += n as u64;
                continue;
            }
            if let Some((part, rel)) = self.partition_at(offset) {
                let hg = rel / HASH_GROUP;
                let d = self.encrypted_hash_group(part, hg)?;
                let within = ((rel - hg * HASH_GROUP) * SECTOR + offset % SECTOR) as usize;
                let n = (d.len() - within).min(out.len());
                out[..n].copy_from_slice(&d[within..within + n]);
                out = &mut out[n..];
                offset += n as u64;
                continue;
            }
            let r = self.raws.iter().find(|r| {
                let start = r.offset - r.offset % BLOCK;
                offset >= start && offset < r.offset + r.size
            });
            let r = match r {
                Some(r) => *r,
                None => {
                    // Outside any raw entry: zero (not stored).
                    out[0] = 0;
                    out = &mut out[1..];
                    offset += 1;
                    continue;
                }
            };
            let start = r.offset - r.offset % BLOCK;
            let end = r.offset + r.size;
            let gi_rel = (offset - start) / cs;
            let gstart = start + gi_rel * cs;
            let glen = (end - gstart).min(cs) as usize;
            let d = self.group_data(r.group_index + gi_rel as u32, gstart, glen)?;
            let within = (offset - gstart) as usize;
            let n = (glen - within).min(out.len());
            out[..n].copy_from_slice(&d[within..within + n]);
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------
// Wii partitions
// ------------------------------------------------------------------------------------------

/// Encrypted disc sector, payload per sector, and sectors per hash group.
const SECTOR: u64 = 0x8000;
const PAYLOAD: u64 = 0x7C00;
const HASH_GROUP: u64 = 64;

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PartData {
    pub first_sector: u32,
    pub sectors: u32,
    group_index: u32,
    groups: u32,
}

/// One Wii partition as stored in WIA/RVZ: its (decrypted) title key and two data ranges.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PartEntry {
    #[serde(skip)]
    pub key: [u8; 16],
    pub data: [PartData; 2],
}

impl PartEntry {
    fn first(&self) -> u64 {
        self.data[0].first_sector as u64
    }
    /// Total sectors of partition data.
    pub fn sectors(&self) -> u64 {
        self.data[0].sectors as u64 + self.data[1].sectors as u64
    }
    /// Absolute disc offset of the partition data.
    pub fn data_offset(&self) -> u64 {
        self.first() * SECTOR
    }
}

/// Decompressed partition group: decrypted payload and hash exceptions.
pub struct DecodedGroup {
    data: Vec<u8>,
    /// (sector index within the group, offset in the 0x400-byte hash block, hash)
    exceptions: Vec<(u64, usize, [u8; 20])>,
}

fn read_partition_entries(src: &dyn DataSource, h: &WiaHeader, groups: usize) -> Result<Vec<PartEntry>> {
    if h.partitions == 0 {
        return Ok(Vec::new());
    }
    if h.partitions > 64 || h.part_entry_size < 0x30 {
        return Err(Error::malformed("implausible WIA partition table"));
    }
    let raw = read_vec(src, h.part_off, h.partitions as u64 * h.part_entry_size as u64, 64 * 0x100)?;
    let mut v = Vec::new();
    for i in 0..h.partitions as usize {
        let e = &raw[i * h.part_entry_size as usize..];
        let d = |o: usize| -> Result<PartData> {
            Ok(PartData { first_sector: u32be(e, o)?, sectors: u32be(e, o + 4)?, group_index: u32be(e, o + 8)?, groups: u32be(e, o + 12)? })
        };
        let p = PartEntry { key: crate::binary::array(e, 0)?, data: [d(0x10)?, d(0x20)?] };
        for pd in &p.data {
            if pd.group_index as usize + pd.groups as usize > groups {
                return Err(Error::malformed("partition data references missing groups"));
            }
        }
        v.push(p);
    }
    Ok(v)
}

impl WiaSource {
    fn sectors_per_group(&self) -> u64 {
        (self.header.chunk_size as u64 / SECTOR).max(1)
    }

    /// Decompress a partition group holding `n` sectors whose decrypted payload starts at
    /// `data_offset` (offset within the partition's decrypted data).
    fn partition_group(&self, gi: u32, n: u64, data_offset: u64) -> Result<Arc<DecodedGroup>> {
        if let Some((g, d)) = self.pgroup_cache.lock().map_err(|_| Error::internal("poisoned"))?.as_ref() {
            if *g == gi {
                return Ok(d.clone());
            }
        }
        let g = self.groups[gi as usize];
        let data_len = (n * PAYLOAD) as usize;
        let decoded = if g.size == 0 {
            DecodedGroup { data: vec![0u8; data_len], exceptions: vec![] }
        } else {
            let raw = read_vec(self.src.as_ref(), g.offset, g.size as u64, 1 << 28)?;
            let plain = if g.compressed {
                let c = self.header.codec()?.ok_or_else(|| Error::malformed("compressed group without a codec"))?;
                decompress(c, &raw, None, data_len + (n as usize / 64 + 1) * 0x20000)?
            } else {
                raw
            };
            let lists = (n / HASH_GROUP).max(1);
            let mut p = 0usize;
            let mut exceptions = Vec::new();
            for k in 0..lists {
                let count = crate::binary::u16be(&plain, p)? as usize;
                p += 2;
                for _ in 0..count {
                    let off = crate::binary::u16be(&plain, p)? as u64;
                    let hash: [u8; 20] = crate::binary::array(&plain, p + 2)?;
                    exceptions.push((k * HASH_GROUP + off / 0x400, (off % 0x400) as usize, hash));
                    p += 22;
                }
            }
            if !g.compressed {
                p = p.div_ceil(4) * 4;
            }
            let body = plain.get(p..).ok_or_else(|| Error::codec("group shorter than its exception lists"))?;
            let data = if g.packed_size != 0 {
                unpack(body, data_offset, data_len)?
            } else {
                if body.len() < data_len {
                    return Err(Error::codec(format!("partition group {gi} holds {} bytes, expected {data_len}", body.len())));
                }
                body[..data_len].to_vec()
            };
            DecodedGroup { data, exceptions }
        };
        let d = Arc::new(decoded);
        *self.pgroup_cache.lock().map_err(|_| Error::internal("poisoned"))? = Some((gi, d.clone()));
        Ok(d)
    }

    /// Decrypted payload and exceptions of partition sector `rel` (relative to the
    /// partition data start).
    fn plain_sector(&self, part: usize, rel: u64) -> Result<(Vec<u8>, Vec<(usize, [u8; 20])>)> {
        let p = &self.parts[part];
        let base = p.first();
        for pd in &p.data {
            let start = pd.first_sector as u64 - base;
            if rel < start || rel >= start + pd.sectors as u64 {
                continue;
            }
            let spg = self.sectors_per_group();
            let s = rel - start;
            let g = s / spg;
            let n = (pd.sectors as u64 - g * spg).min(spg);
            let group_rel = start + g * spg;
            let dg = self.partition_group(pd.group_index + g as u32, n, group_rel * PAYLOAD)?;
            let within = s - g * spg;
            let o = (within * PAYLOAD) as usize;
            let ex = dg.exceptions.iter().filter(|e| e.0 == within).map(|e| (e.1, e.2)).collect();
            return Ok((dg.data[o..o + PAYLOAD as usize].to_vec(), ex));
        }
        Err(Error::bounds("partition sector outside its data entries"))
    }

    /// Regenerate the hash blocks of one 64-sector hash group (exceptions applied).
    fn hash_blocks(&self, part: usize, hg: u64) -> Result<(Vec<Vec<u8>>, Vec<[u8; 0x400]>)> {
        let total = self.parts[part].sectors();
        let first = hg * HASH_GROUP;
        let m = (total - first).min(HASH_GROUP) as usize;
        let mut data = Vec::with_capacity(m);
        let mut exc = Vec::with_capacity(m);
        for s in 0..m as u64 {
            let (d, e) = self.plain_sector(part, first + s)?;
            data.push(d);
            exc.push(e);
        }
        let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let mut blocks = regen_hash_blocks(&refs);
        for (s, hb) in blocks.iter_mut().enumerate() {
            for (off, hash) in &exc[s] {
                if off + 20 <= 0x400 {
                    hb[*off..off + 20].copy_from_slice(hash);
                }
            }
        }
        Ok((data, blocks))
    }

    /// Encrypted sectors of a hash group (cached).
    fn encrypted_hash_group(&self, part: usize, hg: u64) -> Result<Arc<Vec<u8>>> {
        if let Some((k, d)) = self.hgroup_cache.lock().map_err(|_| Error::internal("poisoned"))?.as_ref() {
            if *k == (part, hg) {
                return Ok(d.clone());
            }
        }
        let (data, blocks) = self.hash_blocks(part, hg)?;
        let key = self.parts[part].key;
        let mut out = Vec::with_capacity(data.len() * SECTOR as usize);
        for (d, hb) in data.iter().zip(&blocks) {
            let mut h = hb.to_vec();
            crate::crypto::cbc_encrypt(&key, &[0u8; 16], &mut h)?;
            let iv: [u8; 16] = crate::binary::array(&h, 0x3D0)?;
            let mut p = d.clone();
            crate::crypto::cbc_encrypt(&key, &iv, &mut p)?;
            out.extend_from_slice(&h);
            out.extend_from_slice(&p);
        }
        let out = Arc::new(out);
        *self.hgroup_cache.lock().map_err(|_| Error::internal("poisoned"))? = Some(((part, hg), out.clone()));
        Ok(out)
    }

    /// If `offset` lies in partition data, return (partition, sector relative to its data).
    fn partition_at(&self, offset: u64) -> Option<(usize, u64)> {
        let sector = offset / SECTOR;
        self.parts.iter().enumerate().find_map(|(i, p)| {
            let start = p.first();
            if sector >= start && sector < start + p.sectors() { Some((i, sector - start)) } else { None }
        })
    }

    /// H3 entries recomputed from the regenerated hash tree, compared with `h3` (the table
    /// stored in the partition header). Returns (hash groups, mismatches).
    pub fn verify_partition(&self, part: usize, h3: &[u8], job: &JobContext) -> Result<(u64, u64)> {
        let groups = self.parts[part].sectors().div_ceil(HASH_GROUP);
        let mut bad = 0;
        let mut p = ByteProgress::new(job, Phase::Verifying, Some(groups));
        for hg in 0..groups {
            let (_, blocks) = self.hash_blocks(part, hg)?;
            let want = h3.get(hg as usize * 20..hg as usize * 20 + 20);
            if want != Some(&crate::crypto::sha1(&blocks[0][0x340..0x3E0])[..]) {
                bad += 1;
            }
            p.advance(1)?;
        }
        Ok((groups, bad))
    }
}

/// Decrypted partition data (0x7C00 payload bytes per sector) read straight from WIA/RVZ.
pub struct PlainPartition {
    src: Arc<WiaSource>,
    part: usize,
    len: u64,
}

impl PlainPartition {
    pub fn new(src: Arc<WiaSource>, part: usize) -> Self {
        let len = src.parts[part].sectors() * PAYLOAD;
        PlainPartition { src, part, len }
    }
}

impl DataSource for PlainPartition {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        while !out.is_empty() {
            let s = offset / PAYLOAD;
            let within = (offset % PAYLOAD) as usize;
            let (d, _) = self.src.plain_sector(self.part, s)?;
            let n = (PAYLOAD as usize - within).min(out.len());
            out[..n].copy_from_slice(&d[within..within + n]);
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

/// Encode a GameCube image as RVZ (zstd groups, junk packed). Returns file size.
pub fn write_rvz_gc<W: Write + Seek>(src: &dyn DataSource, out: &mut W, level: i32, chunk: u32, job: &JobContext) -> Result<u64> {
    if !Codec::Zstd.can_encode() {
        return Err(Error::unsupported("RVZ writing requires zstd"));
    }
    let iso_size = src.len()?;
    let mut dh = vec![0u8; 0x80];
    src.read_exact_at(0, &mut dh)?;
    if u32be(&dh, 0x1C)? != crate::wii::disc::GC_MAGIC {
        return Err(Error::invalid_arg("RVZ writing supports GameCube images only"));
    }
    if !chunk.is_power_of_two() || chunk < 0x8000 {
        return Err(Error::invalid_arg("chunk size must be a power of two >= 32 KiB"));
    }
    let cs = chunk as u64;
    let raw_off = 0x80u64;
    let raw_size = iso_size - raw_off;
    let groups = iso_size.div_ceil(cs);
    let h1_len = 0x48u64;
    let h2_len = 0xDCu64;
    // Tables are written after the group data so their compressed sizes are known.
    out.seek(SeekFrom::Start(h1_len + h2_len))?;
    let mut pos = h1_len + h2_len;
    let mut entries = Vec::with_capacity(groups as usize);
    let mut p = ByteProgress::new(job, Phase::Transforming, Some(iso_size));
    for g in 0..groups {
        job.check_cancel()?;
        let off = g * cs;
        let n = (iso_size - off).min(cs) as usize;
        match encode_raw_group(src, off, n as u64, level)? {
            None => entries.push((0u32, 0u32, 0u32)),
            Some((data, compressed, packed)) => {
                pos = crate::binary::align_up(pos, 4)?;
                out.seek(SeekFrom::Start(pos))?;
                out.write_all(&data)?;
                entries.push(((pos >> 2) as u32, data.len() as u32 | if compressed { 0x8000_0000 } else { 0 }, packed));
                pos += data.len() as u64;
            }
        }
        p.advance(n as u64)?;
    }
    let mut gt = ByteWriter::new();
    for (o, s, packed) in &entries {
        gt.u32be(*o).u32be(*s).u32be(*packed);
    }
    let mut rt = ByteWriter::new();
    rt.u64be(raw_off).u64be(raw_size).u32be(0).u32be(groups as u32);
    let gtc = crate::compression::compress(Codec::Zstd, &gt.buf, level)?;
    let rtc = crate::compression::compress(Codec::Zstd, &rt.buf, level)?;
    pos = crate::binary::align_up(pos, 4)?;
    let raw_tbl_off = pos;
    out.seek(SeekFrom::Start(pos))?;
    out.write_all(&rtc)?;
    pos += rtc.len() as u64;
    let grp_tbl_off = pos;
    out.write_all(&gtc)?;
    pos += gtc.len() as u64;
    let file_size = pos;
    let mut h2 = ByteWriter::new();
    h2.u32be(1).u32be(5).u32be(level as u32).u32be(chunk).bytes(&dh).u32be(0).u32be(0x30).u64be(0).bytes(&crate::crypto::sha1(&[]));
    h2.u32be(1).u64be(raw_tbl_off).u32be(rtc.len() as u32).u32be(groups as u32).u64be(grp_tbl_off).u32be(gtc.len() as u32).u8(0).zeros(7);
    let mut h1 = ByteWriter::new();
    h1.bytes(RVZ_MAGIC)
        .u32be(0x0100_0000)
        .u32be(0x0003_0000)
        .u32be(h2.len() as u32)
        .bytes(&crate::crypto::sha1(&h2.buf))
        .u64be(iso_size)
        .u64be(file_size);
    let h1hash = crate::crypto::sha1(&h1.buf);
    h1.bytes(&h1hash);
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&h1.buf)?;
    out.write_all(&h2.buf)?;
    out.seek(SeekFrom::Start(file_size))?;
    Ok(file_size)
}

/// Regenerate the H0/H1/H2 hash blocks of one hash group from its decrypted sector
/// payloads (up to 64). A partial final group is hashed as if its missing sectors held
/// zero-filled data (confirmed against real discs: the stored H3 entry only matches this
/// way). Padding bytes are zero.
pub(crate) fn regen_hash_blocks(data: &[&[u8]]) -> Vec<[u8; 0x400]> {
    let h0_of = |d: &[u8]| -> Vec<u8> { (0..31).flat_map(|k| crate::crypto::sha1(&d[k * 0x400..(k + 1) * 0x400])).collect() };
    let h0: Vec<Vec<u8>> = data.iter().map(|d| h0_of(d)).collect();
    let zero_h0 = h0_of(&[0u8; PAYLOAD as usize]);
    let mut h1 = vec![[0u8; 0xA0]; 8];
    for s in 0..HASH_GROUP as usize {
        let h = h0.get(s).unwrap_or(&zero_h0);
        h1[s / 8][(s % 8) * 20..(s % 8) * 20 + 20].copy_from_slice(&crate::crypto::sha1(h));
    }
    let mut h2 = [0u8; 0xA0];
    for (j, sub) in h1.iter().enumerate() {
        h2[j * 20..j * 20 + 20].copy_from_slice(&crate::crypto::sha1(sub));
    }
    (0..data.len())
        .map(|s| {
            let mut hb = [0u8; 0x400];
            hb[..0x26C].copy_from_slice(&h0[s]);
            hb[0x280..0x320].copy_from_slice(&h1[s / 8]);
            hb[0x340..0x3E0].copy_from_slice(&h2);
            hb
        })
        .collect()
}

/// 20-byte slots covering a whole 0x400-byte hash block: 31 H0, padding, 8 H1, padding,
/// 8 H2, padding (padding slots overlap so that every byte is covered).
fn hash_slots() -> impl Iterator<Item = usize> {
    (0..31)
        .map(|k| k * 20)
        .chain([0x26C])
        .chain((0..8).map(|k| 0x280 + k * 20))
        .chain([0x320, 0x32C])
        .chain((0..8).map(|k| 0x340 + k * 20))
        .chain([0x3E0, 0x3EC])
}

/// Chunk size used for Wii RVZ output: exactly one 64-sector hash group per group, so each
/// group carries exactly one exception list.
pub const WII_CHUNK: u32 = 0x20_0000;

enum GroupJob {
    Raw { start: u64, len: u64 },
    Part { part: usize, first: u64, n: u64 },
}

/// An encoded group: (bytes, compressed flag, RVZ packed size or 0), or `None` when it is
/// all zero.
type Encoded = Option<(Vec<u8>, bool, u32)>;

/// Compress a group payload (exception lists, then plain or RVZ-packed data) when that
/// helps. `packed` marks packed data; the packed size is the payload size after
/// decompression.
fn store(payload: Vec<u8>, lists_len: usize, packed: bool, level: i32) -> Result<(Vec<u8>, bool, u32)> {
    let c = crate::compression::compress(Codec::Zstd, &payload, level)?;
    if c.len() < payload.len() {
        let ps = if packed { payload.len() as u32 } else { 0 };
        return Ok((c, true, ps));
    }
    // Uncompressed groups pad the exception lists to a 4-byte boundary.
    let mut v = payload[..lists_len].to_vec();
    v.resize(lists_len.div_ceil(4) * 4, 0);
    v.extend_from_slice(&payload[lists_len..]);
    let ps = if packed { v.len() as u32 } else { 0 };
    Ok((v, false, ps))
}

fn encode_part_group(pd: &crate::wii::partition::PartitionData, first: u64, n: u64, level: i32) -> Result<Encoded> {
    let mut data = Vec::with_capacity((n * PAYLOAD) as usize);
    let mut actual = Vec::with_capacity(n as usize);
    for s in first..first + n {
        let (h, d) = pd.cluster(s)?;
        actual.push(h);
        data.extend_from_slice(&d);
    }
    let sectors: Vec<&[u8]> = data.chunks(PAYLOAD as usize).collect();
    let regen = regen_hash_blocks(&sectors);
    let mut count = 0u16;
    let mut entries = ByteWriter::new();
    for (s, (a, r)) in actual.iter().zip(&regen).enumerate() {
        for slot in hash_slots() {
            if a[slot..slot + 20] != r[slot..slot + 20] {
                entries.u16be((s * 0x400 + slot) as u16).bytes(&a[slot..slot + 20]);
                count += 1;
            }
        }
    }
    if count == 0 && data.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let mut list = ByteWriter::new();
    list.u16be(count).bytes(&entries.buf);
    let lists_len = list.len();
    let mut payload = list.buf;
    let packed = crate::wii::junk::pack(&data, first * PAYLOAD);
    payload.extend_from_slice(packed.as_deref().unwrap_or(&data));
    store(payload, lists_len, packed.is_some(), level).map(Some)
}

fn encode_raw_group(src: &dyn DataSource, start: u64, len: u64, level: i32) -> Result<Encoded> {
    let d = read_vec(src, start, len, len)?;
    if d.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    match crate::wii::junk::pack(&d, start) {
        Some(p) => store(p, 0, true, level).map(Some),
        None => store(d, 0, false, level).map(Some),
    }
}

/// Encode a Wii image as RVZ. Partition data is stored decrypted together with its title
/// key (the user's common key decrypts the title keys); hash blocks are dropped and every
/// 20-byte slot that does not regenerate exactly is kept as a hash exception, so scrubbed
/// (zeroed) sectors round-trip too. Junk is packed as LFG seeds. Returns the file size.
pub fn write_rvz_wii<W: Write + Seek>(
    src: &SharedSource,
    keys: &dyn crate::KeyProvider,
    out: &mut W,
    level: i32,
    job: &JobContext,
) -> Result<u64> {
    write_rvz_wii_with(src, |p| crate::wii::partition::titlekey(p, keys), out, level, job)
}

/// [`write_rvz_wii`] with title keys supplied directly (for example the decrypted keys an
/// existing WIA/RVZ image already stores), so no common key is needed.
pub fn write_rvz_wii_with<W: Write + Seek>(
    src: &SharedSource,
    title_key: impl Fn(&crate::wii::partition::PartitionInfo) -> Result<zeroize::Zeroizing<[u8; 16]>>,
    out: &mut W,
    level: i32,
    job: &JobContext,
) -> Result<u64> {
    if !Codec::Zstd.can_encode() {
        return Err(Error::unsupported("RVZ writing requires zstd"));
    }
    let iso_size = src.len()?;
    let dh = read_vec(src.as_ref(), 0, 0x80, 0x80)?;
    if u32be(&dh, 0x18)? != crate::wii::disc::WII_MAGIC {
        return Err(Error::invalid_arg("not a Wii disc image"));
    }
    let cs = WII_CHUNK as u64;
    let spg = cs / SECTOR;
    let mut infos = crate::wii::partition::read_partitions(src.as_ref())?;
    infos.sort_by_key(|p| p.abs_data());
    // (decrypted view, title key, first absolute sector, sectors, management sectors)
    let mut parts = Vec::new();
    let mut gaps = Vec::new();
    let mut cur = 0x80u64;
    for p in &infos {
        let start = p.abs_data();
        if start % SECTOR != 0 || start < cur {
            return Err(Error::malformed(format!("partition {} data is misaligned or overlaps another partition", p.index)));
        }
        let key = title_key(p)?;
        let pd = crate::wii::partition::PartitionData::new(src.clone(), p, key.clone())?;
        let sectors = pd.len()? / PAYLOAD;
        if sectors == 0 {
            continue;
        }
        gaps.push((cur, start - cur));
        // Keep the management data (boot, apploader, DOL, FST) in the first data entry.
        let mgmt = read_vec(&pd, 0x424, 8, 8)
            .ok()
            .and_then(|b| Some(((u32be(&b, 0).ok()? as u64) << 2) + ((u32be(&b, 4).ok()? as u64) << 2)))
            .map(|end| end.div_ceil(PAYLOAD).div_ceil(spg) * spg)
            .unwrap_or(sectors)
            .clamp(1, sectors);
        parts.push((pd, *key, start / SECTOR, sectors, mgmt));
        cur = start + sectors * SECTOR;
    }
    let tail = (cur < iso_size).then_some((cur, iso_size - cur));
    // Group jobs in disc order: raw gap, partition, raw gap, ..., raw tail.
    let mut jobs = Vec::new();
    let mut raw_entries = Vec::new(); // (offset, size, group index, groups)
    let mut part_entries = Vec::new(); // per partition: two (first sector, sectors, group index, groups)
    let raw_job = |jobs: &mut Vec<GroupJob>, (off, size): (u64, u64)| -> (u64, u64, u32, u32) {
        let gi = jobs.len() as u32;
        let mut g = off - off % BLOCK;
        while g < off + size {
            let len = (off + size - g).min(cs);
            jobs.push(GroupJob::Raw { start: g, len });
            g += len;
        }
        (off, size, gi, jobs.len() as u32 - gi)
    };
    for (i, (_, _, first_sector, sectors, mgmt)) in parts.iter().enumerate() {
        if gaps[i].1 > 0 {
            raw_entries.push(raw_job(&mut jobs, gaps[i]));
        }
        let mut pe = [(0u64, 0u64, 0u32, 0u32); 2];
        for (k, (a, b)) in [(0, *mgmt), (*mgmt, *sectors)].into_iter().enumerate() {
            let gi = jobs.len() as u32;
            let mut s = a;
            while s < b {
                let n = (b - s).min(spg);
                jobs.push(GroupJob::Part { part: i, first: s, n });
                s += n;
            }
            pe[k] = (first_sector + a, b - a, gi, jobs.len() as u32 - gi);
        }
        part_entries.push(pe);
    }
    if let Some(t) = tail {
        raw_entries.push(raw_job(&mut jobs, t));
    }
    // Encode in parallel batches; write in order.
    let h_len = 0x48u64 + 0xDC;
    out.seek(SeekFrom::Start(h_len))?;
    let mut pos = h_len;
    let mut groups: Vec<(u32, u32, u32)> = Vec::with_capacity(jobs.len());
    let threads = job.threads.max(1);
    let mut progress = ByteProgress::new(job, Phase::Transforming, Some(iso_size));
    let encode = |j: &GroupJob| -> Result<(Encoded, u64)> {
        match j {
            GroupJob::Raw { start, len } => Ok((encode_raw_group(src.as_ref(), *start, *len, level)?, *len)),
            GroupJob::Part { part, first, n } => Ok((encode_part_group(&parts[*part].0, *first, *n, level)?, n * SECTOR)),
        }
    };
    for batch in jobs.chunks(threads * 2) {
        job.check_cancel()?;
        let results: Vec<Result<(Encoded, u64)>> = if threads == 1 {
            batch.iter().map(encode).collect()
        } else {
            std::thread::scope(|sc| {
                let hs: Vec<_> = batch.iter().map(|j| sc.spawn(|| encode(j))).collect();
                hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(Error::internal("RVZ encoder thread panicked")))).collect()
            })
        };
        for r in results {
            let (enc, bytes) = r?;
            match enc {
                None => groups.push((0, 0, 0)),
                Some((data, compressed, packed)) => {
                    pos = crate::binary::align_up(pos, 4)?;
                    out.seek(SeekFrom::Start(pos))?;
                    out.write_all(&data)?;
                    groups.push(((pos >> 2) as u32, data.len() as u32 | if compressed { 0x8000_0000 } else { 0 }, packed));
                    pos += data.len() as u64;
                }
            }
            progress.advance(bytes)?;
        }
    }
    // Tables: partition entries (stored), raw data entries and groups (compressed).
    let mut pt = ByteWriter::new();
    for ((_, key, ..), pe) in parts.iter().zip(&part_entries) {
        pt.bytes(key);
        for (first, n, gi, gn) in pe {
            pt.u32be(*first as u32).u32be(*n as u32).u32be(*gi).u32be(*gn);
        }
    }
    let mut rt = ByteWriter::new();
    for (o, s, gi, gn) in &raw_entries {
        rt.u64be(*o).u64be(*s).u32be(*gi).u32be(*gn);
    }
    let mut gt = ByteWriter::new();
    for (o, s, packed) in &groups {
        gt.u32be(*o).u32be(*s).u32be(*packed);
    }
    let rtc = crate::compression::compress(Codec::Zstd, &rt.buf, level)?;
    let gtc = crate::compression::compress(Codec::Zstd, &gt.buf, level)?;
    pos = crate::binary::align_up(pos, 4)?;
    out.seek(SeekFrom::Start(pos))?;
    let part_off = pos;
    out.write_all(&pt.buf)?;
    pos += pt.len() as u64;
    let raw_tbl_off = pos;
    out.write_all(&rtc)?;
    pos += rtc.len() as u64;
    let grp_tbl_off = pos;
    out.write_all(&gtc)?;
    pos += gtc.len() as u64;
    let file_size = pos;
    let mut h2 = ByteWriter::new();
    h2.u32be(2).u32be(5).u32be(level as u32).u32be(WII_CHUNK).bytes(&dh);
    h2.u32be(parts.len() as u32).u32be(0x30).u64be(part_off).bytes(&crate::crypto::sha1(&pt.buf));
    h2.u32be(raw_entries.len() as u32).u64be(raw_tbl_off).u32be(rtc.len() as u32);
    h2.u32be(groups.len() as u32).u64be(grp_tbl_off).u32be(gtc.len() as u32).u8(0).zeros(7);
    let mut h1 = ByteWriter::new();
    h1.bytes(RVZ_MAGIC)
        .u32be(0x0100_0000)
        .u32be(0x0003_0000)
        .u32be(h2.len() as u32)
        .bytes(&crate::crypto::sha1(&h2.buf))
        .u64be(iso_size)
        .u64be(file_size);
    let h1hash = crate::crypto::sha1(&h1.buf);
    h1.bytes(&h1hash);
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&h1.buf)?;
    out.write_all(&h2.buf)?;
    out.seek(SeekFrom::Start(file_size))?;
    Ok(file_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySource;
    use std::sync::Arc;

    #[test]
    fn lfg_skip_matches_fill() {
        let seed = [7u8; 68];
        let mut a = Lfg::new(&seed);
        let mut all = vec![0u8; 5000];
        a.fill(&mut all);
        let mut b = Lfg::new(&seed);
        b.skip(3000);
        let mut part = vec![0u8; 2000];
        b.fill(&mut part);
        assert_eq!(&all[3000..], &part[..]);
    }

    #[test]
    fn packed_unpack_literal_and_junk() {
        let seed = [3u8; 68];
        let mut packed = Vec::new();
        packed.extend_from_slice(&4u32.to_be_bytes());
        packed.extend_from_slice(b"abcd");
        packed.extend_from_slice(&(0x8000_0000u32 | 100).to_be_bytes());
        packed.extend_from_slice(&seed);
        let out = unpack(&packed, 0x10000, 104).unwrap();
        assert_eq!(&out[..4], b"abcd");
        let mut l = Lfg::new(&seed);
        l.skip(4);
        let mut j = vec![0u8; 100];
        l.fill(&mut j);
        assert_eq!(&out[4..], &j[..]);
    }

    #[test]
    fn gc_rvz_roundtrip() {
        let img = crate::wii::disc::testkit::gc_disc("GTST", "RVZ Test", &[("a.bin", vec![5u8; 70000]), ("b.txt", b"hello".to_vec())]);
        let mut c = std::io::Cursor::new(Vec::new());
        write_rvz_gc(&MemorySource::new(img.clone()), &mut c, 3, 0x20000, &JobContext::default()).unwrap();
        let bytes = c.into_inner();
        assert!(bytes.len() < img.len());
        let w = WiaSource::open(Arc::new(MemorySource::new(bytes))).unwrap();
        let mut back = vec![0u8; img.len()];
        w.read_exact_at(0, &mut back).unwrap();
        assert_eq!(back, img);
    }

    /// Fill `out` with Nintendo-style junk for data-space offset `offset` onward (re-seeded
    /// at every 0x8000-byte block, with an arbitrary per-block seed).
    fn fill_junk(out: &mut [u8], offset: u64) {
        let mut i = 0;
        while i < out.len() {
            let abs = offset + i as u64;
            let blk = abs / BLOCK;
            let lo = (abs % BLOCK) as usize;
            let n = (BLOCK as usize - lo).min(out.len() - i);
            let seed: [u8; 68] = std::array::from_fn(|k| (k as u8).wrapping_mul(29) ^ blk as u8 ^ 0x5C);
            let mut g = Lfg::new(&seed);
            g.skip(lo);
            g.fill(&mut out[i..i + n]);
            i += n;
        }
    }

    #[test]
    fn gc_rvz_packs_junk() {
        let mut img = crate::wii::disc::testkit::gc_disc("GJNK", "Junk Test", &[("a.bin", vec![5u8; 70000])]);
        let start = img.len();
        img.resize(start + 0x300000, 0);
        let off = start as u64 + 0x123;
        fill_junk(&mut img[start + 0x123..], off);
        let mut c = std::io::Cursor::new(Vec::new());
        write_rvz_gc(&MemorySource::new(img.clone()), &mut c, 3, 0x20000, &JobContext::default()).unwrap();
        let bytes = c.into_inner();
        assert!(bytes.len() < 0x10000, "junk not packed: {} bytes", bytes.len());
        let w = WiaSource::open(Arc::new(MemorySource::new(bytes))).unwrap();
        assert!(w.groups.iter().any(|g| g.packed_size != 0));
        let mut back = vec![0u8; img.len()];
        w.read_exact_at(0, &mut back).unwrap();
        assert!(back == img);
    }

    /// Synthetic encrypted Wii disc: one partition of `sectors` sectors. Hash group 1 is
    /// all-zero plaintext, sectors 140..150 are scrubbed (raw zeros), sector 5 has non-zero
    /// hash padding and sector 6 a wrong H0 hash. Returns (image, common key).
    fn wii_disc(sectors: u64) -> (Vec<u8>, [u8; 16]) {
        let ck = [0x11u8; 16];
        let tk = [0x22u8; 16];
        let tid = 0x0001_0000_5254_5354u64;
        let (poff, doff) = (0x50000u64, 0x20000u64);
        let data_start = poff + doff;
        let mut img = vec![0u8; (data_start + sectors * SECTOR + 0x10000) as usize];
        img[..6].copy_from_slice(b"RTSTXX");
        img[0x18..0x1C].copy_from_slice(&crate::wii::disc::WII_MAGIC.to_be_bytes());
        img[0x20..0x28].copy_from_slice(b"Wii Test");
        img[0x40000..0x40004].copy_from_slice(&1u32.to_be_bytes());
        img[0x40004..0x40008].copy_from_slice(&((0x40020u32) >> 2).to_be_bytes());
        img[0x40020..0x40024].copy_from_slice(&((poff >> 2) as u32).to_be_bytes());
        // Partition header: ticket, TMD, H3 and data pointers.
        let mut etk = tk;
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&tid.to_be_bytes());
        crate::crypto::cbc_encrypt(&ck, &iv, &mut etk).unwrap();
        let p = poff as usize;
        img[p + 0x1BF..p + 0x1CF].copy_from_slice(&etk);
        img[p + 0x1DC..p + 0x1E4].copy_from_slice(&tid.to_be_bytes());
        let put = |img: &mut Vec<u8>, o: usize, v: u64| img[p + o..p + o + 4].copy_from_slice(&(v as u32).to_be_bytes());
        put(&mut img, 0x2A4, 0x208);
        put(&mut img, 0x2A8, 0x2C0 >> 2);
        put(&mut img, 0x2B4, 0x8000 >> 2);
        put(&mut img, 0x2B8, doff >> 2);
        put(&mut img, 0x2BC, (sectors * SECTOR) >> 2);
        // Plaintext payloads.
        let mut plain: Vec<Vec<u8>> = (0..sectors)
            .map(|s| {
                if (64..128).contains(&s) {
                    vec![0u8; PAYLOAD as usize]
                } else {
                    (0..PAYLOAD as usize).map(|i| ((i / 7) as u64 ^ (s * 31)) as u8).collect()
                }
            })
            .collect();
        // Sectors 20..40 hold junk in partition payload space.
        for s in 20..40u64.min(sectors) {
            fill_junk(&mut plain[s as usize], s * PAYLOAD);
        }
        plain[0][0x424..0x428].copy_from_slice(&(0x500u32 >> 2).to_be_bytes());
        plain[0][0x428..0x42C].copy_from_slice(&(0x40u32 >> 2).to_be_bytes());
        let mut h3 = vec![0u8; crate::wii::partition::H3_SIZE as usize];
        for hg in 0..sectors.div_ceil(HASH_GROUP) {
            let a = hg * HASH_GROUP;
            let b = (a + HASH_GROUP).min(sectors);
            let refs: Vec<&[u8]> = plain[a as usize..b as usize].iter().map(|v| v.as_slice()).collect();
            let mut blocks = regen_hash_blocks(&refs);
            h3[hg as usize * 20..hg as usize * 20 + 20].copy_from_slice(&crate::crypto::sha1(&blocks[0][0x340..0x3E0]));
            for (k, hb) in blocks.iter_mut().enumerate() {
                let s = a + k as u64;
                if s == 5 {
                    hb[0x270] = 0xAB;
                    hb[0x3F0] = 0xCD;
                }
                if s == 6 {
                    hb[0x14] ^= 0xFF;
                }
                let off = (data_start + s * SECTOR) as usize;
                if (140..150).contains(&s) {
                    continue; // scrubbed: stays all zero
                }
                let mut h = hb.to_vec();
                crate::crypto::cbc_encrypt(&tk, &[0u8; 16], &mut h).unwrap();
                let div: [u8; 16] = h[0x3D0..0x3E0].try_into().unwrap();
                let mut d = plain[s as usize].clone();
                crate::crypto::cbc_encrypt(&tk, &div, &mut d).unwrap();
                img[off..off + 0x400].copy_from_slice(&h);
                img[off + 0x400..off + SECTOR as usize].copy_from_slice(&d);
            }
        }
        img[p + 0x8000..p + 0x8000 + h3.len()].copy_from_slice(&h3);
        let tmd_h3 = crate::crypto::sha1(&h3);
        img[p + 0x2C0 + 0x1E4 + 0x10..p + 0x2C0 + 0x1E4 + 0x24].copy_from_slice(&tmd_h3);
        // Non-zero data after the partition (raw tail entry).
        let n = img.len();
        img[n - 0x100..].fill(0x5A);
        (img, ck)
    }

    #[test]
    fn wii_rvz_write_roundtrip() {
        let (img, ck) = wii_disc(160);
        let mut keys = crate::crypto::KeyFile::new();
        keys.insert("wii_common_key", &ck);
        let src: SharedSource = Arc::new(MemorySource::new(img.clone()));
        let mut c = std::io::Cursor::new(Vec::new());
        let mut job = JobContext::default();
        job.threads = 3;
        write_rvz_wii(&src, &keys, &mut c, 3, &job).unwrap();
        let bytes = c.into_inner();
        assert!(bytes.len() < img.len() / 2, "{} vs {}", bytes.len(), img.len());
        let w = WiaSource::open(Arc::new(MemorySource::new(bytes.clone()))).unwrap();
        assert!(w.header.is_wii());
        assert_eq!(w.parts.len(), 1);
        assert_eq!(w.parts[0].data[0].sectors, 64, "management data in the first entry");
        assert_eq!(w.parts[0].data[1].sectors, 96);
        assert_eq!(w.groups[w.parts[0].data[1].group_index as usize].size, 0, "all-zero group stored empty");
        assert_ne!(w.groups[w.parts[0].data[0].group_index as usize].packed_size, 0, "junk in group 0 is packed");
        let mut back = vec![0u8; img.len()];
        w.read_exact_at(0, &mut back).unwrap();
        for (i, (a, b)) in img.chunks(SECTOR as usize).zip(back.chunks(SECTOR as usize)).enumerate() {
            assert!(a == b, "sector {i} differs");
        }
        // Same result single-threaded; missing key is a key-material error.
        let mut c1 = std::io::Cursor::new(Vec::new());
        write_rvz_wii(&src, &keys, &mut c1, 3, &JobContext::default()).unwrap();
        assert_eq!(c1.into_inner(), bytes);
        let e = write_rvz_wii(&src, &crate::NoKeys, &mut std::io::Cursor::new(Vec::new()), 3, &JobContext::default()).unwrap_err();
        assert_eq!(e.code(), crate::ErrorCode::NeedsKeyMaterial);
        // The partition's plaintext is readable from the RVZ without any key.
        let pp = PlainPartition::new(Arc::new(w), 0);
        let mut s0 = vec![0u8; PAYLOAD as usize];
        pp.read_exact_at(0, &mut s0).unwrap();
        assert_eq!(&s0[0x424..0x428], &(0x500u32 >> 2).to_be_bytes());
    }

    #[test]
    fn wii_iso_to_rvz_plan() {
        use crate::{Backend, ConvertRequest, OpenContext, PackageReader, VerifyLevel};
        let (img, ck) = wii_disc(100);
        let d = tempfile::tempdir().unwrap();
        let iso = d.path().join("w.iso");
        std::fs::write(&iso, &img).unwrap();
        let out = d.path().join("w.rvz");
        let mut keys = crate::crypto::KeyFile::new();
        keys.insert("wii_common_key", &ck);
        let req = |ctx: OpenContext| ConvertRequest {
            input: iso.clone(),
            source: crate::open_file(&iso).unwrap(),
            from: crate::wii::WII_ISO,
            to: crate::wii::WII_RVZ,
            output: out.clone(),
            ctx,
            options: Default::default(),
        };
        let e = crate::wii::WiiBackend.plan_convert(req(OpenContext::default())).err().expect("no key");
        assert_eq!(e.code(), crate::ErrorCode::NeedsKeyMaterial);
        let ctx = OpenContext { keys: Arc::new(keys), ..Default::default() };
        crate::wii::WiiBackend.plan_convert(req(ctx.clone())).unwrap().execute(&JobContext::default()).unwrap();
        let r = crate::wii::rvz_reader::WiiRvzReader::open(crate::open_file(&out).unwrap(), crate::wii::WII_RVZ, &ctx).unwrap();
        let v = r.verify(VerifyLevel::Content, &JobContext::default()).unwrap();
        // The stored H0 oddity in sector 6 is an exception, not part of the H1-H3 chain, so
        // the tree still matches the H3 table and the TMD.
        assert!(v.no_failures(), "{:?}", v.checks);
        assert!(v.checks.iter().any(|c| c.name.contains("regenerated hash tree") && c.status == crate::CheckStatus::Passed));
    }
}

/// Opt-in real-sample check: `ROMUX_WII_RVZ_SAMPLE=path.rvz cargo test --release -p romux --features wii
/// --all-features -- --ignored real_wii_rvz_rewrite`. Re-encodes a Wii RVZ through the
/// writer using the title keys it already stores and requires a byte-identical image.
#[cfg(test)]
mod real_sample {
    use super::*;
    use crate::FileSource;

    #[test]
    #[ignore]
    fn real_wii_rvz_rewrite() {
        let Ok(path) = std::env::var("ROMUX_WII_RVZ_SAMPLE") else { return };
        let w = Arc::new(WiaSource::open(Arc::new(FileSource::open(&path).unwrap())).unwrap());
        let view: SharedSource = w.clone();
        let out = std::env::temp_dir().join("romux-real-wii-rewrite.rvz");
        let mut f = std::fs::File::create(&out).unwrap();
        let mut job = JobContext::default();
        job.threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let t = std::time::Instant::now();
        let size = write_rvz_wii_with(
            &view,
            |p| {
                let e = w.parts.iter().find(|e| e.data_offset() == p.abs_data()).ok_or_else(|| Error::malformed("partition not in RVZ"))?;
                Ok(zeroize::Zeroizing::new(e.key))
            },
            &mut f,
            5,
            &job,
        )
        .unwrap();
        drop(f);
        eprintln!("wrote {size} bytes in {:?}", t.elapsed());
        let back = WiaSource::open(Arc::new(FileSource::open(&out).unwrap())).unwrap();
        let a = crate::crypto::hash_range(view.as_ref(), 0, view.len().unwrap(), crate::crypto::HashAlg::Sha1, None).unwrap();
        let b = crate::crypto::hash_range(&back, 0, back.len().unwrap(), crate::crypto::HashAlg::Sha1, None).unwrap();
        eprintln!("source {} rewritten {} ({:?} total)", crate::hex(&a), crate::hex(&b), t.elapsed());
        std::fs::remove_file(&out).ok();
        assert_eq!(a, b);
    }
}

#[cfg(test)]
mod real_sample_gc {
    use super::*;
    use crate::FileSource;

    /// `ROMUX_GC_RVZ_SAMPLE=path.rvz cargo test --release -p romux --features wii --all-features --
    /// --ignored real_gc_rvz_rewrite`: re-encode a GameCube RVZ; the image must match.
    #[test]
    #[ignore]
    fn real_gc_rvz_rewrite() {
        let Ok(path) = std::env::var("ROMUX_GC_RVZ_SAMPLE") else { return };
        let w = WiaSource::open(Arc::new(FileSource::open(&path).unwrap())).unwrap();
        let out = std::env::temp_dir().join("romux-real-gc-rewrite.rvz");
        let mut f = std::fs::File::create(&out).unwrap();
        let t = std::time::Instant::now();
        let size = write_rvz_gc(&w, &mut f, 5, 0x20000, &JobContext::default()).unwrap();
        drop(f);
        eprintln!("wrote {size} bytes in {:?}", t.elapsed());
        let back = WiaSource::open(Arc::new(FileSource::open(&out).unwrap())).unwrap();
        let a = crate::crypto::hash_range(&w, 0, w.len().unwrap(), crate::crypto::HashAlg::Sha1, None).unwrap();
        let b = crate::crypto::hash_range(&back, 0, back.len().unwrap(), crate::crypto::HashAlg::Sha1, None).unwrap();
        eprintln!("source {} rewritten {}", crate::hex(&a), crate::hex(&b));
        std::fs::remove_file(&out).ok();
        assert_eq!(a, b);
    }
}
