//! Deterministic CHD v5 writer (zlib/zstd and CD zlib/zstd codecs, compressed map).

use super::huffman::BitWriter;
use super::{CD_FRAME, CD_SECTOR, CD_TRACK_PADDING, MDFLAG_CHECKSUM, V5_SELF, V5_TYPE_NONE, crc16, tag};
use crate::compression::{Codec, compress};
use crate::disc::rawcd::TrackMode;
use crate::{ByteProgress, DataSource, Error, JobContext, Phase, Result, SharedSource};
use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};

/// A CD track to encode.
pub struct CdTrackInput {
    pub mode: TrackMode,
    /// Stored sectors of `mode.sector_size()` bytes each.
    pub data: SharedSource,
    /// Pregap frames included at the start of `data` (written as `PGTYPE:V...`).
    pub stored_pregap: u64,
    /// Pregap frames not stored.
    pub unstored_pregap: u64,
    pub postgap: u64,
}

/// What kind of media to encode.
pub enum ChdInput {
    /// DVD/ISO-style image with 2048-byte units.
    Dvd(SharedSource),
    /// CD tracks.
    Cd(Vec<CdTrackInput>),
}

#[derive(Debug, Clone)]
pub struct ChdWriteOptions {
    /// Compressor tags in priority order (max 4). Defaults depend on media type.
    pub compressors: Option<Vec<u32>>,
    pub hunk_bytes: Option<u32>,
    pub zstd_level: i32,
    pub zlib_level: i32,
}

impl Default for ChdWriteOptions {
    fn default() -> Self {
        ChdWriteOptions { compressors: None, hunk_bytes: None, zstd_level: 19, zlib_level: 9 }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChdWriteSummary {
    pub logical_bytes: u64,
    pub hunks: u32,
    pub hunk_bytes: u32,
    pub compressed_hunks: u32,
    pub uncompressed_hunks: u32,
    pub self_refs: u32,
    pub raw_sha1: String,
    pub sha1: String,
    pub compressors: Vec<String>,
}

fn bits_for(v: u64) -> u32 {
    64 - v.leading_zeros()
}

/// Sequential logical-data producer.
trait Feeder {
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}

struct LinearFeeder {
    src: SharedSource,
    pos: u64,
    len: u64,
}

impl Feeder for LinearFeeder {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        let avail = self.len.saturating_sub(self.pos).min(out.len() as u64) as usize;
        if avail > 0 {
            self.src.read_exact_at(self.pos, &mut out[..avail])?;
        }
        out[avail..].fill(0);
        self.pos += out.len() as u64;
        Ok(())
    }
}

struct CdFeeder<'a> {
    tracks: &'a [CdTrackInput],
    track: usize,
    frame: u64,
    frames_in_track: Vec<u64>,
}

impl Feeder for CdFeeder<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        out.fill(0);
        for frame_buf in out.chunks_exact_mut(CD_FRAME as usize) {
            loop {
                if self.track >= self.tracks.len() {
                    break;
                }
                let t = &self.tracks[self.track];
                let frames = self.frames_in_track[self.track];
                let padded = frames + (CD_TRACK_PADDING - frames % CD_TRACK_PADDING) % CD_TRACK_PADDING;
                if self.frame < frames {
                    let ss = t.mode.sector_size().min(CD_SECTOR) as usize;
                    t.data.read_exact_at(self.frame * t.mode.sector_size(), &mut frame_buf[..ss])?;
                    if t.mode == TrackMode::Audio {
                        for p in frame_buf[..ss].chunks_exact_mut(2) {
                            p.swap(0, 1);
                        }
                    }
                    self.frame += 1;
                    break;
                } else if self.frame < padded {
                    self.frame += 1;
                    break;
                } else {
                    self.track += 1;
                    self.frame = 0;
                }
            }
        }
        Ok(())
    }
}

fn compress_hunk(data: &[u8], compressors: &[u32], opts: &ChdWriteOptions) -> Result<Option<(u8, Vec<u8>)>> {
    let mut best: Option<(u8, Vec<u8>)> = None;
    for (i, c) in compressors.iter().enumerate() {
        let out = match &c.to_be_bytes() {
            b"zlib" => compress(Codec::Deflate, data, opts.zlib_level)?,
            b"zstd" => compress(Codec::Zstd, data, opts.zstd_level)?,
            b"cdzl" | b"cdzs" => {
                let codec = if &c.to_be_bytes() == b"cdzl" { Codec::Deflate } else { Codec::Zstd };
                let level = if codec == Codec::Deflate { opts.zlib_level } else { opts.zstd_level };
                let frames = data.len() / CD_FRAME as usize;
                let mut base = Vec::with_capacity(frames * CD_SECTOR as usize);
                let mut sub = Vec::with_capacity(frames * 96);
                for f in data.chunks_exact(CD_FRAME as usize) {
                    base.extend_from_slice(&f[..CD_SECTOR as usize]);
                    sub.extend_from_slice(&f[CD_SECTOR as usize..]);
                }
                let cb = compress(codec, &base, level)?;
                let cs = compress(codec, &sub, level)?;
                let ecc_bytes = frames.div_ceil(8);
                let three = data.len() >= 65536;
                if (!three && cb.len() > 0xFFFF) || cb.len() > 0xFF_FFFF {
                    continue;
                }
                let mut o = vec![0u8; ecc_bytes];
                if three {
                    o.push((cb.len() >> 16) as u8);
                }
                o.push((cb.len() >> 8) as u8);
                o.push(cb.len() as u8);
                o.extend_from_slice(&cb);
                o.extend_from_slice(&cs);
                o
            }
            _ => return Err(Error::unsupported(format!("cannot encode CHD codec {}", super::tag_str(*c)))),
        };
        if out.len() < data.len() && best.as_ref().is_none_or(|b| out.len() < b.1.len()) {
            best = Some((i as u8, out));
        }
    }
    Ok(best)
}

struct RawMapEntry {
    ty: u8,
    length: u32,
    offset: u64,
    crc: u16,
}

fn encode_map(entries: &[RawMapEntry], hunk_bytes: u32) -> Result<Vec<u8>> {
    // CRC over the canonical 12-byte raw map.
    let mut raw = Vec::with_capacity(entries.len() * 12);
    for e in entries {
        raw.push(e.ty);
        raw.extend_from_slice(&e.length.to_be_bytes()[1..]);
        raw.extend_from_slice(&e.offset.to_be_bytes()[2..]);
        raw.extend_from_slice(&e.crc.to_be_bytes());
    }
    let map_crc = crc16(&raw);
    let first_offs = entries.iter().find(|e| e.ty <= V5_TYPE_NONE).map(|e| e.offset).unwrap_or(0);
    let max_len = entries.iter().filter(|e| e.ty < V5_TYPE_NONE).map(|e| e.length as u64).max().unwrap_or(0);
    let max_self = entries.iter().filter(|e| e.ty == V5_SELF).map(|e| e.offset).max().unwrap_or(0);
    let length_bits = bits_for(max_len);
    let self_bits = bits_for(max_self);
    let parent_bits = 0u32;
    let _ = hunk_bytes;

    let mut w = BitWriter::new();
    // Tree: 16 symbols with fixed 4-bit codes (a complete canonical code).
    for _ in 0..16 {
        w.write(4, 4);
    }
    // Symbols with run-length compression.
    let mut i = 0usize;
    let mut last: Option<u8> = None;
    while i < entries.len() {
        let t = entries[i].ty;
        let mut run = 1usize;
        while i + run < entries.len() && entries[i + run].ty == t {
            run += 1;
        }
        let mut remaining = run;
        if last != Some(t) {
            w.write(t as u32, 4);
            remaining -= 1;
            last = Some(t);
        }
        while remaining >= 3 {
            if remaining <= 3 + 15 {
                w.write(super::V5_RLE_SMALL as u32, 4);
                w.write((remaining - 3) as u32, 4);
                remaining = 0;
            } else {
                let m = remaining.min(19 + 255);
                let v = (m - 19) as u32;
                w.write(super::V5_RLE_LARGE as u32, 4);
                w.write(v >> 4, 4);
                w.write(v & 15, 4);
                remaining -= m;
            }
        }
        for _ in 0..remaining {
            w.write(t as u32, 4);
        }
        i += run;
    }
    for e in entries {
        match e.ty {
            0..=3 => {
                w.write(e.length, length_bits);
                w.write(e.crc as u32, 16);
            }
            V5_TYPE_NONE => w.write(e.crc as u32, 16),
            V5_SELF => w.write(e.offset as u32, self_bits),
            _ => return Err(Error::internal("unexpected map entry type in writer")),
        }
    }
    let body = w.finish();
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&first_offs.to_be_bytes()[2..]);
    out.extend_from_slice(&map_crc.to_be_bytes());
    out.push(length_bits as u8);
    out.push(self_bits as u8);
    out.push(parent_bits as u8);
    out.push(0);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Encode a CHD v5 file. The writer must be seekable (the header is finalised last).
pub fn write_chd<W: Write + Seek>(input: &ChdInput, opts: &ChdWriteOptions, out: &mut W, job: &JobContext) -> Result<ChdWriteSummary> {
    let zstd_ok = Codec::Zstd.can_encode();
    let (unit_bytes, hunk_bytes, logical, default_comp, mut feeder, metadata): (
        u32,
        u32,
        u64,
        Vec<u32>,
        Box<dyn Feeder + '_>,
        Vec<(u32, Vec<u8>)>,
    ) = match input {
        ChdInput::Dvd(s) => {
            let unit = 2048u32;
            let len = s.len()?;
            if unit == 0 || len % unit as u64 != 0 {
                return Err(Error::invalid_arg(format!("input length {len} is not a multiple of unit size {unit}")));
            }
            let hb = opts.hunk_bytes.unwrap_or(unit * (0x4000 / unit).max(1));
            if !hb.is_multiple_of(unit) {
                return Err(Error::invalid_arg("hunk size must be a multiple of the unit size"));
            }
            let comp = if zstd_ok { vec![tag(b"zstd"), tag(b"zlib")] } else { vec![tag(b"zlib")] };
            let meta = if matches!(input, ChdInput::Dvd(_)) { vec![(tag(b"DVD "), Vec::new())] } else { vec![] };
            (unit, hb, len, comp, Box::new(LinearFeeder { src: s.clone(), pos: 0, len }), meta)
        }
        ChdInput::Cd(tracks) => {
            if tracks.is_empty() || tracks.len() > 99 {
                return Err(Error::invalid_arg("CD must have 1..99 tracks"));
            }
            let mut frames_in_track = Vec::new();
            let mut total = 0u64;
            let mut meta = Vec::new();
            for (i, t) in tracks.iter().enumerate() {
                let ss = t.mode.sector_size();
                if ss > CD_SECTOR {
                    return Err(Error::unsupported("tracks with stored subcode (CDG) are not supported by the writer"));
                }
                let len = t.data.len()?;
                if len % ss != 0 {
                    return Err(Error::invalid_arg(format!("track {} length is not a multiple of {ss}", i + 1)));
                }
                let frames = len / ss;
                frames_in_track.push(frames);
                total += frames + (CD_TRACK_PADDING - frames % CD_TRACK_PADDING) % CD_TRACK_PADDING;
                let (pregap, pgtype) = if t.stored_pregap > 0 {
                    (t.stored_pregap, format!("V{}", t.mode.chd_name()))
                } else {
                    (t.unstored_pregap, t.mode.chd_name().to_string())
                };
                let text = format!(
                    "TRACK:{} TYPE:{} SUBTYPE:NONE FRAMES:{} PREGAP:{} PGTYPE:{} PGSUB:NONE POSTGAP:{}\0",
                    i + 1,
                    t.mode.chd_name(),
                    frames,
                    pregap,
                    pgtype,
                    t.postgap
                );
                meta.push((tag(b"CHT2"), text.into_bytes()));
            }
            let hb = opts.hunk_bytes.unwrap_or(CD_FRAME as u32 * 8);
            if !hb.is_multiple_of(CD_FRAME as u32) {
                return Err(Error::invalid_arg("CD hunk size must be a multiple of 2448"));
            }
            let comp = if zstd_ok { vec![tag(b"cdzs"), tag(b"cdzl")] } else { vec![tag(b"cdzl")] };
            (CD_FRAME as u32, hb, total * CD_FRAME, comp, Box::new(CdFeeder { tracks, track: 0, frame: 0, frames_in_track }), meta)
        }
    };
    let compressors = opts.compressors.clone().unwrap_or(default_comp);
    if compressors.is_empty() || compressors.len() > 4 {
        return Err(Error::invalid_arg("1..4 compressors required"));
    }
    let hunks = logical.div_ceil(hunk_bytes as u64);
    if hunks > u32::MAX as u64 {
        return Err(Error::limit("too many hunks"));
    }
    let hunks = hunks as u32;

    out.seek(SeekFrom::Start(0))?;
    out.write_all(&[0u8; 124])?;
    let mut pos = 124u64;
    let mut map: Vec<RawMapEntry> = Vec::with_capacity(hunks as usize);
    let mut seen: HashMap<(u32, [u8; 20]), u32> = HashMap::new();
    let mut raw_sha = crate::crypto::StreamHasher::new(crate::crypto::HashAlg::Sha1);
    let mut summary_c = 0u32;
    let mut summary_u = 0u32;
    let mut summary_s = 0u32;
    let mut prog = ByteProgress::new(job, Phase::Transforming, Some(logical));
    let batch = (job.threads.max(1) * 4) as u32;
    let mut h = 0u32;
    while h < hunks {
        job.check_cancel()?;
        let n = batch.min(hunks - h);
        let mut bufs = Vec::with_capacity(n as usize);
        for k in 0..n {
            let mut b = vec![0u8; hunk_bytes as usize];
            feeder.fill(&mut b)?;
            let hunk_index = h + k;
            let end = ((hunk_index as u64 + 1) * hunk_bytes as u64).min(logical);
            let valid = (end - hunk_index as u64 * hunk_bytes as u64) as usize;
            raw_sha.update(&b[..valid]);
            bufs.push(b);
        }
        // Deduplicate first so repeated hunks (e.g. zero fill) are never compressed.
        let mut dup_of: Vec<Option<u32>> = Vec::with_capacity(bufs.len());
        for (k, b) in bufs.iter().enumerate() {
            let key = (crate::crypto::crc32(b), crate::crypto::sha1(b));
            match seen.get(&key) {
                Some(&prev) => dup_of.push(Some(prev)),
                None => {
                    seen.insert(key, h + k as u32);
                    dup_of.push(None);
                }
            }
        }
        let unique: Vec<&Vec<u8>> = bufs.iter().zip(&dup_of).filter(|(_, d)| d.is_none()).map(|(b, _)| b).collect();
        let compressed: Vec<Result<Option<(u8, Vec<u8>)>>> = if job.threads > 1 && unique.len() > 1 {
            std::thread::scope(|s| {
                let handles: Vec<_> = unique.iter().map(|b| s.spawn(|| compress_hunk(b, &compressors, opts))).collect();
                handles.into_iter().map(|j| j.join().unwrap_or_else(|_| Err(Error::internal("worker panicked")))).collect()
            })
        } else {
            unique.iter().map(|b| compress_hunk(b, &compressors, opts)).collect()
        };
        let mut compressed = compressed.into_iter();
        for (b, dup) in bufs.iter().zip(&dup_of) {
            let crc = crc16(b);
            if let Some(prev) = dup {
                map.push(RawMapEntry { ty: V5_SELF, length: 0, offset: *prev as u64, crc: 0 });
                summary_s += 1;
            } else {
                let r = compressed.next().ok_or_else(|| Error::internal("compression result missing"))?;
                match r? {
                    Some((ci, data)) => {
                        out.write_all(&data)?;
                        map.push(RawMapEntry { ty: ci, length: data.len() as u32, offset: pos, crc });
                        pos += data.len() as u64;
                        summary_c += 1;
                    }
                    None => {
                        out.write_all(b)?;
                        map.push(RawMapEntry { ty: V5_TYPE_NONE, length: hunk_bytes, offset: pos, crc });
                        pos += hunk_bytes as u64;
                        summary_u += 1;
                    }
                }
            }
            prog.advance(hunk_bytes as u64)?;
        }
        h += n;
    }
    let map_bytes = encode_map(&map, hunk_bytes)?;
    let map_offset = pos;
    out.write_all(&map_bytes)?;
    pos += map_bytes.len() as u64;
    let meta_offset = if metadata.is_empty() { 0 } else { pos };
    for (i, (t, d)) in metadata.iter().enumerate() {
        let entry_len = 16 + d.len() as u64;
        let next = if i + 1 < metadata.len() { pos + entry_len } else { 0 };
        out.write_all(&t.to_be_bytes())?;
        out.write_all(&[MDFLAG_CHECKSUM])?;
        out.write_all(&(d.len() as u32).to_be_bytes()[1..])?;
        out.write_all(&next.to_be_bytes())?;
        out.write_all(d)?;
        pos += entry_len;
    }
    let raw_sha1: [u8; 20] = raw_sha.finish().try_into().map_err(|_| Error::internal("sha1 length"))?;
    let mut hashes: Vec<[u8; 24]> = metadata
        .iter()
        .map(|(t, d)| {
            let mut x = [0u8; 24];
            x[..4].copy_from_slice(&t.to_be_bytes());
            x[4..].copy_from_slice(&crate::crypto::sha1(d));
            x
        })
        .collect();
    hashes.sort();
    let mut all = raw_sha1.to_vec();
    for x in &hashes {
        all.extend_from_slice(x);
    }
    let sha1 = crate::crypto::sha1(&all);
    let mut hdr = Vec::with_capacity(124);
    hdr.extend_from_slice(super::MAGIC);
    hdr.extend_from_slice(&124u32.to_be_bytes());
    hdr.extend_from_slice(&5u32.to_be_bytes());
    for i in 0..4 {
        hdr.extend_from_slice(&compressors.get(i).copied().unwrap_or(0).to_be_bytes());
    }
    hdr.extend_from_slice(&logical.to_be_bytes());
    hdr.extend_from_slice(&map_offset.to_be_bytes());
    hdr.extend_from_slice(&meta_offset.to_be_bytes());
    hdr.extend_from_slice(&hunk_bytes.to_be_bytes());
    hdr.extend_from_slice(&unit_bytes.to_be_bytes());
    hdr.extend_from_slice(&raw_sha1);
    hdr.extend_from_slice(&sha1);
    hdr.extend_from_slice(&[0u8; 20]);
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&hdr)?;
    out.seek(SeekFrom::Start(pos))?;
    out.flush()?;
    Ok(ChdWriteSummary {
        logical_bytes: logical,
        hunks,
        hunk_bytes,
        compressed_hunks: summary_c,
        uncompressed_hunks: summary_u,
        self_refs: summary_s,
        raw_sha1: crate::hex(&raw_sha1),
        sha1: crate::hex(&sha1),
        compressors: compressors.iter().map(|c| super::tag_str(*c)).collect(),
    })
}

/// Overall SHA-1 of an opened CHD recomputed from its logical data and metadata.
pub fn compute_sha1s(chd: &std::sync::Arc<super::ChdFile>, job: &JobContext) -> Result<([u8; 20], [u8; 20])> {
    let src = super::ChdSource::new(chd.clone());
    let len = src.len()?;
    let mut p = ByteProgress::new(job, Phase::Verifying, Some(len));
    let raw: [u8; 20] = crate::crypto::hash_range(&src, 0, len, crate::crypto::HashAlg::Sha1, Some(&mut p))?
        .try_into()
        .map_err(|_| Error::internal("sha1 length"))?;
    let mut hashes: Vec<[u8; 24]> = chd
        .metadata
        .iter()
        .filter(|m| m.flags & MDFLAG_CHECKSUM != 0)
        .map(|m| {
            let mut x = [0u8; 24];
            x[..4].copy_from_slice(&m.tag.to_be_bytes());
            x[4..].copy_from_slice(&crate::crypto::sha1(&m.data));
            x
        })
        .collect();
    hashes.sort();
    let mut all = raw.to_vec();
    for x in &hashes {
        all.extend_from_slice(x);
    }
    Ok((raw, crate::crypto::sha1(&all)))
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::MemorySource;
    use std::io::Cursor;
    use std::sync::Arc;

    fn roundtrip(input: ChdInput, expect: &[u8]) -> Arc<ChdFile> {
        let mut c = Cursor::new(Vec::new());
        let job = JobContext::default().with_threads(2);
        let s = write_chd(&input, &ChdWriteOptions::default(), &mut c, &job).unwrap();
        let chd = Arc::new(ChdFile::open(Arc::new(MemorySource::new(c.into_inner())), 1 << 26).unwrap());
        assert_eq!(chd.header.logical_bytes, s.logical_bytes);
        let (raw, sha) = compute_sha1s(&chd, &job).unwrap();
        assert_eq!(raw, chd.header.raw_sha1);
        assert_eq!(sha, chd.header.sha1);
        let src = ChdSource::new(chd.clone());
        let mut got = vec![0u8; expect.len()];
        src.read_exact_at(0, &mut got).unwrap();
        assert_eq!(&got[..], expect);
        chd
    }

    #[test]
    fn dvd_roundtrip_with_dupes() {
        let mut data = vec![0u8; 2048 * 64];
        for (i, b) in data.iter_mut().enumerate().take(2048 * 20) {
            *b = (i * 7 % 253) as u8;
        }
        // random-ish incompressible hunk
        let mut x = 12345u32;
        for b in data[2048 * 40..2048 * 48].iter_mut() {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            *b = (x >> 16) as u8;
        }
        let chd = roundtrip(ChdInput::Dvd(Arc::new(MemorySource::new(data.clone()))), &data);
        assert_eq!(chd.media, ChdMedia::Dvd);
        assert!(chd.map.iter().any(|m| matches!(m, MapEntry::SelfRef { .. })));
    }

    #[test]
    fn cd_roundtrip() {
        let mut t1 = Vec::new();
        for lba in 0..30u32 {
            let mut u = [0u8; 2048];
            u[0] = lba as u8;
            t1.extend(crate::disc::rawcd::make_mode1_sector(lba, &u));
        }
        let t2: Vec<u8> = (0..2352 * 7).map(|i| (i % 256) as u8).collect();
        let input = ChdInput::Cd(vec![
            CdTrackInput {
                mode: TrackMode::Mode1Raw,
                data: Arc::new(MemorySource::new(t1.clone())),
                stored_pregap: 0,
                unstored_pregap: 0,
                postgap: 0,
            },
            CdTrackInput {
                mode: TrackMode::Audio,
                data: Arc::new(MemorySource::new(t2.clone())),
                stored_pregap: 0,
                unstored_pregap: 150,
                postgap: 0,
            },
        ]);
        let mut c = Cursor::new(Vec::new());
        write_chd(&input, &ChdWriteOptions::default(), &mut c, &JobContext::default()).unwrap();
        let chd = Arc::new(ChdFile::open(Arc::new(MemorySource::new(c.into_inner())), 1 << 26).unwrap());
        assert_eq!(chd.tracks.len(), 2);
        assert_eq!(chd.tracks[1].start_frame, 32);
        let a = ChdTrackSource::new(chd.clone(), &chd.tracks[1]);
        let mut got = vec![0u8; t2.len()];
        a.read_exact_at(0, &mut got).unwrap();
        assert_eq!(got, t2);
        let d = ChdTrackSource::new(chd.clone(), &chd.tracks[0]);
        let mut got = vec![0u8; t1.len()];
        d.read_exact_at(0, &mut got).unwrap();
        assert_eq!(got, t1);
    }
}
