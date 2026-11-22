//! CHD ("Compressed Hunks of Data") container: v3/v4/v5 reading, v5 writing.
//!
//! Supported hunk codecs: `zlib`, `zstd` (feature), `lzma` (feature `chd`), `huff`, and the
//! CD wrappers `cdzl`, `cdzs`, `cdlz` (with ECC/sync regeneration), and the FLAC codecs
//! `flac` and `cdfl` (CD audio). A/V codecs (`avhu`) are detected and reported as
//! unsupported per hunk.
//! Parent (differencing) CHDs are represented explicitly and resolved only when the parent
//! file is supplied or found alongside the child with a matching SHA-1.

pub mod flac;
pub mod huffman;
pub mod writer;

use crate::binary::{u16be, u32be, u64be, uint_be};
use crate::compression::{Codec, decompress};
use crate::disc::rawcd::TrackMode;
use crate::{DataSource, Error, ErrorCode, Result, SharedSource, hex, read_vec};
use std::sync::{Arc, Mutex};

pub const MAGIC: &[u8; 8] = b"MComprHD";
pub const CD_FRAME: u64 = 2448;
pub const CD_SECTOR: u64 = 2352;
pub const CD_TRACK_PADDING: u64 = 4;
pub const MDFLAG_CHECKSUM: u8 = 0x01;

pub fn tag(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

pub fn tag_str(t: u32) -> String {
    let b = t.to_be_bytes();
    if b.iter().all(|c| c.is_ascii_graphic() || *c == b' ') { String::from_utf8_lossy(&b).into_owned() } else { format!("0x{t:08x}") }
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) as used by CHD maps and hunks.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChdHeader {
    pub version: u32,
    pub header_len: u32,
    pub compressors: [u32; 4],
    pub logical_bytes: u64,
    pub map_offset: u64,
    pub meta_offset: u64,
    pub hunk_bytes: u32,
    pub unit_bytes: u32,
    pub hunk_count: u32,
    #[serde(serialize_with = "ser_hex20")]
    pub raw_sha1: [u8; 20],
    #[serde(serialize_with = "ser_hex20")]
    pub sha1: [u8; 20],
    #[serde(serialize_with = "ser_hex20")]
    pub parent_sha1: [u8; 20],
    /// v3/v4 whole-file compression type.
    pub v34_compression: u32,
}

fn ser_hex20<S: serde::Serializer>(v: &[u8; 20], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex(v))
}

impl ChdHeader {
    pub fn has_parent(&self) -> bool {
        self.parent_sha1 != [0u8; 20]
    }
    pub fn compressor_names(&self) -> Vec<String> {
        if self.version >= 5 {
            self.compressors.iter().filter(|c| **c != 0).map(|c| tag_str(*c)).collect()
        } else {
            vec![match self.v34_compression {
                0 => "none".into(),
                1 | 2 => "zlib".into(),
                3 => "av".into(),
                n => format!("unknown({n})"),
            }]
        }
    }

    pub fn parse(h: &[u8]) -> Result<Self> {
        if h.len() < 16 || &h[..8] != MAGIC {
            return Err(Error::malformed("missing CHD signature"));
        }
        let header_len = u32be(h, 8)?;
        let version = u32be(h, 12)?;
        match version {
            5 => {
                if header_len < 124 || h.len() < 124 {
                    return Err(Error::malformed("CHD v5 header too short"));
                }
                let compressors = [u32be(h, 16)?, u32be(h, 20)?, u32be(h, 24)?, u32be(h, 28)?];
                let logical_bytes = u64be(h, 32)?;
                let hunk_bytes = u32be(h, 56)?;
                let unit_bytes = u32be(h, 60)?;
                if hunk_bytes == 0 || unit_bytes == 0 || hunk_bytes % unit_bytes != 0 {
                    return Err(Error::malformed("invalid CHD hunk/unit size"));
                }
                let hunk_count = logical_bytes.div_ceil(hunk_bytes as u64);
                if hunk_count > u32::MAX as u64 {
                    return Err(Error::malformed("CHD hunk count overflow"));
                }
                Ok(ChdHeader {
                    version,
                    header_len,
                    compressors,
                    logical_bytes,
                    map_offset: u64be(h, 40)?,
                    meta_offset: u64be(h, 48)?,
                    hunk_bytes,
                    unit_bytes,
                    hunk_count: hunk_count as u32,
                    raw_sha1: crate::binary::array(h, 64)?,
                    sha1: crate::binary::array(h, 84)?,
                    parent_sha1: crate::binary::array(h, 104)?,
                    v34_compression: 0,
                })
            }
            3 | 4 => {
                let need = if version == 3 { 120 } else { 108 };
                if h.len() < need {
                    return Err(Error::malformed("CHD v3/v4 header too short"));
                }
                let compression = u32be(h, 20)?;
                let total_hunks = u32be(h, 24)?;
                let logical_bytes = u64be(h, 28)?;
                let meta_offset = u64be(h, 36)?;
                let (hunk_bytes, sha1, parent_sha1, raw_sha1) = if version == 3 {
                    (u32be(h, 76)?, crate::binary::array(h, 80)?, crate::binary::array(h, 100)?, [0u8; 20])
                } else {
                    (u32be(h, 44)?, crate::binary::array(h, 48)?, crate::binary::array(h, 68)?, crate::binary::array(h, 88)?)
                };
                if hunk_bytes == 0 {
                    return Err(Error::malformed("invalid CHD hunk size"));
                }
                Ok(ChdHeader {
                    version,
                    header_len,
                    compressors: [0; 4],
                    logical_bytes,
                    map_offset: header_len as u64,
                    meta_offset,
                    hunk_bytes,
                    unit_bytes: hunk_bytes,
                    hunk_count: total_hunks,
                    raw_sha1,
                    sha1,
                    parent_sha1,
                    v34_compression: compression,
                })
            }
            v => Err(Error::unsupported(format!("CHD version {v} is not supported"))),
        }
    }
}

/// Decoded map entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapEntry {
    /// Compressed with compressor `codec` (index into header compressors, or v3/v4 zlib).
    Compressed {
        codec: u8,
        offset: u64,
        length: u32,
        crc: Option<u32>,
    },
    Uncompressed {
        offset: u64,
        crc: Option<u32>,
    },
    /// v3/v4 "mini" hunk: an 8-byte value repeated.
    Mini {
        value: u64,
    },
    SelfRef {
        hunk: u64,
    },
    /// Offset in parent units (v5) or parent hunk (v3/v4, converted to units).
    ParentRef {
        unit: u64,
    },
    /// No data stored (zero-filled, or from parent when present).
    Unallocated,
}

pub const V5_TYPE_NONE: u8 = 4;
pub const V5_SELF: u8 = 5;
pub const V5_PARENT: u8 = 6;
pub const V5_RLE_SMALL: u8 = 7;
pub const V5_RLE_LARGE: u8 = 8;
pub const V5_SELF_0: u8 = 9;
pub const V5_SELF_1: u8 = 10;
pub const V5_PARENT_SELF: u8 = 11;
pub const V5_PARENT_0: u8 = 12;
pub const V5_PARENT_1: u8 = 13;

fn decode_v5_map(src: &dyn DataSource, h: &ChdHeader, max_meta: u64) -> Result<Vec<MapEntry>> {
    let hc = h.hunk_count as usize;
    if h.compressors[0] == 0 {
        let raw = read_vec(src, h.map_offset, hc as u64 * 4, max_meta)?;
        return Ok((0..hc)
            .map(|i| {
                let v = u32::from_be_bytes([raw[i * 4], raw[i * 4 + 1], raw[i * 4 + 2], raw[i * 4 + 3]]) as u64;
                if v == 0 { MapEntry::Unallocated } else { MapEntry::Uncompressed { offset: v * h.hunk_bytes as u64, crc: None } }
            })
            .collect());
    }
    let mh = read_vec(src, h.map_offset, 16, 16)?;
    let map_bytes = u32be(&mh, 0)? as u64;
    let first_offs = uint_be(&mh, 4, 6)?;
    let map_crc = u16be(&mh, 10)?;
    let length_bits = mh[12] as u32;
    let self_bits = mh[13] as u32;
    let parent_bits = mh[14] as u32;
    if length_bits > 32 || self_bits > 32 || parent_bits > 32 {
        return Err(Error::malformed("CHD map bit widths are invalid"));
    }
    let comp = read_vec(src, h.map_offset + 16, map_bytes, max_meta)?;
    let mut br = huffman::BitReader::new(&comp);
    let mut dec = huffman::HuffDecoder::new(16, 8);
    dec.import_tree_rle(&mut br)?;
    let mut types = vec![0u8; hc];
    let mut last = 0u8;
    let mut rep = 0u32;
    for t in types.iter_mut() {
        if rep > 0 {
            *t = last;
            rep -= 1;
        } else {
            let v = dec.decode_one(&mut br) as u8;
            if v == V5_RLE_SMALL {
                *t = last;
                rep = 2 + dec.decode_one(&mut br);
            } else if v == V5_RLE_LARGE {
                *t = last;
                rep = 2 + 16 + (dec.decode_one(&mut br) << 4);
                rep += dec.decode_one(&mut br);
            } else {
                *t = v;
                last = v;
            }
        }
    }
    let mut cur = first_offs;
    let mut last_self = 0u64;
    let mut last_parent = 0u64;
    let mut out = Vec::with_capacity(hc);
    let mut rawmap = Vec::with_capacity(hc * 12);
    for (i, &t) in types.iter().enumerate() {
        let (stored_type, length, offset, crc): (u8, u32, u64, u16);
        let entry = match t {
            0..=3 => {
                length = br.read(length_bits);
                offset = cur;
                cur += length as u64;
                crc = br.read(16) as u16;
                stored_type = t;
                MapEntry::Compressed { codec: t, offset, length, crc: Some(crc as u32) }
            }
            V5_TYPE_NONE => {
                length = h.hunk_bytes;
                offset = cur;
                cur += length as u64;
                crc = br.read(16) as u16;
                stored_type = t;
                MapEntry::Uncompressed { offset, crc: Some(crc as u32) }
            }
            V5_SELF => {
                last_self = br.read(self_bits) as u64;
                offset = last_self;
                length = 0;
                crc = 0;
                stored_type = V5_SELF;
                MapEntry::SelfRef { hunk: offset }
            }
            V5_PARENT => {
                last_parent = br.read(parent_bits) as u64;
                offset = last_parent;
                length = 0;
                crc = 0;
                stored_type = V5_PARENT;
                MapEntry::ParentRef { unit: offset }
            }
            V5_SELF_1 | V5_SELF_0 => {
                if t == V5_SELF_1 {
                    last_self += 1;
                }
                offset = last_self;
                length = 0;
                crc = 0;
                stored_type = V5_SELF;
                MapEntry::SelfRef { hunk: offset }
            }
            V5_PARENT_SELF => {
                last_parent = (i as u64 * h.hunk_bytes as u64) / h.unit_bytes as u64;
                offset = last_parent;
                length = 0;
                crc = 0;
                stored_type = V5_PARENT;
                MapEntry::ParentRef { unit: offset }
            }
            V5_PARENT_1 | V5_PARENT_0 => {
                if t == V5_PARENT_1 {
                    last_parent += (h.hunk_bytes / h.unit_bytes) as u64;
                }
                offset = last_parent;
                length = 0;
                crc = 0;
                stored_type = V5_PARENT;
                MapEntry::ParentRef { unit: offset }
            }
            other => return Err(Error::malformed(format!("invalid CHD map entry type {other} at hunk {i}"))),
        };
        rawmap.push(stored_type);
        rawmap.extend_from_slice(&length.to_be_bytes()[1..]);
        rawmap.extend_from_slice(&offset.to_be_bytes()[2..]);
        rawmap.extend_from_slice(&crc.to_be_bytes());
        out.push(entry);
    }
    if br.overflow {
        return Err(Error::malformed("CHD compressed map truncated"));
    }
    if crc16(&rawmap) != map_crc {
        return Err(Error::integrity("CHD map CRC mismatch"));
    }
    Ok(out)
}

fn decode_v34_map(src: &dyn DataSource, h: &ChdHeader, max_meta: u64) -> Result<Vec<MapEntry>> {
    let hc = h.hunk_count as usize;
    let raw = read_vec(src, h.map_offset, hc as u64 * 16, max_meta)?;
    let mut out = Vec::with_capacity(hc);
    for i in 0..hc {
        let e = &raw[i * 16..i * 16 + 16];
        let offset = u64be(e, 0)?;
        let crc = u32be(e, 8)?;
        let length = u16be(e, 12)? as u32 | ((e[14] as u32) << 16);
        let flags = e[15] & 0x0f;
        out.push(match flags {
            1 => MapEntry::Compressed { codec: 0, offset, length, crc: Some(crc) },
            2 => MapEntry::Uncompressed { offset, crc: Some(crc) },
            3 => MapEntry::Mini { value: offset },
            4 => MapEntry::SelfRef { hunk: offset },
            5 => MapEntry::ParentRef { unit: offset },
            6 => MapEntry::Compressed { codec: 0, offset, length, crc: Some(crc) },
            0 => MapEntry::Unallocated,
            f => return Err(Error::malformed(format!("invalid v3/v4 map entry type {f} at hunk {i}"))),
        });
    }
    Ok(out)
}

/// A metadata entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetaEntry {
    #[serde(serialize_with = "ser_tag")]
    pub tag: u32,
    pub flags: u8,
    #[serde(skip)]
    pub data: Vec<u8>,
    pub text: Option<String>,
}

fn ser_tag<S: serde::Serializer>(t: &u32, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&tag_str(*t))
}

fn read_metadata(src: &dyn DataSource, mut off: u64, max: u64) -> Result<Vec<MetaEntry>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while off != 0 {
        if !seen.insert(off) || out.len() > 4096 {
            return Err(Error::malformed("CHD metadata chain loops"));
        }
        let h = read_vec(src, off, 16, 16)?;
        let tag = u32be(&h, 0)?;
        let flags = h[4];
        let len = uint_be(&h, 5, 3)?;
        let next = u64be(&h, 8)?;
        let data = read_vec(src, off + 16, len, max)?;
        let text = if data.iter().all(|b| b.is_ascii() && (*b >= 0x20 || *b == 0 || *b == b'\n')) {
            Some(String::from_utf8_lossy(&data).trim_end_matches('\0').to_string())
        } else {
            None
        };
        out.push(MetaEntry { tag, flags, data, text });
        off = next;
    }
    Ok(out)
}

/// A CD track described by CHD metadata.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChdTrack {
    pub number: u32,
    pub mode: TrackMode,
    pub mode_name: String,
    pub subtype: String,
    pub frames: u64,
    pub pregap: u64,
    pub pregap_type: String,
    pub postgap: u64,
    /// First frame of the track within the CHD logical frame space.
    pub start_frame: u64,
}

impl ChdTrack {
    /// Whether pregap frames are stored inside `frames` (PGTYPE prefixed with 'V').
    pub fn pregap_stored(&self) -> bool {
        self.pregap_type.starts_with('V')
    }
}

fn parse_track_text(s: &str) -> Option<(u32, String, String, u64, u64, String, u64)> {
    let mut number = None;
    let mut ty = None;
    let mut sub = "NONE".to_string();
    let mut frames = None;
    let mut pregap = 0;
    let mut pgtype = String::new();
    let mut postgap = 0;
    for tok in s.split_whitespace() {
        let (k, v) = tok.split_once(':')?;
        match k {
            "TRACK" => number = v.parse().ok(),
            "TYPE" => ty = Some(v.to_string()),
            "SUBTYPE" => sub = v.to_string(),
            "FRAMES" => frames = v.parse().ok(),
            "PREGAP" => pregap = v.parse().unwrap_or(0),
            "PGTYPE" => pgtype = v.to_string(),
            "POSTGAP" => postgap = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some((number?, ty?, sub, frames?, pregap, pgtype, postgap))
}

/// Media kind derived from metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChdMedia {
    Cd,
    Gd,
    Dvd,
    HardDisk,
    Laserdisc,
    Raw,
}

struct HunkCache {
    hunk: u32,
    data: Vec<u8>,
}

/// An opened CHD file.
pub struct ChdFile {
    src: SharedSource,
    pub header: ChdHeader,
    pub map: Vec<MapEntry>,
    pub metadata: Vec<MetaEntry>,
    pub media: ChdMedia,
    pub tracks: Vec<ChdTrack>,
    parent: Option<Arc<ChdFile>>,
    cache: Mutex<Option<HunkCache>>,
}

impl ChdFile {
    pub fn open(src: SharedSource, max_meta: u64) -> Result<Self> {
        let h = read_vec(src.as_ref(), 0, 124.min(src.len()?), 124)?;
        let header = ChdHeader::parse(&h)?;
        let total = src.len()?;
        if header.map_offset >= total {
            return Err(Error::bounds("CHD map offset beyond end of file"));
        }
        let map = if header.version >= 5 {
            decode_v5_map(src.as_ref(), &header, max_meta)?
        } else {
            decode_v34_map(src.as_ref(), &header, max_meta)?
        };
        let metadata = if header.meta_offset != 0 { read_metadata(src.as_ref(), header.meta_offset, max_meta)? } else { vec![] };
        let mut media = ChdMedia::Raw;
        let mut tracks = Vec::new();
        let mut frame = 0u64;
        for m in &metadata {
            match &m.tag.to_be_bytes() {
                b"CHT2" | b"CHTR" | b"CHGT" => {
                    media = if &m.tag.to_be_bytes() == b"CHGT" { ChdMedia::Gd } else { ChdMedia::Cd };
                    let t = m
                        .text
                        .as_deref()
                        .and_then(parse_track_text)
                        .ok_or_else(|| Error::malformed("unparseable CHD CD track metadata"))?;
                    let mode =
                        TrackMode::from_chd(&t.1).ok_or_else(|| Error::unsupported(format!("CHD track type {} is not supported", t.1)))?;
                    tracks.push(ChdTrack {
                        number: t.0,
                        mode,
                        mode_name: t.1,
                        subtype: t.2,
                        frames: t.3,
                        pregap: t.4,
                        pregap_type: t.5,
                        postgap: t.6,
                        start_frame: frame,
                    });
                    frame += t.3 + (CD_TRACK_PADDING - t.3 % CD_TRACK_PADDING) % CD_TRACK_PADDING;
                }
                b"CHCD" => {
                    media = ChdMedia::Cd;
                }
                b"DVD " => media = ChdMedia::Dvd,
                b"GDDD" => media = ChdMedia::HardDisk,
                b"AVAV" | b"AVLD" => media = ChdMedia::Laserdisc,
                _ => {}
            }
        }
        Ok(ChdFile { src, header, map, metadata, media, tracks, parent: None, cache: Mutex::new(None) })
    }

    /// Attach the parent CHD. Fails unless the parent's SHA-1 matches.
    pub fn set_parent(&mut self, parent: Arc<ChdFile>) -> Result<()> {
        if parent.header.sha1 != self.header.parent_sha1 {
            return Err(Error::new(ErrorCode::IncompatibleTitles, "parent CHD SHA-1 does not match child's parent reference"));
        }
        self.parent = Some(parent);
        Ok(())
    }

    pub fn has_parent_attached(&self) -> bool {
        self.parent.is_some()
    }

    pub fn needs_parent(&self) -> bool {
        self.header.has_parent() && self.map.iter().any(|e| matches!(e, MapEntry::ParentRef { .. } | MapEntry::Unallocated))
    }

    fn codec_tag(&self, idx: u8) -> u32 {
        if self.header.version >= 5 { self.header.compressors.get(idx as usize).copied().unwrap_or(0) } else { tag(b"zlib") }
    }

    /// Codecs referenced by hunks that this build cannot decode.
    pub fn unsupported_codecs(&self) -> Vec<String> {
        let mut out = Vec::new();
        for c in self.header.compressors.iter().filter(|c| **c != 0) {
            if !codec_supported(*c) {
                out.push(tag_str(*c));
            }
        }
        out
    }

    fn lzma_dict(len: usize) -> u32 {
        (len.max(4096) as u32).next_power_of_two()
    }

    fn decode_codec(&self, ctag: u32, src: &[u8], out_len: usize) -> Result<Vec<u8>> {
        let lim = out_len;
        match &ctag.to_be_bytes() {
            b"zlib" => decompress(Codec::Deflate, src, Some(out_len), lim),
            b"zstd" => decompress(Codec::Zstd, src, Some(out_len), lim),
            b"lzma" => decompress(Codec::Lzma { lc: 3, lp: 0, pb: 2, dict_size: Self::lzma_dict(out_len) }, src, Some(out_len), lim),
            b"huff" => huffman::decode_huff8(src, out_len),
            b"flac" => flac::decode_chd_flac(src, out_len),
            b"cdfl" => Self::decode_cdfl(src, out_len),
            b"cdzl" | b"cdlz" | b"cdzs" => self.decode_cd(ctag, src, out_len),
            _ => Err(Error::unsupported(format!("CHD codec {} is not supported by this build", tag_str(ctag)))),
        }
    }

    /// `cdfl`: FLAC-coded big-endian CD audio for every frame, then raw-deflate subcode.
    fn decode_cdfl(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
        let frames = out_len / CD_FRAME as usize;
        let (pcm, used) = flac::decode_stereo16(src, frames * CD_SECTOR as usize / 4)?;
        let sub_out = frames * 96;
        let sub_src = &src[used.min(src.len())..];
        let sub = if sub_src.is_empty() { vec![0u8; sub_out] } else { decompress(Codec::Deflate, sub_src, Some(sub_out), sub_out)? };
        if sub.len() != sub_out {
            return Err(Error::codec("cdfl subcode length mismatch"));
        }
        let mut out = vec![0u8; out_len];
        for f in 0..frames {
            let o = f * CD_FRAME as usize;
            for (i, s) in pcm[f * CD_SECTOR as usize / 2..(f + 1) * CD_SECTOR as usize / 2].iter().enumerate() {
                out[o + i * 2..o + i * 2 + 2].copy_from_slice(&s.to_be_bytes());
            }
            out[o + CD_SECTOR as usize..o + CD_FRAME as usize].copy_from_slice(&sub[f * 96..(f + 1) * 96]);
        }
        Ok(out)
    }

    fn decode_cd(&self, ctag: u32, src: &[u8], out_len: usize) -> Result<Vec<u8>> {
        let frames = out_len / CD_FRAME as usize;
        let complen_bytes = if out_len < 65536 { 2 } else { 3 };
        let ecc_bytes = frames.div_ceil(8);
        let header_bytes = ecc_bytes + complen_bytes;
        if src.len() < header_bytes {
            return Err(Error::codec("CD hunk header truncated"));
        }
        let mut base_len = ((src[ecc_bytes] as usize) << 8) | src[ecc_bytes + 1] as usize;
        if complen_bytes > 2 {
            base_len = (base_len << 8) | src[ecc_bytes + 2] as usize;
        }
        if header_bytes + base_len > src.len() {
            return Err(Error::codec("CD hunk base length exceeds hunk"));
        }
        let base_out = frames * CD_SECTOR as usize;
        let sub_out = frames * 96;
        let (base_codec, sub_codec) = match &ctag.to_be_bytes() {
            b"cdzl" => (tag(b"zlib"), tag(b"zlib")),
            b"cdlz" => (tag(b"lzma"), tag(b"zlib")),
            _ => (tag(b"zstd"), tag(b"zstd")),
        };
        let base = self.decode_codec(base_codec, &src[header_bytes..header_bytes + base_len], base_out)?;
        let sub_src = &src[header_bytes + base_len..];
        let sub = if sub_src.is_empty() && sub_out > 0 { vec![0u8; sub_out] } else { self.decode_codec(sub_codec, sub_src, sub_out)? };
        let mut out = vec![0u8; out_len];
        for f in 0..frames {
            let o = f * CD_FRAME as usize;
            out[o..o + CD_SECTOR as usize].copy_from_slice(&base[f * CD_SECTOR as usize..(f + 1) * CD_SECTOR as usize]);
            out[o + CD_SECTOR as usize..o + CD_FRAME as usize].copy_from_slice(&sub[f * 96..(f + 1) * 96]);
            if src[f / 8] & (1 << (f % 8)) != 0 {
                let s = &mut out[o..o + CD_SECTOR as usize];
                s[..12].copy_from_slice(&crate::disc::rawcd::SYNC);
                crate::disc::rawcd::ecc_generate(s);
            }
        }
        Ok(out)
    }

    fn read_hunk_uncached(&self, hunk: u32, depth: u32) -> Result<Vec<u8>> {
        if depth > 16 {
            return Err(Error::malformed("CHD self-reference chain too deep"));
        }
        let hb = self.header.hunk_bytes as usize;
        let e = *self.map.get(hunk as usize).ok_or_else(|| Error::bounds(format!("hunk {hunk} beyond map")))?;
        let data = match e {
            MapEntry::Compressed { codec, offset, length, crc } => {
                let comp = read_vec(self.src.as_ref(), offset, length as u64, hb as u64 * 2 + 4096)?;
                let d = self.decode_codec(self.codec_tag(codec), &comp, hb).map_err(|e| e.with_offset(offset))?;
                self.check_crc(hunk, &d, crc)?;
                d
            }
            MapEntry::Uncompressed { offset, crc } => {
                let d = read_vec(self.src.as_ref(), offset, hb as u64, hb as u64)?;
                self.check_crc(hunk, &d, crc)?;
                d
            }
            MapEntry::Mini { value } => {
                let b = value.to_be_bytes();
                (0..hb).map(|i| b[i % 8]).collect()
            }
            MapEntry::SelfRef { hunk: h } => {
                if h >= hunk as u64 && self.header.version >= 5 {
                    return Err(Error::malformed(format!("hunk {hunk} references a later hunk {h}")));
                }
                self.read_hunk_uncached(h as u32, depth + 1)?
            }
            MapEntry::ParentRef { unit } => {
                let p = self.parent.as_ref().ok_or_else(|| {
                    Error::new(ErrorCode::InvalidArgument, "hunk data lives in a parent CHD that was not supplied")
                        .with_suggestion("place the parent CHD next to this file or pass it with --parent")
                })?;
                let off = if self.header.version >= 5 { unit * self.header.unit_bytes as u64 } else { unit * hb as u64 };
                let mut d = vec![0u8; hb];
                ChdSource::new(p.clone()).read_exact_at(off, &mut d)?;
                d
            }
            MapEntry::Unallocated => match &self.parent {
                Some(p) => {
                    let mut d = vec![0u8; hb];
                    ChdSource::new(p.clone()).read_exact_at(hunk as u64 * hb as u64, &mut d)?;
                    d
                }
                None => vec![0u8; hb],
            },
        };
        Ok(data)
    }

    fn check_crc(&self, hunk: u32, d: &[u8], crc: Option<u32>) -> Result<()> {
        if let Some(c) = crc {
            let ok = if self.header.version >= 5 { crc16(d) as u32 == c } else { crate::crypto::crc32(d) == c };
            if !ok {
                return Err(Error::integrity(format!("CHD hunk {hunk} CRC mismatch")));
            }
        }
        Ok(())
    }

    fn with_hunk<R>(&self, hunk: u32, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        {
            let c = self.cache.lock().map_err(|_| Error::internal("CHD cache poisoned"))?;
            if let Some(hc) = c.as_ref() {
                if hc.hunk == hunk {
                    return Ok(f(&hc.data));
                }
            }
        }
        let d = self.read_hunk_uncached(hunk, 0)?;
        let r = f(&d);
        if let Ok(mut c) = self.cache.lock() {
            *c = Some(HunkCache { hunk, data: d });
        }
        Ok(r)
    }

    pub fn source(&self) -> &SharedSource {
        &self.src
    }
}

/// Whether a codec tag is decodable by this build.
pub fn codec_supported(t: u32) -> bool {
    match &t.to_be_bytes() {
        b"zlib" | b"huff" | b"cdzl" | b"flac" | b"cdfl" => true,
        b"zstd" | b"cdzs" => Codec::Zstd.can_decode(),
        b"lzma" | b"cdlz" => Codec::Lzma { lc: 3, lp: 0, pb: 2, dict_size: 1 << 16 }.can_decode(),
        _ => false,
    }
}

/// Logical-byte view of a CHD.
#[derive(Clone)]
pub struct ChdSource {
    chd: Arc<ChdFile>,
}

impl ChdSource {
    pub fn new(chd: Arc<ChdFile>) -> Self {
        ChdSource { chd }
    }
}

impl DataSource for ChdSource {
    fn len(&self) -> Result<u64> {
        Ok(self.chd.header.logical_bytes)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.chd.header.logical_bytes)?;
        let hb = self.chd.header.hunk_bytes as u64;
        while !out.is_empty() {
            let hunk = (offset / hb) as u32;
            let within = (offset % hb) as usize;
            let n = (hb as usize - within).min(out.len());
            let (head, tail) = std::mem::take(&mut out).split_at_mut(n);
            self.chd.with_hunk(hunk, |d| head.copy_from_slice(&d[within..within + n]))?;
            out = tail;
            offset += n as u64;
        }
        Ok(())
    }
    fn identity(&self) -> crate::SourceIdentity {
        self.chd.src.identity()
    }
}

/// View of one CD track as stored sectors of the track mode's size (subcode stripped,
/// audio byte-swapped back to little-endian as in BIN files).
pub struct ChdTrackSource {
    chd: ChdSource,
    start_frame: u64,
    frames: u64,
    sector_size: u64,
    swap: bool,
}

impl ChdTrackSource {
    pub fn new(chd: Arc<ChdFile>, track: &ChdTrack) -> Self {
        ChdTrackSource {
            chd: ChdSource::new(chd),
            start_frame: track.start_frame,
            frames: track.frames,
            sector_size: track.mode.sector_size().min(CD_SECTOR),
            swap: track.mode == TrackMode::Audio,
        }
    }
}

impl DataSource for ChdTrackSource {
    fn len(&self) -> Result<u64> {
        Ok(self.frames * self.sector_size)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        let ss = self.sector_size;
        crate::check_range(offset, out.len() as u64, self.frames * ss)?;
        let mut sector = vec![0u8; ss as usize];
        while !out.is_empty() {
            let f = offset / ss;
            let within = (offset % ss) as usize;
            self.chd.read_exact_at((self.start_frame + f) * CD_FRAME, &mut sector)?;
            if self.swap {
                for p in sector.chunks_exact_mut(2) {
                    p.swap(0, 1);
                }
            }
            let n = (ss as usize - within).min(out.len());
            out[..n].copy_from_slice(&sector[within..within + n]);
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}
