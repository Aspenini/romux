//! NCSD (CCI cartridge layout), NCCH (CXI/CFA) headers, ExeFS and RomFS level 3.

use crate::binary::{u16le, u32le, u64le};
use crate::{DataSource, Error, ResourceLimits, Result, SharedSource, SubSource, read_vec};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct NcsdHeader {
    pub image_size: u64,
    pub media_id: u64,
    pub media_unit: u64,
    /// (index, offset, size) in bytes for non-empty partitions.
    pub partitions: Vec<(usize, u64, u64)>,
    pub crypt_types: [u8; 8],
}

impl NcsdHeader {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h = read_vec(s, 0, 0x200, 0x200)?;
        if &h[0x100..0x104] != b"NCSD" {
            return Err(Error::malformed("missing NCSD magic"));
        }
        let mu = 0x200u64 << h[0x188 + 6].min(8);
        let mut parts = Vec::new();
        let len = s.len()?;
        for i in 0..8 {
            let off = u32le(&h, 0x120 + i * 8)? as u64 * mu;
            let size = u32le(&h, 0x124 + i * 8)? as u64 * mu;
            if size == 0 {
                continue;
            }
            if off + size > len {
                return Err(Error::bounds(format!("NCSD partition {i} extends beyond the image")));
            }
            parts.push((i, off, size));
        }
        Ok(NcsdHeader {
            image_size: u32le(&h, 0x104)? as u64 * mu,
            media_id: u64le(&h, 0x108)?,
            media_unit: mu,
            partitions: parts,
            crypt_types: crate::binary::array(&h, 0x118)?,
        })
    }
}

pub fn partition_name(i: usize) -> &'static str {
    match i {
        0 => "game",
        1 => "manual",
        2 => "download-play",
        6 => "new3ds-update",
        7 => "update",
        _ => "partition",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NcchHeader {
    pub content_size: u64,
    pub partition_id: u64,
    pub maker_code: String,
    pub version: u16,
    pub program_id: u64,
    pub product_code: String,
    pub exheader_size: u32,
    pub flags: [u8; 8],
    pub media_unit: u64,
    pub exefs: (u64, u64, u64),
    pub romfs: (u64, u64, u64),
    #[serde(skip)]
    pub exefs_hash: [u8; 32],
    #[serde(skip)]
    pub romfs_hash: [u8; 32],
    #[serde(skip)]
    pub exheader_hash: [u8; 32],
}

impl NcchHeader {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h = read_vec(s, 0, 0x200, 0x200)?;
        if &h[0x100..0x104] != b"NCCH" {
            return Err(Error::malformed("missing NCCH magic"));
        }
        let flags: [u8; 8] = crate::binary::array(&h, 0x188)?;
        let mu = 0x200u64 << flags[6].min(8);
        let r = |o: usize| -> Result<(u64, u64, u64)> {
            Ok((u32le(&h, o)? as u64 * mu, u32le(&h, o + 4)? as u64 * mu, u32le(&h, o + 8)? as u64 * mu))
        };
        let hdr = NcchHeader {
            content_size: u32le(&h, 0x104)? as u64 * mu,
            partition_id: u64le(&h, 0x108)?,
            maker_code: crate::binary::ascii_z(&h[0x110..0x112]),
            version: u16le(&h, 0x112)?,
            program_id: u64le(&h, 0x118)?,
            product_code: crate::binary::ascii_z(&h[0x150..0x160]),
            exheader_size: u32le(&h, 0x180)?,
            flags,
            media_unit: mu,
            exefs: r(0x1A0)?,
            romfs: r(0x1B0)?,
            exefs_hash: crate::binary::array(&h, 0x1C0)?,
            romfs_hash: crate::binary::array(&h, 0x1E0)?,
            exheader_hash: crate::binary::array(&h, 0x160)?,
        };
        let len = s.len()?;
        for (o, z, _) in [hdr.exefs, hdr.romfs] {
            if z > 0 && o + z > len {
                return Err(Error::bounds("NCCH region extends beyond the content"));
            }
        }
        Ok(hdr)
    }
    pub fn no_crypto(&self) -> bool {
        self.flags[7] & 0x4 != 0
    }
    pub fn content_type(&self) -> &'static str {
        let t = self.flags[5];
        if t & 0x2 != 0 {
            "executable (CXI)"
        } else if t & 0x8 == 0x8 {
            "manual (CFA)"
        } else if t & 0x4 != 0 {
            "system update (CFA)"
        } else {
            "data (CFA)"
        }
    }
}

/// ExeFS: header of 10 file slots + SHA-256 table; data begins at 0x200.
#[derive(Debug, Clone, Serialize)]
pub struct ExefsFile {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    #[serde(skip)]
    pub hash: [u8; 32],
}

pub fn parse_exefs(s: &dyn DataSource) -> Result<Vec<ExefsFile>> {
    let h = read_vec(s, 0, 0x200, 0x200)?;
    let len = s.len()?;
    let mut out = Vec::new();
    for i in 0..10 {
        let e = &h[i * 16..i * 16 + 16];
        if e[..8].iter().all(|b| *b == 0) {
            continue;
        }
        let name = crate::binary::ascii_z(&e[..8]);
        let offset = 0x200 + u32le(e, 8)? as u64;
        let size = u32le(e, 12)? as u64;
        if offset + size > len {
            return Err(Error::bounds(format!("ExeFS file {name} extends beyond the ExeFS")));
        }
        let hash = crate::binary::array(&h, 0xC0 + (9 - i) * 32)?;
        out.push(ExefsFile { name, offset, size, hash });
    }
    Ok(out)
}

/// RomFS file.
#[derive(Debug, Clone)]
pub struct RomfsFile {
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

/// Locate the level-3 data of an IVFC RomFS and list files (UTF-16 names).
pub fn parse_romfs(s: &dyn DataSource, limits: &ResourceLimits) -> Result<(u64, Vec<RomfsFile>)> {
    let ivfc = read_vec(s, 0, 0x60, 0x60)?;
    if &ivfc[..4] != b"IVFC" || u32le(&ivfc, 4)? != 0x10000 {
        return Err(Error::malformed("RomFS IVFC header missing"));
    }
    let master = u32le(&ivfc, 8)? as u64;
    let l3_block = 1u64 << u32le(&ivfc, 0x4C)?.min(20);
    let l3 = crate::binary::align_up(0x60 + master, l3_block)?;
    let h = read_vec(s, l3, 0x28, 0x28)?;
    if u32le(&h, 0)? != 0x28 {
        return Err(Error::malformed("RomFS level-3 header length is not 0x28"));
    }
    let g = |o| -> Result<u64> { Ok(u32le(&h, o)? as u64) };
    let dmeta = read_vec(s, l3 + g(12)?, g(16)?, limits.max_metadata)?;
    let fmeta = read_vec(s, l3 + g(28)?, g(32)?, limits.max_metadata)?;
    let data = l3 + g(36)?;
    let len = s.len()?;
    let mut files = Vec::new();
    let mut stack = vec![(0u32, String::new(), 0u32)];
    let mut seen = std::collections::HashSet::new();
    const NONE: u32 = 0xFFFF_FFFF;
    while let Some((d, prefix, depth)) = stack.pop() {
        if depth > limits.max_depth || !seen.insert(d) {
            return Err(Error::malformed("RomFS directory loop or nesting too deep"));
        }
        let e = d as usize;
        let mut child = u32le(&dmeta, e + 8)?;
        let mut file = u32le(&dmeta, e + 12)?;
        let mut fseen = 0usize;
        while file != NONE {
            fseen += 1;
            if fseen as u64 > limits.max_entries {
                return Err(Error::limit("too many RomFS files"));
            }
            let f = file as usize;
            let off = u64le(&fmeta, f + 8)?;
            let size = u64le(&fmeta, f + 16)?;
            let nl = u32le(&fmeta, f + 28)? as usize;
            let name = crate::binary::utf16le_z(crate::binary::slice(&fmeta, f + 32, nl)?);
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            if data + off + size > len {
                return Err(Error::bounds(format!("RomFS file {path} extends beyond the RomFS")));
            }
            files.push(RomfsFile { path, offset: data + off, size });
            file = u32le(&fmeta, f + 4)?;
        }
        while child != NONE {
            let c = child as usize;
            let nl = u32le(&dmeta, c + 20)? as usize;
            let name = crate::binary::utf16le_z(crate::binary::slice(&dmeta, c + 24, nl)?);
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            stack.push((child, path, depth + 1));
            child = u32le(&dmeta, c + 4)?;
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((l3, files))
}

/// Region view helper.
pub fn region(src: &SharedSource, off: u64, len: u64) -> Result<SharedSource> {
    SubSource::shared(src.clone(), off, len)
}
