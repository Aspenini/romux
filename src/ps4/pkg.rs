//! PS4 PKG header and entry table (big-endian).

use crate::binary::{u32be, u64be};
use crate::ps4::entries;
use crate::{DataSource, Error, ResourceLimits, Result, SharedSource, SubSource, read_vec};
use serde::Serialize;

pub const MAGIC: &[u8; 4] = b"\x7FCNT";

#[derive(Debug, Clone, Serialize)]
pub struct PkgHeader {
    pub pkg_type: u32,
    pub file_count: u32,
    pub entry_count: u32,
    pub table_offset: u32,
    pub body_offset: u64,
    pub body_size: u64,
    pub content_offset: u64,
    pub content_size: u64,
    pub content_id: String,
    pub drm_type: u32,
    pub content_type: u32,
    pub content_flags: u32,
    pub pfs_image_offset: u64,
    pub pfs_image_size: u64,
    pub package_size: u64,
}

impl PkgHeader {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h = read_vec(s, 0, 0x1000, 0x1000)?;
        if &h[..4] != MAGIC {
            return Err(Error::malformed("missing PS4 PKG magic"));
        }
        let content_id = crate::binary::ascii_z(&h[0x40..0x64]);
        if content_id.len() != 36 || !content_id.as_bytes()[6..7].eq(b"-") {
            return Err(Error::malformed(format!("content ID {content_id:?} does not have the PS4 layout")));
        }
        let hdr = PkgHeader {
            pkg_type: u32be(&h, 0x04)?,
            file_count: u32be(&h, 0x0C)?,
            entry_count: u32be(&h, 0x10)?,
            table_offset: u32be(&h, 0x18)?,
            body_offset: u64be(&h, 0x20)?,
            body_size: u64be(&h, 0x28)?,
            content_offset: u64be(&h, 0x30)?,
            content_size: u64be(&h, 0x38)?,
            content_id,
            drm_type: u32be(&h, 0x70)?,
            content_type: u32be(&h, 0x74)?,
            content_flags: u32be(&h, 0x78)?,
            pfs_image_offset: u64be(&h, 0x408)?,
            pfs_image_size: u64be(&h, 0x410)?,
            package_size: u64be(&h, 0x428)?,
        };
        let len = s.len()?;
        if hdr.table_offset as u64 + hdr.entry_count as u64 * 0x20 > len {
            return Err(Error::bounds("PKG entry table extends beyond the file"));
        }
        Ok(hdr)
    }

    /// Title ID (e.g. `CUSA00000`) from the content ID.
    pub fn title_id(&self) -> Option<String> {
        self.content_id.get(7..16).map(String::from)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PkgEntry {
    pub id: u32,
    pub name: String,
    pub flags1: u32,
    pub flags2: u32,
    pub offset: u32,
    pub size: u32,
}

impl PkgEntry {
    pub fn encrypted(&self) -> bool {
        self.flags1 & 0x8000_0000 != 0
    }
    pub fn key_index(&self) -> u32 {
        (self.flags2 & 0xF000) >> 12
    }
}

/// PFS superblock summary (the PFS image itself is not traversed).
#[derive(Debug, Clone, Serialize)]
pub struct PfsInfo {
    pub version: u64,
    pub mode: u16,
    pub block_size: u32,
    pub blocks: u64,
    pub encrypted: bool,
}

pub struct Pkg {
    pub source: SharedSource,
    pub header: PkgHeader,
    pub entries: Vec<PkgEntry>,
    pub pfs: Option<PfsInfo>,
    pub warnings: Vec<String>,
}

pub fn drm_name(v: u32) -> String {
    match v {
        0x0 => "none".into(),
        0xF => "PS4".into(),
        0xD => "PS4 (free)".into(),
        v => format!("0x{v:x}"),
    }
}

pub fn content_type_name(v: u32) -> String {
    match v {
        0x1A => "game data / application (GD)".into(),
        0x1B => "additional content (AC)".into(),
        0x1C => "license (AL)".into(),
        0x1E => "delta patch (DP)".into(),
        v => format!("0x{v:x}"),
    }
}

impl Pkg {
    pub fn open(source: SharedSource, limits: &ResourceLimits) -> Result<Self> {
        let header = PkgHeader::parse(source.as_ref())?;
        let len = source.len()?;
        if header.entry_count as u64 > limits.max_entries.min(0x10000) {
            return Err(Error::limit("too many PKG entries"));
        }
        let table = read_vec(source.as_ref(), header.table_offset as u64, header.entry_count as u64 * 0x20, limits.max_metadata)?;
        let mut raw = Vec::new();
        for i in 0..header.entry_count as usize {
            let e = &table[i * 0x20..];
            raw.push((u32be(e, 0)?, u32be(e, 4)?, u32be(e, 8)?, u32be(e, 12)?, u32be(e, 16)?, u32be(e, 20)?));
        }
        let mut warnings = Vec::new();
        for (id, _, _, _, off, size) in &raw {
            if *off as u64 + *size as u64 > len {
                return Err(Error::bounds(format!("PKG entry 0x{id:04x} extends beyond the file")));
            }
        }
        // Entry names table (unencrypted in practice) provides names for some IDs.
        let names_blob = raw
            .iter()
            .find(|r| r.0 == entries::ENTRY_NAMES && r.2 & 0x8000_0000 == 0)
            .map(|r| read_vec(source.as_ref(), r.4 as u64, r.5 as u64, 1 << 20))
            .transpose()?;
        let mut out = Vec::new();
        for (id, name_off, f1, f2, off, size) in raw {
            let name = match (&names_blob, name_off) {
                (Some(b), n) if n != 0 && (n as usize) < b.len() => {
                    let s = crate::binary::utf8_z(&b[n as usize..]);
                    if s.is_empty() || crate::path::sanitize_components(&s, 255).is_err() { entries::name(id) } else { s }
                }
                _ => entries::name(id),
            };
            out.push(PkgEntry { id, name, flags1: f1, flags2: f2, offset: off, size });
        }
        let mut spans: Vec<(u64, u64, usize)> = out.iter().enumerate().map(|(i, e)| (e.offset as u64, e.size as u64, i)).collect();
        if let Some((a, b)) = crate::binary::find_overlap(&mut spans) {
            warnings.push(format!("entries {} and {} overlap", out[a].name, out[b].name));
        }
        let mut names = std::collections::BTreeSet::new();
        for e in out.iter_mut() {
            if !names.insert(e.name.clone()) {
                e.name = format!("{}.0x{:04x}", e.name, e.id);
            }
        }
        let pfs = if header.pfs_image_offset != 0 && header.pfs_image_offset + 0x100 <= len {
            let sb = read_vec(source.as_ref(), header.pfs_image_offset, 0x100, 0x100)?;
            let magic = crate::binary::u64le(&sb, 8)?;
            if magic == 0x2013_0315 {
                let mode = crate::binary::u16le(&sb, 0x1C)?;
                Some(PfsInfo {
                    version: crate::binary::u64le(&sb, 0)?,
                    mode,
                    block_size: crate::binary::u32le(&sb, 0x20)?,
                    blocks: crate::binary::u64le(&sb, 0x28)?,
                    encrypted: mode & 0x4 != 0,
                })
            } else {
                warnings.push("PFS image superblock not recognised".into());
                None
            }
        } else {
            None
        };
        Ok(Pkg { source, header, entries: out, pfs, warnings })
    }

    pub fn open_entry(&self, e: &PkgEntry) -> Result<SharedSource> {
        if e.encrypted() {
            return Err(Error::needs_keys(format!("{} is encrypted; PKG entry decryption is not supported", e.name)));
        }
        SubSource::shared(self.source.clone(), e.offset as u64, e.size as u64)
    }

    pub fn read_sfo(&self) -> Result<Option<crate::ps4::sfo::Psf>> {
        match self.entries.iter().find(|e| e.id == entries::PARAM_SFO) {
            Some(e) if !e.encrypted() => {
                let s = self.open_entry(e)?;
                Ok(Some(crate::ps4::sfo::parse(&read_vec(s.as_ref(), 0, e.size as u64, 1 << 20)?)?))
            }
            _ => Ok(None),
        }
    }

    /// Heuristic description of the package class (never used to grant capabilities).
    pub fn variant(&self) -> &'static str {
        let enc = self.entries.iter().filter(|e| e.encrypted()).count();
        if enc == 0 {
            "no encrypted package-table entries (development/homebrew-style)"
        } else {
            "contains encrypted package-table entries (protected content)"
        }
    }
}

#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    //! Synthetic PKG builder for tests (structure only; no valid signatures or encryption).
    //!
    //! Synthetic-fixture builder (feature `testkit`; not part of the stable API).
    pub fn build(content_id: &str, entries: &[(u32, Vec<u8>, bool)]) -> Vec<u8> {
        let mut out = vec![0u8; 0x1000];
        out[..4].copy_from_slice(super::MAGIC);
        out[0x10..0x14].copy_from_slice(&(entries.len() as u32).to_be_bytes());
        out[0x18..0x1C].copy_from_slice(&0x2000u32.to_be_bytes());
        out[0x40..0x40 + content_id.len()].copy_from_slice(content_id.as_bytes());
        out[0x70..0x74].copy_from_slice(&0xFu32.to_be_bytes());
        out[0x74..0x78].copy_from_slice(&0x1Au32.to_be_bytes());
        out.resize(0x2000, 0);
        let mut table = Vec::new();
        let mut data = Vec::new();
        let data_start = 0x2000 + entries.len() * 0x20;
        for (id, d, enc) in entries {
            let off = data_start + data.len();
            let mut e = vec![0u8; 0x20];
            e[0..4].copy_from_slice(&id.to_be_bytes());
            e[8..12].copy_from_slice(&(if *enc { 0x8000_0000u32 } else { 0 }).to_be_bytes());
            e[16..20].copy_from_slice(&(off as u32).to_be_bytes());
            e[20..24].copy_from_slice(&(d.len() as u32).to_be_bytes());
            table.extend(e);
            data.extend_from_slice(d);
            while data.len() % 16 != 0 {
                data.push(0);
            }
        }
        out.extend(table);
        out.extend(data);
        let total = out.len() as u64;
        out[0x428..0x430].copy_from_slice(&total.to_be_bytes());
        out
    }
}
