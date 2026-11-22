//! XCI gamecard-style images: header, root HFS0 and partitions (`update`, `normal`,
//! `secure`, `logo`).
//!
//! The `update` partition conventionally carries *system* update content; Romux never
//! interprets it as a digital title update for the bundled game. A rebuilt XCI is a
//! container that follows the gamecard layout — it is not an authentic reproduction of a
//! physical cartridge (no valid header signature, no initial data / key area).

use crate::binary::{u32le, u64le};
use crate::switch::partition::{Kind, PartitionFs};
use crate::{DataSource, Error, ResourceLimits, Result, SharedSource, SubSource, read_vec};
use serde::Serialize;

pub const PAGE: u64 = 0x200;
pub const ROOT_HFS0_OFFSET: u64 = 0xF000;

#[derive(Debug, Clone, Serialize)]
pub struct XciHeader {
    /// 0 for a normal image, 0x1000 when a key-area prefix precedes the header.
    pub base: u64,
    pub secure_area_page: u32,
    pub kek_index: u8,
    pub rom_size: u8,
    pub header_version: u8,
    pub flags: u8,
    pub package_id: u64,
    pub valid_data_end_page: u64,
    pub hfs0_offset: u64,
    pub hfs0_size: u64,
    #[serde(serialize_with = "ser_hex")]
    pub hfs0_hash: [u8; 32],
    pub sel_sec: u32,
    pub sel_t1_key: u32,
    pub sel_key: u32,
    pub lim_area_page: u32,
}

fn ser_hex<S: serde::Serializer>(v: &[u8; 32], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&crate::hex(v))
}

pub fn rom_size_name(b: u8) -> &'static str {
    match b {
        0xFA => "1GB",
        0xF8 => "2GB",
        0xF0 => "4GB",
        0xE0 => "8GB",
        0xE1 => "16GB",
        0xE2 => "32GB",
        _ => "unknown",
    }
}

/// Smallest card capacity code that fits `size` bytes.
pub fn rom_size_for(size: u64) -> u8 {
    const GB: u64 = 1 << 30;
    // Usable capacities are slightly below nominal; leave headroom.
    let caps = [
        (0xFAu8, GB * 15 / 16),
        (0xF8, 2 * GB * 15 / 16),
        (0xF0, 4 * GB * 15 / 16),
        (0xE0, 8 * GB * 15 / 16),
        (0xE1, 16 * GB * 15 / 16),
        (0xE2, 32 * GB * 15 / 16),
    ];
    caps.iter().find(|(_, c)| size <= *c).map(|(b, _)| *b).unwrap_or(0xE2)
}

/// Locate and parse the XCI header.
pub fn parse_header(source: &dyn DataSource) -> Result<XciHeader> {
    for base in [0u64, 0x1000] {
        let mut m = [0u8; 4];
        if source.read_exact_at(base + 0x100, &mut m).is_ok() && &m == b"HEAD" {
            let h = read_vec(source, base, 0x200, 0x200)?;
            let hdr = XciHeader {
                base,
                secure_area_page: u32le(&h, 0x104)?,
                kek_index: h[0x10C],
                rom_size: h[0x10D],
                header_version: h[0x10E],
                flags: h[0x10F],
                package_id: u64le(&h, 0x110)?,
                valid_data_end_page: u64le(&h, 0x118)?,
                hfs0_offset: u64le(&h, 0x130)?,
                hfs0_size: u64le(&h, 0x138)?,
                hfs0_hash: crate::binary::array(&h, 0x140)?,
                sel_sec: u32le(&h, 0x180)?,
                sel_t1_key: u32le(&h, 0x184)?,
                sel_key: u32le(&h, 0x188)?,
                lim_area_page: u32le(&h, 0x18C)?,
            };
            if hdr.hfs0_size == 0 || hdr.hfs0_size > 0x10_0000 {
                return Err(Error::malformed("XCI root HFS0 header size is implausible"));
            }
            return Ok(hdr);
        }
    }
    Err(Error::malformed("no XCI HEAD magic at 0x100 or 0x1100"))
}

/// An opened XCI.
pub struct Xci {
    pub source: SharedSource,
    pub header: XciHeader,
    pub root: PartitionFs,
    pub partitions: Vec<(String, PartitionFs)>,
    pub warnings: Vec<String>,
}

impl Xci {
    pub fn open(source: SharedSource, limits: &ResourceLimits) -> Result<Self> {
        let header = parse_header(source.as_ref())?;
        let total = source.len()?;
        let root_off = header.base + header.hfs0_offset;
        if root_off >= total {
            return Err(Error::bounds("XCI root HFS0 beyond end of image"));
        }
        let root_src = SubSource::shared(source.clone(), root_off, total - root_off)?;
        let root = PartitionFs::parse(root_src, Kind::Hfs0, limits)?;
        let mut partitions = Vec::new();
        let mut warnings = Vec::new();
        for (i, e) in root.entries.iter().enumerate() {
            match root.open(i).and_then(|s| PartitionFs::parse(s, Kind::Hfs0, limits)) {
                Ok(p) => partitions.push((e.name.clone(), p)),
                Err(err) => warnings.push(format!("partition {} unreadable: {err}", e.name)),
            }
        }
        let expected = header.valid_data_end_page.saturating_add(1).saturating_mul(PAGE);
        if expected > total + header.base {
            warnings.push(format!("image is trimmed or truncated: header declares data up to 0x{expected:x}, file is 0x{total:x}"));
        }
        Ok(Xci { source, header, root, partitions, warnings })
    }

    pub fn partition(&self, name: &str) -> Option<&PartitionFs> {
        self.partitions.iter().find(|(n, _)| n == name).map(|(_, p)| p)
    }

    /// Verify root header hash, partition header hashes and file hashed regions.
    pub fn verify_hashes(&self) -> Result<Vec<(String, bool)>> {
        let mut out = Vec::new();
        let root_hdr = read_vec(self.root.source().as_ref(), 0, self.header.hfs0_size, 0x10_0000)?;
        out.push(("root HFS0 header hash".to_string(), crate::crypto::sha256(&root_hdr) == self.header.hfs0_hash));
        for (i, e) in self.root.entries.iter().enumerate() {
            let d = read_vec(self.root.source().as_ref(), self.root.abs_offset(i), e.hashed_region as u64, 0x10_0000)?;
            out.push((format!("{} partition header hash", e.name), crate::crypto::sha256(&d) == e.hash));
        }
        for (name, p) in &self.partitions {
            for (f, ok) in p.verify_hashes()? {
                out.push((format!("{name}/{f} hashed region"), ok));
            }
        }
        Ok(out)
    }
}
