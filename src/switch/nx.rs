//! NX archives (`.nx`, magic `NXAR`, binary versions 0.2 and 0.3): one file holding
//! decrypted Switch 1 / Switch 2 games: a base game, its updates and DLC as complete
//! *snapshots* (file trees) over a shared, deduplicated pool of independent RAW or
//! Zstandard blocks, with a fast Catalog (applications, programs, snapshots, display
//! metadata) and per-16 KiB-slice CRC-32C integrity.
//!
//! Layout: header slots A (offset 0) and B (offset 4096), the Data region at 8192, then
//! one contiguous tail: Media, Catalog, Manifest, hot block index, integrity table. See
//! the NX binary specification (`docs/SPEC.md` of the NXFormat project).
//!
//! The writer produces compact generation-0 archives of version 0.2 without rebuild
//! recipes. The reader accepts 0.2 and 0.3 and validates every structure it relies on.

use crate::switch::formats::SWITCH_NX;
use crate::{
    CapabilitySet, CheckLevel, ContentCategory, ContentNode, EntryId, EntryIter, Error, FormatId, JobContext, MemorySource, NodeKind,
    NodeTable, OpenContext, PackageInfo, PackageReader, Platform, Result, SharedSource, VerifyLevel, VerifyReport, hex, read_vec,
};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

pub const MAGIC: &[u8; 4] = b"NXAR";
const HEADER_SIZE: usize = 256;
const SLOT_B: u64 = 4096;
const DATA_START: u64 = 8192;
const CHECK_SIZE: u64 = 16384;
const ABSENT: u32 = 0xFFFF_FFFF;
const MAX_CATALOG: u64 = 16 << 20;
const MAX_BLOCK: u64 = 1 << 20;

const CATALOG_HEADER: u64 = 128;
const APP_SIZE: u64 = 80;
const PROGRAM_SIZE: u64 = 64;
const SNAPSHOT_SIZE: u64 = 120;
const LOCALIZED_SIZE: u64 = 24;
const DEPENDENCY_SIZE: u64 = 56;
const EXTENSION_SIZE: u64 = 32;
const MEDIA_HEADER: u64 = 32;
const MEDIA_RECORD: u64 = 64;
const MANIFEST_HEADER: u64 = 96;
const DIRECTORY_SIZE: u64 = 16;
const ENTRY_SIZE: u64 = 24;
const FILE_SIZE: u64 = 64;
const BLOCK_SIZE: u64 = 24;

pub const EXT_REQUIRED_FIRMWARE: u32 = 0x0001_0001;
pub const EXT_LANGUAGES: u32 = 0x0001_0002;
pub const EXT_REGIONS: u32 = 0x0001_0003;
pub const EXT_METADATA_HISTORY: u32 = 0x0001_0004;
pub const EXT_NATIVE_METADATA: u32 = 0x0001_0005;
pub const EXT_RECIPES: u32 = 0x0001_0006;
pub const EXT_SOURCE_RESOURCES: u32 = 0x0001_0008;
pub const EXT_EXTRA_FILES: u32 = 0x0001_0009;

pub const SNAPSHOT_BASE: u8 = 0;
pub const SNAPSHOT_UPDATE: u8 = 1;
pub const SNAPSHOT_DLC: u8 = 2;
pub const SNAPSHOT_STANDALONE_UPDATE: u8 = 3;

pub const DEP_REQUIRED_BASE: u8 = 1;
pub const DEP_REQUIRES: u8 = 2;

pub const MEDIA_PNG: u16 = 1;
pub const MEDIA_JPEG: u16 = 2;
pub const MEDIA_NPDM: u16 = 3;
pub const MEDIA_NACP: u16 = 4;

pub fn snapshot_type_name(t: u8) -> &'static str {
    match t {
        SNAPSHOT_BASE => "base",
        SNAPSHOT_UPDATE => "update",
        SNAPSHOT_DLC => "dlc",
        SNAPSHOT_STANDALONE_UPDATE => "standalone-update",
        _ => "unknown",
    }
}

pub fn media_type_name(t: u16) -> &'static str {
    match t {
        MEDIA_PNG => "png icon",
        MEDIA_JPEG => "jpeg icon",
        MEDIA_NPDM => "npdm",
        MEDIA_NACP => "nacp",
        _ => "opaque source metadata",
    }
}

pub fn platform_name(p: u8) -> &'static str {
    match p {
        1 => "switch1",
        2 => "switch2",
        _ => "unknown",
    }
}

fn align(v: u64, a: u64) -> Result<u64> {
    crate::binary::align_up(v, a)
}

/// Bounds-checked little-endian field access.
struct B<'a>(&'a [u8]);
impl B<'_> {
    fn get(&self, o: u64, n: usize) -> Result<&[u8]> {
        let o = usize::try_from(o).map_err(|_| Error::bounds("NX offset exceeds the address space"))?;
        self.0
            .get(o..o.checked_add(n).ok_or_else(|| Error::bounds("NX offset overflows"))?)
            .ok_or_else(|| Error::bounds("NX field outside its section"))
    }
    fn u8(&self, o: u64) -> Result<u8> {
        Ok(self.get(o, 1)?[0])
    }
    fn u16(&self, o: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(self.get(o, 2)?.try_into().map_err(|_| Error::internal("u16"))?))
    }
    fn u32(&self, o: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.get(o, 4)?.try_into().map_err(|_| Error::internal("u32"))?))
    }
    fn u64(&self, o: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.get(o, 8)?.try_into().map_err(|_| Error::internal("u64"))?))
    }
    fn arr<const N: usize>(&self, o: u64) -> Result<[u8; N]> {
        self.get(o, N)?.try_into().map_err(|_| Error::internal("array"))
    }
    fn zero(&self, o: u64, n: usize, what: &str) -> Result<()> {
        if self.get(o, n)?.iter().any(|&b| b != 0) {
            return Err(Error::malformed(format!("NX reserved field {what} is not zero")));
        }
        Ok(())
    }
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

fn valid_component(n: &[u8]) -> bool {
    !n.is_empty()
        && n.len() <= 4096
        && n != b"."
        && n != b".."
        && !n.iter().any(|&c| c == 0 || c == b'/' || c == b'\\')
        && std::str::from_utf8(n).is_ok()
}

fn slice_crcs(data: &[u8]) -> Vec<u32> {
    data.chunks(CHECK_SIZE as usize).map(crate::crypto::crc32c).collect()
}

/// Canonical snapshot identity (§12, algorithm version 3).
pub(crate) fn snapshot_identity(
    platform: u8,
    application_id: u64,
    program_id: Option<u64>,
    snapshot_type: u8,
    version: u32,
    content_id: &[u8; 16],
    nodes: &mut [(String, Option<(u64, [u8; 32])>)],
) -> [u8; 32] {
    use sha2::Digest;
    nodes.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut h = sha2::Sha256::new();
    h.update(b"NX-SNAPSHOT-ID\0");
    h.update(3u16.to_le_bytes());
    h.update([platform]);
    h.update(application_id.to_le_bytes());
    h.update(program_id.unwrap_or(u64::MAX).to_le_bytes());
    h.update([snapshot_type]);
    h.update(version.to_le_bytes());
    h.update(content_id);
    h.update((nodes.len() as u32).to_le_bytes());
    for (path, file) in nodes.iter() {
        h.update([if file.is_some() { 2 } else { 1 }]);
        h.update((path.len() as u32).to_le_bytes());
        h.update(path.as_bytes());
        if let Some((size, sha)) = file {
            h.update(size.to_le_bytes());
            h.update(sha);
        }
    }
    h.finalize().into()
}

// =======================================================================================
// Reader
// =======================================================================================

#[derive(Debug, Clone)]
pub struct Header {
    pub minor: u16,
    pub archive_size: u64,
    pub catalog: (u64, u64),
    pub media: (u64, u64),
    pub data: (u64, u64),
    pub manifest: (u64, u64),
    pub block_index_offset: u64,
    pub block_count: u64,
    pub integrity: (u64, u64),
    pub catalog_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub index_sha256: [u8; 32],
    pub generation: u64,
    pub raw: [u8; HEADER_SIZE],
}

fn parse_header(raw: &[u8], physical: u64) -> Result<Header> {
    let b = B(raw);
    if b.get(0, 4)? != MAGIC {
        return Err(Error::malformed("NX header magic is not NXAR"));
    }
    let crc = b.u32(252)?;
    if crate::crypto::crc32c(&raw[..252]) != crc {
        return Err(Error::integrity("NX header CRC-32C does not match"));
    }
    let major = b.u16(4)?;
    let minor = b.u16(6)?;
    if major != 0 || !(minor == 2 || minor == 3) {
        return Err(Error::unsupported(format!("NX format version {major}.{minor} is not supported (0.2 and 0.3 are)")));
    }
    if b.u32(8)? != HEADER_SIZE as u32 {
        return Err(Error::malformed("NX header_size is not 256"));
    }
    if b.u16(12)? != 1 {
        return Err(Error::unsupported(format!("NX required feature bits 0x{:x} are not supported", b.u16(12)?)));
    }
    if b.u16(14)? != 0 {
        return Err(Error::malformed("NX optional feature bits are not zero"));
    }
    if b.u32(224)? != CHECK_SIZE as u32 {
        return Err(Error::unsupported("NX check_size is not 16384"));
    }
    b.zero(228, 24, "header reserved")?;
    let h = Header {
        minor,
        archive_size: b.u64(16)?,
        catalog: (b.u64(24)?, b.u64(32)?),
        media: (b.u64(40)?, b.u64(48)?),
        data: (b.u64(56)?, b.u64(64)?),
        manifest: (b.u64(72)?, b.u64(80)?),
        block_index_offset: b.u64(88)?,
        block_count: b.u64(96)?,
        integrity: (b.u64(104)?, b.u64(112)?),
        catalog_sha256: b.arr(120)?,
        manifest_sha256: b.arr(152)?,
        index_sha256: b.arr(184)?,
        generation: b.u64(216)?,
        raw: raw[..HEADER_SIZE].try_into().map_err(|_| Error::internal("header"))?,
    };
    if h.archive_size > physical || h.archive_size > i64::MAX as u64 {
        return Err(Error::bounds("NX archive_size exceeds the file"));
    }
    if h.catalog.1 < CATALOG_HEADER || h.catalog.1 > MAX_CATALOG || !h.catalog.0.is_multiple_of(16) {
        return Err(Error::malformed("NX catalog range is invalid"));
    }
    if h.manifest.1 < MANIFEST_HEADER || h.manifest.1 > 4 << 30 || !h.manifest.0.is_multiple_of(16) {
        return Err(Error::malformed("NX manifest range is invalid"));
    }
    if (h.media.0 == 0) != (h.media.1 == 0) || (h.media.1 != 0 && (h.media.1 < MEDIA_HEADER || !h.media.0.is_multiple_of(16))) {
        return Err(Error::malformed("NX media range is invalid"));
    }
    if (h.data.0 == 0) != (h.data.1 == 0) || (h.data.0 != 0 && h.data.0 != DATA_START) {
        return Err(Error::malformed("NX data range is invalid"));
    }
    if h.block_count > 1 << 32 {
        return Err(Error::limit("NX block count exceeds 2^32"));
    }
    if h.block_count == 0 {
        if h.block_index_offset != 0 || h.integrity != (0, 0) || h.data != (0, 0) {
            return Err(Error::malformed("NX archive without blocks declares block regions"));
        }
    } else if h.block_index_offset == 0
        || !h.block_index_offset.is_multiple_of(16)
        || h.integrity.0 == 0
        || !h.integrity.0.is_multiple_of(16)
        || h.data.0 == 0
    {
        return Err(Error::malformed("NX block regions are missing or misaligned"));
    }
    // Sections in order and non-overlapping within the archive.
    let mut regions: Vec<(u64, u64, &str)> = Vec::new();
    if h.data.1 > 0 {
        regions.push((h.data.0, h.data.1, "data"));
    }
    if h.media.1 > 0 {
        regions.push((h.media.0, h.media.1, "media"));
    }
    regions.push((h.catalog.0, h.catalog.1, "catalog"));
    regions.push((h.manifest.0, h.manifest.1, "manifest"));
    if h.block_count > 0 {
        regions.push((h.block_index_offset, h.block_count * BLOCK_SIZE, "block index"));
        regions.push((h.integrity.0, h.integrity.1, "integrity table"));
    }
    let mut end = DATA_START;
    for (o, l, what) in &regions {
        if *o < end {
            return Err(Error::malformed(format!("NX {what} overlaps or precedes the previous region")));
        }
        end = o.checked_add(*l).ok_or_else(|| Error::bounds("NX region overflows"))?;
    }
    if end != h.archive_size {
        return Err(Error::malformed("NX archive_size does not end at the last tail region"));
    }
    Ok(h)
}

#[derive(Debug, Clone)]
pub struct Application {
    pub application_id: u64,
    pub platform: u8,
    pub flags: u8,
    pub first_program: u32,
    pub program_count: u32,
    pub first_snapshot: u32,
    pub snapshot_count: u32,
    pub title: Option<String>,
    pub publisher: Option<String>,
    pub icon: u32,
    pub first_localized: u32,
    pub localized_count: u32,
    pub nacp: u32,
    pub metadata_snapshot: u32,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub program_id: u64,
    pub application_index: u32,
    pub kind: u8,
    pub first_snapshot: u32,
    pub snapshot_count: u32,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub program_index: u32,
    pub snapshot_type: u8,
    pub flags: u8,
    pub version: u32,
    pub root: u32,
    pub logical_size: u64,
    pub display_version: Option<String>,
    pub content_id: [u8; 16],
    pub first_dependency: u32,
    pub dependency_count: u32,
    pub identity: [u8; 32],
    pub build_id: [u8; 32],
    /// Owning application index.
    pub application: u32,
}

impl Snapshot {
    pub fn addon_title_id(&self) -> Option<u64> {
        (self.flags & 2 != 0).then(|| u64::from_le_bytes(self.content_id[..8].try_into().unwrap_or([0; 8])))
    }
}

#[derive(Debug, Clone)]
pub struct Localized {
    pub language: String,
    pub title: Option<String>,
    pub icon: u32,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub kind: u8,
    pub target: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct MediaRecord {
    pub media_type: u16,
    pub size: u64,
    pub offset: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub type_id: u32,
    pub flags: u32,
    pub owner_kind: u16,
    pub owner_index: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NxEntry {
    pub name: String,
    pub target: u32,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct NxFile {
    pub size: u64,
    pub first_ref: u32,
    pub block_count: u32,
    pub chunk_log2: u8,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct Block {
    pub offset: u64,
    pub stored: u32,
    pub logical: u32,
    pub codec: u8,
    pub first_check: u32,
}

/// A parsed, validated NX archive (selected generation).
pub struct Nx {
    pub source: SharedSource,
    pub header: Header,
    pub other_slot_valid: bool,
    pub applications: Vec<Application>,
    pub programs: Vec<Program>,
    pub snapshots: Vec<Snapshot>,
    pub localized: Vec<Localized>,
    pub dependencies: Vec<Dependency>,
    pub extensions: Vec<Extension>,
    pub media: Vec<MediaRecord>,
    pub directories: Vec<(u32, u32)>,
    pub entries: Vec<NxEntry>,
    pub files: Vec<NxFile>,
    pub refs: Vec<u32>,
    pub blocks: Vec<Block>,
    pub checks: Vec<u32>,
    /// `(kind, root directory)` Source Resources (NX 0.3) per application.
    pub resources: Vec<(u32, u32, u32)>,
    /// Root of the optional extra-files tree.
    pub extra_root: Option<u32>,
    pub warnings: Vec<String>,
}

pub fn probe(s: &dyn crate::DataSource) -> bool {
    let mut m = [0u8; 4];
    let ok_a = s.read_exact_at(0, &mut m).is_ok() && &m == MAGIC;
    ok_a || (s.len().is_ok_and(|l| l >= SLOT_B + 4) && s.read_exact_at(SLOT_B, &mut m).is_ok() && &m == MAGIC)
}

fn string_ref(pool: &[u8], off: u32, len: u32) -> Result<Option<String>> {
    if off == ABSENT {
        if len != 0 {
            return Err(Error::malformed("absent NX string has a nonzero length"));
        }
        return Ok(None);
    }
    if len == 0 {
        return Err(Error::malformed("present NX string has zero length"));
    }
    let e = (off as usize).checked_add(len as usize).ok_or_else(|| Error::bounds("string overflows"))?;
    let b = pool.get(off as usize..e).ok_or_else(|| Error::bounds("NX string outside the pool"))?;
    if b.contains(&0) {
        return Err(Error::malformed("NX string contains NUL"));
    }
    String::from_utf8(b.to_vec()).map(Some).map_err(|_| Error::malformed("NX string is not UTF-8"))
}

impl Nx {
    pub fn open(source: SharedSource, limits: &crate::ResourceLimits) -> Result<Self> {
        let physical = source.len()?;
        let read_slot = |at: u64| -> Result<Header> {
            if physical < at + HEADER_SIZE as u64 {
                return Err(Error::bounds("NX header slot beyond the file"));
            }
            let raw = read_vec(source.as_ref(), at, HEADER_SIZE as u64, HEADER_SIZE as u64)?;
            parse_header(&raw, physical)
        };
        let a = read_slot(0);
        let b = read_slot(SLOT_B);
        let (header, other_valid) = match (a, b) {
            (Ok(a), Ok(b)) => {
                if a.generation == b.generation {
                    if a.raw != b.raw {
                        return Err(Error::malformed("NX header slots share a generation but differ"));
                    }
                    (a, true)
                } else if a.generation > b.generation {
                    (a, true)
                } else {
                    (b, true)
                }
            }
            (Ok(a), Err(_)) => (a, false),
            (Err(_), Ok(b)) => (b, false),
            (Err(e), Err(_)) => return Err(e),
        };
        let mut nx = Nx {
            source,
            header,
            other_slot_valid: other_valid,
            applications: Vec::new(),
            programs: Vec::new(),
            snapshots: Vec::new(),
            localized: Vec::new(),
            dependencies: Vec::new(),
            extensions: Vec::new(),
            media: Vec::new(),
            directories: Vec::new(),
            entries: Vec::new(),
            files: Vec::new(),
            refs: Vec::new(),
            blocks: Vec::new(),
            checks: Vec::new(),
            resources: Vec::new(),
            extra_root: None,
            warnings: Vec::new(),
        };
        if !other_valid {
            nx.warnings.push("one NX header slot is damaged; the other slot was used".into());
        }
        nx.load_catalog()?;
        nx.load_media()?;
        nx.load_manifest(limits)?;
        nx.load_blocks()?;
        nx.check_trees(limits)?;
        Ok(nx)
    }

    fn section(&self, (off, len): (u64, u64), limit: u64) -> Result<Vec<u8>> {
        read_vec(self.source.as_ref(), off, len, limit)
    }

    fn load_catalog(&mut self) -> Result<()> {
        let cat = self.section(self.header.catalog, MAX_CATALOG)?;
        if crate::crypto::sha256(&cat) != self.header.catalog_sha256 {
            return Err(Error::integrity("NX catalog SHA-256 does not match the header"));
        }
        let c = B(&cat);
        if c.get(0, 4)? != b"NXCT" || c.u16(4)? != 1 || c.u16(6)? != CATALOG_HEADER as u16 {
            return Err(Error::malformed("NX catalog header is invalid"));
        }
        if c.u64(8)? != cat.len() as u64 {
            return Err(Error::malformed("NX catalog total_size differs from the header"));
        }
        if c.u32(16)? != 0 {
            return Err(Error::malformed("NX catalog flags are not zero"));
        }
        c.zero(44, 4, "catalog reserved0")?;
        c.zero(112, 16, "catalog reserved1")?;
        let (na, np, ns, nl, nd, ne) = (c.u32(20)?, c.u32(24)?, c.u32(28)?, c.u32(32)?, c.u32(36)?, c.u32(40)?);
        if !(1..=4096).contains(&na) || np > 16384 || !(1..=65536).contains(&ns) || nl > 16384 || nd > 32768 || ne > 4096 {
            return Err(Error::limit("NX catalog counts are outside their limits"));
        }
        let (ao, po, so, lo, dof, eo) = (c.u64(48)?, c.u64(56)?, c.u64(64)?, c.u64(72)?, c.u64(80)?, c.u64(88)?);
        let (pool_off, pool_size) = (c.u64(96)?, c.u64(104)?);
        // Layout: each table at the minimum 8-aligned offset after the previous one.
        let mut cursor = CATALOG_HEADER;
        for (off, count, size, what) in [
            (ao, na, APP_SIZE, "application"),
            (po, np, PROGRAM_SIZE, "program"),
            (so, ns, SNAPSHOT_SIZE, "snapshot"),
            (lo, nl, LOCALIZED_SIZE, "localized"),
            (dof, nd, DEPENDENCY_SIZE, "dependency"),
            (eo, ne, EXTENSION_SIZE, "extension"),
        ] {
            if count == 0 {
                if off != 0 {
                    return Err(Error::malformed(format!("empty NX {what} table has a nonzero offset")));
                }
                continue;
            }
            if off != align(cursor, 8)? {
                return Err(Error::malformed(format!("NX {what} table is not at its canonical offset")));
            }
            cursor = off + count as u64 * size;
        }
        if pool_off != align(cursor, 8)? || pool_off.checked_add(pool_size).is_none_or(|e| e > cat.len() as u64) {
            return Err(Error::malformed("NX string pool range is invalid"));
        }
        let pool = &cat[pool_off as usize..(pool_off + pool_size) as usize];
        for i in 0..na as u64 {
            let o = ao + i * APP_SIZE;
            c.zero(o + 10, 2, "application reserved0")?;
            c.zero(o + 72, 8, "application reserved1")?;
            self.applications.push(Application {
                application_id: c.u64(o)?,
                platform: c.u8(o + 8)?,
                flags: c.u8(o + 9)?,
                first_program: c.u32(o + 12)?,
                program_count: c.u32(o + 16)?,
                first_snapshot: c.u32(o + 20)?,
                snapshot_count: c.u32(o + 24)?,
                title: string_ref(pool, c.u32(o + 28)?, c.u32(o + 32)?)?,
                publisher: string_ref(pool, c.u32(o + 36)?, c.u32(o + 40)?)?,
                icon: c.u32(o + 44)?,
                first_localized: c.u32(o + 48)?,
                localized_count: c.u32(o + 52)?,
                nacp: c.u32(o + 56)?,
                metadata_snapshot: c.u32(o + 68)?,
            });
        }
        for i in 0..np as u64 {
            let o = po + i * PROGRAM_SIZE;
            c.zero(o + 14, 2, "program reserved0")?;
            c.zero(o + 44, 20, "program reserved")?;
            self.programs.push(Program {
                program_id: c.u64(o)?,
                application_index: c.u32(o + 8)?,
                kind: c.u8(o + 12)?,
                first_snapshot: c.u32(o + 32)?,
                snapshot_count: c.u32(o + 36)?,
            });
        }
        for i in 0..ns as u64 {
            let o = so + i * SNAPSHOT_SIZE;
            c.zero(o + 6, 2, "snapshot reserved0")?;
            self.snapshots.push(Snapshot {
                program_index: c.u32(o)?,
                snapshot_type: c.u8(o + 4)?,
                flags: c.u8(o + 5)?,
                version: c.u32(o + 8)?,
                root: c.u32(o + 12)?,
                logical_size: c.u64(o + 16)?,
                display_version: string_ref(pool, c.u32(o + 24)?, c.u32(o + 28)?)?,
                content_id: c.arr(o + 32)?,
                first_dependency: c.u32(o + 48)?,
                dependency_count: c.u32(o + 52)?,
                identity: c.arr(o + 56)?,
                build_id: c.arr(o + 88)?,
                application: ABSENT,
            });
        }
        for i in 0..nl as u64 {
            let o = lo + i * LOCALIZED_SIZE;
            let language =
                string_ref(pool, c.u32(o)?, c.u32(o + 4)?)?.ok_or_else(|| Error::malformed("NX localized entry without a language"))?;
            if language.len() > 63 || !language.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return Err(Error::malformed(format!("NX language tag {language:?} is invalid")));
            }
            let title = string_ref(pool, c.u32(o + 8)?, c.u32(o + 12)?)?;
            let icon = c.u32(o + 16)?;
            if c.u32(o + 20)? != 0 || (title.is_none() && icon == ABSENT) {
                return Err(Error::malformed("NX localized entry is empty or has flags"));
            }
            self.localized.push(Localized { language, title, icon });
        }
        for i in 0..nd as u64 {
            let o = dof + i * DEPENDENCY_SIZE;
            let kind = c.u8(o)?;
            if !(1..=3).contains(&kind) || c.u8(o + 1)? > 1 {
                return Err(Error::malformed("NX dependency kind or flags are invalid"));
            }
            let target: [u8; 32] = c.arr(o + 20)?;
            if target == [0; 32] {
                return Err(Error::malformed("NX dependency target identity is zero"));
            }
            self.dependencies.push(Dependency { kind, target });
        }
        let mut prev_end = pool_off + pool_size;
        for i in 0..ne as u64 {
            let o = eo + i * EXTENSION_SIZE;
            let (doff, dsize) = (c.u64(o + 16)?, c.u64(o + 24)?);
            if doff != align(prev_end, 8)? || doff.checked_add(dsize).is_none_or(|e| e > cat.len() as u64) {
                return Err(Error::malformed("NX extension payload is not at its canonical offset"));
            }
            prev_end = doff + dsize;
            let e = Extension {
                type_id: c.u32(o)?,
                flags: c.u32(o + 4)?,
                owner_kind: c.u16(o + 8)?,
                owner_index: c.u32(o + 12)?,
                data: cat[doff as usize..(doff + dsize) as usize].to_vec(),
            };
            if e.flags > 1 {
                return Err(Error::malformed("NX extension flags have undefined bits"));
            }
            self.extensions.push(e);
        }
        if prev_end != cat.len() as u64 {
            return Err(Error::malformed("NX catalog does not end at its last region"));
        }
        self.check_catalog()?;
        Ok(())
    }

    fn check_catalog(&mut self) -> Result<()> {
        let (ns, np) = (self.snapshots.len() as u64, self.programs.len() as u64);
        let mut next_snapshot = 0u64;
        let mut next_program = 0u64;
        let mut next_localized = 0u64;
        let mut prev: Option<(u8, u64)> = None;
        for (ai, a) in self.applications.iter().enumerate() {
            if a.application_id == 0 || a.platform > 2 {
                return Err(Error::malformed("NX application ID or platform is invalid"));
            }
            if prev.is_some_and(|p| p >= (a.platform, a.application_id)) {
                return Err(Error::malformed("NX applications are not strictly ascending"));
            }
            prev = Some((a.platform, a.application_id));
            if a.first_snapshot as u64 != next_snapshot || a.snapshot_count == 0 {
                return Err(Error::malformed("NX application snapshot ranges do not partition the table"));
            }
            next_snapshot += a.snapshot_count as u64;
            if a.program_count == 0 {
                if a.first_program != ABSENT {
                    return Err(Error::malformed("NX empty program range is not absent"));
                }
            } else {
                if a.first_program as u64 != next_program {
                    return Err(Error::malformed("NX application program ranges do not partition the table"));
                }
                next_program += a.program_count as u64;
            }
            if a.first_localized as u64 != next_localized {
                return Err(Error::malformed("NX localized ranges do not partition the table"));
            }
            next_localized += a.localized_count as u64;
            if next_snapshot > ns || next_program > np || next_localized > self.localized.len() as u64 {
                return Err(Error::bounds("NX application ranges exceed their tables"));
            }
            for s in &mut self.snapshots[a.first_snapshot as usize..(a.first_snapshot + a.snapshot_count) as usize] {
                s.application = ai as u32;
            }
            let has_base = self.snapshots[a.first_snapshot as usize..(a.first_snapshot + a.snapshot_count) as usize]
                .iter()
                .any(|s| s.snapshot_type == SNAPSHOT_BASE);
            let has_dlc = self.snapshots[a.first_snapshot as usize..(a.first_snapshot + a.snapshot_count) as usize]
                .iter()
                .any(|s| s.snapshot_type == SNAPSHOT_DLC);
            if a.flags != (has_base as u8 | (has_dlc as u8) << 1) {
                return Err(Error::malformed("NX application flags disagree with its snapshots"));
            }
            if a.metadata_snapshot != ABSENT
                && (a.metadata_snapshot < a.first_snapshot || a.metadata_snapshot >= a.first_snapshot + a.snapshot_count)
            {
                return Err(Error::malformed("NX metadata snapshot is outside its application"));
            }
        }
        if next_snapshot != ns || next_program != np || next_localized != self.localized.len() as u64 {
            return Err(Error::malformed("NX application ranges do not cover every table row"));
        }
        let mut next_dep = 0u64;
        for s in &self.snapshots {
            if s.snapshot_type > 4 || s.flags > 3 {
                return Err(Error::malformed("NX snapshot type or flags are invalid"));
            }
            if (s.flags & 1 != 0) != (s.build_id != [0; 32]) {
                return Err(Error::malformed("NX snapshot BUILD_ID_PRESENT flag disagrees with its build ID"));
            }
            if s.program_index != ABSENT && s.program_index as u64 >= np {
                return Err(Error::bounds("NX snapshot references a missing program"));
            }
            if s.program_index == ABSENT && s.snapshot_type != SNAPSHOT_DLC {
                return Err(Error::malformed("NX executable snapshot without a program"));
            }
            if s.dependency_count > 0 && s.first_dependency as u64 != next_dep {
                return Err(Error::malformed("NX dependency ranges do not partition the table"));
            }
            next_dep += s.dependency_count as u64;
        }
        if next_dep != self.dependencies.len() as u64 {
            return Err(Error::malformed("NX dependency ranges do not cover the table"));
        }
        for (pi, p) in self.programs.iter().enumerate() {
            if p.program_id == 0 || p.application_index as usize >= self.applications.len() || p.kind > 2 || p.snapshot_count == 0 {
                return Err(Error::malformed("NX program row is invalid"));
            }
            let end = p.first_snapshot as u64 + p.snapshot_count as u64;
            if end > ns || self.snapshots[p.first_snapshot as usize..end as usize].iter().any(|s| s.program_index != pi as u32) {
                return Err(Error::malformed("NX program snapshot range covers other snapshots"));
            }
        }
        let mut identities = std::collections::HashSet::new();
        for s in &self.snapshots {
            if !identities.insert(s.identity) {
                return Err(Error::malformed("two NX snapshots share an identity"));
            }
        }
        // Extensions: reject unknown required ones; read the structural ones.
        let mut seen = std::collections::HashSet::new();
        for e in &self.extensions {
            if !seen.insert((e.type_id, e.owner_kind, e.owner_index)) {
                return Err(Error::malformed("duplicate NX extension"));
            }
            let known = matches!(
                e.type_id,
                EXT_REQUIRED_FIRMWARE
                    | EXT_LANGUAGES
                    | EXT_REGIONS
                    | EXT_METADATA_HISTORY
                    | EXT_NATIVE_METADATA
                    | EXT_RECIPES
                    | EXT_SOURCE_RESOURCES
                    | EXT_EXTRA_FILES
            );
            if !known && e.flags & 1 != 0 {
                return Err(Error::unsupported(format!("NX archive requires unknown extension 0x{:08x}", e.type_id)));
            }
            if e.type_id == EXT_SOURCE_RESOURCES {
                let d = B(&e.data);
                if d.get(0, 4)? != b"NXSR" || d.u16(4)? != 1 || d.u16(6)? != 16 {
                    return Err(Error::malformed("NX source resources header is invalid"));
                }
                let n = d.u32(8)? as u64;
                if e.data.len() as u64 != 16 + n * 8 {
                    return Err(Error::malformed("NX source resources payload size is wrong"));
                }
                for i in 0..n {
                    self.resources.push((e.owner_index, d.u32(16 + i * 8)?, d.u32(20 + i * 8)?));
                }
            } else if e.type_id == EXT_EXTRA_FILES {
                let d = B(&e.data);
                if e.data.len() != 16 || d.get(0, 4)? != b"NXEX" || d.u16(4)? != 1 {
                    return Err(Error::malformed("NX extra-files payload is invalid"));
                }
                self.extra_root = Some(d.u32(8)?);
            }
        }
        if (self.header.minor == 3) != !self.resources.is_empty() {
            return Err(Error::malformed("NX 0.3 requires Source Resources and NX 0.2 forbids them"));
        }
        Ok(())
    }

    fn load_media(&mut self) -> Result<()> {
        if self.header.media.1 == 0 {
            if self.applications.iter().any(|a| a.icon != ABSENT || a.nacp != ABSENT) || self.localized.iter().any(|l| l.icon != ABSENT) {
                return Err(Error::malformed("NX catalog references media but the archive has no Media region"));
            }
            return Ok(());
        }
        let (off, size) = self.header.media;
        let head = read_vec(self.source.as_ref(), off, MEDIA_HEADER.min(size), MEDIA_HEADER)?;
        let h = B(&head);
        if h.get(0, 4)? != b"NXMD" || h.u16(4)? != 1 || h.u16(6)? != MEDIA_HEADER as u16 || h.u64(8)? != size {
            return Err(Error::malformed("NX media header is invalid"));
        }
        let count = h.u32(16)? as u64;
        if count == 0 || count > 65535 || h.u16(20)? != MEDIA_RECORD as u16 || h.u32(24)? != MEDIA_HEADER as u32 {
            return Err(Error::malformed("NX media record table is invalid"));
        }
        let payload_area = align(MEDIA_HEADER + count * MEDIA_RECORD, 16)?;
        if h.u32(28)? as u64 != payload_area || payload_area > size {
            return Err(Error::malformed("NX media payload area offset is wrong"));
        }
        let table = read_vec(self.source.as_ref(), off + MEDIA_HEADER, count * MEDIA_RECORD, count * MEDIA_RECORD)?;
        let t = B(&table);
        let mut cursor = payload_area;
        for i in 0..count {
            let o = i * MEDIA_RECORD;
            let r = MediaRecord { media_type: t.u16(o)?, size: t.u64(o + 4)?, offset: t.u64(o + 20)?, sha256: t.arr(o + 28)? };
            if !(1..=5).contains(&r.media_type) || t.u8(o + 2)? != 0 || t.u8(o + 3)? != 0 || t.u64(o + 12)? != r.size || t.u32(o + 60)? != 0
            {
                return Err(Error::malformed("NX media record is invalid"));
            }
            if r.size == 0 || r.size > 64 << 20 || r.offset != align(cursor, 16)? || r.offset + r.size > size {
                return Err(Error::malformed("NX media payload range is invalid"));
            }
            cursor = r.offset + r.size;
            self.media.push(r);
        }
        if cursor != size {
            return Err(Error::malformed("NX media region does not end at its last payload"));
        }
        let m = self.media.len() as u32;
        let ok = |i: u32, types: &[u16]| i == ABSENT || (i < m && types.contains(&self.media[i as usize].media_type));
        for a in &self.applications {
            if !ok(a.icon, &[MEDIA_PNG, MEDIA_JPEG]) || !ok(a.nacp, &[MEDIA_NACP]) {
                return Err(Error::malformed("NX application media reference has the wrong type"));
            }
        }
        for l in &self.localized {
            if !ok(l.icon, &[MEDIA_PNG, MEDIA_JPEG]) {
                return Err(Error::malformed("NX localized icon reference has the wrong type"));
            }
        }
        Ok(())
    }

    pub fn read_media(&self, i: u32) -> Result<Vec<u8>> {
        let r = self.media.get(i as usize).ok_or_else(|| Error::bounds("no such NX media record"))?;
        read_vec(self.source.as_ref(), self.header.media.0 + r.offset, r.size, r.size)
    }

    fn load_manifest(&mut self, limits: &crate::ResourceLimits) -> Result<()> {
        let man = self.section(self.header.manifest, limits.max_metadata.max(64 << 20))?;
        if crate::crypto::sha256(&man) != self.header.manifest_sha256 {
            return Err(Error::integrity("NX manifest SHA-256 does not match the header"));
        }
        let m = B(&man);
        if m.get(0, 4)? != b"NXMF" || m.u16(4)? != 1 || m.u16(6)? != MANIFEST_HEADER as u16 || m.u64(8)? != man.len() as u64 {
            return Err(Error::malformed("NX manifest header is invalid"));
        }
        m.zero(80, 16, "manifest reserved")?;
        let (nd, nf, ne, nr) = (m.u32(16)? as u64, m.u32(20)? as u64, m.u32(24)? as u64, m.u32(28)? as u64);
        if nd == 0 || nd > 16_777_216 || nf > 33_554_432 || ne > 50_331_648 || nd + nf > limits.max_entries.max(1 << 20) * 4 {
            return Err(Error::limit("NX manifest counts are outside their limits"));
        }
        let (dof, fof, eof, rof, pof, psz) = (m.u64(32)?, m.u64(40)?, m.u64(48)?, m.u64(56)?, m.u64(64)?, m.u64(72)?);
        let mut cursor = MANIFEST_HEADER;
        for (off, count, size, al, what) in [
            (dof, nd, DIRECTORY_SIZE, 8, "directory"),
            (fof, nf, FILE_SIZE, 8, "file"),
            (eof, ne, ENTRY_SIZE, 8, "entry"),
            (rof, nr, 4, 4, "block reference"),
        ] {
            if count == 0 {
                if off != 0 {
                    return Err(Error::malformed(format!("empty NX {what} table has a nonzero offset")));
                }
                continue;
            }
            if off != align(cursor, al)? {
                return Err(Error::malformed(format!("NX {what} table is not at its canonical offset")));
            }
            cursor = off + count * size;
        }
        if pof != align(cursor, 8)? || pof + psz != man.len() as u64 || psz > 2 << 30 {
            return Err(Error::malformed("NX path pool range is invalid"));
        }
        let mut next_entry = 0u64;
        for i in 0..nd {
            let o = dof + i * DIRECTORY_SIZE;
            let (first, count) = (m.u32(o)?, m.u32(o + 4)?);
            if m.u32(o + 8)? != 0 || m.u32(o + 12)? != 0 || first as u64 != next_entry {
                return Err(Error::malformed("NX directory entry ranges do not partition the entry table"));
            }
            next_entry += count as u64;
            self.directories.push((first, count));
        }
        if next_entry != ne {
            return Err(Error::malformed("NX directory entry ranges do not cover the entry table"));
        }
        for i in 0..ne {
            let o = eof + i * ENTRY_SIZE;
            let (noff, nlen, target, kind) = (m.u64(o)?, m.u32(o + 8)?, m.u32(o + 12)?, m.u8(o + 16)?);
            if m.u8(o + 17)? != 0 || m.u16(o + 18)? != 0 || m.u32(o + 20)? != 0 {
                return Err(Error::malformed("NX directory entry reserved fields are not zero"));
            }
            if noff < pof || noff.checked_add(nlen as u64).is_none_or(|e| e > man.len() as u64) {
                return Err(Error::bounds("NX entry name outside the path pool"));
            }
            let name = &man[noff as usize..noff as usize + nlen as usize];
            if !valid_component(name) {
                return Err(Error::unsafe_path(format!("NX entry name {:?} is not a valid path component", String::from_utf8_lossy(name))));
            }
            let is_dir = match kind {
                1 => {
                    if target as u64 >= nd {
                        return Err(Error::bounds("NX entry targets a missing directory"));
                    }
                    true
                }
                2 => {
                    if target as u64 >= nf {
                        return Err(Error::bounds("NX entry targets a missing file"));
                    }
                    false
                }
                _ => return Err(Error::malformed("NX entry kind is invalid")),
            };
            self.entries.push(NxEntry { name: String::from_utf8_lossy(name).into_owned(), target, is_dir });
        }
        for &(first, count) in &self.directories {
            let es = &self.entries[first as usize..(first + count) as usize];
            if es.windows(2).any(|w| w[0].name.as_bytes() >= w[1].name.as_bytes()) {
                return Err(Error::malformed("NX directory entries are not strictly sorted"));
            }
        }
        let mut next_ref = 0u64;
        for i in 0..nf {
            let o = fof + i * FILE_SIZE;
            let f = NxFile {
                size: m.u64(o)?,
                first_ref: m.u32(o + 8)?,
                block_count: m.u32(o + 12)?,
                chunk_log2: m.u8(o + 16)?,
                sha256: m.arr(o + 20)?,
            };
            if m.u8(o + 17)? != 0 || m.u16(o + 18)? != 0 {
                return Err(Error::malformed("NX file flags are not zero"));
            }
            m.zero(o + 52, 12, "file reserved1")?;
            if !(16..=20).contains(&f.chunk_log2) || f.size > i64::MAX as u64 {
                return Err(Error::malformed("NX file chunk size or length is invalid"));
            }
            if f.size.div_ceil(1u64 << f.chunk_log2) != f.block_count as u64 || f.first_ref as u64 != next_ref {
                return Err(Error::malformed("NX file block references are inconsistent"));
            }
            next_ref += f.block_count as u64;
            self.files.push(f);
        }
        if next_ref != nr {
            return Err(Error::malformed("NX file block-reference ranges do not cover the table"));
        }
        for i in 0..nr {
            let id = m.u32(rof + i * 4)?;
            if id as u64 >= self.header.block_count {
                return Err(Error::bounds("NX block reference exceeds the block count"));
            }
            self.refs.push(id);
        }
        Ok(())
    }

    fn load_blocks(&mut self) -> Result<()> {
        let n = self.header.block_count;
        if n == 0 {
            if !self.refs.is_empty() {
                return Err(Error::malformed("NX files reference blocks but the archive has none"));
            }
            if self.header.index_sha256 != crate::crypto::sha256(b"") {
                return Err(Error::integrity("NX index SHA-256 of an empty index is wrong"));
            }
            return Ok(());
        }
        const INDEX_LIMIT: u64 = 1 << 30;
        let index = read_vec(self.source.as_ref(), self.header.block_index_offset, n * BLOCK_SIZE, INDEX_LIMIT)?;
        let integrity = self.section(self.header.integrity, INDEX_LIMIT)?;
        let mut cat = index.clone();
        cat.extend_from_slice(&integrity);
        if crate::crypto::sha256(&cat) != self.header.index_sha256 {
            return Err(Error::integrity("NX block index SHA-256 does not match the header"));
        }
        drop(cat);
        let x = B(&index);
        let (data_off, data_end) = (self.header.data.0, self.header.data.0 + self.header.data.1);
        let mut prev_end = data_off;
        let mut checks = 0u64;
        for i in 0..n {
            let o = i * BLOCK_SIZE;
            let b = Block {
                offset: x.u64(o)?,
                stored: x.u32(o + 8)?,
                logical: x.u32(o + 12)?,
                codec: x.u8(o + 16)?,
                first_check: x.u32(o + 20)?,
            };
            if x.u8(o + 17)? != 0 || x.u16(o + 18)? != 0 || b.codec > 1 {
                return Err(Error::malformed("NX block codec or flags are invalid"));
            }
            if b.stored == 0
                || b.stored as u64 > MAX_BLOCK + 65536
                || b.logical == 0
                || b.logical as u64 > MAX_BLOCK
                || (b.codec == 0 && b.stored != b.logical)
            {
                return Err(Error::malformed("NX block sizes are invalid"));
            }
            if !b.offset.is_multiple_of(16)
                || b.offset < align(prev_end, 16)?.max(data_off)
                || b.offset.saturating_add(b.stored as u64) > data_end
            {
                return Err(Error::malformed("NX blocks are misordered or outside the data region"));
            }
            if b.first_check as u64 != checks {
                return Err(Error::malformed("NX block first_check is inconsistent"));
            }
            checks += (b.logical as u64).div_ceil(CHECK_SIZE);
            prev_end = b.offset + b.stored as u64;
            self.blocks.push(b);
        }
        if prev_end != data_end {
            return Err(Error::malformed("NX data region does not end at the last block"));
        }
        if checks * 4 != self.header.integrity.1 {
            return Err(Error::malformed("NX integrity table size differs from the block slices"));
        }
        self.checks = integrity.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap_or([0; 4]))).collect();
        for f in &self.files {
            let refs = &self.refs[f.first_ref as usize..(f.first_ref + f.block_count) as usize];
            let chunk = 1u64 << f.chunk_log2;
            for (k, &id) in refs.iter().enumerate() {
                let want = if k + 1 == refs.len() { f.size - k as u64 * chunk } else { chunk };
                if self.blocks[id as usize].logical as u64 != want {
                    return Err(Error::malformed("NX block length disagrees with its file chunk"));
                }
            }
        }
        Ok(())
    }

    /// Walk a tree: `visit(path, is_dir, target)`; root path is "".
    pub fn walk(&self, root: u32, _limits: &crate::ResourceLimits, visit: &mut dyn FnMut(&str, bool, u32) -> Result<()>) -> Result<()> {
        if root as usize >= self.directories.len() {
            return Err(Error::bounds("NX tree root is not a directory"));
        }
        let mut seen_dirs = std::collections::HashSet::new();
        let mut seen_files = std::collections::HashSet::new();
        let mut stack = vec![(root, String::new(), 0u32)];
        while let Some((d, path, depth)) = stack.pop() {
            if depth > 256 {
                return Err(Error::limit("NX tree exceeds the directory depth limit"));
            }
            if !seen_dirs.insert(d) {
                return Err(Error::malformed("NX directory reached twice within one tree"));
            }
            visit(&path, true, d)?;
            let (first, count) = self.directories[d as usize];
            let mut sub = Vec::new();
            for e in &self.entries[first as usize..(first + count) as usize] {
                let p = if path.is_empty() { e.name.clone() } else { format!("{path}/{}", e.name) };
                if e.is_dir {
                    sub.push((e.target, p, depth + 1));
                } else {
                    if !seen_files.insert(e.target) {
                        return Err(Error::malformed("NX file record reached twice within one tree"));
                    }
                    visit(&p, false, e.target)?;
                }
            }
            stack.extend(sub.into_iter().rev());
        }
        Ok(())
    }

    fn check_trees(&mut self, limits: &crate::ResourceLimits) -> Result<()> {
        for si in 0..self.snapshots.len() {
            let s = self.snapshots[si].clone();
            let mut size = 0u64;
            self.walk(s.root, limits, &mut |_, is_dir, t| {
                if !is_dir {
                    size = size.checked_add(self.files[t as usize].size).ok_or_else(|| Error::bounds("snapshot size overflows"))?;
                }
                Ok(())
            })?;
            if size != s.logical_size {
                return Err(Error::malformed(format!("NX snapshot {si} logical size disagrees with its tree")));
            }
        }
        for &(_, _, root) in &self.resources.clone() {
            self.walk(root, limits, &mut |_, _, _| Ok(()))?;
        }
        if let Some(r) = self.extra_root {
            self.walk(r, limits, &mut |_, _, _| Ok(()))?;
        }
        Ok(())
    }

    /// Recompute a snapshot's canonical identity from the manifest (uses recorded hashes).
    pub fn recompute_identity(&self, si: usize, limits: &crate::ResourceLimits) -> Result<[u8; 32]> {
        let s = &self.snapshots[si];
        let a = &self.applications[s.application as usize];
        let program_id = (s.program_index != ABSENT).then(|| self.programs[s.program_index as usize].program_id);
        let mut nodes = Vec::new();
        self.walk(s.root, limits, &mut |p, is_dir, t| {
            let f = (!is_dir).then(|| (self.files[t as usize].size, self.files[t as usize].sha256));
            nodes.push((p.to_string(), f));
            Ok(())
        })?;
        Ok(snapshot_identity(a.platform, a.application_id, program_id, s.snapshot_type, s.version, &s.content_id, &mut nodes))
    }

    pub fn open_file(self: &Arc<Self>, file: u32) -> Result<SharedSource> {
        let f = self.files.get(file as usize).ok_or_else(|| Error::bounds("no such NX file"))?;
        if f.size == 0 {
            return Ok(Arc::new(MemorySource::new(Vec::new())));
        }
        Ok(Arc::new(NxFileSource { nx: self.clone(), file, cache: Mutex::new(None) }))
    }

    /// Decoded logical bytes of a block, every slice CRC-32C checked.
    pub fn read_block(&self, id: u32) -> Result<Vec<u8>> {
        let b = *self.blocks.get(id as usize).ok_or_else(|| Error::bounds("no such NX block"))?;
        let stored = read_vec(self.source.as_ref(), b.offset, b.stored as u64, MAX_BLOCK + 65536)?;
        let data = if b.codec == 0 {
            stored
        } else {
            crate::compression::decompress(crate::compression::Codec::Zstd, &stored, Some(b.logical as usize), b.logical as usize)?
        };
        if data.len() != b.logical as usize {
            return Err(Error::integrity(format!("NX block {id} decoded to {} bytes, expected {}", data.len(), b.logical)));
        }
        self.check_slices(id, &b, &data, 0)?;
        Ok(data)
    }

    fn check_slices(&self, id: u32, b: &Block, data: &[u8], first_slice: u64) -> Result<()> {
        for (k, c) in slice_crcs(data).iter().enumerate() {
            let idx = b.first_check as usize + first_slice as usize + k;
            if self.checks.get(idx) != Some(c) {
                return Err(Error::integrity(format!("NX block {id} slice {} fails its CRC-32C", first_slice as usize + k)));
            }
        }
        Ok(())
    }

    /// Read part of a RAW block, checking only the covering slices.
    fn read_raw_range(&self, id: u32, within: u64, out: &mut [u8]) -> Result<()> {
        let b = self.blocks[id as usize];
        let s0 = within / CHECK_SIZE;
        let s1 = (within + out.len() as u64).div_ceil(CHECK_SIZE);
        let start = s0 * CHECK_SIZE;
        let end = (s1 * CHECK_SIZE).min(b.logical as u64);
        let buf = read_vec(self.source.as_ref(), b.offset + start, end - start, end - start)?;
        self.check_slices(id, &b, &buf, s0)?;
        let o = (within - start) as usize;
        out.copy_from_slice(&buf[o..o + out.len()]);
        Ok(())
    }
}

/// Random-access, CRC-checked view of one NX file.
struct NxFileSource {
    nx: Arc<Nx>,
    file: u32,
    cache: Mutex<Option<(u32, Arc<Vec<u8>>)>>,
}

impl crate::DataSource for NxFileSource {
    fn len(&self) -> Result<u64> {
        Ok(self.nx.files[self.file as usize].size)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        let f = &self.nx.files[self.file as usize];
        crate::check_range(offset, out.len() as u64, f.size)?;
        let chunk = 1u64 << f.chunk_log2;
        let mut done = 0usize;
        while done < out.len() {
            let pos = offset + done as u64;
            let k = pos / chunk;
            let within = pos % chunk;
            let id = self.nx.refs[f.first_ref as usize + k as usize];
            let b = self.nx.blocks[id as usize];
            let n = ((b.logical as u64 - within) as usize).min(out.len() - done);
            if b.codec == 0 {
                self.nx.read_raw_range(id, within, &mut out[done..done + n])?;
            } else {
                let mut c = self.cache.lock().map_err(|_| Error::internal("NX cache poisoned"))?;
                let data = match c.as_ref() {
                    Some((cid, d)) if *cid == id => d.clone(),
                    _ => {
                        let d = Arc::new(self.nx.read_block(id)?);
                        *c = Some((id, d.clone()));
                        d
                    }
                };
                out[done..done + n].copy_from_slice(&data[within as usize..within as usize + n]);
            }
            done += n;
        }
        Ok(())
    }
}

/// PackageReader for `.nx`.
pub struct NxReader {
    nx: Arc<Nx>,
    table: NodeTable,
    labels: Vec<String>,
    limits: crate::ResourceLimits,
}

fn snapshot_labels(nx: &Nx) -> Vec<String> {
    let base: Vec<String> = nx
        .snapshots
        .iter()
        .map(|s| {
            let app = nx.applications.get(s.application as usize).map(|a| a.application_id).unwrap_or(0);
            let kind = match (s.snapshot_type, s.addon_title_id()) {
                (SNAPSHOT_DLC, Some(t)) => format!("dlc-{t:016x}"),
                (SNAPSHOT_DLC, None) => format!("dlc-{}", hex(&s.content_id[..8])),
                (t, _) => snapshot_type_name(t).to_string(),
            };
            format!("{app:016x}/{kind}-v{}", s.version)
        })
        .collect();
    base.iter()
        .enumerate()
        .map(|(i, l)| {
            if base.iter().filter(|x| *x == l).count() > 1 {
                let s = &nx.snapshots[i];
                match nx.programs.get(s.program_index as usize) {
                    Some(p) => format!("{l}-{:016x}", p.program_id),
                    None => format!("{l}-{i}"),
                }
            } else {
                l.clone()
            }
        })
        .collect()
}

fn image_ext(t: u16) -> &'static str {
    if t == MEDIA_PNG { "png" } else { "jpg" }
}

impl NxReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let nx = Arc::new(Nx::open(source, &ctx.limits)?);
        let labels = snapshot_labels(&nx);
        let mut table = NodeTable::new();
        let push_tree = |table: &mut NodeTable, root: u32, prefix: &str, top: ContentNode| -> Result<()> {
            let mut nodes: Vec<(String, bool, u32)> = Vec::new();
            nx.walk(root, &ctx.limits, &mut |p, d, t| {
                nodes.push((p.to_string(), d, t));
                Ok(())
            })?;
            for (p, is_dir, t) in nodes {
                if p.is_empty() {
                    table.push(top.clone(), None);
                    continue;
                }
                let full = format!("{prefix}/{p}");
                if is_dir {
                    table.push(ContentNode::dir(0, full), None);
                } else {
                    let f = &nx.files[t as usize];
                    let mut n = ContentNode::file(0, full, f.size).encrypted(false).hash("sha256", hex(&f.sha256), None);
                    if p.ends_with(".nca") {
                        n = n.kind(NodeKind::Content).hint(crate::switch::formats::SWITCH_NCA).meta("decrypted", "DNCA");
                    }
                    table.push(n, Some(nx.open_file(t)?));
                }
            }
            Ok(())
        };
        for (ai, a) in nx.applications.iter().enumerate() {
            let app = format!("{:016x}", a.application_id);
            let mut media: Vec<(String, u32)> = Vec::new();
            if a.nacp != ABSENT {
                media.push(("control.nacp".into(), a.nacp));
            }
            if a.icon != ABSENT {
                media.push((format!("icon.{}", image_ext(nx.media[a.icon as usize].media_type)), a.icon));
            }
            for l in &nx.localized[a.first_localized as usize..(a.first_localized + a.localized_count) as usize] {
                if l.icon != ABSENT {
                    media.push((format!("icon_{}.{}", l.language, image_ext(nx.media[l.icon as usize].media_type)), l.icon));
                }
            }
            if !media.is_empty() {
                table.push(ContentNode::dir(0, format!("{app}/metadata")), None);
                for (name, i) in media {
                    let bytes = nx.read_media(i)?;
                    let n = ContentNode::file(0, format!("{app}/metadata/{name}"), bytes.len() as u64).kind(NodeKind::Metadata).hash(
                        "sha256",
                        hex(&nx.media[i as usize].sha256),
                        None,
                    );
                    table.push(n, Some(Arc::new(MemorySource::new(bytes))));
                }
            }
            for si in a.first_snapshot..a.first_snapshot + a.snapshot_count {
                let s = &nx.snapshots[si as usize];
                let label = &labels[si as usize];
                let mut top = ContentNode::dir(0, label.clone())
                    .kind(NodeKind::Partition)
                    .meta("snapshot_type", snapshot_type_name(s.snapshot_type))
                    .meta("version", s.version as u64)
                    .meta("identity", hex(&s.identity));
                if let Some(d) = &s.display_version {
                    top = top.meta("display_version", d.clone());
                }
                if s.build_id != [0; 32] {
                    top = top.meta("build_id", hex(&s.build_id));
                }
                push_tree(&mut table, s.root, label, top)?;
            }
            for (ri, &(owner, kind, root)) in nx.resources.iter().enumerate() {
                if owner as usize == ai {
                    let prefix = format!("{app}/source-resources/{ri}");
                    push_tree(&mut table, root, &prefix, ContentNode::dir(0, prefix.clone()).meta("resource_kind", kind as u64))?;
                }
            }
        }
        if let Some(r) = nx.extra_root {
            push_tree(&mut table, r, "extra", ContentNode::dir(0, "extra"))?;
        }
        Ok(NxReader { nx, table, labels, limits: ctx.limits })
    }
}

impl PackageReader for NxReader {
    fn format(&self) -> FormatId {
        SWITCH_NX
    }
    fn info(&self) -> Result<PackageInfo> {
        let nx = &self.nx;
        let mut i = PackageInfo::new(SWITCH_NX, Platform::Switch, nx.source.len()?);
        i.encrypted = Some(false);
        let a = &nx.applications[0];
        i.title = a.title.clone();
        i.title_id = Some(format!("{:016x}", a.application_id));
        i.family_id = i.title_id.clone();
        i.category = if nx.snapshots.len() > 1 || nx.applications.len() > 1 {
            ContentCategory::MultiContent
        } else {
            match nx.snapshots[0].snapshot_type {
                SNAPSHOT_BASE => ContentCategory::Application,
                SNAPSHOT_DLC => ContentCategory::AddOn,
                _ => ContentCategory::Patch,
            }
        };
        if a.metadata_snapshot != ABSENT {
            i.version = nx.snapshots[a.metadata_snapshot as usize].display_version.clone();
        }
        if let Some(p) = &a.publisher {
            i.field("publisher", p.clone());
        }
        i.field("nx_version", format!("0.{}", nx.header.minor));
        i.field("generation", nx.header.generation);
        i.field(
            "applications",
            nx.applications
                .iter()
                .map(|a| {
                    format!(
                        "{:016x} ({}){}",
                        a.application_id,
                        platform_name(a.platform),
                        a.title.as_ref().map(|t| format!(" \"{t}\"")).unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>(),
        );
        i.field(
            "snapshots",
            nx.snapshots
                .iter()
                .zip(&self.labels)
                .map(|(s, l)| {
                    format!(
                        "{l}: {} version {}{} identity {}",
                        snapshot_type_name(s.snapshot_type),
                        s.version,
                        s.display_version.as_ref().map(|d| format!(" ({d})")).unwrap_or_default(),
                        &hex(&s.identity)[..16]
                    )
                })
                .collect::<Vec<_>>(),
        );
        let loc: Vec<String> = nx.localized[a.first_localized as usize..(a.first_localized + a.localized_count) as usize]
            .iter()
            .filter_map(|l| l.title.as_ref().map(|t| format!("{}: {t}", l.language)))
            .collect();
        if !loc.is_empty() {
            i.field("localized_titles", loc);
        }
        if !nx.media.is_empty() {
            i.field("media", nx.media.iter().map(|m| format!("{} ({} bytes)", media_type_name(m.media_type), m.size)).collect::<Vec<_>>());
        }
        i.field("blocks", nx.blocks.len() as u64);
        i.field("files", nx.files.len() as u64);
        let logical: u64 = nx.files.iter().map(|f| f.size).sum();
        i.sizes.uncompressed = Some(logical);
        i.sizes.payload = Some(nx.header.data.1);
        if nx.extensions.iter().any(|e| e.type_id == EXT_RECIPES) {
            i.field("rebuild_recipes", true);
        }
        i.warnings.extend(nx.warnings.iter().cloned());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let nx = &self.nx;
        let mut r = VerifyReport::new(SWITCH_NX, level);
        r.pass(
            CheckLevel::Structure,
            "header",
            Some(format!("NX 0.{} generation {}, CRC-32C valid", nx.header.minor, nx.header.generation)),
        );
        r.check(CheckLevel::Structure, "header slots", nx.other_slot_valid, "both header slots valid");
        r.pass(
            CheckLevel::Structure,
            "catalog",
            Some(format!("{} applications, {} snapshots; SHA-256 and references checked", nx.applications.len(), nx.snapshots.len())),
        );
        r.pass(
            CheckLevel::Structure,
            "manifest",
            Some(format!("{} directories, {} files; SHA-256, order and ranges checked", nx.directories.len(), nx.files.len())),
        );
        r.pass(CheckLevel::Structure, "block index", Some(format!("{} blocks; SHA-256 and layout checked", nx.blocks.len())));
        for (si, s) in nx.snapshots.iter().enumerate() {
            match nx.recompute_identity(si, &self.limits) {
                Ok(id) => r.check(
                    CheckLevel::Structure,
                    &format!("{} identity", self.labels[si]),
                    id == s.identity,
                    "canonical snapshot identity (§12)",
                ),
                Err(e) => r.fail(CheckLevel::Structure, &format!("{} identity", self.labels[si]), e.to_string()),
            }
        }
        for w in &nx.warnings {
            r.warn(CheckLevel::Structure, "archive", w.clone());
        }
        if level.wants_content() {
            for (i, m) in nx.media.iter().enumerate() {
                let ok = nx.read_media(i as u32).map(|b| crate::crypto::sha256(&b) == m.sha256).unwrap_or(false);
                if !ok {
                    r.fail(CheckLevel::Content, &format!("media {i} SHA-256"), "payload does not match its digest");
                }
            }
            let total: u64 = nx.blocks.iter().map(|b| b.logical as u64).sum();
            let mut prog = crate::ByteProgress::new(job, crate::Phase::Verifying, Some(total));
            let mut bad_blocks = 0usize;
            for id in 0..nx.blocks.len() as u32 {
                job.check_cancel()?;
                if let Err(e) = nx.read_block(id) {
                    bad_blocks += 1;
                    if bad_blocks <= 20 {
                        r.fail(CheckLevel::Content, &format!("block {id}"), e.to_string());
                    }
                }
                prog.advance(nx.blocks[id as usize].logical as u64)?;
            }
            if bad_blocks == 0 {
                r.pass(
                    CheckLevel::Content,
                    "block slices",
                    Some(format!("{} blocks decoded, every 16 KiB slice CRC-32C matches", nx.blocks.len())),
                );
            }
            let mut bad_files = 0usize;
            for (fi, f) in nx.files.iter().enumerate() {
                job.check_cancel()?;
                let ok = nx
                    .open_file(fi as u32)
                    .and_then(|s| crate::crypto::hash_range(s.as_ref(), 0, f.size, crate::crypto::HashAlg::Sha256, None))
                    .map(|h| h == f.sha256);
                match ok {
                    Ok(true) => {}
                    Err(e) if e.code() == crate::ErrorCode::Cancelled => return Err(e),
                    _ => {
                        bad_files += 1;
                        if bad_files <= 20 {
                            r.fail(CheckLevel::Content, &format!("file {fi} SHA-256"), "content does not match the recorded SHA-256");
                        }
                    }
                }
            }
            if bad_files == 0 {
                r.pass(CheckLevel::Content, "file SHA-256", Some(format!("{} files recomputed", nx.files.len())));
            }
        }
        r.authenticity_unavailable("NX has no signatures (hashes detect damage, not tampering)");
        r.limitation("compatibility with consuming emulators is not asserted");
        Ok(r)
    }
    fn content_graph(&self) -> Result<crate::ContentGraph> {
        let nx = &self.nx;
        let mut g = crate::ContentGraph::default();
        let key = |i: usize| self.labels[i].clone();
        for (i, s) in nx.snapshots.iter().enumerate() {
            let a = &nx.applications[s.application as usize];
            let role = match s.snapshot_type {
                SNAPSHOT_BASE => crate::TitleRole::Base,
                SNAPSHOT_UPDATE | SNAPSHOT_STANDALONE_UPDATE => crate::TitleRole::Update,
                SNAPSHOT_DLC => crate::TitleRole::AddOn,
                _ => crate::TitleRole::Unknown,
            };
            let title_id = match (s.addon_title_id(), nx.programs.get(s.program_index as usize)) {
                (Some(t), _) => t,
                (None, Some(p)) => p.program_id,
                (None, None) => a.application_id,
            };
            let mut md = crate::Metadata::new();
            md.insert("identity".into(), hex(&s.identity).into());
            md.insert("platform".into(), platform_name(a.platform).into());
            if let Some(d) = &s.display_version {
                md.insert("display_version".into(), d.clone().into());
            }
            g.titles.push(crate::TitleRecord {
                key: key(i),
                title_id: format!("{title_id:016x}"),
                role,
                version: Some(s.version as u64),
                provenance: "nx snapshot".into(),
                content_ids: if s.flags & 2 == 0 && s.content_id != [0; 16] { vec![hex(&s.content_id)] } else { Vec::new() },
                metadata: md,
            });
            for d in &nx.dependencies[s.first_dependency as usize..(s.first_dependency + s.dependency_count) as usize] {
                let kind = match (d.kind, role) {
                    (DEP_REQUIRED_BASE, crate::TitleRole::Update) => crate::RelationKind::UpdateOf,
                    (_, crate::TitleRole::AddOn) => crate::RelationKind::AddOnOf,
                    _ => crate::RelationKind::Requires,
                };
                match nx.snapshots.iter().position(|t| t.identity == d.target) {
                    Some(t) => g.relations.push(crate::Relation { from: key(i), to: key(t), kind }),
                    None => {
                        g.unresolved.push(format!("{} depends on snapshot {} which is not in this archive", key(i), &hex(&d.target)[..16]))
                    }
                }
            }
        }
        Ok(g)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(crate::switch::capabilities_for(SWITCH_NX))
    }
}

// =======================================================================================
// Writer
// =======================================================================================

/// A file to store.
pub(crate) struct WFile {
    pub name: String,
    pub size: u64,
    pub source: SharedSource,
    /// Identical sources (same key at the same path) are read once and share one record.
    pub reuse_key: Option<String>,
}

pub(crate) enum WEntry {
    /// Nested directory (extracted trees); native snapshots are flat.
    #[allow(dead_code)]
    Dir {
        name: String,
        entries: Vec<WEntry>,
    },
    File(WFile),
}

/// Display metadata of one snapshot (from its native Control data).
#[derive(Default)]
pub(crate) struct WMetadata {
    pub title: Option<String>,
    pub publisher: Option<String>,
    pub icon: Option<Vec<u8>>,
    pub nacp: Option<Vec<u8>>,
    /// `(language tag, title, icon)`.
    pub localized: Vec<(String, Option<String>, Option<Vec<u8>>)>,
}

pub(crate) struct WSnapshot {
    pub program_id: Option<u64>,
    pub snapshot_type: u8,
    pub version: u32,
    pub content_id: [u8; 16],
    pub build_id: Option<[u8; 32]>,
    pub display_version: Option<String>,
    /// `(index of the target in this application's input snapshots, dependency kind)`.
    pub requires: Option<(usize, u8)>,
    pub metadata: Option<WMetadata>,
    pub required_firmware: Option<u32>,
    pub root: Vec<WEntry>,
}

pub(crate) struct WApplication {
    pub application_id: u64,
    pub platform: u8,
    /// `(program id, kind: 0 primary, 1 auxiliary)`.
    pub programs: Vec<(u64, u8)>,
    pub snapshots: Vec<WSnapshot>,
}

#[derive(Clone, Copy)]
pub(crate) struct WriteOptions {
    /// Zstandard level; `None` stores every block RAW.
    pub level: Option<i32>,
    pub chunk_log2: u8,
}

impl Default for WriteOptions {
    fn default() -> Self {
        WriteOptions { level: Some(3), chunk_log2: 18 }
    }
}

pub(crate) struct WriteStats {
    pub size: u64,
    pub files: usize,
    pub blocks: usize,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub deduplicated_chunks: u64,
}

/// A built tree node (data phase result).
enum BNode {
    Dir(String, Vec<BNode>),
    File(String, u32),
}

struct FileRec {
    size: u64,
    first_ref: u32,
    count: u32,
    log2: u8,
    sha256: [u8; 32],
}

struct DataWriter<'a> {
    out: &'a mut crate::AtomicFile,
    back: std::fs::File,
    cursor: u64,
    blocks: Vec<Block>,
    checks: Vec<u32>,
    refs: Vec<u32>,
    files: Vec<FileRec>,
    candidates: HashMap<(u32, u64), Vec<u32>>,
    opts: WriteOptions,
    dedup_hits: u64,
}

fn crc_key(len: usize, crcs: &[u32]) -> (u32, u64) {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for c in crcs {
        for b in c.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    (len as u32, h)
}

fn compress_block(data: &[u8], level: Option<i32>) -> Result<Option<Vec<u8>>> {
    let Some(level) = level else { return Ok(None) };
    if !cfg!(feature = "zstd") {
        return Ok(None);
    }
    let c = crate::compression::compress(crate::compression::Codec::Zstd, data, level)?;
    // Keep a frame only when it saves at least 25 % (reference writer policy).
    Ok((c.len() * 4 <= data.len() * 3).then_some(c))
}

impl DataWriter<'_> {
    fn stored_bytes(&mut self, id: u32) -> Result<Vec<u8>> {
        self.out.flush()?;
        let b = self.blocks[id as usize];
        let mut buf = vec![0u8; b.stored as usize];
        self.back.seek(SeekFrom::Start(b.offset))?;
        self.back.read_exact(&mut buf)?;
        if b.codec == 0 {
            Ok(buf)
        } else {
            crate::compression::decompress(crate::compression::Codec::Zstd, &buf, Some(b.logical as usize), b.logical as usize)
        }
    }

    fn find_existing(&mut self, data: &[u8], key: (u32, u64)) -> Result<Option<u32>> {
        let ids = self.candidates.get(&key).cloned().unwrap_or_default();
        for id in ids {
            if self.stored_bytes(id)? == data {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    fn write_block(&mut self, data: &[u8], crcs: Vec<u32>, key: (u32, u64), compressed: Option<Vec<u8>>) -> Result<u32> {
        let at = align(self.cursor, 16)?;
        crate::copy::write_zeros(&mut *self.out, at - self.cursor)?;
        let (codec, bytes): (u8, &[u8]) = match &compressed {
            Some(c) => (1, c.as_slice()),
            None => (0, data),
        };
        self.out.write_all(bytes)?;
        self.cursor = at + bytes.len() as u64;
        let id = self.blocks.len() as u32;
        self.blocks.push(Block {
            offset: at,
            stored: bytes.len() as u32,
            logical: data.len() as u32,
            codec,
            first_check: self.checks.len() as u32,
        });
        self.checks.extend_from_slice(&crcs);
        self.candidates.entry(key).or_default().push(id);
        Ok(id)
    }

    /// Store one file; returns its record index (a new record, or an identical earlier one
    /// at the same path).
    fn add_file(&mut self, f: &WFile, same_path: &[u32], job: &JobContext, prog: &mut crate::ByteProgress<'_>) -> Result<u32> {
        use sha2::Digest;
        let chunk = 1usize << self.opts.chunk_log2;
        let first_ref = self.refs.len() as u32;
        let mut sha = sha2::Sha256::new();
        let batch = (job.threads.max(1) * 2).max(4);
        let mut pos = 0u64;
        while pos < f.size {
            job.check_cancel()?;
            // Read a batch of chunks.
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            while chunks.len() < batch && pos < f.size {
                let n = ((f.size - pos) as usize).min(chunk);
                let mut buf = vec![0u8; n];
                f.source.read_exact_at(pos, &mut buf)?;
                sha.update(&buf);
                pos += n as u64;
                chunks.push(buf);
            }
            // Deduplicate before compressing: against stored blocks and earlier batch chunks.
            let crcs: Vec<Vec<u32>> = chunks.iter().map(|c| slice_crcs(c)).collect();
            let keys: Vec<(u32, u64)> = chunks.iter().zip(&crcs).map(|(c, k)| crc_key(c.len(), k)).collect();
            let mut resolved: Vec<Option<u32>> = Vec::with_capacity(chunks.len());
            let mut same_as: Vec<Option<usize>> = vec![None; chunks.len()];
            for i in 0..chunks.len() {
                let hit = self.find_existing(&chunks[i], keys[i])?;
                if hit.is_none() {
                    // An earlier new chunk of this batch with identical bytes.
                    same_as[i] =
                        (0..i).find(|&j| resolved[j].is_none() && same_as[j].is_none() && keys[j] == keys[i] && chunks[j] == chunks[i]);
                }
                if hit.is_some() || same_as[i].is_some() {
                    self.dedup_hits += 1;
                }
                resolved.push(hit);
            }
            let todo: Vec<usize> = (0..chunks.len()).filter(|&i| resolved[i].is_none() && same_as[i].is_none()).collect();
            let level = self.opts.level;
            let compressed: Vec<Result<Option<Vec<u8>>>> = if job.threads > 1 && todo.len() > 1 {
                std::thread::scope(|s| {
                    let hs: Vec<_> = todo
                        .iter()
                        .map(|&i| {
                            let c = &chunks[i];
                            s.spawn(move || compress_block(c, level))
                        })
                        .collect();
                    hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(Error::internal("compression worker panicked")))).collect()
                })
            } else {
                todo.iter().map(|&i| compress_block(&chunks[i], level)).collect()
            };
            let mut comp_iter = compressed.into_iter();
            let mut ids: Vec<u32> = Vec::with_capacity(chunks.len());
            for i in 0..chunks.len() {
                let id = if let Some(id) = resolved[i] {
                    id
                } else if let Some(j) = same_as[i] {
                    ids[j]
                } else {
                    let c = comp_iter.next().ok_or_else(|| Error::internal("compression result missing"))??;
                    self.write_block(&chunks[i], crcs[i].clone(), keys[i], c)?
                };
                ids.push(id);
                prog.advance(chunks[i].len() as u64)?;
            }
            self.refs.extend_from_slice(&ids);
        }
        let sha256: [u8; 32] = sha.finalize().into();
        let count = self.refs.len() as u32 - first_ref;
        // An unchanged file at the same path must reuse the existing record.
        for &fid in same_path {
            let r = &self.files[fid as usize];
            if r.size == f.size
                && r.sha256 == sha256
                && r.log2 == self.opts.chunk_log2
                && self.refs[r.first_ref as usize..(r.first_ref + r.count) as usize] == self.refs[first_ref as usize..]
            {
                self.refs.truncate(first_ref as usize);
                return Ok(fid);
            }
        }
        self.files.push(FileRec { size: f.size, first_ref, count, log2: self.opts.chunk_log2, sha256 });
        Ok(self.files.len() as u32 - 1)
    }
}

struct StringPool {
    bytes: Vec<u8>,
    map: HashMap<String, (u32, u32)>,
}
impl StringPool {
    fn new() -> Self {
        StringPool { bytes: Vec::new(), map: HashMap::new() }
    }
    fn intern(&mut self, s: Option<&str>) -> (u32, u32) {
        let Some(s) = s.filter(|s| !s.is_empty()) else { return (ABSENT, 0) };
        if let Some(&r) = self.map.get(s) {
            return r;
        }
        let r = (self.bytes.len() as u32, s.len() as u32);
        self.bytes.extend_from_slice(s.as_bytes());
        self.map.insert(s.to_string(), r);
        r
    }
}

#[derive(Default)]
struct MediaStage {
    records: Vec<(u16, Vec<u8>)>,
    icons: HashMap<(u16, [u8; 32]), u32>,
}
impl MediaStage {
    fn icon(&mut self, bytes: &[u8]) -> u32 {
        let t = if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
            MEDIA_PNG
        } else if bytes.starts_with(&[0xFF, 0xD8]) {
            MEDIA_JPEG
        } else {
            return ABSENT;
        };
        if bytes.is_empty() || bytes.len() > 64 << 20 {
            return ABSENT;
        }
        let key = (t, crate::crypto::sha256(bytes));
        if let Some(&i) = self.icons.get(&key) {
            return i;
        }
        let i = self.records.len() as u32;
        self.records.push((t, bytes.to_vec()));
        self.icons.insert(key, i);
        i
    }
    fn unique(&mut self, t: u16, bytes: &[u8]) -> u32 {
        if bytes.is_empty() || bytes.len() > 64 << 20 {
            return ABSENT;
        }
        let i = self.records.len() as u32;
        self.records.push((t, bytes.to_vec()));
        i
    }
    fn serialize(&self) -> Result<Vec<u8>> {
        if self.records.is_empty() {
            return Ok(Vec::new());
        }
        let n = self.records.len() as u64;
        let area = align(MEDIA_HEADER + n * MEDIA_RECORD, 16)?;
        let mut offs = Vec::new();
        let mut cursor = area;
        for (_, b) in &self.records {
            cursor = align(cursor, 16)?;
            offs.push(cursor);
            cursor += b.len() as u64;
        }
        let mut out = vec![0u8; cursor as usize];
        out[..4].copy_from_slice(b"NXMD");
        put16(&mut out, 4, 1);
        put16(&mut out, 6, MEDIA_HEADER as u16);
        put64(&mut out, 8, cursor);
        put32(&mut out, 16, n as u32);
        put16(&mut out, 20, MEDIA_RECORD as u16);
        put32(&mut out, 24, MEDIA_HEADER as u32);
        put32(&mut out, 28, area as u32);
        for (i, ((t, b), off)) in self.records.iter().zip(&offs).enumerate() {
            let o = (MEDIA_HEADER + i as u64 * MEDIA_RECORD) as usize;
            put16(&mut out, o, *t);
            put64(&mut out, o + 4, b.len() as u64);
            put64(&mut out, o + 12, b.len() as u64);
            put64(&mut out, o + 20, *off);
            out[o + 28..o + 60].copy_from_slice(&crate::crypto::sha256(b));
            out[*off as usize..*off as usize + b.len()].copy_from_slice(b);
        }
        Ok(out)
    }
}

/// Media references of one snapshot's metadata.
struct MetaRefs {
    title: Option<String>,
    publisher: Option<String>,
    icon: u32,
    nacp: u32,
    localized: Vec<(String, Option<String>, u32)>,
}

impl MetaRefs {
    fn from(m: &WMetadata, media: &mut MediaStage) -> Option<Self> {
        let mut localized: Vec<(String, Option<String>, u32)> = m
            .localized
            .iter()
            .map(|(l, t, i)| (l.clone(), t.clone().filter(|t| !t.is_empty()), i.as_deref().map_or(ABSENT, |b| media.icon(b))))
            .filter(|(_, t, i)| t.is_some() || *i != ABSENT)
            .collect();
        localized.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        localized.dedup_by(|a, b| a.0 == b.0);
        let r = MetaRefs {
            title: m.title.clone().filter(|t| !t.is_empty()),
            publisher: m.publisher.clone().filter(|t| !t.is_empty()),
            icon: m.icon.as_deref().map_or(ABSENT, |b| media.icon(b)),
            nacp: m.nacp.as_deref().map_or(ABSENT, |b| media.unique(MEDIA_NACP, b)),
            localized,
        };
        (r.title.is_some() || r.publisher.is_some() || r.icon != ABSENT || r.nacp != ABSENT || !r.localized.is_empty()).then_some(r)
    }
}

struct FinalSnapshot {
    program_index: u32,
    snapshot_type: u8,
    version: u32,
    root: u32,
    logical_size: u64,
    display_version: Option<String>,
    content_id: [u8; 16],
    dependencies: Vec<(u8, [u8; 32])>,
    identity: [u8; 32],
    build_id: [u8; 32],
    meta: Option<MetaRefs>,
    required_firmware: Option<u32>,
}

/// Write a compact NX 0.2 archive.
pub(crate) fn write(out: &mut crate::AtomicFile, apps: &mut [WApplication], opts: WriteOptions, job: &JobContext) -> Result<WriteStats> {
    if apps.is_empty() || apps.iter().any(|a| a.snapshots.is_empty()) {
        return Err(Error::invalid_arg("an NX archive needs at least one application with one snapshot"));
    }
    if !(16..=20).contains(&opts.chunk_log2) {
        return Err(Error::invalid_arg("NX chunk size must be 64 KiB to 1 MiB"));
    }
    apps.sort_by_key(|a| (a.platform, a.application_id));
    for w in apps.windows(2) {
        if (w[0].platform, w[0].application_id) == (w[1].platform, w[1].application_id) {
            return Err(Error::invalid_arg("duplicate NX application"));
        }
    }
    let back = std::fs::File::open(out.temp_path())?;
    out.seek(SeekFrom::Start(0))?;
    crate::copy::write_zeros(&mut *out, DATA_START)?;
    let total: u64 = apps.iter().flat_map(|a| a.snapshots.iter()).map(|s| tree_size(&s.root)).sum();
    let mut prog = crate::ByteProgress::new(job, crate::Phase::Writing, Some(total));
    let mut dw = DataWriter {
        out,
        back,
        cursor: DATA_START,
        blocks: Vec::new(),
        checks: Vec::new(),
        refs: Vec::new(),
        files: Vec::new(),
        candidates: HashMap::new(),
        opts,
        dedup_hits: 0,
    };
    // ---- Data phase: every file of every snapshot tree.
    let mut built: Vec<Vec<Vec<BNode>>> = Vec::new();
    for a in apps.iter() {
        let mut by_path: HashMap<String, Vec<u32>> = HashMap::new();
        let mut by_key: HashMap<(String, String), u32> = HashMap::new();
        let mut snaps = Vec::new();
        for s in &a.snapshots {
            snaps.push(build_tree(&s.root, "", &mut dw, &mut by_path, &mut by_key, job, &mut prog)?);
        }
        built.push(snaps);
    }
    let DataWriter { out, blocks, checks, refs, files, dedup_hits, cursor: data_end, .. } = dw;
    // ---- Manifest: directory IDs pre-order per snapshot root.
    let mut dirs: Vec<Vec<(String, bool, u32)>> = Vec::new();
    let mut roots: Vec<Vec<u32>> = Vec::new();
    for snaps in &built {
        let mut r = Vec::new();
        for tree in snaps {
            r.push(assign_dirs(tree, &mut dirs));
        }
        roots.push(r);
    }
    let manifest = serialize_manifest(&dirs, &files, &refs)?;
    // ---- Catalog.
    let mut media = MediaStage::default();
    let mut cat_apps = Vec::new();
    let mut cat_programs: Vec<(u64, u32, u8, u32, u32)> = Vec::new();
    let mut snapshots: Vec<FinalSnapshot> = Vec::new();
    for (ai, a) in apps.iter().enumerate() {
        // Identities first (dependencies name them).
        let mut identities = Vec::new();
        let mut sizes = Vec::new();
        for (si, s) in a.snapshots.iter().enumerate() {
            let mut nodes = Vec::new();
            collect_nodes(&built[ai][si], "", &files, &mut nodes);
            nodes.push((String::new(), None));
            sizes.push(nodes.iter().filter_map(|n| n.1.map(|f| f.0)).sum::<u64>());
            identities.push(snapshot_identity(
                a.platform,
                a.application_id,
                s.program_id,
                s.snapshot_type,
                s.version,
                &s.content_id,
                &mut nodes,
            ));
        }
        let mut program_ids: Vec<(u64, u8)> = a.programs.clone();
        program_ids.sort_by_key(|p| p.0);
        program_ids.dedup_by_key(|p| p.0);
        for s in &a.snapshots {
            if let Some(p) = s.program_id {
                if !program_ids.iter().any(|x| x.0 == p) {
                    return Err(Error::invalid_arg(format!("snapshot names program {p:016x} which the application does not declare")));
                }
            } else if s.snapshot_type != SNAPSHOT_DLC {
                return Err(Error::invalid_arg("an executable snapshot needs a program"));
            }
        }
        let program_ids: Vec<(u64, u8)> =
            program_ids.into_iter().filter(|p| a.snapshots.iter().any(|s| s.program_id == Some(p.0))).collect();
        let first_program = cat_programs.len() as u32;
        // Snapshot order: program-associated (program, type, version, content, build), then DLC.
        let mut order: Vec<usize> = (0..a.snapshots.len()).collect();
        let pidx = |s: &WSnapshot| s.program_id.and_then(|p| program_ids.iter().position(|x| x.0 == p));
        order.sort_by_key(|&i| {
            let s = &a.snapshots[i];
            let assoc = pidx(s);
            (
                assoc.is_none(),
                assoc.unwrap_or(0),
                if assoc.is_some() { s.snapshot_type } else { 0 },
                s.version,
                s.content_id,
                s.build_id.unwrap_or([0; 32]),
            )
        });
        for w in order.windows(2) {
            let (x, y) = (&a.snapshots[w[0]], &a.snapshots[w[1]]);
            if pidx(x) == pidx(y)
                && (pidx(x).is_none() || x.snapshot_type == y.snapshot_type)
                && x.version == y.version
                && x.content_id == y.content_id
                && x.build_id == y.build_id
            {
                return Err(Error::invalid_arg("two NX snapshots share a sort key"));
            }
        }
        let first_snapshot = snapshots.len() as u32;
        for &i in &order {
            let s = &a.snapshots[i];
            let dependencies = match s.requires {
                Some((t, kind)) => vec![(kind, *identities.get(t).ok_or_else(|| Error::internal("dependency target out of range"))?)],
                None => Vec::new(),
            };
            snapshots.push(FinalSnapshot {
                program_index: pidx(s).map_or(ABSENT, |p| first_program + p as u32),
                snapshot_type: s.snapshot_type,
                version: s.version,
                root: roots[ai][i],
                logical_size: sizes[i],
                display_version: s.display_version.clone().filter(|d| !d.is_empty() && d.len() <= 256),
                content_id: s.content_id,
                dependencies,
                identity: identities[i],
                build_id: s.build_id.unwrap_or([0; 32]),
                meta: None,
                required_firmware: s.required_firmware,
            });
        }
        let mut seen = std::collections::HashSet::new();
        for s in &snapshots[first_snapshot as usize..] {
            if !seen.insert(s.identity) {
                return Err(Error::invalid_arg("two NX snapshots have identical identities"));
            }
        }
        for (pi, (pid, kind)) in program_ids.iter().enumerate() {
            let idx = first_program + pi as u32;
            let range: Vec<u32> =
                (first_snapshot..snapshots.len() as u32).filter(|&k| snapshots[k as usize].program_index == idx).collect();
            cat_programs.push((*pid, ai as u32, *kind, range[0], range.len() as u32));
        }
        // Display metadata: the highest-version non-DLC snapshot with metadata (ties: last).
        for (k, &i) in order.iter().enumerate() {
            if let Some(m) = a.snapshots[i].metadata.as_ref().filter(|_| a.snapshots[i].snapshot_type != SNAPSHOT_DLC) {
                snapshots[first_snapshot as usize + k].meta = MetaRefs::from(m, &mut media);
            }
        }
        let selected = (first_snapshot..snapshots.len() as u32)
            .filter(|&k| snapshots[k as usize].snapshot_type != SNAPSHOT_DLC && snapshots[k as usize].meta.is_some())
            .max_by_key(|&k| (snapshots[k as usize].version, k));
        cat_apps.push((ai, first_program, program_ids.len() as u32, first_snapshot, a.snapshots.len() as u32, selected));
    }
    let catalog = serialize_catalog(apps, &cat_apps, &cat_programs, &snapshots)?;
    if catalog.len() as u64 > MAX_CATALOG {
        return Err(Error::limit("NX catalog exceeds 16 MiB"));
    }
    let media_bytes = media.serialize()?;
    // ---- Tail.
    let mut cursor = data_end;
    let place = |len: u64, cursor: &mut u64| -> Result<u64> {
        let at = align(*cursor, 16)?;
        *cursor = at + len;
        Ok(at)
    };
    let media_off = if media_bytes.is_empty() { 0 } else { place(media_bytes.len() as u64, &mut cursor)? };
    let catalog_off = place(catalog.len() as u64, &mut cursor)?;
    let manifest_off = place(manifest.len() as u64, &mut cursor)?;
    let mut index = Vec::with_capacity(blocks.len() * BLOCK_SIZE as usize);
    for b in &blocks {
        let mut r = [0u8; BLOCK_SIZE as usize];
        put64(&mut r, 0, b.offset);
        put32(&mut r, 8, b.stored);
        put32(&mut r, 12, b.logical);
        r[16] = b.codec;
        put32(&mut r, 20, b.first_check);
        index.extend_from_slice(&r);
    }
    let integrity: Vec<u8> = checks.iter().flat_map(|c| c.to_le_bytes()).collect();
    let (index_off, integrity_off) =
        if blocks.is_empty() { (0, 0) } else { (place(index.len() as u64, &mut cursor)?, place(integrity.len() as u64, &mut cursor)?) };
    let archive_size = cursor;
    let mut at = data_end;
    for (off, bytes) in
        [(media_off, &media_bytes), (catalog_off, &catalog), (manifest_off, &manifest), (index_off, &index), (integrity_off, &integrity)]
    {
        if bytes.is_empty() && off == 0 {
            continue;
        }
        crate::copy::write_zeros(&mut *out, off - at)?;
        out.write_all(bytes)?;
        at = off + bytes.len() as u64;
    }
    // ---- Header slots.
    let mut h = [0u8; HEADER_SIZE];
    h[..4].copy_from_slice(MAGIC);
    put16(&mut h, 4, 0);
    put16(&mut h, 6, 2);
    put32(&mut h, 8, HEADER_SIZE as u32);
    put16(&mut h, 12, 1);
    put64(&mut h, 16, archive_size);
    put64(&mut h, 24, catalog_off);
    put64(&mut h, 32, catalog.len() as u64);
    put64(&mut h, 40, media_off);
    put64(&mut h, 48, media_bytes.len() as u64);
    if !blocks.is_empty() {
        put64(&mut h, 56, DATA_START);
        put64(&mut h, 64, data_end - DATA_START);
    }
    put64(&mut h, 72, manifest_off);
    put64(&mut h, 80, manifest.len() as u64);
    put64(&mut h, 88, index_off);
    put64(&mut h, 96, blocks.len() as u64);
    put64(&mut h, 104, integrity_off);
    put64(&mut h, 112, integrity.len() as u64);
    h[120..152].copy_from_slice(&crate::crypto::sha256(&catalog));
    h[152..184].copy_from_slice(&crate::crypto::sha256(&manifest));
    let mut ix = index.clone();
    ix.extend_from_slice(&integrity);
    h[184..216].copy_from_slice(&crate::crypto::sha256(&ix));
    put64(&mut h, 216, 0);
    put32(&mut h, 224, CHECK_SIZE as u32);
    let crc = crate::crypto::crc32c(&h[..252]);
    put32(&mut h, 252, crc);
    for slot in [0, SLOT_B] {
        out.seek(SeekFrom::Start(slot))?;
        out.write_all(&h)?;
    }
    out.seek(SeekFrom::Start(archive_size))?;
    out.flush_for_verify()?.set_len(archive_size)?;
    Ok(WriteStats {
        size: archive_size,
        files: files.len(),
        blocks: blocks.len(),
        logical_bytes: files.iter().map(|f| f.size).sum(),
        stored_bytes: blocks.iter().map(|b| b.stored as u64).sum(),
        deduplicated_chunks: dedup_hits,
    })
}

fn tree_size(es: &[WEntry]) -> u64 {
    es.iter()
        .map(|e| match e {
            WEntry::Dir { entries, .. } => tree_size(entries),
            WEntry::File(f) => f.size,
        })
        .sum()
}

fn build_tree(
    es: &[WEntry],
    prefix: &str,
    dw: &mut DataWriter<'_>,
    by_path: &mut HashMap<String, Vec<u32>>,
    by_key: &mut HashMap<(String, String), u32>,
    job: &JobContext,
    prog: &mut crate::ByteProgress<'_>,
) -> Result<Vec<BNode>> {
    let mut out = Vec::new();
    let mut names = std::collections::HashSet::new();
    for e in es {
        let name = match e {
            WEntry::Dir { name, .. } | WEntry::File(WFile { name, .. }) => name,
        };
        if !valid_component(name.as_bytes()) {
            return Err(Error::unsafe_path(format!("invalid NX path component {name:?}")));
        }
        if !names.insert(name.clone()) {
            return Err(Error::conflict(format!("duplicate name {name:?} in one NX directory")));
        }
        let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        match e {
            WEntry::Dir { entries, .. } => out.push(BNode::Dir(name.clone(), build_tree(entries, &path, dw, by_path, by_key, job, prog)?)),
            WEntry::File(f) => {
                let reused = f.reuse_key.as_ref().and_then(|k| by_key.get(&(path.clone(), k.clone())).copied());
                let id = match reused {
                    Some(id) => {
                        prog.advance(f.size)?;
                        id
                    }
                    None => {
                        let same = by_path.get(&path).cloned().unwrap_or_default();
                        let id = dw.add_file(f, &same, job, prog)?;
                        let v = by_path.entry(path.clone()).or_default();
                        if !v.contains(&id) {
                            v.push(id);
                        }
                        if let Some(k) = &f.reuse_key {
                            by_key.insert((path.clone(), k.clone()), id);
                        }
                        id
                    }
                };
                out.push(BNode::File(name.clone(), id));
            }
        }
    }
    out.sort_by(|a, b| node_name(a).as_bytes().cmp(node_name(b).as_bytes()));
    Ok(out)
}

fn node_name(n: &BNode) -> &str {
    match n {
        BNode::Dir(s, _) | BNode::File(s, _) => s,
    }
}

/// Assign directory IDs pre-order; returns the root ID. `dirs[id]` holds sorted entries
/// `(name, is_dir, target)`.
fn assign_dirs(tree: &[BNode], dirs: &mut Vec<Vec<(String, bool, u32)>>) -> u32 {
    let id = dirs.len() as u32;
    dirs.push(Vec::new());
    let mut entries = Vec::new();
    for n in tree {
        match n {
            BNode::Dir(name, sub) => {
                let cid = assign_dirs(sub, dirs);
                entries.push((name.clone(), true, cid));
            }
            BNode::File(name, fid) => entries.push((name.clone(), false, *fid)),
        }
    }
    dirs[id as usize] = entries;
    id
}

fn collect_nodes(tree: &[BNode], prefix: &str, files: &[FileRec], out: &mut Vec<(String, Option<(u64, [u8; 32])>)>) {
    for n in tree {
        let path = |name: &str| if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        match n {
            BNode::Dir(name, sub) => {
                let p = path(name);
                out.push((p.clone(), None));
                collect_nodes(sub, &p, files, out);
            }
            BNode::File(name, fid) => {
                let f = &files[*fid as usize];
                out.push((path(name), Some((f.size, f.sha256))));
            }
        }
    }
}

fn serialize_manifest(dirs: &[Vec<(String, bool, u32)>], files: &[FileRec], refs: &[u32]) -> Result<Vec<u8>> {
    let mut pool = StringPool::new();
    let mut entries = Vec::new();
    for d in dirs {
        for (name, is_dir, t) in d {
            let (o, l) = pool.intern(Some(name));
            entries.push((o, l, *t, if *is_dir { 1u8 } else { 2u8 }));
        }
    }
    let mut cursor = MANIFEST_HEADER;
    let dir_off = align(cursor, 8)?;
    cursor = dir_off + dirs.len() as u64 * DIRECTORY_SIZE;
    let file_off = if files.is_empty() {
        0
    } else {
        let o = align(cursor, 8)?;
        cursor = o + files.len() as u64 * FILE_SIZE;
        o
    };
    let entry_off = if entries.is_empty() {
        0
    } else {
        let o = align(cursor, 8)?;
        cursor = o + entries.len() as u64 * ENTRY_SIZE;
        o
    };
    let ref_off = if refs.is_empty() {
        0
    } else {
        let o = align(cursor, 4)?;
        cursor = o + refs.len() as u64 * 4;
        o
    };
    let path_off = align(cursor, 8)?;
    let total = path_off + pool.bytes.len() as u64;
    let mut m = vec![0u8; total as usize];
    m[..4].copy_from_slice(b"NXMF");
    put16(&mut m, 4, 1);
    put16(&mut m, 6, MANIFEST_HEADER as u16);
    put64(&mut m, 8, total);
    put32(&mut m, 16, dirs.len() as u32);
    put32(&mut m, 20, files.len() as u32);
    put32(&mut m, 24, entries.len() as u32);
    put32(&mut m, 28, refs.len() as u32);
    put64(&mut m, 32, dir_off);
    put64(&mut m, 40, file_off);
    put64(&mut m, 48, entry_off);
    put64(&mut m, 56, ref_off);
    put64(&mut m, 64, path_off);
    put64(&mut m, 72, pool.bytes.len() as u64);
    let mut ec = 0u32;
    for (i, d) in dirs.iter().enumerate() {
        let o = (dir_off + i as u64 * DIRECTORY_SIZE) as usize;
        put32(&mut m, o, ec);
        put32(&mut m, o + 4, d.len() as u32);
        ec += d.len() as u32;
    }
    for (i, f) in files.iter().enumerate() {
        let o = (file_off + i as u64 * FILE_SIZE) as usize;
        put64(&mut m, o, f.size);
        put32(&mut m, o + 8, f.first_ref);
        put32(&mut m, o + 12, f.count);
        m[o + 16] = f.log2;
        m[o + 20..o + 52].copy_from_slice(&f.sha256);
    }
    for (i, (no, nl, t, k)) in entries.iter().enumerate() {
        let o = (entry_off + i as u64 * ENTRY_SIZE) as usize;
        put64(&mut m, o, path_off + *no as u64);
        put32(&mut m, o + 8, *nl);
        put32(&mut m, o + 12, *t);
        m[o + 16] = *k;
    }
    for (i, r) in refs.iter().enumerate() {
        put32(&mut m, (ref_off + i as u64 * 4) as usize, *r);
    }
    m[path_off as usize..].copy_from_slice(&pool.bytes);
    Ok(m)
}

type CatApp = (usize, u32, u32, u32, u32, Option<u32>);

fn serialize_catalog(
    apps: &[WApplication],
    cat_apps: &[CatApp],
    programs: &[(u64, u32, u8, u32, u32)],
    snapshots: &[FinalSnapshot],
) -> Result<Vec<u8>> {
    let mut strings = StringPool::new();
    struct EncApp {
        title: (u32, u32),
        publisher: (u32, u32),
        icon: u32,
        nacp: u32,
        first_local: u32,
        local_count: u32,
        selected: u32,
    }
    let mut enc_apps = Vec::new();
    let mut locales: Vec<((u32, u32), (u32, u32), u32)> = Vec::new();
    let mut ext: Vec<(u32, u32, u16, u32, Vec<u8>)> = Vec::new();
    for (ci, &(_, _, _, first_snapshot, snapshot_count, selected)) in cat_apps.iter().enumerate() {
        let cur = selected.and_then(|k| snapshots[k as usize].meta.as_ref());
        let first_local = locales.len() as u32;
        if let Some(m) = cur {
            for (l, t, i) in &m.localized {
                locales.push((strings.intern(Some(l)), strings.intern(t.as_deref()), *i));
            }
        }
        enc_apps.push(EncApp {
            title: strings.intern(cur.and_then(|m| m.title.as_deref())),
            publisher: strings.intern(cur.and_then(|m| m.publisher.as_deref())),
            icon: cur.map_or(ABSENT, |m| m.icon),
            nacp: cur.map_or(ABSENT, |m| m.nacp),
            first_local,
            local_count: locales.len() as u32 - first_local,
            selected: if cur.is_some() { selected.unwrap_or(ABSENT) } else { ABSENT },
        });
        // Snapshot Metadata History for the other metadata-bearing snapshots.
        if let Some(sel) = selected.filter(|_| cur.is_some()) {
            let mut rows: Vec<[u32; 12]> = Vec::new();
            let mut hl: Vec<((u32, u32), (u32, u32), u32)> = Vec::new();
            for k in first_snapshot..first_snapshot + snapshot_count {
                if k == sel {
                    continue;
                }
                let Some(m) = snapshots[k as usize].meta.as_ref() else { continue };
                let t = strings.intern(m.title.as_deref());
                let p = strings.intern(m.publisher.as_deref());
                let fl = hl.len() as u32;
                for (l, tt, i) in &m.localized {
                    hl.push((strings.intern(Some(l)), strings.intern(tt.as_deref()), *i));
                }
                rows.push([k, t.0, t.1, p.0, p.1, m.icon, m.nacp, fl, hl.len() as u32 - fl, 0, 0, 0]);
            }
            if !rows.is_empty() {
                let mut b = vec![0u8; 24 + rows.len() * 48 + hl.len() * 24];
                b[..4].copy_from_slice(b"NXSM");
                put16(&mut b, 4, 1);
                put16(&mut b, 6, 24);
                put32(&mut b, 8, rows.len() as u32);
                put32(&mut b, 12, hl.len() as u32);
                let mut o = 24;
                for r in rows {
                    for v in r {
                        put32(&mut b, o, v);
                        o += 4;
                    }
                }
                for (l, t, i) in hl {
                    put32(&mut b, o, l.0);
                    put32(&mut b, o + 4, l.1);
                    put32(&mut b, o + 8, t.0);
                    put32(&mut b, o + 12, t.1);
                    put32(&mut b, o + 16, i);
                    o += 24;
                }
                ext.push((EXT_METADATA_HISTORY, 1, 1, ci as u32, b));
            }
        }
        // Snapshot Native Metadata (required firmware).
        let rows: Vec<(u32, u32)> = (first_snapshot..first_snapshot + snapshot_count)
            .filter_map(|k| snapshots[k as usize].required_firmware.map(|f| (k, f)))
            .collect();
        if !rows.is_empty() {
            let mut b = vec![0u8; 16 + rows.len() * 16];
            b[..4].copy_from_slice(b"NXNM");
            put16(&mut b, 4, 1);
            put16(&mut b, 6, 16);
            put32(&mut b, 8, rows.len() as u32);
            for (ri, (k, f)) in rows.iter().enumerate() {
                let o = 16 + ri * 16;
                put32(&mut b, o, *k);
                put32(&mut b, o + 4, ABSENT);
                put32(&mut b, o + 8, *f);
                put32(&mut b, o + 12, 1);
            }
            ext.push((EXT_NATIVE_METADATA, 1, 1, ci as u32, b));
        }
    }
    ext.sort_by_key(|e| (e.0, e.2, e.3));
    let displays: Vec<(u32, u32)> = snapshots.iter().map(|s| strings.intern(s.display_version.as_deref())).collect();
    let dep_count: usize = snapshots.iter().map(|s| s.dependencies.len()).sum();
    let (na, np, ns, nl, nd, ne) = (cat_apps.len(), programs.len(), snapshots.len(), locales.len(), dep_count, ext.len());
    let mut cursor = CATALOG_HEADER;
    let table = |count: usize, size: u64, cursor: &mut u64| -> Result<u64> {
        if count == 0 {
            return Ok(0);
        }
        let o = align(*cursor, 8)?;
        *cursor = o + count as u64 * size;
        Ok(o)
    };
    let ao = table(na, APP_SIZE, &mut cursor)?;
    let po = table(np, PROGRAM_SIZE, &mut cursor)?;
    let so = table(ns, SNAPSHOT_SIZE, &mut cursor)?;
    let lo = table(nl, LOCALIZED_SIZE, &mut cursor)?;
    let dof = table(nd, DEPENDENCY_SIZE, &mut cursor)?;
    let eo = table(ne, EXTENSION_SIZE, &mut cursor)?;
    let pool_off = align(cursor, 8)?;
    cursor = pool_off + strings.bytes.len() as u64;
    let mut ext_offs = Vec::new();
    for e in &ext {
        cursor = align(cursor, 8)?;
        ext_offs.push(cursor);
        cursor += e.4.len() as u64;
    }
    let mut c = vec![0u8; cursor as usize];
    c[..4].copy_from_slice(b"NXCT");
    put16(&mut c, 4, 1);
    put16(&mut c, 6, CATALOG_HEADER as u16);
    put64(&mut c, 8, cursor);
    put32(&mut c, 20, na as u32);
    put32(&mut c, 24, np as u32);
    put32(&mut c, 28, ns as u32);
    put32(&mut c, 32, nl as u32);
    put32(&mut c, 36, nd as u32);
    put32(&mut c, 40, ne as u32);
    put64(&mut c, 48, ao);
    put64(&mut c, 56, po);
    put64(&mut c, 64, so);
    put64(&mut c, 72, lo);
    put64(&mut c, 80, dof);
    put64(&mut c, 88, eo);
    put64(&mut c, 96, pool_off);
    put64(&mut c, 104, strings.bytes.len() as u64);
    for (i, (&(ai, fp, pc, fs, sc, _), e)) in cat_apps.iter().zip(&enc_apps).enumerate() {
        let o = (ao + i as u64 * APP_SIZE) as usize;
        let range = &snapshots[fs as usize..(fs + sc) as usize];
        let has_base = range.iter().any(|s| s.snapshot_type == SNAPSHOT_BASE);
        let has_dlc = range.iter().any(|s| s.snapshot_type == SNAPSHOT_DLC);
        put64(&mut c, o, apps[ai].application_id);
        c[o + 8] = apps[ai].platform;
        c[o + 9] = has_base as u8 | (has_dlc as u8) << 1;
        put32(&mut c, o + 12, if pc == 0 { ABSENT } else { fp });
        put32(&mut c, o + 16, pc);
        put32(&mut c, o + 20, fs);
        put32(&mut c, o + 24, sc);
        put32(&mut c, o + 28, e.title.0);
        put32(&mut c, o + 32, e.title.1);
        put32(&mut c, o + 36, e.publisher.0);
        put32(&mut c, o + 40, e.publisher.1);
        put32(&mut c, o + 44, e.icon);
        put32(&mut c, o + 48, e.first_local);
        put32(&mut c, o + 52, e.local_count);
        put32(&mut c, o + 56, e.nacp);
        put32(&mut c, o + 60, 0);
        put32(&mut c, o + 64, 0);
        put32(&mut c, o + 68, e.selected);
    }
    for (i, &(pid, ai, kind, fs, sc)) in programs.iter().enumerate() {
        let o = (po + i as u64 * PROGRAM_SIZE) as usize;
        put64(&mut c, o, pid);
        put32(&mut c, o + 8, ai);
        c[o + 12] = kind;
        put32(&mut c, o + 32, fs);
        put32(&mut c, o + 36, sc);
        put32(&mut c, o + 40, ABSENT);
    }
    let mut dep_i = 0u32;
    for (i, (s, d)) in snapshots.iter().zip(&displays).enumerate() {
        let o = (so + i as u64 * SNAPSHOT_SIZE) as usize;
        put32(&mut c, o, s.program_index);
        c[o + 4] = s.snapshot_type;
        c[o + 5] = (s.build_id != [0; 32]) as u8;
        put32(&mut c, o + 8, s.version);
        put32(&mut c, o + 12, s.root);
        put64(&mut c, o + 16, s.logical_size);
        put32(&mut c, o + 24, d.0);
        put32(&mut c, o + 28, d.1);
        c[o + 32..o + 48].copy_from_slice(&s.content_id);
        put32(&mut c, o + 48, dep_i);
        put32(&mut c, o + 52, s.dependencies.len() as u32);
        c[o + 56..o + 88].copy_from_slice(&s.identity);
        c[o + 88..o + 120].copy_from_slice(&s.build_id);
        for (kind, target) in &s.dependencies {
            let d = (dof + dep_i as u64 * DEPENDENCY_SIZE) as usize;
            c[d] = *kind;
            c[d + 20..d + 52].copy_from_slice(target);
            dep_i += 1;
        }
    }
    for (i, (l, t, icon)) in locales.iter().enumerate() {
        let o = (lo + i as u64 * LOCALIZED_SIZE) as usize;
        put32(&mut c, o, l.0);
        put32(&mut c, o + 4, l.1);
        put32(&mut c, o + 8, t.0);
        put32(&mut c, o + 12, t.1);
        put32(&mut c, o + 16, *icon);
    }
    for (i, ((t, f, ok, oi, data), off)) in ext.iter().zip(&ext_offs).enumerate() {
        let o = (eo + i as u64 * EXTENSION_SIZE) as usize;
        put32(&mut c, o, *t);
        put32(&mut c, o + 4, *f);
        put16(&mut c, o + 8, *ok);
        put32(&mut c, o + 12, *oi);
        put64(&mut c, o + 16, *off);
        put64(&mut c, o + 24, data.len() as u64);
        c[*off as usize..*off as usize + data.len()].copy_from_slice(data);
    }
    c[pool_off as usize..pool_off as usize + strings.bytes.len()].copy_from_slice(&strings.bytes);
    Ok(c)
}
