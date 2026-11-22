//! `\x7FPKG` packages (PS3/PSP/Vita family): header and metadata-entry inspection only.

use crate::binary::{u16be, u32be, u64be};
use crate::{
    CapabilitySet, CheckLevel, ContentNode, DataSource, EntryId, EntryIter, Error, FormatId, JobContext, NodeKind, NodeTable, PackageInfo,
    PackageReader, Platform, Result, SharedSource, VerifyLevel, VerifyReport, read_vec,
};

pub const MAGIC: &[u8; 4] = b"\x7FPKG";

#[derive(Debug, Clone, serde::Serialize)]
pub struct Header {
    pub revision: u16,
    pub pkg_platform: u16,
    pub metadata_offset: u32,
    pub metadata_count: u32,
    pub metadata_size: u32,
    pub item_count: u32,
    pub total_size: u64,
    pub data_offset: u64,
    pub data_size: u64,
    pub content_id: String,
}

impl Header {
    pub fn parse(s: &dyn DataSource) -> Result<Self> {
        let h = read_vec(s, 0, 0xC0, 0xC0)?;
        if &h[..4] != MAGIC {
            return Err(Error::malformed("missing \\x7FPKG magic"));
        }
        let hdr = Header {
            revision: u16be(&h, 4)?,
            pkg_platform: u16be(&h, 6)?,
            metadata_offset: u32be(&h, 8)?,
            metadata_count: u32be(&h, 12)?,
            metadata_size: u32be(&h, 16)?,
            item_count: u32be(&h, 20)?,
            total_size: u64be(&h, 24)?,
            data_offset: u64be(&h, 32)?,
            data_size: u64be(&h, 40)?,
            content_id: crate::binary::ascii_z(&h[0x30..0x60]),
        };
        let len = s.len()?;
        if hdr.data_offset.saturating_add(hdr.data_size) > len.max(hdr.total_size) || hdr.metadata_offset as u64 > len {
            return Err(Error::bounds("PKG header offsets exceed the file"));
        }
        Ok(hdr)
    }
    pub fn platform_name(&self) -> &'static str {
        match self.pkg_platform {
            1 => "PS3",
            2 => "PSP / PS Vita",
            _ => "unknown",
        }
    }
}

pub fn content_type_name(v: u32) -> String {
    match v {
        0x06 => "PSP (PS1 classic)".into(),
        0x07 | 0x0E | 0x0F | 0x10 => "PSP".into(),
        0x15 => "PS Vita application".into(),
        0x16 => "PS Vita DLC".into(),
        0x18 | 0x1D => "PS Vita theme / LiveArea".into(),
        0x1F => "PS Vita theme".into(),
        v => format!("0x{v:02x}"),
    }
}

pub struct PkgReader {
    src: SharedSource,
    pub header: Header,
    pub metadata: Vec<(u32, Vec<u8>)>,
    table: NodeTable,
}

impl PkgReader {
    pub fn open(src: SharedSource) -> Result<Self> {
        let header = Header::parse(src.as_ref())?;
        let mut metadata = Vec::new();
        let mut off = header.metadata_offset as u64;
        let len = src.len()?;
        for _ in 0..header.metadata_count.min(64) {
            if off + 8 > len {
                break;
            }
            let h = read_vec(src.as_ref(), off, 8, 8)?;
            let id = u32be(&h, 0)?;
            let size = u32be(&h, 4)? as u64;
            if size > 0x10000 {
                return Err(Error::malformed("PKG metadata entry too large"));
            }
            metadata.push((id, read_vec(src.as_ref(), off + 8, size, 0x10000)?));
            off += 8 + size;
        }
        let mut table = NodeTable::new();
        for (id, d) in &metadata {
            table.push(ContentNode::file(0, format!("metadata/0x{id:02x}"), d.len() as u64).kind(NodeKind::Metadata).readable(false), None);
        }
        table.push(
            ContentNode::file(0, "items", header.data_size)
                .kind(NodeKind::Partition)
                .encrypted(true)
                .readable(false)
                .meta("item_count", header.item_count as u64),
            None,
        );
        Ok(PkgReader { src, header, metadata, table })
    }
}

impl PackageReader for PkgReader {
    fn format(&self) -> FormatId {
        crate::vita::VITA_PKG
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(crate::vita::VITA_PKG, Platform::Vita, self.src.len()?);
        i.product_code = Some(self.header.content_id.clone());
        i.title_id = self.header.content_id.get(7..16).map(String::from);
        i.family_id = i.title_id.clone();
        i.encrypted = Some(true);
        i.field("platform", self.header.platform_name());
        i.field("revision", if self.header.revision & 0x8000 != 0 { "retail" } else { "debug" });
        i.field("items", self.header.item_count as u64);
        for (id, d) in &self.metadata {
            if *id == 2 && d.len() >= 4 {
                i.field("content_type", content_type_name(u32::from_be_bytes([d[0], d[1], d[2], d[3]])));
            }
        }
        if self.header.pkg_platform == 1 {
            i.platform = Platform::Generic;
            i.warnings.push("PS3 package: recognised for identification only; PS3 is not a supported platform".into());
        }
        i.limitations.push("package items are encrypted; contents are not decrypted".into());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(crate::vita::VITA_PKG, level);
        r.pass(CheckLevel::Structure, "header", Some(format!("{} metadata entries", self.metadata.len())));
        if level.wants_content() {
            r.not_checked(CheckLevel::Content, "item digests", "items are encrypted; digests not checked");
        }
        r.authenticity_unavailable("PKG signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(crate::vita::caps(crate::vita::VITA_PKG))
    }
}
