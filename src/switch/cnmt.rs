//! Content metadata (CNMT) binary records and `.cnmt.xml` sidecars.

use crate::binary::{u16le, u32le, u64le, uint_le};
use crate::{Error, Result, TitleRole, hex};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaType {
    SystemProgram,
    SystemData,
    SystemUpdate,
    BootImagePackage,
    BootImagePackageSafe,
    Application,
    Patch,
    AddOnContent,
    Delta,
    DataPatch,
    Unknown,
}

impl MetaType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => MetaType::SystemProgram,
            0x02 => MetaType::SystemData,
            0x03 => MetaType::SystemUpdate,
            0x04 => MetaType::BootImagePackage,
            0x05 => MetaType::BootImagePackageSafe,
            0x80 => MetaType::Application,
            0x81 => MetaType::Patch,
            0x82 => MetaType::AddOnContent,
            0x83 => MetaType::Delta,
            0x84 => MetaType::DataPatch,
            _ => MetaType::Unknown,
        }
    }
    pub fn from_name(s: &str) -> Self {
        match s {
            "SystemProgram" => MetaType::SystemProgram,
            "SystemData" => MetaType::SystemData,
            "SystemUpdate" => MetaType::SystemUpdate,
            "Application" => MetaType::Application,
            "Patch" => MetaType::Patch,
            "AddOnContent" => MetaType::AddOnContent,
            "Delta" => MetaType::Delta,
            "DataPatch" => MetaType::DataPatch,
            _ => MetaType::Unknown,
        }
    }
    pub fn role(&self) -> TitleRole {
        match self {
            MetaType::Application => TitleRole::Base,
            MetaType::Patch | MetaType::DataPatch => TitleRole::Update,
            MetaType::AddOnContent => TitleRole::AddOn,
            MetaType::Delta => TitleRole::Delta,
            MetaType::Unknown => TitleRole::Unknown,
            _ => TitleRole::System,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentRecord {
    pub id: String,
    pub hash: String,
    pub size: u64,
    pub content_type: u8,
    pub id_offset: u8,
}

impl ContentRecord {}

#[derive(Debug, Clone, Serialize)]
pub struct Cnmt {
    pub title_id: u64,
    pub version: u32,
    pub meta_type: MetaType,
    /// For Application: patch ID; for Patch/AddOn/Delta: the application ID.
    pub related_id: Option<u64>,
    pub required_system_version: Option<u32>,
    pub required_application_version: Option<u32>,
    pub contents: Vec<ContentRecord>,
    /// Source: "cnmt" (binary) or "cnmt.xml".
    pub evidence: &'static str,
}

impl Cnmt {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 0x20 {
            return Err(Error::malformed("CNMT shorter than its header"));
        }
        let title_id = u64le(b, 0)?;
        let version = u32le(b, 8)?;
        let mt = b[12];
        let ext_size = u16le(b, 14)? as usize;
        let content_count = u16le(b, 16)? as usize;
        let meta_type = MetaType::from_u8(mt);
        let ext = crate::binary::slice(b, 0x20, ext_size)?;
        let (related_id, rsv, rav) = match meta_type {
            MetaType::Application if ext.len() >= 0x10 => (Some(u64le(ext, 0)?), Some(u32le(ext, 8)?), Some(u32le(ext, 12)?)),
            MetaType::Patch if ext.len() >= 0x10 => (Some(u64le(ext, 0)?), Some(u32le(ext, 8)?), None),
            MetaType::AddOnContent if ext.len() >= 0xC => (Some(u64le(ext, 0)?), None, Some(u32le(ext, 8)?)),
            MetaType::Delta if ext.len() >= 0x8 => (Some(u64le(ext, 0)?), None, None),
            _ => (None, None, None),
        };
        let mut contents = Vec::with_capacity(content_count);
        let base = 0x20 + ext_size;
        for i in 0..content_count {
            let o = base + i * 0x38;
            let r = crate::binary::slice(b, o, 0x38)?;
            contents.push(ContentRecord {
                hash: hex(&r[..32]),
                id: hex(&r[32..48]),
                size: uint_le(r, 48, 6)?,
                content_type: r[54],
                id_offset: r[55],
            });
        }
        Ok(Cnmt {
            title_id,
            version,
            meta_type,
            related_id,
            required_system_version: rsv,
            required_application_version: rav,
            contents,
            evidence: "cnmt",
        })
    }

    /// Parse a `.cnmt.xml` sidecar (as produced by authoring tools).
    pub fn parse_xml(text: &str) -> Result<Self> {
        let top = text.split("<Content>").next().unwrap_or(text);
        let ty = tag(top, "Type").ok_or_else(|| Error::malformed("cnmt.xml has no <Type>"))?;
        let id = tag(top, "Id").ok_or_else(|| Error::malformed("cnmt.xml has no <Id>"))?;
        let title_id = parse_hex_u64(&id)?;
        let version = tag(top, "Version").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let related_id = tag(top, "ApplicationId")
            .or_else(|| tag(top, "OriginalId"))
            .or_else(|| tag(top, "PatchId"))
            .and_then(|v| parse_hex_u64(&v).ok());
        let mut contents = Vec::new();
        for block in text.split("<Content>").skip(1) {
            let block = block.split("</Content>").next().unwrap_or("");
            let ct = tag(block, "Type").unwrap_or_default();
            let content_type = match ct.as_str() {
                "Meta" => 0,
                "Program" => 1,
                "Data" => 2,
                "Control" => 3,
                "HtmlDocument" => 4,
                "LegalInformation" => 5,
                "DeltaFragment" => 6,
                _ => 0xFF,
            };
            contents.push(ContentRecord {
                id: tag(block, "Id").unwrap_or_default().to_lowercase(),
                hash: tag(block, "Hash").unwrap_or_default().to_lowercase(),
                size: tag(block, "Size").and_then(|s| s.trim().parse().ok()).unwrap_or(0),
                content_type,
                id_offset: tag(block, "IdOffset").and_then(|s| s.trim().parse().ok()).unwrap_or(0),
            });
        }
        Ok(Cnmt {
            title_id,
            version,
            meta_type: MetaType::from_name(ty.trim()),
            related_id,
            required_system_version: tag(top, "RequiredSystemVersion").and_then(|v| v.trim().parse().ok()),
            required_application_version: tag(top, "RequiredApplicationVersion").and_then(|v| v.trim().parse().ok()),
            contents,
            evidence: "cnmt.xml",
        })
    }

    pub fn title_id_hex(&self) -> String {
        format!("{:016x}", self.title_id)
    }
}

fn tag(text: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let s = text.find(&open)? + open.len();
    let e = text[s..].find(&close)? + s;
    Some(text[s..e].trim().to_string())
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|_| Error::malformed(format!("bad hex id {s:?}")))
}

/// Base application ID of a title (application, patch or add-on).
pub fn base_application_id(title_id: u64, role: TitleRole) -> u64 {
    match role {
        TitleRole::Update => title_id & !0xFFF,
        TitleRole::AddOn => (title_id & !0xFFF).wrapping_sub(0x1000),
        _ => title_id & !0xFFF,
    }
}

/// Heuristic role from the title-ID pattern (used only when no CNMT is available).
pub fn role_from_id(title_id: u64) -> TitleRole {
    match title_id & 0xFFF {
        0 => TitleRole::Base,
        0x800 => TitleRole::Update,
        _ => TitleRole::AddOn,
    }
}

/// Human-readable version (`v65536` → `v65536 (1.0.0-ish revision 1)`).
pub fn version_string(v: u32) -> String {
    format!("v{v} (release {}, revision {})", v >> 16, v & 0xFFFF)
}

/// Synthetic-fixture builder (feature `testkit`; not part of the stable API).
#[cfg(any(test, feature = "testkit"))]
pub fn build_binary(title_id: u64, version: u32, mt: u8, related: u64, contents: &[(String, String, u64, u8)]) -> Vec<u8> {
    let mut w = crate::binary::ByteWriter::new();
    w.u64le(title_id).u32le(version).u8(mt).u8(0).u16le(0x10).u16le(contents.len() as u16).u16le(0).u8(0);
    w.zeros(3).u32le(0).zeros(4);
    w.u64le(related).u32le(0).u32le(0);
    for (id, hash, size, ct) in contents {
        let h = crate::parse_hex(hash).unwrap_or_else(|| vec![0; 32]);
        let i = crate::parse_hex(id).unwrap_or_else(|| vec![0; 16]);
        w.fixed(&h, 32).fixed(&i, 16);
        w.bytes(&size.to_le_bytes()[..6]).u8(*ct).u8(0);
    }
    w.zeros(32);
    w.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_and_xml() {
        let b = build_binary(0x0100_1234_5678_0800, 65536, 0x81, 0x0100_1234_5678_0000, &[("00".repeat(16), "11".repeat(32), 0x1234, 1)]);
        let c = Cnmt::parse(&b).unwrap();
        assert_eq!(c.meta_type, MetaType::Patch);
        assert_eq!(c.related_id, Some(0x0100_1234_5678_0000));
        assert_eq!(c.contents[0].size, 0x1234);
        let x = "<ContentMeta><Type>AddOnContent</Type><Id>0x0100123456781001</Id><Version>0</Version><Content><Type>Data</Type><Id>abcd</Id><Size>10</Size><Hash>ff</Hash></Content></ContentMeta>";
        let c = Cnmt::parse_xml(x).unwrap();
        assert_eq!(c.meta_type, MetaType::AddOnContent);
        assert_eq!(c.contents[0].size, 10);
        assert_eq!(base_application_id(0x0100_1234_5678_1001, TitleRole::AddOn), 0x0100_1234_5678_0000);
        assert_eq!(base_application_id(0x0100_1234_5678_0800, TitleRole::Update), 0x0100_1234_5678_0000);
    }
}
