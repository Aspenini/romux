//! PSF key/value tables (`PARAM.SFO`) shared by several Sony platforms.
//!
//! The on-disk format is identical across PSP, PS Vita and PS4, so one reader/writer is
//! shared; each console module interprets the keys.

use crate::binary::{ByteWriter, u16le, u32le};
use crate::{Error, Result};
use std::collections::BTreeMap;

pub const MAGIC: &[u8; 4] = b"\0PSF";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum PsfValue {
    Text(String),
    Int(u32),
    Bytes(Vec<u8>),
}

impl PsfValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PsfValue::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<u32> {
        match self {
            PsfValue::Int(v) => Some(*v),
            _ => None,
        }
    }
    pub fn render(&self) -> String {
        match self {
            PsfValue::Text(s) => s.clone(),
            PsfValue::Int(v) => format!("0x{v:08x}"),
            PsfValue::Bytes(b) => crate::hex(b),
        }
    }
}

/// A parsed PSF table, keeping declared max lengths for faithful rewriting.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Psf {
    pub version: u32,
    pub entries: BTreeMap<String, PsfValue>,
    #[serde(skip)]
    pub max_lengths: BTreeMap<String, u32>,
}

impl Psf {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 0x14 || &b[..4] != MAGIC {
            return Err(Error::malformed("missing PSF magic"));
        }
        let version = u32le(b, 4)?;
        let key_table = u32le(b, 8)? as usize;
        let data_table = u32le(b, 12)? as usize;
        let count = u32le(b, 16)? as usize;
        if count > 4096 || key_table > b.len() || data_table > b.len() {
            return Err(Error::malformed("PSF table offsets out of range"));
        }
        let mut psf = Psf { version, ..Default::default() };
        for i in 0..count {
            let e = 0x14 + i * 16;
            let key_off = u16le(b, e)? as usize;
            let fmt = u16le(b, e + 2)?;
            let len = u32le(b, e + 4)? as usize;
            let max = u32le(b, e + 8)?;
            let data_off = u32le(b, e + 12)? as usize;
            let kb = b.get(key_table + key_off..).ok_or_else(|| Error::malformed("PSF key offset out of range"))?;
            let kend = kb.iter().position(|c| *c == 0).ok_or_else(|| Error::malformed("unterminated PSF key"))?;
            let key = String::from_utf8_lossy(&kb[..kend]).into_owned();
            let d = crate::binary::slice(b, data_table + data_off, len)?;
            let v = match fmt {
                0x0404 => PsfValue::Int(u32le(d, 0).unwrap_or(0)),
                0x0204 | 0x0004 => PsfValue::Text(crate::binary::utf8_z(d)),
                _ => PsfValue::Bytes(d.to_vec()),
            };
            psf.max_lengths.insert(key.clone(), max);
            psf.entries.insert(key, v);
        }
        Ok(psf)
    }

    pub fn get_str(&self, k: &str) -> Option<&str> {
        self.entries.get(k).and_then(|v| v.as_str())
    }
    pub fn get_int(&self, k: &str) -> Option<u32> {
        self.entries.get(k).and_then(|v| v.as_int())
    }

    /// Serialise (keys sorted, data 4-byte aligned) — used for rebuilt homebrew packages.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut keys = ByteWriter::new();
        let mut data = ByteWriter::new();
        let mut index = ByteWriter::new();
        for (k, v) in &self.entries {
            let key_off = keys.len() as u16;
            keys.bytes(k.as_bytes()).u8(0);
            let (fmt, bytes): (u16, Vec<u8>) = match v {
                PsfValue::Int(i) => (0x0404, i.to_le_bytes().to_vec()),
                PsfValue::Text(s) => {
                    let mut b = s.as_bytes().to_vec();
                    b.push(0);
                    (0x0204, b)
                }
                PsfValue::Bytes(b) => (0x0004, b.clone()),
            };
            let max = self.max_lengths.get(k).copied().unwrap_or(0).max((bytes.len().div_ceil(4) * 4) as u32);
            let data_off = data.len() as u32;
            data.bytes(&bytes);
            data.pad_to(data_off as usize + max as usize);
            index.u16le(key_off).u16le(fmt).u32le(bytes.len() as u32).u32le(max).u32le(data_off);
        }
        keys.align(4);
        let key_table = 0x14 + index.len();
        let data_table = key_table + keys.len();
        let mut w = ByteWriter::new();
        w.bytes(MAGIC)
            .u32le(if self.version == 0 { 0x0101 } else { self.version })
            .u32le(key_table as u32)
            .u32le(data_table as u32)
            .u32le(self.entries.len() as u32);
        w.bytes(&index.buf).bytes(&keys.buf).bytes(&data.buf);
        w.into_inner()
    }
}

/// Generic PSF reader shared by Sony backends.
pub struct PsfReader {
    format: crate::FormatId,
    platform: crate::Platform,
    len: u64,
    pub psf: Psf,
    table: crate::NodeTable,
}

impl PsfReader {
    pub fn open(source: crate::SharedSource, format: crate::FormatId, platform: crate::Platform) -> Result<Self> {
        let len = source.len()?;
        let b = crate::read_vec(source.as_ref(), 0, len, 1 << 20)?;
        let psf = Psf::parse(&b)?;
        let mut table = crate::NodeTable::new();
        for (k, v) in &psf.entries {
            table.push(
                crate::ContentNode::file(0, k.clone(), 0).kind(crate::NodeKind::Metadata).meta("value", v.render()).readable(false),
                None,
            );
        }
        Ok(PsfReader { format, platform, len, psf, table })
    }
}

impl crate::PackageReader for PsfReader {
    fn format(&self) -> crate::FormatId {
        self.format
    }
    fn info(&self) -> Result<crate::PackageInfo> {
        let mut i = crate::PackageInfo::new(self.format, self.platform, self.len);
        i.title = self.psf.get_str("TITLE").map(String::from);
        i.title_id = self.psf.get_str("TITLE_ID").or_else(|| self.psf.get_str("DISC_ID")).map(String::from);
        i.version = self.psf.get_str("APP_VER").or_else(|| self.psf.get_str("VERSION")).map(String::from);
        for (k, v) in &self.psf.entries {
            i.fields.insert(k.clone(), crate::MetaValue::Text(v.render()));
        }
        Ok(i)
    }
    fn entries(&self) -> Result<crate::EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: crate::EntryId) -> Result<crate::SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: crate::VerifyLevel, _job: &crate::JobContext) -> Result<crate::VerifyReport> {
        let mut r = crate::VerifyReport::new(self.format, level);
        r.pass(crate::CheckLevel::Structure, "key/data tables", Some(format!("{} keys", self.psf.entries.len())));
        r.skip(crate::CheckLevel::Authenticity, "signature", "PSF tables carry no signature");
        Ok(r)
    }
    fn capabilities(&self) -> Result<crate::CapabilitySet> {
        let mut d = crate::FormatDescriptor::new(self.format, self.platform, "PSF", &["sfo"], "PSF table");
        for op in [crate::Operation::Probe, crate::Operation::Inspect, crate::Operation::List, crate::Operation::Verify] {
            d = d.op(op, crate::Support::Supported, "");
        }
        Ok(crate::CapabilitySet::from_descriptor(&d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let mut p = Psf::default();
        p.entries.insert("TITLE".into(), PsfValue::Text("Hello".into()));
        p.entries.insert("APP_VER".into(), PsfValue::Text("01.00".into()));
        p.entries.insert("ATTRIBUTE".into(), PsfValue::Int(5));
        let b = p.to_bytes();
        let q = Psf::parse(&b).unwrap();
        assert_eq!(q.get_str("TITLE"), Some("Hello"));
        assert_eq!(q.get_int("ATTRIBUTE"), Some(5));
        assert!(Psf::parse(&b[..10]).is_err());
    }
}
