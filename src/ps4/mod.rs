//! # `romux::ps4`
//!
//! PlayStation 4 packages: PKG header and entry table, `param.sfo`, and PFS image
//! metadata. Package-table entries that are stored unencrypted can be extracted; encrypted
//! entries and the PFS image *contents* are not decrypted (protected retail content is
//! never claimed to be extractable). Rebuilding retail-valid packages is not offered.

pub(crate) mod entries;
pub(crate) mod pkg;

/// `param.sfo` parsing (the PSF format shared with other Sony platforms).
pub mod sfo {
    pub use crate::binary::psf::{Psf, PsfValue};
    pub fn parse(b: &[u8]) -> crate::Result<Psf> {
        Psf::parse(b)
    }
}

use crate::{
    Backend, CapabilitySet, CheckLevel, Confidence, ContentCategory, ContentNode, DataSource, EntryId, EntryIter, Error, FormatDescriptor,
    FormatId, JobContext, NodeKind, NodeTable, OpenContext, Operation, PackageInfo, PackageReader, Platform, ProbeEvidence, ProbeLimits,
    Result, SharedSource, Support, VerifyLevel, VerifyReport,
};

pub const PS4_PKG: FormatId = FormatId("ps4.pkg");
pub const PS4_SFO: FormatId = FormatId("ps4.sfo");

#[derive(Default)]
pub struct Ps4Backend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    vec![
        FormatDescriptor::new(PS4_PKG, Platform::Ps4, "PS4 PKG", &["pkg"], "PS4 package container (\\x7FCNT)")
            .op(Probe, Supported, "\\x7FCNT magic with PS4 content ID layout")
            .op(Inspect, Supported, "header, content ID, DRM/content type, entries; param.sfo when stored unencrypted")
            .op(List, Supported, "package-table entries and PFS image region")
            .op(Extract, Conditional, "unencrypted package-table entries only; encrypted entries and PFS contents are not decrypted")
            .op(Verify, Supported, "structure (bounds, overlaps, entry table); digests/signatures not checked")
            .op(Repack, Unsupported, "Romux cannot produce validly signed or encrypted PS4 packages")
            .op(Convert, Unsupported, "no declared conversions")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, "patch PKGs replace files inside encrypted PFS images")
            .op(Scan, Supported, "grouped by title ID"),
        FormatDescriptor::new(PS4_SFO, Platform::Ps4, "PS4 param.sfo", &["sfo"], "PSF key/value table with PS4 keys")
            .op(Probe, Supported, "PSF magic with PS4-specific keys")
            .op(Inspect, Supported, "all keys")
            .op(List, Supported, "keys")
            .op(Verify, Supported, "table structure"),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

impl Backend for Ps4Backend {
    fn name(&self) -> &'static str {
        "ps4"
    }
    fn platform(&self) -> Platform {
        Platform::Ps4
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        if s.len()? >= 0x1000 {
            let mut h = [0u8; 0x80];
            s.read_exact_at(0, &mut h)?;
            if &h[..4] == pkg::MAGIC {
                let mut ev = ProbeEvidence::new(PS4_PKG, Confidence::Medium).matched("\\x7FCNT magic");
                if pkg::PkgHeader::parse(s).is_ok() {
                    ev.confidence = Confidence::High;
                    ev = ev.matched("header offsets within file, content ID present");
                }
                out.push(ev);
            }
        }
        if s.len()? >= 0x14 && s.len()? < (1 << 20) {
            let mut m = [0u8; 4];
            s.read_exact_at(0, &mut m)?;
            if &m == crate::binary::psf::MAGIC {
                let b = crate::read_vec(s, 0, s.len()?, 1 << 20)?;
                if let Ok(p) = sfo::parse(&b) {
                    let ps4 =
                        p.entries.contains_key("PUBTOOLINFO") || p.entries.contains_key("CONTENT_ID") && p.entries.contains_key("APP_TYPE");
                    let conf = if ps4 { Confidence::High } else { Confidence::Low };
                    out.push(ProbeEvidence::new(PS4_SFO, conf).matched(if ps4 {
                        "PSF with PS4 keys"
                    } else {
                        "PSF table (platform keys absent)"
                    }));
                }
            }
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            PS4_PKG => Ok(Box::new(PkgReader::open(source, ctx)?)),
            PS4_SFO => Ok(Box::new(crate::binary::psf::PsfReader::open(source, PS4_SFO, Platform::Ps4)?)),
            _ => Err(Error::unsupported(format!("ps4 backend cannot open {format}"))),
        }
    }
}

/// Reader for PS4 PKG files.
pub(crate) struct PkgReader {
    pkg: pkg::Pkg,
    table: NodeTable,
    sfo: Option<sfo::Psf>,
}

impl PkgReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let pkg = pkg::Pkg::open(source, &ctx.limits)?;
        let mut table = NodeTable::new();
        for e in &pkg.entries {
            let n = ContentNode::file(0, format!("sce_sys/{}", e.name), e.size as u64)
                .kind(if e.id == entries::PARAM_SFO { NodeKind::Metadata } else { NodeKind::File })
                .span(e.offset as u64, e.size as u64)
                .encrypted(e.encrypted())
                .meta("entry_id", format!("0x{:04x}", e.id))
                .meta("key_index", e.key_index() as u64);
            let data = if e.encrypted() { None } else { Some(pkg.open_entry(e)?) };
            table.push(n, data);
        }
        if let Some(p) = &pkg.pfs {
            table.push(
                ContentNode::file(0, "pfs_image.dat", pkg.header.pfs_image_size)
                    .kind(NodeKind::Partition)
                    .encrypted(p.encrypted)
                    .readable(false)
                    .meta("note", "PFS image contents are not decrypted or traversed by Romux"),
                None,
            );
        }
        let sfo = pkg.read_sfo().ok().flatten();
        Ok(PkgReader { pkg, table, sfo })
    }
}

impl PackageReader for PkgReader {
    fn format(&self) -> FormatId {
        PS4_PKG
    }
    fn info(&self) -> Result<PackageInfo> {
        let h = &self.pkg.header;
        let mut i = PackageInfo::new(PS4_PKG, Platform::Ps4, self.pkg.source.len()?);
        i.product_code = Some(h.content_id.clone());
        i.title_id = h.title_id();
        i.family_id = h.title_id();
        i.field("content_id", h.content_id.clone());
        i.field("drm_type", pkg::drm_name(h.drm_type));
        i.field("content_type", pkg::content_type_name(h.content_type));
        i.field("content_flags", format!("0x{:08x}", h.content_flags));
        i.field("pkg_type", format!("0x{:08x}", h.pkg_type));
        i.field("entries", h.entry_count as u64);
        i.field("pfs_image_offset", h.pfs_image_offset);
        i.field("pfs_image_size", h.pfs_image_size);
        i.field("variant", self.pkg.variant());
        i.encrypted = Some(self.pkg.entries.iter().any(|e| e.encrypted()) || self.pkg.pfs.as_ref().is_some_and(|p| p.encrypted));
        i.category = match h.content_type {
            0x1A => ContentCategory::Application,
            0x1B => ContentCategory::AddOn,
            _ => ContentCategory::Unknown,
        };
        if let Some(s) = &self.sfo {
            i.title = s.get_str("TITLE").map(String::from);
            i.version = s.get_str("APP_VER").or_else(|| s.get_str("VERSION")).map(String::from);
            if let Some(c) = s.get_str("CATEGORY") {
                i.field("category", c);
                i.category = match c {
                    "gd" | "gde" => ContentCategory::Application,
                    "gp" => ContentCategory::Patch,
                    "ac" => ContentCategory::AddOn,
                    _ => i.category,
                };
            }
            for (k, v) in &s.entries {
                i.fields.insert(format!("sfo.{k}"), crate::MetaValue::Text(v.render()));
            }
        } else {
            i.limitations.push("param.sfo is encrypted or absent; title metadata limited to the header".into());
        }
        i.limitations.push("PFS image contents are not decrypted or traversed".into());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(PS4_PKG, level);
        r.pass(CheckLevel::Structure, "header", Some(format!("content id {}", self.pkg.header.content_id)));
        r.check(CheckLevel::Structure, "entry table", true, format!("{} entries within file, no overlaps", self.pkg.entries.len()));
        for w in &self.pkg.warnings {
            r.warn(CheckLevel::Structure, "layout", w.clone());
        }
        match &self.pkg.pfs {
            Some(p) => {
                r.pass(CheckLevel::Structure, "PFS superblock", Some(format!("block size {}, encrypted {}", p.block_size, p.encrypted)))
            }
            None => r.skip(CheckLevel::Structure, "PFS superblock", "no PFS image or superblock unrecognised"),
        }
        if level.wants_content() {
            r.not_checked(
                CheckLevel::Content,
                "entry digests",
                "digest semantics for encrypted entries are not implemented; digests not checked",
            );
        }
        r.authenticity_unavailable("PKG RSA signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = caps(PS4_PKG);
        if self.pkg.entries.iter().all(|e| e.encrypted()) {
            c.block(Operation::Extract, "every package-table entry is encrypted");
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, Registry};
    use std::sync::Arc;

    #[test]
    fn synthetic_pkg() {
        let mut psf = sfo::Psf::default();
        psf.entries.insert("TITLE".into(), sfo::PsfValue::Text("Homebrew".into()));
        psf.entries.insert("CATEGORY".into(), sfo::PsfValue::Text("gd".into()));
        psf.entries.insert("CONTENT_ID".into(), sfo::PsfValue::Text("UP0000-CUSA00000_00-HOMEBREW00000000".into()));
        let img = pkg::testkit::build(
            "UP0000-CUSA00000_00-HOMEBREW00000000",
            &[(entries::PARAM_SFO, psf.to_bytes(), false), (0x1200, vec![7u8; 100], false), (0x0010, vec![1u8; 64], true)],
        );
        let reg = Registry::new().with(Ps4Backend);
        let src: SharedSource = Arc::new(MemorySource::new(img));
        assert_eq!(reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap().format, Some(PS4_PKG));
        let r = reg.open(src, &OpenContext::default()).unwrap();
        let i = r.info().unwrap();
        assert_eq!(i.title.as_deref(), Some("Homebrew"));
        assert_eq!(i.title_id.as_deref(), Some("CUSA00000"));
        let nodes: Vec<_> = r.entries().unwrap().map(|n| n.unwrap()).collect();
        assert!(nodes.iter().any(|n| n.path == "sce_sys/icon0.png" && n.readable));
        assert!(nodes.iter().any(|n| n.path == "sce_sys/entry_keys" && !n.readable));
        assert!(r.verify(VerifyLevel::All, &JobContext::default()).unwrap().no_failures());
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::ps4::pkg::testkit::*;
}
