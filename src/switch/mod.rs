//! # `romux::switch`
//!
//! Nintendo Switch package formats (NSP, NSZ, XCI, XCZ, NCA, NCZ, PFS0, HFS0, RomFS) and
//! operations. Most work goes through the generic API ([`crate::open`], [`crate::inspect`],
//! [`crate::plan_convert`]) with the [`SwitchBackend`]. Switch-specific operations have
//! typed builders with `plan()` / `execute()`:
//!
//! | builder | operation |
//! |---|---|
//! | [`BundleBuilder`] | base + update + DLC in one NSP or XCI-style package |
//! | [`ApplyUpdateBuilder`] | apply a BKTR update to a derived content tree |
//! | [`CompressBuilder`], [`DecompressBuilder`] | NSP/XCI ⇄ NSZ/XCZ (byte-identical) |
//! | [`ConvertBuilder`], [`SplitBuilder`] | NSP ⇄ XCI; split a bundle into content sets |
//! | [`RomfsBuilder`] | build a RomFS image |
//!
//! Low-level readers: [`pfs0`], [`hfs0`] and [`exefs`].
//!
//! Capability honesty: NCA internals are encrypted; operations that need keys say so with
//! `NeedsKeyMaterial`. A rebuilt XCI is a gamecard-*style* container, never an authentic
//! cartridge image, and rebuilt packages never carry new valid signatures.

pub(crate) mod apply_update;
pub(crate) mod bktr;
pub(crate) mod bundle;
pub(crate) mod cnmt;
pub(crate) mod convert;
pub(crate) mod keys;
pub(crate) mod nacp;
pub(crate) mod nca;
pub(crate) mod ncz;
pub(crate) mod package;
pub(crate) mod partition;
pub(crate) mod reader;
pub(crate) mod romfs;
pub(crate) mod ticket;
pub(crate) mod title;
pub(crate) mod xci;

/// PFS0 reader/writer.
pub mod pfs0 {
    /// Writer entry point (PFS0 packages).
    pub use crate::switch::package::write_nsp as write;
    pub use crate::switch::partition::{Entry, Kind, NewEntry, PartitionFs as Reader, layout};
}

/// HFS0 reader/writer.
pub mod hfs0 {
    pub use crate::switch::package::write_partition as write;
    pub use crate::switch::partition::{Entry, Kind, NewEntry, PartitionFs as Reader, layout};
}

/// ExeFS is a PFS0 inside a program NCA.
pub mod exefs {
    pub use crate::switch::partition::PartitionFs as Reader;
}

/// Format identifiers.
pub mod formats {
    use crate::FormatId;
    pub const SWITCH_NSP: FormatId = FormatId("switch.nsp");
    pub const SWITCH_NSZ: FormatId = FormatId("switch.nsz");
    pub const SWITCH_XCI: FormatId = FormatId("switch.xci");
    pub const SWITCH_XCZ: FormatId = FormatId("switch.xcz");
    pub const SWITCH_NCA: FormatId = FormatId("switch.nca");
    pub const SWITCH_NCZ: FormatId = FormatId("switch.ncz");
    pub const SWITCH_PFS0: FormatId = FormatId("switch.pfs0");
    pub const SWITCH_HFS0: FormatId = FormatId("switch.hfs0");
    pub const SWITCH_ROMFS: FormatId = FormatId("switch.romfs");
}

pub use apply_update::{ApplyUpdateBuilder, ApplyUpdatePlan, PatchStrategy};
pub use bundle::{BundleBuilder, PackageFormat, PackagePlan};
pub use convert::{CompressBuilder, ConvertBuilder, DecompressBuilder, SplitBuilder, SplitPlan};
pub use formats::*;
pub use romfs::{RomfsBuilder, RomfsLayout};

use crate::{
    Backend, CapabilitySet, Confidence, ConversionEdge, ConversionKind, ConvertRequest, DataSource, Error, FormatDescriptor, FormatId,
    OpenContext, Operation, OutputGuarantee, PackageReader, PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Requirement, Result,
    SharedSource, Support,
};

/// The Switch backend.
#[derive(Default)]
pub struct SwitchBackend;

fn key(name: &str) -> Requirement {
    Requirement::KeyMaterial(name.to_string())
}

/// Static format descriptors (the capability matrix is generated from these).
pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    let z = cfg!(feature = "zstd");
    let zs = if z { Conditional } else { Unsupported };
    let pkg = |id, name, ext: &'static [&'static str], desc, compressed: bool, gamecard: bool| {
        let mut d = FormatDescriptor::new(id, Platform::Switch, name, ext, desc)
            .op(Probe, Supported, if gamecard { "HEAD magic and root HFS0" } else { "PFS0 magic; NCZ members distinguish NSZ" })
            .op(Inspect, Supported, "container always; titles/versions from CNMT (keys), .cnmt.xml, or ticket IDs")
            .op(List, Supported, "members (and partitions for gamecard images)")
            .op(Extract, Supported, "members as stored (NCAs stay encrypted)")
            .op_req(
                Verify,
                Supported,
                "structure, HFS0 hashes, content-ID SHA-256, CNMT hashes when readable; signatures not checked",
                vec![],
            )
            .op_req(
                Bundle,
                Conditional,
                "base + update + DLC kept as separate content sets; role validation needs CNMT/.cnmt.xml",
                vec![key("header_key")],
            )
            .op_req(
                Split,
                Conditional,
                "one package per content set; needs CNMT metadata",
                vec![key("header_key"), key("key_area_key_application_XX")],
            )
            .op_req(
                ApplyUpdate,
                Conditional,
                "BKTR reconstruction to a decrypted tree",
                vec![key("header_key"), key("key_area_key_application_XX"), key("titlekek_XX")],
            )
            .op(Repack, Unsupported, "use bundle/convert; manifest-driven repacking of retail content is not offered")
            .op(Scan, Supported, "grouped by application ID");
        d = if gamecard {
            d.op_req(Convert, Conditional, "to NSP/NSZ: container change; NCAs keep gamecard distribution type", vec![])
        } else {
            d.op_req(
                Convert,
                Conditional,
                "to XCI/XCZ: rights-ID titles need --convert-rights (headers modified, keys required)",
                vec![key("header_key"), key("titlekek_XX")],
            )
        };
        if compressed {
            d = d.op_req(
                Decompress,
                zs,
                "restores every NCA byte-identically (content IDs re-verified); no keys needed",
                vec![Requirement::Codec("zstd".into())],
            );
            d = d.op(Compress, Unsupported, "already compressed");
        } else {
            d = d.op_req(
                Compress,
                zs,
                "NCAs decrypted and zstd-compressed into NCZ (solid or block)",
                vec![key("header_key"), key("key_area_key_application_XX"), Requirement::Codec("zstd".into())],
            );
            d = d.op(Decompress, Unsupported, "not compressed");
        }
        d
    };
    vec![
        pkg(SWITCH_NSP, "NSP", &["nsp"], "PFS0 package of NCAs, tickets and certificates", false, false),
        pkg(SWITCH_NSZ, "NSZ", &["nsz"], "NSP whose NCAs are stored as NCZ", true, false),
        pkg(SWITCH_XCI, "XCI", &["xci"], "gamecard-style image with HFS0 partitions", false, true),
        pkg(SWITCH_XCZ, "XCZ", &["xcz"], "XCI whose NCAs are stored as NCZ", true, true),
        FormatDescriptor::new(SWITCH_NCA, Platform::Switch, "NCA", &["nca"], "encrypted content archive")
            .op(
                Probe,
                Conditional,
                "plaintext headers by magic; encrypted headers only weakly (extension + size) — never decrypted while probing",
            )
            .op_req(Inspect, Conditional, "header fields need header_key", vec![key("header_key")])
            .op_req(
                List,
                Conditional,
                "sections and their PFS0/RomFS files need section keys",
                vec![key("header_key"), key("key_area_key_application_XX")],
            )
            .op_req(Extract, Conditional, "decrypted section files", vec![key("header_key"), key("key_area_key_application_XX")])
            .op_req(Verify, Conditional, "fs-header and master hashes; content ID", vec![key("header_key")])
            .op_req(Compress, zs, "to NCZ", vec![key("header_key"), key("key_area_key_application_XX")])
            .op(Bundle, Unsupported, "bundle packages, not single archives")
            .op(ApplyUpdate, Unsupported, "supply base and update packages"),
        FormatDescriptor::new(SWITCH_NCZ, Platform::Switch, "NCZ", &["ncz"], "compressed NCA (NCZSECTN)")
            .op(Probe, Supported, "NCZSECTN at 0x4000")
            .op(Inspect, Supported, "section table, block info; NCA header needs header_key")
            .op(List, Supported, "restored NCA and its sections when keys are available")
            .op(Extract, Supported, "restored NCA")
            .op(Verify, Supported, "restored content-ID SHA-256")
            .op_req(Decompress, zs, "byte-identical NCA restoration without keys", vec![Requirement::Codec("zstd".into())]),
        FormatDescriptor::new(SWITCH_PFS0, Platform::Switch, "PFS0", &["pfs0", "exefs"], "bare partition filesystem (e.g. ExeFS)")
            .op(Probe, Supported, "PFS0 magic without NCA members")
            .op(Inspect, Supported, "")
            .op(List, Supported, "")
            .op(Extract, Supported, "")
            .op(Verify, Supported, "structure (no per-file hashes)")
            .op(Repack, Supported, "library API: pfs0::layout + package::write_nsp"),
        FormatDescriptor::new(SWITCH_HFS0, Platform::Switch, "HFS0", &["hfs0"], "hashed partition filesystem")
            .op(Probe, Supported, "HFS0 magic")
            .op(Inspect, Supported, "")
            .op(List, Supported, "")
            .op(Extract, Supported, "")
            .op(Verify, Supported, "per-entry SHA-256 of hashed regions")
            .op(Repack, Supported, "library API: hfs0::write"),
        FormatDescriptor::new(SWITCH_ROMFS, Platform::Switch, "RomFS", &["romfs"], "level-3 RomFS image (as extracted from an NCA)")
            .op(Probe, Supported, "header layout heuristics (low confidence)")
            .op(Inspect, Supported, "")
            .op(List, Supported, "")
            .op(Extract, Supported, "")
            .op(Verify, Supported, "table structure")
            .op(Repack, Supported, "library API: romux::switch::RomfsBuilder"),
    ]
}

/// Capability baseline for a format.
pub(crate) fn capabilities_for(f: FormatId) -> CapabilitySet {
    let d = descriptors().into_iter().find(|d| d.id == f).expect("switch descriptor");
    CapabilitySet::from_descriptor(&d)
}

fn conversions() -> Vec<ConversionEdge> {
    use OutputGuarantee::*;
    let z = if cfg!(feature = "zstd") { Support::Conditional } else { Support::Unsupported };
    vec![
        ConversionEdge::new(
            SWITCH_XCI,
            SWITCH_NSP,
            ConversionKind::ContainerRepack,
            Support::Supported,
            "secure-partition NCAs copied into a PFS0",
        )
        .guarantees(&[ContainerValid, PayloadBytesPreserved, CompatibilityUnverified]),
        ConversionEdge::new(
            SWITCH_NSP,
            SWITCH_XCI,
            ConversionKind::ContainerRepack,
            Support::Conditional,
            "tickets dropped; rights-ID NCAs need option convert_rights=true and keys",
        )
        .guarantees(&[ContainerValid, NotAuthentic, CompatibilityUnverified])
        .requires(Requirement::KeyMaterial("header_key".into())),
        ConversionEdge::new(SWITCH_XCZ, SWITCH_NSZ, ConversionKind::ContainerRepack, Support::Supported, "NCZ members copied")
            .guarantees(&[ContainerValid, PayloadBytesPreserved, CompatibilityUnverified]),
        ConversionEdge::new(SWITCH_NSZ, SWITCH_XCZ, ConversionKind::ContainerRepack, Support::Conditional, "as NSP→XCI").guarantees(&[
            ContainerValid,
            NotAuthentic,
            CompatibilityUnverified,
        ]),
        ConversionEdge::new(SWITCH_NSP, SWITCH_NSZ, ConversionKind::Compress, z, "requires keys")
            .guarantees(&[ContainerValid, ByteIdenticalRoundTrip, ContentPreserved])
            .requires(Requirement::KeyMaterial("header_key".into())),
        ConversionEdge::new(SWITCH_XCI, SWITCH_XCZ, ConversionKind::Compress, z, "requires keys; block mode").guarantees(&[
            ContainerValid,
            ByteIdenticalRoundTrip,
            ContentPreserved,
            NotAuthentic,
        ]),
        ConversionEdge::new(SWITCH_NSZ, SWITCH_NSP, ConversionKind::Decompress, z, "no keys needed")
            .guarantees(&[ContainerValid, ByteIdenticalRoundTrip]),
        ConversionEdge::new(SWITCH_XCZ, SWITCH_XCI, ConversionKind::Decompress, z, "no keys needed").guarantees(&[
            ContainerValid,
            ByteIdenticalRoundTrip,
            NotAuthentic,
        ]),
        ConversionEdge::new(SWITCH_NSZ, SWITCH_XCI, ConversionKind::Decompress, z, "decompress + container change").guarantees(&[
            ContainerValid,
            ContentPreserved,
            NotAuthentic,
        ]),
        ConversionEdge::new(SWITCH_XCZ, SWITCH_NSP, ConversionKind::Decompress, z, "decompress + container change")
            .guarantees(&[ContainerValid, ContentPreserved]),
        ConversionEdge::new(SWITCH_NCA, SWITCH_NCZ, ConversionKind::Compress, z, "requires keys").guarantees(&[ByteIdenticalRoundTrip]),
        ConversionEdge::new(SWITCH_NCZ, SWITCH_NCA, ConversionKind::Decompress, z, "no keys needed").guarantees(&[ByteIdenticalRoundTrip]),
    ]
}

impl SwitchBackend {
    pub fn new() -> Self {
        SwitchBackend
    }
}

impl Backend for SwitchBackend {
    fn name(&self) -> &'static str {
        "switch"
    }
    fn platform(&self) -> Platform {
        Platform::Switch
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        conversions()
    }

    fn probe(&self, s: &dyn DataSource, l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let len = s.len()?;
        let mut m = [0u8; 4];
        if len >= 0x10 {
            s.read_exact_at(0, &mut m)?;
        }
        let limits = crate::ResourceLimits { max_metadata: l.max_read, ..Default::default() };
        if &m == b"PFS0" {
            match partition::read_table(s, 0, len, partition::Kind::Pfs0, &limits) {
                Ok((_, entries)) => {
                    let names: Vec<_> = entries.iter().map(|e| e.name.to_ascii_lowercase()).collect();
                    let ncz = names.iter().any(|n| n.ends_with(".ncz"));
                    let nca = names.iter().any(|n| n.ends_with(".nca") || n.ends_with(".tik"));
                    let ev = if ncz {
                        ProbeEvidence::new(SWITCH_NSZ, Confidence::High).matched("PFS0 with .ncz members")
                    } else if nca {
                        ProbeEvidence::new(SWITCH_NSP, Confidence::High).matched("PFS0 with .nca/.tik members")
                    } else {
                        ProbeEvidence::new(SWITCH_PFS0, Confidence::High).matched("PFS0 without package members")
                    };
                    out.push(ev.matched(format!("{} entries, table bounds valid", entries.len())).specificity(2).refines(SWITCH_PFS0));
                }
                Err(e) => {
                    out.push(ProbeEvidence::new(SWITCH_PFS0, Confidence::Low).matched("PFS0 magic").warn(format!("table invalid: {e}")))
                }
            }
        } else if &m == b"HFS0" {
            out.push(ProbeEvidence::new(SWITCH_HFS0, Confidence::High).matched("HFS0 magic"));
        }
        if let Ok(h) = xci::parse_header(s) {
            let mut ev = ProbeEvidence::new(SWITCH_XCI, Confidence::Medium).matched(format!("HEAD magic at 0x{:x}", h.base + 0x100));
            let root_base = h.base + h.hfs0_offset;
            if root_base < len {
                if let Ok((rh, root)) = partition::read_table(s, root_base, len - root_base, partition::Kind::Hfs0, &limits) {
                    ev.confidence = Confidence::High;
                    ev = ev.matched(format!("root HFS0 with partitions {:?}", root.iter().map(|e| e.name.clone()).collect::<Vec<_>>()));
                    if let Some(sec) = root.iter().find(|e| e.name == "secure") {
                        let sb = root_base + rh + sec.offset;
                        if let Ok((_, files)) = partition::read_table(s, sb, sec.size, partition::Kind::Hfs0, &limits) {
                            if files.iter().any(|e| e.name.ends_with(".ncz")) {
                                ev.format = SWITCH_XCZ;
                                ev = ev.matched("secure partition holds .ncz members");
                            }
                        }
                    }
                }
            }
            out.push(ev);
        }
        if ncz::probe(s) {
            out.push(ProbeEvidence::new(SWITCH_NCZ, Confidence::Certain).matched("NCZSECTN at 0x4000").specificity(3));
        } else if len >= 0xC00 {
            let mut magic = [0u8; 4];
            s.read_exact_at(0x200, &mut magic)?;
            if matches!(&magic, b"NCA3" | b"NCA2") {
                out.push(ProbeEvidence::new(SWITCH_NCA, Confidence::High).matched("plaintext NCA header magic"));
            } else if len % 0x200 == 0 {
                let ext = s.identity().path.and_then(|p| p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()));
                if ext.as_deref() == Some("nca") {
                    out.push(
                        ProbeEvidence::new(SWITCH_NCA, Confidence::Low)
                            .matched("extension .nca and media-unit aligned size")
                            .warn("header is encrypted; structure not verified (probing never decrypts)"),
                    );
                }
            }
        }
        if out.is_empty() && romfs::probe(s) {
            out.push(ProbeEvidence::new(SWITCH_ROMFS, Confidence::Low).matched("RomFS level-3 header layout"));
        }
        Ok(out)
    }

    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            SWITCH_NSP | SWITCH_NSZ | SWITCH_XCI | SWITCH_XCZ => Ok(Box::new(reader::SwitchPackage::open(source, ctx)?)),
            SWITCH_NCA | SWITCH_NCZ => Ok(Box::new(reader::NcaReader::open(source, format, ctx)?)),
            SWITCH_PFS0 | SWITCH_HFS0 => Ok(Box::new(reader::PartitionReader::open(source, format, ctx)?)),
            SWITCH_ROMFS => Ok(Box::new(reader::RomfsReader::open(source, ctx)?)),
            _ => Err(Error::unsupported(format!("switch backend cannot open {format}"))),
        }
    }

    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let level = req.option_u64("level")?.map(|v| v as i32).unwrap_or(18);
        let block = req.option_u64("block")?.map(|v| v as u8);
        if req.from == SWITCH_NCA || req.from == SWITCH_NCZ {
            return convert::plan_single_archive(&req.input, &req.output, req.to, &req.ctx, level, block);
        }
        let target = bundle::PackageFormat::from_format_id(req.to).ok_or_else(|| Error::unsupported("undeclared conversion"))?;
        let from = bundle::PackageFormat::from_format_id(req.from).ok_or_else(|| Error::unsupported("undeclared conversion"))?;
        let plan = if !from.is_compressed() && target.is_compressed() {
            CompressBuilder::new(&req.input).target(target).level(level).block_exponent(block).context(req.ctx.clone()).plan()?
        } else if from.is_compressed() && !target.is_compressed() && from.is_gamecard() == target.is_gamecard() {
            DecompressBuilder::new(&req.input).context(req.ctx.clone()).plan()?
        } else {
            ConvertBuilder::new(&req.input, target)
                .convert_rights(req.option("convert_rights") == Some("true"))
                .context(req.ctx.clone())
                .plan()?
        };
        Ok(plan.into_planned(req.output))
    }
}

#[cfg(test)]
pub(crate) mod tests_ops;

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::switch::cnmt::build_binary;
    pub use crate::switch::nca::ContentType;
    pub use crate::switch::nca::testkit::*;
}
