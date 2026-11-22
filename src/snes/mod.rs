//! # `romux::snes`
//!
//! Super Nintendo / Super Famicom cartridge images:
//!
//! | format | layout |
//! |---|---|
//! | `snes.sfc` | the ROM as is (headerless) |
//! | `snes.smc` | a 512-byte copier header (SMC/SWC/FIG) followed by the ROM |
//!
//! The extension does not decide the format: many `.smc` files are headerless and some
//! `.sfc` files carry a copier header. Romux uses the size (`len % 1024 == 512` means a
//! copier header). It locates the internal header (LoROM, HiROM or ExHiROM) by scoring the
//! candidates and verifies the header checksum, including hardware-style mirroring for
//! ROM sizes that are not a power of two. Cartridges have no filesystem, so listing exposes
//! the headerless ROM and the headers as views.

pub(crate) mod rom;

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, FileSource, FormatDescriptor, FormatId, IoPolicy, JobContext, NodeKind,
    NodeTable, OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput, PlanOutput,
    PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Result, SharedSource, SubSource, Support, TransformPlan, VerifyLevel,
    VerifyReport,
};
use rom::{COPIER_HEADER, SnesHeader};
use std::io::Write;
use std::sync::Arc;

pub const SNES_SFC: FormatId = FormatId("snes.sfc");
pub const SNES_SMC: FormatId = FormatId("snes.smc");

#[derive(Default)]
pub struct SnesBackend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    let d = |id, name, ext: &'static [&'static str], desc, convert| {
        FormatDescriptor::new(id, Platform::Snes, name, ext, desc)
            .op(Probe, Supported, "scored internal header (LoROM, HiROM, ExHiROM); copier header from the size")
            .op(Inspect, Supported, "title, game code, region, version, mapping, speed, chipset, ROM/SRAM sizes, checksum")
            .op(List, Supported, "headerless ROM, internal header and copier header views")
            .op(Extract, Supported, "the views above")
            .op(Verify, Supported, "checksum/complement pair and recomputed checksum (mirrored for odd sizes)")
            .op(Convert, Supported, convert)
            .op(Repack, Unsupported, "cartridges have no filesystem")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, "SNES titles have no update packages")
    };
    vec![
        d(SNES_SFC, "SNES ROM", &["sfc", "smc"], "headerless cartridge image", "to SMC (adds a 512-byte copier header)"),
        d(
            SNES_SMC,
            "SNES ROM with copier header",
            &["smc", "swc", "fig"],
            "512-byte copier header + cartridge image",
            "to SFC (drops the copier header)",
        ),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

/// The ROM without any copier header.
pub(crate) fn headerless(source: &SharedSource) -> Result<SharedSource> {
    let len = source.len()?;
    let off = rom::copier_offset(len);
    SubSource::shared(source.clone(), off, len - off)
}

impl Backend for SnesBackend {
    fn name(&self) -> &'static str {
        "snes"
    }
    fn platform(&self) -> Platform {
        Platform::Snes
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        let g = [OutputGuarantee::ContentPreserved, OutputGuarantee::ContainerValid];
        vec![
            ConversionEdge::new(
                SNES_SMC,
                SNES_SFC,
                ConversionKind::ContainerRepack,
                Support::Supported,
                "copier header removed; ROM unchanged",
            )
            .guarantees(&g),
            ConversionEdge::new(
                SNES_SFC,
                SNES_SMC,
                ConversionKind::ContainerRepack,
                Support::Supported,
                "512-byte SWC-style copier header added; ROM unchanged",
            )
            .guarantees(&g),
        ]
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let len = s.len()?;
        if len < 0x8000 + rom::copier_offset(len) {
            return Ok(Vec::new());
        }
        let off = rom::copier_offset(len);
        let view = Offset { s, off, len: len - off };
        let Ok(h) = SnesHeader::detect(&view) else { return Ok(Vec::new()) };
        let format = if off > 0 { SNES_SMC } else { SNES_SFC };
        let confidence = match h.score {
            11.. => Confidence::High,
            8..=10 => Confidence::Medium,
            _ => Confidence::Low,
        };
        let mut ev = ProbeEvidence::new(format, confidence).matched(format!("{} internal header (score {})", h.mapping.name(), h.score));
        if h.complement_ok() {
            ev = ev.matched("checksum and complement agree");
        }
        if off > 0 {
            ev = ev.matched("512-byte copier header (size % 1024 == 512)");
        }
        Ok(vec![ev])
    }
    fn open(&self, format: FormatId, source: SharedSource, _ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            SNES_SFC | SNES_SMC => Ok(Box::new(RomReader::open(source, format)?)),
            _ => Err(Error::unsupported(format!("snes backend cannot open {format}"))),
        }
    }
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        if !matches!((req.from, req.to), (SNES_SMC, SNES_SFC) | (SNES_SFC, SNES_SMC)) {
            return Err(Error::unsupported("undeclared conversion"));
        }
        let mut plan = TransformPlan::new(Operation::Convert);
        plan.inputs.push(PlanInput::capture(&req.input, "source", req.from)?);
        crate::check_output_target(&req.output, &IoPolicy::default(), &plan.input_paths())
            .or_else(|e| if e.code() == crate::ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
        let rom = headerless(&req.source)?;
        SnesHeader::detect(rom.as_ref())?;
        let len = rom.len()?;
        let add = req.to == SNES_SMC;
        plan.outputs.push(PlanOutput {
            path: req.output.clone(),
            format: Some(req.to),
            kind: "file",
            category: "cartridge image".into(),
            estimated_size: Some(len + if add { COPIER_HEADER } else { 0 }),
        });
        plan.guarantees = vec![OutputGuarantee::ContentPreserved, OutputGuarantee::ContainerValid];
        plan.steps.push(if add { "prepend a 512-byte copier header".into() } else { "drop the 512-byte copier header".into() });
        let to = req.to;
        Ok(ClosurePlan::new(
            plan,
            Box::new(move |plan, job| {
                let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                if add {
                    f.write_all(&rom::copier_header(len))?;
                }
                let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(len));
                crate::copy_all(rom.as_ref(), &mut f, &mut p)?;
                f.flush_for_verify()?;
                let back = headerless(&(Arc::new(FileSource::open(f.temp_path())?) as SharedSource))?;
                let a = crate::crypto::hash_range(rom.as_ref(), 0, len, crate::crypto::HashAlg::Sha1, None)?;
                let b = crate::crypto::hash_range(back.as_ref(), 0, back.len()?, crate::crypto::HashAlg::Sha1, None)?;
                if a != b {
                    return Err(Error::new(crate::ErrorCode::VerificationFailed, "converted ROM content differs"));
                }
                let out = f.finish()?;
                let mut rep = OperationReport::new(Operation::Convert, plan.input_paths());
                rep.outputs.push(OutputRecord::from_path(&out, Some(to), &plan.guarantees)?);
                rep.metadata.insert("rom_sha1".into(), crate::hex(&a).into());
                Ok(rep)
            }),
        ))
    }
}

/// Borrowed view past a copier header, for probing without an owned source.
struct Offset<'a> {
    s: &'a dyn DataSource,
    off: u64,
    len: u64,
}

impl DataSource for Offset<'_> {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        self.s.read_exact_at(self.off + offset, out)
    }
}

pub(crate) struct RomReader {
    format: FormatId,
    source: SharedSource,
    rom: SharedSource,
    pub header: SnesHeader,
    copier: bool,
    table: NodeTable,
}

impl RomReader {
    pub fn open(source: SharedSource, format: FormatId) -> Result<Self> {
        let copier = rom::copier_offset(source.len()?) > 0;
        let rom = headerless(&source)?;
        let header = SnesHeader::detect(rom.as_ref())?;
        let mut table = NodeTable::new();
        let len = rom.len()?;
        table.push(ContentNode::file(0, "rom.sfc", len).kind(NodeKind::Track), Some(rom.clone()));
        let at = header.mapping.header_offset() - 0x10;
        table.push(
            ContentNode::file(0, "internal_header.bin", 0x50).kind(NodeKind::Metadata),
            Some(SubSource::shared(rom.clone(), at, 0x50)?),
        );
        if copier {
            table.push(
                ContentNode::file(0, "copier_header.bin", COPIER_HEADER).kind(NodeKind::Metadata),
                Some(SubSource::shared(source.clone(), 0, COPIER_HEADER)?),
            );
        }
        Ok(RomReader { format, source, rom, header, copier, table })
    }
}

impl PackageReader for RomReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let h = &self.header;
        let mut i = PackageInfo::new(self.format, Platform::Snes, self.source.len()?);
        i.title = Some(h.title.clone()).filter(|t| !t.is_empty());
        i.product_code = h.product_code();
        i.title_id = h.game_code.clone();
        // Four-letter codes are type + two-letter game + region; older two-letter codes are the game.
        i.family_id = h.game_code.as_ref().map(|g| if g.len() == 4 { g[1..3].to_string() } else { g.clone() });
        i.region = Some(h.region().into());
        i.version = Some(format!("1.{}", h.version));
        i.category = ContentCategory::Application;
        i.encrypted = Some(false);
        i.field("mapping", h.mapping.name());
        i.field("speed", if h.fast_rom() { "FastROM (3.58 MHz)" } else { "SlowROM (2.68 MHz)" });
        i.field("chipset", h.chipset_name());
        i.field("rom_size", self.rom.len()?);
        if let Some(d) = h.rom_size_bytes() {
            i.field("rom_size_declared", d);
        }
        i.field("sram_size", h.sram_size_bytes());
        i.field("video", h.video());
        if let Some(m) = &h.maker_code {
            i.field("maker_code", m.clone());
        } else {
            i.field("licensee", format!("{:02X}", h.licensee));
        }
        i.field("checksum", format!("{:04X}", h.checksum));
        i.field("complement", format!("{:04X}", h.complement));
        i.field("copier_header", self.copier);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let h = &self.header;
        let mut r = VerifyReport::new(self.format, level);
        r.pass(
            CheckLevel::Structure,
            "internal header",
            Some(format!("{} at 0x{:X} (score {})", h.mapping.name(), h.mapping.header_offset(), h.score)),
        );
        r.check(CheckLevel::Structure, "checksum complement", h.complement_ok(), format!("{:04X} ^ {:04X}", h.checksum, h.complement));
        let len = self.rom.len()?;
        match h.rom_size_bytes() {
            Some(d) if len <= d => r.pass(CheckLevel::Structure, "ROM size", Some(format!("{len} bytes, header declares {d}"))),
            Some(d) => r.warn(CheckLevel::Structure, "ROM size", format!("{len} bytes exceed the declared {d}")),
            None => r.warn(CheckLevel::Structure, "ROM size", format!("unknown size code 0x{:02X}", h.rom_size_code)),
        }
        if level.wants_content() {
            let c = rom::checksum(self.rom.as_ref(), job)?;
            r.check(CheckLevel::Content, "header checksum", c == h.checksum, format!("computed {c:04X}, header {:04X}", h.checksum));
        }
        r.skip(CheckLevel::Authenticity, "signature", "SNES cartridges carry no signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(self.format))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, Registry};

    #[test]
    fn probe_open_verify_and_convert() {
        let rom = rom::testkit::rom(0x20_0000, rom::Mapping::LoRom, "ROMUX SNES TEST", None);
        let mut smc = rom::copier_header(rom.len() as u64).to_vec();
        smc.extend_from_slice(&rom);
        let reg = Registry::new().with(SnesBackend);
        for (bytes, want) in [(&rom, SNES_SFC), (&smc, SNES_SMC)] {
            let src: SharedSource = Arc::new(MemorySource::new(bytes.clone()));
            assert_eq!(reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap().format, Some(want));
            let r = reg.open(src, &OpenContext::default()).unwrap();
            assert_eq!(r.info().unwrap().title.as_deref(), Some("ROMUX SNES TEST"));
            let v = r.verify(VerifyLevel::Content, &JobContext::default()).unwrap();
            assert!(v.no_failures(), "{:?}", v.checks);
        }
        // SMC -> SFC -> SMC round trip.
        let d = tempfile::tempdir().unwrap();
        let input = d.path().join("g.smc");
        std::fs::write(&input, &smc).unwrap();
        let conv = |from, to, input: &std::path::Path, out: &std::path::Path| {
            let req = ConvertRequest {
                input: input.to_path_buf(),
                source: crate::open_file(input).unwrap(),
                from,
                to,
                output: out.to_path_buf(),
                ctx: OpenContext::default(),
                options: Default::default(),
            };
            SnesBackend.plan_convert(req).unwrap().execute(&JobContext::default()).unwrap();
        };
        let sfc = d.path().join("g.sfc");
        conv(SNES_SMC, SNES_SFC, &input, &sfc);
        assert_eq!(std::fs::read(&sfc).unwrap(), rom);
        let back = d.path().join("g2.smc");
        conv(SNES_SFC, SNES_SMC, &sfc, &back);
        assert_eq!(std::fs::read(&back).unwrap(), smc);
        // A corrupted byte fails the checksum.
        let mut bad = rom.clone();
        bad[0x1234] ^= 1;
        let r = reg.open(Arc::new(MemorySource::new(bad)), &OpenContext::default()).unwrap();
        assert!(!r.verify(VerifyLevel::Content, &JobContext::default()).unwrap().no_failures());
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::snes::rom::testkit::*;
}
