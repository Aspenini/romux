//! # `romux::n64`
//!
//! Nintendo 64 cartridge images in their three byte orders:
//!
//! | format | first bytes | layout |
//! |---|---|---|
//! | `n64.z64` | `80 37 12 40` | native big-endian |
//! | `n64.v64` | `37 80 40 12` | 16-bit byte-swapped |
//! | `n64.n64` | `40 12 37 80` | 32-bit little-endian words |
//!
//! Romux reads the header (title, game code, region, revision), identifies the CIC boot
//! chip from the IPL3 boot code, recomputes the header checksums (CRC1/CRC2) and converts
//! between byte orders losslessly. Cartridges have no filesystem, so listing exposes the
//! normalised ROM, header and boot code as views.

pub(crate) mod rom;

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, FileSource, FormatDescriptor, FormatId, IoPolicy, JobContext, NodeKind,
    NodeTable, OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput, PlanOutput,
    PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Result, SharedSource, SubSource, Support, TransformPlan, VerifyLevel,
    VerifyReport,
};
use rom::{ByteOrder, NativeView, RomHeader};
use std::sync::Arc;

pub const N64_Z64: FormatId = FormatId("n64.z64");
pub const N64_V64: FormatId = FormatId("n64.v64");
pub const N64_N64: FormatId = FormatId("n64.n64");

pub(crate) fn format_for(o: ByteOrder) -> FormatId {
    match o {
        ByteOrder::BigEndian => N64_Z64,
        ByteOrder::ByteSwapped => N64_V64,
        ByteOrder::LittleEndian => N64_N64,
    }
}

fn order_for(f: FormatId) -> Option<ByteOrder> {
    Some(match f {
        N64_Z64 => ByteOrder::BigEndian,
        N64_V64 => ByteOrder::ByteSwapped,
        N64_N64 => ByteOrder::LittleEndian,
        _ => return None,
    })
}

#[derive(Default)]
pub struct N64Backend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    let d = |id, name, ext: &'static [&'static str], desc| {
        FormatDescriptor::new(id, Platform::N64, name, ext, desc)
            .op(Probe, Supported, "PI header word in one of the three byte orders")
            .op(Inspect, Supported, "title, game code, region, revision, CIC, checksums, size")
            .op(List, Supported, "normalised big-endian ROM, header and IPL3 boot code views")
            .op(Extract, Supported, "the views above")
            .op(Verify, Supported, "CIC identified from IPL3; header CRC1/CRC2 recomputed")
            .op(Convert, Supported, "to the other byte orders (lossless)")
            .op(Repack, Unsupported, "cartridges have no filesystem")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, "N64 titles have no update packages")
    };
    vec![
        d(N64_Z64, "N64 ROM (big-endian)", &["z64"], "native big-endian cartridge image"),
        d(N64_V64, "N64 ROM (byte-swapped)", &["v64"], "16-bit byte-swapped cartridge image (Doctor V64)"),
        d(N64_N64, "N64 ROM (little-endian)", &["n64"], "32-bit little-endian word cartridge image"),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

impl Backend for N64Backend {
    fn name(&self) -> &'static str {
        "n64"
    }
    fn platform(&self) -> Platform {
        Platform::N64
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        let mut v = Vec::new();
        for a in [N64_Z64, N64_V64, N64_N64] {
            for b in [N64_Z64, N64_V64, N64_N64] {
                if a != b {
                    v.push(
                        ConversionEdge::new(
                            a,
                            b,
                            ConversionKind::ContainerRepack,
                            Support::Supported,
                            "byte-order change; ROM content unchanged",
                        )
                        .guarantees(&[OutputGuarantee::ContentPreserved, OutputGuarantee::ContainerValid]),
                    );
                }
            }
        }
        v
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let len = s.len()?;
        if len < 0x1000 {
            return Ok(out);
        }
        let mut m = [0u8; 4];
        s.read_exact_at(0, &mut m)?;
        if let Some(order) = ByteOrder::detect(&m) {
            let mut ev = ProbeEvidence::new(format_for(order), Confidence::Medium).matched(format!("PI header word ({})", order.name()));
            if len % 4 == 0 && len >= 0x10_1000 {
                ev.confidence = Confidence::High;
                ev = ev.matched("size covers the checksummed region");
            }
            out.push(ev);
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, _ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match order_for(format) {
            Some(_) => Ok(Box::new(RomReader::open(source, format)?)),
            None => Err(Error::unsupported(format!("n64 backend cannot open {format}"))),
        }
    }
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let to_order = order_for(req.to).ok_or_else(|| Error::unsupported("undeclared conversion"))?;
        let mut plan = TransformPlan::new(Operation::Convert);
        plan.inputs.push(PlanInput::capture(&req.input, "source", req.from)?);
        crate::check_output_target(&req.output, &IoPolicy::default(), &plan.input_paths())
            .or_else(|e| if e.code() == crate::ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
        let native: SharedSource = Arc::new(NativeView::new(req.source.clone())?);
        let len = native.len()?;
        if len % 4 != 0 {
            return Err(Error::unsupported("ROM size is not a multiple of 4 bytes; byte order cannot be changed losslessly"));
        }
        plan.outputs.push(PlanOutput {
            path: req.output.clone(),
            format: Some(req.to),
            kind: "file",
            category: "cartridge image".into(),
            estimated_size: Some(len),
        });
        plan.guarantees = vec![OutputGuarantee::ContentPreserved, OutputGuarantee::ContainerValid];
        plan.steps.push(format!("rewrite {} bytes as {}", len, to_order.name()));
        Ok(ClosurePlan::new(
            plan,
            Box::new(move |plan, job| {
                let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                rom::write_order(native.as_ref(), to_order, &mut f, job)?;
                f.flush_for_verify()?;
                let back = NativeView::new(Arc::new(FileSource::open(f.temp_path())?))?;
                let a = crate::crypto::hash_range(native.as_ref(), 0, len, crate::crypto::HashAlg::Sha1, None)?;
                let b = crate::crypto::hash_range(&back, 0, back.len()?, crate::crypto::HashAlg::Sha1, None)?;
                if a != b {
                    return Err(Error::new(crate::ErrorCode::VerificationFailed, "converted ROM content differs"));
                }
                let out = f.finish()?;
                let mut rep = OperationReport::new(Operation::Convert, plan.input_paths());
                rep.outputs.push(OutputRecord::from_path(&out, Some(format_for(to_order)), &plan.guarantees)?);
                rep.metadata.insert("rom_sha1".into(), crate::hex(&a).into());
                Ok(rep)
            }),
        ))
    }
}

pub(crate) struct RomReader {
    format: FormatId,
    source: SharedSource,
    native: SharedSource,
    pub header: RomHeader,
    cic: Option<rom::Cic>,
    table: NodeTable,
}

impl RomReader {
    pub fn open(source: SharedSource, format: FormatId) -> Result<Self> {
        let native: SharedSource = Arc::new(NativeView::new(source.clone())?);
        let head = crate::read_vec(native.as_ref(), 0, 0x1000, 0x1000)?;
        let header = RomHeader::parse(&head)?;
        let cic = rom::Cic::identify(&head[0x40..0x1000]);
        let mut table = NodeTable::new();
        let len = native.len()?;
        table.push(ContentNode::file(0, "rom.z64", len).kind(NodeKind::Track).meta("byte_order", "big-endian"), Some(native.clone()));
        table.push(ContentNode::file(0, "header.bin", 0x40).kind(NodeKind::Metadata), Some(SubSource::shared(native.clone(), 0, 0x40)?));
        table.push(ContentNode::file(0, "ipl3.bin", 0xFC0).kind(NodeKind::Metadata), Some(SubSource::shared(native.clone(), 0x40, 0xFC0)?));
        Ok(RomReader { format, source, native, header, cic, table })
    }
}

impl PackageReader for RomReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let h = &self.header;
        let mut i = PackageInfo::new(self.format, Platform::N64, self.source.len()?);
        i.title = Some(h.title.clone()).filter(|t| !t.is_empty());
        i.product_code = Some(h.product_code());
        i.title_id = Some(h.game_code.clone());
        i.family_id = h.game_code.get(1..3).map(String::from);
        i.region = Some(h.region().into());
        i.version = Some(format!("1.{}", h.version));
        i.category = match h.game_code.as_bytes().first() {
            Some(b'D') | Some(b'E') => ContentCategory::Data,
            _ => ContentCategory::Application,
        };
        i.encrypted = Some(false);
        i.field("byte_order", order_for(self.format).map(|o| o.name()).unwrap_or("?"));
        i.field("media", h.media());
        i.field("crc1", format!("{:08X}", h.crc1));
        i.field("crc2", format!("{:08X}", h.crc2));
        i.field("entry_point", format!("{:08X}", h.entry_point));
        i.field("cic", self.cic.map(|c| c.name()).unwrap_or("unknown"));
        i.field("size_mbit", self.native.len()? * 8 / (1 << 20));
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(self.format, level);
        let len = self.native.len()?;
        r.check(CheckLevel::Structure, "size", len % 4 == 0, format!("{len} bytes"));
        match self.cic {
            Some(c) => r.pass(CheckLevel::Structure, "boot code", Some(format!("IPL3 matches {}", c.name()))),
            None => r.warn(CheckLevel::Structure, "boot code", "IPL3 not recognised; checksum seed unknown"),
        }
        if level.wants_content() {
            match self.cic {
                Some(c) if len >= 0x10_1000 => {
                    job.check_cancel()?;
                    let (c1, c2) = rom::checksum(self.native.as_ref(), c)?;
                    r.check(
                        CheckLevel::Content,
                        "header checksum",
                        c1 == self.header.crc1 && c2 == self.header.crc2,
                        format!("computed {c1:08X} {c2:08X}, header {:08X} {:08X}", self.header.crc1, self.header.crc2),
                    );
                }
                Some(_) => r.skip(CheckLevel::Content, "header checksum", "ROM smaller than the 1 MiB checksummed region"),
                None => r.skip(CheckLevel::Content, "header checksum", "unknown CIC"),
            }
        }
        r.skip(CheckLevel::Authenticity, "signature", "N64 cartridges carry no signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(self.format))
    }
}
