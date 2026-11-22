//! # `romux::n3ds`
//!
//! Nintendo 3DS formats: CCI/.3DS (NCSD cartridge layout), NCCH (CXI/CFA), ExeFS, RomFS,
//! and CIA installable archives. CIA (installable title) and CCI (cartridge layout) stay
//! semantically separate.
//!
//! Access: NCCH partitions flagged *NoCrypto* are read directly. Encrypted NCCH content is
//! decrypted when the user supplies the KeyX slots and key-scrambler constant (see
//! `docs/key-material.md`); without them it stays opaque. CIA
//! content encryption (title key) is supported when the user supplies the normal common
//! key `ctr_common_key_<n>`.

pub(crate) mod cia;
pub(crate) mod ncch;
pub(crate) mod ncch_crypto;

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, ErrorCode, FileSource, FormatDescriptor, FormatId, IoPolicy, JobContext,
    KeyProvider, NodeKind, NodeTable, OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader,
    PlanInput, PlanOutput, PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Result, SharedSource, Support, TransformPlan,
    VerifyLevel, VerifyReport,
};
use std::sync::Arc;

pub const N3DS_CCI: FormatId = FormatId("3ds.cci");
pub const N3DS_NCCH: FormatId = FormatId("3ds.ncch");
pub const N3DS_CIA: FormatId = FormatId("3ds.cia");

#[derive(Default)]
pub struct N3dsBackend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    vec![
        FormatDescriptor::new(N3DS_CCI, Platform::N3ds, "CCI (.3ds)", &["3ds", "cci"], "NCSD cartridge image")
            .op(Probe, Supported, "NCSD magic at 0x100")
            .op(Inspect, Supported, "media ID, partitions, NCCH headers")
            .op(List, Conditional, "partition NCCHs always; ExeFS/RomFS files for NoCrypto or key-decrypted partitions")
            .op(Extract, Conditional, "NCCH partitions always; files for NoCrypto or key-decrypted partitions")
            .op(Verify, Conditional, "structure; ExeFS/RomFS superblock and file hashes for NoCrypto or key-decrypted partitions")
            .op(Convert, Conditional, "to an unsigned CIA (NoCrypto, or decrypted with user keys); not installable on retail systems"),
        FormatDescriptor::new(N3DS_NCCH, Platform::N3ds, "NCCH (CXI/CFA)", &["cxi", "cfa", "app"], "content container")
            .op(Probe, Supported, "NCCH magic at 0x100")
            .op(Inspect, Supported, "program ID, product code, flags")
            .op(List, Conditional, "NoCrypto, or encrypted with slot0x2CKeyX etc. and generator")
            .op(Extract, Conditional, "NoCrypto, or encrypted with user keys")
            .op(Verify, Conditional, "hashes of plaintext content (encrypted content needs keys)"),
        FormatDescriptor::new(N3DS_CIA, Platform::N3ds, "CIA", &["cia"], "installable title archive")
            .op(Probe, Supported, "0x2020 header size")
            .op(Inspect, Supported, "title ID, version, content chunks")
            .op(List, Supported, "certs, ticket, TMD, contents, meta")
            .op(Extract, Supported, "sections and contents as stored")
            .op(Verify, Conditional, "TMD SHA-256 of contents (encrypted contents need ctr_common_key_N)")
            .op(Repack, Unsupported, "signed CIAs cannot be produced")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, "3DS updates are separate installable titles"),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

impl Backend for N3dsBackend {
    fn name(&self) -> &'static str {
        "3ds"
    }
    fn platform(&self) -> Platform {
        Platform::N3ds
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        vec![
            ConversionEdge::new(
                N3DS_CCI,
                N3DS_CIA,
                ConversionKind::Rebuild,
                Support::Conditional,
                "NoCrypto (or key-decrypted) partitions become plaintext CIA contents; zero signatures",
            )
            .guarantees(&[
                OutputGuarantee::ContentPreserved,
                OutputGuarantee::NotAuthentic,
                OutputGuarantee::ModifiedUnsigned,
                OutputGuarantee::CompatibilityUnverified,
            ]),
        ]
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        if s.len()? >= 0x200 {
            let mut m = [0u8; 4];
            s.read_exact_at(0x100, &mut m)?;
            if &m == b"NCSD" {
                out.push(match ncch::NcsdHeader::parse(s) {
                    Ok(h) => {
                        ProbeEvidence::new(N3DS_CCI, Confidence::High).matched(format!("NCSD magic, {} partitions", h.partitions.len()))
                    }
                    Err(e) => ProbeEvidence::new(N3DS_CCI, Confidence::Low).matched("NCSD magic").warn(e.to_string()),
                });
            } else if &m == b"NCCH" {
                out.push(ProbeEvidence::new(N3DS_NCCH, Confidence::High).matched("NCCH magic"));
            }
        }
        if s.len()? >= 0x2040 && cia::probe(s) && cia::Cia::open(Arc::new(Copyless::new(s)?)).is_ok() {
            out.push(ProbeEvidence::new(N3DS_CIA, Confidence::High).matched("CIA header, TMD and content layout valid"));
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            N3DS_CCI => Ok(Box::new(CciReader::open(source, ctx)?)),
            N3DS_NCCH => {
                let mut t = NodeTable::new();
                let view = add_ncch(&mut t, source.clone(), "", ctx)?;
                Ok(Box::new(NcchReader { source, view, table: t }))
            }
            N3DS_CIA => Ok(Box::new(CiaReader::open(source, ctx)?)),
            _ => Err(Error::unsupported(format!("3ds backend cannot open {format}"))),
        }
    }
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let ncsd = ncch::NcsdHeader::parse(req.source.as_ref())?;
        let mut parts = Vec::new();
        for (i, off, size) in &ncsd.partitions {
            let s = ncch::region(&req.source, *off, *size)?;
            let view = view_ncch(&s, req.ctx.keys.as_ref())?;
            match (view.plain, view.state) {
                (Some(p), _) => parts.push((*i as u16, p)),
                (None, state) => {
                    return Err(Error::new(ErrorCode::NeedsKeyMaterial, format!("partition {i} is encrypted NCCH: {}", state.describe()))
                        .with_suggestion("supply slot0x2CKeyX, the method's KeyX slot and generator with --key-file"));
                }
            }
        }
        let mut plan = TransformPlan::new(Operation::Convert);
        plan.inputs.push(PlanInput::capture(&req.input, "source", N3DS_CCI)?);
        crate::check_output_target(&req.output, &IoPolicy::default(), &plan.input_paths())
            .or_else(|e| if e.code() == ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
        plan.outputs.push(PlanOutput {
            path: req.output.clone(),
            format: Some(N3DS_CIA),
            kind: "file",
            category: "unsigned installable archive".into(),
            estimated_size: None,
        });
        plan.guarantees = self.conversions()[0].guarantees.clone();
        plan.restrictions.push("signatures are zero: the CIA will not install on retail systems".into());
        let tid = ncsd.media_id;
        Ok(ClosurePlan::new(
            plan,
            Box::new(move |plan, job| {
                let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                cia::write_unsigned(tid, 0, &parts, &mut f, job)?;
                f.flush_for_verify()?;
                let back = cia::Cia::open(Arc::new(FileSource::open(f.temp_path())?))?;
                for (c, (_, s)) in back.contents.iter().zip(&parts) {
                    let h = crate::crypto::hash_range(back.raw_content(c)?.as_ref(), 0, c.size, crate::crypto::HashAlg::Sha256, None)?;
                    let w = crate::crypto::hash_range(s.as_ref(), 0, s.len()?, crate::crypto::HashAlg::Sha256, None)?;
                    if h != w || crate::hex(&h) != c.hash {
                        return Err(Error::new(ErrorCode::VerificationFailed, "CIA content does not match its source partition"));
                    }
                }
                let out = f.finish()?;
                let mut rep = OperationReport::new(Operation::Convert, plan.input_paths());
                rep.outputs.push(OutputRecord::from_path(&out, Some(N3DS_CIA), &plan.guarantees)?);
                Ok(rep)
            }),
        ))
    }
}

/// Probe helper that owns a copy of the header region for CIA parsing (bounded).
struct Copyless {
    data: Vec<u8>,
    len: u64,
}

impl Copyless {
    fn new(s: &dyn DataSource) -> Result<Self> {
        let len = s.len()?;
        let n = len.min(0x2020 + 0x10000);
        Ok(Copyless { data: crate::read_vec(s, 0, n, n)?, len })
    }
}

impl DataSource for Copyless {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        let end = offset as usize + out.len();
        if end > self.data.len() {
            return Err(Error::limit("probe read outside bounded window"));
        }
        out.copy_from_slice(&self.data[offset as usize..end]);
        Ok(())
    }
}

/// How an NCCH's content can be read.
#[derive(Debug, Clone)]
pub(crate) enum NcchState {
    /// Stored as NoCrypto.
    Plain,
    /// Encrypted; decrypted with user-supplied keys.
    Decrypted,
    /// Encrypted and unreadable (the reason, e.g. a missing key name).
    Encrypted(String),
}

impl NcchState {
    fn describe(&self) -> String {
        match self {
            NcchState::Plain => "NoCrypto".into(),
            NcchState::Decrypted => "decrypted with user-supplied keys".into(),
            NcchState::Encrypted(why) => format!("content is opaque ({why})"),
        }
    }
}

/// An NCCH as stored plus, when possible, a plaintext (NoCrypto-equivalent) view.
pub(crate) struct NcchView {
    pub header: ncch::NcchHeader,
    pub plain: Option<SharedSource>,
    pub state: NcchState,
}

/// Parse an NCCH and decrypt it with `keys` when it is encrypted and the keys are present.
pub(crate) fn view_ncch(src: &SharedSource, keys: &dyn KeyProvider) -> Result<NcchView> {
    let header = ncch::NcchHeader::parse(src.as_ref())?;
    if header.no_crypto() {
        return Ok(NcchView { header, plain: Some(src.clone()), state: NcchState::Plain });
    }
    Ok(match ncch_crypto::DecryptedNcch::shared(src.clone(), keys) {
        Ok(p) => NcchView { header, plain: Some(p), state: NcchState::Decrypted },
        Err(e) => NcchView { header, plain: None, state: NcchState::Encrypted(e.message().to_string()) },
    })
}

/// Add NCCH nodes (header, exheader, ExeFS/RomFS files when readable).
fn add_ncch(t: &mut NodeTable, src: SharedSource, prefix: &str, ctx: &OpenContext) -> Result<NcchView> {
    let view = view_ncch(&src, ctx.keys.as_ref())?;
    let h = &view.header;
    let p = |s: &str| if prefix.is_empty() { s.to_string() } else { format!("{prefix}/{s}") };
    t.push(ContentNode::file(0, p("ncch_header.bin"), 0x200).kind(NodeKind::Metadata), Some(ncch::region(&src, 0, 0x200)?));
    let Some(plain) = view.plain.clone() else {
        if h.exheader_size > 0 {
            t.push(ContentNode::file(0, p("exheader.bin"), 0x800).kind(NodeKind::Metadata).encrypted(true), None);
        }
        if h.exefs.1 > 0 {
            t.push(ContentNode::file(0, p("exefs.bin"), h.exefs.1).encrypted(true), None);
        }
        if h.romfs.1 > 0 {
            t.push(ContentNode::file(0, p("romfs.bin"), h.romfs.1).encrypted(true), None);
        }
        return Ok(view);
    };
    if h.exheader_size > 0 {
        t.push(ContentNode::file(0, p("exheader.bin"), 0x800).kind(NodeKind::Metadata), Some(ncch::region(&plain, 0x200, 0x800)?));
    }
    if h.exefs.1 > 0 {
        let ex = ncch::region(&plain, h.exefs.0, h.exefs.1)?;
        for f in ncch::parse_exefs(ex.as_ref())? {
            t.push(ContentNode::file(0, p(&format!("exefs/{}", f.name)), f.size), Some(ncch::region(&ex, f.offset, f.size)?));
        }
    }
    if h.romfs.1 > 0 {
        let rf = ncch::region(&plain, h.romfs.0, h.romfs.1)?;
        let (_, files) = ncch::parse_romfs(rf.as_ref(), &ctx.limits)?;
        for f in files {
            t.push(ContentNode::file(0, p(&format!("romfs/{}", f.path)), f.size), Some(ncch::region(&rf, f.offset, f.size)?));
        }
    }
    Ok(view)
}

fn verify_ncch(r: &mut VerifyReport, view: &NcchView, name: &str, level: VerifyLevel) -> Result<()> {
    let h = &view.header;
    r.pass(CheckLevel::Structure, &format!("{name} header"), Some(format!("{} {}", h.product_code, h.content_type())));
    let src = match (&view.plain, &view.state) {
        (Some(p), NcchState::Decrypted) => {
            r.pass(CheckLevel::Structure, &format!("{name} decryption"), Some("keys derived from user-supplied key material".into()));
            p
        }
        (Some(p), _) => p,
        (None, state) => {
            r.not_checked(CheckLevel::Content, &format!("{name} hashes"), format!("hashes cover plaintext; {}", state.describe()));
            return Ok(());
        }
    };
    if !level.wants_content() {
        return Ok(());
    }
    if h.exheader_size > 0 {
        let d = read_vec_s(src, 0x200, 0x400)?;
        r.check(CheckLevel::Content, &format!("{name} exheader hash"), crate::crypto::sha256(&d) == h.exheader_hash, "SHA-256");
    }
    if h.exefs.1 > 0 {
        let ex = ncch::region(src, h.exefs.0, h.exefs.1)?;
        let sb = read_vec_s(&ex, 0, h.exefs.2.min(h.exefs.1))?;
        r.check(CheckLevel::Content, &format!("{name} ExeFS superblock hash"), crate::crypto::sha256(&sb) == h.exefs_hash, "SHA-256");
        for f in ncch::parse_exefs(ex.as_ref())? {
            let d = crate::crypto::hash_range(ex.as_ref(), f.offset, f.size, crate::crypto::HashAlg::Sha256, None)?;
            r.check(CheckLevel::Content, &format!("{name} exefs/{}", f.name), d[..] == f.hash, "SHA-256");
        }
    }
    if h.romfs.1 > 0 {
        let rf = ncch::region(src, h.romfs.0, h.romfs.1)?;
        let sb = read_vec_s(&rf, 0, h.romfs.2.min(h.romfs.1))?;
        r.check(CheckLevel::Content, &format!("{name} RomFS superblock hash"), crate::crypto::sha256(&sb) == h.romfs_hash, "SHA-256");
    }
    Ok(())
}

fn read_vec_s(s: &SharedSource, off: u64, len: u64) -> Result<Vec<u8>> {
    crate::read_vec(s.as_ref(), off, len, 64 << 20)
}

fn push_state(i: &mut PackageInfo, name: &str, state: &NcchState) {
    match state {
        NcchState::Plain => {}
        NcchState::Decrypted => {
            i.field(&format!("{name}_decryption"), "user-supplied keys");
        }
        NcchState::Encrypted(why) => i.limitations.push(format!("{name}: encrypted NCCH, ExeFS/RomFS are opaque ({why})")),
    }
}

pub(crate) struct NcchReader {
    source: SharedSource,
    view: NcchView,
    table: NodeTable,
}

impl PackageReader for NcchReader {
    fn format(&self) -> FormatId {
        N3DS_NCCH
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(N3DS_NCCH, Platform::N3ds, self.source.len()?);
        let header = &self.view.header;
        i.title_id = Some(format!("{:016x}", header.program_id));
        i.product_code = Some(header.product_code.clone());
        i.version = Some(header.version.to_string());
        i.encrypted = Some(!header.no_crypto());
        i.field("content_type", header.content_type());
        i.family_id = Some(format!("{:05x}", (header.program_id >> 8) & 0xFFFFF));
        push_state(&mut i, "ncch", &self.view.state);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(N3DS_NCCH, level);
        verify_ncch(&mut r, &self.view, "ncch", level)?;
        r.authenticity_unavailable("NCCH RSA signature");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = caps(N3DS_NCCH);
        if self.view.plain.is_none() {
            c.block(Operation::Extract, "encrypted NCCH");
            c.block(Operation::List, "encrypted NCCH");
        }
        Ok(c)
    }
}

pub(crate) struct CciReader {
    source: SharedSource,
    ncsd: ncch::NcsdHeader,
    headers: Vec<(usize, NcchView)>,
    table: NodeTable,
}

impl CciReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let ncsd = ncch::NcsdHeader::parse(source.as_ref())?;
        let mut table = NodeTable::new();
        let mut headers = Vec::new();
        for (i, off, size) in &ncsd.partitions {
            let name = format!("partition{i}-{}", ncch::partition_name(*i));
            let s = ncch::region(&source, *off, *size)?;
            table.push(ContentNode::file(0, format!("{name}.ncch"), *size).kind(NodeKind::Content), Some(s.clone()));
            match add_ncch(&mut table, s, &name, ctx) {
                Ok(h) => headers.push((*i, h)),
                Err(e) => {
                    table.push(ContentNode::file(0, format!("{name}/(unreadable)"), 0).readable(false).meta("error", e.to_string()), None);
                }
            }
        }
        Ok(CciReader { source, ncsd, headers, table })
    }
}

impl PackageReader for CciReader {
    fn format(&self) -> FormatId {
        N3DS_CCI
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(N3DS_CCI, Platform::N3ds, self.source.len()?);
        i.category = ContentCategory::Application;
        i.title_id = Some(format!("{:016x}", self.ncsd.media_id));
        if let Some((_, v)) = self.headers.iter().find(|(i, _)| *i == 0) {
            let h = &v.header;
            i.product_code = Some(h.product_code.clone());
            i.version = Some(h.version.to_string());
            i.encrypted = Some(!h.no_crypto());
            i.family_id = Some(format!("{:05x}", (h.program_id >> 8) & 0xFFFFF));
        }
        i.field("partitions", self.ncsd.partitions.len() as u64);
        i.field("image_size", self.ncsd.image_size);
        for (n, v) in &self.headers {
            push_state(&mut i, &format!("partition {n}"), &v.state);
        }
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(N3DS_CCI, level);
        r.pass(CheckLevel::Structure, "NCSD partition table", Some(format!("{} partitions within image", self.ncsd.partitions.len())));
        for (i, off, size) in &self.ncsd.partitions {
            match self.headers.iter().find(|(n, _)| n == i) {
                Some((_, v)) => verify_ncch(&mut r, v, &format!("partition {i}"), level)?,
                None => r.fail(
                    CheckLevel::Structure,
                    &format!("partition {i} header"),
                    format!("unreadable NCCH at 0x{off:x} (0x{size:x} bytes)"),
                ),
            }
        }
        r.authenticity_unavailable("NCSD/NCCH RSA signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = caps(N3DS_CCI);
        if self.headers.iter().any(|(_, v)| v.plain.is_none()) {
            c.block(Operation::Convert, "encrypted NCCH partitions need key material to be repackaged");
        }
        Ok(c)
    }
}

pub(crate) struct CiaReader {
    cia: cia::Cia,
    table: NodeTable,
    keys: Arc<dyn KeyProvider>,
}

impl CiaReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let c = cia::Cia::open(source)?;
        let mut table = NodeTable::new();
        table.push(ContentNode::file(0, "certs.bin", c.cert.1).kind(NodeKind::Certificate), Some(c.section(c.cert)?));
        table.push(ContentNode::file(0, "ticket.bin", c.ticket.1).kind(NodeKind::Ticket), Some(c.section(c.ticket)?));
        table.push(ContentNode::file(0, "tmd.bin", c.tmd.1).kind(NodeKind::Metadata), Some(c.section(c.tmd)?));
        for ch in &c.contents {
            let name = format!("{:04x}.{:08x}.app", ch.index, ch.id);
            table.push(
                ContentNode::file(0, name.clone(), ch.size)
                    .kind(NodeKind::Content)
                    .encrypted(ch.encrypted())
                    .meta("sha256", ch.hash.clone()),
                Some(c.raw_content(ch)?),
            );
            if !ch.encrypted() {
                let s = c.raw_content(ch)?;
                if ncch::NcchHeader::parse(s.as_ref()).is_ok() {
                    let _ = add_ncch(&mut table, s, &format!("{:04x}", ch.index), ctx);
                }
            }
        }
        if c.meta.1 > 0 {
            table.push(ContentNode::file(0, "meta.bin", c.meta.1).kind(NodeKind::Metadata), Some(c.section(c.meta)?));
        }
        Ok(CiaReader { cia: c, table, keys: ctx.keys.clone() })
    }
}

impl PackageReader for CiaReader {
    fn format(&self) -> FormatId {
        N3DS_CIA
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(N3DS_CIA, Platform::N3ds, self.cia.src.len()?);
        i.title_id = Some(format!("{:016x}", self.cia.title_id));
        i.version = Some(self.cia.title_version.to_string());
        i.family_id = Some(format!("{:05x}", (self.cia.title_id >> 8) & 0xFFFFF));
        i.category = match (self.cia.title_id >> 32) as u32 {
            0x0004_0000 => ContentCategory::Application,
            0x0004_000E => ContentCategory::Patch,
            0x0004_008C => ContentCategory::AddOn,
            0x0004_0001 => ContentCategory::Application,
            0x0004_0010 | 0x0004_0030 | 0x0004_0130 | 0x0004_001B | 0x0004_009B | 0x0004_00DB => ContentCategory::System,
            _ => ContentCategory::Unknown,
        };
        i.encrypted = Some(self.cia.contents.iter().any(|c| c.encrypted()));
        i.field("contents", self.cia.contents.len() as u64);
        i.field("common_key_index", self.cia.common_key_index);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(N3DS_CIA, level);
        r.pass(CheckLevel::Structure, "sections", Some(format!("{} contents", self.cia.contents.len())));
        if level.wants_content() {
            for c in &self.cia.contents {
                job.check_cancel()?;
                match self.cia.content_plain(c, self.keys.as_ref(), job.limits.max_memory) {
                    Ok(s) => {
                        let h = crate::crypto::hash_range(s.as_ref(), 0, c.size, crate::crypto::HashAlg::Sha256, None)?;
                        r.check(CheckLevel::Content, &format!("content {:04x} SHA-256", c.index), crate::hex(&h) == c.hash, "matches TMD");
                    }
                    Err(e) if e.code() == ErrorCode::NeedsKeyMaterial => {
                        r.skip(CheckLevel::Content, &format!("content {:04x} SHA-256", c.index), e.message().to_string())
                    }
                    Err(e) => r.fail(CheckLevel::Content, &format!("content {:04x}", c.index), e.to_string()),
                }
            }
        }
        r.authenticity_unavailable("ticket/TMD signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(N3DS_CIA))
    }
}

#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    //! Synthetic NoCrypto CCI construction.
    //!
    //! Synthetic-fixture builder (feature `testkit`; not part of the stable API).
    pub fn ncch(program_id: u64, product: &str, exefs_files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut ex = vec![0u8; 0x200];
        let mut data = Vec::new();
        for (i, (n, d)) in exefs_files.iter().enumerate() {
            ex[i * 16..i * 16 + n.len()].copy_from_slice(n.as_bytes());
            ex[i * 16 + 8..i * 16 + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            ex[i * 16 + 12..i * 16 + 16].copy_from_slice(&(d.len() as u32).to_le_bytes());
            let h = crate::crypto::sha256(d);
            ex[0xC0 + (9 - i) * 32..0xC0 + (10 - i) * 32].copy_from_slice(&h);
            data.extend_from_slice(d);
            while data.len() % 0x200 != 0 {
                data.push(0);
            }
        }
        ex.extend(data);
        let mut n = vec![0u8; 0x200];
        n[0x100..0x104].copy_from_slice(b"NCCH");
        n[0x118..0x120].copy_from_slice(&program_id.to_le_bytes());
        n[0x150..0x150 + product.len()].copy_from_slice(product.as_bytes());
        n[0x188 + 5] = 0x3;
        n[0x188 + 7] = 0x4;
        n[0x1A0..0x1A4].copy_from_slice(&1u32.to_le_bytes());
        n[0x1A4..0x1A8].copy_from_slice(&((ex.len() / 0x200) as u32).to_le_bytes());
        n[0x1A8..0x1AC].copy_from_slice(&1u32.to_le_bytes());
        n[0x1C0..0x1E0].copy_from_slice(&crate::crypto::sha256(&ex[..0x200]));
        n.extend(ex);
        let units = (n.len() / 0x200) as u32;
        n[0x104..0x108].copy_from_slice(&units.to_le_bytes());
        n
    }

    pub fn cci(media_id: u64, partitions: &[Vec<u8>]) -> Vec<u8> {
        let mut img = vec![0u8; 0x4000];
        img[0x100..0x104].copy_from_slice(b"NCSD");
        img[0x108..0x110].copy_from_slice(&media_id.to_le_bytes());
        for (i, p) in partitions.iter().enumerate() {
            let off = img.len();
            img[0x120 + i * 8..0x124 + i * 8].copy_from_slice(&((off / 0x200) as u32).to_le_bytes());
            img[0x124 + i * 8..0x128 + i * 8].copy_from_slice(&((p.len() / 0x200) as u32).to_le_bytes());
            img.extend_from_slice(p);
        }
        let units = (img.len() / 0x200) as u32;
        img[0x104..0x108].copy_from_slice(&units.to_le_bytes());
        img
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, Registry};

    #[test]
    fn cci_nocrypto_and_cia_conversion() {
        let n = testkit::ncch(0x0004_0000_0012_3400, "CTR-P-TEST", &[(".code", vec![0xC0u8; 0x400]), ("icon", vec![1u8; 0x36C0])]);
        let img = testkit::cci(0x0004_0000_0012_3400, &[n]);
        let reg = Registry::new().with(N3dsBackend);
        let src: SharedSource = Arc::new(MemorySource::new(img.clone()));
        assert_eq!(reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap().format, Some(N3DS_CCI));
        let r = reg.open(src, &OpenContext::default()).unwrap();
        assert_eq!(r.info().unwrap().product_code.as_deref(), Some("CTR-P-TEST"));
        assert!(r.entries().unwrap().any(|e| e.unwrap().path == "partition0-game/exefs/.code"));
        let v = r.verify(VerifyLevel::Content, &JobContext::default()).unwrap();
        assert!(v.no_failures(), "{:?}", v.checks);
        let d = tempfile::tempdir().unwrap();
        let cci = d.path().join("g.3ds");
        std::fs::write(&cci, &img).unwrap();
        let out = d.path().join("g.cia");
        let req = ConvertRequest {
            input: cci.clone(),
            source: crate::open_file(&cci).unwrap(),
            from: N3DS_CCI,
            to: N3DS_CIA,
            output: out.clone(),
            ctx: OpenContext::default(),
            options: Default::default(),
        };
        N3dsBackend.plan_convert(req).unwrap().execute(&JobContext::default()).unwrap();
        let cs = crate::open_file(&out).unwrap();
        assert_eq!(reg.probe(cs.as_ref(), &ProbeLimits::default()).unwrap().format, Some(N3DS_CIA));
        let c = reg.open(cs, &OpenContext::default()).unwrap();
        assert!(c.verify(VerifyLevel::Content, &JobContext::default()).unwrap().no_failures());
    }
}
