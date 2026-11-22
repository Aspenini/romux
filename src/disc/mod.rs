//! # `romux::disc`
//!
//! Generic, console-agnostic disc formats:
//!
//! * `disc.iso9660` — ISO9660/Joliet filesystems on 2048-byte sector images;
//! * `disc.cue` — CUE sheets with BIN track files (raw 2352 / cooked layouts);
//! * `disc.bin` — single raw 2352-byte sector images without a cue sheet;
//! * `disc.chd` — CHD v3/v4/v5 containers (v5 writing).
//!
//! "ISO" is never treated as a catch-all: console disc images with their own filesystems
//! (GameCube/Wii, Xbox XDVDFS) are handled by their console modules. An opaque disc data
//! stream and a traversable filesystem are always distinguished.

pub(crate) mod chd;
pub(crate) mod cue;
pub(crate) mod iso9660;
pub(crate) mod rawcd;
pub(crate) mod zar;
pub(crate) mod zar_reader;
pub(crate) use zar_reader::ZarReader;
pub use zar_reader::plan_repack_zar;

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, FileSource, FormatDescriptor, FormatId, JobContext, NodeKind, NodeTable,
    OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader, PlanInput, PlanOutput,
    PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Requirement, ResourceLimits, Result, SharedSource, Support, TransformPlan,
    VerifyLevel, VerifyReport, check_output_target,
};
use chd::{ChdFile, ChdMedia, ChdSource, ChdTrackSource};
use cue::CueSheet;
use iso9660::IsoFs;
use rawcd::{CookedSource, TrackMode};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const ISO9660: FormatId = FormatId("disc.iso9660");
pub const CUE: FormatId = FormatId("disc.cue");
pub const BIN: FormatId = FormatId("disc.bin");
pub const CHD: FormatId = FormatId("disc.chd");
pub const ZAR: FormatId = FormatId("archive.zar");

/// The generic disc backend.
#[derive(Default)]
pub struct DiscBackend;

impl DiscBackend {
    pub fn new() -> Self {
        DiscBackend
    }
}

fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    let chd_codecs = format!(
        "decodes zlib, huff, cdzl, flac, cdfl{}{}; A/V codecs unsupported",
        if crate::compression::Codec::Zstd.can_decode() { ", zstd, cdzs" } else { "" },
        if crate::compression::Codec::Lzma2.can_decode() { ", lzma, cdlz" } else { "" }
    );
    vec![
        FormatDescriptor::new(
            ISO9660,
            Platform::Generic,
            "ISO9660 image",
            &["iso"],
            "ECMA-119 filesystem on 2048-byte sectors (Joliet names preferred)",
        )
        .op(Probe, Supported, "primary volume descriptor at sector 16")
        .op(Inspect, Supported, "volume descriptors")
        .op(List, Supported, "directory hierarchy; Rock Ridge extensions ignored")
        .op(Extract, Supported, "files with sanitized paths")
        .op(Verify, Supported, "structure only; ISO9660 declares no content hashes or signatures")
        .op(Repack, Supported, "deterministic image from a directory tree (relaxed names, no Joliet)")
        .op(Compress, Supported, "to CHD (DVD layout)")
        .op(Bundle, Unsupported, "no multi-title semantics")
        .op(ApplyUpdate, Unsupported, "no update semantics")
        .op(Split, Unsupported, "no multi-content semantics"),
        FormatDescriptor::new(CUE, Platform::Generic, "CUE/BIN", &["cue"], "CUE sheet referencing BIN track files")
            .op(Probe, Supported, "text sheet with FILE/TRACK/INDEX")
            .op(Inspect, Supported, "tracks, modes, indexes, pregaps")
            .op(List, Supported, "tracks and the ISO9660 filesystem of the first data track")
            .op(Extract, Supported, "raw tracks and data-track files")
            .op(Verify, Supported, "layout checks and Mode 1 EDC")
            .op(Compress, Supported, "to CHD (CD layout, cdzl/cdzs codecs, subcode not preserved)")
            .op(Convert, Conditional, "first data track to ISO9660 when it carries 2048-byte user data"),
        FormatDescriptor::new(BIN, Platform::Generic, "Raw CD image", &["bin", "img"], "single-track raw 2352-byte sector image")
            .op(Probe, Supported, "CD sync pattern and mode byte")
            .op(Inspect, Supported, "sector mode")
            .op(List, Supported, "track and filesystem")
            .op(Extract, Supported, "filesystem files")
            .op(Verify, Supported, "Mode 1 EDC per sector")
            .op(Convert, Conditional, "to ISO9660 for Mode 1 / Mode 2 Form 1 data; sync/headers/ECC not preserved"),
        FormatDescriptor::new(CHD, Platform::Generic, "CHD", &["chd"], "Compressed Hunks of Data v3/v4/v5")
            .op(Probe, Supported, "MComprHD signature")
            .op(Inspect, Supported, "header, codecs, metadata, CD tracks, parent reference")
            .op(List, Supported, "tracks or image, plus ISO9660 filesystem when present")
            .op(Extract, Conditional, &format!("requires decodable codecs ({chd_codecs}) and the parent CHD when referenced"))
            .op(Verify, Conditional, "map CRC, per-hunk CRC, raw and overall SHA-1 (needs decodable codecs)")
            .op_req(
                Decompress,
                Conditional,
                "to ISO9660 (DVD/raw) or CUE/BIN (CD); byte-identical logical data",
                vec![Requirement::Codec("per-hunk codecs".into())],
            )
            .op(Compress, Supported, "v5 writer; zlib/zstd (DVD) and cdzl/cdzs (CD)"),
        FormatDescriptor::new(ZAR, Platform::Generic, "ZArchive", &["zar"], "zstd-block archive of an extracted game tree (Cemu, Xenia)")
            .op(Probe, Supported, "footer magic 0x169F52D6 and version")
            .op(Inspect, Supported, "block count, sizes, detected content platform")
            .op(List, Supported, "file tree")
            .op(Extract, Supported, "files with sanitized paths (requires zstd)")
            .op(Verify, Supported, "section bounds, tree structure, footer SHA-256 integrity hash")
            .op(Repack, Supported, "deterministic archive from a directory"),
    ]
}

fn conversions() -> Vec<ConversionEdge> {
    use OutputGuarantee::*;
    vec![
        ConversionEdge::new(ISO9660, CHD, ConversionKind::Compress, Support::Supported, "CHD v5 DVD layout; lossless").guarantees(&[
            ByteIdenticalRoundTrip,
            ContainerValid,
            CompatibilityUnverified,
        ]),
        ConversionEdge::new(CUE, CHD, ConversionKind::Compress, Support::Supported, "CHD v5 CD layout; sector data lossless, no subcode")
            .guarantees(&[ContentPreserved, ContainerValid, CompatibilityUnverified]),
        ConversionEdge::new(CHD, ISO9660, ConversionKind::Decompress, Support::Conditional, "DVD/raw CHDs only")
            .guarantees(&[ByteIdenticalRoundTrip])
            .requires(Requirement::Codec("hunk codecs".into())),
        ConversionEdge::new(CHD, CUE, ConversionKind::Decompress, Support::Conditional, "CD CHDs; writes .cue and a single .bin")
            .guarantees(&[ContentPreserved])
            .requires(Requirement::Codec("hunk codecs".into())),
        ConversionEdge::new(BIN, ISO9660, ConversionKind::PartitionExport, Support::Conditional, "Mode 1 / Mode 2 Form 1 user data")
            .guarantees(&[ContentPreserved, LayoutNotPreserved]),
        ConversionEdge::new(CUE, ISO9660, ConversionKind::PartitionExport, Support::Conditional, "first data track user data")
            .guarantees(&[ContentPreserved, LayoutNotPreserved]),
    ]
}

impl Backend for DiscBackend {
    fn name(&self) -> &'static str {
        "disc"
    }
    fn platform(&self) -> Platform {
        Platform::Generic
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        conversions()
    }

    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let len = s.len()?;
        if zar::probe(s) {
            out.push(ProbeEvidence::new(ZAR, Confidence::High).matched("ZArchive footer magic and version"));
        }
        if iso9660::probe(s) {
            out.push(ProbeEvidence::new(ISO9660, Confidence::High).matched("CD001 volume descriptor at sector 16"));
        }
        if len >= 16 {
            let mut h = [0u8; 16];
            s.read_exact_at(0, &mut h)?;
            if &h[..8] == chd::MAGIC {
                out.push(ProbeEvidence::new(CHD, Confidence::High).matched("MComprHD signature"));
            }
            if h[..12] == rawcd::SYNC && len % 2352 == 0 && (h[15] == 1 || h[15] == 2) {
                let mut ev = ProbeEvidence::new(BIN, Confidence::Medium).matched(format!("CD sync pattern, mode {}", h[15]));
                let pvd_off = 16 * 2352 + if h[15] == 1 { 16 } else { 24 };
                let mut p = [0u8; 6];
                if s.read_exact_at(pvd_off, &mut p).is_ok() && &p[1..6] == b"CD001" {
                    ev = ev.matched("ISO9660 descriptor in sector 16 user data");
                    ev.confidence = Confidence::High;
                }
                out.push(ev);
            }
        }
        if (16..=1 << 20).contains(&len) {
            let text = crate::read_vec(s, 0, len.min(64 * 1024), 64 * 1024)?;
            if let Ok(t) = std::str::from_utf8(&text) {
                if cue::looks_like_cue(t) && CueSheet::parse(t).is_ok() {
                    out.push(ProbeEvidence::new(CUE, Confidence::High).matched("valid CUE sheet syntax"));
                }
            }
        }
        Ok(out)
    }

    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            ISO9660 => Ok(Box::new(IsoReader::open(source, ctx)?)),
            CUE => Ok(Box::new(CueReader::open(source, ctx)?)),
            BIN => Ok(Box::new(BinReader::open(source, ctx)?)),
            CHD => Ok(Box::new(ChdReader::open(source, ctx)?)),
            ZAR => Ok(Box::new(ZarReader::open(source, ctx)?)),
            _ => Err(Error::unsupported(format!("disc backend cannot open {format}"))),
        }
    }

    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        plan_conversion(req)
    }
}

// ------------------------------------------------------------------------------------------
// Shared helpers
// ------------------------------------------------------------------------------------------

/// Add the files of an ISO9660 filesystem under `prefix` to a node table.
pub(crate) fn add_iso_nodes(t: &mut NodeTable, fs: &IsoFs, prefix: &str) -> Result<()> {
    for e in fs.entries() {
        let path = if prefix.is_empty() { e.path.clone() } else { format!("{prefix}/{}", e.path) };
        if e.is_dir {
            t.push(ContentNode::dir(0, path), None);
        } else {
            let data = fs.open_entry(e)?;
            let mut n = ContentNode::file(0, path, e.size);
            if let [(lba, _)] = e.extents[..] {
                n = n.meta("lba", lba as u64);
            }
            t.push(n, Some(data));
        }
    }
    Ok(())
}

fn volume_fields(info: &mut PackageInfo, fs: &IsoFs) {
    let v = &fs.volume;
    info.field("volume_id", v.volume_id.clone());
    if !v.system_id.is_empty() {
        info.field("system_id", v.system_id.clone());
    }
    if !v.publisher.is_empty() {
        info.field("publisher", v.publisher.clone());
    }
    if !v.application.is_empty() {
        info.field("application", v.application.clone());
    }
    if !v.creation_date.is_empty() {
        info.field("creation_date", v.creation_date.clone());
    }
    info.field("volume_blocks", v.volume_blocks);
    info.field("joliet", v.joliet);
    info.warnings.extend(fs.warnings.iter().cloned());
}

fn sibling(source: &SharedSource, name: &str) -> Result<PathBuf> {
    let base = source
        .identity()
        .path
        .ok_or_else(|| Error::unsupported("CUE sheets can only be opened from files (BIN paths are relative to the sheet)"))?;
    let comps = crate::path::sanitize_components(name, 255)?;
    let mut p = base.parent().map(Path::to_path_buf).unwrap_or_default();
    for c in comps {
        p.push(c);
    }
    Ok(p)
}

fn caps_for(format: FormatId) -> CapabilitySet {
    let d = descriptors().into_iter().find(|d| d.id == format).expect("descriptor");
    CapabilitySet::from_descriptor(&d)
}

// ------------------------------------------------------------------------------------------
// ISO9660 reader
// ------------------------------------------------------------------------------------------

pub(crate) struct IsoReader {
    source: SharedSource,
    fs: IsoFs,
    table: NodeTable,
}

impl IsoReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let fs = IsoFs::open(source.clone(), &ctx.limits)?;
        let mut table = NodeTable::new();
        add_iso_nodes(&mut table, &fs, "")?;
        Ok(IsoReader { source, fs, table })
    }
}

impl PackageReader for IsoReader {
    fn format(&self) -> FormatId {
        ISO9660
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(ISO9660, Platform::Generic, self.source.len()?);
        i.category = ContentCategory::DiscImage;
        i.title = Some(self.fs.volume.volume_id.clone()).filter(|s| !s.is_empty());
        volume_fields(&mut i, &self.fs);
        i.sizes.payload = Some(self.fs.entries().iter().map(|e| e.size).sum());
        i.encrypted = Some(false);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(ISO9660, level);
        r.pass(CheckLevel::Structure, "volume descriptors", Some(format!("{} blocks", self.fs.volume.volume_blocks)));
        let probs = self.fs.check_extents()?;
        if probs.is_empty() {
            r.pass(CheckLevel::Structure, "file extents", Some(format!("{} entries within image, no overlap", self.fs.entries().len())));
        } else {
            for p in probs {
                if p.contains("overlap") {
                    r.warn(CheckLevel::Structure, "file extents", p);
                } else {
                    r.fail(CheckLevel::Structure, "file extents", p);
                }
            }
        }
        for w in &self.fs.warnings {
            r.warn(CheckLevel::Structure, "filesystem", w.clone());
        }
        if level.wants_content() {
            r.skip(CheckLevel::Content, "content hashes", "ISO9660 declares no content hashes");
        }
        r.skip(CheckLevel::Authenticity, "signature", "ISO9660 has no signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps_for(ISO9660))
    }
}

// ------------------------------------------------------------------------------------------
// CUE reader
// ------------------------------------------------------------------------------------------

pub(crate) struct CueReader {
    source: SharedSource,
    pub sheet: CueSheet,
    pub layouts: Vec<cue::TrackLayout>,
    files: Vec<SharedSource>,
    fs: Option<IsoFs>,
    table: NodeTable,
    warnings: Vec<String>,
}

impl CueReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let text = crate::read_vec(source.as_ref(), 0, source.len()?, 1 << 20)?;
        let text = String::from_utf8_lossy(&text).into_owned();
        let sheet = CueSheet::parse(&text)?;
        let mut files = Vec::new();
        let mut sizes = Vec::new();
        for f in &sheet.files {
            if f.kind != "BINARY" && f.kind != "MOTOROLA" {
                return Err(Error::unsupported(format!("CUE FILE type {} is not supported (only BINARY)", f.kind)));
            }
            let p = sibling(&source, &f.name)?;
            let s = Arc::new(FileSource::open(&p).map_err(|e| e.with_suggestion("BIN files must sit next to the CUE sheet"))?);
            sizes.push(s.len()?);
            files.push(s as SharedSource);
        }
        let layouts = cue::layout(&sheet, &sizes)?;
        let mut table = NodeTable::new();
        let mut warnings = Vec::new();
        let mut fs = None;
        for l in &layouts {
            let data = crate::SubSource::shared(files[l.file].clone(), l.offset, l.length)?;
            let name = format!("track{:02}.{}", l.number, if l.mode.is_data() { "bin" } else { "raw" });
            let n = ContentNode::file(0, name, l.length).kind(NodeKind::Track).meta("mode", l.mode.cue_name()).meta("frames", l.frames);
            table.push(n, Some(data.clone()));
            if fs.is_none() && l.mode.user_data_offset().is_some() {
                let cooked: SharedSource = Arc::new(CookedSource::new(data, l.mode)?);
                if iso9660::probe(cooked.as_ref()) {
                    match IsoFs::open(cooked, &ctx.limits) {
                        Ok(f) => {
                            add_iso_nodes(&mut table, &f, "data")?;
                            fs = Some(f);
                        }
                        Err(e) => warnings.push(format!("track {} filesystem unreadable: {e}", l.number)),
                    }
                }
            }
        }
        Ok(CueReader { source, sheet, layouts, files, fs, table, warnings })
    }

    /// The cooked 2048-byte view of the first data track.
    pub fn first_data_track(&self) -> Result<SharedSource> {
        let l = self
            .layouts
            .iter()
            .find(|l| l.mode.user_data_offset().is_some())
            .ok_or_else(|| Error::unsupported("no track with 2048-byte user data"))?;
        let data = crate::SubSource::shared(self.files[l.file].clone(), l.offset, l.length)?;
        Ok(Arc::new(CookedSource::new(data, l.mode)?))
    }

    pub fn track_data(&self, i: usize) -> Result<SharedSource> {
        let l = &self.layouts[i];
        crate::SubSource::shared(self.files[l.file].clone(), l.offset, l.length)
    }
}

fn edc_scan(data: &dyn DataSource, job: &JobContext) -> Result<(u64, u64)> {
    let sectors = data.len()? / 2352;
    let mut bad = 0u64;
    let mut checked = 0u64;
    let mut buf = vec![0u8; 2352 * 64];
    let mut s = 0u64;
    while s < sectors {
        job.check_cancel()?;
        let n = (sectors - s).min(64);
        let b = &mut buf[..(n * 2352) as usize];
        data.read_exact_at(s * 2352, b)?;
        for sec in b.chunks_exact(2352) {
            if rawcd::detect_raw_mode(sec) == Some(TrackMode::Mode1Raw) {
                checked += 1;
                if !rawcd::mode1_edc_ok(sec) {
                    bad += 1;
                }
            }
        }
        s += n;
    }
    Ok((checked, bad))
}

impl PackageReader for CueReader {
    fn format(&self) -> FormatId {
        CUE
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(CUE, Platform::Generic, self.source.len()?);
        i.category = ContentCategory::DiscImage;
        i.title = self.sheet.title.clone().or_else(|| self.fs.as_ref().map(|f| f.volume.volume_id.clone()));
        i.field("tracks", self.layouts.len() as u64);
        let tracks: Vec<crate::MetaValue> = self
            .layouts
            .iter()
            .map(|l| crate::MetaValue::Text(format!("{:02} {} {} frames", l.number, l.mode.cue_name(), l.frames)))
            .collect();
        i.fields.insert("track_list".into(), crate::MetaValue::List(tracks));
        i.sizes.payload = Some(self.files.iter().map(|f| f.len().unwrap_or(0)).sum());
        if let Some(fs) = &self.fs {
            volume_fields(&mut i, fs);
        }
        i.warnings.extend(self.warnings.iter().cloned());
        i.limitations.push("subchannel data is not part of BIN/CUE and cannot be represented".into());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(CUE, level);
        r.pass(CheckLevel::Structure, "track layout", Some(format!("{} tracks fit their BIN files", self.layouts.len())));
        for (i, f) in self.files.iter().enumerate() {
            let len = f.len()?;
            let raw = self.layouts.iter().filter(|l| l.file == i).all(|l| l.mode.sector_size() == 2352);
            if raw && len % 2352 != 0 {
                r.warn(CheckLevel::Structure, "bin size", format!("{} is not a multiple of 2352 bytes", self.sheet.files[i].name));
            }
        }
        if level.wants_content() {
            for (i, l) in self.layouts.iter().enumerate() {
                if l.mode == TrackMode::Mode1Raw {
                    let (checked, bad) = edc_scan(self.track_data(i)?.as_ref(), job)?;
                    r.check(
                        CheckLevel::Content,
                        &format!("track {:02} EDC", l.number),
                        bad == 0,
                        format!("{bad} of {checked} Mode 1 sectors failed EDC"),
                    );
                } else {
                    r.skip(
                        CheckLevel::Content,
                        &format!("track {:02} EDC", l.number),
                        format!("{} sectors carry no Mode 1 EDC", l.mode.cue_name()),
                    );
                }
            }
        }
        r.skip(CheckLevel::Authenticity, "signature", "BIN/CUE has no signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = caps_for(CUE);
        if self.first_data_track().is_err() {
            c.block(Operation::Convert, "no data track with 2048-byte user data");
        }
        Ok(c)
    }
}

// ------------------------------------------------------------------------------------------
// Raw BIN reader
// ------------------------------------------------------------------------------------------

pub(crate) struct BinReader {
    source: SharedSource,
    mode: TrackMode,
    fs: Option<IsoFs>,
    table: NodeTable,
}

impl BinReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let mut first = [0u8; 2352];
        source.read_exact_at(0, &mut first)?;
        let mode = rawcd::detect_raw_mode(&first).ok_or_else(|| Error::malformed("first sector has no CD sync/mode"))?;
        let mut table = NodeTable::new();
        table.push(
            ContentNode::file(0, "track01.bin", source.len()?).kind(NodeKind::Track).meta("mode", mode.cue_name()),
            Some(source.clone()),
        );
        let cooked: SharedSource = Arc::new(CookedSource::new(source.clone(), mode)?);
        let fs = if iso9660::probe(cooked.as_ref()) { IsoFs::open(cooked, &ctx.limits).ok() } else { None };
        if let Some(f) = &fs {
            add_iso_nodes(&mut table, f, "data")?;
        }
        Ok(BinReader { source, mode, fs, table })
    }
    pub fn cooked(&self) -> Result<SharedSource> {
        Ok(Arc::new(CookedSource::new(self.source.clone(), self.mode)?))
    }
}

impl PackageReader for BinReader {
    fn format(&self) -> FormatId {
        BIN
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(BIN, Platform::Generic, self.source.len()?);
        i.category = ContentCategory::DiscImage;
        i.field("mode", self.mode.cue_name());
        i.field("sectors", self.source.len()? / 2352);
        if let Some(fs) = &self.fs {
            i.title = Some(fs.volume.volume_id.clone());
            volume_fields(&mut i, fs);
        }
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(BIN, level);
        let len = self.source.len()?;
        r.check(CheckLevel::Structure, "sector alignment", len % 2352 == 0, format!("{len} bytes"));
        if level.wants_content() {
            let (checked, bad) = edc_scan(self.source.as_ref(), job)?;
            if checked == 0 {
                r.skip(CheckLevel::Content, "EDC", "no Mode 1 sectors");
            } else {
                r.check(CheckLevel::Content, "EDC", bad == 0, format!("{bad} of {checked} Mode 1 sectors failed EDC"));
            }
        }
        r.skip(CheckLevel::Authenticity, "signature", "raw images have no signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps_for(BIN))
    }
}

// ------------------------------------------------------------------------------------------
// CHD reader
// ------------------------------------------------------------------------------------------

pub(crate) struct ChdReader {
    pub chd: Arc<ChdFile>,
    table: NodeTable,
    fs: Option<IsoFs>,
    warnings: Vec<String>,
}

/// Look for a parent CHD next to the child whose SHA-1 matches.
fn find_parent(source: &SharedSource, chd: &ChdFile, max_meta: u64) -> Option<Arc<ChdFile>> {
    let path = source.identity().path?;
    let dir = path.parent()?;
    for e in std::fs::read_dir(dir).ok()?.flatten().take(4096) {
        let p = e.path();
        if p == path || p.extension().and_then(|x| x.to_str()).map(|x| x.eq_ignore_ascii_case("chd")) != Some(true) {
            continue;
        }
        let s: SharedSource = match FileSource::open(&p) {
            Ok(f) => Arc::new(f),
            Err(_) => continue,
        };
        let mut h = [0u8; 124];
        if s.read_exact_at(0, &mut h).is_err() {
            continue;
        }
        if let Ok(hdr) = chd::ChdHeader::parse(&h) {
            if hdr.sha1 == chd.header.parent_sha1 {
                return ChdFile::open(s, max_meta).ok().map(Arc::new);
            }
        }
    }
    None
}

impl ChdReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let mut chd = ChdFile::open(source.clone(), ctx.limits.max_metadata)?;
        let mut warnings = Vec::new();
        if chd.header.has_parent() {
            match find_parent(&source, &chd, ctx.limits.max_metadata) {
                Some(p) => chd.set_parent(p)?,
                None => warnings.push(format!(
                    "parent CHD (sha1 {}) not found next to this file; hunks stored in the parent are unreadable",
                    crate::hex(&chd.header.parent_sha1)
                )),
            }
        }
        let unsupported = chd.unsupported_codecs();
        if !unsupported.is_empty() {
            warnings.push(format!("codecs not supported by this build: {}", unsupported.join(", ")));
        }
        let chd = Arc::new(chd);
        let mut table = NodeTable::new();
        let mut fs = None;
        let readable = !(chd.needs_parent() && !chd.has_parent_attached());
        let data_view: Option<SharedSource> = match chd.media {
            ChdMedia::Cd | ChdMedia::Gd => {
                for t in &chd.tracks {
                    let src: SharedSource = Arc::new(ChdTrackSource::new(chd.clone(), t));
                    let name = format!("track{:02}.{}", t.number, if t.mode.is_data() { "bin" } else { "raw" });
                    let n = ContentNode::file(0, name, src.len()?)
                        .kind(NodeKind::Track)
                        .meta("mode", t.mode_name.clone())
                        .meta("frames", t.frames);
                    table.push(n, if readable { Some(src) } else { None });
                }
                chd.tracks
                    .iter()
                    .find(|t| t.mode.user_data_offset().is_some())
                    .map(|t| -> Result<SharedSource> {
                        let s: SharedSource = Arc::new(ChdTrackSource::new(chd.clone(), t));
                        Ok(Arc::new(CookedSource::new(s, t.mode)?))
                    })
                    .transpose()?
            }
            _ => {
                let src: SharedSource = Arc::new(ChdSource::new(chd.clone()));
                let name = if chd.media == ChdMedia::Dvd { "image.iso" } else { "image.bin" };
                table.push(
                    ContentNode::file(0, name, chd.header.logical_bytes).kind(NodeKind::Track),
                    if readable { Some(src.clone()) } else { None },
                );
                Some(src)
            }
        };
        if let (Some(v), true) = (data_view, readable) {
            if iso9660::probe(v.as_ref()) {
                match IsoFs::open(v, &ctx.limits) {
                    Ok(f) => {
                        add_iso_nodes(&mut table, &f, "data")?;
                        fs = Some(f);
                    }
                    Err(e) => warnings.push(format!("filesystem unreadable: {e}")),
                }
            }
        }
        Ok(ChdReader { chd, table, fs, warnings })
    }
}

impl PackageReader for ChdReader {
    fn format(&self) -> FormatId {
        CHD
    }
    fn info(&self) -> Result<PackageInfo> {
        let h = &self.chd.header;
        let mut i = PackageInfo::new(CHD, Platform::Generic, self.chd.source().len()?);
        i.category = ContentCategory::DiscImage;
        i.sizes.uncompressed = Some(h.logical_bytes);
        i.field("version", h.version);
        i.field("media", format!("{:?}", self.chd.media).to_lowercase());
        i.field("hunk_bytes", h.hunk_bytes);
        i.field("unit_bytes", h.unit_bytes);
        i.field("hunks", h.hunk_count);
        i.field("compressors", h.compressor_names());
        i.field("sha1", crate::hex(&h.sha1));
        i.field("raw_sha1", crate::hex(&h.raw_sha1));
        if h.has_parent() {
            i.field("parent_sha1", crate::hex(&h.parent_sha1));
            i.field("parent_attached", self.chd.has_parent_attached());
        }
        let meta: Vec<crate::MetaValue> = self
            .chd
            .metadata
            .iter()
            .map(|m| {
                crate::MetaValue::Text(format!(
                    "{}: {}",
                    chd::tag_str(m.tag),
                    m.text.clone().unwrap_or_else(|| format!("{} bytes", m.data.len()))
                ))
            })
            .collect();
        i.fields.insert("metadata".into(), crate::MetaValue::List(meta));
        if let Some(fs) = &self.fs {
            i.title = Some(fs.volume.volume_id.clone());
            volume_fields(&mut i, fs);
        }
        i.warnings.extend(self.warnings.iter().cloned());
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(CHD, level);
        r.pass(CheckLevel::Structure, "header", Some(format!("CHD v{}", self.chd.header.version)));
        if self.chd.header.version >= 5 && self.chd.header.compressors[0] != 0 {
            r.pass(CheckLevel::Structure, "map CRC", Some("compressed map CRC-16 matches".into()));
        }
        for w in &self.warnings {
            r.warn(CheckLevel::Structure, "container", w.clone());
        }
        if level.wants_content() {
            let unsupported = self.chd.unsupported_codecs();
            if !unsupported.is_empty() {
                r.skip(CheckLevel::Content, "hunk data", format!("codecs unsupported by this build: {}", unsupported.join(", ")));
            } else if self.chd.needs_parent() && !self.chd.has_parent_attached() {
                r.skip(CheckLevel::Content, "hunk data", "parent CHD not available");
            } else {
                match chd::writer::compute_sha1s(&self.chd, job) {
                    Ok((raw, sha)) => {
                        if self.chd.header.version >= 4 && self.chd.header.raw_sha1 != [0; 20] {
                            r.check(CheckLevel::Content, "raw SHA-1", raw == self.chd.header.raw_sha1, crate::hex(&raw));
                        }
                        if self.chd.header.version >= 5 {
                            r.check(CheckLevel::Content, "overall SHA-1", sha == self.chd.header.sha1, crate::hex(&sha));
                        } else {
                            r.skip(CheckLevel::Content, "overall SHA-1", "v3/v4 overall hash recomputation is not implemented");
                        }
                        r.pass(CheckLevel::Content, "hunk CRCs", Some(format!("{} hunks decoded", self.chd.header.hunk_count)));
                    }
                    Err(e) if e.code() == crate::ErrorCode::IntegrityMismatch || e.code() == crate::ErrorCode::CodecFailure => {
                        r.fail(CheckLevel::Content, "hunk data", e.to_string())
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        r.skip(CheckLevel::Authenticity, "signature", "CHD carries hashes, not signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = caps_for(CHD);
        let unsupported = self.chd.unsupported_codecs();
        if !unsupported.is_empty() {
            let m = format!("codecs not supported: {}", unsupported.join(", "));
            c.needs(Operation::Extract, "codec", &m);
            c.needs(Operation::Decompress, "codec", &m);
            c.needs(Operation::Verify, "codec", &m);
        }
        if self.chd.needs_parent() && !self.chd.has_parent_attached() {
            c.needs(Operation::Extract, "parent CHD", "parent CHD not found");
            c.needs(Operation::Decompress, "parent CHD", "parent CHD not found");
        }
        Ok(c)
    }
}

// ------------------------------------------------------------------------------------------
// Conversions
// ------------------------------------------------------------------------------------------

fn plan_base(req: &ConvertRequest, op: Operation, edge: &ConversionEdge, category: &str) -> Result<TransformPlan> {
    let mut p = TransformPlan::new(op);
    p.inputs.push(PlanInput::capture(&req.input, "source", req.from)?);
    check_output_target(&req.output, &crate::IoPolicy::default(), &p.input_paths()).or_else(|e| {
        if e.code() == crate::ErrorCode::ConflictingOutput && req.option("overwrite") == Some("true") { Ok(()) } else { Err(e) }
    })?;
    p.outputs.push(PlanOutput {
        path: req.output.clone(),
        format: Some(req.to),
        kind: "file",
        category: category.into(),
        estimated_size: None,
    });
    p.guarantees = edge.guarantees.clone();
    p.steps.push(edge.note.clone());
    Ok(p)
}

fn plan_conversion(req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
    let edge = conversions()
        .into_iter()
        .find(|e| e.from == req.from && e.to == req.to)
        .ok_or_else(|| Error::unsupported("undeclared conversion"))?;
    let op = match edge.kind {
        ConversionKind::Compress => Operation::Compress,
        ConversionKind::Decompress => Operation::Decompress,
        _ => Operation::Convert,
    };
    let ctx = req.ctx.clone();
    match (req.from, req.to) {
        (ISO9660, CHD) => {
            let mut plan = plan_base(&req, op, &edge, "disc image")?;
            let len = req.source.len()?;
            if len % 2048 != 0 {
                return Err(Error::invalid_arg("ISO length is not a multiple of 2048"));
            }
            plan.outputs[0].estimated_size = Some(len / 2);
            let src = req.source.clone();
            Ok(ClosurePlan::new(
                plan,
                Box::new(move |plan, job| write_chd_file(chd::writer::ChdInput::Dvd(src), &plan.outputs[0].path, plan, job)),
            ))
        }
        (CUE, CHD) => {
            let r = CueReader::open(req.source.clone(), &ctx)?;
            let mut plan = plan_base(&req, op, &edge, "disc image")?;
            plan.warnings.push("subchannel data is not present in BIN/CUE and is stored as zeros".into());
            let mut tracks = Vec::new();
            for (i, l) in r.layouts.iter().enumerate() {
                if l.mode == TrackMode::Cdg {
                    return Err(Error::unsupported("CDG tracks are not supported by the CHD writer"));
                }
                let t = &r.sheet.tracks[i];
                tracks.push(chd::writer::CdTrackInput {
                    mode: l.mode,
                    data: r.track_data(i)?,
                    stored_pregap: l.stored_pregap_frames,
                    unstored_pregap: t.pregap_frames,
                    postgap: t.postgap_frames,
                });
            }
            for f in &r.sheet.files {
                if let Ok(p) = sibling(&req.source, &f.name) {
                    plan.inputs.push(PlanInput::capture(&p, "track file", BIN)?);
                }
            }
            Ok(ClosurePlan::new(
                plan,
                Box::new(move |plan, job| write_chd_file(chd::writer::ChdInput::Cd(tracks), &plan.outputs[0].path, plan, job)),
            ))
        }
        (CHD, ISO9660) => {
            let r = ChdReader::open(req.source.clone(), &ctx)?;
            if matches!(r.chd.media, ChdMedia::Cd | ChdMedia::Gd) {
                return Err(Error::new(crate::ErrorCode::InvalidOutputFormat, "this CHD holds a CD; decompress to disc.cue instead"));
            }
            if !r.chd.unsupported_codecs().is_empty() {
                return Err(Error::unsupported(format!("CHD uses unsupported codecs: {}", r.chd.unsupported_codecs().join(", "))));
            }
            let plan = plan_base(&req, op, &edge, "disc image")?;
            let chd = r.chd.clone();
            Ok(ClosurePlan::new(
                plan,
                Box::new(move |plan, job| {
                    let src = ChdSource::new(chd.clone());
                    let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(src.len()?));
                    let mut h = crate::crypto::StreamHasher::new(crate::crypto::HashAlg::Sha1);
                    let mut tee = Tee { a: &mut f, b: &mut h };
                    crate::copy_all(&src, &mut tee, &mut p)?;
                    let sha = h.finish();
                    if chd.header.raw_sha1 != [0; 20] && sha != chd.header.raw_sha1 {
                        return Err(Error::integrity("decoded data does not match the CHD raw SHA-1"));
                    }
                    let out = f.finish()?;
                    let mut rep = OperationReport::new(plan.operation, plan.input_paths());
                    rep.outputs.push(OutputRecord::from_path(&out, Some(ISO9660), &plan.guarantees)?);
                    rep.metadata.insert("raw_sha1".into(), crate::hex(&sha).into());
                    Ok(rep)
                }),
            ))
        }
        (CHD, CUE) => {
            let r = ChdReader::open(req.source.clone(), &ctx)?;
            if !matches!(r.chd.media, ChdMedia::Cd) {
                return Err(Error::new(crate::ErrorCode::InvalidOutputFormat, "this CHD is not a CD image"));
            }
            if !r.chd.unsupported_codecs().is_empty() {
                return Err(Error::unsupported(format!("CHD uses unsupported codecs: {}", r.chd.unsupported_codecs().join(", "))));
            }
            let mut plan = plan_base(&req, op, &edge, "cue sheet + bin")?;
            let bin = req.output.with_extension("bin");
            check_output_target(&bin, &crate::IoPolicy::default(), &plan.input_paths()).ok();
            plan.outputs.push(PlanOutput {
                path: bin,
                format: Some(BIN),
                kind: "file",
                category: "track data".into(),
                estimated_size: None,
            });
            let chd = r.chd.clone();
            Ok(ClosurePlan::new(plan, Box::new(move |plan, job| chd_to_cue(&chd, &plan.outputs[0].path, &plan.outputs[1].path, plan, job))))
        }
        (BIN, ISO9660) | (CUE, ISO9660) => {
            let cooked = if req.from == BIN {
                BinReader::open(req.source.clone(), &ctx)?.cooked()?
            } else {
                CueReader::open(req.source.clone(), &ctx)?.first_data_track()?
            };
            let mut plan = plan_base(&req, op, &edge, "disc image")?;
            plan.warnings.push(
                "sync, headers, subheaders and EDC/ECC are not preserved; the raw disc cannot be reconstructed from the output".into(),
            );
            Ok(ClosurePlan::new(
                plan,
                Box::new(move |plan, job| {
                    let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(cooked.len()?));
                    crate::copy_all(cooked.as_ref(), &mut f, &mut p)?;
                    let out = f.finish()?;
                    let mut rep = OperationReport::new(plan.operation, plan.input_paths());
                    rep.outputs.push(OutputRecord::from_path(&out, Some(ISO9660), &plan.guarantees)?);
                    Ok(rep)
                }),
            ))
        }
        _ => Err(Error::unsupported("undeclared conversion")),
    }
}

struct Tee<'a> {
    a: &'a mut dyn std::io::Write,
    b: &'a mut dyn std::io::Write,
}

impl std::io::Write for Tee<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.a.write_all(buf)?;
        self.b.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.a.flush()?;
        self.b.flush()
    }
}

fn write_chd_file(input: chd::writer::ChdInput, out: &Path, plan: &TransformPlan, job: &JobContext) -> Result<OperationReport> {
    let mut f = AtomicFile::create(out, &job.io, &plan.input_paths())?;
    let summary = chd::writer::write_chd(&input, &chd::writer::ChdWriteOptions::default(), &mut f, job)?;
    // Verify the promised guarantee by decoding the written file before renaming.
    job.progress(crate::Phase::Verifying, 0, None);
    f.flush_for_verify()?;
    let written: SharedSource = Arc::new(FileSource::open(f.temp_path())?);
    let chd = Arc::new(ChdFile::open(written, job.limits.max_metadata)?);
    let (raw, sha) = chd::writer::compute_sha1s(&chd, job)?;
    if crate::hex(&raw) != summary.raw_sha1 || crate::hex(&sha) != summary.sha1 {
        return Err(Error::integrity("written CHD failed read-back verification"));
    }
    drop(chd);
    let path = f.finish()?;
    let mut rep = OperationReport::new(plan.operation, plan.input_paths());
    rep.outputs.push(OutputRecord::from_path(&path, Some(CHD), &plan.guarantees)?);
    rep.metadata.insert("hunks".into(), (summary.hunks as u64).into());
    rep.metadata.insert("compressors".into(), summary.compressors.clone().into());
    rep.metadata.insert("raw_sha1".into(), summary.raw_sha1.clone().into());
    rep.metadata.insert("sha1".into(), summary.sha1.clone().into());
    let mut v = VerifyReport::new(CHD, VerifyLevel::Content);
    v.pass(CheckLevel::Reproducibility, "read-back SHA-1", Some(summary.raw_sha1));
    rep.verification = Some(v);
    Ok(rep)
}

fn chd_to_cue(chd: &Arc<ChdFile>, cue_path: &Path, bin_path: &Path, plan: &TransformPlan, job: &JobContext) -> Result<OperationReport> {
    let bin_name = bin_path.file_name().and_then(|s| s.to_str()).ok_or_else(|| Error::invalid_arg("bad output name"))?.to_string();
    let mut bin = AtomicFile::create(bin_path, &job.io, &plan.input_paths())?;
    let mut sheet = CueSheet::default();
    sheet.files.push(cue::CueFile { name: bin_name, kind: "BINARY".into() });
    let total: u64 = chd.tracks.iter().map(|t| t.frames * t.mode.sector_size()).sum();
    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(total));
    let mut frame_pos = 0u64;
    let mut byte_pos = 0u64;
    for t in &chd.tracks {
        let src = ChdTrackSource::new(chd.clone(), t);
        crate::copy_all(&src, &mut bin, &mut p)?;
        let mut indexes = Vec::new();
        let ss = t.mode.sector_size();
        let start = byte_pos / ss.max(1);
        let _ = frame_pos;
        if t.pregap_stored() && t.pregap > 0 {
            indexes.push(cue::CueIndex { number: 0, frames: start });
            indexes.push(cue::CueIndex { number: 1, frames: start + t.pregap });
        } else {
            indexes.push(cue::CueIndex { number: 1, frames: start });
        }
        sheet.tracks.push(cue::CueTrack {
            number: t.number as u8,
            mode: t.mode,
            file: 0,
            indexes,
            pregap_frames: if t.pregap_stored() { 0 } else { t.pregap },
            postgap_frames: t.postgap,
            flags: vec![],
            title: None,
        });
        frame_pos += t.frames;
        byte_pos += t.frames * ss;
    }
    if chd.tracks.iter().any(|t| t.mode.sector_size() != chd.tracks[0].mode.sector_size()) {
        return Err(Error::unsupported("mixed sector sizes cannot share a single BIN file"));
    }
    let bin_out = bin.finish()?;
    let mut cuef = AtomicFile::create(cue_path, &job.io, &plan.input_paths())?;
    std::io::Write::write_all(&mut cuef, sheet.render().as_bytes())?;
    let cue_out = cuef.finish()?;
    let mut rep = OperationReport::new(plan.operation, plan.input_paths());
    rep.outputs.push(OutputRecord::from_path(&cue_out, Some(CUE), &plan.guarantees)?);
    rep.outputs.push(OutputRecord::from_path(&bin_out, Some(BIN), &plan.guarantees)?);
    Ok(rep)
}

/// Build an ISO9660 image from a directory tree (the `repack` operation for `disc.iso9660`).
pub fn plan_repack_iso(dir: &Path, output: &Path, volume_id: &str, policy: &crate::IoPolicy) -> Result<Box<dyn PlannedOperation>> {
    if !dir.is_dir() {
        return Err(Error::invalid_arg(format!("{} is not a directory", dir.display())));
    }
    check_output_target(output, policy, &[])?;
    let files = collect_dir(dir, &ResourceLimits::default())?;
    let mut plan = TransformPlan::new(Operation::Repack);
    for (_, p) in &files {
        plan.inputs.push(PlanInput::capture(p, "file", ISO9660)?);
    }
    let est: u64 = plan.inputs.iter().map(|i| i.identity.len.div_ceil(2048) * 2048).sum();
    plan.outputs.push(PlanOutput {
        path: output.to_path_buf(),
        format: Some(ISO9660),
        kind: "file",
        category: "disc image".into(),
        estimated_size: Some(est + 64 * 2048),
    });
    plan.guarantees = vec![OutputGuarantee::ContainerValid, OutputGuarantee::ContentPreserved, OutputGuarantee::CompatibilityUnverified];
    plan.steps.push(format!("{} files, relaxed ISO9660 names, fixed timestamps", files.len()));
    let vid = volume_id.to_string();
    Ok(ClosurePlan::new(
        plan,
        Box::new(move |plan, job| {
            let mut b = iso9660::IsoBuilder::new(&vid);
            for (rel, p) in &files {
                b.add_file(rel, Arc::new(FileSource::open(p)?))?;
            }
            let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &[])?;
            b.write(&mut f, job)?;
            f.flush_for_verify()?;
            let check: SharedSource = Arc::new(FileSource::open(f.temp_path())?);
            let fs = IsoFs::open(check, &job.limits)?;
            if fs.entries().iter().filter(|e| !e.is_dir).count() != files.len() {
                return Err(Error::integrity("rebuilt ISO does not list every input file"));
            }
            let out = f.finish()?;
            let mut rep = OperationReport::new(Operation::Repack, plan.input_paths());
            rep.outputs.push(OutputRecord::from_path(&out, Some(ISO9660), &plan.guarantees)?);
            Ok(rep)
        }),
    ))
}

/// Recursively collect regular files under `dir` as (relative path, absolute path), rejecting symlinks.
pub(crate) fn collect_dir(dir: &Path, limits: &ResourceLimits) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new(), 0u32)];
    while let Some((d, rel, depth)) = stack.pop() {
        if depth > limits.max_depth {
            return Err(Error::limit("directory nesting exceeds limit"));
        }
        let mut items: Vec<_> = std::fs::read_dir(&d)?.collect::<std::io::Result<Vec<_>>>()?;
        items.sort_by_key(|e| e.file_name());
        for e in items {
            let ft = e.file_type()?;
            let name = e.file_name().to_string_lossy().into_owned();
            let r = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            if ft.is_symlink() {
                return Err(Error::unsafe_path(format!("symlink {r} is not followed")));
            } else if ft.is_dir() {
                stack.push((e.path(), r, depth + 1));
            } else if ft.is_file() {
                out.push((r, e.path()));
            }
            if out.len() as u64 > limits.max_entries {
                return Err(Error::limit("too many files"));
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, Registry};

    #[test]
    fn probe_and_open_iso() {
        let mut b = iso9660::IsoBuilder::new("VOL");
        b.add_file("X/Y.BIN", Arc::new(MemorySource::new(vec![1u8; 3000]))).unwrap();
        let mut img = Vec::new();
        b.write(&mut img, &JobContext::default()).unwrap();
        let reg = Registry::new().with(DiscBackend);
        let src: SharedSource = Arc::new(MemorySource::new(img));
        let pr = reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap();
        assert_eq!(pr.format, Some(ISO9660));
        let r = reg.open(src, &OpenContext::default()).unwrap();
        let entries: Vec<_> = r.entries().unwrap().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        let v = r.verify(VerifyLevel::All, &JobContext::default()).unwrap();
        assert!(v.no_failures());
    }

    #[test]
    fn raw_bin_detects_fs() {
        let mut b = iso9660::IsoBuilder::new("RAW");
        b.add_file("A.TXT", Arc::new(MemorySource::new(b"data".to_vec()))).unwrap();
        let mut img = Vec::new();
        b.write(&mut img, &JobContext::default()).unwrap();
        let mut raw = Vec::new();
        for (i, s) in img.chunks(2048).enumerate() {
            raw.extend(rawcd::make_mode1_sector(i as u32, s.try_into().unwrap()));
        }
        let reg = Registry::new().with(DiscBackend);
        let src: SharedSource = Arc::new(MemorySource::new(raw));
        assert_eq!(reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap().format, Some(BIN));
        let r = reg.open(src, &OpenContext::default()).unwrap();
        assert!(r.entries().unwrap().any(|e| e.unwrap().path == "data/A.TXT"));
        let v = r.verify(VerifyLevel::Content, &JobContext::default()).unwrap();
        assert!(v.no_failures(), "{:?}", v.checks);
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::disc::chd::flac::{decode_chd_flac, decode_stereo16};
    pub use crate::disc::chd::huffman::decode_huff8;
    pub use crate::disc::chd::writer::{ChdInput, write_chd};
    pub use crate::disc::cue::CueSheet;
    pub use crate::disc::iso9660::IsoBuilder;
    pub use crate::disc::rawcd::make_mode1_sector;
}
