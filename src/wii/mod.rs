//! # `romux::wii`
//!
//! GameCube and Wii formats: GameCube disc images (GCM/ISO), Wii disc images and
//! partitions, WBFS, WIA/RVZ, WAD and U8 archives. Nintendo disc filesystems are distinct
//! from ISO9660 and are never treated as such.
//!
//! Wii partition data on discs and WBFS is encrypted; listing/extracting/hash-verifying it requires the
//! user to supply `wii_common_key` (or `wii_korean_key` / `vwii_common_key`).

pub(crate) mod disc;
pub(crate) mod junk;
pub(crate) mod partition;
pub(crate) mod rvz;
pub(crate) mod rvz_reader;
pub(crate) mod u8arc;
pub(crate) mod wad;
pub(crate) mod wbfs;
pub(crate) use rvz_reader::WiiRvzReader;

use crate::{
    AtomicFile, Backend, CapabilitySet, CheckLevel, ClosurePlan, Confidence, ContentCategory, ContentNode, ConversionEdge, ConversionKind,
    ConvertRequest, DataSource, EntryId, EntryIter, Error, ErrorCode, FileSource, FormatDescriptor, FormatId, IoPolicy, JobContext,
    KeyProvider, NodeKind, NodeTable, OpenContext, Operation, OperationReport, OutputGuarantee, OutputRecord, PackageInfo, PackageReader,
    PlanInput, PlanOutput, PlannedOperation, Platform, ProbeEvidence, ProbeLimits, Requirement, Result, SharedSource, SubSource, Support,
    TransformPlan, VerifyLevel, VerifyReport,
};
use std::path::Path;
use std::sync::Arc;

pub const GC_ISO: FormatId = FormatId("gamecube.iso");
pub const WII_ISO: FormatId = FormatId("wii.iso");
pub const WII_WBFS: FormatId = FormatId("wii.wbfs");
pub const WII_RVZ: FormatId = FormatId("wii.rvz");
pub const WII_WIA: FormatId = FormatId("wii.wia");
pub const WII_WAD: FormatId = FormatId("wii.wad");
pub const WII_U8: FormatId = FormatId("wii.u8");

#[derive(Default)]
pub struct WiiBackend;

pub(crate) fn descriptors() -> Vec<FormatDescriptor> {
    use Operation::*;
    use Support::*;
    let ck = || vec![Requirement::KeyMaterial("wii_common_key".into())];
    vec![
        FormatDescriptor::new(GC_ISO, Platform::GameCube, "GameCube disc", &["iso", "gcm"], "GameCube disc image (GCM)")
            .op(Probe, Supported, "GameCube magic 0xC2339F3D at 0x1C")
            .op(Inspect, Supported, "disc header (game ID, maker, title, region)")
            .op(List, Supported, "sys/ files and FST tree")
            .op(Extract, Supported, "sys/boot.bin, bi2.bin, apploader.img, main.dol, fst.bin and files/")
            .op(Verify, Supported, "header, FST bounds; GameCube discs carry no content hashes")
            .op(Compress, Supported, "to RVZ (zstd groups, junk packed), byte-identical")
            .op(Convert, Supported, "to RVZ"),
        FormatDescriptor::new(WII_ISO, Platform::Wii, "Wii disc", &["iso", "wii"], "Wii disc image with encrypted partitions")
            .op(Probe, Supported, "Wii magic 0x5D1C9EA3 at 0x18 and partition table")
            .op(Inspect, Supported, "disc header, partitions, title IDs, region")
            .op(List, Conditional, "partition tickets/TMDs always; partition files need the common key")
            .op_req(Extract, Conditional, "decrypted partition sys/ and files/", ck())
            .op_req(Verify, Conditional, "H3 table vs TMD always; H0–H3 cluster hashes with the common key", ck())
            .op(Compress, Supported, "to WBFS (all-zero blocks omitted); to RVZ with the common key (wii_common_key)")
            .op(Convert, Supported, "to WBFS; to RVZ with the common key")
            .op(Bundle, Unsupported, "")
            .op(ApplyUpdate, Unsupported, "Wii discs carry system updates, not title patches"),
        FormatDescriptor::new(WII_WBFS, Platform::Wii, "WBFS", &["wbfs"], "sparse Wii disc container")
            .op(Probe, Supported, "WBFS magic and sector sizes")
            .op(Inspect, Supported, "disc header copy, used blocks")
            .op(List, Supported, "reconstructed disc (and its contents, see wii.iso)")
            .op(Extract, Supported, "reconstructed disc image")
            .op(Verify, Supported, "block table bounds")
            .op(Decompress, Supported, "to ISO; omitted blocks become zeros (original filler may not be recoverable)")
            .op(Compress, Conditional, "to RVZ with the common key (wii_common_key)"),
        FormatDescriptor::new(WII_RVZ, Platform::Wii, "RVZ", &["rvz"], "Dolphin RVZ compressed disc (GameCube or Wii)")
            .op(Probe, Supported, "RVZ magic, header hashes")
            .op(Inspect, Supported, "headers, compression, disc header")
            .op(List, Supported, "GameCube files; Wii partition files read from the stored decrypted data (no key needed)")
            .op(Extract, Supported, "as list")
            .op(Verify, Supported, "header SHA-1s; GameCube: every group decodes; Wii: regenerated hash trees checked against each H3 table")
            .op(Decompress, Supported, "GameCube images restore byte-identically (incl. LFG junk); Wii partitions are re-encrypted with the stored title key and hash trees regenerated"),
        FormatDescriptor::new(WII_WIA, Platform::Wii, "WIA", &["wia"], "WIA compressed disc")
            .op(Probe, Supported, "WIA magic")
            .op(Inspect, Supported, "headers")
            .op(Decompress, Conditional, "none/LZMA/LZMA2 compression; bzip2 and purge unsupported"),
        FormatDescriptor::new(WII_WAD, Platform::Wii, "WAD", &["wad"], "installable title archive")
            .op(Probe, Supported, "header size 0x20 and type Is/ib/Bk")
            .op(Inspect, Supported, "title ID, version, contents")
            .op(List, Supported, "cert, ticket, TMD, contents, footer")
            .op(Extract, Supported, "sections as stored; decrypted contents with the common key")
            .op_req(Verify, Conditional, "content SHA-1 needs the common key", ck()),
        FormatDescriptor::new(WII_U8, Platform::Wii, "U8", &["arc", "u8", "app"], "U8 archive")
            .op(Probe, Supported, "0x55AA382D magic")
            .op(Inspect, Supported, "")
            .op(List, Supported, "")
            .op(Extract, Supported, "")
            .op(Verify, Supported, "node table and bounds")
            .op(Repack, Supported, "deterministic archive from a directory"),
    ]
}

fn caps(f: FormatId) -> CapabilitySet {
    CapabilitySet::from_descriptor(&descriptors().into_iter().find(|d| d.id == f).expect("descriptor"))
}

fn disc_magics(s: &dyn DataSource) -> (bool, bool) {
    let mut h = [0u8; 0x20];
    if s.read_exact_at(0, &mut h).is_err() {
        return (false, false);
    }
    (
        u32::from_be_bytes([h[0x18], h[0x19], h[0x1A], h[0x1B]]) == disc::WII_MAGIC,
        u32::from_be_bytes([h[0x1C], h[0x1D], h[0x1E], h[0x1F]]) == disc::GC_MAGIC,
    )
}

impl Backend for WiiBackend {
    fn name(&self) -> &'static str {
        "wii"
    }
    fn platform(&self) -> Platform {
        Platform::Wii
    }
    fn formats(&self) -> Vec<FormatDescriptor> {
        descriptors()
    }
    fn conversions(&self) -> Vec<ConversionEdge> {
        use OutputGuarantee::*;
        vec![
            ConversionEdge::new(GC_ISO, WII_RVZ, ConversionKind::Compress, Support::Supported, "zstd groups with junk packing, verified by read-back")
                .guarantees(&[ByteIdenticalRoundTrip, ContainerValid]),
            ConversionEdge::new(WII_RVZ, GC_ISO, ConversionKind::Decompress, Support::Conditional, "GameCube RVZ only")
                .guarantees(&[ByteIdenticalRoundTrip]),
            ConversionEdge::new(
                WII_RVZ,
                WII_ISO,
                ConversionKind::Decompress,
                Support::Supported,
                "partitions re-encrypted with the stored title key; hash trees regenerated and checked against each H3 table",
            )
            .guarantees(&[ContentPreserved, ContainerValid]),
            ConversionEdge::new(
                WII_WIA,
                WII_ISO,
                ConversionKind::Decompress,
                Support::Conditional,
                "Wii WIA with supported codecs; as RVZ",
            )
            .guarantees(&[ContentPreserved, ContainerValid]),
            ConversionEdge::new(WII_WIA, GC_ISO, ConversionKind::Decompress, Support::Conditional, "GameCube WIA with supported codecs")
                .guarantees(&[ByteIdenticalRoundTrip]),
            ConversionEdge::new(
                WII_ISO,
                WII_RVZ,
                ConversionKind::Compress,
                Support::Conditional,
                "needs the common key the ticket names (wii_common_key, wii_korean_key or vwii_common_key); partitions stored decrypted, 2 MiB zstd groups, verified by read-back",
            )
            .guarantees(&[ByteIdenticalRoundTrip, ContainerValid, CompatibilityUnverified]),
            ConversionEdge::new(
                WII_WBFS,
                WII_RVZ,
                ConversionKind::Compress,
                Support::Conditional,
                "as Wii ISO to RVZ, reading the WBFS directly; omitted blocks become zeros",
            )
            .guarantees(&[ContentPreserved, ContainerValid, LayoutNotPreserved, CompatibilityUnverified]),
            ConversionEdge::new(WII_ISO, WII_WBFS, ConversionKind::Compress, Support::Supported, "all-zero 2 MiB blocks omitted")
                .guarantees(&[ContentPreserved, ContainerValid]),
            ConversionEdge::new(
                WII_WBFS,
                WII_ISO,
                ConversionKind::Decompress,
                Support::Supported,
                "omitted blocks restored as zeros; image padded to a layer size",
            )
            .guarantees(&[ContentPreserved, LayoutNotPreserved]),
        ]
    }
    fn probe(&self, s: &dyn DataSource, _l: &ProbeLimits) -> Result<Vec<ProbeEvidence>> {
        let mut out = Vec::new();
        let len = s.len()?;
        if len >= 0x440 {
            let (wii, gc) = disc_magics(s);
            if wii {
                let mut ev = ProbeEvidence::new(WII_ISO, Confidence::Medium).matched("Wii disc magic");
                if partition::read_partitions(s).map(|p| !p.is_empty()).unwrap_or(false) {
                    ev.confidence = Confidence::High;
                    ev = ev.matched("partition table valid");
                }
                out.push(ev);
            } else if gc {
                out.push(ProbeEvidence::new(GC_ISO, Confidence::High).matched("GameCube disc magic"));
            }
        }
        if let Some(rvz) = rvz::probe(s) {
            match rvz::WiaHeader::parse(s) {
                Ok(h) => out.push(ProbeEvidence::new(if rvz { WII_RVZ } else { WII_WIA }, Confidence::Certain).matched(format!(
                    "{} magic, header SHA-1s valid, {} disc",
                    if rvz { "RVZ" } else { "WIA" },
                    if h.is_wii() { "Wii" } else { "GameCube" }
                ))),
                Err(e) => {
                    out.push(ProbeEvidence::new(if rvz { WII_RVZ } else { WII_WIA }, Confidence::Low).matched("magic").warn(e.to_string()))
                }
            }
        }
        if len >= 0x200 && wbfs::WbfsHeader::parse(s).is_ok() {
            out.push(ProbeEvidence::new(WII_WBFS, Confidence::High).matched("WBFS magic and sector sizes"));
        }
        if wad::probe(s) {
            out.push(ProbeEvidence::new(WII_WAD, Confidence::High).matched("WAD header"));
        }
        if u8arc::probe(s) {
            out.push(ProbeEvidence::new(WII_U8, Confidence::High).matched("U8 magic"));
        }
        Ok(out)
    }
    fn open(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        match format {
            GC_ISO => Ok(Box::new(GcReader::open(source.clone(), source, GC_ISO, ctx)?)),
            WII_ISO => Ok(Box::new(WiiDiscReader::open(source.clone(), source, WII_ISO, ctx)?)),
            WII_WBFS => {
                let d: SharedSource = Arc::new(wbfs::WbfsDisc::open(source.clone(), 0)?);
                Ok(Box::new(WiiDiscReader::open(source, d, WII_WBFS, ctx)?))
            }
            WII_RVZ | WII_WIA => {
                let h = rvz::WiaHeader::parse(source.as_ref())?;
                if h.is_wii() {
                    Ok(Box::new(WiiRvzReader::open(source, format, ctx)?))
                } else {
                    let d: SharedSource = Arc::new(rvz::WiaSource::open(source.clone())?);
                    Ok(Box::new(GcReader::open(source, d, format, ctx)?))
                }
            }
            WII_WAD => Ok(Box::new(WadReader::open(source, ctx)?)),
            WII_U8 => Ok(Box::new(U8Reader::open(source, ctx)?)),
            _ => Err(Error::unsupported(format!("wii backend cannot open {format}"))),
        }
    }
    fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let mut plan = TransformPlan::new(match req.to {
            WII_RVZ | WII_WBFS => Operation::Compress,
            _ => Operation::Decompress,
        });
        plan.inputs.push(PlanInput::capture(&req.input, "source", req.from)?);
        crate::check_output_target(&req.output, &IoPolicy::default(), &plan.input_paths())
            .or_else(|e| if e.code() == ErrorCode::ConflictingOutput { Ok(()) } else { Err(e) })?;
        let edge = self
            .conversions()
            .into_iter()
            .find(|e| e.from == req.from && e.to == req.to)
            .ok_or_else(|| Error::unsupported("undeclared conversion"))?;
        plan.guarantees = edge.guarantees.clone();
        plan.outputs.push(PlanOutput {
            path: req.output.clone(),
            format: Some(req.to),
            kind: "file",
            category: "disc image".into(),
            estimated_size: None,
        });
        let src = req.source.clone();
        let (from, to) = (req.from, req.to);
        let level = req.option_u64("level")?.unwrap_or(19) as i32;
        let chunk = req.option_u64("chunk")?.unwrap_or(0x20000) as u32;
        let restored: Option<SharedSource> = match from {
            WII_RVZ | WII_WIA => Some(Arc::new(rvz::WiaSource::open(src.clone())?)),
            WII_WBFS => Some(Arc::new(wbfs::WbfsDisc::open(src.clone(), 0)?)),
            _ => None,
        };
        // Wii → RVZ: the disc view to encode (the WBFS's restored image or the ISO itself).
        let wii_rvz: Option<SharedSource> = match (from, to) {
            (WII_ISO, WII_RVZ) => Some(src.clone()),
            (WII_WBFS, WII_RVZ) => restored.clone(),
            _ => None,
        };
        let keys = req.ctx.keys.clone();
        if let Some(view) = &wii_rvz {
            if req.option_u64("chunk")?.is_some_and(|c| c != rvz::WII_CHUNK as u64) {
                return Err(Error::invalid_arg(format!("Wii RVZ output uses a fixed 0x{:x}-byte chunk size", rvz::WII_CHUNK)));
            }
            // Fail at planning time (and in --dry-run) when a title key cannot be decrypted.
            let parts = partition::read_partitions(view.as_ref())?;
            for p in &parts {
                partition::titlekey(p, keys.as_ref())
                    .map_err(|e| e.with_suggestion("pass a key file with wii_common_key using --key-file"))?;
            }
            plan.restrictions.push(format!("{} partitions stored decrypted, junk packed as LFG seeds", parts.len()));
        }
        let wii_level = req.option_u64("level")?.unwrap_or(5) as i32;
        if to == WII_WBFS && src.len()? != wbfs::SINGLE_LAYER && src.len()? != wbfs::WII_SECTORS_DL * wbfs::WII_SECTOR {
            plan.warnings.push("input is not a full single/dual-layer image; restoring from WBFS pads it to a layer size".into());
        }
        Ok(ClosurePlan::new(
            plan,
            Box::new(move |plan, job| {
                let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &plan.input_paths())?;
                let mut rep = OperationReport::new(plan.operation, plan.input_paths());
                match to {
                    WII_RVZ => {
                        let input = match &wii_rvz {
                            Some(view) => {
                                rvz::write_rvz_wii(view, keys.as_ref(), &mut f, wii_level, job)?;
                                view.clone()
                            }
                            None => {
                                rvz::write_rvz_gc(src.as_ref(), &mut f, level, chunk, job)?;
                                src.clone()
                            }
                        };
                        f.flush_for_verify()?;
                        let back = rvz::WiaSource::open(Arc::new(FileSource::open(f.temp_path())?))?;
                        let a = crate::crypto::hash_range(input.as_ref(), 0, input.len()?, crate::crypto::HashAlg::Sha1, None)?;
                        let b = crate::crypto::hash_range(&back, 0, back.len()?, crate::crypto::HashAlg::Sha1, None)?;
                        if a != b {
                            return Err(Error::new(ErrorCode::VerificationFailed, "RVZ does not restore the input"));
                        }
                        rep.metadata.insert("sha1".into(), crate::hex(&a).into());
                    }
                    WII_WBFS => {
                        let (blocks, used) = wbfs::write(src.as_ref(), &mut f, job)?;
                        rep.metadata.insert("blocks".into(), blocks.into());
                        rep.metadata.insert("stored_blocks".into(), used.into());
                    }
                    _ => {
                        if to == WII_ISO && matches!(from, WII_RVZ | WII_WIA) {
                            // Check the regenerated hash trees against every partition's H3
                            // table before committing to a multi-gigabyte write.
                            let w = rvz::WiaSource::open(src.clone())?;
                            let mut groups = 0u64;
                            for p in partition::read_partitions(&w)? {
                                let Some(i) = w.parts.iter().position(|e| e.data_offset() == p.abs_data()) else { continue };
                                let h3 = crate::read_vec(&w, p.offset + p.h3_offset, partition::H3_SIZE, partition::H3_SIZE)?;
                                let (n, bad) = w.verify_partition(i, &h3, job)?;
                                if bad != 0 {
                                    return Err(Error::new(
                                        ErrorCode::VerificationFailed,
                                        format!("partition {}: {bad} of {n} regenerated hash groups differ from its H3 table", p.index),
                                    ));
                                }
                                groups += n;
                            }
                            rep.metadata.insert("hash_groups_verified".into(), groups.into());
                        }
                        let r = restored.ok_or_else(|| Error::internal("no restored view"))?;
                        let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(r.len()?));
                        crate::copy_all(r.as_ref(), &mut f, &mut p)?;
                    }
                }
                let out = f.finish()?;
                rep.outputs.push(OutputRecord::from_path(&out, Some(to), &plan.guarantees)?);
                Ok(rep)
            }),
        ))
    }
}

// ------------------------------------------------------------------------------------------

pub(crate) struct GcReader {
    format: FormatId,
    container: SharedSource,
    image: SharedSource,
    header: disc::DiscHeader,
    table: NodeTable,
    files: usize,
    rvz: Option<rvz::WiaHeader>,
}

impl GcReader {
    pub fn open(container: SharedSource, image: SharedSource, format: FormatId, ctx: &OpenContext) -> Result<Self> {
        let mut table = NodeTable::new();
        if format != GC_ISO {
            table.push(ContentNode::file(0, "image.iso", image.len()?).kind(NodeKind::Track), Some(image.clone()));
        }
        let (header, files) = disc::add_filesystem(&mut table, image.clone(), 0, "", &ctx.limits)?;
        if !header.is_gc {
            return Err(Error::malformed("not a GameCube disc"));
        }
        let rvz = if format != GC_ISO { rvz::WiaHeader::parse(container.as_ref()).ok() } else { None };
        Ok(GcReader { format, container, image, header, table, files, rvz })
    }
}

impl PackageReader for GcReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(self.format, Platform::GameCube, self.container.len()?);
        i.category = ContentCategory::DiscImage;
        i.title = Some(self.header.title.clone());
        i.title_id = Some(self.header.product_code());
        i.product_code = Some(self.header.game_id.clone());
        i.region = Some(self.header.region().into());
        i.version = Some(self.header.version.to_string());
        i.family_id = Some(self.header.game_id.clone());
        i.sizes.uncompressed = Some(self.image.len()?);
        i.encrypted = Some(false);
        i.field("disc_number", self.header.disc_number);
        i.field("files", self.files as u64);
        if let Some(h) = &self.rvz {
            i.field("compression", format!("{:?}", h.compression));
            i.field("chunk_size", h.chunk_size);
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
        let mut r = VerifyReport::new(self.format, level);
        r.pass(CheckLevel::Structure, "disc header and FST", Some(format!("{} files within the image", self.files)));
        let unreadable = self.table.nodes().iter().filter(|n| n.kind == NodeKind::File && !n.readable).count();
        r.check(CheckLevel::Structure, "file bounds", unreadable == 0, format!("{unreadable} files extend beyond the image"));
        if level.wants_content() {
            if self.rvz.is_some() {
                let len = self.image.len()?;
                let mut p = crate::ByteProgress::new(job, crate::Phase::Verifying, Some(len));
                match crate::crypto::hash_range(self.image.as_ref(), 0, len, crate::crypto::HashAlg::Sha1, Some(&mut p)) {
                    Ok(h) => r.pass(CheckLevel::Content, "group decode", Some(format!("restored image sha1 {}", crate::hex(&h)))),
                    Err(e) if e.code() == ErrorCode::Cancelled => return Err(e),
                    Err(e) => r.fail(CheckLevel::Content, "group decode", e.to_string()),
                }
            } else {
                r.skip(CheckLevel::Content, "content hashes", "GameCube discs declare no content hashes");
            }
        }
        r.skip(CheckLevel::Authenticity, "signature", "GameCube discs carry no verifiable signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(self.format))
    }
}

pub(crate) struct WiiDiscReader {
    format: FormatId,
    container: SharedSource,
    image: SharedSource,
    header: disc::DiscHeader,
    partitions: Vec<partition::PartitionInfo>,
    decrypted: Vec<Option<Arc<partition::PartitionData>>>,
    key_error: Option<String>,
    table: NodeTable,
}

impl WiiDiscReader {
    pub fn open(container: SharedSource, image: SharedSource, format: FormatId, ctx: &OpenContext) -> Result<Self> {
        let boot = crate::read_vec(image.as_ref(), 0, 0x440, 0x440)?;
        let header = disc::DiscHeader::parse(&boot, 2)?;
        if !header.is_wii {
            return Err(Error::malformed("not a Wii disc"));
        }
        let partitions = partition::read_partitions(image.as_ref())?;
        let mut table = NodeTable::new();
        if format != WII_ISO {
            table.push(ContentNode::file(0, "image.iso", image.len()?).kind(NodeKind::Track).encrypted(true), Some(image.clone()));
        }
        let mut decrypted = Vec::new();
        let mut key_error = None;
        for p in &partitions {
            let base = format!("partitions/{}-{}", p.index, p.kind_name());
            table.push(ContentNode::dir(0, base.clone()).kind(NodeKind::Partition).meta("title_id", format!("{:016x}", p.title_id)), None);
            let sec = |n: &str, off: u64, len: u64| -> Result<(ContentNode, Option<SharedSource>)> {
                let ok = p.offset + off + len <= image.len()?;
                Ok((
                    ContentNode::file(0, format!("{base}/{n}"), len).kind(NodeKind::Metadata),
                    if ok { Some(SubSource::shared(image.clone(), p.offset + off, len)?) } else { None },
                ))
            };
            for (n, off, len) in [
                ("ticket.bin", 0, 0x2A4),
                ("tmd.bin", p.tmd_offset, p.tmd_size),
                ("cert.bin", p.cert_offset, p.cert_size),
                ("h3.bin", p.h3_offset, partition::H3_SIZE),
            ] {
                let (node, data) = sec(n, off, len)?;
                table.push(node, data);
            }
            let d = match partition::titlekey(p, ctx.keys.as_ref()) {
                Ok(k) => Some(Arc::new(partition::PartitionData::new(image.clone(), p, k)?)),
                Err(e) => {
                    key_error = Some(e.to_string());
                    None
                }
            };
            if let Some(pd) = &d {
                let shared: SharedSource = pd.clone();
                match disc::add_filesystem(&mut table, shared, 2, &base, &ctx.limits) {
                    Ok(_) => {}
                    Err(e) => {
                        table.push(
                            ContentNode::file(0, format!("{base}/(unreadable)"), 0).readable(false).meta("error", e.to_string()),
                            None,
                        );
                    }
                }
            } else {
                table.push(
                    ContentNode::dir(0, format!("{base}/files"))
                        .encrypted(true)
                        .meta("note", "partition data encrypted; supply wii_common_key"),
                    None,
                );
            }
            decrypted.push(d);
        }
        Ok(WiiDiscReader { format, container, image, header, partitions, decrypted, key_error, table })
    }
}

impl PackageReader for WiiDiscReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(self.format, Platform::Wii, self.container.len()?);
        i.category = ContentCategory::DiscImage;
        i.title = Some(self.header.title.clone());
        i.title_id = Some(self.header.product_code());
        i.product_code = Some(self.header.game_id.clone());
        i.region = Some(self.header.region().into());
        i.version = Some(self.header.version.to_string());
        i.family_id = Some(self.header.game_id.clone());
        i.encrypted = Some(true);
        i.sizes.uncompressed = Some(self.image.len()?);
        let parts: Vec<crate::MetaValue> = self
            .partitions
            .iter()
            .map(|p| crate::MetaValue::Text(format!("{} {} title {:016x} at 0x{:x}", p.index, p.kind_name(), p.title_id, p.offset)))
            .collect();
        i.fields.insert("partitions".into(), crate::MetaValue::List(parts));
        if let Some(e) = &self.key_error {
            i.limitations.push(e.clone());
        }
        if self.format == WII_WBFS {
            i.limitations.push("WBFS omits blocks; filler data of the original disc may not be recoverable".into());
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
        let mut r = VerifyReport::new(self.format, level);
        r.pass(CheckLevel::Structure, "partition table", Some(format!("{} partitions", self.partitions.len())));
        for (p, d) in self.partitions.iter().zip(&self.decrypted) {
            let name = format!("partition {} ({})", p.index, p.kind_name());
            let h3 = crate::read_vec(self.image.as_ref(), p.offset + p.h3_offset, partition::H3_SIZE, partition::H3_SIZE);
            match (h3, partition::tmd_h3_hash(self.image.as_ref(), p)) {
                (Ok(h3), Ok(want)) => {
                    r.check(CheckLevel::Content, &format!("{name} H3 table vs TMD"), crate::crypto::sha1(&h3) == want, "SHA-1 of H3 table");
                    if level.wants_content() {
                        match d {
                            Some(pd) => {
                                let (n, bad) = pd.verify_hashes(&h3, job)?;
                                r.check(
                                    CheckLevel::Content,
                                    &format!("{name} cluster hashes"),
                                    bad == 0,
                                    format!("{bad} of {n} clusters failed H0–H3"),
                                );
                            }
                            None => r.skip(CheckLevel::Content, &format!("{name} cluster hashes"), "common key not supplied"),
                        }
                    }
                }
                (Err(e), _) | (_, Err(e)) => r.fail(CheckLevel::Structure, &name, e.to_string()),
            }
        }
        r.authenticity_unavailable("ticket/TMD RSA signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        let mut c = caps(self.format);
        if self.key_error.is_some() {
            c.needs(Operation::Extract, "wii_common_key", "partition data is encrypted");
        }
        Ok(c)
    }
}

pub(crate) struct WadReader {
    wad: wad::Wad,
    table: NodeTable,
    keys: Arc<dyn KeyProvider>,
}

impl WadReader {
    pub fn open(source: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let w = wad::Wad::open(source)?;
        let mut table = NodeTable::new();
        table.push(ContentNode::file(0, "cert.bin", w.cert.1).kind(NodeKind::Certificate), Some(w.section(w.cert)?));
        table.push(ContentNode::file(0, "ticket.bin", w.ticket.1).kind(NodeKind::Ticket), Some(w.section(w.ticket)?));
        table.push(ContentNode::file(0, "tmd.bin", w.tmd.1).kind(NodeKind::Metadata), Some(w.section(w.tmd)?));
        for c in &w.contents {
            table.push(
                ContentNode::file(0, format!("{:08x}.app", c.id), c.size)
                    .kind(NodeKind::Content)
                    .encrypted(true)
                    .meta("index", c.index as u64)
                    .meta("sha1", c.sha1.clone()),
                Some(w.content_raw(c)?),
            );
        }
        if w.footer.1 > 0 {
            table.push(ContentNode::file(0, "footer.bin", w.footer.1).kind(NodeKind::Metadata), Some(w.section(w.footer)?));
        }
        Ok(WadReader { wad: w, table, keys: ctx.keys.clone() })
    }
}

impl PackageReader for WadReader {
    fn format(&self) -> FormatId {
        WII_WAD
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(WII_WAD, Platform::Wii, self.wad.src.len()?);
        i.title_id = Some(format!("{:016x}", self.wad.title_id));
        i.version = Some(self.wad.title_version.to_string());
        i.family_id = Some(format!("{:08x}", self.wad.title_id as u32));
        i.category = match (self.wad.title_id >> 32) as u32 {
            0x0001_0000 | 0x0001_0001 | 0x0001_0004 => ContentCategory::Application,
            0x0001_0005 => ContentCategory::AddOn,
            0x0000_0001 | 0x0001_0002 | 0x0001_0008 => ContentCategory::System,
            _ => ContentCategory::Unknown,
        };
        i.encrypted = Some(true);
        i.field("wad_type", String::from_utf8_lossy(&self.wad.wad_type.to_be_bytes()).into_owned());
        i.field("contents", self.wad.contents.len() as u64);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(WII_WAD, level);
        r.pass(CheckLevel::Structure, "sections", Some("aligned sections within the file".into()));
        if level.wants_content() {
            for c in &self.wad.contents {
                job.check_cancel()?;
                match self.wad.decrypt_content(c, self.keys.as_ref(), job.limits.max_memory) {
                    Ok(d) => r.check(
                        CheckLevel::Content,
                        &format!("content {:08x} SHA-1", c.id),
                        crate::hex(&crate::crypto::sha1(&d)) == c.sha1,
                        "matches TMD",
                    ),
                    Err(e) if e.code() == ErrorCode::NeedsKeyMaterial => {
                        r.skip(CheckLevel::Content, "content hashes", e.message().to_string());
                        break;
                    }
                    Err(e) => r.fail(CheckLevel::Content, &format!("content {:08x}", c.id), e.to_string()),
                }
            }
        }
        r.authenticity_unavailable("ticket/TMD RSA signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(WII_WAD))
    }
}

pub(crate) struct U8Reader {
    src: SharedSource,
    table: NodeTable,
}

impl U8Reader {
    pub fn open(src: SharedSource, ctx: &OpenContext) -> Result<Self> {
        let entries = u8arc::parse(src.as_ref(), &ctx.limits)?;
        let mut table = NodeTable::new();
        for e in &entries {
            if e.is_dir {
                table.push(ContentNode::dir(0, e.path.clone()), None);
            } else {
                table.push(
                    ContentNode::file(0, e.path.clone(), e.size).span(e.offset, e.size),
                    Some(SubSource::shared(src.clone(), e.offset, e.size)?),
                );
            }
        }
        Ok(U8Reader { src, table })
    }
}

impl PackageReader for U8Reader {
    fn format(&self) -> FormatId {
        WII_U8
    }
    fn info(&self) -> Result<PackageInfo> {
        let mut i = PackageInfo::new(WII_U8, Platform::Wii, self.src.len()?);
        i.field("entries", self.table.len() as u64);
        Ok(i)
    }
    fn entries(&self) -> Result<EntryIter<'_>> {
        Ok(self.table.iter())
    }
    fn open_entry(&self, id: EntryId) -> Result<SharedSource> {
        self.table.open(id)
    }
    fn verify(&self, level: VerifyLevel, _job: &JobContext) -> Result<VerifyReport> {
        let mut r = VerifyReport::new(WII_U8, level);
        r.pass(CheckLevel::Structure, "node table", Some(format!("{} nodes within bounds", self.table.len())));
        r.skip(CheckLevel::Content, "content hashes", "U8 declares no hashes");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(WII_U8))
    }
}

/// Plan building a U8 archive from a directory.
pub fn plan_repack_u8(dir: &Path, output: &Path, policy: &IoPolicy) -> Result<Box<dyn PlannedOperation>> {
    crate::check_output_target(output, policy, &[])?;
    let files = romux_disc_free_collect(dir)?;
    let mut plan = TransformPlan::new(Operation::Repack);
    for (_, p) in &files {
        plan.inputs.push(PlanInput::capture(p, "file", WII_U8)?);
    }
    plan.outputs.push(PlanOutput {
        path: output.to_path_buf(),
        format: Some(WII_U8),
        kind: "file",
        category: "archive".into(),
        estimated_size: None,
    });
    plan.guarantees = vec![OutputGuarantee::ContainerValid, OutputGuarantee::ContentPreserved];
    Ok(ClosurePlan::new(
        plan,
        Box::new(move |plan, job| {
            let mut b = u8arc::U8Builder::new();
            for (rel, p) in &files {
                b.add_file(rel, Arc::new(FileSource::open(p)?))?;
            }
            let mut f = AtomicFile::create(&plan.outputs[0].path, &job.io, &[])?;
            b.write(&mut f, job)?;
            let out = f.finish()?;
            let mut rep = OperationReport::new(Operation::Repack, plan.input_paths());
            rep.outputs.push(OutputRecord::from_path(&out, Some(WII_U8), &plan.guarantees)?);
            Ok(rep)
        }),
    ))
}

fn romux_disc_free_collect(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((d, rel)) = stack.pop() {
        let mut items: Vec<_> = std::fs::read_dir(&d)?.collect::<std::io::Result<Vec<_>>>()?;
        items.sort_by_key(|e| e.file_name());
        for e in items {
            let ft = e.file_type()?;
            let name = e.file_name().to_string_lossy().into_owned();
            let r = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            if ft.is_symlink() {
                return Err(Error::unsafe_path(format!("symlink {r} is not followed")));
            } else if ft.is_dir() {
                stack.push((e.path(), r));
            } else {
                out.push((r, e.path()));
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
    fn gamecube_disc_listing() {
        let img = disc::testkit::gc_disc("GTST", "Test Disc", &[("data/a.bin", vec![1u8; 100])]);
        let reg = Registry::new().with(WiiBackend);
        let src: SharedSource = Arc::new(MemorySource::new(img));
        assert_eq!(reg.probe(src.as_ref(), &ProbeLimits::default()).unwrap().format, Some(GC_ISO));
        let r = reg.open(src, &OpenContext::default()).unwrap();
        assert_eq!(r.info().unwrap().title.as_deref(), Some("Test Disc"));
        let paths: Vec<_> = r.entries().unwrap().map(|n| n.unwrap().path).collect();
        assert!(paths.contains(&"sys/main.dol".to_string()));
        assert!(paths.contains(&"files/data/a.bin".to_string()));
        assert!(r.verify(VerifyLevel::All, &JobContext::default()).unwrap().no_failures());
    }

    #[test]
    fn u8_roundtrip() {
        let mut b = u8arc::U8Builder::new();
        b.add_file("meta/icon.bin", Arc::new(MemorySource::new(vec![1u8; 33]))).unwrap();
        b.add_file("banner.bin", Arc::new(MemorySource::new(vec![2u8; 70]))).unwrap();
        let mut out = Vec::new();
        b.write(&mut out, &JobContext::default()).unwrap();
        let r = U8Reader::open(Arc::new(MemorySource::new(out)), &OpenContext::default()).unwrap();
        let n: Vec<_> = r.entries().unwrap().map(|n| n.unwrap()).collect();
        let icon = n.iter().find(|n| n.path == "meta/icon.bin").unwrap();
        assert_eq!(crate::read_vec(r.open_entry(icon.id).unwrap().as_ref(), 0, 33, 33).unwrap(), vec![1u8; 33]);
    }

    /// Sparse full single-layer image: Wii magic at the start and data in the final byte.
    struct FullLayer;
    impl DataSource for FullLayer {
        fn len(&self) -> Result<u64> {
            Ok(wbfs::SINGLE_LAYER)
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
            out.fill(0);
            let end = offset + out.len() as u64;
            for (at, v) in (0x18u64..0x1C).zip(disc::WII_MAGIC.to_be_bytes()).chain([(wbfs::SINGLE_LAYER - 1, 0xEE)]) {
                if (offset..end).contains(&at) {
                    out[(at - offset) as usize] = v;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn wbfs_full_single_layer_stays_single_layer() {
        // Regression: the final 2 MiB block overhangs the layer boundary; this must not be
        // mistaken for a dual-layer disc when restoring.
        let mut c = std::io::Cursor::new(Vec::new());
        wbfs::write(&FullLayer, &mut c, &JobContext::default()).unwrap();
        let d = wbfs::WbfsDisc::open(Arc::new(MemorySource::new(c.into_inner())), 0).unwrap();
        assert_eq!(d.len().unwrap(), wbfs::SINGLE_LAYER);
        let mut last = [0u8; 1];
        d.read_exact_at(wbfs::SINGLE_LAYER - 1, &mut last).unwrap();
        assert_eq!(last[0], 0xEE);
    }

    #[test]
    fn wbfs_roundtrip() {
        let mut img = vec![0u8; 8 << 20];
        img[0x18..0x1C].copy_from_slice(&disc::WII_MAGIC.to_be_bytes());
        img[0..6].copy_from_slice(b"RTST01");
        for b in img[(4 << 20)..(4 << 20) + 1000].iter_mut() {
            *b = 0x77;
        }
        let src = MemorySource::new(img.clone());
        let mut c = std::io::Cursor::new(Vec::new());
        let (blocks, used) = wbfs::write(&src, &mut c, &JobContext::default()).unwrap();
        assert_eq!((blocks, used), (4, 2));
        let d = wbfs::WbfsDisc::open(Arc::new(MemorySource::new(c.into_inner())), 0).unwrap();
        let mut back = vec![0u8; img.len()];
        d.read_exact_at(0, &mut back).unwrap();
        assert_eq!(back, img);
        assert_eq!(d.len().unwrap(), wbfs::SINGLE_LAYER);
    }
}

/// Synthetic fixtures and internal writers used by the test suites (feature `testkit`;
/// not a stable API).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    pub use crate::wii::disc::testkit::*;
    pub use crate::wii::rvz::write_rvz_gc;
    pub use crate::wii::u8arc::U8Builder;
}
