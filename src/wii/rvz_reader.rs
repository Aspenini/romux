//! Reader for Wii WIA/RVZ images: partition files are read from the stored decrypted data
//! (no key needed), and the encrypted disc is reconstructed on demand.

use crate::wii::{caps, disc, partition, rvz};
use crate::{
    CapabilitySet, CheckLevel, ContentCategory, ContentNode, DataSource, EntryId, EntryIter, FormatId, JobContext, NodeKind, NodeTable,
    OpenContext, PackageInfo, PackageReader, Platform, Result, SharedSource, SubSource, VerifyLevel, VerifyReport,
};
use std::sync::Arc;

pub(crate) struct WiiRvzReader {
    format: FormatId,
    source: SharedSource,
    image: Arc<rvz::WiaSource>,
    header: disc::DiscHeader,
    /// (partition info from the disc table, index into the WIA partition entries)
    partitions: Vec<(partition::PartitionInfo, Option<usize>)>,
    table: NodeTable,
}

impl WiiRvzReader {
    pub fn open(source: SharedSource, format: FormatId, ctx: &OpenContext) -> Result<Self> {
        let image = Arc::new(rvz::WiaSource::open(source.clone())?);
        let img: SharedSource = image.clone();
        let boot = crate::read_vec(img.as_ref(), 0, 0x440, 0x440)?;
        let header = disc::DiscHeader::parse(&boot, 2)?;
        let infos = partition::read_partitions(img.as_ref())?;
        let mut table = NodeTable::new();
        table.push(ContentNode::file(0, "image.iso", image.len()?).kind(NodeKind::Track).encrypted(true), Some(img.clone()));
        let mut partitions = Vec::new();
        for p in infos {
            let idx = image.parts.iter().position(|e| e.data_offset() == p.abs_data());
            let base = format!("partitions/{}-{}", p.index, p.kind_name());
            table.push(ContentNode::dir(0, base.clone()).kind(NodeKind::Partition).meta("title_id", format!("{:016x}", p.title_id)), None);
            for (n, off, len) in [
                ("ticket.bin", 0, 0x2A4),
                ("tmd.bin", p.tmd_offset, p.tmd_size),
                ("cert.bin", p.cert_offset, p.cert_size),
                ("h3.bin", p.h3_offset, partition::H3_SIZE),
            ] {
                table.push(
                    ContentNode::file(0, format!("{base}/{n}"), len).kind(NodeKind::Metadata),
                    Some(SubSource::shared(img.clone(), p.offset + off, len)?),
                );
            }
            if let Some(i) = idx {
                let plain: SharedSource = Arc::new(rvz::PlainPartition::new(image.clone(), i));
                if let Err(e) = disc::add_filesystem(&mut table, plain, 2, &base, &ctx.limits) {
                    table.push(ContentNode::file(0, format!("{base}/(unreadable)"), 0).readable(false).meta("error", e.to_string()), None);
                }
            }
            partitions.push((p, idx));
        }
        Ok(WiiRvzReader { format, source, image, header, partitions, table })
    }
}

impl PackageReader for WiiRvzReader {
    fn format(&self) -> FormatId {
        self.format
    }
    fn info(&self) -> Result<PackageInfo> {
        let h = &self.image.header;
        let mut i = PackageInfo::new(self.format, Platform::Wii, self.source.len()?);
        i.title = Some(self.header.title.clone());
        i.title_id = Some(self.header.product_code());
        i.product_code = Some(self.header.game_id.clone());
        i.region = Some(self.header.region().into());
        i.version = Some(self.header.version.to_string());
        i.family_id = Some(self.header.game_id.clone());
        i.category = ContentCategory::DiscImage;
        i.encrypted = Some(false);
        i.sizes.uncompressed = Some(h.iso_size);
        i.field("compression", format!("{:?}", h.compression));
        i.field("chunk_size", h.chunk_size);
        let parts: Vec<crate::MetaValue> = self
            .partitions
            .iter()
            .map(|(p, _)| crate::MetaValue::Text(format!("{} {} title {:016x} at 0x{:x}", p.index, p.kind_name(), p.title_id, p.offset)))
            .collect();
        i.fields.insert("partitions".into(), crate::MetaValue::List(parts));
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
        r.pass(CheckLevel::Structure, "header SHA-1s", None);
        r.pass(CheckLevel::Structure, "partition table", Some(format!("{} partitions", self.partitions.len())));
        let img: &dyn DataSource = self.image.as_ref();
        for (p, idx) in &self.partitions {
            let name = format!("partition {} ({})", p.index, p.kind_name());
            let h3 = crate::read_vec(img, p.offset + p.h3_offset, partition::H3_SIZE, partition::H3_SIZE)?;
            match partition::tmd_h3_hash(img, p) {
                Ok(want) => {
                    r.check(CheckLevel::Content, &format!("{name} H3 table vs TMD"), crate::crypto::sha1(&h3) == want, "SHA-1 of H3 table")
                }
                Err(e) => r.fail(CheckLevel::Structure, &format!("{name} TMD"), e.to_string()),
            }
            match (idx, level.wants_content()) {
                (Some(i), true) => {
                    let (groups, bad) = self.image.verify_partition(*i, &h3, job)?;
                    r.check(
                        CheckLevel::Content,
                        &format!("{name} regenerated hash tree"),
                        bad == 0,
                        format!("{bad} of {groups} hash groups differ from the H3 table"),
                    );
                }
                (None, _) => r.warn(CheckLevel::Structure, &name, "partition not described by the WIA partition table"),
                _ => {}
            }
        }
        r.authenticity_unavailable("ticket/TMD RSA signatures");
        Ok(r)
    }
    fn capabilities(&self) -> Result<CapabilitySet> {
        Ok(caps(self.format))
    }
}
