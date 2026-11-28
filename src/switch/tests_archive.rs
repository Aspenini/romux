//! NX and NUP tests over synthetic encrypted packages built with test keys.

use crate::switch::archive::{ArchiveBuilder, ArchiveFormat};
use crate::switch::formats::*;
use crate::switch::nca::testkit::*;
use crate::switch::nca::{ContentType, Nca};
use crate::switch::romfs::RomfsBuilder;
use crate::switch::{nup, nx};
use crate::{CheckStatus, ErrorCode, JobContext, MemorySource, OpenContext, PackageReader, SharedSource, VerifyLevel, hex, read_vec};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const APP: u64 = 0x0100_ABCD_0000_0000;
const DLC: u64 = APP + 0x1001;
const ICON: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

fn ctx(k: &TestKeys) -> OpenContext {
    OpenContext::default().with_keys(Arc::new(k.provider()))
}

fn romfs(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut b = RomfsBuilder::new();
    for (p, d) in files {
        b.add_file(p, Arc::new(MemorySource::new(d.clone()))).unwrap();
    }
    b.layout().unwrap().to_vec().unwrap()
}

fn nacp(name: &str, publisher: &str, version: &str) -> Vec<u8> {
    let mut n = vec![0u8; 0x4000];
    n[..name.len()].copy_from_slice(name.as_bytes());
    n[0x200..0x200 + publisher.len()].copy_from_slice(publisher.as_bytes());
    // Japanese title entry (index 2).
    let ja = "テスト";
    n[0x600..0x600 + ja.len()].copy_from_slice(ja.as_bytes());
    n[0x3060..0x3060 + version.len()].copy_from_slice(version.as_bytes());
    n
}

fn nso(build: u8) -> Vec<u8> {
    let mut m = vec![0u8; 0x200];
    m[..4].copy_from_slice(b"NSO0");
    m[0x40..0x60].fill(build);
    m
}

fn nca(ct: ContentType, tid: u64, sections: Vec<Section>, titlekey: Option<[u8; 16]>, keys: &TestKeys) -> Vec<u8> {
    build(&Spec { content_type: ct, program_id: tid, sections, titlekey, distribution: 0 }, keys)
}

/// An encrypted NSP with one CNMT. `contents`: (CNMT record type, NCA bytes).
fn nsp(
    path: &Path,
    tid: u64,
    mt: u8,
    version: u32,
    related: u64,
    contents: Vec<(u8, Vec<u8>)>,
    ticket: Option<(u64, [u8; 16])>,
    keys: &TestKeys,
) {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut recs = Vec::new();
    for (rt, data) in contents {
        let name = content_name(&data, false);
        recs.push((name.trim_end_matches(".nca").to_string(), hex(&crate::crypto::sha256(&data)), data.len() as u64, rt));
        files.push((name, data));
    }
    let cnmt = crate::switch::cnmt::build_binary(tid, version, mt, related, &recs);
    let meta = nca(ContentType::Meta, tid, vec![Section::Pfs0(pfs0_image(&[("x.cnmt", cnmt)]))], None, keys);
    files.insert(0, (content_name(&meta, true), meta));
    if let Some((rights_tid, tk)) = ticket {
        let (tn, t) = crate::switch::nca::testkit::ticket(rights_tid, &tk, keys);
        files.push((tn, t));
    }
    let refs: Vec<(&str, Vec<u8>)> = files.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
    std::fs::write(path, pfs0_image(&refs)).unwrap();
}

struct Fx {
    dir: tempfile::TempDir,
    keys: TestKeys,
    base: PathBuf,
    update: PathBuf,
    dlc: PathBuf,
}

fn fixture() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let keys = TestKeys::sample();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let zeros = vec![0u8; 900_000];
    let control = |v: &str| {
        nca(
            ContentType::Control,
            APP,
            vec![Section::RomFs(romfs(&[("control.nacp", nacp("Test Game", "Romux", v)), ("icon_AmericanEnglish.dat", ICON.to_vec())]))],
            None,
            &keys,
        )
    };
    let base_prog = nca(
        ContentType::Program,
        APP,
        vec![
            Section::Pfs0(pfs0_image(&[("main", nso(0x11)), ("main.npdm", b"META-base".to_vec())])),
            Section::RomFs(romfs(&[("a.txt", b"old".to_vec()), ("dir/big.bin", big.clone()), ("zeros.bin", zeros.clone())])),
        ],
        None,
        &keys,
    );
    let base = dir.path().join("base.nsp");
    nsp(&base, APP, 0x80, 0, APP | 0x800, vec![(1, base_prog), (3, control("1.0.0"))], None, &keys);
    // A replacement update (its RomFS is complete rather than a BKTR patch), rights-ID crypto.
    let tk = [0x42u8; 16];
    let upd_prog = nca(
        ContentType::Program,
        APP,
        vec![
            Section::Pfs0(pfs0_image(&[("main", nso(0x22)), ("main.npdm", b"META-update".to_vec())])),
            Section::RomFs(romfs(&[("a.txt", b"new!".to_vec()), ("b.txt", b"added".to_vec()), ("dir/big.bin", big)])),
        ],
        Some(tk),
        &keys,
    );
    let upd_control = nca(
        ContentType::Control,
        APP,
        vec![Section::RomFs(romfs(&[("control.nacp", nacp("Test Game", "Romux", "1.1.0")), ("icon_AmericanEnglish.dat", ICON.to_vec())]))],
        Some(tk),
        &keys,
    );
    let update = dir.path().join("update.nsp");
    nsp(&update, APP | 0x800, 0x81, 0x10000, APP, vec![(1, upd_prog), (3, upd_control)], Some((APP, tk)), &keys);
    let data = nca(ContentType::PublicData, DLC, vec![Section::RomFs(romfs(&[("dlc/item.bin", vec![7u8; 5000])]))], None, &keys);
    let dlc = dir.path().join("dlc.nsp");
    nsp(&dlc, DLC, 0x82, 0, APP, vec![(2, data)], None, &keys);
    Fx { dir, keys, base, update, dlc }
}

fn open_reader(path: &Path) -> Box<dyn PackageReader> {
    let src = crate::open_file(path).unwrap();
    let pr = crate::probe(&src).unwrap();
    crate::registry().open_as(pr.format.unwrap(), src, &OpenContext::default()).unwrap()
}

fn read_entry(r: &dyn PackageReader, path: &str) -> Vec<u8> {
    let e = r.entries().unwrap().map(|e| e.unwrap()).find(|e| e.path == path).unwrap_or_else(|| panic!("no entry {path}"));
    let s = r.open_entry(e.id).unwrap();
    read_vec(s.as_ref(), 0, s.len().unwrap(), 1 << 30).unwrap()
}

fn paths(r: &dyn PackageReader) -> Vec<String> {
    r.entries().unwrap().map(|e| e.unwrap().path).collect()
}

#[test]
fn dnca_view_reads_without_keys() {
    let keys = TestKeys::sample();
    let tk = [0x55u8; 16];
    let body = romfs(&[("x/y.bin", vec![9u8; 7000])]);
    let enc = nca(ContentType::Program, APP, vec![Section::Pfs0(pfs0_image(&[("main", nso(1))])), Section::RomFs(body)], Some(tk), &keys);
    let n = Nca::open(Arc::new(MemorySource::new(enc.clone())), &keys.provider(), Some(&tk)).unwrap();
    let dnca = n.dnca_view().unwrap();
    assert_eq!(dnca.len().unwrap(), enc.len() as u64);
    let bytes = read_vec(dnca.as_ref(), 0, dnca.len().unwrap(), 1 << 20).unwrap();
    assert_eq!(&bytes[0x200..0x204], b"DNCA");
    let plain = Nca::open(Arc::new(MemorySource::new(bytes)), &crate::NoKeys, None).unwrap();
    assert!(plain.header.is_dnca());
    assert!(plain.header.sections.iter().all(|s| s.encryption() == crate::switch::nca::EncryptionType::None));
    assert!(plain.verify_structure().iter().all(|(_, ok, _)| *ok));
    let fs = crate::switch::romfs::RomFs::open(plain.romfs_source(1).unwrap(), &Default::default()).unwrap();
    let f = fs.files.iter().find(|f| f.path == "x/y.bin").unwrap();
    assert_eq!(read_vec(fs.open_file(f).unwrap().as_ref(), 0, f.size, 1 << 20).unwrap(), vec![9u8; 7000]);
    // The probe recognises a DNCA as an NCA.
    let pr = crate::Registry::new().with(crate::switch::SwitchBackend).probe(dnca.as_ref(), &Default::default()).unwrap();
    assert_eq!(pr.format, Some(SWITCH_NCA));
}

#[test]
fn nx_from_base_update_and_dlc() {
    let fx = fixture();
    let out = fx.dir.path().join("game.nx");
    let plan =
        ArchiveBuilder::new(ArchiveFormat::Nx).input(&fx.base).input(&fx.update).input(&fx.dlc).context(ctx(&fx.keys)).plan().unwrap();
    assert!(plan.describe().guarantees.contains(&crate::OutputGuarantee::Decrypted));
    let rep = plan.into_planned(out.clone()).execute(&JobContext::default().with_threads(3)).unwrap();
    assert!(rep.verification.as_ref().unwrap().no_failures());
    assert!(rep.metadata.get("deduplicated_chunks").and_then(|v| v.as_u64()).unwrap() > 0);

    let r = open_reader(&out);
    assert_eq!(r.format(), SWITCH_NX);
    let v = r.verify(VerifyLevel::All, &JobContext::default()).unwrap();
    assert!(v.no_failures(), "{:#?}", v.checks);
    let info = r.info().unwrap();
    assert_eq!(info.title.as_deref(), Some("Test Game"));
    assert_eq!(info.version.as_deref(), Some("1.1.0"), "metadata comes from the newest snapshot");
    assert_eq!(info.title_id.as_deref(), Some("0100abcd00000000"));

    let p = paths(r.as_ref());
    let app = "0100abcd00000000";
    assert!(p.contains(&format!("{app}/metadata/control.nacp")), "{p:#?}");
    assert!(p.contains(&format!("{app}/metadata/icon_en-us.jpg")));
    let snap = |prefix: &str| -> Vec<String> { p.iter().filter(|x| x.starts_with(prefix) && x.ends_with(".nca")).cloned().collect() };
    let base_units = snap(&format!("{app}/base-v0/"));
    let upd_units = snap(&format!("{app}/update-v65536/"));
    let dlc_units = snap(&format!("{app}/dlc-"));
    assert_eq!(base_units.len(), 3);
    assert_eq!(upd_units.len(), 6, "an update snapshot is a complete view including base units");
    assert_eq!(dlc_units.len(), 2);
    assert_eq!(read_entry(r.as_ref(), &format!("{app}/metadata/icon_en-us.jpg")), ICON);

    // Every stored unit is a DNCA readable without keys.
    let prog = base_units.iter().find(|u| !u.ends_with(".cnmt.nca")).cloned().unwrap();
    let mut found = false;
    for u in base_units.iter().chain(&upd_units) {
        let bytes = read_entry(r.as_ref(), u);
        assert_eq!(&bytes[0x200..0x204], b"DNCA", "{u}");
        let n = Nca::open(Arc::new(MemorySource::new(bytes)), &crate::NoKeys, None).unwrap();
        if n.header.content_type == ContentType::Program && u.starts_with(&format!("{app}/update")) && n.header.has_rights_id() {
            let fs = crate::switch::romfs::RomFs::open(n.romfs_source(1).unwrap(), &Default::default()).unwrap();
            let f = fs.files.iter().find(|f| f.path == "a.txt").unwrap();
            assert_eq!(read_vec(fs.open_file(f).unwrap().as_ref(), 0, f.size, 64).unwrap(), b"new!");
            found = true;
        }
    }
    assert!(found, "the rights-ID update program was decrypted with its ticket");
    // Base units shared by the update view are one NxFile record.
    let base_prog_name = prog.rsplit('/').next().unwrap();
    let ids: Vec<_> =
        r.entries().unwrap().map(|e| e.unwrap()).filter(|e| e.path.ends_with(base_prog_name)).map(|e| e.hashes[0].hex.clone()).collect();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1]);

    let g = r.content_graph().unwrap();
    assert_eq!(g.titles.len(), 3);
    assert!(g.relations.iter().any(|x| x.kind == crate::RelationKind::UpdateOf));
    assert!(g.relations.iter().any(|x| x.kind == crate::RelationKind::AddOnOf));
    assert!(g.unresolved.is_empty(), "{:?}", g.unresolved);
}

#[test]
fn nx_rejects_corruption() {
    let fx = fixture();
    let out = fx.dir.path().join("one.nx");
    ArchiveBuilder::new(ArchiveFormat::Nx)
        .input(&fx.base)
        .context(ctx(&fx.keys))
        .plan()
        .unwrap()
        .execute(&out, &JobContext::default())
        .unwrap();
    let good = std::fs::read(&out).unwrap();
    let nxr = nx::Nx::open(Arc::new(MemorySource::new(good.clone())), &Default::default()).unwrap();
    assert_eq!(nxr.header.minor, 2);
    assert!(nxr.other_slot_valid);
    // Damage in the Data region: structure opens, content verification fails.
    let mut bad = good.clone();
    let b0 = nxr.blocks[0];
    bad[b0.offset as usize + 10] ^= 0xFF;
    let r = nx::NxReader::open(Arc::new(MemorySource::new(bad)), &OpenContext::default()).unwrap();
    let v = r.verify(VerifyLevel::Content, &JobContext::default()).unwrap();
    assert!(!v.no_failures());
    // Damage in the Catalog: rejected at open.
    let mut bad = good.clone();
    bad[nxr.header.catalog.0 as usize + 200] ^= 1;
    assert_eq!(nx::Nx::open(Arc::new(MemorySource::new(bad)), &Default::default()).err().unwrap().code(), ErrorCode::IntegrityMismatch);
    // One damaged header slot falls back to the other.
    let mut bad = good.clone();
    bad[20] ^= 1;
    let n = nx::Nx::open(Arc::new(MemorySource::new(bad)), &Default::default()).unwrap();
    assert!(!n.other_slot_valid);
    // Both damaged: rejected.
    let mut bad = good;
    bad[20] ^= 1;
    bad[4096 + 20] ^= 1;
    assert!(nx::Nx::open(Arc::new(MemorySource::new(bad)), &Default::default()).is_err());
}

#[test]
fn nx_needs_keys_and_complete_updates() {
    let fx = fixture();
    let e = ArchiveBuilder::new(ArchiveFormat::Nx).input(&fx.base).plan().err().unwrap();
    assert_eq!(e.code(), ErrorCode::NeedsKeyMaterial);
    let e = ArchiveBuilder::new(ArchiveFormat::Nx).input(&fx.update).context(ctx(&fx.keys)).plan().err().unwrap();
    assert_eq!(e.code(), ErrorCode::IncompatibleTitles);
    // DLC alone is a valid archive (unassociated DLC snapshot, no program).
    let out = fx.dir.path().join("dlc.nx");
    ArchiveBuilder::new(ArchiveFormat::Nx)
        .input(&fx.dlc)
        .context(ctx(&fx.keys))
        .plan()
        .unwrap()
        .execute(&out, &JobContext::default())
        .unwrap();
    let r = open_reader(&out);
    assert!(r.verify(VerifyLevel::All, &JobContext::default()).unwrap().no_failures());
    assert!(r.info().unwrap().title.is_none());
}

#[test]
fn nup_from_base_update_and_dlc() {
    let fx = fixture();
    let out = fx.dir.path().join("game.nup");
    let plan =
        ArchiveBuilder::new(ArchiveFormat::Nup).input(&fx.base).input(&fx.update).input(&fx.dlc).context(ctx(&fx.keys)).plan().unwrap();
    let rep = plan.into_planned(out.clone()).execute(&JobContext::default()).unwrap();
    assert!(rep.verification.as_ref().unwrap().no_failures());
    let r = open_reader(&out);
    assert_eq!(r.format(), SWITCH_NUP);
    let v = r.verify(VerifyLevel::All, &JobContext::default()).unwrap();
    assert!(v.no_failures(), "{:#?}", v.checks);
    assert_eq!(read_entry(r.as_ref(), "base/exefs/main"), nso(0x11));
    assert_eq!(read_entry(r.as_ref(), "base/romfs/a.txt"), b"old");
    assert_eq!(read_entry(r.as_ref(), "update-v65536/exefs/main"), nso(0x22));
    assert_eq!(read_entry(r.as_ref(), "update-v65536/romfs/a.txt"), b"new!");
    assert_eq!(read_entry(r.as_ref(), "update-v65536/romfs/b.txt"), b"added");
    assert_eq!(read_entry(r.as_ref(), &format!("addon-{DLC:016x}/romfs/dlc/item.bin")), vec![7u8; 5000]);
    let big = read_entry(r.as_ref(), "update-v65536/romfs/dir/big.bin");
    assert_eq!(big.len(), 200_000);
    assert_eq!(big[1000], (1000 % 251) as u8);

    let n = nup::Nup::open(crate::open_file(&out).unwrap(), &Default::default()).unwrap();
    assert_eq!(n.packages.len(), 3);
    let base = n.app_package();
    assert_eq!(base.kind, nup::KIND_BASE);
    assert_eq!(base.title_id, APP);
    assert_eq!(base.text(nup::TLV_TITLE_NAME).as_deref(), Some("Test Game"));
    assert_eq!(base.text(nup::TLV_PUBLISHER).as_deref(), Some("Romux"));
    assert_eq!(base.text(nup::TLV_DISPLAY_VERSION).as_deref(), Some("1.0.0"));
    assert_eq!(base.meta.get(&nup::TLV_NPDM).map(|v| v.as_slice()), Some(&b"META-base"[..]));
    assert_eq!(base.meta.get(&nup::TLV_BUILD_ID).map(|v| v.as_slice()), Some(&[0x11u8; 32][..]));
    assert_eq!(base.meta.get(&nup::TLV_ICON).map(|v| v.as_slice()), Some(ICON));
    let names = base.localized(nup::TLV_LOCALIZED_TITLES).unwrap();
    assert!(names.iter().any(|(l, t)| l == "ja" && t == "テスト".as_bytes()));
    let upd = &n.packages[1];
    assert_eq!((upd.kind, upd.title_id, upd.version, upd.flags), (nup::KIND_UPDATE, APP, 0x10000, 0));
    assert_eq!(upd.text(nup::TLV_DISPLAY_VERSION).as_deref(), Some("1.1.0"));
    assert_eq!(n.packages[2].kind, nup::KIND_ADDON);
    assert_eq!(n.uuid, n.expected_uuid());
    // Identical files (dir/big.bin in base and update) share one extent.
    let bigs: Vec<_> = n.files.iter().filter(|f| f.name == "big.bin").collect();
    assert_eq!(bigs.len(), 2);
    assert_eq!(bigs[0].extent_offset, bigs[1].extent_offset);
    if cfg!(feature = "zstd") {
        assert!(n.files.iter().any(|f| f.codec == nup::CODEC_ZSTD), "compressible files are zstd frames");
    }
    let g = r.content_graph().unwrap();
    assert_eq!(g.relations.len(), 2);
}

#[test]
fn nup_rejects_corruption_and_multiple_games() {
    let fx = fixture();
    let out = fx.dir.path().join("b.nup");
    ArchiveBuilder::new(ArchiveFormat::Nup)
        .input(&fx.base)
        .context(ctx(&fx.keys))
        .level(0)
        .plan()
        .unwrap()
        .execute(&out, &JobContext::default())
        .unwrap();
    let good = std::fs::read(&out).unwrap();
    let n = nup::Nup::open(Arc::new(MemorySource::new(good.clone())), &Default::default()).unwrap();
    assert!(n.files.iter().all(|f| f.codec == nup::CODEC_RAW), "level 0 stores raw");
    let mut bad = good.clone();
    bad[0x90] ^= 1;
    assert_eq!(nup::Nup::open(Arc::new(MemorySource::new(bad)), &Default::default()).err().unwrap().code(), ErrorCode::IntegrityMismatch);
    let f = n.files.iter().find(|f| f.size > 100).unwrap();
    let mut bad = good.clone();
    bad[f.extent_offset as usize + 5] ^= 1;
    let r = nup::NupReader::open(Arc::new(MemorySource::new(bad)), &OpenContext::default()).unwrap();
    let v = r.verify(VerifyLevel::Content, &JobContext::default()).unwrap();
    assert!(v.checks.iter().any(|c| c.status == CheckStatus::Failed));
    let mut bad = good;
    bad.push(0);
    assert!(nup::Nup::open(Arc::new(MemorySource::new(bad)), &Default::default()).is_err(), "file_size must match");

    // A NUP holds one game.
    let other = fx.dir.path().join("other.nsp");
    let p = nca(ContentType::Program, APP + 0x10000, vec![Section::Pfs0(pfs0_image(&[("main", nso(3))]))], None, &fx.keys);
    nsp(&other, APP + 0x10000, 0x80, 0, 0, vec![(1, p)], None, &fx.keys);
    let e = ArchiveBuilder::new(ArchiveFormat::Nup).input(&fx.base).input(&other).context(ctx(&fx.keys)).plan().err().unwrap();
    assert_eq!(e.code(), ErrorCode::IncompatibleTitles);
    // NX takes both applications.
    let out = fx.dir.path().join("two.nx");
    ArchiveBuilder::new(ArchiveFormat::Nx)
        .input(&fx.base)
        .input(&other)
        .context(ctx(&fx.keys))
        .plan()
        .unwrap()
        .execute(&out, &JobContext::default())
        .unwrap();
    let r = open_reader(&out);
    assert!(r.verify(VerifyLevel::All, &JobContext::default()).unwrap().no_failures());
    assert_eq!(r.info().unwrap().fields["applications"].render().matches("0100abcd").count(), 2);
}

#[test]
fn conversion_edges_and_probe() {
    let fx = fixture();
    let c = ctx(&fx.keys);
    let out = fx.dir.path().join("conv.nup");
    let plan = crate::plan_convert(&fx.base, SWITCH_NUP, &out, &c, Default::default()).unwrap();
    plan.execute(&JobContext::default()).unwrap();
    let out_nx = fx.dir.path().join("conv.nx");
    crate::plan_convert(&fx.base, SWITCH_NX, &out_nx, &c, Default::default()).unwrap().execute(&JobContext::default()).unwrap();
    for (p, f) in [(&out, SWITCH_NUP), (&out_nx, SWITCH_NX)] {
        let src: SharedSource = crate::open_file(p).unwrap();
        assert_eq!(crate::probe(&src).unwrap().format, Some(f));
        let caps = crate::capabilities(&src, &OpenContext::default()).unwrap();
        assert_eq!(caps.format, f);
    }
    assert!(crate::registry().conversions().iter().any(|e| e.from == SWITCH_XCZ && e.to == SWITCH_NX));
    // Extraction through the generic API.
    let ex = fx.dir.path().join("x");
    let rep =
        crate::extract(&crate::open_file(&out).unwrap(), &OpenContext::default(), &ex, &["base/romfs/**".into()], &JobContext::default())
            .unwrap();
    assert_eq!(rep.files, 3);
    assert_eq!(std::fs::read(ex.join("base/romfs/a.txt")).unwrap(), b"old");
}

#[test]
fn snapshot_identity_matches_specification_layout() {
    // Root-only tree: magic, version 3, platform, IDs, type, version, content ID, count, root.
    let mut nodes = vec![(String::new(), None)];
    let id = nx::snapshot_identity(1, 0x0100_0000_0000_1000, Some(0x0100_0000_0000_1000), 0, 0, &[0; 16], &mut nodes);
    let mut buf = b"NX-SNAPSHOT-ID\0".to_vec();
    buf.extend_from_slice(&3u16.to_le_bytes());
    buf.push(1);
    buf.extend_from_slice(&0x0100_0000_0000_1000u64.to_le_bytes());
    buf.extend_from_slice(&0x0100_0000_0000_1000u64.to_le_bytes());
    buf.push(0);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&[0; 16]);
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(1);
    buf.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(id, crate::crypto::sha256(&buf));
}

#[test]
fn mutated_archives_never_panic() {
    let fx = fixture();
    let c = ctx(&fx.keys);
    let mut images = Vec::new();
    for (f, name) in [(ArchiveFormat::Nx, "m.nx"), (ArchiveFormat::Nup, "m.nup")] {
        let out = fx.dir.path().join(name);
        ArchiveBuilder::new(f).input(&fx.dlc).context(c.clone()).plan().unwrap().execute(&out, &JobContext::default()).unwrap();
        images.push(std::fs::read(&out).unwrap());
    }
    let exercise = |bytes: Vec<u8>| {
        let src: SharedSource = Arc::new(MemorySource::new(bytes));
        for f in [SWITCH_NX, SWITCH_NUP] {
            if let Ok(r) = crate::registry().open_as(f, src.clone(), &OpenContext::default()) {
                let _ = r.info();
                let _ = r.content_graph();
                let _ = r.verify(VerifyLevel::All, &JobContext::default());
                for e in r.entries().unwrap().flatten() {
                    if let Ok(s) = r.open_entry(e.id) {
                        let n = s.len().unwrap_or(0).min(1 << 20);
                        let _ = read_vec(s.as_ref(), 0, n, 1 << 20);
                    }
                }
            }
        }
    };
    let mut seed = 0x1234_5678u64;
    for img in &images {
        for cut in [0, 7, 0x80, 0x100, 4096, 8192, img.len() / 2, img.len() - 1] {
            exercise(img[..cut.min(img.len())].to_vec());
        }
        for _ in 0..400 {
            let mut m = img.clone();
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = (seed % m.len() as u64) as usize;
                m[at] = (seed >> 32) as u8;
            }
            exercise(m);
        }
    }
}

fn npdm(program_id: u64) -> Vec<u8> {
    let mut n = vec![0u8; 0x100];
    n[..4].copy_from_slice(b"META");
    n[0x70..0x74].copy_from_slice(&0x80u32.to_le_bytes());
    n[0x74..0x78].copy_from_slice(&0x40u32.to_le_bytes());
    n[0x80..0x84].copy_from_slice(b"ACI0");
    n[0x90..0x98].copy_from_slice(&program_id.to_le_bytes());
    n
}

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

#[test]
fn nup_from_dump_folder() {
    let d = tempfile::tempdir().unwrap();
    let dump = d.path().join("My Game");
    write(&dump, "base/exefs/main", &nso(0x31));
    write(&dump, "base/exefs/main.npdm", &npdm(APP));
    write(&dump, "base/exefs/.listing", b"ftp junk");
    write(&dump, "updates/655360/exefs/main", &nso(0x32));
    write(&dump, "updates/655360/exefs/main.npdm", &npdm(APP));
    write(&dump, "updates/655360/romfs/data/big.bin", &(0..300_000u32).map(|i| (i % 7) as u8).collect::<Vec<_>>());
    write(&dump, "updates/655360/romfs/same.bin", b"same");
    write(&dump, "updates/655360/romfs/copy.bin", b"same");
    std::fs::create_dir_all(dump.join("updates/655360/romfs/empty")).unwrap();
    write(&dump, "updates/notes/readme.txt", b"skipped");
    write(&dump, &format!("dlc/{DLC:016x}/0/romfs/item.bin"), &[9u8; 100]);
    write(&dump, "dlc/not-a-title/0/romfs/x.bin", b"skipped");

    // NX needs native records; a dump folder is refused.
    let e = ArchiveBuilder::new(ArchiveFormat::Nx).input(&dump).plan().err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidOutputFormat);

    let out = d.path().join("game.nup");
    let plan = ArchiveBuilder::new(ArchiveFormat::Nup).input(&dump).plan().unwrap();
    assert_eq!(plan.describe().steps.len(), 4, "{:#?}", plan.describe().steps);
    assert!(plan.describe().warnings.iter().any(|w| w.contains("updates/notes")));
    assert!(plan.describe().warnings.iter().any(|w| w.contains("dlc/not-a-title")));
    let rep = plan.into_planned(out.clone()).execute(&JobContext::default()).unwrap();
    assert!(rep.verification.as_ref().unwrap().no_failures());

    let r = open_reader(&out);
    let v = r.verify(VerifyLevel::All, &JobContext::default()).unwrap();
    assert!(v.no_failures(), "{:#?}", v.checks);
    let p = paths(r.as_ref());
    assert!(!p.iter().any(|x| x.ends_with(".listing")), "dump-tool artifacts are excluded");
    assert!(p.contains(&"update-v655360/romfs/empty".to_string()), "empty directories are kept");
    assert_eq!(read_entry(r.as_ref(), "update-v655360/exefs/main"), nso(0x32));
    assert_eq!(read_entry(r.as_ref(), &format!("addon-{DLC:016x}/romfs/item.bin")), vec![9u8; 100]);

    let n = nup::Nup::open(crate::open_file(&out).unwrap(), &Default::default()).unwrap();
    let kinds: Vec<_> = n.packages.iter().map(|p| (p.kind, p.title_id, p.version, p.flags)).collect();
    assert_eq!(kinds, vec![(nup::KIND_BASE, APP, 0, 0), (nup::KIND_UPDATE, APP, 655360, 0), (nup::KIND_ADDON, DLC, 0, 0)]);
    let base = &n.packages[0];
    assert_eq!(base.romfs_dir, 0xFFFF_FFFF, "the base dump has no RomFS");
    assert_ne!(base.exefs_dir, 0xFFFF_FFFF);
    assert_eq!(base.meta.get(&nup::TLV_BUILD_ID).map(|b| b.as_slice()), Some(&[0x31u8; 32][..]));
    assert_eq!(base.meta.get(&nup::TLV_NPDM).map(|b| b.as_slice()), Some(npdm(APP).as_slice()));
    assert_eq!(base.text(nup::TLV_SOURCE_DUMP).as_deref(), Some("My Game"));
    let same: Vec<_> = n.files.iter().filter(|f| f.name == "same.bin" || f.name == "copy.bin").collect();
    assert_eq!(same[0].extent_offset, same[1].extent_offset, "identical files share one extent");

    // An update-only dump: every update is standalone; the title ID can be overridden.
    let only = d.path().join("updonly");
    write(&only, "updates/65536/exefs/main", &nso(1));
    let out2 = d.path().join("upd.nup");
    ArchiveBuilder::new(ArchiveFormat::Nup).input(&only).title_id(APP).plan().unwrap().execute(&out2, &JobContext::default()).unwrap();
    let n = nup::Nup::open(crate::open_file(&out2).unwrap(), &Default::default()).unwrap();
    assert_eq!((n.packages[0].kind, n.packages[0].flags, n.packages[0].title_id), (nup::KIND_UPDATE, nup::FLAG_STANDALONE_UPDATE, APP));

    // A bare content folder is one base package; a folder without content is refused.
    let bare = d.path().join("bare");
    write(&bare, "romfs/a.txt", b"a");
    let out3 = d.path().join("bare.nup");
    ArchiveBuilder::new(ArchiveFormat::Nup).input(&bare).plan().unwrap().execute(&out3, &JobContext::default()).unwrap();
    let junk = d.path().join("junk");
    write(&junk, "stuff/a.txt", b"a");
    assert_eq!(ArchiveBuilder::new(ArchiveFormat::Nup).input(&junk).plan().err().unwrap().code(), ErrorCode::UnknownFormat);
    // The dump must not change between planning and writing.
    let plan = ArchiveBuilder::new(ArchiveFormat::Nup).input(&bare).plan().unwrap();
    write(&bare, "romfs/a.txt", b"changed!");
    assert!(plan.execute(d.path().join("late.nup"), &JobContext::default()).is_err());
}

/// Where the minimal NUP below puts its single meta block.
#[derive(Clone, Copy, PartialEq)]
enum MetaAt {
    /// Between the TOC and `blob_offset` (layout of some third-party producers).
    BeforeBlob,
    /// After the extents (the reference packer's and Romux's layout).
    AfterExtents,
    /// Starting 4 bytes inside the TOC.
    OverTocEnd,
    /// On top of the file extent.
    OverExtent,
    /// Running past the end of the file.
    PastEnd,
}

/// The §7 worked example (one base package, `romfs/hello.bin` raw), hand-assembled so the
/// meta block position can be chosen independently of Romux's writer.
fn tiny_nup(at: MetaAt) -> Vec<u8> {
    let content = b"hello";
    let mut meta = Vec::new();
    for (t, payload) in [(nup::TLV_NPDM, &b"META-npdm"[..]), (nup::TLV_TITLE_NAME, &b"Tiny"[..])] {
        meta.extend_from_slice(&t.to_le_bytes());
        meta.extend_from_slice(&0u16.to_le_bytes());
        meta.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        meta.extend_from_slice(payload);
    }
    let pool = b"romfshello.bin";
    let toc_size = 0x30 + 0x40 + 2 * 0x18 + 0x50 + 2 * 4 + pool.len() as u64;
    let toc_end = 0x80 + toc_size;
    let align = |v: u64| v.div_ceil(16) * 16;
    let (meta_off, blob, extent, file_size) = match at {
        MetaAt::BeforeBlob => {
            let blob = align(toc_end + meta.len() as u64);
            (toc_end, blob, blob, blob + content.len() as u64)
        }
        MetaAt::OverTocEnd => {
            let blob = align(toc_end + meta.len() as u64);
            (toc_end - 4, blob, blob, blob + content.len() as u64)
        }
        MetaAt::AfterExtents | MetaAt::OverExtent | MetaAt::PastEnd => {
            let blob = align(toc_end);
            let m = blob + content.len() as u64;
            let meta_off = if at == MetaAt::OverExtent { blob } else { m };
            (meta_off, blob, blob, m + meta.len() as u64)
        }
    };
    let meta_size = if at == MetaAt::PastEnd { meta.len() as u32 + 64 } else { meta.len() as u32 };
    let mut t = Vec::new();
    t.extend_from_slice(nup::TOC_MAGIC);
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(&2u64.to_le_bytes());
    t.extend_from_slice(&1u64.to_le_bytes());
    let pool_off = toc_size - pool.len() as u64;
    t.extend_from_slice(&pool_off.to_le_bytes());
    t.extend_from_slice(&(pool.len() as u64).to_le_bytes());
    t.extend_from_slice(&0u64.to_le_bytes());
    // Package: base 0x040074A01BF12000, root 0, no ExeFS, RomFS dir 1, version 1.0.0.
    t.extend_from_slice(&0x0400_74A0_1BF1_2000u64.to_le_bytes());
    for v in [0u32, 0xFFFF_FFFF, 1, 0x10000] {
        t.extend_from_slice(&v.to_le_bytes());
    }
    t.extend_from_slice(&[0u8; 8]);
    t.extend_from_slice(&meta_off.to_le_bytes());
    t.extend_from_slice(&meta_size.to_le_bytes());
    t.extend_from_slice(&[0u8; 20]);
    // Directories: root "" (child slot 0), romfs (child slot 1).
    for (off, len, first) in [(0u32, 0u32, 0u32), (0, 5, 1)] {
        for v in [off, len, first, 1] {
            t.extend_from_slice(&v.to_le_bytes());
        }
        t.extend_from_slice(&0u64.to_le_bytes());
    }
    // File hello.bin.
    for v in [5u32, 9] {
        t.extend_from_slice(&v.to_le_bytes());
    }
    for v in [content.len() as u64, extent, content.len() as u64] {
        t.extend_from_slice(&v.to_le_bytes());
    }
    t.extend_from_slice(&crate::crypto::sha256(content));
    t.extend_from_slice(&[nup::CODEC_RAW, 0, 0, 0]);
    t.extend_from_slice(&[0u8; 12]);
    // Children: root -> dir 1; romfs -> file (node id 2 = dir_count + 0).
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(&2u32.to_le_bytes());
    t.extend_from_slice(pool);
    assert_eq!(t.len() as u64, toc_size);
    let mut f = vec![0u8; file_size as usize];
    f[..4].copy_from_slice(nup::MAGIC);
    f[4..6].copy_from_slice(&0x80u16.to_le_bytes());
    f[6..8].copy_from_slice(&1u16.to_le_bytes());
    f[8..0x10].copy_from_slice(&0x80u64.to_le_bytes());
    f[0x10..0x18].copy_from_slice(&toc_size.to_le_bytes());
    f[0x18..0x38].copy_from_slice(&crate::crypto::sha256(&t));
    f[0x38..0x40].copy_from_slice(&blob.to_le_bytes());
    f[0x40..0x48].copy_from_slice(&file_size.to_le_bytes());
    f[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
    f[0x50..0x60].copy_from_slice(&nup::derive_uuid([(0x0400_74A0_1BF1_2000, 0x10000, 0)].into_iter()));
    f[0x80..toc_end as usize].copy_from_slice(&t);
    f[extent as usize..extent as usize + content.len()].copy_from_slice(content);
    let m = meta_off as usize;
    if at != MetaAt::OverExtent && at != MetaAt::OverTocEnd {
        f[m..m + meta.len()].copy_from_slice(&meta);
    }
    f
}

#[test]
fn nup_meta_block_between_toc_and_blob_is_accepted() {
    // Regression: a meta block before blob_offset (absolute offset, after the TOC) is valid
    // NUP v1; Romux used to reject it as "outside the blob region".
    for at in [MetaAt::BeforeBlob, MetaAt::AfterExtents] {
        let bytes = tiny_nup(at);
        let n = nup::Nup::open(Arc::new(MemorySource::new(bytes.clone())), &Default::default()).unwrap();
        let p = &n.packages[0];
        assert_eq!(p.meta.get(&nup::TLV_NPDM).map(|v| v.as_slice()), Some(&b"META-npdm"[..]));
        assert_eq!(p.text(nup::TLV_TITLE_NAME).as_deref(), Some("Tiny"));
        if at == MetaAt::BeforeBlob {
            assert!(p.meta_offset < n.blob_offset);
        }
        let r = nup::NupReader::open(Arc::new(MemorySource::new(bytes)), &OpenContext::default()).unwrap();
        let v = r.verify(VerifyLevel::All, &JobContext::default()).unwrap();
        assert!(v.no_failures(), "{:#?}", v.checks);
        assert_eq!(read_entry(&r, "base/romfs/hello.bin"), b"hello");
        assert_eq!(r.info().unwrap().title.as_deref(), Some("Tiny"));
    }
}

#[test]
fn nup_misplaced_meta_blocks_are_rejected_with_details() {
    let open = |at| nup::Nup::open(Arc::new(MemorySource::new(tiny_nup(at))), &Default::default()).err().expect("must be rejected");
    let e = open(MetaAt::OverTocEnd);
    assert_eq!(e.code(), ErrorCode::BoundsViolation);
    let m = e.to_string();
    assert!(m.contains("NUP v1, header_version 1"), "{m}");
    assert!(m.contains("package 0 (040074a01bf12000) meta block [0x"), "{m}");
    assert!(m.contains("after the superblock and TOC") && m.contains("blob region starts at 0x"), "{m}");
    assert!(e.context().offset.is_some(), "the offending offset is attached");

    let e = open(MetaAt::PastEnd);
    assert_eq!(e.code(), ErrorCode::BoundsViolation);
    assert!(e.to_string().contains("is outside the region it may occupy"), "{e}");

    let e = open(MetaAt::OverExtent);
    assert_eq!(e.code(), ErrorCode::BoundsViolation);
    let m = e.to_string();
    assert!(m.contains("overlaps") && m.contains("meta block") && m.contains("extent [0x"), "{m}");
}
