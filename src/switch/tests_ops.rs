//! Operation tests over synthetic packages built with test keys.

use crate::switch::apply_update::ApplyUpdateBuilder;
use crate::switch::bundle::tests::fixture;
use crate::switch::bundle::{BundleBuilder, PackageFormat};
use crate::switch::convert::{CompressBuilder, ConvertBuilder, DecompressBuilder, SplitBuilder};
use crate::switch::formats::*;
use crate::switch::nca::ContentType;
use crate::switch::nca::testkit::*;
use crate::switch::reader::open_package;
use crate::{ErrorCode, FileSource, JobContext, MemorySource, OpenContext, OutputGuarantee, hex};
use std::path::Path;
use std::sync::Arc;

fn ctx(k: &TestKeys) -> OpenContext {
    OpenContext::default().with_keys(Arc::new(k.provider()))
}

#[cfg(feature = "zstd")]
#[test]
fn compress_decompress_roundtrip_is_byte_identical() {
    let fx = fixture();
    let c = ctx(&fx.keys);
    let all = fx.dir.path().join("all.nsp");
    BundleBuilder::new(&fx.base)
        .update(&fx.update)
        .dlc(&fx.dlc)
        .context(c.clone())
        .plan()
        .unwrap()
        .execute(&all, &JobContext::default())
        .unwrap();
    let nsz = fx.dir.path().join("all.nsz");
    assert_eq!(CompressBuilder::new(&all).plan().err().unwrap().code(), ErrorCode::NeedsKeyMaterial);
    let rep =
        CompressBuilder::new(&all).level(3).min_size(0).context(c.clone()).plan().unwrap().execute(&nsz, &JobContext::default()).unwrap();
    assert!(rep.verification.unwrap().no_failures());
    let pkg = open_package(Arc::new(FileSource::open(&nsz).unwrap()), &OpenContext::default()).unwrap();
    assert_eq!(pkg.format, SWITCH_NSZ);
    let back = fx.dir.path().join("back.nsp");
    DecompressBuilder::new(&nsz).plan().unwrap().execute(&back, &JobContext::default()).unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), std::fs::read(&all).unwrap());
    // XCI -> XCZ -> XCI also round-trips.
    let xci = fx.dir.path().join("b.xci");
    ConvertBuilder::new(&fx.base, PackageFormat::Xci).context(c.clone()).plan().unwrap().execute(&xci, &JobContext::default()).unwrap();
    let xcz = fx.dir.path().join("b.xcz");
    CompressBuilder::new(&xci).level(3).min_size(0).context(c.clone()).plan().unwrap().execute(&xcz, &JobContext::default()).unwrap();
    let xci2 = fx.dir.path().join("b2.xci");
    DecompressBuilder::new(&xcz).plan().unwrap().execute(&xci2, &JobContext::default()).unwrap();
    assert_eq!(std::fs::read(&xci2).unwrap(), std::fs::read(&xci).unwrap());
}

#[test]
fn split_restores_individual_titles() {
    let fx = fixture();
    let c = ctx(&fx.keys);
    let all = fx.dir.path().join("all.nsp");
    BundleBuilder::new(&fx.base)
        .update(&fx.update)
        .dlc(&fx.dlc)
        .context(c.clone())
        .plan()
        .unwrap()
        .execute(&all, &JobContext::default())
        .unwrap();
    assert_eq!(SplitBuilder::new(&all).plan().err().unwrap().code(), ErrorCode::NeedsKeyMaterial);
    let out = fx.dir.path().join("parts");
    let rep = SplitBuilder::new(&all).context(c.clone()).plan().unwrap().execute(&out, &JobContext::default()).unwrap();
    assert_eq!(rep.outputs.len(), 3);
    let base_part = rep.outputs.iter().find(|o| o.path.to_string_lossy().contains("_base")).unwrap();
    assert_eq!(std::fs::read(&base_part.path).unwrap(), std::fs::read(&fx.base).unwrap());
}

#[test]
fn xci_to_nsp_preserves_payload_and_refuses_overwrite() {
    let fx = fixture();
    let c = ctx(&fx.keys);
    let xci = fx.dir.path().join("b.xci");
    ConvertBuilder::new(&fx.base, PackageFormat::Xci).context(c.clone()).plan().unwrap().execute(&xci, &JobContext::default()).unwrap();
    let before: Vec<_> = std::fs::read_dir(fx.dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    let plan = ConvertBuilder::new(&xci, PackageFormat::Nsp).plan().unwrap();
    drop(plan);
    let after: Vec<_> = std::fs::read_dir(fx.dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(before, after, "planning must not write");
    let nsp = fx.dir.path().join("b2.nsp");
    let rep = ConvertBuilder::new(&xci, PackageFormat::Nsp).plan().unwrap().execute(&nsp, &JobContext::default()).unwrap();
    assert!(rep.outputs[0].guarantees.contains(&OutputGuarantee::PayloadBytesPreserved));
    assert!(ConvertBuilder::new(&xci, PackageFormat::Nsp).plan().unwrap().execute(&nsp, &JobContext::default()).is_err());
    assert!(ConvertBuilder::new(&xci, PackageFormat::Nsp).plan().unwrap().execute(&xci, &JobContext::default()).is_err());
}

fn program(tid: u64, exe: &[(&str, Vec<u8>)], romfs: &[(&str, Vec<u8>)], keys: &TestKeys) -> Vec<u8> {
    let mut b = crate::switch::romfs::RomfsBuilder::new();
    for (p, d) in romfs {
        b.add_file(p, Arc::new(MemorySource::new(d.clone()))).unwrap();
    }
    let r = b.layout().unwrap().to_vec().unwrap();
    build(
        &Spec {
            content_type: ContentType::Program,
            program_id: tid,
            sections: vec![Section::Pfs0(pfs0_image(exe)), Section::RomFs(r)],
            titlekey: None,
            distribution: 0,
        },
        keys,
    )
}

fn single_nsp(path: &Path, tid: u64, mt: u8, version: u32, related: u64, prog: Vec<u8>, keys: &TestKeys) {
    let cname = content_name(&prog, false);
    let cnmt = crate::switch::cnmt::build_binary(
        tid,
        version,
        mt,
        related,
        &[(cname.trim_end_matches(".nca").into(), hex(&crate::crypto::sha256(&prog)), prog.len() as u64, 1)],
    );
    let meta = build(
        &Spec {
            content_type: ContentType::Meta,
            program_id: tid,
            sections: vec![Section::Pfs0(pfs0_image(&[("x.cnmt", cnmt)]))],
            titlekey: None,
            distribution: 0,
        },
        keys,
    );
    std::fs::write(path, pfs0_image(&[(&content_name(&meta, true), meta), (&cname, prog)])).unwrap();
}

#[test]
fn replacement_update_produces_derived_tree() {
    let d = tempfile::tempdir().unwrap();
    let keys = TestKeys::sample();
    let c = ctx(&keys);
    let base_id = 0x0100_1111_2222_0000u64;
    let bp = d.path().join("base.nsp");
    let up = d.path().join("upd.nsp");
    single_nsp(
        &bp,
        base_id,
        0x80,
        0,
        base_id | 0x800,
        program(base_id, &[("main", b"v1".to_vec())], &[("a.txt", b"old".to_vec()), ("gone.bin", vec![1])], &keys),
        &keys,
    );
    single_nsp(
        &up,
        base_id | 0x800,
        0x81,
        0x10000,
        base_id,
        program(base_id, &[("main", b"v2".to_vec())], &[("a.txt", b"new!".to_vec()), ("b.txt", b"added".to_vec())], &keys),
        &keys,
    );
    assert!(ApplyUpdateBuilder::new(&up, &bp).output_directory(d.path().join("x")).context(c.clone()).plan().is_err());
    assert_eq!(
        ApplyUpdateBuilder::new(&bp, &up).output_directory(d.path().join("x")).plan().err().unwrap().code(),
        ErrorCode::NeedsKeyMaterial
    );
    let out = d.path().join("derived");
    let plan = ApplyUpdateBuilder::new(&bp, &up).output_directory(&out).context(c).plan().unwrap();
    assert!(plan.describe().guarantees.contains(&OutputGuarantee::DerivedArtifact));
    plan.execute(&JobContext::default()).unwrap();
    assert_eq!(std::fs::read(out.join("romfs/a.txt")).unwrap(), b"new!");
    assert_eq!(std::fs::read(out.join("exefs/main")).unwrap(), b"v2");
    let m: serde_json::Value = serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let statuses: Vec<String> = m["romfs"].as_array().unwrap().iter().map(|f| f["status"].as_str().unwrap().to_string()).collect();
    assert!(statuses.contains(&"added".to_string()) && statuses.contains(&"removed".to_string()));
}

#[test]
fn ctr_ex_generations_are_applied_per_subsection() {
    let key = [7u8; 16];
    let upper = [1, 2, 3, 4, 0, 0, 0, 9];
    let plain = vec![0xABu8; 0x400];
    let mut enc = plain.clone();
    let mut c1 = crate::switch::nca::ctr_base(upper);
    c1[4..8].copy_from_slice(&5u32.to_be_bytes());
    let mut c2 = crate::switch::nca::ctr_base(upper);
    c2[4..8].copy_from_slice(&6u32.to_be_bytes());
    crate::crypto::ctr_apply(&key, c1, 0x1000, &mut enc[..0x200]);
    crate::crypto::ctr_apply(&key, c2, 0x1200, &mut enc[0x200..]);
    let mut raw = vec![0u8; 0x1000];
    raw.extend_from_slice(&enc);
    let s = crate::switch::nca::CtrSource::new(Arc::new(MemorySource::new(raw)), 0x1000, 0x400, &key, upper)
        .unwrap()
        .with_subsections(vec![(0, 5), (0x200, 6)]);
    let mut out = vec![0u8; 0x400];
    crate::DataSource::read_exact_at(&s, 0, &mut out).unwrap();
    assert_eq!(out, plain);
}

#[test]
fn probe_identifies_packages() {
    let fx = fixture();
    let reg = crate::Registry::new().with(crate::switch::SwitchBackend);
    let src = crate::open_file(&fx.base).unwrap();
    let pr = reg.probe(src.as_ref(), &Default::default()).unwrap();
    assert_eq!(pr.format, Some(SWITCH_NSP));
    let r = reg.open(src, &ctx(&fx.keys)).unwrap();
    let info = r.info().unwrap();
    assert_eq!(info.title_id.as_deref(), Some("0100aaaabbbb0000"));
    let v = r.verify(crate::VerifyLevel::All, &JobContext::default()).unwrap();
    assert!(v.no_failures(), "{:#?}", v.checks);
    assert!(v.checks.iter().any(|c| c.status == crate::CheckStatus::NotChecked));
}
