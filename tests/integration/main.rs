//! Workspace integration tests (run through the `romux` umbrella crate with all formats).

mod fixtures;

use fixtures::*;
use romux::{CancelToken, ErrorCode, IoPolicy, JobContext, OpenContext, Operation, ProbeLimits, SafeOutputDir, Support, VerifyLevel};

#[test]
fn every_fixture_probes_to_its_format_and_reads() {
    for (name, want, bytes) in all() {
        let src = mem(bytes);
        let pr = romux::probe(&src).unwrap();
        assert_eq!(pr.format.map(|f| f.to_string()).as_deref(), Some(want), "{name}: {:?}", pr);
        let r = romux::open_reader(&src, &OpenContext::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let info = r.info().unwrap();
        assert_eq!(info.format.to_string(), want);
        let n = r.entries().unwrap().count();
        assert!(n > 0, "{name} lists no entries");
        let v = r.verify(VerifyLevel::All, &JobContext::default()).unwrap();
        assert!(v.no_failures(), "{name}: {:#?}", v.checks);
        assert!(!v.checks.is_empty());
        let caps = r.capabilities().unwrap();
        assert!(caps.get(Operation::Probe).is_some(), "{name} declares no probe capability");
    }
}

#[test]
fn specific_formats_refine_generic_iso() {
    let generic = mem(iso(&[("A", b"a")]));
    assert_eq!(romux::probe(&generic).unwrap().format.unwrap().as_str(), "disc.iso9660");
    let psp = romux::probe(&mem(psp_iso())).unwrap();
    assert_eq!(psp.format.unwrap().as_str(), "psp.iso");
    assert!(psp.ambiguity.is_empty());
    // A GameCube disc is not ISO9660 and must not be reported as such.
    let gc = romux::probe(&mem(gc_disc())).unwrap();
    assert!(gc.candidates.iter().all(|c| c.format.as_str() != "disc.iso9660"));
}

#[test]
fn nested_probe_finds_inner_filesystem() {
    let src = mem(cso(&psp_iso()));
    let pr = romux::probe_nested(&src, &ProbeLimits::default(), &OpenContext::default()).unwrap();
    assert!(pr.children.iter().any(|c| c.path == "image.iso" && c.format.as_str() == "psp.iso"), "{:?}", pr.children);
}

#[test]
fn registry_declarations_are_consistent() {
    let formats = romux::supported_formats();
    let mut ids: Vec<_> = formats.iter().map(|f| f.id).collect();
    ids.dedup();
    assert_eq!(ids.len(), formats.len(), "duplicate format ids");
    for f in &formats {
        assert!(f.get(Operation::Probe).is_some(), "{} lacks a probe declaration", f.id);
        assert!(f.id.as_str().contains('.'), "{} is not namespaced", f.id);
    }
    for e in romux::registry().conversions() {
        assert!(formats.iter().any(|f| f.id == e.from), "edge from unknown {}", e.from);
        assert!(formats.iter().any(|f| f.id == e.to), "edge to unknown {}", e.to);
        assert!(!e.guarantees.is_empty() || e.support == Support::Unsupported, "edge {}->{} declares no guarantees", e.from, e.to);
    }
}

#[test]
fn capability_matrix_documentation_matches_code() {
    let md = romux::matrix::markdown(&romux::supported_formats(), &romux::registry().conversions());
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/format-support.md");
    if std::env::var_os("ROMUX_UPDATE_DOCS").is_some() {
        std::fs::write(path, &md).unwrap();
    }
    let on_disk = std::fs::read_to_string(path).expect("docs/format-support.md missing (run with ROMUX_UPDATE_DOCS=1)");
    assert_eq!(on_disk.replace("\r\n", "\n"), md, "docs/format-support.md is stale; regenerate with `romux formats --markdown`");
}

#[test]
fn extraction_rejects_traversal_and_collisions() {
    let d = tempfile::tempdir().unwrap();
    for (name, files) in
        [("traversal", vec![("../evil.txt", vec![1u8])]), ("collision", vec![("Data.bin", vec![1u8]), ("dATA.BIN", vec![2u8])])]
    {
        let src = mem(pfs0(&files.iter().map(|(n, d)| (*n, d.clone())).collect::<Vec<_>>()));
        let out = d.path().join(name);
        let err = romux::extract(&src, &OpenContext::default(), &out, &[], &JobContext::default()).unwrap_err();
        assert!(matches!(err.code(), ErrorCode::UnsafePath | ErrorCode::ConflictingOutput), "{name}: {err}");
        assert!(!d.path().join("evil.txt").exists());
    }
}

#[test]
fn extraction_refuses_non_empty_directory_without_overwrite() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("keep.txt"), b"x").unwrap();
    let src = mem(iso(&[("A", b"a")]));
    let e = romux::extract(&src, &OpenContext::default(), d.path(), &[], &JobContext::default()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ConflictingOutput);
    let job = JobContext::default().with_io(IoPolicy { overwrite: true, ..Default::default() });
    romux::extract(&src, &OpenContext::default(), d.path(), &[], &job).unwrap();
    assert_eq!(std::fs::read(d.path().join("keep.txt")).unwrap(), b"x");
}

#[test]
fn cancellation_leaves_no_partial_output() {
    let d = tempfile::tempdir().unwrap();
    let input = d.path().join("in.iso");
    std::fs::write(&input, iso(&[("BIG.BIN", &vec![5u8; 3 << 20])])).unwrap();
    let out = d.path().join("out.chd");
    let plan = romux::plan_convert(&input, romux::disc::CHD, &out, &OpenContext::default(), Default::default()).unwrap();
    let cancel = CancelToken::new();
    cancel.cancel();
    let err = plan.execute(&JobContext::default().with_cancel(cancel)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
    let leftovers: Vec<_> = std::fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(leftovers, vec![std::ffi::OsString::from("in.iso")], "partial output left behind");
}

#[test]
fn plans_revalidate_inputs_before_execution() {
    let d = tempfile::tempdir().unwrap();
    let input = d.path().join("in.iso");
    std::fs::write(&input, iso(&[("A", b"a")])).unwrap();
    let plan = romux::plan_convert(&input, romux::disc::CHD, d.path().join("o.chd"), &OpenContext::default(), Default::default()).unwrap();
    std::fs::write(&input, iso(&[("A", b"changed!")])).unwrap();
    let e = plan.execute(&JobContext::default()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ConflictingOutput);
}

/// Deterministic xorshift for mutation tests (no external dependency).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Exercise a source through every read path; must never panic.
fn exercise(bytes: Vec<u8>) {
    let src = mem(bytes);
    if let Ok(pr) = romux::probe(&src) {
        for c in pr.candidates {
            if let Ok(r) = romux::registry().open_as(c.format, src.clone(), &OpenContext::default()) {
                let _ = r.info();
                let _ = r.content_graph();
                let _ = r.capabilities();
                if let Ok(it) = r.entries() {
                    for n in it.take(64).flatten() {
                        if let Ok(s) = r.open_entry(n.id) {
                            let mut b = vec![0u8; (s.len().unwrap_or(0).min(4096)) as usize];
                            let _ = s.read_exact_at(0, &mut b);
                        }
                    }
                }
                let _ = r.verify(VerifyLevel::Structure, &JobContext::default());
            }
        }
    }
}

#[test]
fn truncated_and_mutated_inputs_never_panic() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    for (_, _, bytes) in all() {
        // Truncations at structural boundaries and random points.
        for cut in [0usize, 1, 3, 0x10, 0x100, 0x200, 0x1000, 0x8000, 0x8800, bytes.len() / 2, bytes.len().saturating_sub(1)] {
            exercise(bytes[..cut.min(bytes.len())].to_vec());
        }
        // Random bit flips concentrated in headers (where parsers make decisions).
        for _ in 0..40 {
            let mut m = bytes.clone();
            for _ in 0..4 {
                let limit = if rng.next().is_multiple_of(2) { m.len().min(0x9000) } else { m.len() };
                let i = (rng.next() as usize) % limit.max(1);
                m[i] ^= 1 << (rng.next() % 8);
            }
            exercise(m);
        }
    }
}

#[test]
fn malicious_counts_are_bounded() {
    // PFS0 header claiming 0xFFFFFFFF entries and a huge string table.
    let mut b = b"PFS0".to_vec();
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&[0; 4]);
    exercise(b);
    // ZIP end record pointing far beyond the file.
    let mut z = b"PK\x03\x04".to_vec();
    z.resize(64, 0);
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\0");
    exercise(z);
    // CHD with an absurd hunk count.
    let mut c = b"MComprHD".to_vec();
    c.extend_from_slice(&124u32.to_be_bytes());
    c.extend_from_slice(&5u32.to_be_bytes());
    c.extend_from_slice(&[0u8; 16]);
    c.extend_from_slice(&u64::MAX.to_be_bytes());
    c.resize(124, 0);
    c[56..60].copy_from_slice(&1u32.to_be_bytes());
    c[60..64].copy_from_slice(&1u32.to_be_bytes());
    exercise(c);
}

#[test]
fn inspection_memory_is_metadata_proportional() {
    // A 6 GiB sparse file with only an ISO header: probing/inspecting must not read payload.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("big.iso");
    let head = iso(&[("A.BIN", b"x")]);
    std::fs::write(&p, &head).unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(6 << 30).unwrap();
    drop(f);
    let t = std::time::Instant::now();
    let src = romux::open(&p).unwrap();
    let rep = romux::inspect(&src, &romux::InspectOptions::default()).unwrap();
    assert_eq!(rep.info.format.as_str(), "disc.iso9660");
    assert!(t.elapsed() < std::time::Duration::from_secs(10), "inspection read far more than metadata");
}

#[test]
fn key_file_values_never_appear_in_errors() {
    let d = tempfile::tempdir().unwrap();
    let k = d.path().join("k.keys");
    std::fs::write(&k, "header_key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\nbad line here\n").unwrap();
    let e = romux::load_keys(&k).err().unwrap();
    assert!(!e.to_string().contains("00112233"));
}

#[test]
fn safe_output_dir_blocks_symlink_escape() {
    let d = tempfile::tempdir().unwrap();
    let out = SafeOutputDir::create(d.path().join("o"), &IoPolicy::default()).unwrap();
    assert!(out.create_file("a/../../x").is_err());
    assert!(out.create_file("/abs").is_err());
    assert!(out.create_file("C:/x").is_err());
}

/// Throughput and bounded-memory check on a 1 GiB sparse image (opt-in: `cargo test -- --ignored`).
#[test]
#[ignore]
fn large_image_chd_roundtrip_throughput() {
    let d = tempfile::tempdir().unwrap();
    let input = d.path().join("big.iso");
    std::fs::write(&input, iso(&[("SEED.BIN", &vec![0xA5u8; 8 << 20])])).unwrap();
    std::fs::OpenOptions::new().write(true).open(&input).unwrap().set_len(1 << 30).unwrap();
    let job = JobContext::default().with_threads(4);
    let t = std::time::Instant::now();
    let out = d.path().join("big.chd");
    romux::plan_convert(&input, romux::disc::CHD, &out, &OpenContext::default(), Default::default()).unwrap().execute(&job).unwrap();
    let secs = t.elapsed().as_secs_f64();
    eprintln!("CHD compress: {:.1} MiB/s", 1024.0 / secs);
    let back = d.path().join("back.iso");
    romux::plan_convert(&out, romux::disc::ISO9660, &back, &OpenContext::default(), Default::default()).unwrap().execute(&job).unwrap();
    let a = romux::crypto::hash_range(romux::open(&input).unwrap().as_ref(), 0, 1 << 30, romux::crypto::HashAlg::Sha1, None).unwrap();
    let b = romux::crypto::hash_range(romux::open(&back).unwrap().as_ref(), 0, 1 << 30, romux::crypto::HashAlg::Sha1, None).unwrap();
    assert_eq!(a, b);
}
