//! CLI behaviour: exit codes, JSON envelope, dry-run immutability, overwrite refusal,
//! progress isolation, help snapshot, and an end-to-end Switch bundle with test keys.

use romux::switch::testkit::ContentType;
use romux::switch::testkit::{Section, Spec, TestKeys, build, content_name, pfs0_image};
use std::path::{Path, PathBuf};
use std::process::Command;

fn romux() -> Command {
    Command::new(env!("CARGO_BIN_EXE_romux"))
}

fn run(args: &[&str]) -> (i32, String, String) {
    let o = romux().args(args).output().expect("run romux");
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {s}"))
}

fn files_in(d: &Path) -> Vec<String> {
    let mut v: Vec<_> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

fn make_tree(d: &Path) -> PathBuf {
    let src = d.join("tree");
    std::fs::create_dir_all(src.join("SUB")).unwrap();
    std::fs::write(src.join("A.TXT"), b"alpha").unwrap();
    std::fs::write(src.join("SUB/B.BIN"), vec![7u8; 10_000]).unwrap();
    src
}

#[test]
fn formats_json_envelope_is_stable() {
    let (code, out, _) = run(&["--json", "formats"]);
    assert_eq!(code, 0);
    let v = json(&out);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["operation"], "formats");
    assert_eq!(v["status"], "ok");
    for k in ["inputs", "outputs", "format", "metadata", "warnings", "verification", "diagnostics"] {
        assert!(v.get(k).is_some(), "envelope lacks {k}");
    }
    let ids: Vec<_> = v["metadata"]["formats"].as_array().unwrap().iter().map(|f| f["id"].as_str().unwrap().to_string()).collect();
    for want in ["switch.nsp", "switch.xci", "ps4.pkg", "3ds.cia", "wii.rvz", "wiiu.wux", "psp.cso", "vita.vpk", "xbox.xiso", "disc.chd"] {
        assert!(ids.iter().any(|i| i == want), "missing {want}");
    }
}

#[test]
fn unknown_input_exit_code_and_json_error() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("junk.bin");
    std::fs::write(&f, vec![0x42u8; 4096]).unwrap();
    let (code, out, _) = run(&["--json", "inspect", f.to_str().unwrap()]);
    assert_eq!(code, romux::exit::UNSUPPORTED);
    let v = json(&out);
    assert_eq!(v["status"], "error");
    assert_eq!(v["diagnostics"][0]["code"], "unknown_format");
    let (code, _, _) = run(&["inspect", d.path().join("missing").to_str().unwrap()]);
    assert_eq!(code, romux::exit::IO);
    let (code, _, _) = run(&["convert", f.to_str().unwrap(), "--format", "nope.fmt", "-o", "x"]);
    assert_eq!(code, romux::exit::INVALID_ARGUMENT);
}

#[test]
fn dry_run_writes_nothing_and_overwrite_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let src = make_tree(d.path());
    let iso = d.path().join("t.iso");
    let before = files_in(d.path());
    let (code, out, _) = run(&["--json", "--dry-run", "disc", "repack", src.to_str().unwrap(), "-o", iso.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(json(&out)["status"], "dry-run");
    assert_eq!(files_in(d.path()), before, "dry run modified the filesystem");
    assert_eq!(run(&["--quiet", "disc", "repack", src.to_str().unwrap(), "-o", iso.to_str().unwrap()]).0, 0);
    let size = std::fs::metadata(&iso).unwrap().len();
    let (code, _, err) = run(&["disc", "repack", src.to_str().unwrap(), "-o", iso.to_str().unwrap()]);
    assert_eq!(code, romux::exit::INVALID_ARGUMENT, "{err}");
    assert_eq!(std::fs::metadata(&iso).unwrap().len(), size);
    // Writing over the input is refused even with --overwrite.
    let (code, _, _) = run(&["--overwrite", "convert", iso.to_str().unwrap(), "--format", "disc.chd", "-o", iso.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert_eq!(std::fs::metadata(&iso).unwrap().len(), size);
    // Extraction dry run.
    let out_dir = d.path().join("x");
    let (code, out, _) = run(&["--json", "--dry-run", "extract", iso.to_str().unwrap(), "-o", out_dir.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(json(&out)["metadata"]["files"], 2);
    assert!(!out_dir.exists());
}

#[test]
fn compress_verify_decompress_roundtrip_and_corruption_exit_code() {
    let d = tempfile::tempdir().unwrap();
    let src = make_tree(d.path());
    let iso = d.path().join("t.iso");
    run(&["--quiet", "disc", "repack", src.to_str().unwrap(), "-o", iso.to_str().unwrap()]);
    let cso = d.path().join("t.cso");
    let (code, out, err) = run(&["--json", "psp", "compress", iso.to_str().unwrap(), "-o", cso.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}{err}");
    let back = d.path().join("back.iso");
    assert_eq!(run(&["--quiet", "psp", "decompress", cso.to_str().unwrap(), "-o", back.to_str().unwrap()]).0, 0);
    assert_eq!(std::fs::read(&iso).unwrap(), std::fs::read(&back).unwrap());
    let chd = d.path().join("t.chd");
    assert_eq!(run(&["--quiet", "disc", "compress", iso.to_str().unwrap(), "-o", chd.to_str().unwrap()]).0, 0);
    let (code, out, _) = run(&["--json", "verify", chd.to_str().unwrap(), "--level", "all"]);
    assert_eq!(code, 0);
    assert!(json(&out)["verification"]["checks"].as_array().unwrap().len() >= 3);
    // Corrupt one compressed hunk byte: verification must fail with the documented code.
    let mut b = std::fs::read(&chd).unwrap();
    b[200] ^= 0xFF;
    std::fs::write(&chd, b).unwrap();
    let (code, out, _) = run(&["--json", "verify", chd.to_str().unwrap()]);
    assert!(code == romux::exit::VERIFICATION_FAILED || code == romux::exit::CORRUPT_INPUT, "code {code}: {out}");
}

#[test]
fn json_stdout_is_clean_and_progress_goes_to_stderr() {
    let d = tempfile::tempdir().unwrap();
    let src = make_tree(d.path());
    let iso = d.path().join("t.iso");
    let (code, out, _) = run(&["--json", "disc", "repack", src.to_str().unwrap(), "-o", iso.to_str().unwrap()]);
    assert_eq!(code, 0);
    let v = json(&out);
    assert_eq!(v["operation"], "repack");
    assert!(v["outputs"][0]["path"].as_str().unwrap().ends_with("t.iso"));
}

#[test]
fn help_snapshot() {
    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, 0);
    let snap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots/help.txt");
    if std::env::var_os("ROMUX_UPDATE_SNAPSHOTS").is_some() || !Path::new(snap).exists() {
        std::fs::create_dir_all(Path::new(snap).parent().unwrap()).unwrap();
        std::fs::write(snap, &out).unwrap();
    }
    let want = std::fs::read_to_string(snap).unwrap().replace("\r\n", "\n");
    assert_eq!(out.replace("\r\n", "\n").replace("romux.exe", "romux"), want.replace("romux.exe", "romux"));
    for sub in
        ["formats", "probe", "inspect", "list", "extract", "verify", "scan", "switch", "ps4", "3ds", "wii", "wiiu", "psp", "vita", "xbox"]
    {
        assert!(out.contains(sub), "help lacks {sub}");
    }
}

fn write_keys(d: &Path, k: &TestKeys) -> PathBuf {
    let p = d.join("test.keys");
    std::fs::write(
        &p,
        format!(
            "# synthetic test keys (not real key material)\nheader_key = {}\nkey_area_key_application_00 = {}\ntitlekek_00 = {}\n",
            romux::hex(&k.header_key),
            romux::hex(&k.kak_app),
            romux::hex(&k.titlekek)
        ),
    )
    .unwrap();
    p
}

fn title_nsp(dir: &Path, name: &str, tid: u64, mt: u8, version: u32, related: u64, k: &TestKeys) -> PathBuf {
    let content = build(
        &Spec {
            content_type: ContentType::Program,
            program_id: tid,
            sections: vec![Section::Pfs0(pfs0_image(&[("x", vec![tid as u8; 0x2000])]))],
            titlekey: None,
            distribution: 0,
        },
        k,
    );
    let cname = content_name(&content, false);
    let cnmt = romux::switch::testkit::build_binary(
        tid,
        version,
        mt,
        related,
        &[(cname.trim_end_matches(".nca").into(), romux::hex(&romux::crypto::sha256(&content)), content.len() as u64, 1)],
    );
    let meta = build(
        &Spec {
            content_type: ContentType::Meta,
            program_id: tid,
            sections: vec![Section::Pfs0(pfs0_image(&[("a.cnmt", cnmt)]))],
            titlekey: None,
            distribution: 0,
        },
        k,
    );
    let p = dir.join(name);
    std::fs::write(&p, pfs0_image(&[(&content_name(&meta, true), meta), (&cname, content)])).unwrap();
    p
}

#[test]
fn switch_bundle_split_via_cli_with_key_file() {
    let d = tempfile::tempdir().unwrap();
    let k = TestKeys::sample();
    let keys = write_keys(d.path(), &k);
    let base_id = 0x0100_0000_00C0_0000u64;
    let base = title_nsp(d.path(), "base.nsp", base_id, 0x80, 0, base_id | 0x800, &k);
    let upd = title_nsp(d.path(), "upd.nsp", base_id | 0x800, 0x81, 0x20000, base_id, &k);
    let out = d.path().join("all.xci");
    let ks = keys.to_str().unwrap();
    // Without keys the relationship cannot be verified.
    let (code, _, _) = run(&[
        "switch",
        "bundle",
        base.to_str().unwrap(),
        "--update",
        upd.to_str().unwrap(),
        "--format",
        "xci",
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, romux::exit::PROTECTED_CONTENT);
    let (code, o, e) = run(&[
        "--json",
        "--key-file",
        ks,
        "switch",
        "bundle",
        base.to_str().unwrap(),
        "--update",
        upd.to_str().unwrap(),
        "--format",
        "xci",
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{o}{e}");
    let v = json(&o);
    let g = v["outputs"][0]["guarantees"].as_array().unwrap();
    assert!(g.iter().any(|x| x == "not_authentic"), "XCI bundle must not claim authenticity: {g:?}");
    let (code, o, _) = run(&["--json", "--key-file", ks, "inspect", out.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(json(&o)["metadata"]["package"]["category"], "multi_content");
    let parts = d.path().join("parts");
    let (code, o, e) = run(&["--json", "--key-file", ks, "switch", "split", out.to_str().unwrap(), "-o", parts.to_str().unwrap()]);
    assert_eq!(code, 0, "{o}{e}");
    assert_eq!(files_in(&parts).len(), 2);
    // Key values must never be echoed.
    assert!(!o.contains(&romux::hex(&k.header_key)) && !e.contains(&romux::hex(&k.header_key)));
}

/// Like `title_nsp`, but the Program NCA carries `program_id` (updates use the base ID).
fn program_nsp(dir: &Path, name: &str, tid: u64, program_id: u64, mt: u8, version: u32, related: u64, k: &TestKeys) -> PathBuf {
    let content = build(
        &Spec {
            content_type: ContentType::Program,
            program_id,
            sections: vec![Section::Pfs0(pfs0_image(&[("main", vec![version as u8; 0x3000]), ("main.npdm", b"META".to_vec())]))],
            titlekey: None,
            distribution: 0,
        },
        k,
    );
    let cname = content_name(&content, false);
    let cnmt = romux::switch::testkit::build_binary(
        tid,
        version,
        mt,
        related,
        &[(cname.trim_end_matches(".nca").into(), romux::hex(&romux::crypto::sha256(&content)), content.len() as u64, 1)],
    );
    let meta = build(
        &Spec {
            content_type: ContentType::Meta,
            program_id: tid,
            sections: vec![Section::Pfs0(pfs0_image(&[("a.cnmt", cnmt)]))],
            titlekey: None,
            distribution: 0,
        },
        k,
    );
    let p = dir.join(name);
    std::fs::write(&p, pfs0_image(&[(&content_name(&meta, true), meta), (&cname, content)])).unwrap();
    p
}

#[test]
fn switch_nx_and_nup_via_cli_with_key_file() {
    let d = tempfile::tempdir().unwrap();
    let k = TestKeys::sample();
    let keys = write_keys(d.path(), &k);
    let ks = keys.to_str().unwrap();
    let base_id = 0x0100_0000_00D0_0000u64;
    let base = program_nsp(d.path(), "base.nsp", base_id, base_id, 0x80, 0, base_id | 0x800, &k);
    let upd = program_nsp(d.path(), "upd.nsp", base_id | 0x800, base_id, 0x81, 0x20000, base_id, &k);
    let nx = d.path().join("game.nx");
    let args =
        ["switch", "bundle", base.to_str().unwrap(), "--update", upd.to_str().unwrap(), "--format", "nx", "-o", nx.to_str().unwrap()];
    // Decryption needs keys.
    let (code, _, _) = run(&args);
    assert_eq!(code, romux::exit::PROTECTED_CONTENT);
    let mut with_keys = vec!["--json", "--key-file", ks];
    with_keys.extend_from_slice(&args);
    let (code, o, e) = run(&with_keys);
    assert_eq!(code, 0, "{o}{e}");
    let v = json(&o);
    assert_eq!(v["outputs"][0]["format"], "switch.nx");
    assert!(v["outputs"][0]["guarantees"].as_array().unwrap().iter().any(|g| g == "decrypted"));
    // Reading an NX never needs keys.
    let (code, o, _) = run(&["--json", "inspect", nx.to_str().unwrap()]);
    assert_eq!(code, 0, "{o}");
    let v = json(&o);
    assert_eq!(v["format"], "switch.nx");
    assert_eq!(v["metadata"]["package"]["category"], "multi_content");
    assert_eq!(v["metadata"]["content_graph"]["relations"][0]["kind"], "update_of");
    let (code, o, _) = run(&["--json", "verify", nx.to_str().unwrap(), "--level", "all"]);
    assert_eq!(code, 0, "{o}");
    let nup = d.path().join("game.nup");
    let (code, o, e) =
        run(&["--json", "--key-file", ks, "switch", "convert", base.to_str().unwrap(), "--format", "nup", "-o", nup.to_str().unwrap()]);
    assert_eq!(code, 0, "{o}{e}");
    let (code, o, _) = run(&["--json", "list", nup.to_str().unwrap()]);
    assert_eq!(code, 0);
    let entries: Vec<String> =
        json(&o)["metadata"]["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap().to_string()).collect();
    assert!(entries.contains(&"base/exefs/main".to_string()), "{entries:?}");
    let ex = d.path().join("ex");
    let (code, _, _) = run(&["extract", nup.to_str().unwrap(), "-o", ex.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(std::fs::read(ex.join("base/exefs/main.npdm")).unwrap(), b"META");
    // Generic convert along the declared edge.
    let nx2 = d.path().join("base.nx");
    let (code, o, e) = run(&["--key-file", ks, "convert", base.to_str().unwrap(), "--format", "switch.nx", "-o", nx2.to_str().unwrap()]);
    assert_eq!(code, 0, "{o}{e}");
    assert!(!o.contains(&romux::hex(&k.header_key)) && !e.contains(&romux::hex(&k.header_key)));
}

#[test]
fn switch_pack_nup_from_dump_folder() {
    let d = tempfile::tempdir().unwrap();
    let dump = d.path().join("dump");
    std::fs::create_dir_all(dump.join("base/exefs")).unwrap();
    std::fs::create_dir_all(dump.join("updates/65536/romfs")).unwrap();
    std::fs::write(dump.join("base/exefs/main"), vec![1u8; 0x100]).unwrap();
    std::fs::write(dump.join("updates/65536/romfs/a.bin"), vec![2u8; 5000]).unwrap();
    let out = d.path().join("game.nup");
    let (code, o, e) = run(&["--json", "--dry-run", "switch", "pack-nup", dump.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert_eq!(code, 0, "{o}{e}");
    assert!(!out.exists(), "dry run writes nothing");
    let (code, o, e) =
        run(&["--json", "switch", "pack-nup", dump.to_str().unwrap(), "-o", out.to_str().unwrap(), "--title-id", "0100000000010000"]);
    assert_eq!(code, 0, "{o}{e}");
    assert_eq!(json(&o)["outputs"][0]["format"], "switch.nup");
    let (code, o, _) = run(&["--json", "inspect", out.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(json(&o)["metadata"]["package"]["title_id"], "0100000000010000");
    let (code, _, _) = run(&["verify", out.to_str().unwrap(), "--level", "all"]);
    assert_eq!(code, 0);
    let (code, _, _) = run(&["switch", "pack-nup", dump.to_str().unwrap(), "-o", out.to_str().unwrap(), "--title-id", "xyz"]);
    assert_ne!(code, 0);
}
