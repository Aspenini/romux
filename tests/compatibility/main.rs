//! Opt-in compatibility tests against *legally acquired, user-supplied* local samples.
//!
//! Nothing here ships copyrighted data. Set `ROMUX_COMPAT_DIR` to a folder of samples and,
//! for key-dependent checks, `ROMUX_COMPAT_KEYS` to a key file. Each sample is probed,
//! inspected, listed and verified at content level; results are printed so maintainers can
//! record precisely what worked in `docs/compatibility.md`.
//!
//! ```text
//! ROMUX_COMPAT_DIR=/path/to/samples cargo test -p romux --test compatibility -- --nocapture
//! ```

use romux::{JobContext, OpenContext, VerifyLevel};

#[test]
fn user_supplied_samples() {
    let dir = match std::env::var_os("ROMUX_COMPAT_DIR") {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            eprintln!("ROMUX_COMPAT_DIR not set; skipping compatibility samples");
            return;
        }
    };
    let mut ctx = OpenContext::default();
    if let Some(k) = std::env::var_os("ROMUX_COMPAT_KEYS") {
        ctx.keys = romux::load_keys(k).expect("key file");
    }
    let rep = romux::scan(
        &dir,
        &romux::ScanOptions { recursive: true, hash: false, context: ctx.clone(), max_hash_size: 0 },
        &JobContext::default(),
    )
    .unwrap();
    let mut failures = 0;
    for f in &rep.files {
        let src = romux::open(&f.path).unwrap();
        match romux::open_reader(&src, &ctx).and_then(|r| r.verify(VerifyLevel::Content, &JobContext::default())) {
            Ok(v) => {
                let s = v.summary();
                println!(
                    "{} [{}]: {} passed, {} failed, {} skipped, {} not checked",
                    f.path.display(),
                    f.format.clone().unwrap_or_default(),
                    s.passed,
                    s.failed,
                    s.skipped,
                    s.not_checked
                );
                if !v.no_failures() {
                    failures += 1;
                }
            }
            Err(e) => println!("{}: {e}", f.path.display()),
        }
    }
    assert_eq!(failures, 0, "some samples failed verification");
}
