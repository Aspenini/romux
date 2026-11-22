//! Shared harness: run a format's read paths over arbitrary bytes. Any panic, unbounded
//! allocation (libFuzzer -rss_limit_mb), stack overflow or path escape is a bug.
use romux::{JobContext, MemorySource, OpenContext, SharedSource, VerifyLevel};
use std::sync::Arc;

pub fn run_format(data: &[u8], format: Option<&str>) {
    let src: SharedSource = Arc::new(MemorySource::new(data.to_vec()));
    let reg = romux::registry();
    let ctx = OpenContext::default();
    let formats: Vec<romux::FormatId> = match format {
        Some(f) => reg.find_format(f).into_iter().collect(),
        None => match reg.probe(src.as_ref(), &Default::default()) {
            Ok(p) => p.candidates.iter().map(|c| c.format).collect(),
            Err(_) => return,
        },
    };
    for f in formats {
        if let Ok(r) = reg.open_as(f, src.clone(), &ctx) {
            let _ = r.info();
            let _ = r.content_graph();
            if let Ok(it) = r.entries() {
                for n in it.take(256).flatten() {
                    // Paths must always be rejected or sanitised, never escape.
                    let _ = romux::path::sanitize_components(&n.path, 255);
                    if let Ok(s) = r.open_entry(n.id) {
                        let len = s.len().unwrap_or(0).min(1 << 16) as usize;
                        let mut b = vec![0u8; len];
                        let _ = s.read_exact_at(0, &mut b);
                    }
                }
            }
            let _ = r.verify(VerifyLevel::Content, &JobContext::default());
        }
    }
}
