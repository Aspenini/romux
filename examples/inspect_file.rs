//! Library consumer example: probe, inspect, query capabilities, iterate entries, extract
//! one member, verify, and dry-run a conversion — without the CLI.
//!
//! ```text
//! cargo run -p romux --example inspect_file -- <file> [member-path]
//! ```

use romux::{JobContext, OpenContext, VerifyLevel};
use std::io::Write;

fn main() -> romux::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or_else(|| romux::Error::invalid_arg("usage: inspect_file <file> [member]"))?;
    let member = args.next();

    // 1. Open and auto-probe.
    let source = romux::open(&path)?;
    let probe = romux::probe(&source)?;
    println!("format: {:?} (candidates: {})", probe.format, probe.candidates.len());

    // 2. Inspect and query capabilities in the current context (no keys).
    let ctx = OpenContext::default();
    let report = romux::inspect(&source, &romux::InspectOptions { context: ctx.clone(), ..Default::default() })?;
    println!("title: {:?}  id: {:?}  platform: {}", report.info.title, report.info.title_id, report.info.platform);
    for c in &report.capabilities.entries {
        println!("  {:<12} {:?}", c.operation.as_str(), c.availability);
    }

    // 3. Iterate entries (streaming) and optionally extract one member to stdout.
    let reader = romux::open_reader(&source, &ctx)?;
    for node in reader.entries()?.take(20) {
        let node = node?;
        println!("  {:>12}  {}", node.length, node.path);
        if member.as_deref() == Some(node.path.as_str()) {
            let data = reader.open_entry(node.id)?;
            let bytes = romux::read_vec(data.as_ref(), 0, data.len()?, 64 << 20)?;
            std::io::stdout().write_all(&bytes)?;
        }
    }

    // 4. Verify: checks performed, skipped and their evidence.
    let v = reader.verify(VerifyLevel::Structure, &JobContext::default())?;
    println!("verify: {:?}", v.summary());

    // 5. Dry run: list conversion edges for this format without writing anything.
    if let Some(f) = probe.format {
        for e in romux::registry().conversions().into_iter().filter(|e| e.from == f) {
            println!("  can convert to {} ({:?}, {})", e.to, e.kind, e.support.as_str());
        }
    }
    Ok(())
}
