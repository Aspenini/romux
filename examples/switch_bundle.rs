//! Library consumer example (feature `switch` only): plan and execute a multi-content
//! bundle, printing the plan first (the same data `--dry-run` shows).
//!
//! ```text
//! cargo run -p romux --no-default-features --features switch,compression-zstd \
//!     --example switch_bundle -- keys.txt base.nsp update.nsp dlc.nsp out.nsp
//! ```

use romux::JobContext;
use romux::switch::{BundleBuilder, PackageFormat};

fn main() -> romux::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        return Err(romux::Error::invalid_arg("usage: switch_bundle <keys> <base> [update] [dlc...] <out>"));
    }
    let keys = romux::load_keys(&a[0])?;
    let out = a.last().cloned().unwrap_or_default();
    let mut b =
        BundleBuilder::new(&a[1]).keys(keys).output_format(if out.ends_with(".xci") { PackageFormat::Xci } else { PackageFormat::Nsp });
    if a.len() > 3 {
        b = b.update(&a[2]);
    }
    for d in a.iter().skip(3).take(a.len().saturating_sub(4)) {
        b = b.dlc(d);
    }
    let plan = b.plan()?;
    for s in &plan.describe().steps {
        println!("step: {s}");
    }
    for g in &plan.describe().guarantees {
        println!("guarantee: {}", g.describe());
    }
    let rep = plan.execute(&out, &JobContext::default())?;
    println!("wrote {:?}", rep.outputs.first().map(|o| &o.path));
    Ok(())
}
