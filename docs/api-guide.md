# API guide

All examples assume `romux = { version = "0.3", features = [...] }`.

## Open, probe, inspect

```rust
let src = romux::open("image.chd")?;                 // read-only, positional
let probe = romux::probe(&src)?;                       // bounded, never decrypts
println!("{:?} {:?}", probe.format, probe.candidates); // evidence for each candidate
if !probe.ambiguity.is_empty() { /* choose with registry().open_as(...) */ }

let report = romux::inspect(&src, &romux::InspectOptions { deep: true, ..Default::default() })?;
println!("{:?}", report.info.title);
for child in &report.probe.children { println!("nested: {} {}", child.path, child.format); }
```

## Capabilities in context

```rust
let ctx = romux::OperationContext::default().with_keys(romux::load_keys("my.keys")?);
let caps = romux::capabilities(&src, &ctx)?;
for e in &caps.entries {
    println!("{} {:?} missing={:?}", e.operation, e.availability, e.missing);
}
```

## Iterate entries and read one member

```rust
let reader = romux::open_reader(&src, &ctx)?;
for node in reader.entries()? {                       // streaming iterator
    let node = node?;
    if node.path.ends_with("PARAM.SFO") && node.readable {
        let data = reader.open_entry(node.id)?;      // random-access view, no copy
        let bytes = romux::read_vec(data.as_ref(), 0, data.len()?, 1 << 20)?;
        let sfo = romux::ps4::sfo::parse(&bytes)?;          // the PSF format shared by PS4, PSP and Vita
    }
}
```

## Extract with filters

```rust
let job = romux::JobContext::default();
let rep = romux::extract(&src, &ctx, "out", &["**/*.bin".into()], &job)?;
for s in rep.skipped { eprintln!("skipped {}: {}", s.path, s.reason); }
```

## Verify

```rust
let v = romux::verify(&src, &ctx, romux::VerifyLevel::All, &job)?;
for c in &v.checks { println!("{:?} {:?} {}", c.status, c.level, c.name); }
// `not_checked` is never "valid"; `no_failures()` says nothing about skipped checks.
```

## Plans and dry runs

Every mutation returns a plan before anything is written:

```rust
let plan = romux::plan_convert("game.iso", romux::psp::PSP_CSO, "game.cso", &ctx, Default::default())?;
println!("{}", romux::to_json(plan.plan())?);  // inputs, outputs, guarantees, warnings, steps
let report = plan.execute(&job)?;              // inputs are checked again first
```

## Switch builders

```rust
use romux::switch::*;
let plan = BundleBuilder::new("base.nsp").update("update.nsp").dlc("dlc.nsp")
    .output_format(PackageFormat::Nsp).context(ctx.clone()).plan()?;
plan.execute("all.nsp", &job)?;

CompressBuilder::new("all.nsp").level(18).block_exponent(Some(20)).context(ctx.clone())
    .plan()?.execute("all.nsz", &job)?;
DecompressBuilder::new("all.nsz").plan()?.execute("restored.nsp", &job)?;   // no keys needed
SplitBuilder::new("all.nsp").context(ctx.clone()).plan()?.execute("parts/", &job)?;
ApplyUpdateBuilder::new("base.nsp", "update.nsp").output_directory("derived")
    .context(ctx).plan()?.execute(&job)?;
```

## Low-level modules

Most formats are reached through the generic reader API above (an ISO9660 image or a CHD
opens like any other source). A few parsers are public on their own:

```rust
let fs = romux::switch::pfs0::Reader::parse(src.clone(), romux::switch::pfs0::Kind::Pfs0, &Default::default())?;
let psf = romux::ps4::sfo::parse(&bytes)?;              // also romux::psp::sfo, romux::vita::sfo
let rom = romux::switch::RomfsBuilder::new();            // build a Switch RomFS image
romux::psp::write_pbp(&sections, &mut out, &job)?;       // build an EBOOT.PBP from its sections
```

## Progress and cancellation

```rust
struct Bar;
impl romux::ProgressSink for Bar {
    fn report(&self, e: &romux::ProgressEvent) { eprintln!("{:?} {}/{:?}", e.phase, e.completed, e.total); }
}
let cancel = romux::CancelToken::new();
let job = romux::JobContext::new().with_progress(std::sync::Arc::new(Bar)).with_cancel(cancel.clone()).with_threads(4);
// cancel.cancel() from another thread → Err(ErrorCode::Cancelled); no partial output remains.
```

## Using a single platform

```toml
romux = { version = "0.3", default-features = false, features = ["xbox"] }
```

This compiles only the `xbox` module plus the shared core.
