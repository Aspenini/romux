# Romux

Romux is a library-first Rust toolkit and CLI for **inspecting, extracting, validating,
rebuilding, converting, compressing and bundling** console game packages. Every operation is
a typed Rust API and a `romux` command. The CLI contains no format logic.

Romux writes its own format readers and writers. It does not depend on, link, run or vendor
any existing ROM tool. It works offline: no accounts, network access, telemetry, bundled keys,
certificates or firmware.

> Romux is a package/file tool. It is not an emulator, downloader, key supplier or bypass
> tool. Use it with homebrew, content you created yourself, and files you are authorized to
> process.

## What it supports

| Platform | Formats | Highlights |
|---|---|---|
| Nintendo Switch | NSP, NSZ, XCI, XCZ, NCA, NCZ, PFS0, HFS0, RomFS | multi-content **bundle**, **split**, NSP⇄XCI, NSZ/XCZ compress/decompress (byte-identical), BKTR **apply-update** to a derived tree, content-ID and HFS0 hash verification |
| PlayStation 4 | PKG, param.sfo | header/entry table, unencrypted entry extraction, PFS metadata |
| Nintendo 3DS | CCI/.3ds, NCCH (CXI/CFA), CIA | ExeFS/RomFS for NoCrypto and (with your keys) encrypted NCCH, incl. seeds; TMD hash checks; unsigned CCI→CIA |
| GameCube / Wii | GCM/ISO, Wii ISO, WBFS, RVZ, WIA, WAD, U8 | FST extraction, Wii partition decryption (user key) with full H0–H3 checks, RVZ read/write for GameCube (incl. junk packing and regeneration), Wii RVZ/WIA→ISO restoration (re-encryption + H0–H3 regeneration, no key needed), Wii ISO/WBFS→RVZ (common key), WBFS⇄ISO, U8 repack |
| Wii U | WUD, WUX, installable titles (TMD) | WUD⇄WUX (byte-identical), file-overlay apply-update on decrypted trees |
| PSP | UMD ISO, CSO, PBP | CSO compress/decompress, PBP inspect/pack |
| PS Vita | VPK, PKG (header) | VPK inspect/extract/verify/rebuild |
| Original Xbox | XISO, XGD1 full disc | XDVDFS extract, deterministic XISO rebuild, full-disc→XISO, XBE metadata |
| Xbox 360 | XISO, XGD2/XGD3 full disc, Games on Demand (CON/SVOD) | XDVDFS extract, full-disc→XISO, GoD→XISO, XEX title/media ID, STFS header metadata |
| Nintendo 64 | z64, v64, n64 | byte-order detection and lossless conversion, CIC identification, CRC1/CRC2 checks |
| Super Nintendo | SFC, SMC (copier header) | LoROM/HiROM/ExHiROM header detection, title, game code, region, chipset, checksum (mirrored for odd sizes), SMC⇄SFC |
| Generic | ISO9660, CUE/BIN, raw BIN, CHD v3–v5, ZArchive (.zar) | CHD read (incl. FLAC audio hunks) and v5 write (CD and DVD), EDC checks, ISO9660 builder, ZArchive read/verify/repack |

[`docs/format-support.md`](docs/format-support.md) lists every format and operation as
`supported`, `conditional`, `read-only` or `unsupported`. It is **generated from the live
backend declarations**, and a test fails if the file goes stale.

## Quick start

Install the CLI from crates.io:

```sh
cargo install romux-cli
```

Or the latest development version from GitHub:

```sh
cargo install --git https://github.com/Aspenini/romux romux-cli
```

Or build from a clone:

```sh
git clone https://github.com/Aspenini/romux
cd romux
cargo build --release
./target/release/romux formats
./target/release/romux inspect game.xci
./target/release/romux verify image.chd --level all
./target/release/romux --dry-run switch bundle base.nsp --update upd.nsp --dlc dlc.nsp --format nsp -o all.nsp
./target/release/romux --key-file prod.keys switch compress all.nsp -o all.nsz
./target/release/romux psp compress game.iso -o game.cso
./target/release/romux --json probe unknown.bin
```

Operations that need key material read it only from a key file you pass with `--key-file`.
That file holds `name = hex` lines. See [`docs/key-material.md`](docs/key-material.md).

## Library use

```rust
let source = romux::open("game.xci")?;
let probe = romux::probe(&source)?;
let report = romux::inspect(&source, &romux::InspectOptions::default())?;
let caps = romux::capabilities(&source, &romux::OperationContext::default())?;

// Keep separate Switch content sets inside one container.
let plan = romux::switch::BundleBuilder::new("base.nsp")
    .update("update.nsp")
    .dlc("dlc-a.nsp")
    .output_format(romux::switch::PackageFormat::Xci)
    .convert_rights(true)        // explicit: rewrites NCA headers, signatures become invalid
    .keys(romux::load_keys("prod.keys")?)
    .plan()?;                    // inspect and validate; nothing written yet
println!("{:#?}", plan.describe());
plan.execute("combined.xci", &romux::JobContext::default())?;

// A different operation: reconstruct an updated derived tree.
let plan = romux::switch::ApplyUpdateBuilder::new("base.nsp", "update.nsp")
    .output_directory("updated-content")
    .keys(romux::load_keys("prod.keys")?)
    .plan()?;
plan.execute(&romux::JobContext::default())?;
```

Enable only what you need:

```toml
romux = { version = "0.1", default-features = false, features = ["switch", "disc"] }
```

Features: `switch`, `ps4`, `3ds`, `wii`, `wiiu`, `psp`, `vita`, `xbox`, `n64`, `snes`, `disc`,
`compression-zstd`, `compression-chd`, `json`, `all-formats`. Turning on one console never
pulls in another console's backend. `testkit` exposes the synthetic fixture builders used
by the test suites (each console's hidden `testkit` module); it is not part of the stable
API.

More examples live in [`examples`](examples) and
[`docs/api-guide.md`](docs/api-guide.md).

## Guarantees and honesty

- **Distinct operations.** `bundle` keeps base, update and DLC as separate content sets.
  `apply-update` builds a derived artifact. Neither is called "merge".
- **Plans before writes.** Every mutation has a `plan()` step, which is also what `--dry-run`
  shows. Inputs are checked again just before the write.
- **Safe output.** Outputs are written to a temporary sibling, verified, then renamed into
  place. Inputs are never overwritten. Existing outputs are refused unless you pass
  `--overwrite`. Extraction rejects traversal, absolute paths, symlink escape, reserved names
  and case-insensitive collisions.
- **Composable output guarantees**, for example `byte_identical_round_trip`,
  `payload_bytes_preserved`, `modified_unsigned`, `not_authentic`,
  `compatibility_unverified` and `layout_not_preserved`. A rebuilt XCI is reported as a
  gamecard-*style* container, never as an authentic cartridge.
- **Verification reports**, not a single boolean. Each check is recorded as passed, failed,
  skipped or not checked. Romux ships no verification keys, so signatures always show as
  `not checked`.

## Known limitations

- NCA, Wii partition, CIA, WAD and encrypted 3DS NCCH contents need key material that you
  supply. Romux does not implement PS4 PKG/PFS decryption, Vita PKG decryption, Wii U disc
  decryption or personalized Switch tickets. These cases report `NeedsKeyMaterial` or
  `UnsupportedFeature`.
- 3DS NCCH decryption and Xbox 360 Games on Demand are tested with synthetic data built
  to the documented layouts. They have not yet been checked against real encrypted or GoD
  dumps.
- CHD A/V codecs (`avhu`) are recognized but not decoded.
- The Switch BKTR (update) path is tested against synthetic data built with the documented
  layout. Compatibility with real titles is a separate, opt-in test
  (see [`docs/compatibility.md`](docs/compatibility.md)).
- Romux makes no claims about emulator compatibility.

## Repository layout

See [`docs/architecture.md`](docs/architecture.md). In short: one `romux` library crate at
the root. `src/` holds the core (sources, errors, model, capabilities, jobs, registry, safe
output, plus the `binary`, `crypto` and `compression` modules), with one folder per console
family (`src/switch/`, `src/wii/`, `src/snes/`, and so on). The command-line tool lives in
`apps/romux-cli`.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
