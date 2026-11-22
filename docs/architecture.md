# Architecture

```text
apps/romux-cli ──► romux (one library crate, at the repository root)
                     src/            core: sources, errors, model, capabilities, jobs,
                                     registry, safe output, binary, crypto, compression,
                                     plus the high-level API (open, inspect, scan, matrix)
                     src/switch/     src/ps4/   src/n3ds/ (3DS)   src/wii/ (GameCube + Wii)
                     src/wiiu/       src/psp/   src/vita/        src/xbox/ (Xbox + Xbox 360)
                     src/n64/        src/snes/
                     src/disc/       generic: ISO9660, CUE/BIN, CHD, ZArchive
```

Romux is a single crate. Each console is a folder under `src/`, compiled only when its
cargo feature is on (`3ds` builds the `n3ds` module, since module names cannot start with a
digit). The workspace holds the library and the apps in `apps/`.

## Layers

**The core** (the crate root) is console-agnostic. It holds the shared model and runtime,
plus three infrastructure modules that every backend uses.

- `DataSource`: a positional, length-known reader. Implementations include `FileSource`,
  `MemorySource`, `SubSource` (checked sub-ranges), `ConcatSource` and `ZeroSource`. Readers
  hold no shared cursor, so they can be shared across threads.
- `Error`/`ErrorCode`: typed errors with machine-readable codes, context (operation,
  format, file, offset, content ID), a suggestion and a source chain. `Error` is boxed.
- The model: `ContentNode`, `PackageInfo`, `ContentGraph`, `MetaValue`.
- Capabilities: `FormatDescriptor` (static declarations), `CapabilitySet` (per source and
  context), `OutputGuarantee` and `ConversionEdge`.
- `JobContext` carries cancellation, a progress sink, `ResourceLimits`, `IoPolicy` and
  diagnostics. Standard phases are Probing, Validating, Planning, Reading, Transforming,
  Writing, Verifying and Finalizing.
- Plans: `TransformPlan`, `PlanInput` (identity plus fingerprint, revalidated before
  execution), `PlannedOperation` and `ClosurePlan`.
- Safe output: `AtomicFile` and `SafeOutputDir`.
- The `Registry` probes every backend, resolves ambiguity (see `specificity` and `refines`),
  runs nested probing, and dispatches conversions to the backend that declares the edge.

- `romux::binary`: checked endian readers, `Cursor`, alignment and overlap helpers,
  string decoding, a deterministic `ByteWriter`, and the PSF (`PARAM.SFO`) table that several
  Sony platforms share.
- `romux::crypto`: standard primitives (SHA-256, SHA-1, MD5, CRC32, and AES-128 in ECB,
  CBC, CTR and Nintendo-tweak XTS modes), plus `KeyFile`, the user-supplied key provider.
- `romux::compression`: deflate, zlib, zstd (feature `zstd`), and LZMA/LZMA2 decoding
  (feature `lzma`), all with mandatory output limits.

Console modules depend only on the core, never on each other. The exceptions are `psp`
and `wiiu`, which use the generic `disc` module (their features turn `disc` on). Turning on
one console never compiles another.

**Console modules** each export a `Backend`, which provides format descriptors, conversion
edges, a structural probe, readers and conversion planning.

## Public API

The public surface is deliberately small; everything else is `pub(crate)` and can change
in any release.

- The crate root: the high-level functions (`open`, `probe`, `inspect`, `verify`,
  `extract`, `plan_convert`, `scan`), the `Registry`, the model, capability, plan and
  error types, and the `crypto` (`KeyFile`, hashing) and `compression` modules.
- Per console: its `Backend`, its format identifiers, and its high-level operations: the
  Switch builders (`BundleBuilder`, `ApplyUpdateBuilder`, `CompressBuilder`, …) and the
  `plan_repack_*` / `plan_apply_update_tree` functions.
- A few curated parsers and writers behind small facade modules: `switch::pfs0`, `hfs0`
  and `exefs`, the `sfo` parsers of `ps4`, `psp` and `vita`, `switch::RomfsBuilder` and
  `psp::write_pbp`.

Concrete readers are not public; the registry hands them out as `Box<dyn PackageReader>`.
Enums that grow as formats are added (`Platform`, `ErrorCode`, `Operation`, `NodeKind`,
`ContentCategory`, `OutputGuarantee`, `Codec` and others) are `#[non_exhaustive]`, so new
variants are not breaking changes. Fixed sets (`Support`, `Confidence`, the verify levels)
stay exhaustive.

## Key design rules

- **Detection reads bytes and structure, never the file extension alone.** Probes are
  bounded and never decrypt anything. The only extension-assisted probe, for encrypted NCAs,
  is reported with `Low` confidence and a warning.
- **Generic and specific formats.** A specific format, such as `psp.iso`, *refines* a
  generic one, such as `disc.iso9660`, through higher specificity. Console disc filesystems
  (GameCube/Wii, XDVDFS) are never treated as ISO9660.
- **Planning comes before writing.** Builders validate role relationships, version
  conflicts, duplicate content, target-container limits and output-path risks in `plan()`.
  `execute()` checks the inputs again and writes atomically.
- **Readers expose metadata cheaply.** Opening a container reads only headers and tables.
  Payloads stream in 1 MiB chunks.
- **Writers lay out from manifests.** Package writers receive members, either source-backed
  or produced on the fly. They stream data and patch headers afterwards, and header sizes
  depend only on names, so memory stays bounded.
- **The CLI is thin.** It parses arguments, selects policies, renders text and JSON, and
  shows progress on stderr. It never parses formats.

## Threading

Core I/O is synchronous and positional. Chunked work runs in parallel through
`std::thread::scope` in deterministic batches: CHD hunks, NCZ blocks and CSO blocks. Output
order never depends on scheduling. Romux has no async runtime dependency.

## Adding a GUI later

Builders, plans, `JobContext` progress and cancellation, and the JSON-serializable reports
all live in the libraries. A GUI can call them directly without any CLI involvement.

## Test fixtures (`testkit`)

Each console module builds its own synthetic fixtures (minimal NCAs, CNMTs, NCCHs, Wii
discs, XEX headers, SVOD layouts and so on) in a `testkit` module. These modules compile
for the unit tests and behind the `testkit` cargo feature, gathered at each console's
`#[doc(hidden)]` `testkit` module. The integration tests and the
CLI tests turn it on; normal builds do not. Fixture builders are not part of the stable
API.
