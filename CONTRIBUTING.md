# Contributing to Romux

## Ground rules

- **Write your own format code.** Do not copy, fork or transplant format-handling code from
  other projects. Public documentation and other projects' observable behavior can tell you
  what a format looks like. The implementation has to be written independently. If you
  discover something unusual about a format, record where it came from in
  `docs/formats/<platform>.md`.
- **No external ROM tools.** Nothing may install, link, shell out to or vendor NSC_Builder,
  hactool, chdman, Dolphin, ffmpeg, Python scripts or similar.
- **No proprietary material.** Never commit keys, certificates, tickets, firmware, retail
  images or copyrighted assets. Build test fixtures in-process (see
  `tests/integration/fixtures.rs`) or from material you created yourself. Synthetic keys in
  tests must be obviously fake, for example `[0x11; 32]`.
- **Be honest about capabilities.** A new operation is `supported` only when fixtures cover
  every claimed variant. Use `conditional` only when there is a deterministic condition
  detector and a tested error path. Claiming that an unsupported patch, installability or
  authenticity works is a functional bug.

## Adding a format

1. Write the binary layout and validation rules into `docs/formats/<platform>.md` first.
2. Implement a parser that uses checked `u64` arithmetic, bounded allocation and strict
   validation. A parser must never panic on malformed input.
3. Declare the format in the backend's `descriptors()`. Declare conversions as
   `ConversionEdge`s with their guarantees.
4. Add tests: synthetic fixtures, a round trip where writing is supported, negative cases,
   and a fuzz target in `fuzz/fuzz_targets`.
5. Regenerate the capability matrix:
   `ROMUX_UPDATE_DOCS=1 cargo test -p romux --all-features --test integration`.

## Checks before a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

Rust code must not use `unsafe` (`unsafe_code = "forbid"` is set workspace-wide). Every
third-party dependency is reviewed for license compatibility (MIT/Apache-2.0) and for its
use of `unsafe`.

## License

Contributions are dual-licensed under MIT and Apache-2.0.
