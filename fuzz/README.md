# Fuzzing

Every public parser and decompressor has a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target.
The crate is excluded from the main workspace.

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run probe_all -- -rss_limit_mb=1024 -max_len=1048576
cargo +nightly fuzz run chd -- -rss_limit_mb=1024
```

Seed corpora can be generated from the synthetic fixtures in `tests/integration/fixtures.rs`
(they are small and redistributable). Never add copyrighted images to a corpus.

The in-tree test `truncated_and_mutated_inputs_never_panic` runs a deterministic subset of the
same harness on every `cargo test`, so regressions surface without nightly tooling.
