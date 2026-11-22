# Data safety

- **Inputs are read-only.** Romux opens sources read-only and never writes to them. An
  output path that resolves to an input is refused, even with `--overwrite`.
- **No partial outputs.** A file is written to `.<name>.romux-tmp-<pid>-<n>` in the target's
  directory, flushed, `fsync`ed, verified where the operation promises a guarantee, and then
  renamed. A failure or cancellation removes the temporary file. Extracted files are staged
  as `<name>.romux-part`.
- **Cross-device destinations.** Staging always happens beside the target, so the final
  rename never crosses filesystems. `--temp-dir` affects only scratch data.
- **Refusing overwrite is the default.** An existing output file, or a non-empty output
  directory, is a `conflicting_output` error unless you pass `--overwrite`.
- **Extraction sandbox.** Absolute and drive-prefixed paths, `..`, NUL and control
  characters, `: * ? " < > |`, reserved Windows device names (`CON`, `AUX`, `COM1`…),
  trailing dots or spaces, and over-long components are all rejected. An existing symlink
  on the output path is never followed. Entries that collide case-insensitively are
  rejected, which protects Windows and macOS.
- **TOCTOU protection.** Plans record each input's size, modification time and a head/tail
  content fingerprint. Execution checks them again and refuses inputs that changed.
- **Resource limits.** Entry counts, metadata sizes, name lengths, nesting depth and
  decompressed sizes are all bounded (`ResourceLimits`, `--max-memory`).
- **Cancellation.** Ctrl-C, or a library caller's `CancelToken`, is checked between chunks
  and before an output is finalized.
