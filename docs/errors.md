# Error codes

Every error carries a stable machine-readable `code`, a message, context (operation, format,
file, offset, content ID), an optional suggestion and a chain of causes.

| Code | Exit | Meaning | Typical resolution |
|---|---|---|---|
| `io` | 6 | Filesystem or read error | check the path and permissions |
| `unknown_format` | 3 | No compiled backend recognized the bytes | `romux formats`; check feature flags |
| `ambiguous_format` | 3 | Several formats match equally well | pass `--as <format-id>` |
| `malformed_header` | 5 | Magic, version or table structure invalid | the file is corrupt or not that format |
| `bounds_violation` | 5 | An offset or size points outside its container | truncated or corrupt input |
| `integrity_mismatch` | 5 | A declared hash or CRC does not match | re-acquire the file |
| `unsupported_feature` | 3 | Valid input, but this variant or operation is not implemented | see `docs/format-support.md` |
| `needs_key_material` | 4 | The operation needs user-supplied keys | `--key-file`; see `docs/key-material.md` |
| `incompatible_titles` | 2 | Inputs belong to different titles or roles | choose the matching base/update/DLC |
| `incompatible_versions` | 2 | Conflicting or invalid versions (for example two updates) | supply exactly one update |
| `invalid_output_format` | 2 | No declared conversion to that target | `romux formats --conversions` |
| `insufficient_space` | 6 | Disk full | free space or change the output location |
| `cancelled` | 7 | Cancelled by the user or by the caller's token | re-run |
| `unsafe_path` | 5 | An archive entry would escape the output directory | none needed; the entry is refused |
| `conflicting_output` | 2 | The output exists, collides, or would overwrite an input | new path or `--overwrite` |
| `codec_failure` | 5 | Decompression failed | corrupt data |
| `signature_unavailable` | 4 | Signature verification material is unavailable | none needed; reported as `not checked` |
| `internal_invariant` | 1 | A bug in Romux | please report it |
| `invalid_argument` | 2 | Bad CLI or API argument | see `--help` |
| `limit_exceeded` | 5 | A resource limit was hit (entries, metadata, expansion) | raise limits or reject the input |
| `verification_failed` | 8 | Output failed read-back verification, or verify found failures | inspect the report |
