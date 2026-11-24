# CLI reference

```text
romux [GLOBAL OPTIONS] <COMMAND>
```

## Global options

| Option | Meaning |
|---|---|
| `--json` | Print the machine-readable result envelope on stdout. Progress stays on stderr. |
| `-q, --quiet` | Suppress progress and non-essential output. |
| `-v, --verbose` | Show more detail, such as all SFO keys and per-operation capability rows. |
| `--color auto\|always\|never` | Color mode. `NO_COLOR` is honored in `auto`. |
| `--dry-run` | Plan and report without writing anything. |
| `--overwrite` | Allow replacing existing outputs. Inputs are never overwritten. |
| `--jobs N` | Worker threads for chunk-parallel work. Output stays deterministic. |
| `--temp-dir DIR` | Scratch directory. Outputs are still staged next to their target. |
| `--max-memory SIZE` | Memory budget, for example `512M` or `2G`. |
| `--key-file PATH` | User-supplied keys. Only operations that need keys read this file. |

## Generic commands

```text
romux formats [--markdown] [--conversions]
romux probe <input> [--deep]
romux inspect <input> [--deep] [--as FORMAT]
romux list <input> [--recursive] [--offset N] [--limit N] [--as FORMAT]
romux extract <input> --output <dir> [--filter <glob>]... [--as FORMAT]
romux verify <input> [--level structure|content|authenticity|all] [--as FORMAT]
romux capabilities <input>
romux scan <directory> [--recursive] [--hash]
romux convert <input> --format <format-id> --output <path> [--option key=value]...
```

`--filter` takes globs. `*` and `?` match within one path segment, and `**` crosses
segments. A pattern without a `/` also matches basenames.

## Console commands

```text
romux switch inspect|extract|verify ...
romux switch bundle <base> [--update <path>]... [--dlc <path>]... --format nsp|xci|nsz|xcz|nx|nup --output <path>
                    [--convert-rights] [--allow-unverified] [--level N]
romux switch apply-update <base> <update> --output <dir>
romux switch split <bundle> --output <dir>
romux switch convert <input> --format nsp|xci|nsz|xcz|nx|nup --output <path> [--convert-rights] [--level N]
romux switch compress <input> [--format nsz|xcz] --output <path> [--level 18] [--block N] [--min-size BYTES]
romux switch decompress <input> --output <path>

  (nx and nup decrypt the content with --key-file keys; --level sets zstd, default 3, 0 = raw.
   NX takes several games; NUP takes one game, and an update needs its base among the inputs.)

romux ps4  inspect|extract|verify <game.pkg> ...
romux 3ds  inspect|extract|verify|convert ...           (convert --format cia: unsigned CIA from NoCrypto CCI)
romux wii  inspect|extract|verify|convert|compress|decompress|repack ...
           (convert --format rvz|wbfs|iso; repack --format u8 <dir>)
romux wiiu inspect|extract|verify|compress|decompress|apply-update ...
romux psp  inspect|extract|verify|compress|decompress|repack ...   (CSO; repack builds ISO9660)
romux vita inspect|extract|verify|repack ...                       (repack builds a VPK)
romux xbox inspect|extract|verify|convert|repack ...               (convert full disc → xiso)
romux disc inspect|extract|verify|compress|decompress|repack ...   (CHD; ISO9660 builder)
```

Short target names (`rvz`, `cso`, `chd`, `cue`, `wbfs`, `cia`, `xiso`, `iso`, …) are
resolved against the conversion graph for the input's detected format. When a name is
ambiguous, Romux asks for a full format ID. Subcommands prefer targets on their own platform
(for example, `psp compress` on a plain ISO chooses `psp.cso`).

The console subcommands become active only where the backend declares the operation. A
console subcommand rejects input from another platform.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | internal error |
| 2 | invalid argument, incompatible titles/versions, conflicting output |
| 3 | unsupported or unrecognized format or feature |
| 4 | protected content is inaccessible (key material needed, signature unavailable) |
| 5 | corrupt input (malformed header, bounds, integrity, codec, unsafe path, limits) |
| 6 | I/O error or insufficient space |
| 7 | cancelled (Ctrl-C) |
| 8 | verification failed |

## JSON envelope (`schema_version` 1)

```json
{
  "schema_version": 1,
  "operation": "verify",
  "status": "ok | dry-run | error | verification_failed | unrecognized",
  "inputs": ["..."],
  "outputs": [{"path": "...", "format": "...", "size": 0, "guarantees": ["..."]}],
  "format": "disc.chd",
  "metadata": {},
  "warnings": ["..."],
  "verification": {"format": "...", "requested": "content", "checks": [{"name": "...", "level": "content", "status": "passed", "detail": "..."}], "limitations": []},
  "diagnostics": [{"severity": "error", "code": "needs_key_material", "message": "...", "context": {"operation": "...", "format": "...", "file": "...", "offset": 0}, "suggestion": "..."}]
}
```

The `diagnostics[].code` values are listed in [`errors.md`](errors.md). A field is added
without a version bump only when existing consumers keep working. Any incompatible change
increments `schema_version`.

## Dry runs

`--dry-run` prints the detected formats and input identities, the planned outputs with their
categories and estimated sizes, every step, the output guarantees, any restrictions (for
example "rebuilt gamecard-style container"), the required key-material names, and an
estimate of temporary space. It writes nothing.
