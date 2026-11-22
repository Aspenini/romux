# Compression behavior

Romux keeps three properties apart:

- **lossless payload preservation**: every file and content survives unchanged;
- **byte-identical decompression**: restoring the image reproduces the input byte for byte;
- **disc-image reconstructability**: the *original* disc, including filler and layout, can
  be recovered.

| Edge | Byte-identical | Notes |
|---|---|---|
| NSP→NSZ, XCI→XCZ (`switch compress`) | yes, for every NCA | Section data is decrypted and zstd-compressed (solid, or blocks of 2^N bytes). The NCZ section table stores the section keys so restoration needs no keys. Every NCZ is decompressed during verification and checked against its content ID before the output is committed. NCAs under `--min-size` and meta NCAs stay `.nca`. |
| NSZ→NSP, XCZ→XCI | yes | No keys needed. Restored NCAs are checked against their content IDs. |
| ISO→CSO (`psp compress`) | yes | CSO v1, raw deflate per 2048-byte block. Blocks that do not shrink are stored. Read-back SHA-256 is compared. |
| ISO→CHD (DVD layout) | yes | CHD v5 with zstd/zlib hunks, duplicate-hunk self-references and a compressed map. The raw and overall SHA-1 are computed by reading the written file back. |
| CUE/BIN→CHD (CD layout) | sector data yes | `cdzs`/`cdzl` codecs. ECC is not stripped. BIN/CUE has no subchannel, so subcode is stored as zeros. Audio is byte-swapped as CHD requires. |
| CHD→ISO / CHD→CUE | yes (logical data) | Verified against the CHD raw SHA-1. |
| GameCube ISO→RVZ | yes | zstd groups with junk packing (LFG seeds recovered from the data). Read-back SHA-1 is compared. |
| Wii ISO/WBFS→RVZ | yes | needs the common key; partitions stored decrypted, hash exceptions, junk packing. Read-back SHA-1 is compared. |
| GameCube RVZ/WIA→ISO | yes | RVZ junk runs are regenerated with the lagged Fibonacci generator. |
| Wii ISO→WBFS | content | Only all-zero 2 MiB blocks are dropped, and they restore as zeros. A restored image is padded to a layer size. |
| WBFS→ISO | not guaranteed | Blocks the original writer omitted, often scrubbed filler, come back as zeros. Reported as `layout_not_preserved`. |
| WUD→WUX | yes | Identical sectors are stored once. Duplicates are confirmed byte for byte, not only by hash. |
| XGD1 full disc→XISO | content | Only the game partition is kept. Video partition and security data are dropped (`layout_not_preserved`). |
| raw BIN/CUE→ISO | content | Sync, headers, EDC/ECC and subheaders are dropped (`layout_not_preserved`). |

## Codecs

Always available: store, deflate, zlib. Feature `compression-zstd`: zstd. Feature
`compression-chd`: LZMA and LZMA2 decoding, used by CHD `lzma`/`cdlz` and WIA/RVZ.
Romux does not encode LZMA. CHD FLAC hunks (`flac`, `cdfl`) are decoded by a built-in FLAC
frame decoder (fixed, LPC, verbatim and constant subframes, with CRC-8 and CRC-16 checks).
bzip2 (WIA) is not implemented and is reported per group.

All decoders run with output limits, which protects against decompression bombs.
Compression batches are parallel (`--jobs`), and output order stays deterministic.
