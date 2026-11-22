# Compatibility evidence

"The container is valid" and "a consuming tool accepts it" are separate statements. This
file records **only** compatibility that someone has observed and tested. Anything not
listed here is `compatibility_unverified`, and Romux outputs carry that guarantee label.

## How evidence is collected

1. Use samples you are legally entitled to process: your own dumps, homebrew, or test
   packages you built yourself. Never commit them.
2. Run the opt-in suite:
   ```sh
   ROMUX_COMPAT_DIR=/path/to/samples ROMUX_COMPAT_KEYS=/path/to/keys \
     cargo test -p romux --all-features --test compatibility -- --nocapture
   ```
3. To test a consuming tool, record the exact tool and version, the Romux command, the
   input class (format, encryption, single or multi-content) and what precisely worked, such
   as "boots", "installs", "update applied" or "DLC detected".

## Recorded results

| Date | Romux | Operation | Input class | Consumer (version) | Result |
|---|---|---|---|---|---|
| — | — | — | — | — | No external consumer results recorded yet. |

## Real-sample reader checks

These results come from running Romux on real dumps the maintainer owns. They show that
Romux's readers and verifiers agree with real files. They say nothing about what a console
or emulator accepts. Samples are listed by input class only.

| Date | Input class | Commands | Result |
|---|---|---|---|
| 2026-11-22 | Switch NSP, base application (16 GB) and update | inspect, list, verify, scan | every content ID and CNMT hash matches; scan groups base and update into one family |
| 2026-11-22 | Wii WBFS | inspect, verify | H3 tables match TMD hashes; cluster hashes need the user's common key |
| 2026-11-22 | Wii RVZ, dual-partition retail disc | list, verify, convert to ISO | 9,233 files listed with no key; 2,199 of 2,199 regenerated hash groups match the H3 tables; restores to ISO |
| 2026-11-22 | Wii RVZ, dual-partition retail disc | re-encode through the Wii RVZ writer (title keys taken from the RVZ) | byte-identical image (same SHA-1); 61 s to write with all cores; with junk packing, 298 MB against 320 MB for the Dolphin-made original (4.27 GB before junk packing) |
| 2026-11-22 | GameCube RVZ | re-encode through the GameCube RVZ writer | byte-identical image; 164.4 MB against 163.8 MB for the Dolphin-made original; 3.6 s |
| 2026-11-22 | GameCube RVZ | list, convert to ISO | 847 files; restores in about 2 s |
| 2026-11-22 | 3DS CCI, NoCrypto | list, verify | all ExeFS and RomFS hashes pass (14 checks) |
| 2026-11-22 | Original Xbox XISO | inspect, list | XBE title, title ID and region read |
| 2026-11-22 | Xbox 360 XGD2 full disc | inspect, list | XEX title and media ID read; 2,965 files |
| 2026-11-22 | ZArchive holding an Xbox 360 tree | verify, repack | integrity hash verifies; the repack round trip is identical |
| 2026-11-22 | N64 z64 | verify, convert to v64/n64 and back | CIC identified and CRC1/CRC2 match; byte-order round trips are identical |
| 2026-11-22 | SNES SFC, HiROM 4 MiB (headerless) | probe, inspect, verify, convert to SMC | detected with full score; product code `SNS-8X-USA`; checksum matches; converted SMC verifies, ROM byte-identical |
| 2026-11-22 | SNES SMC, LoROM 2 MiB with copier header | probe, inspect, verify, SMC→SFC→SMC | copier header detected; checksum matches; ROM byte-identical after both conversions |

Bugs these runs found and fixed:
- Switch: the cnmt.xml hash for the Meta entry was reported as a mismatch. Romux now
  skips it, because it does not cover the stored file, and treats DeltaFragments as
  optional.
- Wii RVZ: the last hash group of each partition failed. Sectors the image does not store
  are now hashed as zeros.
- WBFS: single-layer images were reported as dual-layer.
- Xbox 360: discs were sometimes probed as plain ISO9660. XDVDFS now refines ISO9660.
- Wii RVZ reader: reads before a partition's data computed an underflowing sector
  number. Release builds silently discarded it; debug builds panicked.

Not covered by real samples yet: encrypted 3DS NCCH, Xbox 360 Games on Demand packages,
CHD files (including FLAC audio), and WBFS→RVZ with a real common key.

## What the automated suite does establish

The in-tree tests use synthetic fixtures built from the documented layouts. They establish
that Romux's readers and writers agree with each other, through round trips, byte identity
and hash verification. They also establish that malformed input is rejected safely. They
**do not** establish acceptance by consoles, installers or emulators.
