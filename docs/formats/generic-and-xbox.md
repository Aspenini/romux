# Generic discs, Xbox, Xbox 360, N64 and SNES

References: ECMA-119, the MAME CHD documentation, the Xbox developer wiki (XDVDFS),
Free60 (XEX, STFS/SVOD), the ZArchive format notes and the N64brew wiki
and the SNESdev wiki.

## ISO9660 (`disc.iso9660`)
- Volume descriptors start at sector 16 (`CD001`). The PVD holds the volume ID, block count
  and root record. A Joliet SVD (escape `%/@`, `%/C` or `%/E`) provides UTF-16BE names and
  is preferred when present.
- Directory records never cross sector boundaries, and Romux handles multi-extent files.
  Loops and excessive depth are rejected. Rock Ridge is ignored.
- The builder writes a PVD, terminator, L and M path tables, sorted records and files on
  sector boundaries, with fixed timestamps. Names are "relaxed" (case preserved, `;1`
  suffix).

## CUE/BIN (`disc.cue`) and raw BIN (`disc.bin`)
- Supported keywords: FILE (BINARY/MOTOROLA), TRACK (AUDIO, MODE1/2048, MODE1/2352,
  MODE2/2336, MODE2/2352, MODE2/2048, MODE2/2324, CDG), INDEX, PREGAP, POSTGAP, FLAGS,
  TITLE, PERFORMER, CATALOG and REM.
- The BIN paths a CUE names are resolved only next to the sheet, and with path
  sanitization.
- Raw sectors: user data sits at 16 (Mode 1) or 24 (Mode 2 Form 1). Mode 1 EDC is checked.
  ECC P/Q is regenerated for CHD CD hunks flagged in the ECC bitmap.

## CHD (`disc.chd`)
- Versions 3, 4 and 5. v5 has a 124-byte BE header, four compressor tags, logical bytes,
  map and metadata offsets, hunk/unit size and three SHA-1s.
- The v5 compressed map uses a 16-symbol RLE Huffman tree, then per-hunk lengths, CRC-16,
  and self and parent references. A map CRC-16 over the canonical 12-byte entries is
  checked.
- Codecs Romux decodes: `zlib` (raw deflate), `zstd`, `lzma` (lc3/lp0/pb2), `huff`, and the
  CD wrappers `cdzl`, `cdzs` and `cdlz` (ECC bitmap, base and subcode streams), `flac`
  (an `L`/`B` endianness byte, then FLAC frames of 16-bit stereo) and `cdfl` (FLAC audio
  for every frame of the hunk, written big-endian, then raw-deflate subcode). A/V codecs
  are recognized and reported.
- Metadata: `CHT2`/`CHTR` CD tracks (frames padded to multiples of 4), `CHGT`, `DVD `,
  `GDDD`. Audio is stored big-endian.
- Parent CHDs are located next to the child by matching SHA-1. A missing parent is
  reported, and reads that depend on it fail clearly.
- The writer emits v5 with zstd/zlib (DVD) or cdzs/cdzl (CD), self-references for
  duplicate hunks, a fixed-length 4-bit map tree and `CHT2`/`DVD ` metadata with checksums.
  After writing, it reads the file back and compares the raw and overall SHA-1.

## ZArchive (`archive.zar`)
- Used by Cemu and Xenia for extracted game trees. Data is split into 64 KiB blocks, each
  zstd-compressed; a block that does not shrink is stored raw at exactly 64 KiB. The file
  ends with a 0x90-byte footer. It holds six section (offset, size) pairs (compressed data,
  offset records, name table, file tree, meta directory, meta data), a 32-byte SHA-256
  integrity hash, the total size, version `0x61BF3A01` and magic `0x169F52D6`.
- Each offset record covers 16 blocks: a u64 base offset and 16 u16 `size − 1` values.
- The integrity hash is SHA-256 of the whole file with the hash field zeroed. Romux checks
  it in `verify` and writes it when repacking (`romux repack DIR --format zar`).
- Romux reports the platform of the tree inside (an Xbox 360 `default.xex` or a Wii U
  `code/`/`content/`/`meta/` layout).

## Xbox and Xbox 360 XDVDFS (`xbox.xiso`, `xbox.disc`, `xbox360.xiso`, `xbox360.disc`)
- The volume descriptor is at sector 32 of the game partition: `MICROSOFT*XBOX*MEDIA`, root
  sector, root size, time, and the magic again at 0x7EC.
- Game partition offsets: 0 for filesystem-only images ("XISO", including those made by
  extract-xiso), 0x18300000 for XGD1 full discs, 0xFD90000 for XGD2 and 0x2080000 for XGD3
  full discs. Redump-style full discs convert to filesystem-only images. The video partition
  and security sectors are not carried over.
- Directory entries form a binary tree: u16 left/right offsets in dwords, start sector,
  size, attributes (0x10 = directory), name length, name. Padding is 0xFF, and entries never
  cross sectors.
- `default.xbe` (original Xbox): the certificate is found at (cert address − base). It
  holds the title ID, the UTF-16 title name, region and version.
- `default.xex` (Xbox 360): optional header 0x00040006 (execution info) gives the media
  ID, version, base version, title ID and disc number/count. The title ID's top two bytes
  are the publisher letters, as in `EA-2226`.
- Xbox and Xbox 360 images share the ISO extension. Romux tells them apart by the
  executable at the root, and it prefers XDVDFS over a plain ISO9660 reading of the same
  file.
- The builder writes balanced BSTs ordered case-insensitively, with the smallest name at
  offset 0 as root and the remaining names in a balanced right subtree.

## Xbox 360 packages (`xbox360.stfs`): CON/LIVE/PIRS and Games on Demand
- Header magic `CON `, `LIVE` or `PIRS`. Romux reads the content type at 0x344, media ID at
  0x354, version at 0x358, title ID at 0x360, disc number/count at 0x366, data file count
  at 0x39D, descriptor type at 0x3A9 (1 = SVOD), display name at 0x411, publisher at 0x1611
  and title name at 0x1691.
- Games on Demand and installed games are SVOD packages. The header file sits next to a
  `<header>.data/` folder holding `Data0000`, `Data0001`, …. Each part starts with a master
  hash block. After it come sub-parts made of one hash block and 0xCC data blocks of 4 KiB.
  Romux joins the data blocks into one stream that contains an XDVDFS filesystem. It lists
  and extracts files from that stream and converts it to an Xbox 360 XISO.
- **Limitations:** SVOD hash blocks and package signatures are not checked. Plain STFS
  packages (DLC, saves, title updates) are inspect-only. The GoD layout is tested with
  synthetic data only.

## Nintendo 64 (`n64.z64`, `n64.v64`, `n64.n64`)
- One ROM, three byte orders, told apart by the first word:
  - `80 37 12 40`: big-endian, native (`.z64`).
  - `37 80 40 12`: 16-bit byte-swapped (`.v64`).
  - `40 12 37 80`: 32-bit little-endian (`.n64`).

  Romux converts between all three losslessly. Extensions are not trusted; the probe uses
  the first word.
- Header (native order): clock rate, entry point, CRC1 at 0x10, CRC2 at 0x14, internal name
  at 0x20 (20 bytes), game code at 0x3B (category, two-letter ID, region), version at 0x3F.
- The CIC boot chip is identified by the CRC32 of the IPL3 boot code (0x40–0x1000):
  6101, 6102/7101, 6103/7103, 6105/7105, 6106/7106 or 7102. Verification recomputes CRC1/CRC2
  over 1 MiB from 0x1000 with that CIC's seed, the way the boot code does.
- Romux lists the ROM, header and IPL3 as entries.
- **Limitations:** 64DD disk images (`.ndd`) and save files are not handled.

## Super Nintendo (`snes.sfc`, `snes.smc`)
- A cartridge image is the ROM as is (`.sfc`), or the ROM after a 512-byte copier header
  (`.smc`, `.swc`, `.fig`). Extensions are not trusted. A file whose size is 512 more
  than a multiple of 1024 has a copier header.
- The internal header has no magic. It sits at 0x7FC0 (LoROM), 0xFFC0 (HiROM) or
  0x40FFC0 (ExHiROM) in the headerless ROM. Romux scores every candidate:
  - checksum + complement = 0xFFFF: 4 points, plus 1 when the checksum is not 0 or 0xFFFF;
  - a map mode that fits the location (0x20/0x22/0x23 LoROM, 0x21/0x2A HiROM, 0x25
    ExHiROM; bit 4 = FastROM): 3;
  - a reset vector of 0x8000 or more: 2;
  - a printable title, and sane ROM size, SRAM size and country bytes: 1 each.

  The best candidate wins if it scores at least 6 of 14.
- Header fields: title (21 bytes, ASCII or JIS X 0201 katakana), map mode, chipset (memory
  type in the low nibble, coprocessor in the high nibble), ROM and SRAM size codes
  (1 KiB << n), country (region and NTSC/PAL), licensee, version, complement and checksum.
  Licensee 0x33 marks an extended header just before it, holding the maker code, the game
  code (four letters, or two in early titles, as in `SNS-8X-USA`) and the chipset subtype
  (SPC7110, ST010/011, ST018, CX4).
- Checksum: the 16-bit sum of every ROM byte. Sizes that are not a power of two are
  mirrored as the hardware sees them, for example 3 MiB = 2 MiB + the last 1 MiB twice.
- Converting SMC→SFC drops the copier header. Converting SFC→SMC adds a minimal SWC-style
  header (size in 8 KiB units, `AA BB 04` at offset 8). Either way the ROM is unchanged,
  which Romux checks by SHA-1.
- **Limitations:** interleaved dumps (some old copier formats), BS-X and Sufami Turbo
  images, and split multi-file dumps are not recognized.
