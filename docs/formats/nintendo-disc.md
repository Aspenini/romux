# GameCube, Wii, Wii U, 3DS

References: WiiBrew (WAD, U8), Dolphin's WIA/RVZ notes, 3dbrew (NCSD, CIA), and the wudd
README (WUX).

## GameCube / Wii disc header
- Game ID at 0, maker at 4, disc number at 6, version at 7. Wii magic 0x5D1C9EA3 sits at
  0x18 and GameCube magic 0xC2339F3D at 0x1C. The title is at 0x20. DOL, FST offset and FST
  size are at 0x420, 0x424 and 0x428. Wii partition headers store these shifted right by 2.
- FST entries are 12 bytes: type, 24-bit name offset, offset/parent, size/next index.
- Extraction layout: `sys/boot.bin`, `sys/bi2.bin`, `sys/apploader.img` (0x20 + size +
  trailer), `sys/main.dol` (size from its 18 sections), `sys/fst.bin`, `files/...`.

## Wii partitions
- The partition table at 0x40000 has four groups (count, offset >> 2). Each entry is a
  partition offset >> 2 plus a type.
- Partition header: ticket (encrypted title key at 0x1BF, title ID at 0x1DC, common-key
  index at 0x1F1), TMD size/offset, cert, H3 offset, data offset/size.
- Data is in 0x8000-byte clusters: a 0x400-byte hash block (AES-CBC, IV 0), then 0x7C00
  data bytes (AES-CBC, IV taken from offset 0x3D0 of the encrypted cluster).
- Verification: SHA-1(H3) is compared with TMD content 0, which needs no key. With the
  common key, every cluster's H0 (31 blocks), H1, H2 and H3 are checked.

## WBFS (`wii.wbfs`)
- `WBFS`, n_hd_sectors (BE), hd-sector shift, wbfs-sector shift. A disc table starts at
  0xC. Disc info lives at hd-sector 1: a 0x100-byte header copy, then a BE u16 block table
  for 286864 >> (shift − 15) blocks. Block 0 means "not stored".

## WIA / RVZ (`wii.wia`, `wii.rvz`)
- Header 1 (0x48 bytes) and header 2 (0xDC bytes), each SHA-1 checked. Header 2 holds the
  disc type, compression, level, chunk size, the first 0x80 disc bytes, and the partition,
  raw-data and group tables. The tables are compressed with the image codec.
- RVZ group entries: offset >> 2, size (bit 31 = compressed), packed size. A packed group is
  a sequence of `u32 BE size` runs. When bit 31 is set the run is junk, regenerated from a
  68-byte seed by the lagged Fibonacci generator (K = 521, J = 32) advanced to
  `offset % 0x8000`. Otherwise the run is literal data.
- Wii images store partition data decrypted, along with the title key. Romux lists
  partition files straight from that data (no key needed). To restore an ISO it rebuilds
  each 2 MiB group: H0 hashes over the 31 KiB payloads, H1 and H2 over those, with the
  stored hash exceptions applied. It then re-encrypts every sector with AES-CBC and checks
  the regenerated H2 hashes against the partition's H3 table before writing. Sectors the
  image does not store are hashed as zeros.
- Writing Wii RVZ (`romux wii convert game.wbfs --format rvz -o game.rvz --key-file keys.txt`,
  also from an ISO) decrypts each partition's title key with the user's common key. Each
  partition is then stored as decrypted 0x7C00-byte payloads, in 2 MiB groups that each
  hold exactly one 64-sector hash group, so there is one exception list per group. Every
  20-byte slot of a stored hash block that differs from the regenerated one is kept as an
  exception, including the padding slots at 0x26C, 0x320/0x32C and 0x3E0/0x3EC. Scrubbed
  sectors (encrypted zeros, as in WBFS images) therefore round-trip exactly. The first
  data entry ends after the FST (the management data), rounded up to a group. Groups that
  are all zero with no exceptions are stored empty. Everything outside partition data goes
  in raw data entries. Romux reads the result back and requires a byte-identical image
  before it keeps the file. The default zstd level is 5; `--option level=N` changes it.
- Junk packing (GameCube and Wii writers): discs fill unused space with LFG output
  re-seeded at every 0x8000 bytes of data space. That is disc offsets for GameCube and
  unpartitioned areas, and decrypted payload offsets inside Wii partitions. Junk words obey
  `w[t] = w[t−521] ^ w[t−32]`, which is used as a cheap pre-check. For each block, Romux
  takes an aligned 2084-byte window, undoes `4 + m` generator steps to reach the initial
  state, and rebuilds the 17-word seed. The init mask hides bits 16–17 of each word; for
  words 1–16 they follow from bits 7–8 of later expanded words, and word 0's hidden bits
  never reach the output. The block is then regenerated from that seed. Only exactly
  matching ranges of at least 512 bytes become junk runs, so a wrong guess can never alter
  data. Junk that never fills an aligned window (under about 4 KiB at a block's end) stays
  literal.
- **Limitations:** WIA purge and bzip2 compression are unsupported. Acceptance of
  Romux-written RVZ files by Dolphin is not yet verified.

## WAD (`wii.wad`)
- Header size 0x20, type `Is`/`ib`/`Bk`, then cert, ticket, TMD, data and footer, each
  aligned to 0x40. TMD content records start at 0x1E4 (0x24 bytes each, SHA-1 at +0x10).
  Contents use AES-CBC with the title key and an IV of the content index.

## U8 (`wii.u8`)
- Magic 0x55AA382D, root node offset, node + string table size, data offset. Nodes are 12
  bytes (BE).

## Wii U (`wiiu.wud`, `wiiu.wux`, `wiiu.title`)
- WUD: a raw 25,025,314,816-byte image whose product code `WUP-…` is at offset 0. The rest
  is encrypted.
- WUX: header `WUX0`, 0x1099D02E, sector size, padding, u64 uncompressed size, flags
  (0x20 bytes). A u32 sector-index table follows, with sector data at the next aligned
  offset.
- TMD: signature type 0x10004, version byte 1 at 0x180, title ID at 0x18C, title version at
  0x1DC, count at 0x1DE. Content records are 0x30 bytes at 0xB04.

## 3DS (`3ds.cci`, `3ds.ncch`, `3ds.cia`)
- NCSD: `NCSD` at 0x100, image size, media ID, eight partition (offset, size) pairs in
  media units.
- NCCH: `NCCH` at 0x100. Program ID is at 0x118 and the product code at 0x150. Flags are at
  0x188: [5] content type, [6] unit-size exponent, [7] bit 2 = NoCrypto. ExeFS is at 0x1A0
  and RomFS at 0x1B0, followed by the superblock hashes.
- ExeFS: 10 entries of (name, offset, size), with SHA-256 stored in reverse order at 0xC0.
  Data starts at 0x200.
- RomFS: an IVFC header whose level-3 data sits at `align(0x60 + master hash size, level-3
  block size)`. The 0x28-byte level-3 header has u32 fields. Names are UTF-16LE.
- CIA: header 0x2020 with a content-index bitmap, then cert, ticket, TMD, content and meta,
  each aligned to 64. Content chunks are 0x30 bytes with SHA-256. Encrypted contents need
  the normal common key `ctr_common_key_<n>`.
- Encrypted NCCH (AES-128-CTR) is decrypted when you supply the key material (see
  [key material](../key-material.md)). Normal keys come from the key scrambler with KeyY =
  the first 16 signature bytes. The exheader, ExeFS header and ExeFS files other than
  `.code` use slot 0x2C. `.code` and the RomFS use the crypto method's slot (`flags[3]`:
  0x00 → 0x2C, 0x01 → 0x25, 0x0A → 0x18, 0x0B → 0x1B). Seeded titles (`flags[7]` bit 5)
  use KeyY = SHA-256(KeyY ‖ seed)[0..16], after checking the seed against 0x114. Counters
  are the partition ID (big-endian) plus a section byte (1, 2 or 3) for versions 0 and 2,
  and the partition ID (little-endian) plus the section byte offset for version 1. The
  fixed-key flag selects the all-zero key, or `ncch_fixed_system_key` for system titles.
- A decrypted NCCH is presented as its NoCrypto equivalent, with `flags[3]` cleared and
  `flags[7]` set to NoCrypto, so wrong keys fail the hash checks instead of passing silently.
- **Limitations:** CCI→CIA writes zero signatures and is not installable on retail systems.
  Decryption is tested with synthetic keys against the documented layout. Real encrypted
  dumps have not been checked yet.
