# Nintendo Switch formats

Public references: Switchbrew NCA and Gamecard pages, the NSZ format notes (see the
specification's Appendix A), the NX binary specification (NXFormat `docs/SPEC.md`, release
1.0.4) and the NUP v1 specification (`SPEC.md` of the NUP project). These notes describe
structures only. No implementation code was copied.

## PFS0 (`switch.pfs0`, the basis of NSP/NSZ)
- Header (LE): `PFS0`, u32 entry count, u32 string-table size, u32 reserved.
- Entries of 0x18 bytes: u64 data offset (relative to the data region), u64 size, u32 name
  offset, u32 reserved.
- The data region starts after the header, entry table and string table.
- Romux's writer pads the string table so the header is a multiple of 0x20, and packs
  entries back to back.
- Validation covers counts, every span against the file, overlaps, duplicate names and
  UTF-8 names.

## HFS0 (`switch.hfs0`)
- As PFS0 with 0x40-byte entries: offset, size, name offset, hashed-region size,
  8 reserved bytes, and the SHA-256 of the first `hashed-region` bytes.
- Romux's writer pads the header to 0x200 and aligns each entry to 0x200.

## XCI / XCZ (`switch.xci`, `switch.xcz`)
- `HEAD` at 0x100. Images prefixed with a 0x1000-byte key area are detected too, with the
  header at 0x1100.
- Fields read: secure-area page, kek index, ROM-size code, header version, flags, package
  ID, valid-data-end page, root HFS0 offset/size/SHA-256, selection words and limit area.
- The root HFS0 (normally at 0xF000) lists partitions: `update`, `normal`, `secure` and
  optionally `logo`. The **`update` partition holds system software**, and Romux never
  treats it as the game's title update.
- Verification covers the root header hash, each partition header hash and every entry's
  hashed region.
- When Romux rebuilds an XCI, the signature, certificate area (0xFF-filled), initial data
  and encrypted header are not reproducible. Output carries `not_authentic`.

## NCA (`switch.nca`)
- A 0xC00-byte header, AES-128-XTS with the Nintendo tweak (big-endian sector number) and
  0x200-byte sectors. NCA3 decrypts the whole header. NCA2 decrypts each FS header as
  sector 0. NCA0 is unsupported.
- Fields: magic, distribution type, content type, key generation, key-area-key index,
  content size, program ID, content index, SDK version, rights ID, four FS entries (media
  units of 0x200), FS-header SHA-256s, and the encrypted key area.
- FS header: FS type, hash type (hierarchical SHA-256 / IVFC), encryption (none, XTS, CTR,
  CTR-EX), patch info (BKTR indirect and AES-CTR-EX tables), generation and secure value.
  The upper half of the CTR counter is these 8 bytes reversed.
- Keys: the key area is decrypted with `key_area_key_<family>_<gen>`. Rights-ID titles use
  the common-ticket title key decrypted with `titlekek_<gen>`.
- Probing never decrypts. An encrypted NCA is detected only weakly (extension plus
  media-unit-aligned size) and reported at `Low` confidence.

## CNMT and `.cnmt.xml`
- Binary header: title ID, version, meta type, extended-header size, content count. The
  extended header gives the patch ID or application ID and required versions. Content
  records are 0x38 bytes: SHA-256, content ID, 48-bit size, type, ID offset.
- Title relationships: patch = application | 0x800. Add-on base =
  (add-on & ~0xFFF) − 0x1000.

## NCZ / NSZ
- The first 0x4000 bytes are the original NCA. Then come `NCZSECTN`, a section count and
  0x40-byte sections (offset, size, crypto type, key, counter). An optional `NCZBLOCK`
  header follows (version 2, type 1, size exponent, block count, decompressed size, u32
  compressed sizes). The data is either one zstd stream or blocks. A block whose compressed
  size is at least its decompressed size is stored raw.
- Restoration re-applies AES-CTR (crypto types 3 and 4) with the stored key and counter,
  using `counter[0..8] || BE(offset >> 4)`.

## RomFS (`switch.romfs`)
- A 0x50-byte header of u64 offsets and sizes: directory hash table, directory metadata,
  file hash table, file metadata, data offset. Entries are linked lists of 32-bit offsets,
  with `0xFFFFFFFF` meaning none. Names are UTF-8 padded to 4 bytes.
- The builder uses the standard path hash (`parent ^ 123456789`, ROR 5 / XOR per byte) and
  a prime-ish bucket count.

## BKTR (apply-update)
- The indirect bucket tree uses 0x4000-byte nodes and 0x14-byte entries (virtual offset,
  physical offset, storage index). The AES-CTR-EX tree uses 0x10-byte entries (offset, …,
  generation). The patch section is read through CTR with the generation substituted in
  counter bytes 4..8.
- The virtual RomFS is read at the IVFC data level of the patch FS header. Storage 0 is the
  base title's decrypted section. Storage 1 is the patch section.
- **Tested variants:** synthetic indirect tables and CTR-EX subsections, plus a full
  replacement update. Compatibility with real retail updates has not been recorded yet; see
  `docs/compatibility.md`.

## DNCA (decrypted NCA)
- An NCA whose header is stored in plaintext with the marker `DNCA` at 0x200 (instead of
  `NCA3`), every section decrypted in place and declared as encryption type 1 (none), and
  each FS-header SHA-256 at 0x280 recomputed. Sizes, offsets, hash trees and BKTR tables are
  unchanged. DNSP/DXCI packages and NX archives carry DNCA units.
- Romux reads a DNCA without keys (it probes as `switch.nca`). It writes DNCA units when it
  builds an NX archive. AES-CTR-EX sections also decrypt their trailing BKTR tables with the
  section's plain counter. Sections with sparse storage are rejected.

## NX (`switch.nx`)
- Decrypted Switch 1/2 games in one file: each base, update and DLC is a complete
  *snapshot* (a file tree) over a pool of independent RAW or Zstandard blocks of at most
  1 MiB, deduplicated by byte comparison across files and snapshots.
- Layout: header slot A at 0 and slot B at 4096 (256 bytes each, CRC-32C, generation), the
  Data region at 8192, then one tail: Media (icons, NACP, NPDM), Catalog (applications,
  programs, snapshots, localized entries, dependencies, extensions, string pool), Manifest
  (directories, entries, files, block references, path pool), the hot block index and the
  integrity table (one CRC-32C per 16 KiB slice of uncompressed block data). Catalog,
  Manifest and index are covered by SHA-256 digests in the header.
- The reader accepts binary versions 0.2 and 0.3 (Source Resources), selects the valid slot
  with the highest generation, validates every table range, sort order, reference and
  reserved field it relies on, and rejects unknown required extensions. Every file read is
  checked against its slice CRCs. `verify --level content` decodes every block and recomputes
  every file SHA-256 and snapshot identity.
- Listing paths: `<application id>/<type>-v<version>/<file>` (types `base`, `update`,
  `dlc-<id>`), `<application id>/metadata/` (control.nacp and icons per language),
  `<application id>/source-resources/<n>/` and `extra/`.
- The writer produces compact generation-0 archives of version 0.2 from NSP/NSZ/XCI/XCZ: one
  snapshot per CNMT, holding the content set's NCAs as DNCA units (`<id>.nca`,
  `<id>.cnmt.nca`). An update snapshot also contains its base units (complete view) and a
  required-base dependency; DLC names the oldest base/update it requires. Display metadata
  comes from the newest Control data (other versions in the Snapshot Metadata History
  extension); CNMT required system versions go to Snapshot Native Metadata. Blocks are
  256 KiB chunks, zstd level 3 by default, kept only when they save 25 %.
- Not written: rebuild recipes (`0x00010006`), Source Resources, Switch 2 content (reported
  as unverified), in-place edits.

## NUP (`switch.nup`)
- Unencrypted Switch 1/2 ExeFS files and complete RomFS trees for one game: a 0x80-byte
  superblock (`NUP\x01`), a SHA-256-protected TOC (0x40-byte package records, 0x18-byte
  directories, 0x50-byte files, a flat child-slot array and a string pool), then 16-byte
  aligned extents (raw or one zstd frame with the content size) and per-package TLV meta
  blocks. Identical files share one extent.
- Package kinds: base, update (flag `standalone_update` without a base), add-on.
- The reader validates the superblock, TOC digest, every range, codec and kind, tree
  names and cycles, and the localized TLV records. `verify --level content` recomputes
  every file SHA-256 once per extent.
- Listing paths: `base/…`, `update-v<version>/…`, `addon-<title id>/…`.
- The writer extracts the primary Program's `exefs/` and `romfs/` per title. An update
  package holds the complete updated tree (BKTR applied to the base RomFS, so the base must
  be among the inputs). Meta TLVs: NPDM, build ID (NSO ModuleId), NACP and display version
  per package; title, publisher, icon and localized titles/icons from the newest Control
  data on the base package; the input file name as provenance.
- RomFS sections using compressed or sparse storage are not extracted yet.
