# Sony formats (PS4, PSP, PS Vita)

References: PS4 developer wiki (PKG), Vita developer wiki (VPK), PS3 developer wiki (PBP).

## PSF / `PARAM.SFO` (shared: `ps4.sfo`, `psp.sfo`, `vita.sfo`)
- `\0PSF`, u32 version, u32 key-table offset, u32 data-table offset, u32 count. Entries are
  16 bytes: u16 key offset, u16 format (0x0004 special UTF-8, 0x0204 UTF-8, 0x0404 u32),
  u32 length, u32 max length, u32 data offset.
- Platform detection uses distinctive keys: `PUBTOOLINFO`/`APP_TYPE` for PS4,
  `PSP_SYSTEM_VER`/`DISC_ID` for PSP, `PSP2_*` for Vita.

## PS4 PKG (`ps4.pkg`)
- Big-endian header with magic `\x7FCNT`: entry count at 0x10, table offset at 0x18, body
  and content offsets, a 36-character content ID at 0x40, DRM type at 0x70, content type
  at 0x74, PFS image offset/size at 0x408/0x410.
- Entry table records are 0x20 bytes: id, name offset, flags1 (bit 31 = encrypted), flags2
  (key index in bits 12–15), offset, size.
- Entry names come from the `entry_names` table when that table is unencrypted, otherwise
  from a table of well-known IDs.
- **Limitations:** encrypted entries and PFS image contents are not decrypted. Only the
  PFS superblock (magic 0x20130315, mode bit 2 = encrypted) is read. Digests and signatures
  are reported as not checked. Repacking is not offered.

## PSP UMD ISO (`psp.iso`)
- An ISO9660 image whose root holds `PSP_GAME/PARAM.SFO` or `UMD_DATA.BIN`, or whose system
  identifier is `PSP GAME`. It refines `disc.iso9660`.

## CSO (`psp.cso`)
- `CISO`, u32 header size (0x18), u64 total bytes, u32 block size, u8 version (v1 only),
  u8 alignment shift. An index of `blocks + 1` u32 entries follows. Bit 31 marks a stored
  block, and offsets are `(entry & 0x7FFFFFFF) << align`. Blocks are raw deflate.
- CSO v2 (LZ4) and ZSO are recognized as unsupported.

## PBP (`psp.pbp`)
- `\0PBP`, version, then eight u32 offsets for PARAM.SFO, ICON0.PNG, ICON1.PMF, PIC0.PNG,
  PIC1.PNG, SND0.AT3, DATA.PSP and DATA.PSAR. Each section ends where the next begins.
  `~PSP` at the start of DATA.PSP means it is encrypted. `PSISOIMG` in DATA.PSAR marks a
  PS1 classic.

## VPK (`vita.vpk`)
- A ZIP archive (stored or deflate; ZIP64 is supported for reading) that contains
  `sce_sys/param.sfo`. Every entry's CRC-32 is verified. Rebuilds are deterministic, with
  fixed timestamps and sorted names.

## `\x7FPKG` (`vita.pkg`)
- Big-endian header: revision (bit 15 = retail), platform type (1 = PS3, 2 = PSP/Vita),
  metadata offset/count, item count, total/data size, content ID at 0x30. Metadata entry 2
  is the content type.
- Items are encrypted. Romux inspects the header only.
