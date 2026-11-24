# Key material policy

Romux contains **no keys, certificates, tickets or firmware**. It never downloads, derives
to disk, logs or transmits key material, and it never extracts secrets from consoles.
Operations that need keys accept them only from the user, through a `KeyProvider`. In the
CLI that is a text file passed with `--key-file`.

```text
# name = hex   (comments start with # or ;)
header_key = <64 hex chars>
key_area_key_application_00 = <32 hex chars>
titlekek_00 = <32 hex chars>
```

Names are case-insensitive. Values live in zeroizing buffers. `Debug` output and error
messages show key *names* only. A malformed line is reported by its line number, never by
its content.

## Which operations use which keys

| Platform | Operation | Key names |
|---|---|---|
| Switch | read NCA headers (titles, versions, CNMT, split, bundle validation) | `header_key` |
| Switch | decrypt sections (list/extract NCA files, compress to NCZ, apply-update) | `key_area_key_{application,ocean,system}_XX` |
| Switch | rights-ID titles (title keys from common tickets) | `titlekek_XX` |
| Switch | build NX / NUP archives from NSP/NSZ/XCI/XCZ (decrypts every NCA) | `header_key`, `key_area_key_application_XX`, and `titlekek_XX` for rights-ID titles |
| Switch | read, list, extract or verify NX / NUP archives and DNCA units | none (the content is already decrypted) |
| Wii / vWii | partition data, WAD contents, Wii ISO/WBFS → RVZ | `wii_common_key`, `wii_korean_key`, `vwii_common_key` |
| 3DS | CIA content title keys | `ctr_common_key_<n>` (normal key) |
| 3DS | encrypted NCCH (exheader, ExeFS, RomFS) | `slot0x2CKeyX`, plus `slot0x25KeyX` / `slot0x18KeyX` / `slot0x1BKeyX` for titles that use those crypto methods, and `generator` (the key-scrambler constant) |
| 3DS | seeded NCCH titles | `seed_<program id as 16 hex digits>` (checked against the NCCH seed hash) |
| 3DS | fixed-key system NCCH | `ncch_fixed_system_key` (non-system fixed-key titles use the all-zero key and need nothing) |

`XX` is the master-key generation in two-digit lowercase hex, for example `00` or `0a`.
The 3DS names follow the usual `aes_keys.txt` layout, so such a file can be passed as is.
Romux reads only the names listed here.

## Things Romux will never do

- Decrypt personalized Switch tickets. They are bound to a device; Romux reports them as
  unsupported.
- Ship or guess any console secret. That includes the 3DS key-scrambler constant, which
  Romux reads from your key file (`generator`) like any other key.
- Implement PS4 PKG/PFS decryption, PS Vita PKG decryption or Wii U disc decryption.
- Produce new valid signatures. Rebuilt or modified packages are labeled
  `modified_unsigned` / `not_authentic`.

Decompressing NSZ/XCZ/NCZ needs **no** keys, because the section keys are stored in the NCZ
section table, exactly as the original compressor wrote them. Romux re-encrypts with them
and checks every restored NCA against its content ID.
