# Fixtures

Romux keeps **no binary game images** in the repository. All fixtures are synthesized at
test time from documented layouts. See:

- `tests/integration/fixtures.rs`: one specimen per supported container (ISO9660, PSP UMD,
  CHD, PFS0, CSO, PS4 PKG, XISO, GameCube, RVZ, U8, CCI, VPK, WUX);
- `romux::switch::testkit`: encrypted NCA3 archives, tickets and content IDs built with
  obviously fake keys (`[0x11; 32]`, …);
- `romux::disc::testkit::make_mode1_sector`: raw CD sectors with valid EDC and ECC.

These specimens are original and redistributable. Users who run the opt-in compatibility
tests (`tests/compatibility`) must supply real samples themselves and keep them out of the
repository.
