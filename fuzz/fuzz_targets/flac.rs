#![no_main]
//! CHD FLAC hunk decoding must reject malformed frames without panicking.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = romux::disc::testkit::decode_chd_flac(data, 2352 * 4);
    let _ = romux::disc::testkit::decode_stereo16(data, 4096);
});
