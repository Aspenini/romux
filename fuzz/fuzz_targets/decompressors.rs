#![no_main]
//! Bounded decompression must never panic or exceed its output limit.
use romux::compression::{decompress, Codec};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    for c in [Codec::Deflate, Codec::Zlib, Codec::Zstd, Codec::Lzma2, Codec::Lzma { lc: 3, lp: 0, pb: 2, dict_size: 1 << 16 }] {
        if let Ok(v) = decompress(c, data, None, 1 << 20) {
            assert!(v.len() <= 1 << 20);
        }
    }
    let _ = romux::disc::testkit::decode_huff8(data, 4096);
    let _ = romux::disc::testkit::CueSheet::parse(&String::from_utf8_lossy(data));
});
