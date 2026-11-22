#![no_main]
//! Xbox 360 XDVDFS images (XEX metadata) and CON/LIVE/PIRS package headers.
#[path = "common.rs"]
mod common;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    for f in ["xbox360.xiso", "xbox360.stfs"] {
        common::run_format(data, Some(f));
    }
});
