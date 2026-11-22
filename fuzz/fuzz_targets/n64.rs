#![no_main]
#[path = "common.rs"]
mod common;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    for f in ["n64.z64", "n64.v64", "n64.n64"] {
        common::run_format(data, Some(f));
    }
});
