#![no_main]
#[path = "common.rs"]
mod common;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    for f in ["snes.sfc", "snes.smc"] {
        common::run_format(data, Some(f));
    }
});
