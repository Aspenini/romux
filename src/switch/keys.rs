//! Switch key-material lookup by conventional names.
//!
//! Romux ships no keys. Users supply a key file with entries such as `header_key`,
//! `key_area_key_application_XX`, `titlekek_XX`.

use crate::{Error, KeyProvider, Result};
use zeroize::Zeroizing;

pub const HEADER_KEY: &str = "header_key";

/// Key-area encryption key families.
pub fn kaek_family(index: u8) -> &'static str {
    match index {
        0 => "application",
        1 => "ocean",
        _ => "system",
    }
}

pub fn key_area_key_name(index: u8, generation: u8) -> String {
    format!("key_area_key_{}_{:02x}", kaek_family(index), generation)
}

pub fn titlekek_name(generation: u8) -> String {
    format!("titlekek_{generation:02x}")
}

fn fixed<const N: usize>(p: &dyn KeyProvider, name: &str) -> Result<Zeroizing<[u8; N]>> {
    match p.get(name) {
        Some(v) if v.len() == N => {
            let mut a = Zeroizing::new([0u8; N]);
            a.copy_from_slice(&v);
            Ok(a)
        }
        Some(_) => Err(Error::invalid_arg(format!("key {name} has the wrong length (expected {N} bytes)"))),
        None => Err(Error::needs_keys(format!("key material `{name}` is required"))),
    }
}

pub fn header_key(p: &dyn KeyProvider) -> Result<Zeroizing<[u8; 32]>> {
    fixed::<32>(p, HEADER_KEY)
}

pub fn key_area_key(p: &dyn KeyProvider, index: u8, generation: u8) -> Result<Zeroizing<[u8; 16]>> {
    fixed::<16>(p, &key_area_key_name(index, generation))
}

pub fn titlekek(p: &dyn KeyProvider, generation: u8) -> Result<Zeroizing<[u8; 16]>> {
    fixed::<16>(p, &titlekek_name(generation))
}

pub fn has_header_key(p: &dyn KeyProvider) -> bool {
    p.get(HEADER_KEY).is_some_and(|k| k.len() == 32)
}
