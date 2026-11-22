//! Key-provider interface. Romux never ships, derives-to-disk, downloads, or logs key material.
//!
//! Only capabilities that genuinely need keys consult a [`KeyProvider`]; plain archive
//! operations never do.

use zeroize::Zeroizing;

/// Owned secret bytes that are zeroized on drop.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// A source of named, user-supplied key material.
pub trait KeyProvider: Send + Sync {
    /// Look up a key by its conventional name (e.g. `header_key`). Names are case-insensitive.
    fn get(&self, name: &str) -> Option<SecretBytes>;
    /// Names of available keys (names only, never values), for diagnostics.
    fn names(&self) -> Vec<String>;
}

/// A provider with no keys.
pub struct NoKeys;
impl KeyProvider for NoKeys {
    fn get(&self, _: &str) -> Option<SecretBytes> {
        None
    }
    fn names(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Fetch a key of an exact length.
pub fn fixed_key<const N: usize>(p: &dyn KeyProvider, name: &str) -> Option<Zeroizing<[u8; N]>> {
    let v = p.get(name)?;
    if v.len() != N {
        return None;
    }
    let mut a = Zeroizing::new([0u8; N]);
    a.copy_from_slice(&v);
    Some(a)
}
