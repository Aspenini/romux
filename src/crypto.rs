//! Cryptography (formerly the `romux-crypto` crate)
//!
//! Standard cryptographic primitives used by Romux format backends and the
//! [`KeyFile`] key provider for user-supplied key material.
//!
//! Policy: Romux ships no keys, certificates or firmware; it never downloads, logs or
//! persists key material; owned secrets are zeroized on drop. Hashes are distinguished
//! from signatures throughout the API, and nothing here implements access-control
//! circumvention — only standard ciphers applied with keys the user already possesses.

use crate::{ByteProgress, DataSource, Error, KeyProvider, Result, SecretBytes};
use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use zeroize::Zeroizing;

pub use crate::keys::{NoKeys, fixed_key};

// ---------------------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}
pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashAlg {
    Sha256,
    Sha1,
    Md5,
    Crc32,
}

impl HashAlg {
    pub fn name(&self) -> &'static str {
        match self {
            HashAlg::Sha256 => "sha256",
            HashAlg::Sha1 => "sha1",
            HashAlg::Md5 => "md5",
            HashAlg::Crc32 => "crc32",
        }
    }
}

/// Incremental hasher over any supported algorithm.
pub enum StreamHasher {
    Sha256(Sha256),
    Sha1(Sha1),
    Md5(Md5),
    Crc32(crc32fast::Hasher),
}

impl StreamHasher {
    pub fn new(alg: HashAlg) -> Self {
        match alg {
            HashAlg::Sha256 => StreamHasher::Sha256(Sha256::new()),
            HashAlg::Sha1 => StreamHasher::Sha1(Sha1::new()),
            HashAlg::Md5 => StreamHasher::Md5(Md5::new()),
            HashAlg::Crc32 => StreamHasher::Crc32(crc32fast::Hasher::new()),
        }
    }
    pub fn update(&mut self, d: &[u8]) {
        match self {
            StreamHasher::Sha256(h) => h.update(d),
            StreamHasher::Sha1(h) => h.update(d),
            StreamHasher::Md5(h) => h.update(d),
            StreamHasher::Crc32(h) => h.update(d),
        }
    }
    pub fn finish(self) -> Vec<u8> {
        match self {
            StreamHasher::Sha256(h) => h.finalize().to_vec(),
            StreamHasher::Sha1(h) => h.finalize().to_vec(),
            StreamHasher::Md5(h) => h.finalize().to_vec(),
            StreamHasher::Crc32(h) => h.finalize().to_be_bytes().to_vec(),
        }
    }
}

impl std::io::Write for StreamHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Hash a range of a source in bounded chunks.
pub fn hash_range(
    source: &dyn DataSource,
    offset: u64,
    len: u64,
    alg: HashAlg,
    progress: Option<&mut ByteProgress<'_>>,
) -> Result<Vec<u8>> {
    let mut h = StreamHasher::new(alg);
    let mut buf = vec![0u8; (1usize << 20).min(len.max(1) as usize)];
    let mut done = 0u64;
    let mut progress = progress;
    while done < len {
        let n = ((len - done) as usize).min(buf.len());
        source.read_exact_at(offset + done, &mut buf[..n])?;
        h.update(&buf[..n]);
        done += n as u64;
        if let Some(p) = progress.as_deref_mut() {
            p.advance(n as u64)?;
        }
    }
    Ok(h.finish())
}

// ---------------------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------------------

fn cipher(key: &[u8; 16]) -> Aes128 {
    Aes128::new(GenericArray::from_slice(key))
}

fn check_blocks(data: &[u8]) -> Result<()> {
    if !data.len().is_multiple_of(16) {
        return Err(Error::invalid_arg("AES block operation on data not a multiple of 16 bytes"));
    }
    Ok(())
}

/// AES-128-ECB decrypt in place.
pub fn ecb_decrypt(key: &[u8; 16], data: &mut [u8]) -> Result<()> {
    check_blocks(data)?;
    let c = cipher(key);
    for b in data.chunks_exact_mut(16) {
        c.decrypt_block(GenericArray::from_mut_slice(b));
    }
    Ok(())
}

/// AES-128-ECB encrypt in place.
pub fn ecb_encrypt(key: &[u8; 16], data: &mut [u8]) -> Result<()> {
    check_blocks(data)?;
    let c = cipher(key);
    for b in data.chunks_exact_mut(16) {
        c.encrypt_block(GenericArray::from_mut_slice(b));
    }
    Ok(())
}

/// AES-128-CBC decrypt in place.
pub fn cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    check_blocks(data)?;
    let c = cipher(key);
    let mut prev = *iv;
    for b in data.chunks_exact_mut(16) {
        let mut cur = [0u8; 16];
        cur.copy_from_slice(b);
        c.decrypt_block(GenericArray::from_mut_slice(b));
        for i in 0..16 {
            b[i] ^= prev[i];
        }
        prev = cur;
    }
    Ok(())
}

/// AES-128-CBC encrypt in place.
pub fn cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    check_blocks(data)?;
    let c = cipher(key);
    let mut prev = *iv;
    for b in data.chunks_exact_mut(16) {
        for i in 0..16 {
            b[i] ^= prev[i];
        }
        c.encrypt_block(GenericArray::from_mut_slice(b));
        prev.copy_from_slice(b);
    }
    Ok(())
}

/// Add `n` to a 128-bit big-endian counter.
pub fn ctr_add(ctr: [u8; 16], n: u64) -> [u8; 16] {
    let v = u128::from_be_bytes(ctr).wrapping_add(n as u128);
    v.to_be_bytes()
}

/// AES-128-CTR keystream XOR in place. `byte_offset` is the position of `data[0]` in the
/// stream that starts with counter `ctr0` (counter increments once per 16-byte block).
pub fn ctr_apply(key: &[u8; 16], ctr0: [u8; 16], byte_offset: u64, data: &mut [u8]) {
    let c = cipher(key);
    let mut block = byte_offset / 16;
    let mut skip = (byte_offset % 16) as usize;
    let mut i = 0usize;
    // Process in batches of blocks for throughput.
    let mut ks = vec![GenericArray::from([0u8; 16]); 256];
    while i < data.len() {
        let remaining = data.len() - i + skip;
        let nblocks = remaining.div_ceil(16).min(ks.len());
        for (k, b) in ks.iter_mut().take(nblocks).enumerate() {
            *b = GenericArray::from(ctr_add(ctr0, block + k as u64));
        }
        c.encrypt_blocks(&mut ks[..nblocks]);
        for b in ks.iter().take(nblocks) {
            for &kb in b.iter().skip(skip) {
                if i >= data.len() {
                    break;
                }
                data[i] ^= kb;
                i += 1;
            }
            skip = 0;
        }
        block += nblocks as u64;
    }
}

fn gf_mul_alpha(t: &mut [u8; 16]) {
    let mut carry = 0u8;
    for b in t.iter_mut() {
        let nc = *b >> 7;
        *b = (*b << 1) | carry;
        carry = nc;
    }
    if carry != 0 {
        t[0] ^= 0x87;
    }
}

/// AES-128-XTS with the Nintendo tweak convention (sector number encoded big-endian).
pub struct XtsNintendo {
    k1: Aes128,
    k2: Aes128,
}

impl XtsNintendo {
    /// `key` is 32 bytes: data key followed by tweak key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::invalid_arg("XTS key must be 32 bytes"));
        }
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&key[..16]);
        b.copy_from_slice(&key[16..]);
        let r = XtsNintendo { k1: cipher(&a), k2: cipher(&b) };
        zeroize::Zeroize::zeroize(&mut a);
        zeroize::Zeroize::zeroize(&mut b);
        Ok(r)
    }

    fn run(&self, data: &mut [u8], first_sector: u64, sector_size: usize, decrypt: bool) -> Result<()> {
        if sector_size == 0 || !sector_size.is_multiple_of(16) || !data.len().is_multiple_of(sector_size) {
            return Err(Error::invalid_arg("XTS data must be whole sectors"));
        }
        for (i, sector) in data.chunks_exact_mut(sector_size).enumerate() {
            let mut t = GenericArray::from(((first_sector + i as u64) as u128).to_be_bytes());
            self.k2.encrypt_block(&mut t);
            let mut tw = [0u8; 16];
            tw.copy_from_slice(&t);
            for b in sector.chunks_exact_mut(16) {
                for j in 0..16 {
                    b[j] ^= tw[j];
                }
                if decrypt {
                    self.k1.decrypt_block(GenericArray::from_mut_slice(b));
                } else {
                    self.k1.encrypt_block(GenericArray::from_mut_slice(b));
                }
                for j in 0..16 {
                    b[j] ^= tw[j];
                }
                gf_mul_alpha(&mut tw);
            }
        }
        Ok(())
    }

    pub fn decrypt(&self, data: &mut [u8], first_sector: u64, sector_size: usize) -> Result<()> {
        self.run(data, first_sector, sector_size, true)
    }
    pub fn encrypt(&self, data: &mut [u8], first_sector: u64, sector_size: usize) -> Result<()> {
        self.run(data, first_sector, sector_size, false)
    }
}

// ---------------------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------------------

/// Keys loaded from a user-supplied text file of `name = hex` lines.
///
/// Lines starting with `#` or `;` are comments. Names are case-insensitive. Values are
/// held in zeroizing buffers and never printed (`Debug` shows names only).
#[derive(Default)]
pub struct KeyFile {
    keys: BTreeMap<String, SecretBytes>,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile").field("names", &self.keys.keys().collect::<Vec<_>>()).finish()
    }
}

impl KeyFile {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse key text. Malformed lines are reported by line number only (never contents).
    pub fn parse(text: &str) -> Result<Self> {
        let mut kf = KeyFile::new();
        for (no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
                continue;
            }
            let (name, value) = match line.split_once('=').or_else(|| line.split_once(':')) {
                Some(p) => p,
                None => return Err(Error::invalid_arg(format!("key file line {} is not `name = hex`", no + 1))),
            };
            let value: String = value.trim().chars().filter(|c| !c.is_whitespace()).collect();
            let bytes =
                crate::parse_hex(&value).ok_or_else(|| Error::invalid_arg(format!("key file line {} has an invalid hex value", no + 1)))?;
            kf.keys.insert(name.trim().to_ascii_lowercase(), Zeroizing::new(bytes));
        }
        Ok(kf)
    }

    /// Load a key file from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = Zeroizing::new(std::fs::read_to_string(path.as_ref()).map_err(|e| Error::from(e).with_operation("load key file"))?);
        Self::parse(&text)
    }

    /// Insert a key programmatically.
    pub fn insert(&mut self, name: &str, value: &[u8]) {
        self.keys.insert(name.to_ascii_lowercase(), Zeroizing::new(value.to_vec()));
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl KeyProvider for KeyFile {
    fn get(&self, name: &str) -> Option<SecretBytes> {
        self.keys.get(&name.to_ascii_lowercase()).map(|v| Zeroizing::new(v.to_vec()))
    }
    fn names(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
}

/// Lookup of a 16-byte key by name.
pub fn key16(p: &dyn KeyProvider, name: &str) -> Option<Zeroizing<[u8; 16]>> {
    fixed_key::<16>(p, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_known_answer() {
        // FIPS-197 C.1 AES-128 test vector.
        let key: [u8; 16] = crate::parse_hex("000102030405060708090a0b0c0d0e0f").unwrap().try_into().unwrap();
        let mut b = crate::parse_hex("00112233445566778899aabbccddeeff").unwrap();
        ecb_encrypt(&key, &mut b).unwrap();
        assert_eq!(crate::hex(&b), "69c4e0d86a7b0430d8cdb78070b4c55a");
        ecb_decrypt(&key, &mut b).unwrap();
        assert_eq!(crate::hex(&b), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn ctr_offsets_consistent() {
        let key = [7u8; 16];
        let ctr = [1u8; 16];
        let mut whole = vec![0u8; 1000];
        ctr_apply(&key, ctr, 0, &mut whole);
        let mut part = vec![0u8; 333];
        ctr_apply(&key, ctr, 517, &mut part);
        assert_eq!(&whole[517..850], &part[..]);
    }

    #[test]
    fn cbc_xts_roundtrip() {
        let key = [3u8; 16];
        let iv = [9u8; 16];
        let orig: Vec<u8> = (0..64u8).collect();
        let mut d = orig.clone();
        cbc_encrypt(&key, &iv, &mut d).unwrap();
        assert_ne!(d, orig);
        cbc_decrypt(&key, &iv, &mut d).unwrap();
        assert_eq!(d, orig);
        let x = XtsNintendo::new(&[5u8; 32]).unwrap();
        let orig: Vec<u8> = (0..0x400u32).map(|i| i as u8).collect();
        let mut d = orig.clone();
        x.encrypt(&mut d, 2, 0x200).unwrap();
        let mut second = d[0x200..].to_vec();
        x.decrypt(&mut second, 3, 0x200).unwrap();
        assert_eq!(&second[..], &orig[0x200..]);
    }

    #[test]
    fn keyfile_parse_and_debug_hides_values() {
        let kf = KeyFile::parse("# c\nheader_key = 00112233\nOther: aa bb\n").unwrap();
        assert_eq!(kf.get("HEADER_KEY").unwrap().as_slice(), &[0, 0x11, 0x22, 0x33]);
        assert_eq!(kf.get("other").unwrap().as_slice(), &[0xaa, 0xbb]);
        let dbg = format!("{kf:?}");
        assert!(!dbg.contains("0011"));
        assert!(KeyFile::parse("bad line").is_err());
    }
}
