//! NCCH content decryption with user-supplied key material.
//!
//! Encrypted NCCH regions are AES-128-CTR. The normal key for each region comes from the
//! console key scrambler: `KeyN = ROL128((ROL128(KeyX, 2) ^ KeyY) + generator, 87)`, with
//! `KeyY` taken from the first 16 bytes of the NCCH signature. The exheader, the ExeFS
//! header and the ExeFS files other than `.code` use KeyX slot 0x2C; `.code` and the RomFS
//! use the slot chosen by the header's crypto method (0x2C, 0x25, 0x18 or 0x1B), and titles
//! flagged with a seed derive their secondary KeyY from `SHA-256(KeyY || seed)`.
//!
//! Romux ships none of this material. Names follow the common `aes_keys.txt` layout:
//! `slot0x2CKeyX`, `slot0x25KeyX`, `slot0x18KeyX`, `slot0x1BKeyX`, `generator`, plus
//! `seed_<program id>` for seeded titles. Titles using the fixed test key (non-system,
//! all zeros) need no keys; the fixed *system* key is read from `ncch_fixed_system_key`.
//!
//! [`DecryptedNcch`] presents an encrypted NCCH as the equivalent NoCrypto image (header
//! flags patched), so listing, extraction, hash verification and CIA repackaging reuse the
//! plaintext code paths. Wrong keys show up as hash mismatches, not silent garbage.

use crate::n3ds::ncch::NcchHeader;
use crate::{DataSource, Error, KeyProvider, Result, SharedSource, read_vec};
use std::sync::Arc;
use zeroize::Zeroizing;

const FLAG_FIXED_KEY: u8 = 0x01;
const FLAG_NO_CRYPTO: u8 = 0x04;
const FLAG_SEED: u8 = 0x20;

fn key16(keys: &dyn KeyProvider, name: &str) -> Result<Zeroizing<[u8; 16]>> {
    crate::crypto::fixed_key::<16>(keys, name).ok_or_else(|| Error::needs_keys(format!("encrypted NCCH needs the 16-byte key `{name}`")))
}

/// The 3DS AES key scrambler.
pub fn scramble(key_x: &[u8; 16], key_y: &[u8; 16], generator: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    let x = u128::from_be_bytes(*key_x);
    let y = u128::from_be_bytes(*key_y);
    let c = u128::from_be_bytes(*generator);
    Zeroizing::new((x.rotate_left(2) ^ y).wrapping_add(c).rotate_left(87).to_be_bytes())
}

/// KeyX slot used by an NCCH crypto method byte (`flags[3]`).
pub fn method_slot(method: u8) -> Option<u8> {
    match method {
        0x00 => Some(0x2C),
        0x01 => Some(0x25),
        0x0A => Some(0x18),
        0x0B => Some(0x1B),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Exheader = 1,
    Exefs = 2,
    Romfs = 3,
}

/// Region keys and counters for one NCCH.
pub struct NcchCrypto {
    key0: Zeroizing<[u8; 16]>,
    key1: Zeroizing<[u8; 16]>,
    partition_id: u64,
    version: u16,
    exheader: Option<(u64, u64)>,
    exefs: Option<(u64, u64)>,
    code: Option<(u64, u64)>,
    romfs: Option<(u64, u64)>,
}

impl NcchCrypto {
    /// Derive the region keys. `raw` is the 0x200-byte NCCH header.
    pub fn new(h: &NcchHeader, raw: &[u8], keys: &dyn KeyProvider) -> Result<Self> {
        if h.no_crypto() {
            return Err(Error::invalid_arg("NCCH is not encrypted"));
        }
        let flags = h.flags;
        let (key0, key1) = if flags[7] & FLAG_FIXED_KEY != 0 {
            let k = if (h.program_id >> 32) & 0x10 != 0 { key16(keys, "ncch_fixed_system_key")? } else { Zeroizing::new([0u8; 16]) };
            (k.clone(), k)
        } else {
            let slot = method_slot(flags[3]).ok_or_else(|| Error::unsupported(format!("unknown NCCH crypto method 0x{:02x}", flags[3])))?;
            let generator = key16(keys, "generator")?;
            let mut key_y = Zeroizing::new([0u8; 16]);
            key_y.copy_from_slice(&raw[..16]);
            let key0 = scramble(&*key16(keys, "slot0x2CKeyX")?, &key_y, &generator);
            let mut key_y2 = key_y.clone();
            if flags[7] & FLAG_SEED != 0 {
                let name = format!("seed_{:016x}", h.program_id);
                let seed = key16(keys, &name)?;
                let mut check = Zeroizing::new(seed.to_vec());
                check.extend_from_slice(&h.program_id.to_le_bytes());
                if crate::crypto::sha256(&check)[..4] != raw[0x114..0x118] {
                    return Err(Error::integrity(format!("`{name}` does not match the NCCH seed check")));
                }
                let mut ys = Zeroizing::new(key_y.to_vec());
                ys.extend_from_slice(&seed[..]);
                key_y2.copy_from_slice(&crate::crypto::sha256(&ys)[..16]);
            }
            let key1 = if slot == 0x2C && flags[7] & FLAG_SEED == 0 {
                key0.clone()
            } else {
                scramble(&*key16(keys, &format!("slot0x{slot:02X}KeyX"))?, &key_y2, &generator)
            };
            (key0, key1)
        };
        let some = |r: (u64, u64, u64)| (r.1 > 0).then_some((r.0, r.1));
        Ok(NcchCrypto {
            key0,
            key1,
            partition_id: h.partition_id,
            version: h.version,
            exheader: (h.exheader_size > 0).then_some((0x200, 0x800)),
            exefs: some(h.exefs),
            code: None,
            romfs: some(h.romfs),
        })
    }

    /// Record where `.code` lives, from the plaintext 0x200-byte ExeFS header.
    pub fn set_code(&mut self, exefs_header: &[u8]) -> Result<()> {
        let Some((base, len)) = self.exefs else { return Ok(()) };
        for i in 0..10 {
            let e = &exefs_header[i * 16..i * 16 + 16];
            if &e[..8] == b".code\0\0\0" {
                let off = 0x200 + crate::binary::u32le(e, 8)? as u64;
                let size = (crate::binary::u32le(e, 12)? as u64).div_ceil(0x200) * 0x200;
                if off + size > len {
                    return Err(Error::bounds("ExeFS .code extends beyond the ExeFS"));
                }
                self.code = Some((base + off, size));
            }
        }
        Ok(())
    }

    fn counter(&self, s: Section, section_offset: u64) -> [u8; 16] {
        let mut c = [0u8; 16];
        if self.version == 1 {
            c[..8].copy_from_slice(&self.partition_id.to_le_bytes());
            c[12..].copy_from_slice(&(section_offset as u32).to_be_bytes());
        } else {
            c[..8].copy_from_slice(&self.partition_id.to_be_bytes());
            c[8] = s as u8;
        }
        c
    }

    /// XOR the keystream into `buf`, which holds NCCH bytes starting at `offset`.
    pub fn apply(&self, offset: u64, buf: &mut [u8]) {
        let end = offset + buf.len() as u64;
        let mut run = |start: u64, len: u64, section: Section, base: u64, key: &[u8; 16]| {
            let (a, b) = (start.max(offset), (start + len).min(end));
            if a < b {
                let ctr = self.counter(section, base);
                crate::crypto::ctr_apply(key, ctr, a - base, &mut buf[(a - offset) as usize..(b - offset) as usize]);
            }
        };
        if let Some((o, l)) = self.exheader {
            run(o, l, Section::Exheader, o, &self.key0);
        }
        if let Some((o, l)) = self.exefs {
            match self.code {
                Some((co, cl)) => {
                    run(o, co - o, Section::Exefs, o, &self.key0);
                    run(co, cl, Section::Exefs, o, &self.key1);
                    run(co + cl, o + l - (co + cl), Section::Exefs, o, &self.key0);
                }
                None => run(o, l, Section::Exefs, o, &self.key0),
            }
        }
        if let Some((o, l)) = self.romfs {
            run(o, l, Section::Romfs, o, &self.key1);
        }
    }
}

/// Header bytes rewritten to describe the decrypted image (NoCrypto, no seed, no fixed key).
pub fn plain_flags(flags: [u8; 8]) -> [u8; 8] {
    let mut f = flags;
    f[3] = 0;
    f[7] = (f[7] & !(FLAG_FIXED_KEY | FLAG_SEED)) | FLAG_NO_CRYPTO;
    f
}

/// An encrypted NCCH presented as its NoCrypto equivalent.
pub struct DecryptedNcch {
    src: SharedSource,
    crypto: NcchCrypto,
    flags: [u8; 8],
}

impl DecryptedNcch {
    pub fn open(src: SharedSource, keys: &dyn KeyProvider) -> Result<Self> {
        let raw = read_vec(src.as_ref(), 0, 0x200, 0x200)?;
        let h = NcchHeader::parse(src.as_ref())?;
        let mut crypto = NcchCrypto::new(&h, &raw, keys)?;
        if let Some((o, _)) = crypto.exefs {
            let mut eh = read_vec(src.as_ref(), o, 0x200, 0x200)?;
            crypto.apply(o, &mut eh);
            crypto.set_code(&eh)?;
        }
        Ok(DecryptedNcch { src, crypto, flags: plain_flags(h.flags) })
    }

    pub fn shared(src: SharedSource, keys: &dyn KeyProvider) -> Result<SharedSource> {
        Ok(Arc::new(Self::open(src, keys)?))
    }
}

impl DataSource for DecryptedNcch {
    fn len(&self) -> Result<u64> {
        self.src.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        self.src.read_exact_at(offset, out)?;
        self.crypto.apply(offset, out);
        let end = offset + out.len() as u64;
        for (i, b) in self.flags.iter().enumerate() {
            let p = 0x188 + i as u64;
            if p >= offset && p < end {
                out[(p - offset) as usize] = *b;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyFile;
    use crate::n3ds::{N3DS_CCI, N3DS_CIA, N3dsBackend, testkit};
    use crate::{Backend, ConvertRequest, JobContext, MemorySource, OpenContext, Registry, VerifyLevel, read_vec as rv};

    fn keys(x2c: u8, seed: Option<(u64, [u8; 16])>) -> KeyFile {
        let mut k = KeyFile::new();
        k.insert("slot0x2CKeyX", &[x2c; 16]);
        k.insert("slot0x25KeyX", &[0x25; 16]);
        k.insert("generator", &[0x5A; 16]);
        if let Some((pid, s)) = seed {
            k.insert(&format!("seed_{pid:016x}"), &s);
        }
        k
    }

    /// Encrypt a NoCrypto test NCCH in place (CTR is symmetric).
    fn encrypt(n: &mut [u8], flags3: u8, flags7: u8, keys: &KeyFile) {
        n[..16].copy_from_slice(&[0x77; 16]);
        n[0x188 + 3] = flags3;
        n[0x188 + 7] = flags7;
        let h = NcchHeader::parse(&MemorySource::new(n.to_vec())).unwrap();
        let mut c = NcchCrypto::new(&h, &n[..0x200], keys).unwrap();
        let eh = n[h.exefs.0 as usize..h.exefs.0 as usize + 0x200].to_vec();
        c.set_code(&eh).unwrap();
        c.apply(0, n);
    }

    #[test]
    fn scrambler_math() {
        let y = [0x11u8; 16];
        let k = scramble(&[0; 16], &y, &[0; 16]);
        assert_eq!(u128::from_be_bytes(*k), u128::from_be_bytes(y).rotate_left(87));
    }

    #[test]
    fn decrypts_ncch_cci_and_converts() {
        let pid = 0x0004_0000_0055_6600u64;
        let code = (0..0x400).map(|i| (i * 7) as u8).collect::<Vec<u8>>();
        let plain = testkit::ncch(pid, "CTR-P-CRYP", &[(".code", code.clone()), ("icon", vec![3u8; 0x36C0])]);
        let seed = [0x42u8; 16];
        for (flags7, seeded) in [(0u8, false), (FLAG_SEED, true)] {
            let k = keys(0x2C, seeded.then_some((pid, seed)));
            let mut enc = plain.clone();
            enc[0x108..0x110].copy_from_slice(&pid.to_le_bytes());
            if seeded {
                let mut c = seed.to_vec();
                c.extend_from_slice(&pid.to_le_bytes());
                enc[0x114..0x118].copy_from_slice(&crate::crypto::sha256(&c)[..4]);
            }
            encrypt(&mut enc, 0x01, flags7, &k);
            assert_ne!(enc[0x400..0x800], plain[0x400..0x800], "ExeFS data must be encrypted");

            let reg = Registry::new().with(N3dsBackend);
            let cci = testkit::cci(pid, &[enc.clone()]);
            let ctx = OpenContext { keys: Arc::new(keys(0x2C, seeded.then_some((pid, seed)))), ..Default::default() };
            let src: SharedSource = Arc::new(MemorySource::new(cci.clone()));
            let r = reg.open_as(N3DS_CCI, src.clone(), &ctx).unwrap();
            let e = r.entries().unwrap().map(|e| e.unwrap()).find(|e| e.path == "partition0-game/exefs/.code").expect(".code listed");
            let s = r.open_entry(e.id).unwrap();
            assert_eq!(rv(s.as_ref(), 0, 0x400, 0x400).unwrap(), code);
            let v = r.verify(VerifyLevel::Content, &JobContext::default()).unwrap();
            assert!(v.no_failures(), "{:?}", v.checks);
            assert!(v.checks.iter().any(|c| c.name.contains("decryption")));

            // Without keys: opaque, hashes not checked.
            let r = reg.open_as(N3DS_CCI, src.clone(), &OpenContext::default()).unwrap();
            assert!(r.entries().unwrap().any(|e| e.unwrap().path == "partition0-game/exefs.bin"));
            assert!(!r.info().unwrap().limitations.is_empty());
            // Wrong KeyX: decryption "succeeds" but hashes catch it.
            let bad = OpenContext { keys: Arc::new(keys(0x2D, seeded.then_some((pid, seed)))), ..Default::default() };
            let r = reg.open_as(N3DS_CCI, src.clone(), &bad).unwrap();
            assert!(!r.verify(VerifyLevel::Content, &JobContext::default()).unwrap().no_failures());

            // CCI -> CIA writes plaintext NCCH content that verifies.
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("g.3ds");
            std::fs::write(&path, &cci).unwrap();
            let out = d.path().join("g.cia");
            let req = ConvertRequest {
                input: path.clone(),
                source: crate::open_file(&path).unwrap(),
                from: N3DS_CCI,
                to: N3DS_CIA,
                output: out.clone(),
                ctx: ctx.clone(),
                options: Default::default(),
            };
            N3dsBackend.plan_convert(req).unwrap().execute(&JobContext::default()).unwrap();
            let c = reg.open(crate::open_file(&out).unwrap(), &OpenContext::default()).unwrap();
            assert!(c.entries().unwrap().any(|e| e.unwrap().path == "0000/exefs/.code"));
            assert!(c.verify(VerifyLevel::Content, &JobContext::default()).unwrap().no_failures());
        }
    }
}
