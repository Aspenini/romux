//! Detection and RVZ packing of Nintendo's pseudo-random disc padding ("junk").
//!
//! GameCube discs and Wii partitions fill unused space with the output of a lagged
//! Fibonacci generator ([`Lfg`]) that is re-seeded at every 0x8000-byte block of data
//! space (disc offsets for GameCube and unpartitioned areas, decrypted payload offsets for
//! Wii partitions). RVZ stores such runs as a 68-byte seed instead of the bytes.
//!
//! Detection never trusts a guess. A seed is recovered from one aligned 2084-byte window
//! of output, the whole block is regenerated from it, and only byte ranges that match the
//! data exactly become junk runs. Data that merely looks random is stored as is.
//!
//! Seed recovery inverts the generator. The output of block `m` (bytes `m*2084..`) is the
//! state after `4 + m` forward steps; undoing those steps yields the initial state, whose
//! words are the expanded seed passed through the init mask
//! `x' = (x & 0xFF00FFFF) | ((x >> 2) & 0x00FF0000)`. The mask hides bits 16-17 of every
//! word; for seed words 1..16 they follow from the expansion recurrence
//! `u[i] = (u[i-17] << 23) ^ (u[i-16] >> 9) ^ u[i-1]` (bits 7-8 of `u[i]`), and the hidden
//! bits of word 0 never influence the output.

use crate::wii::rvz::{BLOCK, Lfg};

const K: usize = 521;
const J: usize = 32;
const STATE_BYTES: usize = K * 4;
/// Shortest junk run worth a 72-byte run header.
const MIN_RUN: usize = 512;

fn backward(b: &mut [u32; K]) {
    for i in (J..K).rev() {
        b[i] ^= b[i - J];
    }
    for i in 0..J {
        b[i] ^= b[i + K - J];
    }
}

/// Recover a seed whose generator output, at block-relative byte `m * 2084`, equals
/// `window` (2084 bytes). The caller must still check the result against the data.
pub fn recover_seed(window: &[u8], m: usize) -> Option<[u8; 68]> {
    if window.len() < STATE_BYTES {
        return None;
    }
    let mut b = [0u32; K];
    for (i, w) in b.iter_mut().enumerate() {
        *w = u32::from_be_bytes([window[i * 4], window[i * 4 + 1], window[i * 4 + 2], window[i * 4 + 3]]);
    }
    for _ in 0..4 + m {
        backward(&mut b);
    }
    let mut u = [0u32; 33];
    for i in 0..33 {
        let s = b[i];
        // Bits 22-23 of the masked word repeat bits 24-25 of the original.
        if (s >> 22) & 3 != (s >> 24) & 3 {
            return None;
        }
        u[i] = (s & 0xFF00_FFFF) | ((s & 0x003F_0000) << 2);
    }
    for j in 1..17 {
        u[j] |= (((u[j + 16] ^ u[j + 15]) >> 7) & 3) << 16;
    }
    let mut seed = [0u8; 68];
    for i in 0..17 {
        seed[i * 4..i * 4 + 4].copy_from_slice(&u[i].to_be_bytes());
    }
    Some(seed)
}

/// Cheap pre-check for window `m >= 1`: LFG output satisfies `w[t] = w[t-521] ^ w[t-32]`.
fn looks_like_lfg(block: &[u8], q: usize) -> bool {
    let w = |byte: usize| u32::from_be_bytes([block[byte], block[byte + 1], block[byte + 2], block[byte + 3]]);
    (0..16).all(|k| {
        let t = q + k * 4;
        w(t) == w(t - STATE_BYTES) ^ w(t - J * 4)
    })
}

/// One output segment of packed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Run {
    Literal(std::ops::Range<usize>),
    Junk(std::ops::Range<usize>, [u8; 68]),
}

/// Junk runs within one LFG block. `block` holds data at block-relative bytes
/// `lo..lo + block.len()` (a sub-range of the 0x8000-byte block).
fn junk_in_block(block: &[u8], lo: usize) -> Option<([u8; 68], Vec<std::ops::Range<usize>>)> {
    let hi = lo + block.len();
    for m in lo.div_ceil(STATE_BYTES)..BLOCK as usize / STATE_BYTES + 1 {
        let q = m * STATE_BYTES;
        if q + STATE_BYTES > hi {
            break;
        }
        let rel = q - lo;
        if m >= 1 && q >= lo + STATE_BYTES && !looks_like_lfg(block, rel) {
            continue;
        }
        let Some(seed) = recover_seed(&block[rel..rel + STATE_BYTES], m) else { continue };
        if seed.iter().all(|b| *b == 0) {
            continue; // zeros: left to the compressor
        }
        let mut gen_ = vec![0u8; hi];
        Lfg::new(&seed).fill(&mut gen_);
        if gen_[q..q + STATE_BYTES] != block[rel..rel + STATE_BYTES] {
            continue;
        }
        // One seed per block: collect every long matching range.
        let mut runs = Vec::new();
        let mut i = 0;
        while i < block.len() {
            if block[i] != gen_[lo + i] {
                i += 1;
                continue;
            }
            let s = i;
            while i < block.len() && block[i] == gen_[lo + i] {
                i += 1;
            }
            if i - s >= MIN_RUN {
                runs.push(s..i);
            }
        }
        return Some((seed, runs));
    }
    None
}

/// Split `data` (starting at data-space offset `offset`) into literal and junk runs.
pub fn find_runs(data: &[u8], offset: u64) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    let push_lit = |out: &mut Vec<Run>, r: std::ops::Range<usize>| {
        if r.is_empty() {
            return;
        }
        if let Some(Run::Literal(prev)) = out.last_mut() {
            if prev.end == r.start {
                prev.end = r.end;
                return;
            }
        }
        out.push(Run::Literal(r));
    };
    let mut pos = 0usize;
    while pos < data.len() {
        let abs = offset + pos as u64;
        let lo = (abs % BLOCK) as usize;
        let n = (BLOCK as usize - lo).min(data.len() - pos);
        let mut cur = pos;
        if let Some((seed, runs)) = junk_in_block(&data[pos..pos + n], lo) {
            for r in runs {
                push_lit(&mut out, cur..pos + r.start);
                out.push(Run::Junk(pos + r.start..pos + r.end, seed));
                cur = pos + r.end;
            }
        }
        push_lit(&mut out, cur..pos + n);
        pos += n;
    }
    out
}

/// RVZ-pack `data` when that saves space: `u32 BE size` runs, bit 31 marking a junk run
/// followed by its seed. Returns `None` when there is little or no junk.
pub fn pack(data: &[u8], offset: u64) -> Option<Vec<u8>> {
    let runs = find_runs(data, offset);
    let junk: usize = runs.iter().map(|r| if let Run::Junk(r, _) = r { r.len() } else { 0 }).sum();
    if junk < 4096 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() - junk + runs.len() * 72);
    for r in runs {
        match r {
            Run::Literal(r) => {
                out.extend_from_slice(&(r.len() as u32).to_be_bytes());
                out.extend_from_slice(&data[r]);
            }
            Run::Junk(r, seed) => {
                out.extend_from_slice(&(r.len() as u32 | 0x8000_0000).to_be_bytes());
                out.extend_from_slice(&seed);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn junk_block(seed_byte: u8) -> Vec<u8> {
        let seed: [u8; 68] = std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ seed_byte);
        let mut v = vec![0u8; BLOCK as usize];
        Lfg::new(&seed).fill(&mut v);
        v
    }

    #[test]
    fn recovers_seed_from_every_window() {
        let b = junk_block(9);
        for m in 0..15 {
            let s = recover_seed(&b[m * STATE_BYTES..(m + 1) * STATE_BYTES], m).unwrap();
            let mut g = vec![0u8; BLOCK as usize];
            Lfg::new(&s).fill(&mut g);
            assert_eq!(g, b, "window {m}");
        }
    }

    #[test]
    fn packs_mixed_data_and_unpacks() {
        // Two blocks of junk with different seeds, real data at the start, in the middle and
        // overlapping a block boundary, and an unaligned start offset.
        let off = 0x8000 * 7 + 0x1234;
        let mut data = vec![0u8; 0x8000 * 3];
        let mut abs = off as usize;
        let mut i = 0;
        while i < data.len() {
            let blk = abs / 0x8000;
            let lo = abs % 0x8000;
            let n = (0x8000 - lo).min(data.len() - i);
            let b = junk_block(blk as u8);
            data[i..i + n].copy_from_slice(&b[lo..lo + n]);
            i += n;
            abs += n;
        }
        for (a, z) in [(0usize, 300usize), (0x5000, 0x6800), (0xADCC, 0xAE40)] {
            for (k, b) in data[a..z].iter_mut().enumerate() {
                *b = (k % 251) as u8;
            }
        }
        let packed = pack(&data, off).expect("junk found");
        assert!(packed.len() < 0x3000, "{}", packed.len());
        let back = crate::wii::rvz::unpack(&packed, off, data.len()).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn random_and_zero_data_are_not_packed() {
        let mut x = 0x1234_5678u32;
        let rnd: Vec<u8> = (0..0x10000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        assert!(pack(&rnd, 0).is_none());
        assert!(pack(&[0u8; 0x10000], 0).is_none());
    }
}
