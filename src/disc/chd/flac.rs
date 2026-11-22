//! FLAC frame decoder for CHD's `flac` and `cdfl` codecs.
//!
//! CHD stores bare FLAC frames (no `fLaC` stream header) of 16-bit stereo audio. This is
//! an independent implementation of the frame layer from the FLAC specification
//! (RFC 9639): constant, verbatim, fixed and LPC subframes, Rice residuals, inter-channel
//! decorrelation, and CRC-8/CRC-16 checks.

use crate::{Error, Result};

struct Bits<'a> {
    data: &'a [u8],
    pos: usize, // bit position
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits { data, pos: 0 }
    }
    fn bit(&mut self) -> Result<u32> {
        let byte = *self.data.get(self.pos / 8).ok_or_else(|| Error::codec("FLAC stream truncated"))?;
        let b = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Ok(b as u32)
    }
    fn read(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Ok(v)
    }
    fn read_signed(&mut self, n: u32) -> Result<i32> {
        if n == 0 {
            return Ok(0);
        }
        let v = self.read(n)?;
        Ok(((v << (32 - n)) as i32) >> (32 - n))
    }
    fn read_signed_wide(&mut self, n: u32) -> Result<i64> {
        if n == 0 {
            return Ok(0);
        }
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()? as u64;
        }
        Ok(((v << (64 - n)) as i64) >> (64 - n))
    }
    fn unary(&mut self) -> Result<u32> {
        let mut n = 0u32;
        while self.bit()? == 0 {
            n += 1;
            if n > 1 << 20 {
                return Err(Error::codec("FLAC unary value runs away"));
            }
        }
        Ok(n)
    }
    fn align(&mut self) {
        self.pos = self.pos.div_ceil(8) * 8;
    }
    fn byte_pos(&self) -> usize {
        self.pos / 8
    }
}

fn crc8(data: &[u8]) -> u8 {
    let mut c = 0u8;
    for &b in data {
        c ^= b;
        for _ in 0..8 {
            c = if c & 0x80 != 0 { (c << 1) ^ 0x07 } else { c << 1 };
        }
    }
    c
}

fn crc16(data: &[u8]) -> u16 {
    let mut c = 0u16;
    for &b in data {
        c ^= (b as u16) << 8;
        for _ in 0..8 {
            c = if c & 0x8000 != 0 { (c << 1) ^ 0x8005 } else { c << 1 };
        }
    }
    c
}

fn block_size(code: u32, br: &mut Bits<'_>) -> Result<usize> {
    Ok(match code {
        1 => 192,
        2..=5 => 576 << (code - 2),
        6 => br.read(8)? as usize + 1,
        7 => br.read(16)? as usize + 1,
        8..=15 => 256 << (code - 8),
        _ => return Err(Error::codec("reserved FLAC block size")),
    })
}

fn residual(br: &mut Bits<'_>, block: usize, order: usize, out: &mut [i64]) -> Result<()> {
    let method = br.read(2)?;
    let (pbits, escape) = match method {
        0 => (4, 15),
        1 => (5, 31),
        _ => return Err(Error::codec("reserved FLAC residual method")),
    };
    let porder = br.read(4)?;
    let parts = 1usize << porder;
    if !block.is_multiple_of(parts) || (block >> porder) < order {
        return Err(Error::codec("FLAC partition order inconsistent with block size"));
    }
    let mut i = order;
    for p in 0..parts {
        let n = (block >> porder) - if p == 0 { order } else { 0 };
        let k = br.read(pbits)?;
        if k == escape {
            let bits = br.read(5)?;
            for _ in 0..n {
                out[i] = br.read_signed(bits)? as i64;
                i += 1;
            }
        } else {
            for _ in 0..n {
                let q = br.unary()? as u64;
                let r = br.read(k)? as u64;
                let u = (q << k) | r;
                out[i] = ((u >> 1) as i64) ^ -((u & 1) as i64);
                i += 1;
            }
        }
    }
    Ok(())
}

fn subframe(br: &mut Bits<'_>, block: usize, bps: u32) -> Result<Vec<i64>> {
    if br.bit()? != 0 {
        return Err(Error::codec("FLAC subframe padding bit set"));
    }
    let t = br.read(6)?;
    let wasted = if br.bit()? == 1 { br.unary()? + 1 } else { 0 };
    let bps = bps.checked_sub(wasted).ok_or_else(|| Error::codec("FLAC wasted bits exceed sample size"))?;
    let mut s = vec![0i64; block];
    match t {
        0 => {
            let v = br.read_signed_wide(bps)?;
            s.fill(v);
        }
        1 => {
            for x in s.iter_mut() {
                *x = br.read_signed_wide(bps)?;
            }
        }
        8..=12 => {
            let order = (t - 8) as usize;
            if order > block {
                return Err(Error::codec("FLAC predictor order exceeds block"));
            }
            for x in s.iter_mut().take(order) {
                *x = br.read_signed_wide(bps)?;
            }
            residual(br, block, order, &mut s)?;
            for i in order..block {
                let p = match order {
                    0 => 0,
                    1 => s[i - 1],
                    2 => s[i - 1].wrapping_mul(2).wrapping_sub(s[i - 2]),
                    3 => s[i - 1].wrapping_mul(3).wrapping_sub(s[i - 2].wrapping_mul(3)).wrapping_add(s[i - 3]),
                    _ => s[i - 1]
                        .wrapping_mul(4)
                        .wrapping_sub(s[i - 2].wrapping_mul(6))
                        .wrapping_add(s[i - 3].wrapping_mul(4))
                        .wrapping_sub(s[i - 4]),
                };
                s[i] = s[i].wrapping_add(p);
            }
        }
        32..=63 => {
            let order = (t - 31) as usize;
            if order > block {
                return Err(Error::codec("FLAC LPC order exceeds block"));
            }
            for x in s.iter_mut().take(order) {
                *x = br.read_signed_wide(bps)?;
            }
            let precision = br.read(4)? + 1;
            if precision == 16 {
                return Err(Error::codec("invalid FLAC LPC precision"));
            }
            let shift = br.read_signed(5)?;
            if shift < 0 {
                return Err(Error::codec("negative FLAC LPC shift"));
            }
            let coefs: Vec<i64> = (0..order).map(|_| br.read_signed(precision).map(|v| v as i64)).collect::<Result<_>>()?;
            residual(br, block, order, &mut s)?;
            for i in order..block {
                let mut acc = 0i64;
                for (j, c) in coefs.iter().enumerate() {
                    acc = acc.wrapping_add(c.wrapping_mul(s[i - j - 1]));
                }
                s[i] = s[i].wrapping_add(acc >> shift);
            }
        }
        _ => return Err(Error::codec(format!("reserved FLAC subframe type {t}"))),
    }
    if wasted > 0 {
        for x in s.iter_mut() {
            *x = x.wrapping_shl(wasted);
        }
    }
    Ok(s)
}

/// Decode FLAC frames from `data` until `samples` stereo sample pairs have been produced.
/// Returns interleaved 16-bit samples and the number of input bytes consumed.
pub fn decode_stereo16(data: &[u8], samples: usize) -> Result<(Vec<i16>, usize)> {
    let mut out = Vec::with_capacity(samples * 2);
    let mut br = Bits::new(data);
    while out.len() < samples * 2 {
        let frame_start = br.byte_pos();
        if br.read(14)? != 0x3FFE {
            return Err(Error::codec("FLAC frame sync not found"));
        }
        br.read(2)?; // reserved + blocking strategy
        let bs_code = br.read(4)?;
        let sr_code = br.read(4)?;
        let ch = br.read(4)?;
        let ss = br.read(3)?;
        br.read(1)?;
        // UTF-8-style coded frame/sample number.
        let first = br.read(8)?;
        let extra = match first {
            0x00..=0x7F => 0,
            0xC0..=0xDF => 1,
            0xE0..=0xEF => 2,
            0xF0..=0xF7 => 3,
            0xF8..=0xFB => 4,
            0xFC..=0xFD => 5,
            0xFE => 6,
            _ => return Err(Error::codec("invalid FLAC coded number")),
        };
        for _ in 0..extra {
            if br.read(8)? & 0xC0 != 0x80 {
                return Err(Error::codec("invalid FLAC coded number continuation"));
            }
        }
        let block = block_size(bs_code, &mut br)?;
        match sr_code {
            12 => {
                br.read(8)?;
            }
            13 | 14 => {
                br.read(16)?;
            }
            15 => return Err(Error::codec("invalid FLAC sample rate code")),
            _ => {}
        }
        let header_end = br.byte_pos();
        let want_crc8 = br.read(8)? as u8;
        if crc8(&data[frame_start..header_end]) != want_crc8 {
            return Err(Error::integrity("FLAC frame header CRC-8 mismatch"));
        }
        let bps = match ss {
            0 | 4 => 16,
            1 => 8,
            2 => 12,
            5 => 20,
            6 => 24,
            _ => return Err(Error::unsupported("unsupported FLAC sample size")),
        };
        let (a, b) = match ch {
            0 => (subframe(&mut br, block, bps)?, None),
            1 => (subframe(&mut br, block, bps)?, Some((subframe(&mut br, block, bps)?, 1))),
            8 => (subframe(&mut br, block, bps)?, Some((subframe(&mut br, block, bps + 1)?, 8))),
            9 => (subframe(&mut br, block, bps + 1)?, Some((subframe(&mut br, block, bps)?, 9))),
            10 => (subframe(&mut br, block, bps)?, Some((subframe(&mut br, block, bps + 1)?, 10))),
            _ => return Err(Error::unsupported("CHD FLAC streams must be stereo")),
        };
        let (left, right) = match b {
            Some((side, 8)) => {
                let r: Vec<i64> = a.iter().zip(&side).map(|(l, s)| l.wrapping_sub(*s)).collect();
                (a, r)
            }
            Some((right, 9)) => {
                let l: Vec<i64> = a.iter().zip(&right).map(|(s, r)| s.wrapping_add(*r)).collect();
                (l, right)
            }
            Some((right, 1)) => (a, right),
            Some((side, _)) => {
                let mut l = Vec::with_capacity(block);
                let mut r = Vec::with_capacity(block);
                for (m, s) in a.iter().zip(&side) {
                    let mid = m.wrapping_shl(1) | (s & 1);
                    l.push(mid.wrapping_add(*s) >> 1);
                    r.push(mid.wrapping_sub(*s) >> 1);
                }
                (l, r)
            }
            None => (a.clone(), a),
        };
        br.align();
        let frame_end = br.byte_pos();
        let want_crc16 = br.read(16)? as u16;
        if crc16(&data[frame_start..frame_end]) != want_crc16 {
            return Err(Error::integrity("FLAC frame CRC-16 mismatch"));
        }
        for (l, r) in left.iter().zip(&right) {
            if out.len() >= samples * 2 {
                break;
            }
            out.push(*l as i16);
            out.push(*r as i16);
        }
    }
    Ok((out, br.byte_pos()))
}

/// CHD `flac` codec: first byte `L`/`B` selects output endianness.
pub fn decode_chd_flac(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let (&endian, frames) = src.split_first().ok_or_else(|| Error::codec("empty FLAC hunk"))?;
    let (samples, _) = decode_stereo16(frames, out_len / 4)?;
    let mut out = Vec::with_capacity(out_len);
    for s in samples {
        match endian {
            b'L' => out.extend_from_slice(&s.to_le_bytes()),
            b'B' => out.extend_from_slice(&s.to_be_bytes()),
            _ => return Err(Error::codec("CHD FLAC hunk has an unknown endianness marker")),
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod testenc {
    //! Tiny FLAC frame writer for tests (exercises every subframe type).
    struct W {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }
    impl W {
        fn put(&mut self, v: u64, bits: u32) {
            for i in (0..bits).rev() {
                self.acc = (self.acc << 1) | ((v >> i) & 1);
                self.n += 1;
                if self.n == 8 {
                    self.out.push(self.acc as u8);
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }
        fn put_signed(&mut self, v: i64, bits: u32) {
            self.put((v as u64) & ((1u64 << bits) - 1), bits);
        }
        fn align(&mut self) {
            while self.n != 0 {
                self.put(0, 1);
            }
        }
        fn rice(&mut self, vals: &[i64], k: u32) {
            for &v in vals {
                let u = ((v << 1) ^ (v >> 63)) as u64;
                for _ in 0..(u >> k) {
                    self.put(0, 1);
                }
                self.put(1, 1);
                self.put(u & ((1 << k) - 1), k);
            }
        }
    }

    /// Subframe encodings to exercise.
    #[derive(Clone, Copy)]
    pub enum Kind {
        Verbatim,
        Fixed(usize),
        Lpc,
    }

    fn sub(w: &mut W, s: &[i64], bps: u32, kind: Kind) {
        let constant = s.iter().all(|x| *x == s[0]);
        w.put(0, 1);
        if constant {
            w.put(0, 6);
            w.put(0, 1);
            w.put_signed(s[0], bps);
            return;
        }
        match kind {
            Kind::Verbatim => {
                w.put(1, 6);
                w.put(0, 1);
                for &x in s {
                    w.put_signed(x, bps);
                }
            }
            Kind::Fixed(order) => {
                w.put(8 + order as u64, 6);
                w.put(0, 1);
                for &x in &s[..order] {
                    w.put_signed(x, bps);
                }
                let res: Vec<i64> = (order..s.len())
                    .map(|i| {
                        let p = match order {
                            0 => 0,
                            1 => s[i - 1],
                            2 => 2 * s[i - 1] - s[i - 2],
                            3 => 3 * s[i - 1] - 3 * s[i - 2] + s[i - 3],
                            _ => 4 * s[i - 1] - 6 * s[i - 2] + 4 * s[i - 3] - s[i - 4],
                        };
                        s[i] - p
                    })
                    .collect();
                w.put(0, 2);
                w.put(0, 4);
                w.put(10, 4);
                w.rice(&res, 10);
            }
            Kind::Lpc => {
                let coefs = [3i64, -2, 1];
                let shift = 1;
                w.put(31 + 3, 6);
                w.put(0, 1);
                for &x in &s[..3] {
                    w.put_signed(x, bps);
                }
                w.put(11, 4); // precision 12
                w.put_signed(shift, 5);
                for c in coefs {
                    w.put_signed(c, 12);
                }
                let res: Vec<i64> =
                    (3..s.len()).map(|i| s[i] - ((coefs[0] * s[i - 1] + coefs[1] * s[i - 2] + coefs[2] * s[i - 3]) >> shift)).collect();
                w.put(1, 2);
                w.put(0, 4);
                w.put(31, 5); // escape: raw residuals
                w.put(20, 5);
                for r in res {
                    w.put_signed(r, 20);
                }
            }
        }
    }

    /// Encode one stereo frame (block of `left`/`right` 16-bit samples) using mid/side or
    /// independent channels, with the given subframe kind.
    pub fn frame(left: &[i16], right: &[i16], number: u8, mid_side: bool, kind: Kind) -> Vec<u8> {
        let n = left.len();
        let mut w = W { out: vec![], acc: 0, n: 0 };
        w.put(0x3FFE, 14);
        w.put(0, 2);
        w.put(7, 4); // 16-bit block size follows
        w.put(9, 4); // 44.1 kHz
        w.put(if mid_side { 10 } else { 1 }, 4);
        w.put(4, 3);
        w.put(0, 1);
        w.put(number as u64 & 0x7F, 8);
        w.put((n - 1) as u64, 16);
        let crc = super::crc8(&w.out);
        w.put(crc as u64, 8);
        let l: Vec<i64> = left.iter().map(|x| *x as i64).collect();
        let r: Vec<i64> = right.iter().map(|x| *x as i64).collect();
        if mid_side {
            let mid: Vec<i64> = l.iter().zip(&r).map(|(a, b)| (a + b) >> 1).collect();
            let side: Vec<i64> = l.iter().zip(&r).map(|(a, b)| a - b).collect();
            sub(&mut w, &mid, 16, kind);
            sub(&mut w, &side, 17, kind);
        } else {
            // Independent channel assignment code 1 means two channels.
            sub(&mut w, &l, 16, kind);
            sub(&mut w, &r, 16, kind);
        }
        w.align();
        let crc = super::crc16(&w.out);
        w.put(crc as u64, 16);
        w.out
    }
}

#[cfg(test)]
mod tests {
    use super::testenc::{Kind, frame};
    use super::*;

    #[test]
    fn decodes_every_subframe_kind() {
        let n = 1024;
        let left: Vec<i16> = (0..n).map(|i| ((i as f64 / 7.0).sin() * 12000.0) as i16).collect();
        let right: Vec<i16> = (0..n).map(|i| ((i as f64 / 11.0).cos() * 9000.0) as i16 - 3).collect();
        let mut stream = Vec::new();
        let kinds = [Kind::Verbatim, Kind::Fixed(0), Kind::Fixed(1), Kind::Fixed(2), Kind::Fixed(3), Kind::Fixed(4), Kind::Lpc];
        for (i, k) in kinds.iter().enumerate() {
            stream.extend(frame(&left, &right, i as u8, i % 2 == 0, *k));
        }
        stream.extend(frame(&[5; 64], &[5; 64], 99, false, Kind::Verbatim)); // constant subframes
        let total = n * kinds.len() + 64;
        let (pcm, used) = decode_stereo16(&stream, total).unwrap();
        assert_eq!(used, stream.len());
        for f in 0..kinds.len() {
            for i in 0..n {
                assert_eq!(pcm[(f * n + i) * 2], left[i], "frame {f} sample {i}");
                assert_eq!(pcm[(f * n + i) * 2 + 1], right[i]);
            }
        }
        assert!(pcm[kinds.len() * n * 2..].iter().all(|s| *s == 5));
        // Corruption is detected by CRC.
        let mut bad = stream.clone();
        bad[40] ^= 0x10;
        assert!(decode_stereo16(&bad, total).is_err());
    }
    #[test]
    fn chd_flac_and_cdfl_hunks() {
        // `flac`: endianness marker + frames.
        let l: Vec<i16> = (0..588).map(|i| (i * 37 % 2000) as i16 - 1000).collect();
        let r: Vec<i16> = (0..588).map(|i| (i * 13 % 500) as i16).collect();
        for (mark, be) in [(b'L', false), (b'B', true)] {
            let mut hunk = vec![mark];
            hunk.extend(frame(&l, &r, 0, true, Kind::Fixed(2)));
            let out = decode_chd_flac(&hunk, 588 * 4).unwrap();
            let s0 = if be { i16::from_be_bytes([out[0], out[1]]) } else { i16::from_le_bytes([out[0], out[1]]) };
            assert_eq!(s0, l[0]);
            let s3 = if be { i16::from_be_bytes([out[6], out[7]]) } else { i16::from_le_bytes([out[6], out[7]]) };
            assert_eq!(s3, r[1]);
        }
        // `cdfl`: two CD frames of audio (one 1176-sample FLAC block) + deflated subcode.
        let n = 2 * 2352 / 4;
        let l: Vec<i16> = (0..n).map(|i| ((i as f64 / 5.0).sin() * 20000.0) as i16).collect();
        let r: Vec<i16> = (0..n).map(|i| ((i as f64 / 3.0).cos() * 15000.0) as i16).collect();
        let sub: Vec<u8> = (0..192).map(|i| i as u8).collect();
        let mut hunk = frame(&l, &r, 0, false, Kind::Lpc);
        hunk.extend(crate::compression::compress(crate::compression::Codec::Deflate, &sub, 6).unwrap());
        let out = super::super::ChdFile::decode_cdfl(&hunk, 2 * 2448).unwrap();
        for f in 0..2 {
            let o = f * 2448;
            for i in 0..588 {
                let k = f * 588 + i;
                assert_eq!(i16::from_be_bytes([out[o + i * 4], out[o + i * 4 + 1]]), l[k]);
                assert_eq!(i16::from_be_bytes([out[o + i * 4 + 2], out[o + i * 4 + 3]]), r[k]);
            }
            assert_eq!(&out[o + 2352..o + 2448], &sub[f * 96..(f + 1) * 96]);
        }
    }
    #[test]
    fn mutated_frames_never_panic() {
        let l: Vec<i16> = (0..1176).map(|i| ((i as f64 / 9.0).sin() * 30000.0) as i16).collect();
        let base: Vec<u8> =
            [Kind::Lpc, Kind::Fixed(4), Kind::Verbatim].iter().enumerate().flat_map(|(i, k)| frame(&l, &l, i as u8, i == 1, *k)).collect();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..3000 {
            let mut d = base.clone();
            for _ in 0..1 + (x % 6) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let at = 8 + (x as usize % (d.len() - 8));
                d[at] ^= (x >> 32) as u8 | 1;
            }
            let _ = decode_stereo16(&d, 1176 * 3);
            let _ = decode_chd_flac(&d, 2352 * 2);
        }
    }
}
