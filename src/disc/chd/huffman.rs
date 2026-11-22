//! Canonical Huffman coding and MSB-first bitstreams as used by the CHD container
//! (map compression and the `huff` hunk codec). Independently implemented from the
//! published container description.

use crate::{Error, Result};

/// MSB-first bit reader. Reads past the end yield zero bits and set `overflow`.
pub struct BitReader<'a> {
    data: &'a [u8],
    bitpos: usize,
    pub overflow: bool,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader { data, bitpos: 0, overflow: false }
    }
    pub fn peek(&self, n: u32) -> u32 {
        let mut v = 0u32;
        for i in 0..n as usize {
            let p = self.bitpos + i;
            let bit = if p / 8 < self.data.len() { (self.data[p / 8] >> (7 - (p % 8))) & 1 } else { 0 };
            v = (v << 1) | bit as u32;
        }
        v
    }
    pub fn remove(&mut self, n: u32) {
        self.bitpos += n as usize;
        if self.bitpos > self.data.len() * 8 {
            self.overflow = true;
        }
    }
    pub fn read(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = self.peek(n);
        self.remove(n);
        v
    }
}

/// MSB-first bit writer.
#[derive(Default)]
pub struct BitWriter {
    pub data: Vec<u8>,
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn write(&mut self, value: u32, n: u32) {
        if n == 0 {
            return;
        }
        for i in (0..n).rev() {
            self.acc = (self.acc << 1) | ((value >> i) & 1) as u64;
            self.nbits += 1;
            if self.nbits == 8 {
                self.data.push(self.acc as u8);
                self.acc = 0;
                self.nbits = 0;
            }
        }
    }
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.data.push((self.acc << (8 - self.nbits)) as u8);
        }
        self.data
    }
}

/// A canonical Huffman decoder over `numcodes` symbols with codes up to `maxbits` bits.
pub struct HuffDecoder {
    numcodes: usize,
    maxbits: u32,
    lengths: Vec<u8>,
    lookup: Vec<u32>,
}

impl HuffDecoder {
    pub fn new(numcodes: usize, maxbits: u32) -> Self {
        HuffDecoder { numcodes, maxbits, lengths: vec![0; numcodes], lookup: Vec::new() }
    }

    fn assign_and_build(&mut self) -> Result<()> {
        let mut histo = [0u32; 33];
        for &l in &self.lengths {
            if l as u32 > self.maxbits {
                return Err(Error::codec("huffman code length exceeds maximum"));
            }
            histo[l as usize] += 1;
        }
        let mut curstart = 0u32;
        let mut starts = [0u32; 33];
        for codelen in (1..=32usize).rev() {
            let next = (curstart + histo[codelen]) >> 1;
            if codelen != 1 && next * 2 != curstart + histo[codelen] {
                return Err(Error::codec("huffman code lengths are inconsistent"));
            }
            starts[codelen] = curstart;
            curstart = next;
        }
        let mut codes = vec![0u32; self.numcodes];
        for (i, &l) in self.lengths.iter().enumerate() {
            if l > 0 {
                codes[i] = starts[l as usize];
                starts[l as usize] += 1;
            }
        }
        self.lookup = vec![0u32; 1 << self.maxbits];
        for (sym, &l) in self.lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let shift = self.maxbits - l as u32;
            let base = (codes[sym] << shift) as usize;
            let end = base + (1usize << shift);
            if end > self.lookup.len() {
                return Err(Error::codec("huffman code out of range"));
            }
            for e in &mut self.lookup[base..end] {
                *e = ((sym as u32) << 5) | l as u32;
            }
        }
        Ok(())
    }

    /// Import a tree stored with the small run-length scheme (CHD map trees).
    pub fn import_tree_rle(&mut self, br: &mut BitReader<'_>) -> Result<()> {
        let numbits = if self.maxbits >= 16 {
            5
        } else if self.maxbits >= 8 {
            4
        } else {
            3
        };
        let mut cur = 0usize;
        while cur < self.numcodes {
            let nb = br.read(numbits);
            if nb != 1 {
                self.lengths[cur] = nb as u8;
                cur += 1;
            } else {
                let nb2 = br.read(numbits);
                if nb2 == 1 {
                    self.lengths[cur] = 1;
                    cur += 1;
                } else {
                    let rep = br.read(numbits) + 3;
                    for _ in 0..rep {
                        if cur >= self.numcodes {
                            return Err(Error::codec("huffman tree run overflows symbol table"));
                        }
                        self.lengths[cur] = nb2 as u8;
                        cur += 1;
                    }
                }
            }
        }
        self.assign_and_build()?;
        if br.overflow {
            return Err(Error::codec("huffman tree truncated"));
        }
        Ok(())
    }

    /// Import a tree that is itself Huffman-coded (CHD `huff` codec trees).
    pub fn import_tree_huffman(&mut self, br: &mut BitReader<'_>) -> Result<()> {
        let mut small = HuffDecoder::new(24, 6);
        small.lengths[0] = br.read(3) as u8;
        let start = br.read(3) as usize + 1;
        let mut count = 0u32;
        for index in 1..24 {
            if index < start || count == 7 {
                small.lengths[index] = 0;
            } else {
                count = br.read(3);
                small.lengths[index] = if count == 7 { 0 } else { count as u8 };
            }
        }
        small.assign_and_build()?;
        let mut temp = self.numcodes as u32 - 9;
        let mut rlefullbits = 0u32;
        while temp != 0 {
            temp >>= 1;
            rlefullbits += 1;
        }
        let mut last = 0u8;
        let mut cur = 0usize;
        while cur < self.numcodes {
            let value = small.decode_one(br);
            if value != 0 {
                last = (value - 1) as u8;
                self.lengths[cur] = last;
                cur += 1;
            } else {
                let mut count = br.read(3) + 2;
                if count == 7 + 2 {
                    count += br.read(rlefullbits);
                }
                while count != 0 && cur < self.numcodes {
                    self.lengths[cur] = last;
                    cur += 1;
                    count -= 1;
                }
            }
        }
        self.assign_and_build()?;
        if br.overflow {
            return Err(Error::codec("huffman tree truncated"));
        }
        Ok(())
    }

    pub fn decode_one(&self, br: &mut BitReader<'_>) -> u32 {
        let bits = br.peek(self.maxbits) as usize;
        let e = self.lookup.get(bits).copied().unwrap_or(0);
        let len = e & 0x1f;
        br.remove(len.max(1));
        e >> 5
    }
}

/// Decode the CHD `huff` hunk codec: an 8-bit Huffman stream.
pub fn decode_huff8(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut br = BitReader::new(src);
    let mut dec = HuffDecoder::new(256, 16);
    dec.import_tree_huffman(&mut br)?;
    let mut out = Vec::with_capacity(out_len);
    for _ in 0..out_len {
        out.push(dec.decode_one(&mut br) as u8);
    }
    if br.overflow {
        return Err(Error::codec("huff stream truncated"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rle_tree_fixed_lengths() {
        // 16 symbols, all length 4: encode tree as sixteen raw 4s.
        let mut w = BitWriter::new();
        for _ in 0..16 {
            w.write(4, 4);
        }
        for s in [3u32, 15, 0, 7] {
            w.write(s, 4);
        }
        let data = w.finish();
        let mut br = BitReader::new(&data);
        let mut d = HuffDecoder::new(16, 8);
        d.import_tree_rle(&mut br).unwrap();
        let got: Vec<u32> = (0..4).map(|_| d.decode_one(&mut br)).collect();
        assert_eq!(got, vec![3, 15, 0, 7]);
    }
}
