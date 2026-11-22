//! Wii disc partitions: partition table, ticket/TMD, title-key handling with
//! user-supplied common keys, decrypted partition-data view and H0–H3 hash verification.

use crate::binary::{u32be, u64be};
use crate::crypto::{cbc_decrypt, sha1};
use crate::{DataSource, Error, KeyProvider, Result, SharedSource, read_vec};
use serde::Serialize;
use std::sync::Mutex;
use zeroize::Zeroizing;

pub const CLUSTER: u64 = 0x8000;
pub const CLUSTER_DATA: u64 = 0x7C00;
pub const H3_SIZE: u64 = 0x18000;

/// Key names for the Wii common keys (index from the ticket).
pub fn common_key_name(index: u8) -> &'static str {
    match index {
        1 => "wii_korean_key",
        2 => "vwii_common_key",
        _ => "wii_common_key",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PartitionInfo {
    pub index: usize,
    pub group: usize,
    pub offset: u64,
    pub kind: u32,
    pub title_id: u64,
    pub common_key_index: u8,
    #[serde(skip)]
    pub encrypted_titlekey: [u8; 16],
    pub tmd_offset: u64,
    pub tmd_size: u64,
    pub cert_offset: u64,
    pub cert_size: u64,
    pub h3_offset: u64,
    pub data_offset: u64,
    pub data_size: u64,
}

impl PartitionInfo {
    pub fn kind_name(&self) -> String {
        match self.kind {
            0 => "game".into(),
            1 => "update".into(),
            2 => "channel".into(),
            k => {
                let b = k.to_be_bytes();
                if b.iter().all(|c| c.is_ascii_alphanumeric()) { String::from_utf8_lossy(&b).into_owned() } else { format!("0x{k:08x}") }
            }
        }
    }
    pub fn abs_data(&self) -> u64 {
        self.offset + self.data_offset
    }
}

pub fn read_partitions(s: &dyn DataSource) -> Result<Vec<PartitionInfo>> {
    let t = read_vec(s, 0x40000, 0x20, 0x20)?;
    let mut out = Vec::new();
    let len = s.len()?;
    for g in 0..4 {
        let count = u32be(&t, g * 8)? as u64;
        let off = (u32be(&t, g * 8 + 4)? as u64) << 2;
        if count == 0 {
            continue;
        }
        if count > 64 || off + count * 8 > len {
            return Err(Error::malformed("Wii partition table out of range"));
        }
        let e = read_vec(s, off, count * 8, 64 * 8)?;
        for i in 0..count as usize {
            let poff = (u32be(&e, i * 8)? as u64) << 2;
            let kind = u32be(&e, i * 8 + 4)?;
            if poff + 0x2C0 > len {
                return Err(Error::bounds("Wii partition header beyond image"));
            }
            let h = read_vec(s, poff, 0x2C0, 0x2C0)?;
            let p = PartitionInfo {
                index: out.len(),
                group: g,
                offset: poff,
                kind,
                title_id: u64be(&h, 0x1DC)?,
                common_key_index: h[0x1F1],
                encrypted_titlekey: crate::binary::array(&h, 0x1BF)?,
                tmd_size: u32be(&h, 0x2A4)? as u64,
                tmd_offset: (u32be(&h, 0x2A8)? as u64) << 2,
                cert_size: u32be(&h, 0x2AC)? as u64,
                cert_offset: (u32be(&h, 0x2B0)? as u64) << 2,
                h3_offset: (u32be(&h, 0x2B4)? as u64) << 2,
                data_offset: (u32be(&h, 0x2B8)? as u64) << 2,
                data_size: (u32be(&h, 0x2BC)? as u64) << 2,
            };
            out.push(p);
        }
    }
    Ok(out)
}

/// Decrypt the partition title key with a user-supplied common key.
pub fn titlekey(p: &PartitionInfo, keys: &dyn KeyProvider) -> Result<Zeroizing<[u8; 16]>> {
    let name = common_key_name(p.common_key_index);
    let ck = crate::crypto::key16(keys, name)
        .ok_or_else(|| Error::needs_keys(format!("key material `{name}` is required to decrypt Wii partitions")))?;
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&p.title_id.to_be_bytes());
    let mut k = Zeroizing::new(p.encrypted_titlekey);
    cbc_decrypt(&ck, &iv, &mut k[..])?;
    Ok(k)
}

/// Content-0 SHA-1 from the partition TMD (covers the H3 table).
pub fn tmd_h3_hash(s: &dyn DataSource, p: &PartitionInfo) -> Result<[u8; 20]> {
    let tmd = read_vec(s, p.offset + p.tmd_offset, p.tmd_size, 1 << 20)?;
    if tmd.len() < 0x1E4 + 0x24 {
        return Err(Error::malformed("partition TMD too short"));
    }
    crate::binary::array(&tmd, 0x1E4 + 0x10)
}

/// Decrypted partition data view (0x7C00 payload bytes per 0x8000 cluster).
pub struct PartitionData {
    raw: SharedSource,
    base: u64,
    clusters: u64,
    key: Zeroizing<[u8; 16]>,
    cache: Mutex<Option<(u64, Vec<u8>)>>,
}

impl PartitionData {
    pub fn new(raw: SharedSource, p: &PartitionInfo, key: Zeroizing<[u8; 16]>) -> Result<Self> {
        let avail = raw.len()?.saturating_sub(p.abs_data());
        let clusters = p.data_size.min(avail) / CLUSTER;
        Ok(PartitionData { raw, base: p.abs_data(), clusters, key, cache: Mutex::new(None) })
    }

    /// Decrypt one cluster: returns (hash block 0x400, data 0x7C00).
    pub fn cluster(&self, c: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut enc = read_vec(self.raw.as_ref(), self.base + c * CLUSTER, CLUSTER, CLUSTER)?;
        let iv: [u8; 16] = crate::binary::array(&enc, 0x3D0)?;
        let (h, d) = enc.split_at_mut(0x400);
        cbc_decrypt(&self.key, &iv, d)?;
        cbc_decrypt(&self.key, &[0u8; 16], h)?;
        Ok((h.to_vec(), d.to_vec()))
    }

    fn data_block(&self, c: u64) -> Result<Vec<u8>> {
        if let Some((cc, d)) = self.cache.lock().map_err(|_| Error::internal("poisoned"))?.as_ref() {
            if *cc == c {
                return Ok(d.clone());
            }
        }
        let (_, d) = self.cluster(c)?;
        *self.cache.lock().map_err(|_| Error::internal("poisoned"))? = Some((c, d.clone()));
        Ok(d)
    }

    /// Verify H0..H3 for every cluster against the partition's H3 table.
    pub fn verify_hashes(&self, h3: &[u8], job: &crate::JobContext) -> Result<(u64, u64)> {
        let mut bad = 0u64;
        let mut p = crate::ByteProgress::new(job, crate::Phase::Verifying, Some(self.clusters * CLUSTER));
        for c in 0..self.clusters {
            let (h, d) = self.cluster(c)?;
            let mut ok = true;
            for i in 0..31 {
                if sha1(&d[i * 0x400..(i + 1) * 0x400])[..] != h[i * 20..i * 20 + 20] {
                    ok = false;
                }
            }
            let h1i = (c % 8) as usize;
            if sha1(&h[..0x26C])[..] != h[0x280 + h1i * 20..0x280 + h1i * 20 + 20] {
                ok = false;
            }
            let h2i = ((c / 8) % 8) as usize;
            if sha1(&h[0x280..0x280 + 0xA0])[..] != h[0x340 + h2i * 20..0x340 + h2i * 20 + 20] {
                ok = false;
            }
            let h3i = (c / 64) as usize;
            if h3.len() >= (h3i + 1) * 20 && sha1(&h[0x340..0x340 + 0xA0])[..] != h3[h3i * 20..h3i * 20 + 20] {
                ok = false;
            }
            if !ok {
                bad += 1;
            }
            p.advance(CLUSTER)?;
        }
        Ok((self.clusters, bad))
    }
}

impl DataSource for PartitionData {
    fn len(&self) -> Result<u64> {
        Ok(self.clusters * CLUSTER_DATA)
    }
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.clusters * CLUSTER_DATA)?;
        while !out.is_empty() {
            let c = offset / CLUSTER_DATA;
            let within = (offset % CLUSTER_DATA) as usize;
            let d = self.data_block(c)?;
            let n = (CLUSTER_DATA as usize - within).min(out.len());
            out[..n].copy_from_slice(&d[within..within + n]);
            out = &mut out[n..];
            offset += n as u64;
        }
        Ok(())
    }
}
