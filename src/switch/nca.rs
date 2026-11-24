//! NCA content archives: header decryption, section metadata, key resolution and
//! decrypted section views (AES-CTR, AES-CTR-EX, AES-XTS, plaintext).
//!
//! NCA internals are encrypted and integrity-protected. Everything here requires
//! user-supplied key material; nothing is derived from or embedded in Romux.

use crate::binary::{u32le, u64le};
use crate::crypto::{XtsNintendo, ctr_apply, ecb_decrypt, ecb_encrypt};
use crate::switch::keys;
use crate::{DataSource, Error, KeyProvider, Result, SharedSource, hex, read_vec};
use serde::Serialize;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const HEADER_SIZE: usize = 0xC00;
pub const MEDIA_UNIT: u64 = 0x200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Program,
    Meta,
    Control,
    Manual,
    Data,
    PublicData,
    Unknown,
}

impl ContentType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => ContentType::Program,
            1 => ContentType::Meta,
            2 => ContentType::Control,
            3 => ContentType::Manual,
            4 => ContentType::Data,
            5 => ContentType::PublicData,
            _ => ContentType::Unknown,
        }
    }
    pub fn as_u8(&self) -> u8 {
        match self {
            ContentType::Program => 0,
            ContentType::Meta => 1,
            ContentType::Control => 2,
            ContentType::Manual => 3,
            ContentType::Data => 4,
            ContentType::PublicData => 5,
            ContentType::Unknown => 0xFF,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsType {
    RomFs,
    PartitionFs,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionType {
    Auto,
    None,
    AesXts,
    AesCtr,
    AesCtrEx,
    AesCtrSkipLayerHash,
    AesCtrExSkipLayerHash,
    Unknown,
}

impl EncryptionType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => EncryptionType::Auto,
            1 => EncryptionType::None,
            2 => EncryptionType::AesXts,
            3 => EncryptionType::AesCtr,
            4 => EncryptionType::AesCtrEx,
            5 => EncryptionType::AesCtrSkipLayerHash,
            6 => EncryptionType::AesCtrExSkipLayerHash,
            _ => EncryptionType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashType {
    Auto,
    None,
    HierarchicalSha256,
    HierarchicalIntegrity,
    Other,
}

/// One filesystem header inside the NCA header.
#[derive(Clone)]
pub struct FsHeader {
    pub raw: [u8; 0x200],
    pub index: usize,
    pub start: u64,
    pub end: u64,
}

impl FsHeader {
    pub fn version(&self) -> u16 {
        u16::from_le_bytes([self.raw[0], self.raw[1]])
    }
    pub fn fs_type(&self) -> FsType {
        match self.raw[2] {
            0 => FsType::RomFs,
            1 => FsType::PartitionFs,
            _ => FsType::Unknown,
        }
    }
    pub fn hash_type(&self) -> HashType {
        match self.raw[3] {
            0 => HashType::Auto,
            1 => HashType::None,
            2 => HashType::HierarchicalSha256,
            3 => HashType::HierarchicalIntegrity,
            _ => HashType::Other,
        }
    }
    pub fn encryption(&self) -> EncryptionType {
        EncryptionType::from_u8(self.raw[4])
    }
    pub fn hash_data(&self) -> &[u8] {
        &self.raw[0x8..0x100]
    }
    pub fn patch_info(&self) -> &[u8] {
        &self.raw[0x100..0x140]
    }
    pub fn generation(&self) -> u32 {
        u32::from_le_bytes([self.raw[0x140], self.raw[0x141], self.raw[0x142], self.raw[0x143]])
    }
    pub fn secure_value(&self) -> u32 {
        u32::from_le_bytes([self.raw[0x144], self.raw[0x145], self.raw[0x146], self.raw[0x147]])
    }
    /// Upper 8 bytes of the AES-CTR counter for this section.
    pub fn ctr_upper(&self) -> [u8; 8] {
        let mut u = [0u8; 8];
        for (i, b) in u.iter_mut().enumerate() {
            *b = self.raw[0x147 - i];
        }
        u
    }
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
    /// For PartitionFs sections with hierarchical SHA-256: (offset, size) of the PFS0.
    pub fn pfs0_region(&self) -> Option<(u64, u64)> {
        if self.hash_type() != HashType::HierarchicalSha256 {
            return None;
        }
        let hd = self.hash_data();
        let layers = u32le(hd, 0x24).ok()? as usize;
        if !(1..=5).contains(&layers) {
            return None;
        }
        let o = 0x28 + (layers - 1) * 0x10;
        Some((u64le(hd, o).ok()?, u64le(hd, o + 8).ok()?))
    }
    /// For hierarchical SHA-256: (master hash, block size, hash-table region).
    pub fn sha256_layer0(&self) -> Option<([u8; 32], u32, u64, u64)> {
        if self.hash_type() != HashType::HierarchicalSha256 {
            return None;
        }
        let hd = self.hash_data();
        Some((crate::binary::array(hd, 0).ok()?, u32le(hd, 0x20).ok()?, u64le(hd, 0x28).ok()?, u64le(hd, 0x30).ok()?))
    }
    /// For IVFC (hierarchical integrity): (offset, size) of the data level (RomFS).
    pub fn ivfc_data_region(&self) -> Option<(u64, u64)> {
        let hd = self.hash_data();
        if &hd[..4] != b"IVFC" {
            return None;
        }
        let max_layers = u32le(hd, 0x0C).ok()? as usize;
        if !(2..=7).contains(&max_layers) {
            return None;
        }
        let o = 0x10 + (max_layers - 2) * 0x18;
        Some((u64le(hd, o).ok()?, u64le(hd, o + 8).ok()?))
    }
    pub fn indirect_table(&self) -> (u64, u64, &[u8]) {
        let p = self.patch_info();
        (
            u64::from_le_bytes(p[0..8].try_into().unwrap_or([0; 8])),
            u64::from_le_bytes(p[8..16].try_into().unwrap_or([0; 8])),
            &p[0x10..0x20],
        )
    }
    pub fn aes_ctr_ex_table(&self) -> (u64, u64, &[u8]) {
        let p = self.patch_info();
        (
            u64::from_le_bytes(p[0x20..0x28].try_into().unwrap_or([0; 8])),
            u64::from_le_bytes(p[0x28..0x30].try_into().unwrap_or([0; 8])),
            &p[0x30..0x40],
        )
    }
    pub fn is_patch(&self) -> bool {
        let (_, size, hdr) = self.indirect_table();
        size > 0 && &hdr[..4] == b"BKTR"
    }
    /// Sparse-storage info (FS header 0x148..0x178) is present: the stored section is a
    /// relocated subset of a larger virtual storage.
    pub fn has_sparse_info(&self) -> bool {
        self.raw[0x148..0x178].iter().any(|&b| b != 0)
    }
    /// Compressed-storage info (FS header 0x178..0x1A0) is present.
    pub fn has_compression_info(&self) -> bool {
        self.raw[0x178..0x1A0].iter().any(|&b| b != 0)
    }
}

/// A decrypted NCA header.
#[derive(Clone)]
pub struct NcaHeader {
    pub raw: Zeroizing<Vec<u8>>,
    pub magic: [u8; 4],
    /// Header bytes were stored unencrypted.
    pub plaintext: bool,
    pub distribution: u8,
    pub content_type: ContentType,
    pub key_gen_old: u8,
    pub kaek_index: u8,
    pub content_size: u64,
    pub program_id: u64,
    pub content_index: u32,
    pub sdk_version: u32,
    pub key_gen: u8,
    pub rights_id: [u8; 16],
    pub sections: Vec<FsHeader>,
}

impl std::fmt::Debug for NcaHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NcaHeader")
            .field("magic", &String::from_utf8_lossy(&self.magic))
            .field("content_type", &self.content_type)
            .field("program_id", &format!("{:016x}", self.program_id))
            .field("key_generation", &self.key_generation())
            .finish()
    }
}

fn has_magic(b: &[u8]) -> bool {
    matches!(&b[0x200..0x204], b"NCA3" | b"NCA2" | b"NCA0" | b"DNCA")
}

/// Header marker of a decrypted NCA ("DNCA"): plaintext header, every section declares
/// encryption type 1 (none) and its FS-header hash is recomputed. Used by DNSP/DXCI
/// packages and NX archives.
pub const DNCA_MAGIC: &[u8; 4] = b"DNCA";

impl NcaHeader {
    /// Decrypt (or accept a plaintext) 0xC00-byte header.
    pub fn decrypt(enc: &[u8], key_provider: &dyn KeyProvider) -> Result<Self> {
        if enc.len() < HEADER_SIZE {
            return Err(Error::bounds("NCA shorter than its header"));
        }
        if has_magic(enc) {
            let raw = Zeroizing::new(enc[..HEADER_SIZE].to_vec());
            return Self::parse(raw, true);
        }
        let key = keys::header_key(key_provider)?;
        let xts = XtsNintendo::new(&key[..])?;
        let mut dec = Zeroizing::new(enc[..HEADER_SIZE].to_vec());
        xts.decrypt(&mut dec, 0, 0x200)?;
        match &dec[0x200..0x204] {
            b"NCA3" => {}
            b"NCA2" => {
                dec[..].copy_from_slice(&enc[..HEADER_SIZE]);
                xts.decrypt(&mut dec[..0x400], 0, 0x200)?;
                for i in 0..4 {
                    let o = 0x400 + i * 0x200;
                    xts.decrypt(&mut dec[o..o + 0x200], 0, 0x200)?;
                }
            }
            b"NCA0" => return Err(Error::unsupported("NCA0 archives are not supported")),
            _ => {
                return Err(Error::new(
                    crate::ErrorCode::MalformedHeader,
                    "NCA header did not decrypt to a known magic (wrong header_key or not an NCA)",
                ));
            }
        }
        Self::parse(dec, false)
    }

    fn parse(raw: Zeroizing<Vec<u8>>, plaintext: bool) -> Result<Self> {
        let r = &raw[..];
        let magic: [u8; 4] = crate::binary::array(r, 0x200)?;
        let mut sections = Vec::new();
        for i in 0..4 {
            let e = 0x240 + i * 0x10;
            let start = u32le(r, e)? as u64 * MEDIA_UNIT;
            let end = u32le(r, e + 4)? as u64 * MEDIA_UNIT;
            if end == 0 && start == 0 {
                continue;
            }
            if end < start {
                return Err(Error::malformed(format!("NCA section {i} ends before it starts")));
            }
            let mut fh = [0u8; 0x200];
            fh.copy_from_slice(&r[0x400 + i * 0x200..0x600 + i * 0x200]);
            sections.push(FsHeader { raw: fh, index: i, start, end });
        }
        Ok(NcaHeader {
            magic,
            plaintext,
            distribution: r[0x204],
            content_type: ContentType::from_u8(r[0x205]),
            key_gen_old: r[0x206],
            kaek_index: r[0x207],
            content_size: u64le(r, 0x208)?,
            program_id: u64le(r, 0x210)?,
            content_index: u32le(r, 0x218)?,
            sdk_version: u32le(r, 0x21C)?,
            key_gen: r[0x220],
            rights_id: crate::binary::array(r, 0x230)?,
            sections,
            raw,
        })
    }

    /// Effective master-key generation index.
    pub fn key_generation(&self) -> u8 {
        self.key_gen_old.max(self.key_gen).saturating_sub(1)
    }
    pub fn has_rights_id(&self) -> bool {
        self.rights_id != [0u8; 16]
    }
    /// The header carries the decrypted-content (DNCA) marker.
    pub fn is_dnca(&self) -> bool {
        &self.magic == DNCA_MAGIC
    }
    pub fn rights_id_hex(&self) -> String {
        hex(&self.rights_id)
    }
    pub fn title_id(&self) -> String {
        format!("{:016x}", self.program_id)
    }
    pub fn sdk_version_string(&self) -> String {
        let v = self.sdk_version;
        format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)
    }
    pub fn encrypted_key_area(&self) -> [[u8; 16]; 4] {
        let mut k = [[0u8; 16]; 4];
        for (i, slot) in k.iter_mut().enumerate() {
            slot.copy_from_slice(&self.raw[0x300 + i * 16..0x310 + i * 16]);
        }
        k
    }
    pub fn fs_header_hash(&self, index: usize) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.raw[0x280 + index * 32..0x2A0 + index * 32]);
        h
    }

    /// Re-encrypt the (possibly modified) header as NCA3.
    pub fn encrypt(&self, key_provider: &dyn KeyProvider) -> Result<Vec<u8>> {
        if &self.magic != b"NCA3" {
            return Err(Error::unsupported("only NCA3 headers can be re-encrypted"));
        }
        let key = keys::header_key(key_provider)?;
        let xts = XtsNintendo::new(&key[..])?;
        let mut out = self.raw.to_vec();
        xts.encrypt(&mut out, 0, 0x200)?;
        Ok(out)
    }

    /// Decrypt the key area with the appropriate key-area key.
    pub fn decrypt_key_area(&self, key_provider: &dyn KeyProvider) -> Result<Zeroizing<[[u8; 16]; 4]>> {
        let kak = keys::key_area_key(key_provider, self.kaek_index, self.key_generation())?;
        let mut ka = Zeroizing::new(self.encrypted_key_area());
        for k in ka.iter_mut() {
            ecb_decrypt(&kak, k)?;
        }
        Ok(ka)
    }

    /// Replace rights-ID crypto with standard crypto: clear the rights ID and store the
    /// title key in key-area slot 2 (re-encrypted with the key-area key). The header
    /// signature becomes invalid; the content data is unchanged.
    pub fn convert_to_standard_crypto(&mut self, titlekey: &[u8; 16], key_provider: &dyn KeyProvider) -> Result<()> {
        if !self.has_rights_id() {
            return Ok(());
        }
        let kak = keys::key_area_key(key_provider, self.kaek_index, self.key_generation())?;
        let mut slot = *titlekey;
        ecb_encrypt(&kak, &mut slot)?;
        let raw = &mut self.raw;
        raw[0x300 + 2 * 16..0x300 + 3 * 16].copy_from_slice(&slot);
        raw[0x230..0x240].fill(0);
        self.rights_id = [0; 16];
        Ok(())
    }
}

/// Decrypt a common-ticket title key with `titlekek_XX`.
pub fn decrypt_titlekey(enc: &[u8; 16], generation: u8, key_provider: &dyn KeyProvider) -> Result<Zeroizing<[u8; 16]>> {
    let kek = keys::titlekek(key_provider, generation)?;
    let mut k = Zeroizing::new(*enc);
    ecb_decrypt(&kek, &mut k[..])?;
    Ok(k)
}

/// Resolved section keys.
#[derive(Clone)]
pub struct SectionKeys {
    pub ctr: Zeroizing<[u8; 16]>,
    pub xts: Zeroizing<[u8; 32]>,
}

/// Resolve section keys from the key area, or from a decrypted title key for rights-ID titles.
pub fn section_keys(h: &NcaHeader, key_provider: &dyn KeyProvider, titlekey: Option<&[u8; 16]>) -> Result<SectionKeys> {
    if h.has_rights_id() {
        let tk = titlekey.ok_or_else(|| {
            Error::needs_keys(format!("NCA uses rights ID {}; a matching ticket and titlekek are required", h.rights_id_hex()))
        })?;
        return Ok(SectionKeys { ctr: Zeroizing::new(*tk), xts: Zeroizing::new([0u8; 32]) });
    }
    let ka = h.decrypt_key_area(key_provider)?;
    let mut xts = Zeroizing::new([0u8; 32]);
    xts[..16].copy_from_slice(&ka[0]);
    xts[16..].copy_from_slice(&ka[1]);
    Ok(SectionKeys { ctr: Zeroizing::new(ka[2]), xts })
}

/// Build the 16-byte counter base for a section.
pub fn ctr_base(upper: [u8; 8]) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[..8].copy_from_slice(&upper);
    c
}

/// AES-CTR decrypted view of a byte range of an NCA (offsets in the CTR are absolute).
pub struct CtrSource {
    inner: SharedSource,
    base: u64,
    len: u64,
    key: Zeroizing<[u8; 16]>,
    upper: [u8; 8],
    /// AES-CTR-EX subsections: (start offset relative to `base`, generation).
    subsections: Option<Arc<Vec<(u64, u32)>>>,
}

impl CtrSource {
    pub fn new(inner: SharedSource, base: u64, len: u64, key: &[u8; 16], upper: [u8; 8]) -> Result<Self> {
        crate::check_range(base, len, inner.len()?)?;
        Ok(CtrSource { inner, base, len, key: Zeroizing::new(*key), upper, subsections: None })
    }
    pub fn with_subsections(mut self, subs: Vec<(u64, u32)>) -> Self {
        self.subsections = Some(Arc::new(subs));
        self
    }

    fn counter_for(&self, rel: u64) -> ([u8; 16], u64) {
        let mut c = ctr_base(self.upper);
        let mut limit = u64::MAX;
        if let Some(subs) = &self.subsections {
            let idx = match subs.binary_search_by(|(o, _)| o.cmp(&rel)) {
                Ok(i) => i,
                Err(i) => i.saturating_sub(1),
            };
            if let Some((_, r#gen)) = subs.get(idx) {
                c[4..8].copy_from_slice(&r#gen.to_be_bytes());
            }
            if let Some((next, _)) = subs.get(idx + 1) {
                limit = *next;
            }
        }
        (c, limit)
    }
}

impl DataSource for CtrSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        let mut done = 0usize;
        while done < out.len() {
            let rel = offset + done as u64;
            let (ctr, limit) = self.counter_for(rel);
            let n = ((limit - rel).min((out.len() - done) as u64)) as usize;
            let chunk = &mut out[done..done + n];
            self.inner.read_exact_at(self.base + rel, chunk)?;
            ctr_apply(&self.key, ctr, self.base + rel, chunk);
            done += n;
        }
        Ok(())
    }
}

/// AES-XTS decrypted view (sector numbers relative to section start, 0x200 sectors).
pub struct XtsSource {
    inner: SharedSource,
    base: u64,
    len: u64,
    xts: XtsNintendo,
}

impl DataSource for XtsSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        crate::check_range(offset, out.len() as u64, self.len)?;
        let first = offset / 0x200;
        let last = (offset + out.len() as u64).div_ceil(0x200);
        let mut buf = vec![0u8; ((last - first) * 0x200) as usize];
        let avail = (self.len - first * 0x200).min(buf.len() as u64) as usize;
        self.inner.read_exact_at(self.base + first * 0x200, &mut buf[..avail])?;
        self.xts.decrypt(&mut buf, first, 0x200)?;
        let s = (offset - first * 0x200) as usize;
        out.copy_from_slice(&buf[s..s + out.len()]);
        Ok(())
    }
}

/// An NCA opened with (optional) key material.
pub struct Nca {
    pub source: SharedSource,
    pub header: NcaHeader,
    keys: Option<SectionKeys>,
    pub key_error: Option<String>,
}

impl Nca {
    /// Parse the header. Fails with `NeedsKeyMaterial` without `header_key` (unless plaintext).
    pub fn open(source: SharedSource, key_provider: &dyn KeyProvider, titlekey: Option<&[u8; 16]>) -> Result<Self> {
        let raw = read_vec(source.as_ref(), 0, HEADER_SIZE as u64, HEADER_SIZE as u64)?;
        let header = NcaHeader::decrypt(&raw, key_provider)?;
        let total = source.len()?;
        for s in &header.sections {
            if s.end > total {
                return Err(Error::bounds(format!("NCA section {} extends beyond the archive", s.index)));
            }
        }
        let (keys, key_error) = match section_keys(&header, key_provider, titlekey) {
            Ok(k) => (Some(k), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Ok(Nca { source, header, keys, key_error })
    }

    pub fn has_section_keys(&self) -> bool {
        self.keys.is_some()
    }

    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    pub fn section_keys(&self) -> Option<&SectionKeys> {
        self.keys.as_ref()
    }

    fn need_keys(&self) -> Result<&SectionKeys> {
        self.keys.as_ref().ok_or_else(|| Error::needs_keys(self.key_error.clone().unwrap_or_else(|| "section keys unavailable".into())))
    }

    /// Decrypted view of a whole section (`index` = section slot 0..3).
    pub fn section(&self, index: usize) -> Result<SharedSource> {
        let s = self
            .header
            .sections
            .iter()
            .find(|s| s.index == index)
            .ok_or_else(|| Error::invalid_arg(format!("NCA has no section {index}")))?;
        let len = s.size();
        match s.encryption() {
            EncryptionType::None => crate::SubSource::shared(self.source.clone(), s.start, len),
            EncryptionType::AesCtr | EncryptionType::AesCtrSkipLayerHash | EncryptionType::Auto => {
                let k = self.need_keys()?;
                Ok(Arc::new(CtrSource::new(self.source.clone(), s.start, len, &k.ctr, s.ctr_upper())?))
            }
            EncryptionType::AesXts => {
                let k = self.need_keys()?;
                Ok(Arc::new(XtsSource { inner: self.source.clone(), base: s.start, len, xts: XtsNintendo::new(&k.xts[..])? }))
            }
            EncryptionType::AesCtrEx | EncryptionType::AesCtrExSkipLayerHash => {
                let k = self.need_keys()?;
                let subs = self.ctr_ex_subsections(s)?;
                Ok(Arc::new(CtrSource::new(self.source.clone(), s.start, len, &k.ctr, s.ctr_upper())?.with_subsections(subs)))
            }
            EncryptionType::Unknown => Err(Error::unsupported(format!("NCA section {index} uses an unknown encryption type"))),
        }
    }

    /// The whole NCA as a decrypted NCA ("DNCA"): plaintext header with the `DNCA` marker,
    /// every section decrypted in place and declared as encryption type 1 with a recomputed
    /// FS-header hash. Sizes and offsets are unchanged, so section tables, hash trees and
    /// BKTR patch tables keep their meaning. Bytes outside sections are copied as stored.
    ///
    /// Sparse sections (relocated storage) are rejected: decrypting them needs the virtual
    /// layout, which this view does not rebuild.
    pub fn dnca_view(&self) -> Result<SharedSource> {
        let total = self.source.len()?;
        if self.header.content_size != total {
            return Err(Error::malformed(format!("NCA header size {} differs from the stored size {total}", self.header.content_size)));
        }
        let mut header = self.header.raw.to_vec();
        header[0x200..0x204].copy_from_slice(DNCA_MAGIC);
        let mut sections: Vec<&FsHeader> = self.header.sections.iter().collect();
        sections.sort_by_key(|s| s.start);
        for s in &sections {
            if s.has_sparse_info() {
                return Err(Error::unsupported(format!(
                    "NCA section {} uses sparse storage; decrypting it into a DNCA is not supported",
                    s.index
                )));
            }
            if s.start < HEADER_SIZE as u64 || s.end > total {
                return Err(Error::bounds(format!("NCA section {} range is invalid", s.index)));
            }
            let o = 0x400 + s.index * 0x200;
            header[o + 4] = 1;
            let h = crate::crypto::sha256(&header[o..o + 0x200]);
            header[0x280 + s.index * 32..0x2A0 + s.index * 32].copy_from_slice(&h);
        }
        for w in sections.windows(2) {
            if w[1].start < w[0].end {
                return Err(Error::malformed("NCA sections overlap"));
            }
        }
        let mut parts: Vec<SharedSource> = vec![Arc::new(crate::MemorySource::new(header))];
        let mut at = HEADER_SIZE as u64;
        for s in &sections {
            if s.start > at {
                parts.push(crate::SubSource::shared(self.source.clone(), at, s.start - at)?);
            }
            parts.push(self.dnca_section(s)?);
            at = s.end;
        }
        if total > at {
            parts.push(crate::SubSource::shared(self.source.clone(), at, total - at)?);
        }
        Ok(Arc::new(crate::ConcatSource::new(parts)?))
    }

    /// Decrypted bytes of one whole section as stored (AES-CTR-EX sections also decrypt
    /// their trailing BKTR tables, which use the section's plain counter).
    fn dnca_section(&self, s: &FsHeader) -> Result<SharedSource> {
        match s.encryption() {
            EncryptionType::AesCtrEx | EncryptionType::AesCtrExSkipLayerHash => {
                let k = self.need_keys()?;
                let mut subs = self.ctr_ex_subsections(s)?;
                let (ind_off, ind_size, _) = s.indirect_table();
                let (ex_off, ex_size, _) = s.aes_ctr_ex_table();
                let tables =
                    [(ind_off, ind_size), (ex_off, ex_size)].iter().filter(|(_, n)| *n > 0).map(|(o, _)| *o).min().unwrap_or(s.size());
                let upper = s.ctr_upper();
                let plain_gen = u32::from_be_bytes([upper[4], upper[5], upper[6], upper[7]]);
                subs.retain(|(o, _)| *o < tables);
                subs.push((tables, plain_gen));
                Ok(Arc::new(CtrSource::new(self.source.clone(), s.start, s.size(), &k.ctr, upper)?.with_subsections(subs)))
            }
            _ => self.section(s.index),
        }
    }

    /// Plain-CTR view of a section regardless of its declared type (used for bucket tables).
    pub fn section_plain_ctr(&self, s: &FsHeader) -> Result<SharedSource> {
        let k = self.need_keys()?;
        Ok(Arc::new(CtrSource::new(self.source.clone(), s.start, s.size(), &k.ctr, s.ctr_upper())?))
    }

    fn ctr_ex_subsections(&self, s: &FsHeader) -> Result<Vec<(u64, u32)>> {
        let (off, size, hdr) = s.aes_ctr_ex_table();
        if &hdr[..4] != b"BKTR" {
            return Err(Error::malformed("AES-CTR-EX section without a BKTR subsection table"));
        }
        let count = u32le(hdr, 8)? as u64;
        let plain = self.section_plain_ctr(s)?;
        let table = read_vec(plain.as_ref(), off, size, 256 << 20)?;
        let entries = crate::switch::bktr::parse_bucket_tree(&table, 0x10, count)?;
        let mut v = Vec::with_capacity(entries.len());
        for e in entries {
            v.push((u64le(e, 0)?, u32le(e, 0xC)?));
        }
        Ok(v)
    }

    /// The PFS0 inside a PartitionFs section.
    pub fn pfs0(&self, index: usize, limits: &crate::ResourceLimits) -> Result<crate::switch::partition::PartitionFs> {
        let s = self.header.sections.iter().find(|s| s.index == index).ok_or_else(|| Error::invalid_arg("no such section"))?;
        let (off, size) = s.pfs0_region().ok_or_else(|| Error::unsupported("section is not a hierarchical-SHA256 PFS0"))?;
        let sec = self.section(index)?;
        let sub = crate::SubSource::shared(sec, off, size)?;
        crate::switch::partition::PartitionFs::parse(sub, crate::switch::partition::Kind::Pfs0, limits)
    }

    /// The RomFS data level of a RomFS section.
    pub fn romfs_source(&self, index: usize) -> Result<SharedSource> {
        let s = self.header.sections.iter().find(|s| s.index == index).ok_or_else(|| Error::invalid_arg("no such section"))?;
        let (off, size) = s.ivfc_data_region().ok_or_else(|| Error::unsupported("section has no IVFC RomFS level"))?;
        if s.is_patch() {
            return Err(Error::unsupported("this RomFS is a BKTR patch; use apply-update with its base title"));
        }
        crate::SubSource::shared(self.section(index)?, off, size)
    }

    /// Verify fs-header hashes and hierarchical SHA-256 master hashes.
    pub fn verify_structure(&self) -> Vec<(String, bool, String)> {
        let mut v = Vec::new();
        for s in &self.header.sections {
            let ok = crate::crypto::sha256(&s.raw) == self.header.fs_header_hash(s.index);
            v.push((format!("section {} header hash", s.index), ok, String::new()));
            if let Some((master, _bs, off, size)) = s.sha256_layer0() {
                match self.section(s.index).and_then(|sec| read_vec(sec.as_ref(), off, size, 64 << 20)) {
                    Ok(table) => {
                        v.push((format!("section {} master hash", s.index), crate::crypto::sha256(&table) == master, String::new()))
                    }
                    Err(e) => v.push((format!("section {} master hash", s.index), false, e.to_string())),
                }
            }
        }
        v
    }
}

#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    //! Synthetic NCA construction for tests (unsigned; uses caller-provided test keys).
    //!
    //! Synthetic-fixture builder (feature `testkit`; not part of the stable API).
    use super::*;
    use crate::switch::partition::{Kind, NewEntry, layout};

    pub struct TestKeys {
        pub header_key: [u8; 32],
        pub kak_app: [u8; 16],
        pub titlekek: [u8; 16],
        pub generation: u8,
    }

    impl TestKeys {
        pub fn sample() -> Self {
            TestKeys { header_key: [0x11; 32], kak_app: [0x22; 16], titlekek: [0x33; 16], generation: 0 }
        }
        pub fn provider(&self) -> crate::crypto::KeyFile {
            let mut k = crate::crypto::KeyFile::new();
            k.insert("header_key", &self.header_key);
            k.insert(&crate::switch::keys::key_area_key_name(0, self.generation), &self.kak_app);
            k.insert(&crate::switch::keys::titlekek_name(self.generation), &self.titlekek);
            k
        }
    }

    pub fn pfs0_image(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let entries: Vec<NewEntry> =
            files.iter().map(|(n, d)| NewEntry { name: n.to_string(), size: d.len() as u64, hashed_region: 0, hash: [0; 32] }).collect();
        let l = layout(Kind::Pfs0, &entries).expect("layout");
        let mut out = l.header;
        for (_, d) in files {
            out.extend_from_slice(d);
        }
        out
    }

    pub enum Section {
        /// PFS0 with hierarchical SHA-256.
        Pfs0(Vec<u8>),
        /// RomFS data placed at an IVFC data level.
        RomFs(Vec<u8>),
    }

    pub struct Spec {
        pub content_type: ContentType,
        pub program_id: u64,
        pub sections: Vec<Section>,
        /// When set, the NCA uses this (plain) title key via rights ID instead of the key area.
        pub titlekey: Option<[u8; 16]>,
        pub distribution: u8,
    }

    /// Build an encrypted NCA3 and return its bytes.
    pub fn build(spec: &Spec, keys: &TestKeys) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_SIZE];
        h[0x200..0x204].copy_from_slice(b"NCA3");
        h[0x204] = spec.distribution;
        h[0x205] = spec.content_type.as_u8();
        h[0x206] = keys.generation.min(2);
        h[0x207] = 0;
        h[0x210..0x218].copy_from_slice(&spec.program_id.to_le_bytes());
        h[0x21C..0x220].copy_from_slice(&0x0C01_0000u32.to_le_bytes());
        h[0x220] = if keys.generation >= 2 { keys.generation + 1 } else { 0 };
        let ctr_key = [0x5Au8; 16];
        let section_key = spec.titlekey.unwrap_or(ctr_key);
        if spec.titlekey.is_some() {
            let mut rid = [0u8; 16];
            rid[..8].copy_from_slice(&spec.program_id.to_be_bytes());
            rid[15] = keys.generation;
            h[0x230..0x240].copy_from_slice(&rid);
        } else {
            let mut slot = ctr_key;
            ecb_encrypt(&keys.kak_app, &mut slot).expect("ecb");
            h[0x320..0x330].copy_from_slice(&slot);
        }
        let mut body: Vec<u8> = vec![0u8; 0x4000 - HEADER_SIZE];
        for (i, sec) in spec.sections.iter().enumerate() {
            let start = (HEADER_SIZE + body.len()) as u64;
            let mut fs = [0u8; 0x200];
            fs[0..2].copy_from_slice(&2u16.to_le_bytes());
            fs[4] = 3; // AES-CTR
            let r#gen = (i as u32 + 1) * 7;
            fs[0x140..0x144].copy_from_slice(&r#gen.to_le_bytes());
            let data = match sec {
                Section::Pfs0(p) => {
                    fs[2] = 1;
                    fs[3] = 2;
                    let bs = 0x1000usize;
                    let mut table = Vec::new();
                    for c in p.chunks(bs) {
                        table.extend_from_slice(&crate::crypto::sha256(c));
                    }
                    let master = crate::crypto::sha256(&table);
                    let pfs_off = crate::binary::align_up(table.len() as u64, 0x200).expect("align");
                    let hd = &mut fs[8..0x100];
                    hd[0..32].copy_from_slice(&master);
                    hd[0x20..0x24].copy_from_slice(&(bs as u32).to_le_bytes());
                    hd[0x24..0x28].copy_from_slice(&2u32.to_le_bytes());
                    hd[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
                    hd[0x30..0x38].copy_from_slice(&(table.len() as u64).to_le_bytes());
                    hd[0x38..0x40].copy_from_slice(&pfs_off.to_le_bytes());
                    hd[0x40..0x48].copy_from_slice(&(p.len() as u64).to_le_bytes());
                    let mut d = table;
                    d.resize(pfs_off as usize, 0);
                    d.extend_from_slice(p);
                    d
                }
                Section::RomFs(r) => {
                    fs[2] = 0;
                    fs[3] = 3;
                    let hd = &mut fs[8..0x100];
                    hd[0..4].copy_from_slice(b"IVFC");
                    hd[4..8].copy_from_slice(&0x20000u32.to_le_bytes());
                    hd[8..12].copy_from_slice(&0x20u32.to_le_bytes());
                    hd[12..16].copy_from_slice(&7u32.to_le_bytes());
                    // Five 0x200-byte placeholder hash levels then the data level.
                    for lvl in 0..6usize {
                        let o = 0x10 + lvl * 0x18;
                        let (off, size) = if lvl < 5 { (lvl as u64 * 0x200, 0x200u64) } else { (0xA00u64, r.len() as u64) };
                        hd[o..o + 8].copy_from_slice(&off.to_le_bytes());
                        hd[o + 8..o + 16].copy_from_slice(&size.to_le_bytes());
                        hd[o + 16..o + 20].copy_from_slice(&14u32.to_le_bytes());
                    }
                    let mut d = vec![0u8; 0xA00];
                    d.extend_from_slice(r);
                    d
                }
            };
            let mut d = data;
            d.resize(crate::binary::align_up(d.len() as u64, 0x200).expect("align") as usize, 0);
            let end = start + d.len() as u64;
            let mut upper = [0u8; 8];
            for (k, b) in upper.iter_mut().enumerate() {
                *b = fs[0x147 - k];
            }
            ctr_apply(&section_key, ctr_base(upper), start, &mut d);
            body.extend_from_slice(&d);
            let e = 0x240 + i * 0x10;
            h[e..e + 4].copy_from_slice(&((start / MEDIA_UNIT) as u32).to_le_bytes());
            h[e + 4..e + 8].copy_from_slice(&((end / MEDIA_UNIT) as u32).to_le_bytes());
            h[0x280 + i * 32..0x2A0 + i * 32].copy_from_slice(&crate::crypto::sha256(&fs));
            h[0x400 + i * 0x200..0x600 + i * 0x200].copy_from_slice(&fs);
        }
        let total = (HEADER_SIZE + body.len()) as u64;
        h[0x208..0x210].copy_from_slice(&total.to_le_bytes());
        let xts = XtsNintendo::new(&keys.header_key).expect("xts");
        xts.encrypt(&mut h, 0, 0x200).expect("xts");
        h.extend_from_slice(&body);
        h
    }

    /// Build a common ticket for a rights-ID title key.
    pub fn ticket(program_id: u64, titlekey: &[u8; 16], keys: &TestKeys) -> (String, Vec<u8>) {
        let mut t = vec![0u8; 0x2C0];
        t[0..4].copy_from_slice(&0x10004u32.to_le_bytes());
        let mut enc = *titlekey;
        ecb_encrypt(&keys.titlekek, &mut enc).expect("ecb");
        t[0x180..0x190].copy_from_slice(&enc);
        t[0x280] = 2;
        t[0x285] = keys.generation;
        let mut rid = [0u8; 16];
        rid[..8].copy_from_slice(&program_id.to_be_bytes());
        rid[15] = keys.generation;
        t[0x2A0..0x2B0].copy_from_slice(&rid);
        (format!("{}.tik", hex(&rid)), t)
    }

    /// Name an NCA by its content ID (first 16 bytes of SHA-256).
    pub fn content_name(data: &[u8], meta: bool) -> String {
        let id = hex(&crate::crypto::sha256(data)[..16]);
        if meta { format!("{id}.cnmt.nca") } else { format!("{id}.nca") }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::{MemorySource, ResourceLimits};

    #[test]
    fn header_roundtrip_and_sections() {
        let keys = TestKeys::sample();
        let kp = keys.provider();
        let pfs = pfs0_image(&[("main.npdm", b"META".to_vec()), ("main", vec![9u8; 5000])]);
        let nca = build(
            &Spec {
                content_type: ContentType::Program,
                program_id: 0x0100_0000_0000_1000,
                sections: vec![Section::Pfs0(pfs)],
                titlekey: None,
                distribution: 0,
            },
            &keys,
        );
        let n = Nca::open(Arc::new(MemorySource::new(nca.clone())), &kp, None).unwrap();
        assert_eq!(n.header.program_id, 0x0100_0000_0000_1000);
        assert_eq!(n.header.content_type, ContentType::Program);
        let fs = n.pfs0(0, &ResourceLimits::default()).unwrap();
        assert_eq!(fs.entries[1].name, "main");
        let s = fs.open(1).unwrap();
        assert_eq!(read_vec(s.as_ref(), 0, 5000, 5000).unwrap(), vec![9u8; 5000]);
        assert!(n.verify_structure().iter().all(|(_, ok, _)| *ok));
        // Without keys: header cannot be read.
        assert_eq!(
            Nca::open(Arc::new(MemorySource::new(nca)), &crate::NoKeys, None).err().map(|e| e.code()),
            Some(crate::ErrorCode::NeedsKeyMaterial)
        );
    }

    #[test]
    fn rights_id_conversion() {
        let keys = TestKeys::sample();
        let kp = keys.provider();
        let tk = [0x77u8; 16];
        let pfs = pfs0_image(&[("a", vec![1u8; 100])]);
        let nca = build(
            &Spec {
                content_type: ContentType::Data,
                program_id: 0x0100_0000_0000_2001,
                sections: vec![Section::Pfs0(pfs)],
                titlekey: Some(tk),
                distribution: 0,
            },
            &keys,
        );
        let src: SharedSource = Arc::new(MemorySource::new(nca.clone()));
        let n = Nca::open(src.clone(), &kp, None).unwrap();
        assert!(n.header.has_rights_id());
        assert!(!n.has_section_keys());
        let (_, tik) = ticket(0x0100_0000_0000_2001, &tk, &keys);
        let enc: [u8; 16] = tik[0x180..0x190].try_into().unwrap();
        let dec = decrypt_titlekey(&enc, 0, &kp).unwrap();
        let n2 = Nca::open(src, &kp, Some(&dec)).unwrap();
        assert!(n2.pfs0(0, &ResourceLimits::default()).is_ok());
        let mut h = n2.header.clone();
        h.convert_to_standard_crypto(&dec, &kp).unwrap();
        let mut converted = h.encrypt(&kp).unwrap();
        converted.extend_from_slice(&nca[HEADER_SIZE..]);
        let n3 = Nca::open(Arc::new(MemorySource::new(converted)), &kp, None).unwrap();
        assert!(!n3.header.has_rights_id());
        assert!(n3.pfs0(0, &ResourceLimits::default()).is_ok());
    }
}
