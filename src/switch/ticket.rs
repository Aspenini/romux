//! Ticket (`.tik`) parsing. Only *common* tickets can be used with user-supplied
//! `titlekek` keys; personalized tickets require console-unique keys and are reported as
//! unsupported (Romux never extracts console secrets).

use crate::binary::u32le;
use crate::{Error, Result, hex};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Ticket {
    pub signature_type: u32,
    pub issuer: String,
    #[serde(skip)]
    pub titlekey_block: Vec<u8>,
    pub titlekey_type: u8,
    pub master_key_revision: u8,
    pub rights_id: String,
    #[serde(skip)]
    pub rights_id_bytes: [u8; 16],
    pub ticket_id: u64,
    pub device_id: u64,
    pub account_id: u32,
}

fn sig_layout(t: u32) -> Option<usize> {
    // Signature + padding sizes for each signature type.
    Some(match t {
        0x10000 => 0x200 + 0x3C,
        0x10001 => 0x100 + 0x3C,
        0x10002 => 0x3C + 0x40,
        0x10003 => 0x200 + 0x3C,
        0x10004 => 0x100 + 0x3C,
        0x10005 => 0x3C + 0x40,
        0x10006 => 0x14 + 0x28,
        _ => return None,
    })
}

impl Ticket {
    pub fn parse(b: &[u8]) -> Result<Self> {
        let st = u32le(b, 0)?;
        let sig = sig_layout(st).ok_or_else(|| Error::malformed(format!("unknown ticket signature type 0x{st:x}")))?;
        let d = crate::binary::slice(b, 4 + sig, 0x180)?;
        let mut rid = [0u8; 16];
        rid.copy_from_slice(&d[0x160..0x170]);
        Ok(Ticket {
            signature_type: st,
            issuer: crate::binary::ascii_z(&d[..0x40]),
            titlekey_block: d[0x40..0x140].to_vec(),
            titlekey_type: d[0x141],
            master_key_revision: d[0x145],
            rights_id: hex(&rid),
            rights_id_bytes: rid,
            ticket_id: u64::from_le_bytes(d[0x150..0x158].try_into().unwrap_or([0; 8])),
            device_id: u64::from_le_bytes(d[0x158..0x160].try_into().unwrap_or([0; 8])),
            account_id: u32::from_le_bytes(d[0x170..0x174].try_into().unwrap_or([0; 4])),
        })
    }

    pub fn is_common(&self) -> bool {
        self.titlekey_type == 0
    }

    /// Title ID embedded in the rights ID.
    pub fn title_id(&self) -> u64 {
        u64::from_be_bytes(self.rights_id_bytes[..8].try_into().unwrap_or([0; 8]))
    }

    /// Encrypted title key of a common ticket.
    pub fn encrypted_titlekey(&self) -> Result<[u8; 16]> {
        if !self.is_common() {
            return Err(Error::unsupported("personalized ticket: the title key is bound to a console and cannot be used"));
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(&self.titlekey_block[..16]);
        Ok(k)
    }
}
