//! Application control property (`control.nacp`) essentials.

use crate::binary::utf8_z;
use crate::{Error, Result};
use serde::Serialize;

pub const LANGUAGES: [&str; 16] = [
    "AmericanEnglish",
    "BritishEnglish",
    "Japanese",
    "French",
    "German",
    "LatinAmericanSpanish",
    "Spanish",
    "Italian",
    "Dutch",
    "CanadianFrench",
    "Portuguese",
    "Russian",
    "Korean",
    "TraditionalChinese",
    "SimplifiedChinese",
    "BrazilianPortuguese",
];

#[derive(Debug, Clone, Serialize)]
pub struct Nacp {
    pub titles: Vec<(String, String, String)>,
    pub display_version: String,
}

impl Nacp {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 0x3070 {
            return Err(Error::malformed("control.nacp too short"));
        }
        let mut titles = Vec::new();
        for (i, lang) in LANGUAGES.iter().enumerate() {
            let e = &b[i * 0x300..(i + 1) * 0x300];
            let name = utf8_z(&e[..0x200]);
            let publisher = utf8_z(&e[0x200..]);
            if !name.is_empty() {
                titles.push((lang.to_string(), name, publisher));
            }
        }
        Ok(Nacp { titles, display_version: utf8_z(&b[0x3060..0x3070]) })
    }
    pub fn name(&self) -> Option<&str> {
        self.titles.first().map(|t| t.1.as_str())
    }
}
