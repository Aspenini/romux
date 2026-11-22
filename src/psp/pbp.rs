//! EBOOT.PBP: eight sections addressed by an offset table.

use crate::binary::u32le;
use crate::{DataSource, Error, JobContext, Result, SharedSource, read_vec};
use std::io::Write;

pub const MAGIC: &[u8; 4] = b"\0PBP";
pub const SECTIONS: [&str; 8] = ["PARAM.SFO", "ICON0.PNG", "ICON1.PMF", "PIC0.PNG", "PIC1.PNG", "SND0.AT3", "DATA.PSP", "DATA.PSAR"];

pub struct Pbp {
    pub source: SharedSource,
    pub offsets: [u64; 8],
}

impl Pbp {
    pub fn parse_table(s: &dyn DataSource) -> Result<([u64; 8], u32)> {
        let h = read_vec(s, 0, 0x28, 0x28)?;
        if &h[..4] != MAGIC {
            return Err(Error::malformed("missing PBP magic"));
        }
        let mut offs = [0u64; 8];
        for (i, o) in offs.iter_mut().enumerate() {
            *o = u32le(&h, 8 + i * 4)? as u64;
        }
        let len = s.len()?;
        if offs[0] < 0x28 || offs.windows(2).any(|w| w[1] < w[0]) || offs[7] > len {
            return Err(Error::malformed("PBP section offsets are not ordered within the file"));
        }
        Ok((offs, u32le(&h, 4)?))
    }

    pub fn open(source: SharedSource) -> Result<Self> {
        let (offsets, _version) = Self::parse_table(source.as_ref())?;
        Ok(Pbp { source, offsets })
    }

    /// (name, offset, length) of each section.
    pub fn sections(&self) -> Vec<(String, u64, u64)> {
        let len = self.source.len().unwrap_or(0);
        (0..8)
            .map(|i| {
                let end = if i < 7 { self.offsets[i + 1] } else { len };
                (SECTIONS[i].to_string(), self.offsets[i], end - self.offsets[i])
            })
            .collect()
    }

    pub fn sfo(&self) -> Result<Option<crate::binary::psf::Psf>> {
        let (_, off, len) = self.sections()[0].clone();
        if len == 0 {
            return Ok(None);
        }
        Ok(Some(crate::binary::psf::Psf::parse(&read_vec(self.source.as_ref(), off, len, 1 << 20)?)?))
    }

    pub fn data_psp_encrypted(&self) -> Result<bool> {
        let (_, off, len) = self.sections()[6].clone();
        if len < 4 {
            return Ok(false);
        }
        Ok(&read_vec(self.source.as_ref(), off, 4, 4)?[..] == b"~PSP")
    }

    pub fn data_psar_is_ps1(&self) -> Result<bool> {
        let (_, off, len) = self.sections()[7].clone();
        if len < 8 {
            return Ok(false);
        }
        let m = read_vec(self.source.as_ref(), off, 8, 8)?;
        Ok(&m == b"PSISOIMG" || &m == b"PSTITLEI")
    }
}

/// Write a PBP from up to eight sections (missing sections are empty).
pub fn write(sections: &[Option<SharedSource>], out: &mut dyn Write, job: &JobContext) -> Result<u64> {
    if sections.len() != 8 {
        return Err(Error::invalid_arg("a PBP has exactly eight section slots"));
    }
    let mut offs = [0u32; 8];
    let mut cur = 0x28u64;
    for (i, s) in sections.iter().enumerate() {
        offs[i] = u32::try_from(cur).map_err(|_| Error::limit("PBP exceeds 4 GiB"))?;
        if let Some(s) = s {
            cur += s.len()?;
        }
    }
    let mut h = crate::binary::ByteWriter::new();
    h.bytes(MAGIC).u32le(0x0001_0000);
    for o in offs {
        h.u32le(o);
    }
    out.write_all(&h.buf)?;
    let mut p = crate::ByteProgress::new(job, crate::Phase::Writing, Some(cur));
    for s in sections.iter().flatten() {
        crate::copy_all(s.as_ref(), out, &mut p)?;
    }
    Ok(cur)
}
