//! CUE sheet parsing and BIN track layout.

use crate::disc::rawcd::TrackMode;
use crate::{Error, Result};

/// MSF frames per second.
pub const FRAMES_PER_SECOND: u64 = 75;

/// One INDEX entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CueIndex {
    pub number: u8,
    /// Frames relative to the start of the track's FILE.
    pub frames: u64,
}

/// One TRACK entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CueTrack {
    pub number: u8,
    pub mode: TrackMode,
    /// Index into `CueSheet::files`.
    pub file: usize,
    pub indexes: Vec<CueIndex>,
    pub pregap_frames: u64,
    pub postgap_frames: u64,
    pub flags: Vec<String>,
    pub title: Option<String>,
}

impl CueTrack {
    /// Start (INDEX 01, or first index) in frames within its file.
    pub fn start_frames(&self) -> u64 {
        self.indexes.iter().find(|i| i.number == 1).or_else(|| self.indexes.first()).map(|i| i.frames).unwrap_or(0)
    }
    /// First stored frame (INDEX 00 if present).
    pub fn first_stored_frame(&self) -> u64 {
        self.indexes.first().map(|i| i.frames).unwrap_or(0)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CueFile {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CueSheet {
    pub files: Vec<CueFile>,
    pub tracks: Vec<CueTrack>,
    pub catalog: Option<String>,
    pub title: Option<String>,
    pub performer: Option<String>,
    pub remarks: Vec<String>,
}

fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse `mm:ss:ff` into frames.
pub fn parse_msf(s: &str) -> Result<u64> {
    let p: Vec<&str> = s.split(':').collect();
    if p.len() != 3 {
        return Err(Error::malformed(format!("bad MSF time {s:?}")));
    }
    let n = |x: &str| x.parse::<u64>().map_err(|_| Error::malformed(format!("bad MSF time {s:?}")));
    let (m, sec, f) = (n(p[0])?, n(p[1])?, n(p[2])?);
    if sec >= 60 || f >= 75 {
        return Err(Error::malformed(format!("MSF field out of range in {s:?}")));
    }
    Ok((m * 60 + sec) * FRAMES_PER_SECOND + f)
}

/// Format frames as `mm:ss:ff`.
pub fn format_msf(frames: u64) -> String {
    let f = frames % 75;
    let s = (frames / 75) % 60;
    let m = frames / 75 / 60;
    format!("{m:02}:{s:02}:{f:02}")
}

/// Heuristic text check used by the probe.
pub fn looks_like_cue(text: &str) -> bool {
    let up = text.to_ascii_uppercase();
    up.contains("FILE") && up.contains("TRACK") && up.contains("INDEX")
}

impl CueSheet {
    pub fn parse(text: &str) -> Result<Self> {
        let mut cs = CueSheet::default();
        for (no, raw) in text.lines().enumerate() {
            let t = tokens(raw.trim_start_matches('\u{feff}'));
            if t.is_empty() {
                continue;
            }
            let kw = t[0].to_ascii_uppercase();
            let err = |m: &str| Error::malformed(format!("cue line {}: {m}", no + 1));
            match kw.as_str() {
                "FILE" => {
                    if t.len() < 3 {
                        return Err(err("FILE needs a name and type"));
                    }
                    cs.files.push(CueFile { name: t[1].clone(), kind: t[2].to_ascii_uppercase() });
                }
                "TRACK" => {
                    if t.len() < 3 {
                        return Err(err("TRACK needs number and mode"));
                    }
                    let number: u8 = t[1].parse().map_err(|_| err("bad track number"))?;
                    let mode = TrackMode::from_cue(&t[2]).ok_or_else(|| err("unsupported track mode"))?;
                    if cs.files.is_empty() {
                        return Err(err("TRACK before FILE"));
                    }
                    cs.tracks.push(CueTrack {
                        number,
                        mode,
                        file: cs.files.len() - 1,
                        indexes: vec![],
                        pregap_frames: 0,
                        postgap_frames: 0,
                        flags: vec![],
                        title: None,
                    });
                }
                "INDEX" => {
                    let tr = cs.tracks.last_mut().ok_or_else(|| err("INDEX outside TRACK"))?;
                    if t.len() < 3 {
                        return Err(err("INDEX needs number and time"));
                    }
                    let number: u8 = t[1].parse().map_err(|_| err("bad index number"))?;
                    let frames = parse_msf(&t[2])?;
                    if tr.indexes.last().is_some_and(|l| l.frames > frames) {
                        return Err(err("INDEX times must not decrease"));
                    }
                    tr.indexes.push(CueIndex { number, frames });
                }
                "PREGAP" => {
                    let tr = cs.tracks.last_mut().ok_or_else(|| err("PREGAP outside TRACK"))?;
                    tr.pregap_frames = parse_msf(t.get(1).ok_or_else(|| err("missing time"))?)?;
                }
                "POSTGAP" => {
                    let tr = cs.tracks.last_mut().ok_or_else(|| err("POSTGAP outside TRACK"))?;
                    tr.postgap_frames = parse_msf(t.get(1).ok_or_else(|| err("missing time"))?)?;
                }
                "FLAGS" => {
                    if let Some(tr) = cs.tracks.last_mut() {
                        tr.flags = t[1..].to_vec();
                    }
                }
                "TITLE" => {
                    let v = t.get(1).cloned();
                    match cs.tracks.last_mut() {
                        Some(tr) => tr.title = v,
                        None => cs.title = v,
                    }
                }
                "PERFORMER" if cs.tracks.is_empty() => cs.performer = t.get(1).cloned(),
                "CATALOG" => cs.catalog = t.get(1).cloned(),
                "REM" => cs.remarks.push(t[1..].join(" ")),
                _ => {}
            }
        }
        if cs.tracks.is_empty() {
            return Err(Error::malformed("cue sheet declares no tracks"));
        }
        for tr in &cs.tracks {
            if tr.indexes.is_empty() {
                return Err(Error::malformed(format!("track {} has no INDEX", tr.number)));
            }
        }
        Ok(cs)
    }

    /// Render as CUE text.
    pub fn render(&self) -> String {
        let mut s = String::new();
        if let Some(c) = &self.catalog {
            s.push_str(&format!("CATALOG {c}\n"));
        }
        let mut cur_file = usize::MAX;
        for t in &self.tracks {
            if t.file != cur_file {
                cur_file = t.file;
                let f = &self.files[t.file];
                s.push_str(&format!("FILE \"{}\" {}\n", f.name, f.kind));
            }
            s.push_str(&format!("  TRACK {:02} {}\n", t.number, t.mode.cue_name()));
            if t.pregap_frames > 0 {
                s.push_str(&format!("    PREGAP {}\n", format_msf(t.pregap_frames)));
            }
            for i in &t.indexes {
                s.push_str(&format!("    INDEX {:02} {}\n", i.number, format_msf(i.frames)));
            }
            if t.postgap_frames > 0 {
                s.push_str(&format!("    POSTGAP {}\n", format_msf(t.postgap_frames)));
            }
        }
        s
    }
}

/// Resolved byte layout of one track inside its BIN file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrackLayout {
    pub number: u8,
    pub mode: TrackMode,
    pub file: usize,
    /// Byte offset of the first stored frame (INDEX 00 or 01).
    pub offset: u64,
    /// Bytes stored for the track in its file.
    pub length: u64,
    pub frames: u64,
    /// Frames of stored pregap (INDEX 00 → 01).
    pub stored_pregap_frames: u64,
}

/// Compute byte layouts given each file's size.
pub fn layout(sheet: &CueSheet, file_sizes: &[u64]) -> Result<Vec<TrackLayout>> {
    let mut out = Vec::new();
    for (i, t) in sheet.tracks.iter().enumerate() {
        let ss = t.mode.sector_size();
        let start = t.first_stored_frame();
        let fsize = *file_sizes.get(t.file).ok_or_else(|| Error::malformed("track refers to missing file"))?;
        let end_frames = match sheet.tracks.get(i + 1) {
            Some(n) if n.file == t.file => n.first_stored_frame(),
            _ => fsize / ss,
        };
        if end_frames < start {
            return Err(Error::malformed(format!("track {} ends before it starts", t.number)));
        }
        let frames = end_frames - start;
        let offset = start * ss;
        let length = frames * ss;
        if offset + length > fsize {
            return Err(Error::bounds(format!("track {} extends beyond its BIN file", t.number)));
        }
        out.push(TrackLayout {
            number: t.number,
            mode: t.mode,
            file: t.file,
            offset,
            length,
            frames,
            stored_pregap_frames: t.start_frames() - start,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_render() {
        let cue = "FILE \"game (track 1).bin\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\nFILE \"t2.bin\" BINARY\n  TRACK 02 AUDIO\n    INDEX 00 00:00:00\n    INDEX 01 00:02:00\n";
        let cs = CueSheet::parse(cue).unwrap();
        assert_eq!(cs.files[0].name, "game (track 1).bin");
        assert_eq!(cs.tracks[1].start_frames(), 150);
        let l = layout(&cs, &[2352 * 100, 2352 * 300]).unwrap();
        assert_eq!(l[0].frames, 100);
        assert_eq!(l[1].stored_pregap_frames, 150);
        assert_eq!(CueSheet::parse(&cs.render()).unwrap().tracks.len(), 2);
        assert!(CueSheet::parse("TRACK 01 AUDIO").is_err());
    }
}
