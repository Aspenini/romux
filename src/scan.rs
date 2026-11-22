//! Batch scanning: probe a folder, group recognised files by title family, report
//! duplicates. Produces a report only — never mutates anything, never queries a network.

use crate::{ContentCategory, Error, FileSource, JobContext, OpenContext, Platform, ProbeLimits, Result, SharedSource, registry};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct ScanOptions {
    pub recursive: bool,
    /// Compute SHA-256 of each recognised file for deduplication (slow).
    pub hash: bool,
    pub context: OpenContext,
    /// Skip files larger than this when hashing (0 = no limit).
    pub max_hash_size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanEntry {
    pub path: PathBuf,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<ContentCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanGroup {
    pub platform: Platform,
    pub family_id: String,
    pub title: Option<String>,
    pub members: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScanReport {
    pub root: PathBuf,
    pub files: Vec<ScanEntry>,
    pub groups: Vec<ScanGroup>,
    pub duplicates: Vec<Vec<PathBuf>>,
    pub unrecognized: Vec<PathBuf>,
}

fn walk(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>, depth: u32) -> Result<()> {
    if depth > 64 {
        return Err(Error::limit("directory nesting too deep"));
    }
    let mut items: Vec<_> = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    items.sort_by_key(|e| e.file_name());
    for e in items {
        let ft = e.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if recursive {
                walk(&e.path(), recursive, out, depth + 1)?;
            }
        } else if ft.is_file() {
            out.push(e.path());
        }
    }
    Ok(())
}

/// Scan a directory.
pub fn scan(dir: impl AsRef<Path>, opts: &ScanOptions, job: &JobContext) -> Result<ScanReport> {
    let dir = dir.as_ref();
    if !dir.is_dir() {
        return Err(Error::invalid_arg(format!("{} is not a directory", dir.display())));
    }
    let mut paths = Vec::new();
    walk(dir, opts.recursive, &mut paths, 0)?;
    let mut rep = ScanReport { root: dir.to_path_buf(), ..Default::default() };
    let total = paths.len() as u64;
    for (i, p) in paths.iter().enumerate() {
        job.check_cancel()?;
        job.progress_item(crate::Phase::Probing, i as u64, Some(total), &p.display().to_string());
        let src: SharedSource = match FileSource::open(p) {
            Ok(f) => Arc::new(f),
            Err(e) => {
                rep.files.push(ScanEntry {
                    path: p.clone(),
                    size: 0,
                    format: None,
                    platform: None,
                    title: None,
                    title_id: None,
                    version: None,
                    category: None,
                    family_id: None,
                    sha256: None,
                    error: Some(e.to_string()),
                });
                continue;
            }
        };
        let size = src.len()?;
        let mut entry = ScanEntry {
            path: p.clone(),
            size,
            format: None,
            platform: None,
            title: None,
            title_id: None,
            version: None,
            category: None,
            family_id: None,
            sha256: None,
            error: None,
        };
        let pr = match registry().probe(src.as_ref(), &ProbeLimits::default()) {
            Ok(pr) => pr,
            Err(e) => {
                entry.error = Some(e.to_string());
                rep.files.push(entry);
                continue;
            }
        };
        match pr.format {
            None => {
                if !pr.ambiguity.is_empty() {
                    entry.error = Some(pr.ambiguity.join("; "));
                    rep.files.push(entry);
                } else {
                    rep.unrecognized.push(p.clone());
                }
                continue;
            }
            Some(f) => {
                entry.format = Some(f.to_string());
                match registry().open_as(f, src.clone(), &opts.context).and_then(|r| r.info()) {
                    Ok(info) => {
                        entry.platform = Some(info.platform);
                        entry.title = info.title;
                        entry.title_id = info.title_id;
                        entry.version = info.version;
                        entry.category = Some(info.category);
                        entry.family_id = info.family_id;
                    }
                    Err(e) => entry.error = Some(e.to_string()),
                }
            }
        }
        if opts.hash && (opts.max_hash_size == 0 || size <= opts.max_hash_size) {
            let h = crate::crypto::hash_range(src.as_ref(), 0, size, crate::crypto::HashAlg::Sha256, None)?;
            entry.sha256 = Some(crate::hex(&h));
        }
        rep.files.push(entry);
    }
    let mut groups: BTreeMap<(Platform, String), ScanGroup> = BTreeMap::new();
    for f in &rep.files {
        if let (Some(pl), Some(fam)) = (f.platform, &f.family_id) {
            let g = groups.entry((pl, fam.clone())).or_insert_with(|| ScanGroup {
                platform: pl,
                family_id: fam.clone(),
                title: None,
                members: vec![],
            });
            g.members.push(f.path.clone());
            if g.title.is_none() {
                g.title = f.title.clone();
            }
        }
    }
    rep.groups = groups.into_values().collect();
    let mut dup: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for f in &rep.files {
        let key = match &f.sha256 {
            Some(h) => format!("sha256:{h}"),
            None => match (&f.format, &f.title_id, &f.version) {
                (Some(fm), Some(t), v) => format!("id:{fm}:{t}:{}:{}", v.clone().unwrap_or_default(), f.size),
                _ => continue,
            },
        };
        dup.entry(key).or_default().push(f.path.clone());
    }
    rep.duplicates = dup.into_values().filter(|v| v.len() > 1).collect();
    Ok(rep)
}
