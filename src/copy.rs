//! Streaming copy and generic extraction helpers.

use crate::error::{Error, Result};
use crate::filter::glob_match;
use crate::job::{ByteProgress, JobContext, Phase};
use crate::model::NodeKind;
use crate::output::SafeOutputDir;
use crate::reader::PackageReader;
use crate::source::DataSource;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;

/// Chunk size for streaming copies.
pub const CHUNK: usize = 1 << 20;

/// Copy `len` bytes at `offset` from a source into a writer, chunked, with cancellation.
pub fn copy_range(source: &dyn DataSource, offset: u64, len: u64, out: &mut dyn Write, progress: &mut ByteProgress<'_>) -> Result<()> {
    let mut buf = vec![0u8; CHUNK.min(len.max(1) as usize)];
    let mut done = 0u64;
    while done < len {
        let n = ((len - done) as usize).min(buf.len());
        source.read_exact_at(offset + done, &mut buf[..n])?;
        out.write_all(&buf[..n])?;
        done += n as u64;
        progress.advance(n as u64)?;
    }
    Ok(())
}

/// Copy a whole source.
pub fn copy_all(source: &dyn DataSource, out: &mut dyn Write, progress: &mut ByteProgress<'_>) -> Result<()> {
    copy_range(source, 0, source.len()?, out, progress)
}

/// Write `n` zero bytes.
#[cfg_attr(not(any(feature = "psp", feature = "switch", feature = "wii", feature = "wiiu", feature = "xbox")), allow(dead_code))]
pub fn write_zeros(out: &mut dyn Write, mut n: u64) -> Result<()> {
    let z = [0u8; 4096];
    while n > 0 {
        let k = n.min(z.len() as u64) as usize;
        out.write_all(&z[..k])?;
        n -= k as u64;
    }
    Ok(())
}

/// One skipped entry with the reason.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedEntry {
    pub path: String,
    pub reason: String,
}

/// Summary of an extraction.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ExtractReport {
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
    pub written: Vec<PathBuf>,
    pub skipped: Vec<SkippedEntry>,
}

/// Extract readable entries (optionally filtered) into a sandboxed directory.
pub fn extract_to_dir(reader: &dyn PackageReader, out: &SafeOutputDir, filters: &[String], job: &JobContext) -> Result<ExtractReport> {
    let mut nodes = Vec::new();
    for n in reader.entries()? {
        nodes.push(n?);
        if nodes.len() as u64 > job.limits.max_entries {
            return Err(Error::limit("entry count exceeds configured limit"));
        }
    }
    let selected: Vec<_> = nodes.into_iter().filter(|n| filters.is_empty() || filters.iter().any(|f| glob_match(f, &n.path))).collect();
    let total: u64 =
        selected.iter().filter(|n| !matches!(n.kind, NodeKind::Directory | NodeKind::Partition) && n.readable).map(|n| n.length).sum();
    let mut rep = ExtractReport::default();
    let mut prog = ByteProgress::new(job, Phase::Writing, Some(total));
    for n in selected {
        job.check_cancel()?;
        match n.kind {
            NodeKind::Directory | NodeKind::Partition => {
                out.create_dir(&n.path)?;
                rep.directories += 1;
            }
            _ => {
                if !n.readable {
                    rep.skipped.push(SkippedEntry {
                        path: n.path.clone(),
                        reason: if n.encrypted == Some(true) {
                            "encrypted and required key material is unavailable".into()
                        } else {
                            "entry data is not accessible".into()
                        },
                    });
                    continue;
                }
                let src = match reader.open_entry(n.id) {
                    Ok(s) => s,
                    Err(e) => {
                        rep.skipped.push(SkippedEntry { path: n.path.clone(), reason: e.to_string() });
                        continue;
                    }
                };
                let mut f = out.create_file(&n.path)?;
                copy_all(src.as_ref(), &mut f, &mut prog)?;
                rep.written.push(f.finish()?);
                rep.files += 1;
                rep.bytes += n.length;
            }
        }
    }
    job.progress(Phase::Finalizing, rep.bytes, Some(total));
    Ok(rep)
}
