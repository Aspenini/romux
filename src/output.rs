//! Safe output: atomic files and sandboxed extraction directories.
//!
//! Outputs are written to a sibling temporary path and renamed into place only after the
//! writer succeeds. Partially written outputs are removed on drop. Input files are never
//! overwritten, even with `overwrite` enabled.

use crate::error::{Error, Result};
use crate::job::IoPolicy;
use crate::path::{collision_key, sanitize_components};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_name(target: &Path) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = target.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "out".into());
    let tmp = format!(".{name}.romux-tmp-{}-{n}", std::process::id());
    target.with_file_name(tmp)
}

/// Refuse to write `target` if it is one of the inputs or exists without overwrite.
pub fn check_output_target(target: &Path, policy: &IoPolicy, inputs: &[PathBuf]) -> Result<()> {
    // A target that does not exist cannot be an existing input; otherwise resolve the
    // target once rather than once per input.
    if let Ok(t) = fs::canonicalize(target) {
        for i in inputs {
            if fs::canonicalize(i).is_ok_and(|x| x == t) {
                return Err(Error::conflict(format!("output {} would overwrite an input file", target.display())));
            }
        }
    }
    match fs::symlink_metadata(target) {
        Ok(m) => {
            if m.is_dir() {
                return Err(Error::conflict(format!("output {} is an existing directory", target.display())));
            }
            if !policy.overwrite {
                return Err(Error::conflict(format!("output {} already exists", target.display()))
                    .with_suggestion("choose a new output path or pass --overwrite"));
            }
            if m.file_type().is_symlink() {
                return Err(Error::unsafe_path(format!("output {} is a symlink", target.display())));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// A file written to a temporary sibling path and atomically renamed on `finish`.
pub struct AtomicFile {
    target: PathBuf,
    temp: PathBuf,
    writer: Option<BufWriter<File>>,
    sync: bool,
    finished: bool,
}

impl AtomicFile {
    pub fn create(target: impl AsRef<Path>, policy: &IoPolicy, inputs: &[PathBuf]) -> Result<Self> {
        let target = target.as_ref().to_path_buf();
        check_output_target(&target, policy, inputs)?;
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let temp = temp_name(&target);
        let file = OpenOptions::new().write(true).read(true).create_new(true).open(&temp)?;
        Ok(AtomicFile { target, temp, writer: Some(BufWriter::with_capacity(1 << 20, file)), sync: !policy.no_sync, finished: false })
    }

    pub fn target(&self) -> &Path {
        &self.target
    }
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    fn w(&mut self) -> io::Result<&mut BufWriter<File>> {
        self.writer.as_mut().ok_or_else(|| io::Error::other("atomic file already finished"))
    }

    /// Flush and return the underlying file for read-back verification before finishing.
    pub fn flush_for_verify(&mut self) -> Result<&File> {
        let w = self.w()?;
        w.flush()?;
        Ok(w.get_ref())
    }

    /// Flush, optionally fsync, and rename into place.
    pub fn finish(mut self) -> Result<PathBuf> {
        let mut w = self.writer.take().ok_or_else(|| Error::internal("finish called twice"))?;
        w.flush()?;
        let file = w.into_inner().map_err(|e| Error::from(e.into_error()))?;
        if self.sync {
            file.sync_all()?;
        }
        drop(file);
        match fs::rename(&self.temp, &self.target) {
            Ok(()) => {}
            Err(_) if self.target.exists() => {
                // Some platforms refuse to rename over an existing file; overwrite was
                // already authorised by `check_output_target`.
                fs::remove_file(&self.target)?;
                fs::rename(&self.temp, &self.target)?;
            }
            Err(e) => return Err(e.into()),
        }
        self.finished = true;
        Ok(self.target.clone())
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w()?.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w()?.flush()
    }
}

impl Seek for AtomicFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.w()?.seek(pos)
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.finished {
            self.writer.take();
            let _ = fs::remove_file(&self.temp);
        }
    }
}

/// A sandboxed output directory for extraction.
pub struct SafeOutputDir {
    root: PathBuf,
    overwrite: bool,
    max_component_len: usize,
    seen: Mutex<HashSet<String>>,
}

impl SafeOutputDir {
    /// Create (or reuse an empty) directory. A non-empty directory requires `overwrite`.
    pub fn create(root: impl AsRef<Path>, policy: &IoPolicy) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        match fs::symlink_metadata(&root) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return Err(Error::unsafe_path(format!("output directory {} is a symlink", root.display())));
                }
                if !m.is_dir() {
                    return Err(Error::conflict(format!("output {} exists and is not a directory", root.display())));
                }
                if fs::read_dir(&root)?.next().is_some() && !policy.overwrite {
                    return Err(Error::conflict(format!("output directory {} is not empty", root.display()))
                        .with_suggestion("choose an empty directory or pass --overwrite"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir_all(&root)?,
            Err(e) => return Err(e.into()),
        }
        Ok(SafeOutputDir { root, overwrite: policy.overwrite, max_component_len: 255, seen: Mutex::new(HashSet::new()) })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a logical path to a safe filesystem path, creating parent directories.
    pub fn resolve(&self, logical: &str, is_dir: bool) -> Result<PathBuf> {
        let comps = sanitize_components(logical, self.max_component_len)?;
        let key = collision_key(&comps);
        {
            let mut seen = self.seen.lock().map_err(|_| Error::internal("collision set poisoned"))?;
            if !is_dir && !seen.insert(key.clone()) {
                return Err(Error::conflict(format!("entry {logical:?} collides with another entry (case-insensitive)")));
            }
            if is_dir {
                seen.insert(format!("{key}/"));
            }
        }
        let mut cur = self.root.clone();
        let dir_count = if is_dir { comps.len() } else { comps.len() - 1 };
        for c in &comps[..dir_count] {
            cur.push(c);
            match fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(Error::unsafe_path(format!("symlink in output path: {}", cur.display())));
                }
                Ok(m) if m.is_dir() => {}
                Ok(_) => return Err(Error::conflict(format!("{} exists and is not a directory", cur.display()))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&cur)?,
                Err(e) => return Err(e.into()),
            }
        }
        if !is_dir {
            cur.push(&comps[comps.len() - 1]);
        }
        Ok(cur)
    }

    /// Create a file for a logical path. The returned writer stages into a `.romux-part` file
    /// that is renamed when [`ExtractedFile::finish`] is called.
    pub fn create_file(&self, logical: &str) -> Result<ExtractedFile> {
        let path = self.resolve(logical, false)?;
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(Error::unsafe_path(format!("refusing to write through symlink {}", path.display())));
            }
            Ok(_) if !self.overwrite => return Err(Error::conflict(format!("{} already exists", path.display()))),
            _ => {}
        }
        let mut part = path.clone().into_os_string();
        part.push(".romux-part");
        let part = PathBuf::from(part);
        let f = OpenOptions::new().write(true).create(true).truncate(true).open(&part)?;
        Ok(ExtractedFile { path, part, writer: Some(BufWriter::with_capacity(1 << 20, f)) })
    }

    pub fn create_dir(&self, logical: &str) -> Result<PathBuf> {
        self.resolve(logical, true)
    }
}

/// A file being extracted.
pub struct ExtractedFile {
    path: PathBuf,
    part: PathBuf,
    writer: Option<BufWriter<File>>,
}

impl ExtractedFile {
    pub fn finish(mut self) -> Result<PathBuf> {
        let mut w = self.writer.take().ok_or_else(|| Error::internal("finish called twice"))?;
        w.flush()?;
        drop(w);
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        fs::rename(&self.part, &self.path)?;
        Ok(self.path.clone())
    }
}

impl Write for ExtractedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.as_mut().ok_or_else(|| io::Error::other("finished"))?.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.as_mut().ok_or_else(|| io::Error::other("finished"))?.flush()
    }
}

impl Drop for ExtractedFile {
    fn drop(&mut self) {
        if self.writer.take().is_some() {
            let _ = fs::remove_file(&self.part);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_file_no_partial_output() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("out.bin");
        {
            let mut f = AtomicFile::create(&target, &IoPolicy::default(), &[]).unwrap();
            f.write_all(b"abc").unwrap();
            // dropped without finish
        }
        assert!(!target.exists());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
        let mut f = AtomicFile::create(&target, &IoPolicy::default(), &[]).unwrap();
        f.write_all(b"abc").unwrap();
        f.finish().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"abc");
        assert!(AtomicFile::create(&target, &IoPolicy::default(), &[]).is_err());
        assert!(AtomicFile::create(&target, &IoPolicy { overwrite: true, ..Default::default() }, std::slice::from_ref(&target)).is_err());
    }

    #[test]
    fn safe_dir_collisions_and_traversal() {
        let d = tempfile::tempdir().unwrap();
        let out = SafeOutputDir::create(d.path().join("x"), &IoPolicy::default()).unwrap();
        out.create_file("a/B.txt").unwrap().finish().unwrap();
        assert!(out.create_file("A/b.TXT").is_err());
        assert!(out.create_file("../evil").is_err());
    }
}
