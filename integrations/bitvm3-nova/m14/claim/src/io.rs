//! Bounded artifact IO. A reader owns the same file through preflight and consumption.
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};

use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use crate::Artifact;

pub const MAX_JSON_BYTES: u64 = 64 * 1024;

/// Inspect the path before opening it, and the handle after opening it. O_NONBLOCK also closes
/// the race where a regular file is replaced by a FIFO between those checks.
pub fn open_regular(path: &Path) -> Result<File> {
    ensure!(
        std::fs::metadata(path)?.is_file(),
        "expected a regular file: {}",
        path.display()
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "expected a regular file: {}",
        path.display()
    );
    Ok(file)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_JSON_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JSON_BYTES,
        "JSON exceeds size limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn create_new(path: &Path, private: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    ensure!(
        !private,
        "private claim state currently requires Unix file permissions"
    );
    Ok(options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?)
}

pub fn sync_directory(path: &Path) -> Result<()> {
    // Persist the directory entry before any label can be released. Unsupported platforms fail
    // closed rather than silently weakening crash durability.
    File::open(path)?.sync_all()?;
    Ok(())
}

pub fn write_json_new(path: &Path, value: &impl Serialize, private: bool) -> Result<()> {
    let mut file = create_new(path, private)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    sync_directory(parent_directory(path))
}

pub fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub struct ArtifactWriter {
    file: BufWriter<File>,
    hash: Sha256,
    bytes: u64,
}

impl ArtifactWriter {
    pub fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            file: BufWriter::with_capacity(1024 * 1024, create_new(path, false)?),
            hash: Sha256::new(),
            bytes: 0,
        })
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .context("artifact size overflow")?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<Artifact> {
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        Ok(Artifact {
            bytes: self.bytes,
            sha256: self.hash.finalize().into(),
        })
    }
}

pub struct CheckedReader {
    file: BufReader<File>,
    expected: Artifact,
    hash: Sha256,
    bytes: u64,
}

impl CheckedReader {
    pub fn open(path: &Path, expected: &Artifact) -> Result<Self> {
        let file = open_regular(path)?;
        let meta = file.metadata()?;
        ensure!(meta.is_file(), "expected a regular artifact file");
        ensure!(
            meta.len() == expected.bytes,
            "artifact length mismatch: {}",
            path.display()
        );
        Ok(Self {
            file: BufReader::with_capacity(1024 * 1024, file),
            expected: expected.clone(),
            hash: Sha256::new(),
            bytes: 0,
        })
    }

    pub fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        let end = self
            .bytes
            .checked_add(bytes.len() as u64)
            .context("artifact size overflow")?;
        ensure!(
            end <= self.expected.bytes,
            "read exceeds committed artifact length"
        );
        self.file
            .read_exact(bytes)
            .context("artifact truncated during use")?;
        self.hash.update(&*bytes);
        self.bytes = end;
        Ok(())
    }

    fn check_end(&mut self) -> Result<()> {
        ensure!(
            self.bytes == self.expected.bytes,
            "artifact was not fully consumed"
        );
        let mut extra = [0; 1];
        ensure!(
            self.file.read(&mut extra)? == 0,
            "artifact has trailing bytes"
        );
        let got: [u8; 32] = self.hash.clone().finalize().into();
        ensure!(got == self.expected.sha256, "artifact SHA-256 mismatch");
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.check_end()
    }

    pub fn preflight(&mut self) -> Result<()> {
        let mut buffer = [0; 64 * 1024];
        while self.bytes < self.expected.bytes {
            let n = (self.expected.bytes - self.bytes).min(buffer.len() as u64) as usize;
            self.read_exact(&mut buffer[..n])?;
        }
        self.check_end()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.bytes = 0;
        self.hash = Sha256::new();
        Ok(())
    }
}
