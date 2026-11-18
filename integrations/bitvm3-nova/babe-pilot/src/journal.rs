//! Durable guards for one garbler session on a local Unix filesystem.
//!
//! A journal has at most four fixed-size, SHA-256-chained records: session pins,
//! the first challenger nonce, the finalized public artifact hash, and the first
//! input hash. Each transition is appended and fsynced while the journal inode is
//! exclusively locked. A torn record, unexpected suffix, changed inode, or wrong
//! externally supplied head fails closed. Recovery never truncates a file.
//!
//! The caller owns the independent anchor. After a successful transition it must
//! durably compare-and-set that anchor from the expected head to the returned
//! head **before** exposing openings, proofs, or labels. The local hash chain
//! cannot detect a complete rollback when its anchor is rolled back too. Copied
//! journals also require that external compare-and-set to reject forks. Keep the
//! anchor and its update authority outside the journal's rollback domain.
//!
//! This module stores public reservation digests, with private-directory and file
//! permissions as defense in depth. Secret seeds and finalized artifact bytes
//! belong in separately protected, durably written files. Same-user processes
//! that ignore advisory locks and a hostile kernel are outside this boundary.

use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"BABJNL01";
const DOMAIN: &[u8] = b"babe-pilot/session-journal/v1\0";
const DIGEST_OFFSET: usize = 209;
/// Fixed binary record size. No allocation is controlled by a field in the file.
pub const JOURNAL_RECORD_BYTES: usize = DIGEST_OFFSET + 32;
/// Initialization, nonce reservation, artifact finalization, and input reservation.
pub const MAX_JOURNAL_BYTES: usize = 4 * JOURNAL_RECORD_BYTES;
/// Absolute ceiling for a separately stored seed or finalized public artifact.
/// Callers should pass the smaller bound appropriate for each artifact type.
pub const MAX_PRIVATE_BLOB_BYTES: usize = 64 * 1024 * 1024;

/// Independently agreed identities. `circuit_id` must commit to the complete spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalPins {
    pub session_id: [u8; 32],
    pub circuit_id: [u8; 32],
    pub commit1: [u8; 32],
}

/// A trusted external anchor for the exact accepted history of this session.
/// The record digest includes all three session pins and the preceding digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalHead {
    pub sequence: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalSnapshot {
    pub pins: JournalPins,
    pub head: JournalHead,
    pub nonce: Option<[u8; 32]>,
    pub finalized_setup_sha256: Option<[u8; 32]>,
    /// Input digest or a release-descriptor digest that commits the input and its
    /// authorization. The durable wrapper uses the latter and restores the inner
    /// input digest into its in-memory label guard after validating the descriptor.
    pub input_sha256: Option<[u8; 32]>,
}

impl JournalSnapshot {
    /// Check a complete candidate transition before an authority mutates its store.
    /// `self` must be the authority's current trusted snapshot. The candidate must
    /// preserve every prior reservation and contain the exact next record digest.
    pub fn validate_successor(&self, next: &Self) -> Result<()> {
        ensure!(self.pins == next.pins, "journal successor pins mismatch");
        ensure!(
            self.head.sequence.checked_add(1) == Some(next.head.sequence),
            "journal successor must advance one record"
        );
        let mut expected = *self;
        let mut payload = [0; 64];
        match self.head.sequence {
            1 => {
                ensure!(
                    self.nonce.is_none()
                        && self.finalized_setup_sha256.is_none()
                        && self.input_sha256.is_none(),
                    "invalid initialized snapshot"
                );
                let nonce = next.nonce.context("successor lacks nonce")?;
                payload[..32].copy_from_slice(&nonce);
                expected.nonce = Some(nonce);
            }
            2 => {
                ensure!(
                    self.finalized_setup_sha256.is_none() && self.input_sha256.is_none(),
                    "invalid nonce snapshot"
                );
                payload[..32].copy_from_slice(&self.nonce.context("current nonce missing")?);
                let digest = next
                    .finalized_setup_sha256
                    .context("successor lacks setup digest")?;
                payload[32..].copy_from_slice(&digest);
                expected.finalized_setup_sha256 = Some(digest);
            }
            3 => {
                ensure!(
                    self.finalized_setup_sha256.is_some() && self.input_sha256.is_none(),
                    "invalid finalized snapshot"
                );
                payload[..32].copy_from_slice(&self.nonce.context("current nonce missing")?);
                let digest = next.input_sha256.context("successor lacks input digest")?;
                payload[32..].copy_from_slice(&digest);
                expected.input_sha256 = Some(digest);
            }
            _ => bail!("unsupported journal successor"),
        }
        let record = encode_record(*self, self.head.sequence as u8, payload);
        expected.head = JournalHead {
            sequence: self.head.sequence + 1,
            digest: record[DIGEST_OFFSET..].try_into().expect("fixed record"),
        };
        ensure!(
            expected == *next,
            "journal successor state or digest mismatch"
        );
        Ok(())
    }
}

/// An exclusively locked journal. Dropping the handle releases the OS lock.
///
/// The parent directory must already exist with mode 0700 and belong to the
/// effective user. Every path component is opened without following symlinks.
/// The journal must be a singly linked, owner-only regular file with mode 0600.
/// Relative paths are resolved once; `..` components are rejected.
pub struct SessionJournal {
    file: File,
    directory: File,
    path: PathBuf,
    name: OsString,
    snapshot: JournalSnapshot,
    poisoned: bool,
}

impl SessionJournal {
    /// Create a fresh session. Existing paths are never overwritten or repaired.
    /// Persist the returned initial head independently before publishing Commit1.
    pub fn create(path: impl AsRef<Path>, pins: JournalPins) -> Result<Self> {
        let path = absolute_path(path.as_ref())?;
        let (directory, name) = open_private_parent(&path)?;
        let file = open_journal_file(&directory, &name, true)?;
        file.try_lock().context("lock new session journal")?;
        let mut journal = Self {
            file,
            directory,
            path,
            name,
            snapshot: JournalSnapshot {
                pins,
                head: JournalHead {
                    sequence: 0,
                    digest: [0; 32],
                },
                nonce: None,
                finalized_setup_sha256: None,
                input_sha256: None,
            },
            poisoned: false,
        };
        journal.validate_files()?;
        journal.append(0, [0; 64])?;
        Ok(journal)
    }

    /// Reopen only the exact independently pinned head. Both shorter and longer
    /// histories fail closed, including a crash after fsync but before anchoring.
    pub fn open(
        path: impl AsRef<Path>,
        pins: JournalPins,
        expected_head: JournalHead,
    ) -> Result<Self> {
        let (journal, pending) = Self::open_checked(path.as_ref(), pins, expected_head, false)?;
        ensure!(pending.is_none(), "journal anchor mismatch");
        Ok(journal)
    }

    /// Recover either the trusted head or exactly one complete append after it.
    /// The returned `Some(head)` requires an authoritative, durable anchor CAS
    /// from `trusted_head` to `head` before any openings, proofs, or labels escape.
    /// A caller must also check the saved nonce/input against its agreed challenge.
    ///
    /// This handles a crash between a journal fsync and the anchor CAS. A divergent
    /// prefix, a truncated record, an older history, or two unanchored transitions
    /// fails closed. The candidate next head is never silently adopted as trusted.
    pub fn open_recovering(
        path: impl AsRef<Path>,
        pins: JournalPins,
        trusted_head: JournalHead,
    ) -> Result<(Self, Option<JournalHead>)> {
        Self::open_checked(path.as_ref(), pins, trusted_head, true)
    }

    /// Open the independently administered authority store itself.
    ///
    /// **Trust boundary:** this method accepts the final valid on-disk head as
    /// authoritative. The caller must protect this store against rollback and
    /// unauthorized replacement independently of the ordinary session journal.
    /// Merely putting a second copy in another directory does not establish that
    /// independence. Use `open` or `open_recovering` for the ordinary session file.
    pub fn open_authoritative(path: impl AsRef<Path>, pins: JournalPins) -> Result<Self> {
        let path = absolute_path(path.as_ref())?;
        let (directory, name) = open_private_parent(&path)?;
        let mut file = open_journal_file(&directory, &name, false)?;
        file.try_lock()
            .context("authority journal is locked or locking is unsupported")?;
        let snapshot = read_snapshot(&mut file, pins)?;
        let journal = Self {
            file,
            directory,
            path,
            name,
            snapshot,
            poisoned: false,
        };
        journal.sync_recovered_history()?;
        Ok(journal)
    }

    fn open_checked(
        path: &Path,
        pins: JournalPins,
        expected_head: JournalHead,
        allow_one_pending: bool,
    ) -> Result<(Self, Option<JournalHead>)> {
        let path = absolute_path(path)?;
        let (directory, name) = open_private_parent(&path)?;
        let mut file = open_journal_file(&directory, &name, false)?;
        file.try_lock()
            .context("session journal is locked or locking is unsupported")?;
        let history = read_history(&mut file, pins)?;
        let snapshot = *history.last().context("empty journal")?;
        let pending = if snapshot.head == expected_head {
            None
        } else {
            ensure!(allow_one_pending, "journal anchor mismatch");
            ensure!(
                expected_head.sequence.checked_add(1) == Some(snapshot.head.sequence),
                "recovery requires exactly one pending append"
            );
            ensure!(
                history.iter().any(|state| state.head == expected_head),
                "trusted journal prefix mismatch"
            );
            Some(snapshot.head)
        };
        let journal = Self {
            file,
            directory,
            path,
            name,
            snapshot,
            poisoned: false,
        };
        journal.sync_recovered_history()?;
        Ok((journal, pending))
    }

    /// The last validated state held by this handle. It grants no release by itself.
    pub fn snapshot(&self) -> JournalSnapshot {
        self.snapshot
    }

    fn sync_recovered_history(&self) -> Result<()> {
        self.validate_files()?;
        // A previous process may have exited between a complete write and fsync.
        // Persist the validated history before returning any recovered candidate
        // that the caller could accept through its independent authority CAS.
        self.file.sync_all().context("fsync recovered journal")?;
        self.directory
            .sync_all()
            .context("fsync recovered journal directory")?;
        self.validate_files()
    }

    /// Revalidate disk contents, file identity, permissions, and the external pin.
    pub fn check_head(&mut self, expected_head: JournalHead) -> Result<JournalSnapshot> {
        ensure!(
            !self.poisoned,
            "journal handle is poisoned after a failed append"
        );
        ensure!(
            self.snapshot.head == expected_head,
            "journal anchor mismatch"
        );
        self.validate_files()?;
        let disk = read_snapshot(&mut self.file, self.snapshot.pins)?;
        ensure!(disk == self.snapshot, "journal changed while locked");
        self.validate_files()?;
        Ok(disk)
    }

    /// Reserve the first challenger nonce before producing an opening or proof.
    /// Exact retries return the current head without adding another record.
    pub fn reserve_nonce(
        &mut self,
        expected_head: JournalHead,
        nonce: [u8; 32],
    ) -> Result<JournalSnapshot> {
        self.check_head(expected_head)?;
        if let Some(saved) = self.snapshot.nonce {
            ensure!(saved == nonce, "challenger nonce already reserved");
            return Ok(self.snapshot);
        }
        let mut payload = [0; 64];
        payload[..32].copy_from_slice(&nonce);
        self.append(1, payload)
    }

    /// Pin the exact finalized setup bytes after saving and fsyncing that artifact.
    /// Restarted callers reload those bytes and check this hash. A newly randomized
    /// proof cannot replace a previously finalized artifact for this session.
    pub fn mark_finalized(
        &mut self,
        expected_head: JournalHead,
        nonce: [u8; 32],
        setup_sha256: [u8; 32],
    ) -> Result<JournalSnapshot> {
        self.check_head(expected_head)?;
        ensure!(self.snapshot.nonce == Some(nonce), "nonce was not reserved");
        if let Some(saved) = self.snapshot.finalized_setup_sha256 {
            ensure!(saved == setup_sha256, "different setup already finalized");
            return Ok(self.snapshot);
        }
        let mut payload = [0; 64];
        payload[..32].copy_from_slice(&nonce);
        payload[32..].copy_from_slice(&setup_sha256);
        self.append(2, payload)
    }

    /// Reserve one complete, independently agreed input before releasing labels.
    /// The caller supplies a domain-separated, length-bound input digest or a
    /// release-descriptor commitment that binds that digest and its authorization.
    pub fn reserve_input(
        &mut self,
        expected_head: JournalHead,
        nonce: [u8; 32],
        input_sha256: [u8; 32],
    ) -> Result<JournalSnapshot> {
        self.check_head(expected_head)?;
        ensure!(self.snapshot.nonce == Some(nonce), "nonce was not reserved");
        ensure!(
            self.snapshot.finalized_setup_sha256.is_some(),
            "setup must be finalized before reserving an input"
        );
        if let Some(saved) = self.snapshot.input_sha256 {
            ensure!(saved == input_sha256, "different input already reserved");
            return Ok(self.snapshot);
        }
        let mut payload = [0; 64];
        payload[..32].copy_from_slice(&nonce);
        payload[32..].copy_from_slice(&input_sha256);
        self.append(3, payload)
    }

    fn append(&mut self, event: u8, payload: [u8; 64]) -> Result<JournalSnapshot> {
        ensure!(
            !self.poisoned,
            "journal handle is poisoned after a failed append"
        );
        ensure!(self.snapshot.head.sequence < 4, "session journal is full");
        ensure!(
            u64::from(event) == self.snapshot.head.sequence,
            "journal transition out of order"
        );
        let record = encode_record(self.snapshot, event, payload);
        let expected_head = JournalHead {
            sequence: self.snapshot.head.sequence + 1,
            digest: record[DIGEST_OFFSET..].try_into().expect("fixed record"),
        };

        // No subsequent operation may reuse this handle if a write or fsync fails.
        // Partial records remain on disk and are rejected on the next open.
        self.poisoned = true;
        self.file
            .write_all(&record)
            .context("append journal record")?;
        self.file.sync_all().context("fsync session journal")?;
        self.directory
            .sync_all()
            .context("fsync journal directory")?;
        self.validate_files()?;
        let snapshot = read_snapshot(&mut self.file, self.snapshot.pins)?;
        ensure!(
            snapshot.head == expected_head,
            "journal append readback mismatch"
        );
        self.validate_files()?;
        self.snapshot = snapshot;
        self.poisoned = false;
        Ok(snapshot)
    }

    #[cfg(unix)]
    fn validate_files(&self) -> Result<()> {
        validate_private_file(
            &self.directory,
            &self.file,
            &self.name,
            &self.path,
            MAX_JOURNAL_BYTES,
        )
    }

    #[cfg(not(unix))]
    fn validate_files(&self) -> Result<()> {
        bail!("durable session journals require Unix ownership and directory fsync")
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    ensure!(path.file_name().is_some(), "journal path needs a file name");
    for part in path.components() {
        ensure!(
            !matches!(part, Component::ParentDir | Component::Prefix(_)),
            "journal path must not contain parent or platform-prefix components"
        );
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

#[cfg(unix)]
fn open_private_parent(path: &Path) -> Result<(File, OsString)> {
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;

    let name = path
        .file_name()
        .context("journal path needs a file name")?
        .to_owned();
    let parent = path.parent().context("journal path needs a parent")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory: File = open("/", flags, Mode::empty())?.into();
    for part in parent.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .context("open journal ancestor without following symlinks")?
                    .into();
                let owner = directory.metadata()?.uid();
                ensure!(
                    owner == 0 || owner == rustix::process::geteuid().as_raw(),
                    "journal ancestor has an untrusted owner"
                );
            }
            _ => bail!("unsupported journal path component"),
        }
    }
    validate_private_directory(&directory.metadata()?)?;
    Ok((directory, name))
}

#[cfg(unix)]
fn validate_private_directory(meta: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(meta.is_dir(), "journal parent must be a directory");
    ensure!(
        meta.mode() & 0o7777 == 0o700,
        "journal parent mode must be 0700"
    );
    ensure!(
        meta.uid() == rustix::process::geteuid().as_raw(),
        "journal parent owner must be the effective user"
    );
    Ok(())
}

#[cfg(unix)]
fn open_journal_file(directory: &File, name: &std::ffi::OsStr, create: bool) -> Result<File> {
    use rustix::fs::{openat, Mode, OFlags};
    let mut flags =
        OFlags::RDWR | OFlags::APPEND | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    let file: File = openat(directory, name, flags, Mode::RUSR | Mode::WUSR)
        .context("open session journal without following symlinks")?
        .into();
    // O_NONBLOCK prevents a substituted FIFO from blocking this validation.
    ensure!(file.metadata()?.is_file(), "journal must be a regular file");
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_parent(_path: &Path) -> Result<(File, OsString)> {
    bail!("durable session journals require Unix ownership and directory fsync")
}

#[cfg(not(unix))]
fn open_journal_file(_directory: &File, _name: &std::ffi::OsStr, _create: bool) -> Result<File> {
    bail!("durable session journals require Unix ownership and directory fsync")
}

#[cfg(unix)]
fn validate_private_file(
    directory: &File,
    file: &File,
    name: &std::ffi::OsStr,
    path: &Path,
    max_bytes: usize,
) -> Result<()> {
    use rustix::fs::{statat, AtFlags, FileType};
    use std::os::unix::fs::MetadataExt;

    let parent = directory.metadata()?;
    validate_private_directory(&parent)?;
    let (current_directory, _) = open_private_parent(path)?;
    let current = current_directory.metadata()?;
    ensure!(
        (parent.dev(), parent.ino()) == (current.dev(), current.ino()),
        "private directory was replaced"
    );
    let meta = file.metadata()?;
    ensure!(meta.is_file(), "private file must be a regular file");
    ensure!(
        meta.nlink() == 1,
        "private file must have exactly one hard link"
    );
    ensure!(
        meta.mode() & 0o7777 == 0o600,
        "private file mode must be 0600"
    );
    ensure!(
        meta.uid() == rustix::process::geteuid().as_raw(),
        "private file owner must be the effective user"
    );
    ensure!(
        meta.len() <= max_bytes as u64,
        "private file exceeds size limit"
    );
    let entry = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .context("inspect private file directory entry")?;
    ensure!(
        FileType::from_raw_mode(entry.st_mode) == FileType::RegularFile,
        "private path must remain a regular file"
    );
    // Unix targets differ in the integer widths/types of stat's device and inode.
    #[allow(clippy::unnecessary_cast)]
    let identity = (entry.st_dev as u64, entry.st_ino as u64);
    ensure!(
        identity == (meta.dev(), meta.ino()),
        "private file path was replaced"
    );
    Ok(())
}

/// Read a bounded, immutable private blob without following any symlink.
/// The caller must authenticate its bytes using the seed's agreed Commit1 or the
/// finalized artifact hash in the anchored journal, and zeroize secret buffers.
pub fn read_private_blob(path: impl AsRef<Path>, max_bytes: usize) -> Result<Vec<u8>> {
    ensure!(
        max_bytes <= MAX_PRIVATE_BLOB_BYTES,
        "private blob bound exceeds ceiling"
    );
    read_private_blob_impl(path.as_ref(), max_bytes)
}

/// Read an optional private blob. Only a missing final directory entry yields
/// `None`; an invalid parent, symlink, permission failure, or malformed file is an
/// error. This supports a crash before atomic publication of a finalized setup.
pub fn read_optional_private_blob(
    path: impl AsRef<Path>,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    ensure!(
        max_bytes <= MAX_PRIVATE_BLOB_BYTES,
        "private blob bound exceeds ceiling"
    );
    read_optional_private_blob_impl(path.as_ref(), max_bytes)
}

#[cfg(unix)]
fn read_private_blob_impl(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    read_optional_private_blob_impl(path, max_bytes)?.context("private blob is missing")
}

#[cfg(unix)]
fn read_optional_private_blob_impl(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let path = absolute_path(path)?;
    let (directory, name) = open_private_parent(&path)?;
    match open_blob_file(&directory, &name) {
        Ok(mut file) => Ok(Some(read_blob_from_file(
            &directory, &mut file, &name, &path, max_bytes,
        )?)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(error).context("open private blob"),
    }
}

#[cfg(not(unix))]
fn read_private_blob_impl(_path: &Path, _max_bytes: usize) -> Result<Vec<u8>> {
    bail!("private blobs require Unix ownership and directory fsync")
}

#[cfg(not(unix))]
fn read_optional_private_blob_impl(_path: &Path, _max_bytes: usize) -> Result<Option<Vec<u8>>> {
    bail!("private blobs require Unix ownership and directory fsync")
}

#[cfg(unix)]
fn open_blob_file(directory: &File, name: &std::ffi::OsStr) -> rustix::io::Result<File> {
    use rustix::fs::{openat, Mode, OFlags};
    Ok(openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into())
}

#[cfg(unix)]
fn read_blob_from_file(
    directory: &File,
    file: &mut File,
    name: &std::ffi::OsStr,
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    validate_private_file(directory, file, name, path, max_bytes)?;
    let expected_bytes = file.metadata()?.len();
    let mut bytes = Vec::with_capacity(expected_bytes as usize);
    file.seek(SeekFrom::Start(0))?;
    (&mut *file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max_bytes, "private blob exceeds size limit");
    ensure!(
        bytes.len() as u64 == expected_bytes,
        "private blob size changed during read"
    );
    validate_private_file(directory, file, name, path, max_bytes)?;
    Ok(bytes)
}

/// Publish an immutable private blob exactly once, with idempotent byte-exact retries.
///
/// The file is written to an owner-0600 staging file in the same private directory,
/// fsynced, and atomically renamed with no-replace semantics before directory fsync.
/// Concurrent writers can succeed together only if their complete bytes match.
/// A crash can leave a private staging file; it cannot publish partial blob bytes.
/// Existing target bytes are never overwritten. This needs Unix plus an atomic
/// no-replace rename implementation (currently Linux, Android, or Apple targets).
pub fn write_private_blob_once(
    path: impl AsRef<Path>,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<()> {
    ensure!(
        max_bytes <= MAX_PRIVATE_BLOB_BYTES,
        "private blob bound exceeds ceiling"
    );
    ensure!(bytes.len() <= max_bytes, "private blob exceeds size limit");
    write_private_blob_once_impl(path.as_ref(), bytes, max_bytes)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn write_private_blob_once_impl(path: &Path, bytes: &[u8], max_bytes: usize) -> Result<()> {
    use rustix::fs::{openat, renameat_with, Mode, OFlags, RenameFlags};
    use rustix::io::Errno;

    let path = absolute_path(path)?;
    let (directory, name) = open_private_parent(&path)?;
    match open_blob_file(&directory, &name) {
        Ok(mut file) => {
            return finish_existing_blob(&directory, &mut file, &name, &path, bytes, max_bytes);
        }
        Err(Errno::NOENT) => {}
        Err(error) => return Err(error).context("inspect existing private blob"),
    }
    let stage_name = format!(
        ".babe-stage-{}-{:032x}",
        std::process::id(),
        rand::random::<u128>()
    );
    let mut file: File = openat(
        &directory,
        stage_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .context("create private blob stage")?
    .into();
    let _stage_guard = PrivateStage {
        directory: &directory,
        name: &stage_name,
    };
    file.write_all(bytes).context("write private blob stage")?;
    file.sync_all().context("fsync private blob stage")?;
    match renameat_with(
        &directory,
        stage_name.as_str(),
        &directory,
        &name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(Errno::EXIST) => {}
        Err(error) => return Err(error).context("publish private blob atomically"),
    }
    let mut published =
        open_blob_file(&directory, &name).context("reopen published private blob")?;
    finish_existing_blob(&directory, &mut published, &name, &path, bytes, max_bytes)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn finish_existing_blob(
    directory: &File,
    file: &mut File,
    name: &std::ffi::OsStr,
    path: &Path,
    expected: &[u8],
    max_bytes: usize,
) -> Result<()> {
    let actual =
        zeroize::Zeroizing::new(read_blob_from_file(directory, file, name, path, max_bytes)?);
    ensure!(
        actual.as_slice() == expected,
        "different private blob already exists"
    );
    file.sync_all().context("fsync private blob")?;
    directory
        .sync_all()
        .context("fsync private blob directory")?;
    validate_private_file(directory, file, name, path, max_bytes)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
struct PrivateStage<'a> {
    directory: &'a File,
    name: &'a str,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl Drop for PrivateStage<'_> {
    fn drop(&mut self) {
        // The private staging name was generated by this call with CREATE|EXCL.
        // Once published it is absent; otherwise discard this call's temporary file.
        let _ = rustix::fs::unlinkat(self.directory, self.name, rustix::fs::AtFlags::empty());
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn write_private_blob_once_impl(_path: &Path, _bytes: &[u8], _max_bytes: usize) -> Result<()> {
    bail!("private blob publication requires atomic no-replace rename support")
}

fn encode_record(
    snapshot: JournalSnapshot,
    event: u8,
    payload: [u8; 64],
) -> [u8; JOURNAL_RECORD_BYTES] {
    let mut record = [0; JOURNAL_RECORD_BYTES];
    record[..8].copy_from_slice(MAGIC);
    record[8..16].copy_from_slice(&(snapshot.head.sequence + 1).to_le_bytes());
    record[16..48].copy_from_slice(&snapshot.head.digest);
    record[48..80].copy_from_slice(&snapshot.pins.session_id);
    record[80..112].copy_from_slice(&snapshot.pins.circuit_id);
    record[112..144].copy_from_slice(&snapshot.pins.commit1);
    record[144] = event;
    record[145..209].copy_from_slice(&payload);
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(&record[..DIGEST_OFFSET]);
    record[DIGEST_OFFSET..].copy_from_slice(&h.finalize());
    record
}

fn read_snapshot(file: &mut File, pins: JournalPins) -> Result<JournalSnapshot> {
    read_history(file, pins)?
        .last()
        .copied()
        .context("empty journal")
}

fn read_history(file: &mut File, pins: JournalPins) -> Result<Vec<JournalSnapshot>> {
    ensure!(
        file.metadata()?.len() <= MAX_JOURNAL_BYTES as u64,
        "journal exceeds size limit"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(MAX_JOURNAL_BYTES);
    file.take(MAX_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_JOURNAL_BYTES,
        "journal exceeds size limit"
    );
    ensure!(
        !bytes.is_empty() && bytes.len() % JOURNAL_RECORD_BYTES == 0,
        "journal is empty or has a torn record"
    );
    let mut state = JournalSnapshot {
        pins,
        head: JournalHead {
            sequence: 0,
            digest: [0; 32],
        },
        nonce: None,
        finalized_setup_sha256: None,
        input_sha256: None,
    };
    let mut history = Vec::with_capacity(4);
    for record in bytes.chunks_exact(JOURNAL_RECORD_BYTES) {
        ensure!(&record[..8] == MAGIC, "journal magic/version mismatch");
        ensure!(
            u64::from_le_bytes(record[8..16].try_into().expect("fixed record"))
                == state.head.sequence + 1,
            "journal sequence mismatch"
        );
        ensure!(
            record[16..48] == state.head.digest,
            "journal hash chain mismatch"
        );
        ensure!(
            record[48..80] == pins.session_id
                && record[80..112] == pins.circuit_id
                && record[112..144] == pins.commit1,
            "journal session/spec/Commit1 mismatch"
        );
        ensure!(
            u64::from(record[144]) == state.head.sequence,
            "journal event order mismatch"
        );
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(&record[..DIGEST_OFFSET]);
        let digest: [u8; 32] = h.finalize().into();
        ensure!(
            digest == record[DIGEST_OFFSET..],
            "journal record digest mismatch"
        );
        let first: [u8; 32] = record[145..177].try_into().expect("fixed record");
        let second: [u8; 32] = record[177..209].try_into().expect("fixed record");
        match record[144] {
            0 => ensure!(
                first == [0; 32] && second == [0; 32],
                "noncanonical initialization record"
            ),
            1 => {
                ensure!(second == [0; 32], "noncanonical nonce record");
                state.nonce = Some(first);
            }
            2 => {
                ensure!(state.nonce == Some(first), "finalization nonce mismatch");
                state.finalized_setup_sha256 = Some(second);
            }
            3 => {
                ensure!(state.nonce == Some(first), "input nonce mismatch");
                ensure!(
                    state.finalized_setup_sha256.is_some(),
                    "input precedes finalization"
                );
                state.input_sha256 = Some(second);
            }
            _ => bail!("unknown journal event"),
        }
        state.head = JournalHead {
            sequence: state.head.sequence + 1,
            digest: record[DIGEST_OFFSET..].try_into().expect("fixed record"),
        };
        history.push(state);
    }
    Ok(history)
}
