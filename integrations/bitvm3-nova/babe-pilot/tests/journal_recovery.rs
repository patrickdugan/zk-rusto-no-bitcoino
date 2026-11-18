//! Bounded filesystem and subprocess tests for the durable session guard.
#![cfg(unix)]

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    sync::atomic::{AtomicU64, Ordering},
};

use babe_pilot::journal::{
    read_optional_private_blob, read_private_blob, write_private_blob_once, JournalHead,
    JournalPins, JournalSnapshot, SessionJournal, JOURNAL_RECORD_BYTES, MAX_JOURNAL_BYTES,
    MAX_PRIVATE_BLOB_BYTES,
};
use sha2::{Digest, Sha256};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const NONCE: [u8; 32] = [41; 32];
const SETUP: [u8; 32] = [42; 32];
const INPUT: [u8; 32] = [43; 32];

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        let name = format!(
            "babe-journal-{}-{}-{:016x}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
            rand::random::<u64>(),
        );
        let path = std::env::temp_dir().join(name);
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("session.journal")
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pins() -> JournalPins {
    JournalPins {
        session_id: [11; 32],
        circuit_id: [12; 32],
        commit1: [13; 32],
    }
}

fn completed(path: &Path) -> JournalSnapshot {
    let mut journal = SessionJournal::create(path, pins()).unwrap();
    let head = journal.snapshot().head;
    let head = journal.reserve_nonce(head, NONCE).unwrap().head;
    let head = journal.mark_finalized(head, NONCE, SETUP).unwrap().head;
    journal.reserve_input(head, NONCE, INPUT).unwrap()
}

#[test]
fn reservations_are_ordered_idempotent_and_survive_reopen() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let mut journal = SessionJournal::create(&path, pins()).unwrap();
    let initial = journal.snapshot();
    assert_eq!(initial.head.sequence, 1);
    assert!(initial.nonce.is_none());
    assert!(SessionJournal::create(&path, pins()).is_err());
    assert!(journal.mark_finalized(initial.head, NONCE, SETUP).is_err());
    assert!(journal.reserve_input(initial.head, NONCE, INPUT).is_err());

    let reserved = journal.reserve_nonce(initial.head, NONCE).unwrap();
    assert_eq!(reserved.head.sequence, 2);
    assert_eq!(
        journal.reserve_nonce(reserved.head, NONCE).unwrap(),
        reserved
    );
    assert!(journal.reserve_nonce(reserved.head, [44; 32]).is_err());
    assert!(journal.reserve_nonce(initial.head, NONCE).is_err());
    assert!(journal.reserve_input(reserved.head, NONCE, INPUT).is_err());
    drop(journal);

    let mut journal = SessionJournal::open(&path, pins(), reserved.head).unwrap();
    assert_eq!(journal.snapshot(), reserved);
    assert!(journal
        .mark_finalized(reserved.head, [44; 32], SETUP)
        .is_err());
    let finalized = journal.mark_finalized(reserved.head, NONCE, SETUP).unwrap();
    assert_eq!(finalized.head.sequence, 3);
    assert_eq!(
        journal
            .mark_finalized(finalized.head, NONCE, SETUP)
            .unwrap(),
        finalized
    );
    assert!(journal
        .mark_finalized(finalized.head, NONCE, [44; 32])
        .is_err());
    drop(journal);

    let mut journal = SessionJournal::open(&path, pins(), finalized.head).unwrap();
    let input = journal.reserve_input(finalized.head, NONCE, INPUT).unwrap();
    assert_eq!(input.head.sequence, 4);
    assert_eq!(
        journal.reserve_input(input.head, NONCE, INPUT).unwrap(),
        input
    );
    assert!(journal.reserve_input(input.head, NONCE, [44; 32]).is_err());
    assert!(journal.reserve_input(input.head, [44; 32], INPUT).is_err());
    assert_eq!(journal.reserve_nonce(input.head, NONCE).unwrap(), input);
    assert_eq!(
        journal.mark_finalized(input.head, NONCE, SETUP).unwrap(),
        input
    );
    assert_eq!(fs::metadata(&path).unwrap().len(), MAX_JOURNAL_BYTES as u64);
    drop(journal);
    assert_eq!(
        SessionJournal::open(&path, pins(), input.head)
            .unwrap()
            .snapshot(),
        input
    );
}

fn child(path: &Path, head: JournalHead, action: &str, anchor: &Path) -> ExitStatus {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "journal_process_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("BABE_JOURNAL_TEST_PATH", path)
        .env(
            "BABE_JOURNAL_TEST_HEAD",
            serde_json::to_string(&head).unwrap(),
        )
        .env("BABE_JOURNAL_TEST_ACTION", action)
        .env("BABE_JOURNAL_TEST_ANCHOR", anchor)
        .status()
        .unwrap()
}

/// Runs in a separate process. Exit 73 deliberately skips Rust destructors after
/// the reservation and its test-owned external anchor have both been fsynced.
#[test]
#[ignore = "subprocess entrypoint, invoked by the parent recovery and locking tests"]
fn journal_process_worker() {
    let path = PathBuf::from(std::env::var_os("BABE_JOURNAL_TEST_PATH").unwrap());
    let expected: JournalHead =
        serde_json::from_str(&std::env::var("BABE_JOURNAL_TEST_HEAD").unwrap()).unwrap();
    let action = std::env::var("BABE_JOURNAL_TEST_ACTION").unwrap();
    if action == "locked" {
        assert!(SessionJournal::open(&path, pins(), expected).is_err());
        return;
    }
    let mut journal = SessionJournal::open(&path, pins(), expected).unwrap();
    let snapshot = match action.as_str() {
        "nonce" => journal.reserve_nonce(expected, NONCE).unwrap(),
        "input" => journal.reserve_input(expected, NONCE, INPUT).unwrap(),
        _ => panic!("unknown subprocess action"),
    };
    let anchor = PathBuf::from(std::env::var_os("BABE_JOURNAL_TEST_ANCHOR").unwrap());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&anchor)
        .unwrap();
    file.write_all(&serde_json::to_vec(&snapshot.head).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    File::open(anchor.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    std::process::exit(73);
}

#[test]
fn process_exit_preserves_nonce_and_input_reservations() {
    let dir = PrivateDirectory::new();
    let anchors = PrivateDirectory::new();
    let path = dir.journal();
    let journal = SessionJournal::create(&path, pins()).unwrap();
    let initial = journal.snapshot().head;
    drop(journal);
    let nonce_anchor = anchors.0.join("nonce.anchor");
    assert_eq!(
        child(&path, initial, "nonce", &nonce_anchor).code(),
        Some(73)
    );
    let nonce_head = serde_json::from_slice(&fs::read(nonce_anchor).unwrap()).unwrap();
    let mut recovered = SessionJournal::open(&path, pins(), nonce_head).unwrap();
    assert_eq!(recovered.snapshot().nonce, Some(NONCE));
    assert!(recovered.reserve_nonce(nonce_head, [99; 32]).is_err());
    assert_eq!(
        recovered.reserve_nonce(nonce_head, NONCE).unwrap().head,
        nonce_head
    );
    let finalized = recovered.mark_finalized(nonce_head, NONCE, SETUP).unwrap();
    drop(recovered);

    let input_anchor = anchors.0.join("input.anchor");
    assert_eq!(
        child(&path, finalized.head, "input", &input_anchor).code(),
        Some(73)
    );
    let input_head = serde_json::from_slice(&fs::read(input_anchor).unwrap()).unwrap();
    let mut recovered = SessionJournal::open(&path, pins(), input_head).unwrap();
    assert_eq!(recovered.snapshot().finalized_setup_sha256, Some(SETUP));
    assert_eq!(recovered.snapshot().input_sha256, Some(INPUT));
    assert!(recovered
        .reserve_input(input_head, NONCE, [99; 32])
        .is_err());
    assert_eq!(
        recovered
            .reserve_input(input_head, NONCE, INPUT)
            .unwrap()
            .head,
        input_head
    );
}

#[test]
fn one_process_holds_the_lock_until_its_handle_drops() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let journal = SessionJournal::create(&path, pins()).unwrap();
    let head = journal.snapshot().head;
    assert!(SessionJournal::open(&path, pins(), head).is_err());
    assert!(child(&path, head, "locked", &dir.0.join("unused.anchor")).success());
    drop(journal);
    assert!(SessionJournal::open(&path, pins(), head).is_ok());
}

#[test]
fn independently_pinned_head_detects_rollback_forks_and_unanchored_appends() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let mut journal = SessionJournal::create(&path, pins()).unwrap();
    let initial = journal.snapshot().head;
    let initial_bytes = fs::read(&path).unwrap();
    let reserved = journal.reserve_nonce(initial, NONCE).unwrap().head;
    drop(journal);
    // A crash between the local append and the external anchor update fails closed.
    assert!(SessionJournal::open(&path, pins(), initial).is_err());
    assert!(SessionJournal::open(&path, pins(), reserved).is_ok());
    fs::write(&path, &initial_bytes).unwrap();
    assert!(SessionJournal::open(&path, pins(), reserved).is_err());

    // Same length, sequence and pins, with a different valid history, also fails.
    let mut alternate = SessionJournal::open(&path, pins(), initial).unwrap();
    let alternate_head = alternate.reserve_nonce(initial, [97; 32]).unwrap().head;
    assert_eq!(alternate_head.sequence, reserved.sequence);
    assert_ne!(alternate_head.digest, reserved.digest);
    drop(alternate);
    assert!(SessionJournal::open(&path, pins(), reserved).is_err());
    // Deliberately supplying the rolled-back anchor authorizes the older history.
    // This expresses why the independent anchor must survive a local rollback.
    assert!(SessionJournal::open(&path, pins(), alternate_head).is_ok());
}

#[test]
fn recovery_exposes_only_one_complete_successor_of_the_trusted_prefix() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let mut journal = SessionJournal::create(&path, pins()).unwrap();
    let initial = journal.snapshot().head;
    let reserved = journal.reserve_nonce(initial, NONCE).unwrap();
    drop(journal);
    let (mut recovered, pending) = SessionJournal::open_recovering(&path, pins(), initial).unwrap();
    assert_eq!(pending, Some(reserved.head));
    assert_eq!(recovered.snapshot(), reserved);
    assert!(recovered.check_head(initial).is_err());
    let finalized = recovered
        .mark_finalized(reserved.head, NONCE, SETUP)
        .unwrap();
    drop(recovered);

    assert!(SessionJournal::open_recovering(&path, pins(), initial).is_err());
    let (recovered, pending) =
        SessionJournal::open_recovering(&path, pins(), reserved.head).unwrap();
    assert_eq!(pending, Some(finalized.head));
    drop(recovered);
    let (recovered, pending) =
        SessionJournal::open_recovering(&path, pins(), finalized.head).unwrap();
    assert!(pending.is_none());
    drop(recovered);
    let forged_prefix = JournalHead {
        sequence: reserved.head.sequence,
        digest: [0; 32],
    };
    assert!(SessionJournal::open_recovering(&path, pins(), forged_prefix).is_err());
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop();
    fs::write(&path, &bytes).unwrap();
    assert!(SessionJournal::open_recovering(&path, pins(), reserved.head).is_err());
}

#[test]
fn explicit_authority_open_still_checks_chain_permissions_and_lock() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let saved = completed(&path);
    let authority = SessionJournal::open_authoritative(&path, pins()).unwrap();
    assert_eq!(authority.snapshot(), saved);
    assert!(SessionJournal::open_authoritative(&path, pins()).is_err());
    drop(authority);
    let mut bytes = fs::read(&path).unwrap();
    bytes[48] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(SessionJournal::open_authoritative(&path, pins()).is_err());
}

#[test]
fn session_spec_and_commit1_are_independent_pins() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let saved = completed(&path);
    for change in 0..3 {
        let mut different = pins();
        match change {
            0 => different.session_id[0] ^= 1,
            1 => different.circuit_id[0] ^= 1,
            _ => different.commit1[0] ^= 1,
        }
        assert!(SessionJournal::open(&path, different, saved.head).is_err());
    }
}

#[test]
fn every_truncated_prefix_and_oversized_suffix_fails_closed() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let saved = completed(&path);
    let complete = fs::read(&path).unwrap();
    for cut in 0..complete.len() {
        fs::write(&path, &complete[..cut]).unwrap();
        assert!(
            SessionJournal::open(&path, pins(), saved.head).is_err(),
            "cut {cut}"
        );
    }
    let mut oversized = complete.clone();
    oversized.push(0);
    fs::write(&path, &oversized).unwrap();
    assert!(SessionJournal::open(&path, pins(), saved.head).is_err());
    fs::write(&path, &complete).unwrap();
    assert!(SessionJournal::open(&path, pins(), saved.head).is_ok());
}

#[test]
fn every_single_byte_corruption_is_rejected() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let saved = completed(&path);
    let mut bytes = fs::read(&path).unwrap();
    for index in 0..bytes.len() {
        bytes[index] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(
            SessionJournal::open(&path, pins(), saved.head).is_err(),
            "byte {index}"
        );
        bytes[index] ^= 1;
    }
}

/// Recompute the format's hash chain to exercise semantic checks independently of
/// accidental corruption checks. A supplied anchor alone cannot bless bad state.
fn rehash_history(bytes: &mut [u8]) -> JournalHead {
    let mut prior = [0; 32];
    let mut count = 0;
    for record in bytes.chunks_exact_mut(JOURNAL_RECORD_BYTES) {
        record[16..48].copy_from_slice(&prior);
        let mut h = Sha256::new();
        h.update(b"babe-pilot/session-journal/v1\0");
        h.update(&record[..209]);
        prior = h.finalize().into();
        record[209..].copy_from_slice(&prior);
        count += 1;
    }
    JournalHead {
        sequence: count,
        digest: prior,
    }
}

#[test]
fn correctly_rehashed_invalid_state_transitions_are_rejected() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    completed(&path);
    let original = fs::read(&path).unwrap();
    let invalid_offsets = [
        0,                              // magic/version
        8,                              // initial sequence
        145,                            // initialization payload
        JOURNAL_RECORD_BYTES + 177,     // unused nonce payload
        JOURNAL_RECORD_BYTES + 144,     // nonce event type
        2 * JOURNAL_RECORD_BYTES + 48,  // a changed session pin
        2 * JOURNAL_RECORD_BYTES + 145, // finalization with a different nonce
        3 * JOURNAL_RECORD_BYTES + 145, // input with a different nonce
    ];
    for offset in invalid_offsets {
        let mut bad = original.clone();
        bad[offset] ^= 1;
        let forged_anchor = rehash_history(&mut bad);
        fs::write(&path, &bad).unwrap();
        assert!(
            SessionJournal::open(&path, pins(), forged_anchor).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn symlinks_hardlinks_and_unsafe_permissions_are_rejected() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let saved = completed(&path);
    let link = dir.0.join("symlink.journal");
    symlink(&path, &link).unwrap();
    assert!(SessionJournal::open(&link, pins(), saved.head).is_err());
    assert!(SessionJournal::create(&link, pins()).is_err());
    let parent_link = dir.0.join("linked-parent");
    symlink(&dir.0, &parent_link).unwrap();
    assert!(SessionJournal::open(parent_link.join("session.journal"), pins(), saved.head).is_err());

    let hardlink = dir.0.join("hardlink.journal");
    fs::hard_link(&path, &hardlink).unwrap();
    assert!(SessionJournal::open(&path, pins(), saved.head).is_err());
    fs::remove_file(hardlink).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(SessionJournal::open(&path, pins(), saved.head).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(SessionJournal::open(&path, pins(), saved.head).is_err());
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(SessionJournal::open(&path, pins(), saved.head).is_ok());
}

#[test]
fn changed_path_or_contents_are_rechecked_before_any_reservation() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    let mut journal = SessionJournal::create(&path, pins()).unwrap();
    let head = journal.snapshot().head;
    let original = fs::read(&path).unwrap();
    fs::rename(&path, dir.0.join("old-inode.journal")).unwrap();
    let mut replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    replacement.write_all(&original).unwrap();
    assert!(journal.reserve_nonce(head, NONCE).is_err());
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        JOURNAL_RECORD_BYTES as u64
    );
    drop(journal);

    let mut journal = SessionJournal::open(&path, pins(), head).unwrap();
    let mut corrupt = original;
    corrupt[145] ^= 1;
    fs::write(&path, corrupt).unwrap();
    assert!(journal.reserve_nonce(head, NONCE).is_err());
}

#[test]
fn fifo_paths_fail_without_waiting_for_a_peer() {
    let dir = PrivateDirectory::new();
    let path = dir.journal();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(SessionJournal::open(
        &path,
        pins(),
        JournalHead {
            sequence: 1,
            digest: [0; 32]
        }
    )
    .is_err());
}

#[test]
fn private_blobs_are_bounded_private_and_byte_exact_on_retry() {
    let dir = PrivateDirectory::new();
    let path = dir.0.join("master-seed.bin");
    let seed = [81; 32];
    assert_eq!(read_optional_private_blob(&path, 32).unwrap(), None);
    assert!(read_optional_private_blob(dir.0.join("missing-parent/file"), 32).is_err());
    write_private_blob_once(&path, &seed, 32).unwrap();
    assert_eq!(
        read_optional_private_blob(&path, 32).unwrap(),
        Some(seed.to_vec())
    );
    assert_eq!(read_private_blob(&path, 32).unwrap(), seed);
    write_private_blob_once(&path, &seed, 32).unwrap();
    assert!(write_private_blob_once(&path, &[82; 32], 32).is_err());
    assert_eq!(read_private_blob(&path, 32).unwrap(), seed);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(read_private_blob(&path, 31).is_err());
    assert!(read_private_blob(&path, MAX_PRIVATE_BLOB_BYTES + 1).is_err());
    assert!(write_private_blob_once(dir.0.join("oversized.bin"), &[0; 33], 32).is_err());
    assert!(!dir.0.join("oversized.bin").exists());
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}

#[test]
fn private_blob_publication_rejects_links_and_unsafe_existing_files() {
    let dir = PrivateDirectory::new();
    let path = dir.0.join("saved.bin");
    write_private_blob_once(&path, b"saved", 16).unwrap();
    let link = dir.0.join("link.bin");
    symlink(&path, &link).unwrap();
    assert!(read_private_blob(&link, 16).is_err());
    assert!(read_optional_private_blob(&link, 16).is_err());
    assert!(write_private_blob_once(&link, b"changed", 16).is_err());
    assert_eq!(read_private_blob(&path, 16).unwrap(), b"saved");
    let hardlink = dir.0.join("hardlink.bin");
    fs::hard_link(&path, &hardlink).unwrap();
    assert!(read_private_blob(&path, 16).is_err());
    assert!(write_private_blob_once(&path, b"saved", 16).is_err());
    fs::remove_file(hardlink).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_private_blob(&path, 16).is_err());
    assert!(write_private_blob_once(&path, b"saved", 16).is_err());
}

#[test]
fn complete_successor_check_rejects_malformed_cas_candidates() {
    let dir = PrivateDirectory::new();
    let mut journal = SessionJournal::create(dir.journal(), pins()).unwrap();
    let initial = journal.snapshot();
    let nonce = journal.reserve_nonce(initial.head, NONCE).unwrap();
    initial.validate_successor(&nonce).unwrap();
    let mut malformed = nonce;
    malformed.head.digest[0] ^= 1;
    assert!(initial.validate_successor(&malformed).is_err());
    malformed = nonce;
    malformed.finalized_setup_sha256 = Some(SETUP);
    assert!(initial.validate_successor(&malformed).is_err());
    let finalized = journal.mark_finalized(nonce.head, NONCE, SETUP).unwrap();
    nonce.validate_successor(&finalized).unwrap();
    malformed = finalized;
    malformed.nonce = Some([99; 32]);
    assert!(nonce.validate_successor(&malformed).is_err());
    let input = journal.reserve_input(finalized.head, NONCE, INPUT).unwrap();
    finalized.validate_successor(&input).unwrap();
    malformed = input;
    malformed.finalized_setup_sha256 = Some([99; 32]);
    assert!(finalized.validate_successor(&malformed).is_err());
    assert!(initial.validate_successor(&input).is_err());
}

#[test]
fn concurrent_private_blob_writers_publish_one_complete_value() {
    use std::sync::{Arc, Barrier};

    let dir = PrivateDirectory::new();
    let path = dir.0.join("setup.bin");
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0u8..4)
        .map(|index| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let bytes = vec![index; 64 * 1024];
                barrier.wait();
                write_private_blob_once(path, &bytes, bytes.len()).is_ok()
            })
        })
        .collect();
    let winners = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|success| *success)
        .count();
    assert_eq!(winners, 1);
    let published = read_private_blob(&path, 64 * 1024).unwrap();
    assert_eq!(published.len(), 64 * 1024);
    assert!(published.iter().all(|byte| *byte == published[0]));
    assert!(published[0] < 4);

    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            let bytes = published.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                write_private_blob_once(path, &bytes, bytes.len()).unwrap();
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}
