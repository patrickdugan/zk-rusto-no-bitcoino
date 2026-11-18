//! Restartable garbler sessions with an independently held compare-and-set head.
//!
//! Secrets are saved in owner-only, no-follow files. Every reservation is fsynced
//! and accepted by the authoritative head before a proof or label can leave this
//! wrapper. Exact public setup bytes are retained because proof compression may
//! use fresh randomness. Rebuilding a session never chooses another partition.
//!
//! `LocalHeadAnchor` is a reference deployment of the head service. Its directory
//! must be independently protected against rollback; placing two directories on
//! one backup volume does not supply that property. A remote CAS service can
//! implement `HeadAnchor` without changing the garbler state machine.

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    challenge::AuthorizedChallenge,
    dispute_circuit::IndexedDisputeSpec,
    journal::{
        read_optional_private_blob, read_private_blob, write_private_blob_once, JournalHead,
        JournalPins, JournalSnapshot, SessionJournal,
    },
    program::DisputeProgram,
    protocol::{
        hash_input_bits, verify_public_setup, ActiveBaseLabelDelivery, FinalizedPublicSetup,
        GarblerSession, PreChallengeManifest,
    },
    soldering::SolderingTimings,
};

const SEED_NAME: &str = "master-seed.bin";
const SETUP_NAME: &str = "public-setup.bin";
const RELEASE_NAME: &str = "release-binding.bin";
const JOURNAL_NAME: &str = "session.journal";
pub const MAX_SAVED_SETUP_BYTES: usize = crate::journal::MAX_PRIVATE_BLOB_BYTES;
const MAX_RELEASE_BYTES: usize = 1024;

pub trait HeadAnchor {
    fn current(&mut self) -> Result<JournalSnapshot>;
    /// The update must be durable and exclusive before returning success.
    fn compare_and_set(&mut self, expected: JournalHead, next: JournalSnapshot) -> Result<()>;
}

pub struct LocalHeadAnchor {
    journal: SessionJournal,
}

impl LocalHeadAnchor {
    pub fn create(path: impl AsRef<Path>, pins: JournalPins) -> Result<Self> {
        Ok(Self {
            journal: SessionJournal::create(path, pins)?,
        })
    }
    /// The path is the trusted authority. Its valid final head is accepted as-is.
    pub fn open(path: impl AsRef<Path>, pins: JournalPins) -> Result<Self> {
        Ok(Self {
            journal: SessionJournal::open_authoritative(path, pins)?,
        })
    }
}

impl HeadAnchor for LocalHeadAnchor {
    fn current(&mut self) -> Result<JournalSnapshot> {
        self.journal.check_head(self.journal.snapshot().head)
    }
    fn compare_and_set(&mut self, expected: JournalHead, next: JournalSnapshot) -> Result<()> {
        let current = self.journal.check_head(expected)?;
        ensure!(current.pins == next.pins, "anchor pins mismatch");
        if current == next {
            return Ok(());
        }
        current.validate_successor(&next)?;
        let saved = match next.head.sequence {
            2 => self
                .journal
                .reserve_nonce(expected, next.nonce.context("missing reserved nonce")?)?,
            3 => self.journal.mark_finalized(
                expected,
                next.nonce.context("missing reserved nonce")?,
                next.finalized_setup_sha256
                    .context("missing setup digest")?,
            )?,
            4 => self.journal.reserve_input(
                expected,
                next.nonce.context("missing reserved nonce")?,
                next.input_sha256.context("missing release digest")?,
            )?,
            _ => anyhow::bail!("unsupported anchor transition"),
        };
        ensure!(saved == next, "authority and session history disagree");
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReleaseBinding {
    input_sha256: [u8; 32],
    authorization_sha256: [u8; 32],
}

pub struct DurableGarblerSession<P = IndexedDisputeSpec, A = LocalHeadAnchor> {
    directory: PathBuf,
    garbler: GarblerSession<P>,
    journal: SessionJournal,
    anchor: A,
    setup: Option<FinalizedPublicSetup<P>>,
    usable: bool,
}

impl<P: DisputeProgram> DurableGarblerSession<P, LocalHeadAnchor> {
    pub fn create(
        directory: impl AsRef<Path>,
        anchor_path: impl AsRef<Path>,
        session_id: [u8; 32],
        spec: P,
        master_seed: [u8; 32],
    ) -> Result<Self> {
        Self::create_with_anchor(directory, session_id, spec, master_seed, |pins| {
            LocalHeadAnchor::create(anchor_path, pins)
        })
    }

    pub fn open(
        directory: impl AsRef<Path>,
        anchor_path: impl AsRef<Path>,
        pins: JournalPins,
        expected_spec: P,
    ) -> Result<Self> {
        Self::open_with_anchor(
            directory,
            pins,
            expected_spec,
            LocalHeadAnchor::open(anchor_path, pins)?,
        )
    }
}

impl<P: DisputeProgram, A: HeadAnchor> DurableGarblerSession<P, A> {
    pub fn create_with_anchor(
        directory: impl AsRef<Path>,
        session_id: [u8; 32],
        spec: P,
        master_seed: [u8; 32],
        make_anchor: impl FnOnce(JournalPins) -> Result<A>,
    ) -> Result<Self> {
        spec.validate()?;
        let directory = absolute_session_directory(directory.as_ref())?;
        let secret = Zeroizing::new(master_seed);
        let garbler = GarblerSession::setup(session_id, spec.clone(), *secret);
        let pins = JournalPins {
            session_id,
            circuit_id: spec.circuit_id(),
            commit1: garbler.pre_challenge_manifest().commit1_digest()?,
        };
        write_private_blob_once(directory.join(SEED_NAME), secret.as_ref(), 32)?;
        let journal = SessionJournal::create(directory.join(JOURNAL_NAME), pins)?;
        let mut anchor = make_anchor(pins)?;
        ensure!(
            anchor.current()? == journal.snapshot(),
            "initial authority mismatch"
        );
        Ok(Self {
            directory,
            garbler,
            journal,
            anchor,
            setup: None,
            usable: true,
        })
    }

    pub fn open_with_anchor(
        directory: impl AsRef<Path>,
        pins: JournalPins,
        expected_spec: P,
        mut anchor: A,
    ) -> Result<Self> {
        expected_spec.validate()?;
        ensure!(
            expected_spec.circuit_id() == pins.circuit_id,
            "expected circuit mismatch"
        );
        let directory = absolute_session_directory(directory.as_ref())?;
        let trusted = anchor.current()?;
        ensure!(trusted.pins == pins, "authority pins mismatch");
        let (journal, pending) =
            SessionJournal::open_recovering(directory.join(JOURNAL_NAME), pins, trusted.head)?;
        let snapshot = journal.snapshot();
        // Validate artifacts before rolling a pending finalization or release forward.
        let setup = load_saved_setup::<P>(&directory, &snapshot, &expected_spec)?;
        let release = load_saved_release(&directory, &snapshot)?;
        let secret = Zeroizing::new(read_private_blob(directory.join(SEED_NAME), 32)?);
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(secret.as_slice())
                .context("saved master seed has wrong length")?,
        );
        let mut garbler = GarblerSession::setup(pins.session_id, expected_spec, *seed);
        let mut guards = snapshot;
        guards.input_sha256 = release.map(|r| r.input_sha256);
        garbler.restore_guards(&guards)?;
        if pending.is_some() {
            anchor.compare_and_set(trusted.head, snapshot)?;
        }
        ensure!(anchor.current()? == snapshot, "recovery authority mismatch");
        Ok(Self {
            directory,
            garbler,
            journal,
            anchor,
            setup,
            usable: true,
        })
    }

    pub fn manifest(&self) -> PreChallengeManifest<P> {
        self.garbler.pre_challenge_manifest()
    }
    pub fn snapshot(&self) -> JournalSnapshot {
        self.journal.snapshot()
    }

    fn current(&mut self) -> Result<JournalSnapshot> {
        ensure!(
            self.usable,
            "session requires recovery after a failed authority update"
        );
        let snapshot = self.anchor.current()?;
        self.journal.check_head(snapshot.head)?;
        ensure!(
            snapshot == self.journal.snapshot(),
            "authority state mismatch"
        );
        Ok(snapshot)
    }

    fn anchor_transition(&mut self, expected: JournalHead, next: JournalSnapshot) -> Result<()> {
        self.usable = false;
        self.anchor.compare_and_set(expected, next)?;
        ensure!(
            self.anchor.current()? == next,
            "authority did not accept the requested state"
        );
        self.usable = true;
        Ok(())
    }

    pub fn finalize(
        &mut self,
        nonce: [u8; 32],
    ) -> Result<(FinalizedPublicSetup<P>, Option<SolderingTimings>)> {
        let before = self.current()?;
        let reserved = self.journal.reserve_nonce(before.head, nonce)?;
        self.anchor_transition(before.head, reserved)?;
        if let Some(setup) = &self.setup {
            return Ok((setup.clone(), None));
        }
        // A crash can leave a complete immutable blob before the final journal record.
        let (setup, timings, saved_bytes) = if let Some(bytes) =
            read_optional_private_blob(self.directory.join(SETUP_NAME), MAX_SAVED_SETUP_BYTES)?
        {
            let setup: FinalizedPublicSetup<P> = decode_bounded(&bytes, MAX_SAVED_SETUP_BYTES)?;
            verify_public_setup(
                &reserved.pins.session_id,
                &self.manifest().spec,
                &reserved.pins.commit1,
                &nonce,
                &setup,
            )?;
            (setup, None, bytes)
        } else {
            let (setup, timings) = self.garbler.finalize_cut_and_choose(nonce)?;
            let bytes = bincode::serialize(&setup)?;
            ensure!(
                bytes.len() <= MAX_SAVED_SETUP_BYTES,
                "public setup exceeds persistence policy"
            );
            write_private_blob_once(
                self.directory.join(SETUP_NAME),
                &bytes,
                MAX_SAVED_SETUP_BYTES,
            )?;
            (setup, Some(timings), bytes)
        };
        // Bind the exact bytes durably stored above, including the recovery case.
        let next = self.journal.mark_finalized(
            reserved.head,
            nonce,
            Sha256::digest(&saved_bytes).into(),
        )?;
        self.anchor_transition(reserved.head, next)?;
        // A cached artifact may come from a previous process; rebuilding the
        // garbler on reopen restores this guard. Here the artifact is verified.
        self.garbler.mark_recovered_finalized(nonce)?;
        self.setup = Some(setup.clone());
        Ok((setup, timings))
    }

    pub fn public_setup(&self) -> Option<&FinalizedPublicSetup<P>> {
        self.setup.as_ref()
    }

    /// The capability comes from an authenticated catalogue and an independently
    /// observed confirmed challenge. Its digest binds the graph and exact spend.
    pub fn release(&mut self, authorized: &AuthorizedChallenge) -> Result<ActiveBaseLabelDelivery> {
        self.release_authenticated(
            authorized.pins(),
            authorized.nonce(),
            authorized.input_bits(),
            authorized.digest(),
        )
    }

    // The public entrypoint requires the challenge capability. Keeping the disk
    // transition here also lets unit tests exercise crash boundaries on a tiny
    // program while the challenge module tests catalogue and chain authentication.
    fn release_authenticated(
        &mut self,
        pins: JournalPins,
        nonce: [u8; 32],
        input_bits: &[bool],
        authorization_sha256: [u8; 32],
    ) -> Result<ActiveBaseLabelDelivery> {
        let before = self.current()?;
        ensure!(pins == before.pins, "authorized session mismatch");
        ensure!(Some(nonce) == before.nonce, "authorized nonce mismatch");
        ensure!(
            before.finalized_setup_sha256.is_some() && self.setup.is_some(),
            "setup must be finalized before releasing labels"
        );
        ensure!(
            input_bits.len() == self.manifest().num_wires,
            "authorized input width mismatch"
        );
        let binding = ReleaseBinding {
            input_sha256: hash_input_bits(input_bits),
            authorization_sha256,
        };
        let bytes = bincode::serialize(&binding)?;
        write_private_blob_once(self.directory.join(RELEASE_NAME), &bytes, MAX_RELEASE_BYTES)?;
        let next = self
            .journal
            .reserve_input(before.head, nonce, Sha256::digest(&bytes).into())?;
        self.anchor_transition(before.head, next)?;
        self.garbler.release_active_base_labels(nonce, input_bits)
    }
}

fn absolute_session_directory(path: &Path) -> Result<PathBuf> {
    // Resolve once so later process working-directory changes cannot redirect
    // artifact IO away from the inode-locked journal's directory. The journal IO
    // layer still rejects symlinks and parent components on every actual open.
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

fn load_saved_setup<P: DisputeProgram>(
    directory: &Path,
    snapshot: &JournalSnapshot,
    spec: &P,
) -> Result<Option<FinalizedPublicSetup<P>>> {
    let Some(expected_hash) = snapshot.finalized_setup_sha256 else {
        return Ok(None);
    };
    let bytes = read_private_blob(directory.join(SETUP_NAME), MAX_SAVED_SETUP_BYTES)
        .context("finalized setup artifact is missing")?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == expected_hash,
        "saved setup digest mismatch"
    );
    let setup = decode_bounded(&bytes, MAX_SAVED_SETUP_BYTES)?;
    verify_public_setup(
        &snapshot.pins.session_id,
        spec,
        &snapshot.pins.commit1,
        &snapshot.nonce.context("finalized setup has no nonce")?,
        &setup,
    )?;
    Ok(Some(setup))
}

fn load_saved_release(
    directory: &Path,
    snapshot: &JournalSnapshot,
) -> Result<Option<ReleaseBinding>> {
    let Some(expected_hash) = snapshot.input_sha256 else {
        return Ok(None);
    };
    let bytes = read_private_blob(directory.join(RELEASE_NAME), MAX_RELEASE_BYTES)
        .context("reserved release artifact is missing")?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == expected_hash,
        "saved release digest mismatch"
    );
    Ok(Some(decode_bounded(&bytes, MAX_RELEASE_BYTES)?))
}

pub fn decode_bounded<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "encoded artifact exceeds size policy"
    );
    catch_unwind(AssertUnwindSafe(|| {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(limit as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)
    }))
    .map_err(|_| anyhow::anyhow!("artifact decoder panicked"))?
    .context("decode canonical saved artifact")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, sync::OnceLock};

    use crate::gates::{and, W};
    use garbled_snark_verifier::CircuitContext;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TwoInputProgram;

    impl DisputeProgram for TwoInputProgram {
        fn circuit_id(&self) -> [u8; 32] {
            Sha256::digest(b"babe-pilot/durable-test/two-input-program/v1\0").into()
        }
        fn input_bits(&self) -> usize {
            2
        }
        fn validate(&self) -> Result<()> {
            Ok(())
        }
        fn eval<C: CircuitContext>(&self, c: &mut C, input: &[W]) -> Vec<W> {
            vec![and(c, input[0], input[1])]
        }
    }

    const SESSION: [u8; 32] = [101; 32];
    const SEED: [u8; 32] = [102; 32];
    const NONCE: [u8; 32] = [103; 32];
    const AUTHORIZATION: [u8; 32] = [104; 32];
    const INPUT: [bool; 2] = [true, false];

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "babe-durable-{}-{:032x}",
                std::process::id(),
                rand::random::<u128>()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn anchor(&self) -> PathBuf {
            self.0.join("authority.journal")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        setup_bytes: Vec<u8>,
    }
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            // One real two-input Nova certificate is shared by every crash case.
            let mut garbler = GarblerSession::setup(SESSION, TwoInputProgram, SEED);
            let (setup, _) = garbler.finalize_cut_and_choose(NONCE).unwrap();
            Fixture {
                setup_bytes: bincode::serialize(&setup).unwrap(),
            }
        })
    }

    struct FailingAnchor {
        inner: LocalHeadAnchor,
        fail_sequence: u64,
        after_commit: bool,
    }
    impl HeadAnchor for FailingAnchor {
        fn current(&mut self) -> Result<JournalSnapshot> {
            self.inner.current()
        }
        fn compare_and_set(&mut self, expected: JournalHead, next: JournalSnapshot) -> Result<()> {
            if next.head.sequence == self.fail_sequence {
                if self.after_commit {
                    self.inner.compare_and_set(expected, next)?;
                }
                anyhow::bail!("injected interruption at anchor boundary");
            }
            self.inner.compare_and_set(expected, next)
        }
    }

    fn failing_session(
        directory: &Directory,
        authority: &Directory,
        fail_sequence: u64,
        after_commit: bool,
    ) -> DurableGarblerSession<TwoInputProgram, FailingAnchor> {
        DurableGarblerSession::create_with_anchor(
            &directory.0,
            SESSION,
            TwoInputProgram,
            SEED,
            |pins| {
                Ok(FailingAnchor {
                    inner: LocalHeadAnchor::create(authority.anchor(), pins)?,
                    fail_sequence,
                    after_commit,
                })
            },
        )
        .unwrap()
    }

    fn save_fixture(directory: &Directory) {
        write_private_blob_once(
            directory.0.join(SETUP_NAME),
            &fixture().setup_bytes,
            MAX_SAVED_SETUP_BYTES,
        )
        .unwrap();
    }

    #[test]
    fn malformed_anchor_cas_leaves_authority_unchanged() {
        let session_dir = Directory::new();
        let authority_dir = Directory::new();
        let pins = JournalPins {
            session_id: SESSION,
            circuit_id: [1; 32],
            commit1: [2; 32],
        };
        let mut session = SessionJournal::create(session_dir.0.join(JOURNAL_NAME), pins).unwrap();
        let mut authority = LocalHeadAnchor::create(authority_dir.anchor(), pins).unwrap();
        let initial = session.snapshot();
        let valid = session.reserve_nonce(initial.head, NONCE).unwrap();
        let mut invalid = valid;
        invalid.head.digest[0] ^= 1;
        assert!(authority.compare_and_set(initial.head, invalid).is_err());
        assert_eq!(authority.current().unwrap(), initial);
        invalid = valid;
        invalid.finalized_setup_sha256 = Some([9; 32]);
        assert!(authority.compare_and_set(initial.head, invalid).is_err());
        assert_eq!(authority.current().unwrap(), initial);
        authority.compare_and_set(initial.head, valid).unwrap();
        assert_eq!(authority.current().unwrap(), valid);
    }

    #[test]
    fn recovery_checks_seed_commitment_before_advancing_authority() {
        let dir = Directory::new();
        let authority_dir = Directory::new();
        let mut session = failing_session(&dir, &authority_dir, 2, false);
        let pins = session.snapshot().pins;
        assert!(session.finalize(NONCE).is_err());
        assert!(session.finalize(NONCE).is_err());
        assert!(session.public_setup().is_none());
        drop(session);
        fs::remove_file(dir.0.join(SEED_NAME)).unwrap();
        assert!(
            DurableGarblerSession::open(&dir.0, authority_dir.anchor(), pins, TwoInputProgram)
                .is_err()
        );
        let mut authority = LocalHeadAnchor::open(authority_dir.anchor(), pins).unwrap();
        assert_eq!(authority.current().unwrap().head.sequence, 1);
        drop(authority);
        write_private_blob_once(dir.0.join(SEED_NAME), &[0; 32], 32).unwrap();
        assert!(
            DurableGarblerSession::open(&dir.0, authority_dir.anchor(), pins, TwoInputProgram)
                .is_err()
        );
        let mut authority = LocalHeadAnchor::open(authority_dir.anchor(), pins).unwrap();
        assert_eq!(authority.current().unwrap().head.sequence, 1);
        drop(authority);
        fs::write(dir.0.join(SEED_NAME), SEED).unwrap();
        let mut recovered =
            DurableGarblerSession::open(&dir.0, authority_dir.anchor(), pins, TwoInputProgram)
                .unwrap();
        assert_eq!(recovered.snapshot().nonce, Some(NONCE));
        assert!(recovered
            .release_authenticated(pins, NONCE, &INPUT, AUTHORIZATION)
            .is_err());
        assert!(!dir.0.join(RELEASE_NAME).exists());
        assert!(recovered.finalize([99; 32]).is_err());
    }

    #[test]
    fn corrupted_optional_setup_never_triggers_fresh_proving_or_overwrite() {
        let dir = Directory::new();
        let authority_dir = Directory::new();
        let mut session = DurableGarblerSession::create(
            &dir.0,
            authority_dir.anchor(),
            SESSION,
            TwoInputProgram,
            SEED,
        )
        .unwrap();
        let pins = session.snapshot().pins;
        let bad_blob = b"invalid saved setup";
        write_private_blob_once(dir.0.join(SETUP_NAME), bad_blob, MAX_SAVED_SETUP_BYTES).unwrap();
        assert!(session.finalize(NONCE).is_err());
        assert_eq!(session.snapshot().head.sequence, 2);
        assert!(session.public_setup().is_none());
        assert_eq!(
            read_private_blob(dir.0.join(SETUP_NAME), MAX_SAVED_SETUP_BYTES).unwrap(),
            bad_blob
        );
        assert!(session.finalize([99; 32]).is_err());
        drop(session);
        let mut reopened =
            DurableGarblerSession::open(&dir.0, authority_dir.anchor(), pins, TwoInputProgram)
                .unwrap();
        assert!(reopened.finalize(NONCE).is_err());
        assert!(reopened.public_setup().is_none());
    }

    #[test]
    fn finalized_setup_recovers_at_both_sides_of_the_anchor_cas() {
        for after_commit in [false, true] {
            let dir = Directory::new();
            let authority_dir = Directory::new();
            let mut session = failing_session(&dir, &authority_dir, 3, after_commit);
            let pins = session.snapshot().pins;
            // Simulate a crash after atomically publishing the proof blob but
            // before finalization reached the journal. No new proof is generated.
            save_fixture(&dir);
            assert!(session.finalize(NONCE).is_err());
            assert_eq!(session.snapshot().head.sequence, 3);
            assert!(session.public_setup().is_none());
            drop(session);
            let mut recovered =
                DurableGarblerSession::open(&dir.0, authority_dir.anchor(), pins, TwoInputProgram)
                    .unwrap();
            let (setup, timings) = recovered.finalize(NONCE).unwrap();
            assert!(timings.is_none());
            assert_eq!(bincode::serialize(&setup).unwrap(), fixture().setup_bytes);
            assert!(recovered.finalize([99; 32]).is_err());
            assert!(recovered
                .release_authenticated(pins, NONCE, &[true], AUTHORIZATION)
                .is_err());
            assert!(!dir.0.join(RELEASE_NAME).exists());
        }
    }

    #[test]
    fn label_release_recovers_exact_input_and_authorization_after_interruption() {
        for after_commit in [false, true] {
            let dir = Directory::new();
            let authority_dir = Directory::new();
            let mut session = failing_session(&dir, &authority_dir, 4, after_commit);
            let pins = session.snapshot().pins;
            save_fixture(&dir);
            session.finalize(NONCE).unwrap();
            assert!(session
                .release_authenticated(pins, NONCE, &INPUT, AUTHORIZATION)
                .is_err());
            assert_eq!(session.snapshot().head.sequence, 4);
            assert!(session
                .release_authenticated(pins, NONCE, &INPUT, AUTHORIZATION)
                .is_err());
            drop(session);
            let mut recovered =
                DurableGarblerSession::open(&dir.0, authority_dir.anchor(), pins, TwoInputProgram)
                    .unwrap();
            let first = recovered
                .release_authenticated(pins, NONCE, &INPUT, AUTHORIZATION)
                .unwrap();
            assert_eq!(first.active_labels.len(), 2);
            assert_eq!(first.input_sha256, hash_input_bits(&INPUT));
            assert_eq!(
                recovered
                    .release_authenticated(pins, NONCE, &INPUT, AUTHORIZATION)
                    .unwrap(),
                first
            );
            assert!(recovered
                .release_authenticated(pins, NONCE, &[false, false], AUTHORIZATION)
                .is_err());
            assert!(recovered
                .release_authenticated(pins, NONCE, &INPUT, [99; 32])
                .is_err());
            drop(recovered);
            let mut restarted =
                DurableGarblerSession::open(&dir.0, authority_dir.anchor(), pins, TwoInputProgram)
                    .unwrap();
            assert_eq!(
                restarted
                    .release_authenticated(pins, NONCE, &INPUT, AUTHORIZATION)
                    .unwrap(),
                first
            );
        }
    }
}
