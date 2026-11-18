//! Two-Phase Cut-and-Choose + Transparent Nova Soldering Protocol (`(N = 7, M = 3)` Pilot).
//!
//! Enforces strict role separation between:
//! - `GarblerSession`: owns the secret 256-bit ChaCha20 seeds `{s_k}` (`ZeroizeOnDrop`), generates
//!   `Commit_1`, opens `N - M` seeds after challenger randomness `nonce`, proves `SolderingCertificate`,
//!   and releases ONLY the active base labels `{L_{b,i,x_i}}` for an agreed dispute input `x`.
//! - `PublicSetup` / `Evaluator`: receives ONLY authenticated public artifacts, opened C&C seeds,
//!   verified `SolderingCertificate`, and active base labels—zero access to retained seeds,
//!   Free-XOR `Delta_j`, or inactive wire labels.

use anyhow::{ensure, Context, Result};
use ff::Field;
use garbled_snark_verifier::{
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode,
        EncodeInput, EvaluateMode, StreamingResult,
    },
    AesCcrGateHasher, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, S,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    dispute_circuit::IndexedDisputeSpec,
    elem::{f_from_canonical, f_to_le, F},
    gates::W,
    program::DisputeProgram,
    soldering::{
        compute_base_tap_root, compute_pos_instance_root, derive_wire_blindings,
        prove_soldering_certificate, tap_label_sha256, unsolder_active_labels,
        verify_soldering_certificate, GarblerSolderingSecret, SolderingCertificate,
        SolderingTimings, PILOT_SOLDERED_INSTANCES,
    },
};

#[cfg(test)]
#[path = "protocol_hardening_tests.rs"]
mod hardening_tests;

pub const PILOT_TOTAL_INSTANCES: usize = 7; // N = 7
pub const PILOT_RETAINED_INSTANCES: usize = 3; // M = 3 (1 base + 2 soldered)
pub const PILOT_OPENED_INSTANCES: usize = PILOT_TOTAL_INSTANCES - PILOT_RETAINED_INSTANCES; // 4
const GARBLE_CAPACITY: usize = 32_768;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceHeader {
    pub index: usize,
    pub public_salt: [u8; 16],
    pub true_label: [u8; 16],
    pub false_label: [u8; 16],
    pub ciphertext_count: u64,
    pub ciphertext_sha256: [u8; 32],
    /// Poseidon accumulator root `R_tap[k]` of Tapscript `OP_SHA256` hashlock pairs (serialized canonical LE).
    pub tap_commitment_root: [u8; 32],
    /// Poseidon accumulator root `R_pos[k]` of hiding Poseidon wire commitments (serialized canonical LE).
    pub pos_commitment_root: [u8; 32],
    /// Raw `OP_SHA256` commitment to output label `O_{k,0}` (no authenticated refutation).
    pub accept_output_sha256: [u8; 32],
    /// Raw `OP_SHA256` commitment to output label `O_{k,1}` (`refute == true` -> claim refuted / slashable).
    pub refute_output_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreChallengeManifest<P = IndexedDisputeSpec> {
    pub session_id: [u8; 32],
    pub spec: P,
    pub num_wires: usize,
    pub headers: Vec<InstanceHeader>,
}

impl<P: DisputeProgram> PreChallengeManifest<P> {
    /// Computes `Commit_1` binding session ID, circuit spec, and all `N` candidate headers prior to `nonce`.
    pub fn commit1_digest(&self) -> Result<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(b"babe-pilot/commit1/v2\0");
        h.update(bincode::serialize(self).context("serialize PreChallengeManifest")?);
        Ok(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutAndChoosePartition {
    pub commit1: [u8; 32],
    pub nonce: [u8; 32],
    pub opened_indices: [usize; PILOT_OPENED_INSTANCES],
    pub base_index: usize,
    pub soldered_indices: [usize; PILOT_SOLDERED_INSTANCES],
}

impl CutAndChoosePartition {
    /// Deterministically derives the `(opened, retained)` split and `base = min(retained)` from `(Commit_1, nonce)`.
    pub fn derive(commit1: [u8; 32], nonce: [u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(b"babe-pilot/cc-partition/v2\0");
        h.update(commit1);
        h.update(nonce);
        let rng_seed: [u8; 32] = h.finalize().into();
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        let mut indices: Vec<usize> = (0..PILOT_TOTAL_INSTANCES).collect();
        for i in (1..indices.len()).rev() {
            let j = rng.gen_range(0..=i);
            indices.swap(i, j);
        }
        let mut opened = [0usize; PILOT_OPENED_INSTANCES];
        opened.copy_from_slice(&indices[..PILOT_OPENED_INSTANCES]);
        opened.sort_unstable();

        let mut retained = indices[PILOT_OPENED_INSTANCES..].to_vec();
        retained.sort_unstable();
        let base_index = retained[0];
        let soldered_indices: [usize; PILOT_SOLDERED_INSTANCES] =
            retained[1..].try_into().expect("PILOT_SOLDERED_INSTANCES");

        Self {
            commit1,
            nonce,
            opened_indices: opened,
            base_index,
            soldered_indices,
        }
    }

    pub fn retained_indices(&self) -> [usize; PILOT_RETAINED_INSTANCES] {
        [
            self.base_index,
            self.soldered_indices[0],
            self.soldered_indices[1],
        ]
    }
}

/// Finalized public artifacts delivered to the challenger/evaluator after Phase 2 (`Commit_2`).
/// Contains ONLY opened seeds (for `O`) and public ciphertexts / hashlocks / ZK certificate (for `R`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedPublicSetup<P = IndexedDisputeSpec> {
    pub manifest: PreChallengeManifest<P>,
    pub nonce: [u8; 32],
    pub opened_seeds: [([u8; 32], usize); PILOT_OPENED_INSTANCES],
    /// Public `CheckLampSigsMatch` SHA-256 hashlock pairs `(h_{b,i,0}, h_{b,i,1})` for base instance `b`.
    pub base_tap_hashlocks: Vec<([u8; 32], [u8; 32])>,
    /// Retained ciphertext streams (16-byte LE entries) for `[base, soldered_0, soldered_1]`.
    pub retained_ciphertexts: [Vec<[u8; 16]>; PILOT_RETAINED_INSTANCES],
    pub certificate: SolderingCertificate,
}

/// A setup verified against a commitment independently recorded before the nonce.
/// Private fields prevent constructing this capability from unverified network data.
/// The borrow prevents mutation of the artifacts during evaluation.
#[derive(Debug)]
pub struct VerifiedPublicSetup<'a, P = IndexedDisputeSpec> {
    setup: &'a FinalizedPublicSetup<P>,
    partition: CutAndChoosePartition,
    snark_verify_seconds: f64,
}

impl<P: DisputeProgram> VerifiedPublicSetup<'_, P> {
    pub fn snark_verify_seconds(&self) -> f64 {
        self.snark_verify_seconds
    }

    pub fn setup(&self) -> &FinalizedPublicSetup<P> {
        self.setup
    }

    pub fn partition(&self) -> &CutAndChoosePartition {
        &self.partition
    }
}

/// Active base labels revealed on-chain (`AssertLabelsTx`) for a challenged dispute input `x`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveBaseLabelDelivery {
    pub session_id: [u8; 32],
    pub input_sha256: [u8; 32],
    pub base_index: usize,
    pub active_labels: Vec<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceVerdict {
    NoRefutation { output_label: [u8; 16] },
    Refute { output_label: [u8; 16] },
    CorruptedOutput { raw_label: [u8; 16] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeResolution {
    /// At least one circuit produced its zero label and none produced a refutation.
    /// This includes malformed openings and does not establish global claim validity.
    NoAuthenticatedRefutation,
    /// At least one retained circuit `instance_index` produced its authentic `refute` preimage,
    /// allowing the challenger to spend leaf `instance_index` of the 1-of-`M` `Disprove` Taptree!
    AuthenticatedRefutation {
        winning_instance_index: usize,
        refute_preimage: [u8; 16],
        refute_sha256: [u8; 32],
    },
    /// Delivery is absent or invalid. The enclosing funded graph must enforce and observe
    /// its CSV deadline before a withholding spend becomes available.
    AwaitingWithholdingTimeout { reason: String },
}

// --------------------------------------------------------------------------------------------
// Internal Streaming Garble / Evaluate Adapters
// --------------------------------------------------------------------------------------------

struct GInput(usize);
impl CircuitInput for GInput {
    type WireRepr = Vec<W>;
    fn allocate(&self, mut issue: impl FnMut() -> W) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<W> {
        w.clone()
    }
}
impl<H: GateHasher, CTH: CiphertextHandler> EncodeInput<GarbleMode<H, CTH>> for GInput {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut GarbleMode<H, CTH>) {
        for &w in wires {
            let gw = mode.issue_garbled_wire();
            mode.feed_wire(w, gw);
        }
    }
}

struct EInput<'a> {
    labels: &'a [S],
    bits: &'a [bool],
}
impl CircuitInput for EInput<'_> {
    type WireRepr = Vec<W>;
    fn allocate(&self, mut issue: impl FnMut() -> W) -> Self::WireRepr {
        (0..self.bits.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<W> {
        w.clone()
    }
}
impl<H: GateHasher, SRC: CiphertextSource> EncodeInput<EvaluateMode<H, SRC>> for EInput<'_> {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut EvaluateMode<H, SRC>) {
        for (i, &w) in wires.iter().enumerate() {
            mode.feed_wire(w, EvaluatedWire::new(self.labels[i], self.bits[i]));
        }
    }
}

#[derive(Default)]
struct VecCiphertextSink {
    entries: Vec<[u8; 16]>,
    hasher: Sha256,
}
impl CiphertextHandler for VecCiphertextSink {
    type Result = (Vec<[u8; 16]>, [u8; 32]);
    fn handle(&mut self, ct: S) {
        let le = ct.to_le_bytes();
        self.hasher.update(le);
        self.entries.push(le);
    }
    fn finalize(self) -> Self::Result {
        (self.entries, self.hasher.finalize().into())
    }
}

struct SliceCiphertextSource<'a> {
    entries: &'a [[u8; 16]],
    cursor: usize,
}
impl CiphertextSource for SliceCiphertextSource<'_> {
    type Result = usize;
    fn recv(&mut self) -> Option<S> {
        let bytes = self.entries.get(self.cursor)?;
        self.cursor += 1;
        Some(S::from_le_bytes(*bytes))
    }
    fn finalize(self) -> Self::Result {
        self.cursor
    }
}

struct GarbledInstanceMaterial {
    header: InstanceHeader,
    ciphertexts: Vec<[u8; 16]>,
    tap_hashlocks: Vec<([u8; 32], [u8; 32])>,
    delta: u128,
    input_wires: Vec<(S, S)>,
    blindings: Vec<(F, F)>,
}

fn garble_single_instance<P: DisputeProgram>(
    session_id: &[u8; 32],
    spec: &P,
    index: usize,
    seed: [u8; 32],
) -> GarbledInstanceMaterial {
    let mode = GarbleMode::<AesCcrGateHasher, _>::new_with_seed(
        GARBLE_CAPACITY,
        seed,
        VecCiphertextSink::default(),
    );
    let public_salt = mode.gate_hasher_seed().to_le_bytes();
    let res: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::run_streaming(GInput(spec.input_bits()), mode, |c, w| spec.eval(c, w));
    assert_eq!(res.output_value.len(), 1);
    let (ciphertexts, ciphertext_sha256) = res.ciphertext_handler_result;

    let input_wires: Vec<(S, S)> = res
        .input_wire_values
        .iter()
        .map(|gw| (gw.label0, gw.label1))
        .collect();
    let delta = (input_wires[0].0 ^ &input_wires[0].1).to_u128();
    let tap_hashlocks: Vec<([u8; 32], [u8; 32])> = input_wires
        .iter()
        .map(|&(l0, l1)| (tap_label_sha256(l0), tap_label_sha256(l1)))
        .collect();
    let tap_root = compute_base_tap_root(session_id, &spec.circuit_id(), index, &tap_hashlocks);

    let blindings = derive_wire_blindings(&seed, index, spec.input_bits());
    let pos_root = compute_pos_instance_root(
        session_id,
        &spec.circuit_id(),
        index,
        &input_wires,
        &blindings,
    );

    let out_wire = &res.output_value[0];
    // The zero label means this opening supplied no authenticated refutation.
    let accept_output_sha256 = tap_label_sha256(out_wire.select(false));
    let refute_output_sha256 = tap_label_sha256(out_wire.select(true));

    let header = InstanceHeader {
        index,
        public_salt,
        true_label: res.true_wire_constant.select(true).to_le_bytes(),
        false_label: res.false_wire_constant.select(false).to_le_bytes(),
        ciphertext_count: ciphertexts.len() as u64,
        ciphertext_sha256,
        tap_commitment_root: f_to_le(&tap_root),
        pos_commitment_root: f_to_le(&pos_root),
        accept_output_sha256,
        refute_output_sha256,
    };

    GarbledInstanceMaterial {
        header,
        ciphertexts,
        tap_hashlocks,
        delta,
        input_wires,
        blindings,
    }
}

pub fn hash_input_bits(bits: &[bool]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"babe-pilot/input-bits/v1\0");
    h.update((bits.len() as u64).to_le_bytes());
    for chunk in bits.chunks(8) {
        let byte = chunk
            .iter()
            .enumerate()
            .fold(0u8, |acc, (i, &b)| acc | (u8::from(b) << i));
        h.update([byte]);
    }
    h.finalize().into()
}

// ============================================================================================
// Garbler Session (Private State Isolated; Master Seeds Zeroized on Drop)
// ============================================================================================

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GarblerSession<P = IndexedDisputeSpec> {
    session_id: [u8; 32],
    #[zeroize(skip)]
    spec: P,
    seeds: [[u8; 32]; PILOT_TOTAL_INSTANCES],
    #[zeroize(skip)]
    instances: Vec<GarbledInstanceMaterial>,
    released_input: Option<[u8; 32]>,
    challenge_nonce: Option<[u8; 32]>,
    finalized: bool,
}

impl<P: DisputeProgram> GarblerSession<P> {
    pub fn setup(session_id: [u8; 32], spec: P, master_rng_seed: [u8; 32]) -> Self {
        spec.validate()
            .expect("setup requires a canonical independently selected program");
        assert!(
            spec.input_bits() > 0 && spec.input_bits().is_multiple_of(2),
            "soldering requires a positive even input width"
        );
        let mut rng = ChaCha20Rng::from_seed(master_rng_seed);
        let seeds: [[u8; 32]; PILOT_TOTAL_INSTANCES] = std::array::from_fn(|_| {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            s
        });
        let instances: Vec<GarbledInstanceMaterial> = (0..PILOT_TOTAL_INSTANCES)
            .map(|k| garble_single_instance(&session_id, &spec, k, seeds[k]))
            .collect();
        Self {
            session_id,
            spec,
            seeds,
            instances,
            released_input: None,
            challenge_nonce: None,
            finalized: false,
        }
    }

    pub fn pre_challenge_manifest(&self) -> PreChallengeManifest<P> {
        PreChallengeManifest {
            session_id: self.session_id,
            spec: self.spec.clone(),
            num_wires: self.spec.input_bits(),
            headers: self.instances.iter().map(|m| m.header.clone()).collect(),
        }
    }

    /// Restore process guards only after the durable wrapper has checked its
    /// independent head and verified the saved public artifact, when present.
    pub(crate) fn restore_guards(&mut self, saved: &crate::journal::JournalSnapshot) -> Result<()> {
        ensure!(
            self.challenge_nonce.is_none() && !self.finalized && self.released_input.is_none(),
            "session already active"
        );
        let manifest = self.pre_challenge_manifest();
        ensure!(
            saved.pins.session_id == self.session_id,
            "journal session mismatch"
        );
        ensure!(
            saved.pins.circuit_id == self.spec.circuit_id(),
            "journal circuit mismatch"
        );
        ensure!(
            saved.pins.commit1 == manifest.commit1_digest()?,
            "journal setup mismatch"
        );
        self.challenge_nonce = saved.nonce;
        self.finalized = saved.finalized_setup_sha256.is_some();
        self.released_input = saved.input_sha256;
        Ok(())
    }

    pub(crate) fn mark_recovered_finalized(&mut self, nonce: [u8; 32]) -> Result<()> {
        ensure!(
            self.challenge_nonce.is_none_or(|saved| saved == nonce),
            "recovered nonce mismatch"
        );
        self.challenge_nonce = Some(nonce);
        self.finalized = true;
        Ok(())
    }

    /// Adversarial test hook: corrupts the Half-Gates ciphertext table of `instance_idx` *prior*
    /// to publishing `Commit_1`, modelling a malicious garbler who attempts to slip corrupted
    /// circuits past Cut-and-Choose while keeping input-wire soldering commitments valid.
    pub fn corrupt_ciphertext_before_commit1(&mut self, instance_idx: usize) {
        assert!(self.challenge_nonce.is_none(), "setup already challenged");
        let inst = &mut self.instances[instance_idx];
        let mut h = Sha256::new();
        for entry in &mut inst.ciphertexts {
            entry[0] ^= 0xff;
            h.update(*entry);
        }
        inst.header.ciphertext_sha256 = h.finalize().into();
    }

    /// Responds to challenger randomness `nonce` by opening `N - M` seeds and proving `R_solder` in ZK.
    pub fn finalize_cut_and_choose(
        &mut self,
        nonce: [u8; 32],
    ) -> Result<(FinalizedPublicSetup<P>, SolderingTimings)> {
        // Reserve before proving so a failed attempt cannot open another partition.
        // Persistence across process restarts belongs to the enclosing protocol.
        if let Some(pinned) = self.challenge_nonce {
            ensure!(
                pinned == nonce,
                "session already bound to another challenger nonce"
            );
        } else {
            self.challenge_nonce = Some(nonce);
        }
        let manifest = self.pre_challenge_manifest();
        let commit1 = manifest.commit1_digest()?;
        let part = CutAndChoosePartition::derive(commit1, nonce);

        let opened_seeds: [([u8; 32], usize); PILOT_OPENED_INSTANCES] = std::array::from_fn(|i| {
            let idx = part.opened_indices[i];
            (self.seeds[idx], idx)
        });

        let b = part.base_index;
        let sj = part.soldered_indices;

        let secret = GarblerSolderingSecret {
            base_delta: self.instances[b].delta,
            base_labels0: self.instances[b]
                .input_wires
                .iter()
                .map(|w| w.0.to_u128())
                .collect(),
            soldered_deltas: std::array::from_fn(|m| self.instances[sj[m]].delta),
            soldered_labels0: (0..self.spec.input_bits())
                .map(|i| std::array::from_fn(|m| self.instances[sj[m]].input_wires[i].0.to_u128()))
                .collect(),
            soldered_blindings: std::array::from_fn(|m| self.instances[sj[m]].blindings.clone()),
        };

        let (certificate, timings) = prove_soldering_certificate(
            &self.session_id,
            &self.spec.circuit_id(),
            &nonce,
            b,
            sj,
            &secret,
        )?;

        let retained_indices = part.retained_indices();
        let retained_ciphertexts: [Vec<[u8; 16]>; PILOT_RETAINED_INSTANCES] =
            std::array::from_fn(|r_slot| {
                self.instances[retained_indices[r_slot]].ciphertexts.clone()
            });

        self.finalized = true;
        Ok((
            FinalizedPublicSetup {
                manifest,
                nonce,
                opened_seeds,
                base_tap_hashlocks: self.instances[b].tap_hashlocks.clone(),
                retained_ciphertexts,
                certificate,
            },
            timings,
        ))
    }

    /// Single-use active base label release: refuses to release labels for two distinct inputs on the same setup.
    pub fn release_active_base_labels(
        &mut self,
        nonce: [u8; 32],
        input_bits: &[bool],
    ) -> Result<ActiveBaseLabelDelivery> {
        ensure!(self.finalized, "session has no finalized public setup");
        ensure!(
            self.challenge_nonce == Some(nonce),
            "challenger nonce mismatch"
        );
        ensure!(
            input_bits.len() == self.spec.input_bits(),
            "input bit count mismatch"
        );
        let input_hash = hash_input_bits(input_bits);
        if let Some(prev) = self.released_input {
            ensure!(
                prev == input_hash,
                "single-use violation: base instance already released labels for another input"
            );
        } else {
            self.released_input = Some(input_hash);
        }

        let commit1 = self.pre_challenge_manifest().commit1_digest()?;
        let part = CutAndChoosePartition::derive(commit1, nonce);
        let b = part.base_index;
        let active_labels: Vec<[u8; 16]> = self.instances[b]
            .input_wires
            .iter()
            .zip(input_bits)
            .map(|(&(l0, l1), &bit)| (if bit { l1 } else { l0 }).to_le_bytes())
            .collect();

        Ok(ActiveBaseLabelDelivery {
            session_id: self.session_id,
            input_sha256: input_hash,
            base_index: b,
            active_labels,
        })
    }
}

// ============================================================================================
// Stateless Challenger / Evaluator Verification & Unsoldering Pipeline
// ============================================================================================

/// Independently verifies the entire finalized setup (`Commit_1`, `N - M` opened C&C seeds,
/// retained ciphertext SHA-256 commitments, base `OP_SHA256` hashlock table, and ZK `CompressedSNARK`).
pub fn verify_public_setup<'a, P: DisputeProgram>(
    expected_session_id: &[u8; 32],
    expected_spec: &P,
    expected_commit1: &[u8; 32],
    expected_nonce: &[u8; 32],
    setup: &'a FinalizedPublicSetup<P>,
) -> Result<VerifiedPublicSetup<'a, P>> {
    ensure!(
        &setup.manifest.session_id == expected_session_id,
        "session ID mismatch (replay rejected)"
    );
    ensure!(
        &setup.manifest.spec == expected_spec,
        "circuit specification mismatch (substituted circuit rejected)"
    );
    ensure!(
        setup.manifest.num_wires == expected_spec.input_bits(),
        "manifest wire count mismatch"
    );
    ensure!(
        setup.manifest.headers.len() == PILOT_TOTAL_INSTANCES,
        "manifest header count mismatch"
    );
    ensure!(&setup.nonce == expected_nonce, "challenger nonce mismatch");
    expected_spec.validate()?;

    for (idx, hdr) in setup.manifest.headers.iter().enumerate() {
        ensure!(hdr.index == idx, "non-sequential header index");
        ensure!(
            hdr.accept_output_sha256 != hdr.reject_or_refute_alias(),
            "degenerate coinciding output label commitments"
        );
    }

    let commit1 = setup.manifest.commit1_digest()?;
    ensure!(
        &commit1 == expected_commit1,
        "pre-challenge commitment mismatch"
    );
    let part = CutAndChoosePartition::derive(commit1, setup.nonce);

    // 1. Deterministically regarble all N - M opened instances from their seeds and verify exact header match!
    for (slot, &(seed, idx)) in setup.opened_seeds.iter().enumerate() {
        ensure!(
            idx == part.opened_indices[slot],
            "opened seed index {idx} does not match C&C partition"
        );
        let regarbled = garble_single_instance(expected_session_id, expected_spec, idx, seed);
        ensure!(
            regarbled.header == setup.manifest.headers[idx],
            "Cut-and-Choose check failed: opened instance {idx} diverges from Commit_1 header"
        );
        ensure!(
            setup
                .manifest
                .headers
                .iter()
                .all(|h| h.ciphertext_count == regarbled.header.ciphertext_count),
            "ciphertext count differs from the pinned circuit shape"
        );
    }

    // 2. Verify retained ciphertext streams match Commit_1 SHA-256 digests & counts.
    let retained_indices = part.retained_indices();
    for (r_slot, &inst_idx) in retained_indices.iter().enumerate() {
        let hdr = &setup.manifest.headers[inst_idx];
        let cts = &setup.retained_ciphertexts[r_slot];
        ensure!(
            cts.len() as u64 == hdr.ciphertext_count,
            "retained ciphertext count mismatch at instance {inst_idx}"
        );
        let mut h = Sha256::new();
        for entry in cts {
            h.update(entry);
        }
        let got_sha: [u8; 32] = h.finalize().into();
        ensure!(
            got_sha == hdr.ciphertext_sha256,
            "retained ciphertext SHA-256 mismatch at instance {inst_idx}"
        );
    }

    // 3. Verify base Tapscript SHA-256 hashlock table folds to Commit_1's `tap_commitment_root[b]`.
    ensure!(
        setup.base_tap_hashlocks.len() == expected_spec.input_bits(),
        "base Tapscript hashlock count mismatch"
    );
    let b = part.base_index;
    let expected_base_tap_root = f_from_canonical(&setup.manifest.headers[b].tap_commitment_root)?;
    let recomputed_tap_root = compute_base_tap_root(
        expected_session_id,
        &expected_spec.circuit_id(),
        b,
        &setup.base_tap_hashlocks,
    );
    ensure!(
        recomputed_tap_root == expected_base_tap_root,
        "base Tapscript hashlocks do not match Commit_1 tap_commitment_root"
    );

    // 4. Verify transparent zero-knowledge Nova/Spartan CompressedSNARK soldering certificate!
    let expected_soldered_pos_roots: [F; PILOT_SOLDERED_INSTANCES] = std::array::from_fn(|m| {
        f_from_canonical(&setup.manifest.headers[part.soldered_indices[m]].pos_commitment_root)
            .unwrap_or(F::ZERO)
    });
    for m in 0..PILOT_SOLDERED_INSTANCES {
        let _ = f_from_canonical(
            &setup.manifest.headers[part.soldered_indices[m]].pos_commitment_root,
        )?;
    }

    let snark_verify_seconds = verify_soldering_certificate(
        expected_session_id,
        &expected_spec.circuit_id(),
        expected_nonce,
        b,
        part.soldered_indices,
        expected_spec.input_bits(),
        expected_base_tap_root,
        expected_soldered_pos_roots,
        &setup.certificate,
    )?;
    Ok(VerifiedPublicSetup {
        setup,
        partition: part,
        snark_verify_seconds,
    })
}

impl InstanceHeader {
    fn reject_or_refute_alias(&self) -> [u8; 32] {
        self.refute_output_sha256
    }
}

/// Verifies `CheckLampSigsMatch` on the delivered base active labels against `setup.base_tap_hashlocks`.
pub fn verify_active_base_labels<P: DisputeProgram>(
    verified: &VerifiedPublicSetup<'_, P>,
    input_bits: &[bool],
    delivery: &ActiveBaseLabelDelivery,
) -> Result<Vec<S>> {
    let setup = verified.setup;
    ensure!(
        delivery.session_id == setup.manifest.session_id,
        "active label delivery session mismatch"
    );
    ensure!(
        delivery.base_index == setup.certificate.base_index,
        "active label delivery base index mismatch"
    );
    ensure!(
        input_bits.len() == setup.manifest.num_wires
            && delivery.active_labels.len() == setup.manifest.num_wires,
        "active label count mismatch"
    );
    ensure!(
        delivery.input_sha256 == hash_input_bits(input_bits),
        "active label delivery input digest mismatch"
    );

    let mut out = Vec::with_capacity(setup.manifest.num_wires);
    for (i, (&raw_lbl, &bit)) in delivery.active_labels.iter().zip(input_bits).enumerate() {
        let lbl = S::from_le_bytes(raw_lbl);
        let got_hash = tap_label_sha256(lbl);
        let expected_hash = if bit {
            setup.base_tap_hashlocks[i].1
        } else {
            setup.base_tap_hashlocks[i].0
        };
        ensure!(
            got_hash == expected_hash,
            "CheckLampSigsMatch failed at wire {i} for bit {bit}"
        );
        out.push(lbl);
    }
    Ok(out)
}

/// Evaluates all `M` retained garbled circuits using ONLY verified public artifacts + active base labels.
pub fn evaluate_retained_instances<P: DisputeProgram>(
    verified: &VerifiedPublicSetup<'_, P>,
    input_bits: &[bool],
    delivery: &ActiveBaseLabelDelivery,
) -> Result<[InstanceVerdict; PILOT_RETAINED_INSTANCES]> {
    let base_labels = verify_active_base_labels(verified, input_bits, delivery)?;
    evaluate_with_verified_labels(verified, input_bits, base_labels)
}

fn evaluate_with_verified_labels<P: DisputeProgram>(
    verified: &VerifiedPublicSetup<'_, P>,
    input_bits: &[bool],
    base_labels: Vec<S>,
) -> Result<[InstanceVerdict; PILOT_RETAINED_INSTANCES]> {
    let setup = verified.setup;
    let retained_indices = verified.partition.retained_indices();

    let mut verdicts = Vec::with_capacity(PILOT_RETAINED_INSTANCES);
    for (r_slot, &inst_idx) in retained_indices.iter().enumerate() {
        let active_for_inst: Vec<S> = if r_slot == 0 {
            base_labels.clone()
        } else {
            unsolder_active_labels(&base_labels, input_bits, &setup.certificate, r_slot - 1)?
        };
        let hdr = &setup.manifest.headers[inst_idx];
        let cts = &setup.retained_ciphertexts[r_slot];
        let evaluated: StreamingResult<_, _, Vec<EvaluatedWire>> =
            CircuitBuilder::streaming_evaluation(
                EInput {
                    labels: &active_for_inst,
                    bits: input_bits,
                },
                GARBLE_CAPACITY,
                u128::from_le_bytes(hdr.true_label),
                u128::from_le_bytes(hdr.false_label),
                AesCcrGateHasher::from_seed(S::from_le_bytes(hdr.public_salt)),
                SliceCiphertextSource {
                    entries: cts,
                    cursor: 0,
                },
                |c, w| setup.manifest.spec.eval(c, w),
            );
        ensure!(
            evaluated.ciphertext_handler_result == cts.len(),
            "evaluator did not consume full ciphertext stream at instance {inst_idx}"
        );
        let out_lbl = evaluated.output_value[0].active_label;
        let out_bytes = out_lbl.to_le_bytes();
        let out_sha = tap_label_sha256(out_lbl);
        if out_sha == hdr.accept_output_sha256 {
            verdicts.push(InstanceVerdict::NoRefutation {
                output_label: out_bytes,
            });
        } else if out_sha == hdr.refute_output_sha256 {
            verdicts.push(InstanceVerdict::Refute {
                output_label: out_bytes,
            });
        } else {
            // Note: Under malicious-garbler testing where M-1 retained tables were tampered with
            // after setup or built dishonestly, a bad retained instance yields a garbage output label
            // while ANY 1 honest retained instance still yields its authentic `Refute` preimage!
            verdicts.push(InstanceVerdict::CorruptedOutput {
                raw_label: out_bytes,
            });
        }
    }
    Ok(verdicts.try_into().expect("PILOT_RETAINED_INSTANCES"))
}

/// Complete challenger dispute resolution with 1-of-`M` fault tolerance and withholding recovery.
pub fn resolve_dispute<P: DisputeProgram>(
    verified: &VerifiedPublicSetup<'_, P>,
    input_bits: &[bool],
    maybe_delivery: Option<&ActiveBaseLabelDelivery>,
) -> Result<DisputeResolution> {
    ensure!(
        input_bits.len() == verified.setup.manifest.num_wires,
        "input bit count mismatch"
    );
    let Some(delivery) = maybe_delivery else {
        return Ok(DisputeResolution::AwaitingWithholdingTimeout {
            reason: "active base labels unavailable; CSV deadline requires chain observation"
                .into(),
        });
    };

    let base_labels = match verify_active_base_labels(verified, input_bits, delivery) {
        Ok(labels) => labels,
        Err(err) => {
            return Ok(DisputeResolution::AwaitingWithholdingTimeout {
                reason: format!(
                    "invalid active labels; CSV deadline requires chain observation: {err}"
                ),
            });
        }
    };
    let verdicts = evaluate_with_verified_labels(verified, input_bits, base_labels)?;
    resolve_verdicts(verified, &verdicts)
}

fn resolve_verdicts<P: DisputeProgram>(
    verified: &VerifiedPublicSetup<'_, P>,
    verdicts: &[InstanceVerdict; PILOT_RETAINED_INSTANCES],
) -> Result<DisputeResolution> {
    let setup = verified.setup;
    let retained_indices = verified.partition.retained_indices();

    for (r_slot, verdict) in verdicts.iter().enumerate() {
        if let InstanceVerdict::Refute { output_label } = verdict {
            let inst_idx = retained_indices[r_slot];
            return Ok(DisputeResolution::AuthenticatedRefutation {
                winning_instance_index: inst_idx,
                refute_preimage: *output_label,
                refute_sha256: setup.manifest.headers[inst_idx].refute_output_sha256,
            });
        }
    }

    ensure!(
        verdicts
            .iter()
            .any(|v| matches!(v, InstanceVerdict::NoRefutation { .. })),
        "inconclusive dispute: every retained circuit produced an unauthenticated output"
    );
    Ok(DisputeResolution::NoAuthenticatedRefutation)
}
