//! Phase 3 Acceptance & Adversarial Test Suite for the BABE-Inspired Transparent Nova Pilot.
//!
//! Shares one valid `(N=7, M=3)` Cut-and-Choose + `CompressedSNARK` soldering fixture across
//! mutation/adversarial checks so the entire suite runs fast on ordinary CPU CI runners.

use std::sync::OnceLock;

use babe_pilot::{
    bitcoin_script::measure_pilot_bitcoin_paths,
    dispute_circuit::IndexedDisputeSpec,
    protocol::{
        evaluate_retained_instances, resolve_dispute, verify_public_setup, CutAndChoosePartition,
        DisputeResolution, FinalizedPublicSetup, GarblerSession, InstanceVerdict,
        PILOT_RETAINED_INSTANCES,
    },
};
use sha2::{Digest, Sha256};

struct SharedSessionFixture {
    session_id: [u8; 32],
    nonce: [u8; 32],
    commit1: [u8; 32],
    spec: IndexedDisputeSpec,
    public_setup: FinalizedPublicSetup,
    honest_slot3_bits: Vec<bool>,
    honest_slot3_delivery: babe_pilot::protocol::ActiveBaseLabelDelivery,
    dishonest_slot5_bits: Vec<bool>,
}

fn shared_fixture() -> &'static SharedSessionFixture {
    static FIXTURE: OnceLock<SharedSessionFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let claim_id = [0xa5u8; 32];
        let (mut spec, honest_inputs) = IndexedDisputeSpec::sample_honest_trace(claim_id);

        let mut bad_inp = honest_inputs[5].clone();
        bad_inp.s_out ^= 1;
        spec.commit_step(&bad_inp); // operator commits the invalid slot before setup
        assert!(spec.native_refutes(&bad_inp));
        let dishonest_slot5_bits = bad_inp.to_bits();

        // Session A: honest dispute input at slot 3 (`native_refutes == false` -> `Accept`).
        let session_id = [0x11u8; 32];
        let nonce = [0x22u8; 32];
        let mut garbler_a = GarblerSession::setup(session_id, spec.clone(), [0x77u8; 32]);
        let commit1 = garbler_a.pre_challenge_manifest().commit1_digest().unwrap();
        let (public_setup, _timings) = garbler_a
            .finalize_cut_and_choose(nonce)
            .expect("finalize honest C&C + CompressedSNARK soldering");
        let honest_slot3_bits = honest_inputs[3].to_bits();
        let honest_slot3_delivery = garbler_a
            .release_active_base_labels(nonce, &honest_slot3_bits)
            .expect("release active base labels for honest slot 3");
        // Drop `garbler_a` here so the evaluator tests have no access to private garbler state.
        drop(garbler_a);

        SharedSessionFixture {
            session_id,
            nonce,
            commit1,
            spec,
            public_setup,
            honest_slot3_bits,
            honest_slot3_delivery,
            dishonest_slot5_bits,
        }
    })
}

#[test]
fn e2e_honest_accept_and_dishonest_refute_across_all_retained_instances() {
    let fx = shared_fixture();

    // 1. Independent verification of public setup + ZK CompressedSNARK certificate:
    let verified = verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &fx.public_setup,
    )
    .expect("independent verification of public setup + CompressedSNARK");
    assert!(verified.snark_verify_seconds() >= 0.0);

    // 2. Evaluator (with zero private garbler state) evaluates all M=3 retained instances on honest input:
    let verdicts =
        evaluate_retained_instances(&verified, &fx.honest_slot3_bits, &fx.honest_slot3_delivery)
            .expect("evaluate all M retained instances");
    for (slot, v) in verdicts.iter().enumerate() {
        assert!(
            matches!(v, InstanceVerdict::NoRefutation { .. }),
            "retained slot {slot} did not accept honest input: {v:?}"
        );
    }
    assert_eq!(
        resolve_dispute(
            &verified,
            &fx.honest_slot3_bits,
            Some(&fx.honest_slot3_delivery),
        )
        .unwrap(),
        DisputeResolution::NoAuthenticatedRefutation
    );

    // 3. Fresh session on a dishonest claim input produces `Refute` across all M=3 retained instances
    //    and measures serialized Bitcoin Taproot witness sizes.
    let session_b = [0x33u8; 32];
    let nonce_b = [0x44u8; 32];
    let mut garbler_b = GarblerSession::setup(session_b, fx.spec.clone(), [0x88u8; 32]);
    let commit1_b = garbler_b.pre_challenge_manifest().commit1_digest().unwrap();
    let (setup_b, _) = garbler_b.finalize_cut_and_choose(nonce_b).unwrap();
    let mut other_nonce = nonce_b;
    other_nonce[0] ^= 1;
    assert!(garbler_b.finalize_cut_and_choose(other_nonce).is_err());
    assert!(garbler_b
        .release_active_base_labels(other_nonce, &fx.dishonest_slot5_bits)
        .is_err());
    let delivery_b = garbler_b
        .release_active_base_labels(nonce_b, &fx.dishonest_slot5_bits)
        .unwrap();
    // Single-use enforcement: idempotent retry for same input succeeds; second distinct input is refused!
    assert_eq!(
        garbler_b
            .release_active_base_labels(nonce_b, &fx.dishonest_slot5_bits)
            .unwrap(),
        delivery_b
    );
    assert!(garbler_b
        .release_active_base_labels(nonce_b, &fx.honest_slot3_bits)
        .is_err());
    drop(garbler_b);

    let verified_b =
        verify_public_setup(&session_b, &fx.spec, &commit1_b, &nonce_b, &setup_b).unwrap();
    let bad_verdicts =
        evaluate_retained_instances(&verified_b, &fx.dishonest_slot5_bits, &delivery_b).unwrap();
    for (slot, v) in bad_verdicts.iter().enumerate() {
        assert!(
            matches!(v, InstanceVerdict::Refute { .. }),
            "retained slot {slot} failed to refute invalid input: {v:?}"
        );
    }

    let resolution =
        resolve_dispute(&verified_b, &fx.dishonest_slot5_bits, Some(&delivery_b)).unwrap();
    let (win_inst, preimage, sha) = match resolution {
        DisputeResolution::AuthenticatedRefutation {
            winning_instance_index,
            refute_preimage,
            refute_sha256,
        } => (winning_instance_index, refute_preimage, refute_sha256),
        other => panic!("expected AuthenticatedRefutation, got {other:?}"),
    };
    assert_eq!(<[u8; 32]>::from(Sha256::digest(preimage)), sha);

    let part_b = CutAndChoosePartition::derive(commit1_b, nonce_b);
    let retained = part_b.retained_indices();
    let win_slot = retained.iter().position(|&idx| idx == win_inst).unwrap();
    let refute_hashes: Vec<[u8; 32]> = retained
        .iter()
        .map(|&idx| setup_b.manifest.headers[idx].refute_output_sha256)
        .collect();

    let btc = measure_pilot_bitcoin_paths(
        &setup_b.base_tap_hashlocks,
        &fx.dishonest_slot5_bits,
        &delivery_b.active_labels,
        &refute_hashes,
        win_slot,
        &preimage,
    )
    .expect("serialized Taproot dispute samples");
    assert!(
        btc.assert_labels_tx
            .initial_stack_items_within_policy_bounds
    );
    assert!(btc.disprove_tx.initial_stack_items_within_policy_bounds);
    assert!(
        btc.withholding_timeout_tx
            .initial_stack_items_within_policy_bounds
    );
    assert!(btc.disprove_tx.vsize < 250);
    assert!(!btc.assert_labels_tx.consensus_verified);
    assert!(!btc.assert_labels_tx.standardness_verified);
}

#[test]
fn rejects_inconsistent_soldering_mappings_and_altered_commitments() {
    let fx = shared_fixture();

    // 1. Mutate a wire translation delta S_{j_m, i}:
    let mut bad_wire_delta = fx.public_setup.clone();
    bad_wire_delta.certificate.wire_deltas[17][0] ^= 1;
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &bad_wire_delta
    )
    .is_err());

    // 2. Mutate a global instance offset translation Gamma_m:
    let mut bad_gamma = fx.public_setup.clone();
    bad_gamma.certificate.gammas[1] ^= 1;
    assert!(
        verify_public_setup(&fx.session_id, &fx.spec, &fx.commit1, &fx.nonce, &bad_gamma).is_err()
    );

    // 3. Alter a base Tapscript SHA-256 hashlock in `base_tap_hashlocks`:
    let mut bad_tap_lock = fx.public_setup.clone();
    bad_tap_lock.base_tap_hashlocks[0].0[0] ^= 1;
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &bad_tap_lock
    )
    .is_err());

    // 4. Alter a soldered Poseidon commitment root in `Commit_1` header (and recompute opened indices?
    //    Even if altered in the header or certificate, verification fails):
    let mut bad_pos_root = fx.public_setup.clone();
    let sj0 = bad_pos_root.certificate.soldered_indices[0];
    bad_pos_root.manifest.headers[sj0].pos_commitment_root[0] ^= 1;
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &bad_pos_root
    )
    .is_err());
}

#[test]
fn rejects_substituted_circuit_id_and_replayed_session_or_nonce() {
    let fx = shared_fixture();
    let mut substituted_commitment = fx.commit1;
    substituted_commitment[7] ^= 1;
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &substituted_commitment,
        &fx.nonce,
        &fx.public_setup
    )
    .unwrap_err()
    .to_string()
    .contains("pre-challenge commitment mismatch"));

    // 1. Replay under another session_id:
    let mut other_session = fx.session_id;
    other_session[0] ^= 1;
    assert!(verify_public_setup(
        &other_session,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &fx.public_setup
    )
    .is_err());

    // 2. Replay under another challenger nonce:
    let mut other_nonce = fx.nonce;
    other_nonce[31] ^= 1;
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &other_nonce,
        &fx.public_setup
    )
    .is_err());

    // 3. Substitute circuit identity / pinned statement:
    let (other_spec, _) = IndexedDisputeSpec::sample_honest_trace([0xfe; 32]);
    assert!(verify_public_setup(
        &fx.session_id,
        &other_spec,
        &fx.commit1,
        &fx.nonce,
        &fx.public_setup
    )
    .is_err());

    // Even if an attacker rewrites `setup.manifest.session_id` and `nonce` to match the new session,
    // the ZK `CompressedSNARK` binding_tag inside `z0` rejects the replayed proof!
    let mut forged_replay = fx.public_setup.clone();
    forged_replay.manifest.session_id = other_session;
    assert!(verify_public_setup(
        &other_session,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &forged_replay
    )
    .is_err());
}

#[test]
fn malicious_garbler_corrupting_m_minus_one_retained_circuits_still_gets_slashed() {
    let fx = shared_fixture();

    // Malicious garbler corrupts M - 1 = 2 instances (indices 0 and 1) BEFORE publishing `Commit_1`!
    let session_m = [0x99u8; 32];
    let mut garbler = GarblerSession::setup(session_m, fx.spec.clone(), [0x55u8; 32]);
    garbler.corrupt_ciphertext_before_commit1(0);
    garbler.corrupt_ciphertext_before_commit1(1);

    let commit1 = garbler.pre_challenge_manifest().commit1_digest().unwrap();

    // First verify that if a challenger nonce opens either corrupted instance (0 or 1), `verify_public_setup`
    // would fail C&C inspection; then test the worst-case C&C evasion event (probability C(5,4)/C(7,4) = 1/7)
    // where BOTH corrupted instances 0 and 1 land in the retained set R!
    let mut lucky_nonce = [0u8; 32];
    for counter in 0u64..1_000 {
        lucky_nonce[..8].copy_from_slice(&counter.to_le_bytes());
        let part = CutAndChoosePartition::derive(commit1, lucky_nonce);
        let r = part.retained_indices();
        if r.contains(&0) && r.contains(&1) {
            break;
        }
    }
    let part = CutAndChoosePartition::derive(commit1, lucky_nonce);
    let retained = part.retained_indices();
    assert_eq!(&retained[..2], &[0, 1]);
    let honest_inst = retained[2];

    let (setup, _) = garbler.finalize_cut_and_choose(lucky_nonce).unwrap();
    let delivery = garbler
        .release_active_base_labels(lucky_nonce, &fx.dishonest_slot5_bits)
        .unwrap();
    drop(garbler);

    // The deliberately selected test nonce leaves one honest retained circuit. Every setup check (`Commit_1`, all 4 opened C&C seeds, AND ZK `CompressedSNARK`) PASSES!
    let verified_m = verify_public_setup(&session_m, &fx.spec, &commit1, &lucky_nonce, &setup)
        .expect("lucky malicious garbler evades C&C opening and proves valid input soldering");

    // Yet during evaluation, slots 0 and 1 yield garbage while the 1 honest retained instance (`slot 2`)
    // yields the authentic `Refute` preimage for the local dispute result.
    let verdicts =
        evaluate_retained_instances(&verified_m, &fx.dishonest_slot5_bits, &delivery).unwrap();
    assert_eq!(verdicts.len(), PILOT_RETAINED_INSTANCES);
    assert!(matches!(
        verdicts[0],
        InstanceVerdict::CorruptedOutput { .. }
    ));
    assert!(matches!(
        verdicts[1],
        InstanceVerdict::CorruptedOutput { .. }
    ));
    assert!(matches!(verdicts[2], InstanceVerdict::Refute { .. }));

    let resolution =
        resolve_dispute(&verified_m, &fx.dishonest_slot5_bits, Some(&delivery)).unwrap();
    assert!(matches!(
        resolution,
        DisputeResolution::AuthenticatedRefutation {
            winning_instance_index,
            ..
        } if winning_instance_index == honest_inst
    ));
}

#[test]
fn adversarial_withholding_opened_seed_tampering_and_malformed_artifacts() {
    let fx = shared_fixture();

    // 1. Complete withholding of active base labels -> AwaitingWithholdingTimeout:
    let verified = verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &fx.public_setup,
    )
    .unwrap();
    let withheld = resolve_dispute(&verified, &fx.honest_slot3_bits, None).unwrap();
    assert!(matches!(
        withheld,
        DisputeResolution::AwaitingWithholdingTimeout { .. }
    ));

    // 2. Equivocated/corrupted active base label -> rejected by CheckLampSigsMatch -> Timeout slash:
    let mut bad_delivery = fx.honest_slot3_delivery.clone();
    bad_delivery.active_labels[5][0] ^= 1;
    let equivocated =
        resolve_dispute(&verified, &fx.honest_slot3_bits, Some(&bad_delivery)).unwrap();
    assert!(matches!(
        equivocated,
        DisputeResolution::AwaitingWithholdingTimeout { .. }
    ));

    // 3. Corrupted opened Cut-and-Choose seed -> caught during Phase 1 inspection:
    let mut bad_seed_setup = fx.public_setup.clone();
    bad_seed_setup.opened_seeds[0].0[0] ^= 1;
    let err = verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &bad_seed_setup,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("Cut-and-Choose"), "{err}");

    // 4. Truncated / corrupted retained ciphertext stream -> rejected before evaluation:
    let mut truncated_ct = fx.public_setup.clone();
    truncated_ct.retained_ciphertexts[1].pop();
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &truncated_ct
    )
    .is_err());

    let mut flipped_ct = fx.public_setup.clone();
    flipped_ct.retained_ciphertexts[2][10][0] ^= 1;
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &flipped_ct
    )
    .is_err());

    // Appended bytes and impossible vector lengths are rejected at the proof decoder boundary.
    let mut trailing_snark = fx.public_setup.clone();
    trailing_snark.certificate.compressed_snark_bytes.push(0);
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &trailing_snark
    )
    .unwrap_err()
    .to_string()
    .contains("trailing bytes"));
    let mut huge_vec_snark = fx.public_setup.clone();
    huge_vec_snark.certificate.compressed_snark_bytes[96..104]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(verify_public_setup(
        &fx.session_id,
        &fx.spec,
        &fx.commit1,
        &fx.nonce,
        &huge_vec_snark
    )
    .is_err());

    // Malformed / truncated CompressedSNARK bytes -> clean error without panic:
    let mut bad_snark = fx.public_setup.clone();
    bad_snark.certificate.compressed_snark_bytes.truncate(32);
    assert!(
        verify_public_setup(&fx.session_id, &fx.spec, &fx.commit1, &fx.nonce, &bad_snark).is_err()
    );
}
