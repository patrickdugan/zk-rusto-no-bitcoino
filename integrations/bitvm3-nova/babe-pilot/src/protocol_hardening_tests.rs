//! Fast protocol boundary checks. The synthetic fixtures below deliberately contain no
//! proof. They are used only for rejection paths and private verdict classification.
//! Successful public setup verification is covered by the separate end-to-end suite.

use super::*;

fn header(index: usize) -> InstanceHeader {
    InstanceHeader {
        index,
        public_salt: [0; 16],
        true_label: [1; 16],
        false_label: [2; 16],
        ciphertext_count: 0,
        ciphertext_sha256: [0; 32],
        tap_commitment_root: [0; 32],
        pos_commitment_root: [0; 32],
        accept_output_sha256: tap_label_sha256(S::from_le_bytes([3; 16])),
        refute_output_sha256: tap_label_sha256(S::from_le_bytes([4; 16])),
    }
}

fn synthetic_setup() -> FinalizedPublicSetup {
    let (spec, _) = IndexedDisputeSpec::sample_honest_trace([0x5a; 32]);
    let manifest = PreChallengeManifest {
        session_id: [1; 32],
        spec,
        num_wires: PILOT_INPUT_BITS,
        headers: (0..PILOT_TOTAL_INSTANCES).map(header).collect(),
    };
    let nonce = [2; 32];
    let part = CutAndChoosePartition::derive(manifest.commit1_digest().unwrap(), nonce);
    FinalizedPublicSetup {
        manifest,
        nonce,
        opened_seeds: std::array::from_fn(|i| ([0; 32], part.opened_indices[i])),
        base_tap_hashlocks: vec![([0; 32], [1; 32]); PILOT_INPUT_BITS],
        retained_ciphertexts: std::array::from_fn(|_| Vec::new()),
        certificate: SolderingCertificate {
            base_index: part.base_index,
            soldered_indices: part.soldered_indices,
            num_wires: PILOT_INPUT_BITS,
            gammas: [0; PILOT_SOLDERED_INSTANCES],
            wire_deltas: vec![[0; PILOT_SOLDERED_INSTANCES]; PILOT_INPUT_BITS],
            compressed_snark_bytes: Vec::new(),
        },
    }
}

// Private unit-test construction isolates the classification function from proof generation.
// Public callers cannot construct this capability or mutate its borrowed artifacts.
fn classification_only_capability(setup: &FinalizedPublicSetup) -> VerifiedPublicSetup<'_> {
    VerifiedPublicSetup {
        setup,
        partition: CutAndChoosePartition::derive(
            setup.manifest.commit1_digest().unwrap(),
            setup.nonce,
        ),
        snark_verify_seconds: 0.0,
    }
}

fn guard_only_session() -> GarblerSession {
    GarblerSession {
        session_id: [1; 32],
        spec: IndexedDisputeSpec::sample_honest_trace([0x5a; 32]).0,
        seeds: [[0; 32]; PILOT_TOTAL_INSTANCES],
        instances: Vec::new(),
        released_input: None,
        challenge_nonce: None,
        finalized: false,
    }
}

#[test]
fn all_unauthenticated_outputs_are_inconclusive() {
    let setup = synthetic_setup();
    let verified = classification_only_capability(&setup);
    let verdicts = std::array::from_fn(|_| InstanceVerdict::CorruptedOutput { raw_label: [5; 16] });
    let err = resolve_verdicts(&verified, &verdicts).unwrap_err();
    assert!(err.to_string().contains("inconclusive dispute"));
}

#[test]
fn one_no_refutation_among_corrupt_outputs_has_no_slash_result() {
    let setup = synthetic_setup();
    let verified = classification_only_capability(&setup);
    let mut verdicts =
        std::array::from_fn(|_| InstanceVerdict::CorruptedOutput { raw_label: [5; 16] });
    verdicts[1] = InstanceVerdict::NoRefutation {
        output_label: [3; 16],
    };
    assert_eq!(
        resolve_verdicts(&verified, &verdicts).unwrap(),
        DisputeResolution::NoAuthenticatedRefutation
    );
}

#[test]
fn authenticated_refutation_selects_the_matching_retained_instance() {
    let setup = synthetic_setup();
    let verified = classification_only_capability(&setup);
    let verdicts = [
        InstanceVerdict::NoRefutation {
            output_label: [3; 16],
        },
        InstanceVerdict::CorruptedOutput { raw_label: [5; 16] },
        InstanceVerdict::Refute {
            output_label: [4; 16],
        },
    ];
    let expected_index = verified.partition.retained_indices()[2];
    assert_eq!(
        resolve_verdicts(&verified, &verdicts).unwrap(),
        DisputeResolution::AuthenticatedRefutation {
            winning_instance_index: expected_index,
            refute_preimage: [4; 16],
            refute_sha256: setup.manifest.headers[expected_index].refute_output_sha256,
        }
    );
}

#[test]
fn wrong_prechallenge_pin_rejects_before_openings_or_proof() {
    let mut setup = synthetic_setup();
    let mut wrong_pin = setup.manifest.commit1_digest().unwrap();
    wrong_pin[0] ^= 1;
    // These deliberately impossible opening indices must never reach garbling or indexing.
    setup.opened_seeds = [([0; 32], usize::MAX); PILOT_OPENED_INSTANCES];
    let err = verify_public_setup(
        &setup.manifest.session_id,
        &setup.manifest.spec,
        &wrong_pin,
        &setup.nonce,
        &setup,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "pre-challenge commitment mismatch");
}

#[test]
fn malformed_manifest_shape_rejects_before_cryptographic_work() {
    for mutation in 0..4 {
        let mut setup = synthetic_setup();
        let expected_spec = setup.manifest.spec.clone();
        let expected_commit1 = setup.manifest.commit1_digest().unwrap();
        let expected_error = match mutation {
            0 => {
                setup.manifest.num_wires += 1;
                "manifest wire count mismatch"
            }
            1 => {
                setup.manifest.headers.pop();
                "manifest header count mismatch"
            }
            2 => {
                setup.manifest.headers[0].index = usize::MAX;
                "non-sequential header index"
            }
            _ => {
                setup.manifest.headers[0].accept_output_sha256 =
                    setup.manifest.headers[0].refute_output_sha256;
                "degenerate coinciding output label commitments"
            }
        };
        let err = verify_public_setup(
            &setup.manifest.session_id,
            &expected_spec,
            &expected_commit1,
            &setup.nonce,
            &setup,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), expected_error);
    }
}

#[test]
fn wrong_nonce_and_noncanonical_spec_reject_before_opening() {
    let mut setup = synthetic_setup();
    let commit1 = setup.manifest.commit1_digest().unwrap();
    let err = verify_public_setup(
        &setup.manifest.session_id,
        &setup.manifest.spec,
        &commit1,
        &[9; 32],
        &setup,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "challenger nonce mismatch");
    setup.manifest.spec.generators[0] = crate::dispute_circuit::PILOT_PRIME as u32;
    setup.manifest.spec.recompute_circuit_id();
    let commit1 = setup.manifest.commit1_digest().unwrap();
    let err = verify_public_setup(
        &setup.manifest.session_id,
        &setup.manifest.spec,
        &commit1,
        &setup.nonce,
        &setup,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "non-canonical fixed generator");
}

#[test]
fn unfinalized_sessions_cannot_release_labels() {
    let mut session = guard_only_session();
    let err = session
        .release_active_base_labels([2; 32], &[false; PILOT_INPUT_BITS])
        .unwrap_err();
    assert_eq!(err.to_string(), "session has no finalized public setup");
    assert!(session.released_input.is_none());
}

#[test]
fn nonce_reservation_survives_failure_and_blocks_another_partition() {
    let mut session = guard_only_session();
    session.challenge_nonce = Some([2; 32]);
    let err = session.finalize_cut_and_choose([3; 32]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "session already bound to another challenger nonce"
    );
    assert_eq!(session.challenge_nonce, Some([2; 32]));
    assert!(!session.finalized);
}

#[test]
fn release_checks_nonce_and_shape_before_reserving_input() {
    let mut session = guard_only_session();
    session.challenge_nonce = Some([2; 32]);
    session.finalized = true;
    let err = session
        .release_active_base_labels([3; 32], &[false; PILOT_INPUT_BITS])
        .unwrap_err();
    assert_eq!(err.to_string(), "challenger nonce mismatch");
    for length in [PILOT_INPUT_BITS - 1, PILOT_INPUT_BITS + 1] {
        let err = session
            .release_active_base_labels([2; 32], &vec![false; length])
            .unwrap_err();
        assert_eq!(err.to_string(), "input bit count mismatch");
    }
    assert!(session.released_input.is_none());
}

#[test]
fn missing_delivery_requires_chain_deadline_observation() {
    let setup = synthetic_setup();
    let verified = classification_only_capability(&setup);
    assert!(matches!(
        resolve_dispute(&verified, &[false; PILOT_INPUT_BITS], None).unwrap(),
        DisputeResolution::AwaitingWithholdingTimeout { .. }
    ));
    assert!(resolve_dispute(&verified, &[false], None).is_err());
}

#[test]
fn malformed_soldering_delta_shape_returns_an_error_before_indexing() {
    let mut setup = synthetic_setup();
    setup.certificate.wire_deltas.pop();
    let labels = vec![S::from_u128(1); PILOT_INPUT_BITS];
    let bits = vec![false; PILOT_INPUT_BITS];
    let err = unsolder_active_labels(&labels, &bits, &setup.certificate, 0).unwrap_err();
    assert_eq!(err.to_string(), "active label / input bit count mismatch");
    assert!(
        unsolder_active_labels(&labels, &bits, &setup.certificate, PILOT_SOLDERED_INSTANCES)
            .is_err()
    );
}
