//! Run after producing a compressed bundle:
//! LNM_NOVA_BUNDLE=/absolute/path/to/bundle cargo test --release --locked \
//!   --manifest-path LNMarkets/nova/Cargo.toml --test persisted_artifact -- --ignored
use lnm_bitvm3_nova::artifact::{decode_proof, read_bounded, MAX_PROOF_BYTES};

#[test]
#[ignore = "requires LNM_NOVA_BUNDLE pointing to a locally produced compressed bundle"]
fn persisted_compressed_proof_rejects_trailing_and_truncated_bytes() {
    let directory = std::env::var_os("LNM_NOVA_BUNDLE")
        .expect("set LNM_NOVA_BUNDLE to the completed bundle directory");
    let path = std::path::PathBuf::from(directory).join("proof.bin");
    let mut bytes = read_bounded(&path, MAX_PROOF_BYTES).unwrap();
    decode_proof(&bytes).expect("the original compressed proof must decode");
    bytes.push(0);
    assert!(decode_proof(&bytes).is_err(), "trailing byte was accepted");
    bytes.truncate(bytes.len() - 2);
    assert!(
        decode_proof(&bytes).is_err(),
        "truncated proof was accepted"
    );
}

#[test]
#[ignore = "requires LNM_NOVA_BUNDLE and rebuilds the full current verifier key once"]
fn malformed_nova_vectors_fail_closed_after_valid_binary_decoding() {
    use lnm_bitvm3_nova::artifact::{serialize_bounded, setup_params, verify_proof_bytes, Cs};
    use lnm_bitvm3_nova::initial_state;
    let directory = std::path::PathBuf::from(
        std::env::var_os("LNM_NOVA_BUNDLE")
            .expect("set LNM_NOVA_BUNDLE to the completed bundle directory"),
    );
    let bytes = read_bounded(&directory.join("proof.bin"), MAX_PROOF_BYTES).unwrap();
    let journal: [u8; lnm_batch_statement::JOURNAL_LEN] = read_bounded(
        &directory.join("journal.bin"),
        lnm_batch_statement::JOURNAL_LEN,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let parsed = lnm_batch_statement::decode_journal(&journal).unwrap();
    let initial = initial_state(&journal, parsed.epoch);
    let pp = setup_params().unwrap();
    let (_, vk) = Cs::setup(&pp).unwrap();
    verify_proof_bytes(&bytes, &vk, parsed.row_count as usize, &initial)
        .expect("the original proof must verify before mutating its internals");
    let original = serde_json::to_value(decode_proof(&bytes).unwrap()).unwrap();
    for pointer in [
        "/snark_primary/sc_proof_outer/compressed_polys/0/coeffs_except_linear_term",
        "/snark_primary/evals_batch",
    ] {
        let mut mutated = original.clone();
        *mutated
            .pointer_mut(pointer)
            .expect("Nova 0.76 proof path changed") = serde_json::json!([]);
        let malformed: Cs = serde_json::from_value(mutated).unwrap();
        let encoded = serialize_bounded(&malformed, MAX_PROOF_BYTES).unwrap();
        decode_proof(&encoded).expect("attack must reach Nova verification after valid decoding");
        let error = verify_proof_bytes(&encoded, &vk, parsed.row_count as usize, &initial)
            .expect_err("malformed Nova vectors must be refused through the Result boundary");
        assert!(error.contains("verifier rejection"), "{pointer}: {error}");
    }
}
