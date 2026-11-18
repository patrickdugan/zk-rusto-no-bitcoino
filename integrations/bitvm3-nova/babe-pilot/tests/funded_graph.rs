//! Transaction construction and signature coverage tests. Consensus execution lives in
//! scripts/run-regtest.py and its Bitcoin Core receipt, not in these host-side checks.

use babe_pilot::transaction_graph::{
    tx_hex, wrong_response_label, GraphChoice, GraphConfig, PreparedGraph,
};
use bitcoin::{
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    OutPoint, Txid, Witness,
};
use sha2::{Digest, Sha256};

fn key(byte: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    )
}

fn label(wire: usize, bit: bool) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&(wire as u64).to_le_bytes());
    value[8] = u8::from(bit);
    value[15] = 37;
    value
}

fn fixture() -> (GraphConfig, OutPoint, Keypair, Keypair) {
    let operator = key(1);
    let challenger = key(2);
    let config = GraphConfig {
        session_id: [3; 32],
        commit1: [4; 32],
        catalog_hash: [5; 32],
        choices: (0..16)
            .map(|index| GraphChoice {
                index,
                input_bits: (0..128)
                    .map(|wire| wire < 4 && index >> wire & 1 == 1)
                    .collect(),
            })
            .collect(),
        base_hashlocks: (0..128)
            .map(|wire| {
                (
                    Sha256::digest(label(wire, false)).into(),
                    Sha256::digest(label(wire, true)).into(),
                )
            })
            .collect(),
        refute_hashes: (201..204)
            .map(|byte| Sha256::digest([byte; 16]).into())
            .collect(),
        operator_key: operator.x_only_public_key().0.serialize(),
        challenger_key: challenger.x_only_public_key().0.serialize(),
        operator_destination: [vec![0, 20], vec![11; 20]].concat(),
        challenger_destination: [vec![0, 20], vec![12; 20]].concat(),
        funding_sats: 1_000_000,
        challenge_fee_sats: 2_000,
        response_fee_sats: 5_000,
        terminal_fee_sats: 2_000,
        assertion_csv: 12,
        labels_csv: 4,
        payout_csv: 5,
    };
    (
        config,
        OutPoint {
            txid: Txid::from_byte_array([6; 32]),
            vout: 2,
        },
        operator,
        challenger,
    )
}

#[test]
fn all_choices_are_authorized_before_one_is_selected() {
    let (config, funding, operator, challenger) = fixture();
    let independently_rebuilt = PreparedGraph::new(config.clone(), funding).unwrap();
    let graph = PreparedGraph::new(config, funding).unwrap();
    let op = graph.presign_operator(&operator).unwrap();
    independently_rebuilt
        .verify_operator_presignatures(&op)
        .unwrap();
    let ch = independently_rebuilt
        .presign_challenger(&op, &challenger)
        .unwrap();
    graph.verify_challenger_presignatures(&ch).unwrap();
    for index in 0..16 {
        assert_eq!(op.challenges[index].len(), 65);
        assert_eq!(op.challenges[index][64], 1);
        assert_eq!(ch.responses[index][64], 1);
        let challenge = graph.complete_challenge(index, &op, &challenger).unwrap();
        assert_eq!(graph.observe_challenge(&tx_hex(&challenge)).unwrap(), index);
        assert_eq!(
            challenge.compute_txid(),
            graph.unsigned_challenge(index).unwrap().compute_txid()
        );
        let labels: Vec<_> = graph.config().choices[index]
            .input_bits
            .iter()
            .enumerate()
            .map(|(i, &bit)| label(i, bit))
            .collect();
        let response = graph
            .complete_response(index, &ch, &operator, &labels)
            .unwrap();
        graph
            .verify_response_presignature_for(index, &response, &ch)
            .unwrap();
        assert_eq!(response.input[0].witness.len(), 132);
    }
}

#[test]
fn retaining_operator_key_cannot_redirect_pre_signed_response() {
    let (config, funding, operator, challenger) = fixture();
    let graph = PreparedGraph::new(config, funding).unwrap();
    let op = graph.presign_operator(&operator).unwrap();
    let ch = graph.presign_challenger(&op, &challenger).unwrap();
    let labels: Vec<_> = graph.config().choices[3]
        .input_bits
        .iter()
        .enumerate()
        .map(|(i, &bit)| label(i, bit))
        .collect();
    let response = graph.complete_response(3, &ch, &operator, &labels).unwrap();
    let redirected = graph
        .redirected_response_attempt(3, &response, &operator)
        .unwrap();
    assert_ne!(redirected.compute_txid(), response.compute_txid());
    assert!(graph
        .verify_response_presignature_for(3, &redirected, &ch)
        .is_err());
}

#[test]
fn graph_mutations_invalidate_pre_funding_signatures() {
    let (config, funding, operator, challenger) = fixture();
    let graph = PreparedGraph::new(config.clone(), funding).unwrap();
    let op = graph.presign_operator(&operator).unwrap();
    let ch = graph.presign_challenger(&op, &challenger).unwrap();
    for field in 0..8 {
        let mut changed = config.clone();
        match field {
            0 => changed.session_id[0] ^= 1,
            1 => changed.commit1[0] ^= 1,
            2 => changed.catalog_hash[0] ^= 1,
            3 => changed.operator_destination[2] ^= 1,
            4 => changed.response_fee_sats += 1,
            5 => changed.labels_csv += 1,
            6 => changed.payout_csv += 1,
            _ => changed.refute_hashes[0][0] ^= 1,
        }
        let replaced = PreparedGraph::new(changed, funding).unwrap();
        assert!(
            replaced.verify_operator_presignatures(&op).is_err(),
            "mutated field {field}"
        );
        // Input scripts and dispute outputs are also covered by response signatures.
        // Session metadata is bound at the funding output, which is spent by the signed
        // challenge transaction; its txid alone does not include the funding script.
        if field >= 4 {
            assert!(
                replaced.verify_challenger_presignatures(&ch).is_err(),
                "mutated field {field}"
            );
        }
    }
    let another_outpoint = OutPoint {
        vout: funding.vout + 1,
        ..funding
    };
    let replay = PreparedGraph::new(config, another_outpoint).unwrap();
    assert!(replay.verify_operator_presignatures(&op).is_err());
    assert!(replay.verify_challenger_presignatures(&ch).is_err());
}

#[test]
fn signatures_cannot_be_omitted_or_downgraded() {
    let (config, funding, operator, challenger) = fixture();
    let graph = PreparedGraph::new(config, funding).unwrap();
    let op = graph.presign_operator(&operator).unwrap();
    let ch = graph.presign_challenger(&op, &challenger).unwrap();
    let mut omitted = op.clone();
    omitted.challenges.pop();
    assert!(graph.presign_challenger(&omitted, &challenger).is_err());
    let mut downgraded = op.clone();
    downgraded.challenges[3][64] = 0x81;
    assert!(graph.verify_operator_presignatures(&downgraded).is_err());
    let mut truncated = ch;
    truncated.responses[3].pop();
    assert!(graph.verify_challenger_presignatures(&truncated).is_err());
    assert!(graph.presign_operator(&challenger).is_err());
}

#[test]
fn observed_selection_requires_the_exact_valid_witness() {
    let (config, funding, operator, challenger) = fixture();
    let graph = PreparedGraph::new(config, funding).unwrap();
    let op = graph.presign_operator(&operator).unwrap();
    let challenge = graph.complete_challenge(5, &op, &challenger).unwrap();
    let mut changed = challenge.clone();
    changed.output[0].value = bitcoin::Amount::from_sat(changed.output[0].value.to_sat() - 1);
    assert!(graph.observe_challenge(&tx_hex(&changed)).is_err());
    let mut stack: Vec<Vec<u8>> = challenge.input[0]
        .witness
        .iter()
        .map(|v| v.to_vec())
        .collect();
    stack[0][0] ^= 1;
    changed = challenge.clone();
    changed.input[0].witness = Witness::from_slice(&stack);
    assert!(graph.observe_challenge(&tx_hex(&changed)).is_err());
    assert!(graph
        .observe_challenge(&tx_hex(graph.unsigned_challenge(5).unwrap()))
        .is_err());
    assert!(graph.observe_challenge(&"00".repeat(50_001)).is_err());
}

#[test]
fn selected_hashlocks_and_refutation_hashes_are_checked() {
    let (config, funding, operator, challenger) = fixture();
    let graph = PreparedGraph::new(config, funding).unwrap();
    let op = graph.presign_operator(&operator).unwrap();
    let ch = graph.presign_challenger(&op, &challenger).unwrap();
    let mut labels: Vec<_> = graph.config().choices[3]
        .input_bits
        .iter()
        .enumerate()
        .map(|(i, &bit)| label(i, bit))
        .collect();
    let response = graph.complete_response(3, &ch, &operator, &labels).unwrap();
    let changed = wrong_response_label(&response).unwrap();
    assert_eq!(changed.compute_txid(), response.compute_txid());
    assert_ne!(changed.compute_wtxid(), response.compute_wtxid());
    labels[0] = label(0, false);
    assert!(graph.complete_response(3, &ch, &operator, &labels).is_err());
    assert!(graph.disprove(3, 0, [201; 16], &challenger).is_ok());
    assert!(graph.disprove(3, 0, [202; 16], &challenger).is_err());
    assert!(graph.disprove(3, 3, [201; 16], &challenger).is_err());
}

#[test]
fn graph_bounds_reject_malformed_configuration() {
    let (config, funding, _, _) = fixture();
    for case in 0..8 {
        let mut changed = config.clone();
        match case {
            0 => changed.choices[1].input_bits = changed.choices[0].input_bits.clone(),
            1 => changed.choices[0].input_bits.pop().map(|_| ()).unwrap(),
            2 => changed.operator_key = changed.challenger_key,
            3 => changed.base_hashlocks[0].0 = changed.base_hashlocks[0].1,
            4 => changed.funding_sats = 1_000,
            5 => changed.labels_csv = 0,
            6 => changed.operator_destination = vec![0x51],
            _ => changed.refute_hashes[1] = changed.refute_hashes[0],
        }
        assert!(PreparedGraph::new(changed, funding).is_err(), "case {case}");
    }
}

#[test]
fn graph_accepts_a_bounded_catalogue_with_another_input_width() {
    let (mut config, funding, operator, challenger) = fixture();
    config.choices.truncate(4);
    for choice in &mut config.choices {
        choice.input_bits.truncate(8);
    }
    config.base_hashlocks.truncate(8);
    config.refute_hashes.truncate(1);
    let graph = PreparedGraph::new(config, funding).unwrap();
    let op = graph.presign_operator(&operator).unwrap();
    let ch = graph.presign_challenger(&op, &challenger).unwrap();
    assert_eq!(op.challenges.len(), 4);
    assert_eq!(ch.responses.len(), 4);
    let labels: Vec<_> = graph.config().choices[2]
        .input_bits
        .iter()
        .enumerate()
        .map(|(i, &bit)| label(i, bit))
        .collect();
    assert!(graph.complete_response(2, &ch, &operator, &labels).is_ok());
    assert!(graph.complete_challenge(4, &op, &challenger).is_err());
}
