//! Bounded checks for the fixed-input label leaf and its measurement evidence.
//!
//! These tests inspect the exact emitted template, validate Taproot commitments using
//! rust-bitcoin, and verify real BIP341 Schnorr signatures. They do not run a Bitcoin
//! Script interpreter, create funded UTXOs, or establish consensus/relay acceptance.

use babe_pilot::bitcoin_script::{
    build_assert_labels_taptree, build_check_lamp_sigs_script, measure_pilot_bitcoin_paths,
    sample_xonly_pubkey, MAX_ASSERT_LABELS_PER_LEAF, MAX_ASSERT_LABELS_SCRIPT_BYTES,
};
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_SHA256},
    script::Instruction,
    secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash},
    transaction::Version,
    Amount, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use sha2::{Digest, Sha256};

type Label = [u8; 16];
type Hashlocks = ([u8; 32], [u8; 32]);

fn fixture(wires: usize) -> (Vec<(Label, Label)>, Vec<Hashlocks>) {
    let labels: Vec<_> = (0..wires)
        .map(|wire| {
            let label = |bit: u8| -> Label {
                let mut h = Sha256::new();
                h.update(b"fixed-input-script-test");
                h.update((wire as u64).to_le_bytes());
                h.update([bit]);
                h.finalize()[..16].try_into().unwrap()
            };
            (label(0), label(1))
        })
        .collect();
    let locks = labels
        .iter()
        .map(|(l0, l1)| (Sha256::digest(l0).into(), Sha256::digest(l1).into()))
        .collect();
    (labels, locks)
}

/// Inspect only the generated straight-line template. This deliberately supports no
/// arbitrary Bitcoin scripts and makes no claim to replace a consensus interpreter.
fn selected_hashlocks(script: &Script) -> (Vec<[u8; 32]>, XOnlyPublicKey) {
    let instructions: Vec<_> = script
        .instructions_minimal()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(instructions.len() >= 5);
    assert_eq!((instructions.len() - 2) % 3, 0);
    let end = instructions.len() - 2;
    let mut locks = Vec::new();
    for chunk in instructions[..end].chunks_exact(3) {
        assert_eq!(chunk[0], Instruction::Op(OP_SHA256));
        assert_eq!(chunk[2], Instruction::Op(OP_EQUALVERIFY));
        let Instruction::PushBytes(hash) = chunk[1] else {
            panic!("expected a committed SHA256 hashlock")
        };
        locks.push(hash.as_bytes().try_into().unwrap());
    }
    let Instruction::PushBytes(key) = instructions[end] else {
        panic!("expected operator public key")
    };
    assert_eq!(instructions[end + 1], Instruction::Op(OP_CHECKSIG));
    (locks, XOnlyPublicKey::from_slice(key.as_bytes()).unwrap())
}

/// Check the template's hashlocks and final signature with mature hashing/secp256k1
/// implementations. Full Script execution and the availability of its prevout are separate.
fn template_witness_checks(script: &Script, stack: &[Vec<u8>], sighash: &Message) -> bool {
    let (locks, operator) = selected_hashlocks(script);
    if stack.len() != locks.len() + 1 {
        return false;
    }
    for (i, expected) in locks.iter().enumerate() {
        let actual: [u8; 32] = Sha256::digest(&stack[locks.len() - i]).into();
        if &actual != expected {
            return false;
        }
    }
    let Ok(signature) = Signature::from_slice(&stack[0]) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&signature, sighash, &operator)
        .is_ok()
}

#[test]
fn fixed_input_leaf_contains_only_expected_hashlocks() {
    let (_, hashlocks) = fixture(4);
    let bits = [false, true, true, false];
    let operator = sample_xonly_pubkey(1);
    let script = build_check_lamp_sigs_script(&hashlocks, &bits, &operator).unwrap();
    let (selected, actual_operator) = selected_hashlocks(&script);
    assert_eq!(actual_operator, operator);
    for i in 0..bits.len() {
        assert_eq!(
            selected[i],
            if bits[i] {
                hashlocks[i].1
            } else {
                hashlocks[i].0
            }
        );
    }
    assert_eq!(script.len(), 35 * bits.len() + 34);
}

#[test]
fn changing_one_expected_bit_changes_the_funded_taproot_commitment() {
    let (_, hashlocks) = fixture(4);
    let bits = [false, true, false, true];
    let op = sample_xonly_pubkey(1);
    let ch = sample_xonly_pubkey(2);
    let (original, script, _) =
        build_assert_labels_taptree(&hashlocks, &bits, &op, &ch, 6).unwrap();
    let secp = Secp256k1::verification_only();
    let control = original
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap();
    assert!(control.verify_taproot_commitment(
        &secp,
        original.output_key().to_x_only_public_key(),
        &script
    ));
    for i in 0..bits.len() {
        let mut other_bits = bits;
        other_bits[i] ^= true;
        let (other, other_script, _) =
            build_assert_labels_taptree(&hashlocks, &other_bits, &op, &ch, 6).unwrap();
        assert_ne!(original.output_key(), other.output_key());
        assert!(!control.verify_taproot_commitment(
            &secp,
            original.output_key().to_x_only_public_key(),
            &other_script
        ));
    }
}

#[test]
fn real_schnorr_signature_and_fixed_hashlocks_reject_substitutions() {
    let (labels, hashlocks) = fixture(4);
    let bits = [false, true, false, true];
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32]).unwrap());
    let operator = keypair.x_only_public_key().0;
    let challenger = sample_xonly_pubkey(2);
    let (info, script, _) =
        build_assert_labels_taptree(&hashlocks, &bits, &operator, &challenger, 6).unwrap();
    let prevout = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr_tweaked(info.output_key()),
    };
    // A synthetic outpoint lets us test the real signature's commitment. This transaction
    // is not presented to Core and does not claim that the outpoint exists.
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7; 32]),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(199_000),
            script_pubkey: prevout.script_pubkey.clone(),
        }],
    };
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let message_for = |candidate: &Transaction| {
        let digest = SighashCache::new(candidate)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        Message::from_digest(digest.to_byte_array())
    };
    let message = message_for(&tx);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    let mut stack = vec![signature.as_ref().to_vec()];
    for i in (0..bits.len()).rev() {
        stack.push(if bits[i] { labels[i].1 } else { labels[i].0 }.to_vec());
    }
    assert!(template_witness_checks(&script, &stack, &message));
    for i in 0..bits.len() {
        let mut substituted = stack.clone();
        substituted[bits.len() - i] = if bits[i] { labels[i].0 } else { labels[i].1 }.to_vec();
        assert!(!template_witness_checks(&script, &substituted, &message));
    }
    let mut old_style_selector = stack.clone();
    old_style_selector.push(vec![1]);
    assert!(!template_witness_checks(
        &script,
        &old_style_selector,
        &message
    ));
    let mut redirected = tx.clone();
    redirected.output[0].value = Amount::from_sat(198_000);
    assert!(!template_witness_checks(
        &script,
        &stack,
        &message_for(&redirected)
    ));
}

#[test]
fn malformed_and_oversized_input_sets_fail_before_script_construction() {
    let (_, hashlocks) = fixture(MAX_ASSERT_LABELS_PER_LEAF + 1);
    let operator = sample_xonly_pubkey(1);
    assert!(build_check_lamp_sigs_script(&[], &[], &operator).is_err());
    assert!(build_check_lamp_sigs_script(&hashlocks[..2], &[false], &operator).is_err());
    assert!(build_check_lamp_sigs_script(&hashlocks[..1], &[false, true], &operator).is_err());
    assert!(
        build_check_lamp_sigs_script(&hashlocks, &vec![false; hashlocks.len()], &operator).is_err()
    );
    assert!(build_check_lamp_sigs_script(&[([0; 32], [0; 32])], &[false], &operator).is_err());
    let max_script = build_check_lamp_sigs_script(
        &hashlocks[..MAX_ASSERT_LABELS_PER_LEAF],
        &vec![true; MAX_ASSERT_LABELS_PER_LEAF],
        &operator,
    )
    .unwrap();
    assert_eq!(max_script.len(), MAX_ASSERT_LABELS_SCRIPT_BYTES);
    assert!(build_assert_labels_taptree(
        &hashlocks[..1],
        &[false],
        &operator,
        &sample_xonly_pubkey(2),
        0
    )
    .is_err());
}

#[test]
fn measurement_reports_serialization_scope_and_fixed_input_stack() {
    let (labels, hashlocks) = fixture(4);
    let bits = [false, true, false, true];
    let active: Vec<_> = bits
        .iter()
        .enumerate()
        .map(|(i, bit)| if *bit { labels[i].1 } else { labels[i].0 })
        .collect();
    let refute_label = [9; 16];
    let refute_hash: [u8; 32] = Sha256::digest(refute_label).into();
    let measurements =
        measure_pilot_bitcoin_paths(&hashlocks, &bits, &active, &[refute_hash], 0, &refute_label)
            .unwrap();
    assert_eq!(
        measurements.assert_labels_tx.initial_stack_items,
        bits.len() + 1
    );
    assert_eq!(measurements.assert_labels_tx.witness_items, bits.len() + 3);
    for result in [
        measurements.assert_labels_tx,
        measurements.withholding_timeout_tx,
        measurements.disprove_tx,
        measurements.operator_payout_tx,
    ] {
        assert_eq!(result.evidence_kind, "serialization-only");
        assert!(result.initial_stack_items_within_policy_bounds);
        assert!(!result.consensus_verified);
        assert!(!result.standardness_verified);
    }
    let mut wrong_labels = active;
    wrong_labels[0] = labels[0].1;
    assert!(measure_pilot_bitcoin_paths(
        &hashlocks,
        &bits,
        &wrong_labels,
        &[refute_hash],
        0,
        &refute_label
    )
    .is_err());
}
