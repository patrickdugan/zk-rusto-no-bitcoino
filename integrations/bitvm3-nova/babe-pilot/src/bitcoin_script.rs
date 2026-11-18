//! Bitcoin Taproot (`BIP-341` / `BIP-342`) Script & Witness Construction for BABE-Nova Disputes.
//!
//! Constructs real `bitcoin` v0.32 Taproot script trees, control blocks, and witness-bearing
//! transactions to measure virtual bytes (`vsize`), weight units (`WU`), and selected witness
//! bounds. The measurement transactions use dummy outpoints and signatures. They provide
//! serialization evidence; Script execution, consensus validity, and relay acceptance require
//! separate checks against funded transactions.

use anyhow::{ensure, Result};
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    key::Secp256k1,
    opcodes::all::*,
    script::Builder,
    secp256k1::XOnlyPublicKey,
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;
pub const MAX_TAPSCRIPT_INITIAL_STACK_ITEMS: usize = 1_000;
/// Local construction cap for one label-revelation leaf. Larger inputs must be split across
/// separately committed outputs. This is a pilot resource bound, not a consensus script limit.
pub const MAX_ASSERT_LABELS_PER_LEAF: usize = 480;
pub const MAX_ASSERT_LABELS_SCRIPT_BYTES: usize = 35 * MAX_ASSERT_LABELS_PER_LEAF + 34;

/// BIP-341 standard unspendable NUMS x-only internal public key.
pub fn nums_internal_key() -> XOnlyPublicKey {
    let bytes = hex::decode("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("32-byte NUMS hex");
    XOnlyPublicKey::from_slice(&bytes).expect("valid x-only NUMS key")
}

pub fn sample_xonly_pubkey(tag: u8) -> XOnlyPublicKey {
    // Deterministic valid x-only pubkey derived via secp256k1 generator multiplication.
    let secp = Secp256k1::new();
    let mut sk_bytes = [0x11u8; 32];
    sk_bytes[0] = tag.wrapping_add(1);
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes).expect("valid secret key");
    let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
    kp.x_only_public_key().0
}

/// Builds a label-revelation leaf for an independently authenticated, fixed challenge input.
///
/// The caller must obtain `expected_input_bits` from the agreed challenge, rather than from
/// the spending witness, and commit this tree in the funding/challenge graph before exposing
/// funds. Each wire commits only the hashlock selected by that expected bit. The spending
/// witness cannot choose another bit or substitute labels for a different challenge input.
///
/// The stack is `[operator_signature, label_{W-1}, ..., label_0]`, bottom to top. Execution
/// consumes one label per wire, then checks the operator signature. The enclosing protocol
/// still has to authorize the challenge and bind the transaction's destinations.
pub fn build_check_lamp_sigs_script(
    hashlocks: &[([u8; 32], [u8; 32])],
    expected_input_bits: &[bool],
    operator_pk: &XOnlyPublicKey,
) -> Result<ScriptBuf> {
    ensure!(
        hashlocks.len() == expected_input_bits.len(),
        "hashlock / expected input length mismatch"
    );
    ensure!(
        (1..=MAX_ASSERT_LABELS_PER_LEAF).contains(&hashlocks.len()),
        "label count must be in 1..={MAX_ASSERT_LABELS_PER_LEAF}"
    );
    let mut b = Builder::new();
    for (i, (&(h0, h1), &expected_bit)) in hashlocks.iter().zip(expected_input_bits).enumerate() {
        ensure!(h0 != h1, "coinciding bit hashlocks at wire {i}");
        b = b
            .push_opcode(OP_SHA256)
            .push_slice(if expected_bit { h1 } else { h0 })
            .push_opcode(OP_EQUALVERIFY);
    }
    let script = b
        .push_x_only_key(operator_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ensure!(
        script.len() <= MAX_ASSERT_LABELS_SCRIPT_BYTES,
        "label-revelation script exceeds local construction bound"
    );
    Ok(script)
}

pub fn build_csv_timeout_script(csv_blocks: u16, sweep_pk: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(csv_blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(sweep_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn build_disprove_leaf_script(
    refute_label_sha256: &[u8; 32],
    challenger_pk: &XOnlyPublicKey,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(*refute_label_sha256)
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(challenger_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Builds the 2-leaf `Challenge` output Taptree:
/// - Depth 1 left: fixed-input label revelation (operator reveals the selected base labels);
/// - Depth 1 right: `WithholdingTimeout` (challenger sweeps bond after `D_label` blocks if withheld).
///
/// This commits to `expected_input_bits` through the selected hashlocks. Constructing a tree
/// does not establish that a challenge was authorized or that the enclosing graph funds it.
pub fn build_assert_labels_taptree(
    hashlocks: &[([u8; 32], [u8; 32])],
    expected_input_bits: &[bool],
    operator_pk: &XOnlyPublicKey,
    challenger_pk: &XOnlyPublicKey,
    d_label_blocks: u16,
) -> Result<(TaprootSpendInfo, ScriptBuf, ScriptBuf)> {
    ensure!(
        d_label_blocks > 0,
        "label withholding delay must be positive"
    );
    let secp = Secp256k1::verification_only();
    let lamp_script = build_check_lamp_sigs_script(hashlocks, expected_input_bits, operator_pk)?;
    let timeout_script = build_csv_timeout_script(d_label_blocks, challenger_pk);
    let info = TaprootBuilder::new()
        .add_leaf(1, lamp_script.clone())
        .expect("leaf 0")
        .add_leaf(1, timeout_script.clone())
        .expect("leaf 1")
        .finalize(&secp, nums_internal_key())
        .expect("finalize AssertLabels Taptree");
    Ok((info, lamp_script, timeout_script))
}

/// Builds a balanced `(M + 1)`-leaf `Disprove` Taptree (`M` instance refute leaves + `1` operator CSV payout leaf).
pub fn build_disprove_taptree(
    refute_hashes: &[[u8; 32]],
    challenger_pk: &XOnlyPublicKey,
    operator_pk: &XOnlyPublicKey,
    d3_blocks: u16,
) -> (TaprootSpendInfo, Vec<ScriptBuf>, ScriptBuf) {
    let secp = Secp256k1::verification_only();
    let disprove_scripts: Vec<ScriptBuf> = refute_hashes
        .iter()
        .map(|h| build_disprove_leaf_script(h, challenger_pk))
        .collect();
    let payout_script = build_csv_timeout_script(d3_blocks, operator_pk);

    let mut all_scripts = disprove_scripts.clone();
    all_scripts.push(payout_script.clone());

    // Assign balanced Huffman/power-of-two depths so `TaprootBuilder` forms a valid complete binary tree.
    let total = all_scripts.len();
    assert!(total >= 2);
    let max_pow2 = total.next_power_of_two();
    let base_depth = max_pow2.trailing_zeros() as u8;
    let shallow_count = max_pow2 - total; // leaves at `base_depth - 1`

    let mut builder = TaprootBuilder::new();
    for (i, script) in all_scripts.iter().enumerate() {
        let depth = if i < shallow_count {
            base_depth - 1
        } else {
            base_depth
        };
        builder = builder
            .add_leaf(depth, script.clone())
            .expect("add balanced Taptree leaf");
    }
    let info = builder
        .finalize(&secp, nums_internal_key())
        .expect("finalize Disprove Taptree");
    (info, disprove_scripts, payout_script)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxMeasurement {
    pub name: String,
    pub vsize: usize,
    pub weight_wu: u64,
    pub total_bytes: usize,
    pub witness_items: usize,
    pub script_bytes: usize,
    pub control_block_bytes: usize,
    pub initial_stack_items: usize,
    pub max_initial_stack_item_bytes: usize,
    pub initial_stack_items_within_policy_bounds: bool,
    pub evidence_kind: String,
    pub consensus_verified: bool,
    pub standardness_verified: bool,
}

fn dummy_tx(sequence: Sequence, witness: Witness, out_script: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(198_000),
            script_pubkey: out_script,
        }],
    }
}

fn measure_tapscript_tx(
    name: &str,
    sequence: Sequence,
    mut stack_items: Vec<Vec<u8>>,
    leaf_script: &ScriptBuf,
    spend_info: &TaprootSpendInfo,
) -> Result<TxMeasurement> {
    let initial_stack_items = stack_items.len();
    let max_initial_stack_item_bytes = stack_items.iter().map(|it| it.len()).max().unwrap_or(0);
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .expect("leaf present in TaprootSpendInfo");
    let control_bytes = control_block.serialize();

    stack_items.push(leaf_script.to_bytes());
    stack_items.push(control_bytes.clone());

    let mut witness = Witness::new();
    for item in &stack_items {
        witness.push(item.as_slice());
    }

    let p2tr_dest = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    let tx = dummy_tx(sequence, witness, p2tr_dest);

    Ok(TxMeasurement {
        name: name.into(),
        vsize: tx.vsize(),
        weight_wu: tx.weight().to_wu(),
        total_bytes: bitcoin::consensus::serialize(&tx).len(),
        witness_items: stack_items.len(),
        script_bytes: leaf_script.len(),
        control_block_bytes: control_bytes.len(),
        initial_stack_items,
        max_initial_stack_item_bytes,
        initial_stack_items_within_policy_bounds: max_initial_stack_item_bytes
            <= MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE
            && initial_stack_items <= MAX_TAPSCRIPT_INITIAL_STACK_ITEMS,
        evidence_kind: "serialization-only".into(),
        consensus_verified: false,
        standardness_verified: false,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinDisputeMeasurements {
    pub assert_labels_tx: TxMeasurement,
    pub withholding_timeout_tx: TxMeasurement,
    pub disprove_tx: TxMeasurement,
    pub operator_payout_tx: TxMeasurement,
}

/// Measures four standalone Taproot templates using dummy outpoints and signatures.
/// Checks label/hashlock consistency before serialization. Full transaction validity and
/// the connected funding, challenge, and exit graph remain outside this measurement.
pub fn measure_pilot_bitcoin_paths(
    base_hashlocks: &[([u8; 32], [u8; 32])],
    input_bits: &[bool],
    active_base_labels: &[[u8; 16]],
    retained_refute_hashes: &[[u8; 32]],
    winning_slot: usize,
    winning_refute_preimage: &[u8; 16],
) -> Result<BitcoinDisputeMeasurements> {
    ensure!(
        base_hashlocks.len() == input_bits.len() && input_bits.len() == active_base_labels.len(),
        "base label / input length mismatch"
    );
    ensure!(
        winning_slot < retained_refute_hashes.len(),
        "winning slot out of range"
    );
    let got_refute_sha: [u8; 32] = Sha256::digest(winning_refute_preimage).into();
    ensure!(
        got_refute_sha == retained_refute_hashes[winning_slot],
        "winning refute preimage does not match Disprove leaf SHA-256 hashlock"
    );

    let op_pk = sample_xonly_pubkey(1);
    let ch_pk = sample_xonly_pubkey(2);
    let dummy_schnorr_sig = vec![0x42u8; 64];

    let (assert_info, lamp_script, timeout_script) =
        build_assert_labels_taptree(base_hashlocks, input_bits, &op_pk, &ch_pk, 6)?;

    // Witness stack bottom-to-top:
    // `[op_sig]` is consumed last by `<op_pk> OP_CHECKSIG`.
    // Above it, wire `W-1` down to wire `0` so wire `0` is at the top of stack when execution starts:
    // Each wire consumes only its fixed-input label; there are no witness-selected bit flags.
    let mut assert_stack = Vec::with_capacity(1 + input_bits.len());
    assert_stack.push(dummy_schnorr_sig.clone());
    for i in (0..input_bits.len()).rev() {
        let got_h: [u8; 32] = Sha256::digest(active_base_labels[i]).into();
        let exp_h = if input_bits[i] {
            base_hashlocks[i].1
        } else {
            base_hashlocks[i].0
        };
        ensure!(
            got_h == exp_h,
            "AssertLabels witness preimage mismatch at wire {i}"
        );
        assert_stack.push(active_base_labels[i].to_vec());
    }
    let assert_labels_tx = measure_tapscript_tx(
        "AssertLabelsTx (CheckLampSigsMatch)",
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        assert_stack,
        &lamp_script,
        &assert_info,
    )?;

    let withholding_timeout_tx = measure_tapscript_tx(
        "WithholdingTimeoutTx (CSV D_label=6)",
        Sequence::from_height(6),
        vec![dummy_schnorr_sig.clone()],
        &timeout_script,
        &assert_info,
    )?;

    let (disprove_info, disprove_scripts, payout_script) =
        build_disprove_taptree(retained_refute_hashes, &ch_pk, &op_pk, 6);

    // Disprove leaf: `<OP_SHA256> <hash> <OP_EQUALVERIFY> <ch_pk> <OP_CHECKSIG>`
    // Bottom-to-top initial stack: `[ch_sig (64B), refute_preimage (16B)]`.
    let disprove_tx = measure_tapscript_tx(
        "DisproveTx (1-of-M refute hashlock)",
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        vec![dummy_schnorr_sig.clone(), winning_refute_preimage.to_vec()],
        &disprove_scripts[winning_slot],
        &disprove_info,
    )?;

    let operator_payout_tx = measure_tapscript_tx(
        "OperatorPayoutTx (CSV D_3=6)",
        Sequence::from_height(6),
        vec![dummy_schnorr_sig],
        &payout_script,
        &disprove_info,
    )?;

    Ok(BitcoinDisputeMeasurements {
        assert_labels_tx,
        withholding_timeout_tx,
        disprove_tx,
        operator_payout_tx,
    })
}
