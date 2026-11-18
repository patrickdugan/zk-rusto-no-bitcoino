//! Bounded two-party transaction graph for a sixteen-choice regtest dispute.
//!
//! The caller supplies a challenge catalogue independently authenticated against the proof
//! setup. Before funding, the operator signs every challenge transaction and the challenger
//! signs every response transaction. A response leaf requires both signatures, so an operator
//! retaining its key cannot redirect a label revelation away from the committed dispute output.
//! This module does not select a canonical application state or prove collateral ownership.

use anyhow::{ensure, Context, Result};
use bitcoin::{
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_EQUALVERIFY, OP_RETURN, OP_SHA256},
    script::Builder,
    secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bitcoin_script::{
    build_csv_timeout_script, build_disprove_taptree, nums_internal_key, MAX_ASSERT_LABELS_PER_LEAF,
};

pub const GRAPH_CHOICES: usize = 16;
pub const GRAPH_INPUT_BITS: usize = 128; // current pilot fixture width; builders accept 1..=480
pub const GRAPH_RETAINED_INSTANCES: usize = 3;
const MIN_OUTPUT_SATS: u64 = 1_000;
const MAX_FUNDING_SATS: u64 = 100_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphChoice {
    pub index: u8,
    pub input_bits: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphConfig {
    pub session_id: [u8; 32],
    pub commit1: [u8; 32],
    pub catalog_hash: [u8; 32],
    pub choices: Vec<GraphChoice>,
    pub base_hashlocks: Vec<([u8; 32], [u8; 32])>,
    pub refute_hashes: Vec<[u8; 32]>,
    pub operator_key: [u8; 32],
    pub challenger_key: [u8; 32],
    pub operator_destination: Vec<u8>,
    pub challenger_destination: Vec<u8>,
    pub funding_sats: u64,
    pub challenge_fee_sats: u64,
    pub response_fee_sats: u64,
    pub terminal_fee_sats: u64,
    pub assertion_csv: u16,
    pub labels_csv: u16,
    pub payout_csv: u16,
}

impl GraphConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=GRAPH_CHOICES).contains(&self.choices.len()),
            "challenge catalogue must contain 1..=16 choices"
        );
        ensure!(
            (1..=MAX_ASSERT_LABELS_PER_LEAF).contains(&self.base_hashlocks.len()),
            "base hashlock count outside 1..=480"
        );
        ensure!(
            (1..=64).contains(&self.refute_hashes.len()),
            "retained hashlock count outside 1..=64"
        );
        ensure!(
            self.operator_key != self.challenger_key,
            "operator and challenger keys must differ"
        );
        XOnlyPublicKey::from_slice(&self.operator_key).context("operator key")?;
        XOnlyPublicKey::from_slice(&self.challenger_key).context("challenger key")?;
        for (i, choice) in self.choices.iter().enumerate() {
            ensure!(
                choice.index as usize == i,
                "challenge catalogue indices must be 0..15 in order"
            );
            ensure!(
                choice.input_bits.len() == self.base_hashlocks.len(),
                "challenge input width mismatch"
            );
            ensure!(
                self.choices[..i]
                    .iter()
                    .all(|other| other.input_bits != choice.input_bits),
                "duplicate challenge input vector"
            );
        }
        ensure!(
            self.base_hashlocks.iter().all(|(a, b)| a != b),
            "coinciding base hashlocks"
        );
        ensure!(
            self.refute_hashes
                .iter()
                .enumerate()
                .all(|(i, a)| self.refute_hashes[..i].iter().all(|b| a != b)),
            "duplicate refutation hashlocks"
        );
        ensure!(
            self.assertion_csv > 0 && self.labels_csv > 0 && self.payout_csv > 0,
            "CSV delays must be positive"
        );
        for script in [&self.operator_destination, &self.challenger_destination] {
            ensure!(
                matches!(script.as_slice(), [0, 20, ..] if script.len() == 22)
                    || matches!(script.as_slice(), [0x51, 32, ..] if script.len() == 34),
                "destination must be native P2WPKH or P2TR"
            );
        }
        ensure!(
            (MIN_OUTPUT_SATS..=MAX_FUNDING_SATS).contains(&self.funding_sats),
            "funding amount outside bounded regtest profile"
        );
        let fees = self
            .challenge_fee_sats
            .checked_add(self.response_fee_sats)
            .and_then(|v| v.checked_add(self.terminal_fee_sats))
            .context("fee sum overflow")?;
        ensure!(
            fees > 0
                && self
                    .funding_sats
                    .checked_sub(fees)
                    .is_some_and(|v| v >= MIN_OUTPUT_SATS),
            "fees exhaust the funded output"
        );
        Ok(())
    }

    /// Commits the complete expected catalogue, keys, destinations, and fee/timelock policy.
    /// The catalogue's semantic authentication is the caller's prerequisite.
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"babe-pilot/regtest-transaction-graph/v1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hash.finalize().into())
    }

    pub fn assertion_script_pubkey(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::new_p2tr_tweaked(
            assertion_tree(self)?.0.output_key(),
        ))
    }

    pub fn regtest_address(&self) -> Result<Address> {
        Ok(Address::p2tr_tweaked(
            assertion_tree(self)?.0.output_key(),
            Network::Regtest,
        ))
    }
}

fn two_party_script(operator: XOnlyPublicKey, challenger: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&operator)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&challenger)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn assertion_tree(config: &GraphConfig) -> Result<(TaprootSpendInfo, ScriptBuf, ScriptBuf)> {
    config.validate()?;
    let operator = XOnlyPublicKey::from_slice(&config.operator_key)?;
    let challenger = XOnlyPublicKey::from_slice(&config.challenger_key)?;
    let challenge = two_party_script(operator, challenger);
    let timeout = build_csv_timeout_script(config.assertion_csv, &operator);
    let binding = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(config.digest()?)
        .into_script();
    let tree = TaprootBuilder::new()
        .add_leaf(1, binding)?
        .add_leaf(2, challenge.clone())?
        .add_leaf(2, timeout.clone())?
        .finalize(&Secp256k1::verification_only(), nums_internal_key())
        .map_err(|_| anyhow::anyhow!("incomplete assertion tree"))?;
    Ok((tree, challenge, timeout))
}

fn response_tree(
    config: &GraphConfig,
    choice: &GraphChoice,
) -> Result<(TaprootSpendInfo, ScriptBuf, ScriptBuf)> {
    let operator = XOnlyPublicKey::from_slice(&config.operator_key)?;
    let challenger = XOnlyPublicKey::from_slice(&config.challenger_key)?;
    let mut builder = Builder::new();
    for (&(h0, h1), &bit) in config.base_hashlocks.iter().zip(&choice.input_bits) {
        builder = builder
            .push_opcode(OP_SHA256)
            .push_slice(if bit { h1 } else { h0 })
            .push_opcode(OP_EQUALVERIFY);
    }
    // Challenger's pre-signature commits the response destination. The operator's signature
    // alone cannot spend this leaf, even when the operator knows both labels of every wire.
    let response = builder
        .push_x_only_key(&operator)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&challenger)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let timeout = build_csv_timeout_script(config.labels_csv, &challenger);
    let tree = TaprootBuilder::new()
        .add_leaf(1, response.clone())?
        .add_leaf(1, timeout.clone())?
        .finalize(&Secp256k1::verification_only(), nums_internal_key())
        .map_err(|_| anyhow::anyhow!("incomplete response tree"))?;
    Ok((tree, response, timeout))
}

fn transaction(
    previous_output: OutPoint,
    sequence: Sequence,
    value: u64,
    destination: ScriptBuf,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: destination,
        }],
    }
}

fn message(tx: &Transaction, prevout: &TxOut, script: &ScriptBuf) -> Result<Message> {
    let hash = SighashCache::new(tx).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(std::slice::from_ref(prevout)),
        TapLeafHash::from_script(script, LeafVersion::TapScript),
        TapSighashType::All,
    )?;
    Ok(Message::from_digest(hash.to_byte_array()))
}

fn signature(
    tx: &Transaction,
    prevout: &TxOut,
    script: &ScriptBuf,
    keypair: &Keypair,
) -> Result<Vec<u8>> {
    let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&message(tx, prevout, script)?, keypair);
    let mut bytes = sig.as_ref().to_vec();
    bytes.push(1); // explicit SIGHASH_ALL
    Ok(bytes)
}

fn verify_signature(
    tx: &Transaction,
    prevout: &TxOut,
    script: &ScriptBuf,
    public_key: &[u8; 32],
    bytes: &[u8],
) -> Result<()> {
    ensure!(
        bytes.len() == 65 && bytes[64] == 1,
        "connector requires explicit SIGHASH_ALL"
    );
    Secp256k1::verification_only()
        .verify_schnorr(
            &Signature::from_slice(&bytes[..64])?,
            &message(tx, prevout, script)?,
            &XOnlyPublicKey::from_slice(public_key)?,
        )
        .context("connector signature does not authorize the exact transaction")
}

fn require_key(keypair: &Keypair, expected: &[u8; 32]) -> Result<()> {
    ensure!(
        &keypair.x_only_public_key().0.serialize() == expected,
        "signing key differs from independently expected role"
    );
    Ok(())
}

fn attach_witness(
    mut tx: Transaction,
    mut stack: Vec<Vec<u8>>,
    tree: &TaprootSpendInfo,
    script: &ScriptBuf,
) -> Result<Transaction> {
    stack.push(script.to_bytes());
    stack.push(
        tree.control_block(&(script.clone(), LeafVersion::TapScript))
            .context("missing graph leaf")?
            .serialize(),
    );
    tx.input[0].witness = Witness::from_slice(&stack);
    Ok(tx)
}

#[derive(Clone)]
struct Branch {
    challenge: Transaction,
    response: Transaction,
    response_tree: TaprootSpendInfo,
    response_script: ScriptBuf,
    withholding_script: ScriptBuf,
}

pub struct PreparedGraph {
    config: GraphConfig,
    funding: OutPoint,
    funding_output: TxOut,
    assertion_tree: TaprootSpendInfo,
    challenge_script: ScriptBuf,
    assertion_timeout_script: ScriptBuf,
    branches: Vec<Branch>,
    disprove_tree: TaprootSpendInfo,
    disprove_scripts: Vec<ScriptBuf>,
    payout_script: ScriptBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPreSignatures {
    pub challenges: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengerPreSignatures {
    pub responses: Vec<Vec<u8>>,
}

impl PreparedGraph {
    pub fn new(config: GraphConfig, funding: OutPoint) -> Result<Self> {
        config.validate()?;
        let (assertion_tree, challenge_script, assertion_timeout_script) = assertion_tree(&config)?;
        let funding_output = TxOut {
            value: Amount::from_sat(config.funding_sats),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(assertion_tree.output_key()),
        };
        let op = XOnlyPublicKey::from_slice(&config.operator_key)?;
        let ch = XOnlyPublicKey::from_slice(&config.challenger_key)?;
        let (disprove_tree, disprove_scripts, payout_script) =
            build_disprove_taptree(&config.refute_hashes, &ch, &op, config.payout_csv);
        let dispute_spk = ScriptBuf::new_p2tr_tweaked(disprove_tree.output_key());
        let mut branches = Vec::with_capacity(GRAPH_CHOICES);
        for choice in &config.choices {
            let (response_tree, response_script, withholding_script) =
                response_tree(&config, choice)?;
            let challenge = transaction(
                funding,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                config.funding_sats - config.challenge_fee_sats,
                ScriptBuf::new_p2tr_tweaked(response_tree.output_key()),
            );
            let response = transaction(
                OutPoint {
                    txid: challenge.compute_txid(),
                    vout: 0,
                },
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                challenge.output[0].value.to_sat() - config.response_fee_sats,
                dispute_spk.clone(),
            );
            branches.push(Branch {
                challenge,
                response,
                response_tree,
                response_script,
                withholding_script,
            });
        }
        Ok(Self {
            config,
            funding,
            funding_output,
            assertion_tree,
            challenge_script,
            assertion_timeout_script,
            branches,
            disprove_tree,
            disprove_scripts,
            payout_script,
        })
    }

    pub fn config(&self) -> &GraphConfig {
        &self.config
    }
    pub fn funding_outpoint(&self) -> OutPoint {
        self.funding
    }
    pub fn funding_output(&self) -> &TxOut {
        &self.funding_output
    }
    fn branch(&self, index: usize) -> Result<&Branch> {
        self.branches
            .get(index)
            .context("challenge index outside catalogue")
    }
    pub fn unsigned_challenge(&self, index: usize) -> Result<&Transaction> {
        Ok(&self.branch(index)?.challenge)
    }
    pub fn unsigned_response(&self, index: usize) -> Result<&Transaction> {
        Ok(&self.branch(index)?.response)
    }

    pub fn presign_operator(&self, operator: &Keypair) -> Result<OperatorPreSignatures> {
        require_key(operator, &self.config.operator_key)?;
        Ok(OperatorPreSignatures {
            challenges: self
                .branches
                .iter()
                .map(|b| {
                    signature(
                        &b.challenge,
                        &self.funding_output,
                        &self.challenge_script,
                        operator,
                    )
                })
                .collect::<Result<_>>()?,
        })
    }

    pub fn verify_operator_presignatures(&self, presigned: &OperatorPreSignatures) -> Result<()> {
        ensure!(
            presigned.challenges.len() == self.config.choices.len(),
            "operator pre-signature count mismatch"
        );
        for (branch, sig) in self.branches.iter().zip(&presigned.challenges) {
            verify_signature(
                &branch.challenge,
                &self.funding_output,
                &self.challenge_script,
                &self.config.operator_key,
                sig,
            )?;
        }
        Ok(())
    }

    /// An independently configured challenger rebuilds this graph and verifies the operator's
    /// entire challenge catalogue before pre-signing responses or authorizing funding.
    pub fn presign_challenger(
        &self,
        operator_presigned: &OperatorPreSignatures,
        challenger: &Keypair,
    ) -> Result<ChallengerPreSignatures> {
        self.verify_operator_presignatures(operator_presigned)?;
        require_key(challenger, &self.config.challenger_key)?;
        Ok(ChallengerPreSignatures {
            responses: self
                .branches
                .iter()
                .map(|b| {
                    signature(
                        &b.response,
                        &b.challenge.output[0],
                        &b.response_script,
                        challenger,
                    )
                })
                .collect::<Result<_>>()?,
        })
    }

    pub fn verify_challenger_presignatures(
        &self,
        presigned: &ChallengerPreSignatures,
    ) -> Result<()> {
        ensure!(
            presigned.responses.len() == self.config.choices.len(),
            "challenger pre-signature count mismatch"
        );
        for (branch, sig) in self.branches.iter().zip(&presigned.responses) {
            verify_signature(
                &branch.response,
                &branch.challenge.output[0],
                &branch.response_script,
                &self.config.challenger_key,
                sig,
            )?;
        }
        Ok(())
    }

    pub fn complete_challenge(
        &self,
        index: usize,
        presigned: &OperatorPreSignatures,
        challenger: &Keypair,
    ) -> Result<Transaction> {
        self.verify_operator_presignatures(presigned)?;
        require_key(challenger, &self.config.challenger_key)?;
        let b = self.branch(index)?;
        let ch_sig = signature(
            &b.challenge,
            &self.funding_output,
            &self.challenge_script,
            challenger,
        )?;
        attach_witness(
            b.challenge.clone(),
            vec![ch_sig, presigned.challenges[index].clone()],
            &self.assertion_tree,
            &self.challenge_script,
        )
    }

    pub fn complete_response(
        &self,
        index: usize,
        presigned: &ChallengerPreSignatures,
        operator: &Keypair,
        labels: &[[u8; 16]],
    ) -> Result<Transaction> {
        self.verify_challenger_presignatures(presigned)?;
        require_key(operator, &self.config.operator_key)?;
        let b = self.branch(index)?;
        ensure!(
            labels.len() == self.config.base_hashlocks.len(),
            "active label count mismatch"
        );
        for (i, label) in labels.iter().enumerate() {
            let expected = if self.config.choices[index].input_bits[i] {
                self.config.base_hashlocks[i].1
            } else {
                self.config.base_hashlocks[i].0
            };
            let actual: [u8; 32] = Sha256::digest(label).into();
            ensure!(
                actual == expected,
                "active label does not match the authenticated challenge at wire {i}"
            );
        }
        let op_sig = signature(
            &b.response,
            &b.challenge.output[0],
            &b.response_script,
            operator,
        )?;
        let mut stack = vec![presigned.responses[index].clone(), op_sig];
        stack.extend(labels.iter().rev().map(|v| v.to_vec()));
        attach_witness(
            b.response.clone(),
            stack,
            &b.response_tree,
            &b.response_script,
        )
    }

    pub fn withholding(&self, index: usize, challenger: &Keypair) -> Result<Transaction> {
        require_key(challenger, &self.config.challenger_key)?;
        let b = self.branch(index)?;
        let tx = transaction(
            OutPoint {
                txid: b.challenge.compute_txid(),
                vout: 0,
            },
            Sequence::from_height(self.config.labels_csv),
            b.challenge.output[0].value.to_sat() - self.config.terminal_fee_sats,
            ScriptBuf::from_bytes(self.config.challenger_destination.clone()),
        );
        let sig = signature(
            &tx,
            &b.challenge.output[0],
            &b.withholding_script,
            challenger,
        )?;
        attach_witness(tx, vec![sig], &b.response_tree, &b.withholding_script)
    }

    pub fn operator_payout(&self, index: usize, operator: &Keypair) -> Result<Transaction> {
        require_key(operator, &self.config.operator_key)?;
        let b = self.branch(index)?;
        let tx = transaction(
            OutPoint {
                txid: b.response.compute_txid(),
                vout: 0,
            },
            Sequence::from_height(self.config.payout_csv),
            b.response.output[0].value.to_sat() - self.config.terminal_fee_sats,
            ScriptBuf::from_bytes(self.config.operator_destination.clone()),
        );
        let sig = signature(&tx, &b.response.output[0], &self.payout_script, operator)?;
        attach_witness(tx, vec![sig], &self.disprove_tree, &self.payout_script)
    }

    pub fn disprove(
        &self,
        index: usize,
        retained_slot: usize,
        preimage: [u8; 16],
        challenger: &Keypair,
    ) -> Result<Transaction> {
        require_key(challenger, &self.config.challenger_key)?;
        let b = self.branch(index)?;
        let script = self
            .disprove_scripts
            .get(retained_slot)
            .context("retained slot outside graph")?;
        let actual: [u8; 32] = Sha256::digest(preimage).into();
        ensure!(
            actual == self.config.refute_hashes[retained_slot],
            "refutation label does not open the pinned hashlock"
        );
        let tx = transaction(
            OutPoint {
                txid: b.response.compute_txid(),
                vout: 0,
            },
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            b.response.output[0].value.to_sat() - self.config.terminal_fee_sats,
            ScriptBuf::from_bytes(self.config.challenger_destination.clone()),
        );
        let sig = signature(&tx, &b.response.output[0], script, challenger)?;
        attach_witness(
            tx,
            vec![sig, preimage.to_vec()],
            &self.disprove_tree,
            script,
        )
    }

    pub fn assertion_timeout(&self, operator: &Keypair) -> Result<Transaction> {
        require_key(operator, &self.config.operator_key)?;
        let tx = transaction(
            self.funding,
            Sequence::from_height(self.config.assertion_csv),
            self.config.funding_sats - self.config.terminal_fee_sats,
            ScriptBuf::from_bytes(self.config.operator_destination.clone()),
        );
        let sig = signature(
            &tx,
            &self.funding_output,
            &self.assertion_timeout_script,
            operator,
        )?;
        attach_witness(
            tx,
            vec![sig],
            &self.assertion_tree,
            &self.assertion_timeout_script,
        )
    }

    /// Used by adversarial regtest to model an operator retaining its key and trying to
    /// redirect a response. The challenger's pre-signature remains unchanged, so Core must
    /// reject the transaction even after the operator signs the changed output correctly.
    pub fn redirected_response_attempt(
        &self,
        index: usize,
        completed: &Transaction,
        operator: &Keypair,
    ) -> Result<Transaction> {
        require_key(operator, &self.config.operator_key)?;
        let b = self.branch(index)?;
        ensure!(
            completed.compute_txid() == b.response.compute_txid(),
            "not the expected completed response"
        );
        let mut tx = completed.clone();
        tx.output[0].script_pubkey =
            ScriptBuf::from_bytes(self.config.operator_destination.clone());
        let op_sig = signature(&tx, &b.challenge.output[0], &b.response_script, operator)?;
        let mut witness: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|v| v.to_vec()).collect();
        ensure!(
            witness.len() == self.config.base_hashlocks.len() + 4,
            "response witness shape mismatch"
        );
        witness[1] = op_sig;
        tx.input[0].witness = Witness::from_slice(&witness);
        Ok(tx)
    }

    pub fn verify_response_presignature_for(
        &self,
        index: usize,
        candidate: &Transaction,
        presigned: &ChallengerPreSignatures,
    ) -> Result<()> {
        ensure!(
            presigned.responses.len() == self.config.choices.len(),
            "challenger pre-signature count mismatch"
        );
        let b = self.branch(index)?;
        verify_signature(
            candidate,
            &b.challenge.output[0],
            &b.response_script,
            &self.config.challenger_key,
            &presigned.responses[index],
        )
    }

    /// Recognizes the exact selected challenge transaction, including its valid two-party
    /// witness. Chain membership/confirmation must be obtained separately from Core.
    pub fn observe_challenge(&self, tx_hex: &str) -> Result<usize> {
        ensure!(
            tx_hex.len() <= 100_000,
            "challenge transaction exceeds bound"
        );
        let raw = hex::decode(tx_hex)?;
        let tx: Transaction = deserialize(&raw)?;
        ensure!(serialize(&tx) == raw, "non-canonical challenge transaction");
        let index = self
            .branches
            .iter()
            .position(|b| b.challenge.compute_txid() == tx.compute_txid())
            .context("transaction is outside the committed challenge catalogue")?;
        let stack: Vec<_> = tx.input[0].witness.iter().collect();
        ensure!(stack.len() == 4, "challenge witness shape mismatch");
        let control = self
            .assertion_tree
            .control_block(&(self.challenge_script.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();
        ensure!(
            stack[2] == self.challenge_script.as_bytes() && stack[3] == control,
            "challenge witness uses another leaf"
        );
        verify_signature(
            &tx,
            &self.funding_output,
            &self.challenge_script,
            &self.config.operator_key,
            stack[1],
        )?;
        verify_signature(
            &tx,
            &self.funding_output,
            &self.challenge_script,
            &self.config.challenger_key,
            stack[0],
        )?;
        Ok(index)
    }
}

pub fn tx_hex(tx: &Transaction) -> String {
    hex::encode(serialize(tx))
}

/// Changes one label while retaining otherwise valid signatures for a Core rejection test.
pub fn wrong_response_label(tx: &Transaction) -> Result<Transaction> {
    let mut changed = tx.clone();
    ensure!(changed.input.len() == 1, "expected one response input");
    let mut stack: Vec<Vec<u8>> = changed.input[0]
        .witness
        .iter()
        .map(|v| v.to_vec())
        .collect();
    ensure!(
        stack.len() >= 5 && stack.len() <= MAX_ASSERT_LABELS_PER_LEAF + 4 && stack[2].len() == 16,
        "response witness shape mismatch"
    );
    stack[2][0] ^= 1;
    changed.input[0].witness = Witness::from_slice(&stack);
    Ok(changed)
}
