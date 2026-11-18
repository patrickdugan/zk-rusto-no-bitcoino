//! Authenticate a complete challenge catalogue, then observe its selected spend.
//!
//! Selection happens after the graph has been funded. Each pre-signed alternative
//! commits the selected bit hashlocks in its output. A durable garbler accepts an
//! `AuthorizedChallenge` only after a configured chain observer has checked the
//! exact confirmed transaction and the still-unspent response output.

use anyhow::{ensure, Context, Result};
use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    BlockHash, Transaction, TxOut, Txid,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    dispute_circuit::{
        compute_step_auth_tag, IndexedDisputeInput, IndexedDisputeSpec, PILOT_NUM_SLOTS,
    },
    journal::JournalPins,
    protocol::{hash_input_bits, VerifiedPublicSetup},
    transaction_graph::{GraphChoice, GraphConfig, PreparedGraph},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogueRow {
    pub index: u8,
    pub input_bits: Vec<bool>,
}

pub struct AuthenticatedCatalogue {
    pins: JournalPins,
    nonce: [u8; 32],
    rows: Vec<CatalogueRow>,
    digest: [u8; 32],
    hashlocks: Vec<([u8; 32], [u8; 32])>,
    refute_hashes: Vec<[u8; 32]>,
}

impl AuthenticatedCatalogue {
    /// All slots must be available and authenticated before accepting funding.
    /// Arithmetic faults are retained so their committed rows can be challenged.
    pub fn from_openings(
        verified: &VerifiedPublicSetup<'_, IndexedDisputeSpec>,
        openings: &[IndexedDisputeInput],
    ) -> Result<Self> {
        ensure!(
            openings.len() == PILOT_NUM_SLOTS,
            "incomplete challenge catalogue"
        );
        let setup = verified.setup();
        let spec = &setup.manifest.spec;
        let pins = JournalPins {
            session_id: setup.manifest.session_id,
            circuit_id: spec.circuit_id,
            commit1: verified.partition().commit1,
        };
        let mut rows = Vec::with_capacity(PILOT_NUM_SLOTS);
        for (index, input) in openings.iter().enumerate() {
            ensure!(
                input.is_representable() && usize::from(input.index) == index,
                "noncanonical catalogue index or field"
            );
            ensure!(
                compute_step_auth_tag(&spec.claim_id, spec.generators[index], input)
                    == spec.step_auth_tags[index],
                "catalogue row is not operator-committed"
            );
            rows.push(CatalogueRow {
                index: input.index,
                input_bits: input.to_bits(),
            });
        }
        let mut hash = Sha256::new();
        hash.update(b"babe-pilot/authenticated-catalogue/v1\0");
        hash.update(pins.session_id);
        hash.update(pins.circuit_id);
        hash.update(pins.commit1);
        hash.update(setup.nonce);
        hash.update((rows.len() as u64).to_le_bytes());
        for row in &rows {
            hash.update([row.index]);
            hash.update(hash_input_bits(&row.input_bits));
        }
        let refute_hashes = verified
            .partition()
            .retained_indices()
            .iter()
            .map(|&index| setup.manifest.headers[index].refute_output_sha256)
            .collect();
        Ok(Self {
            pins,
            nonce: setup.nonce,
            rows,
            digest: hash.finalize().into(),
            hashlocks: setup.base_tap_hashlocks.clone(),
            refute_hashes,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn pins(&self) -> JournalPins {
        self.pins
    }
    pub fn rows(&self) -> &[CatalogueRow] {
        &self.rows
    }
    pub fn graph_choices(&self) -> Vec<GraphChoice> {
        self.rows
            .iter()
            .map(|row| GraphChoice {
                index: row.index,
                input_bits: row.input_bits.clone(),
            })
            .collect()
    }
    pub fn refute_hashes(&self) -> &[[u8; 32]] {
        &self.refute_hashes
    }

    pub fn verify_graph(&self, config: &GraphConfig) -> Result<()> {
        config.validate()?;
        ensure!(
            config.session_id == self.pins.session_id
                && config.commit1 == self.pins.commit1
                && config.catalog_hash == self.digest,
            "graph uses another authenticated catalogue"
        );
        ensure!(
            config.base_hashlocks == self.hashlocks && config.refute_hashes == self.refute_hashes,
            "graph hashlocks differ from verified setup"
        );
        ensure!(
            config.choices.len() == self.rows.len()
                && config
                    .choices
                    .iter()
                    .zip(&self.rows)
                    .all(|(a, b)| a.index == b.index && a.input_bits == b.input_bits),
            "graph changes catalogue selection"
        );
        Ok(())
    }

    pub fn authorize_confirmed(
        &self,
        graph: &PreparedGraph,
        challenge_hex: &str,
        observer: &mut impl ChallengeChain,
        required_confirmations: u32,
    ) -> Result<AuthorizedChallenge> {
        ensure!(
            required_confirmations > 0,
            "confirmation policy must be positive"
        );
        self.verify_graph(graph.config())?;
        let selected = graph.observe_challenge(challenge_hex)?;
        let expected: Transaction = deserialize(&hex::decode(challenge_hex)?)?;
        let txid = expected.compute_txid();
        let seen = observer.observe_challenge(txid, 0)?;
        ensure!(
            serialize(&seen.transaction) == serialize(&expected),
            "chain observer returned another transaction or witness"
        );
        ensure!(
            seen.confirmations >= required_confirmations,
            "challenge lacks required confirmations"
        );
        ensure!(
            seen.confirmation_height > 0
                && seen
                    .current_height
                    .checked_sub(seen.confirmation_height)
                    .and_then(|n| n.checked_add(1))
                    == Some(seen.confirmations),
            "inconsistent chain heights"
        );
        ensure!(
            seen.unspent_output.as_ref() == expected.output.first(),
            "challenge response output is already spent or changed"
        );
        let input_bits = self
            .rows
            .get(selected)
            .context("selected catalogue row absent")?
            .input_bits
            .clone();
        let mut hash = Sha256::new();
        hash.update(b"babe-pilot/confirmed-release/v1\0");
        hash.update(self.digest);
        hash.update(graph.config().digest()?);
        hash.update(serialize(&graph.funding_outpoint()));
        hash.update(txid.to_byte_array());
        hash.update((selected as u64).to_le_bytes());
        hash.update(hash_input_bits(&input_bits));
        Ok(AuthorizedChallenge {
            pins: self.pins,
            nonce: self.nonce,
            input_bits,
            selected_index: selected,
            transaction_id: txid,
            graph_digest: graph.config().digest()?,
            block_hash: seen.block_hash,
            confirmation_height: seen.confirmation_height,
            digest: hash.finalize().into(),
        })
    }
}

/// A trusted node adapter supplies this observation. Callers configure that
/// adapter independently of the operator's transaction and confirmation claims.
pub struct ChainObservation {
    pub transaction: Transaction,
    pub block_hash: BlockHash,
    pub confirmation_height: u32,
    pub confirmations: u32,
    pub current_height: u32,
    pub unspent_output: Option<TxOut>,
}

pub trait ChallengeChain {
    fn observe_challenge(&mut self, txid: Txid, output_index: u32) -> Result<ChainObservation>;
}

#[derive(Debug)]
pub struct AuthorizedChallenge {
    pins: JournalPins,
    nonce: [u8; 32],
    input_bits: Vec<bool>,
    selected_index: usize,
    transaction_id: Txid,
    graph_digest: [u8; 32],
    block_hash: BlockHash,
    confirmation_height: u32,
    digest: [u8; 32],
}

impl AuthorizedChallenge {
    pub fn pins(&self) -> JournalPins {
        self.pins
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    pub fn input_bits(&self) -> &[bool] {
        &self.input_bits
    }
    pub fn selected_index(&self) -> usize {
        self.selected_index
    }
    pub fn transaction_id(&self) -> Txid {
        self.transaction_id
    }
    pub fn graph_digest(&self) -> [u8; 32] {
        self.graph_digest
    }
    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }
    pub fn confirmation_height(&self) -> u32 {
        self.confirmation_height
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// A bounded decoder for the fixed indexed pilot's public challenge rows.
pub fn decode_indexed_row(row: &CatalogueRow) -> Result<IndexedDisputeInput> {
    use crate::dispute_circuit::{PILOT_ELEM_BITS, PILOT_INDEX_BITS, PILOT_INPUT_BITS};
    ensure!(
        row.input_bits.len() == PILOT_INPUT_BITS && usize::from(row.index) < PILOT_NUM_SLOTS,
        "invalid catalogue row width or index"
    );
    let value = |offset: usize, width: usize| -> u32 {
        row.input_bits[offset..offset + width]
            .iter()
            .enumerate()
            .fold(0u32, |acc, (bit, &v)| acc | (u32::from(v) << bit))
    };
    ensure!(
        value(0, PILOT_INDEX_BITS) == u32::from(row.index),
        "encoded catalogue index mismatch"
    );
    Ok(IndexedDisputeInput {
        index: row.index,
        s_in: value(PILOT_INDEX_BITS, PILOT_ELEM_BITS),
        step_val: value(PILOT_INDEX_BITS + PILOT_ELEM_BITS, PILOT_ELEM_BITS),
        s_out: value(PILOT_INDEX_BITS + 2 * PILOT_ELEM_BITS, PILOT_ELEM_BITS),
        witness_quotient: value(PILOT_INDEX_BITS + 3 * PILOT_ELEM_BITS, PILOT_ELEM_BITS),
    })
}
