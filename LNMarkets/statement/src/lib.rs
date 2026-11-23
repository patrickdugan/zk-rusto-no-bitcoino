//! A co-signed batch-proposal certificate for synthetic Bitcoin-regtest DLCs.
//!
//! This relation verifies application signatures over committed DLC summaries,
//! oracle-authorized payout membership, a deterministic unsigned batch proposal,
//! and consumed-authorization nullifier transitions. The original adaptor/refund
//! package is represented by a co-signed recovery digest. Opening that package,
//! Bitcoin witnesses, funding existence, chain truth, and venue-wide liability
//! completeness are outside this statement.
#![forbid(unsafe_code)]

use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

mod codec;
mod merkle;
mod taproot;

#[cfg(feature = "native")]
pub mod fixture;

pub use codec::{decode_batch, decode_journal, encode_batch, encode_journal};
pub use merkle::{
    accepted_contracts_root, empty_nullifier_root, outcome_leaf_hash, outcome_root_and_path,
    SparseNullifierTree,
};
pub use taproot::derive_funding_script;

pub type Hash = [u8; 32];
pub type Sig = [u8; 64];
pub type Script = [u8; 34];
pub type Result<T> = std::result::Result<T, String>;

pub const MAX_ROWS: usize = 32;
pub const MAX_OUTCOMES: u32 = 1024;
pub const MAX_WITNESS_BYTES: usize = 512 * 1024;
pub const JOURNAL_LEN: usize = 276;
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
pub const MIN_OUTPUT_SATS: u64 = 330;
pub const MAX_ROW_FEE_SATS: u64 = 1_000_000;
pub const SMT_DEPTH: usize = 256;
pub const BATCH_MAGIC: &[u8; 8] = b"LNMBAT01";
pub const JOURNAL_MAGIC: &[u8; 8] = b"LNMJNL01";
const DOMAIN: &str = "UTXORef/LNMarkets/bitcoin-regtest/lnmarkets/v1/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchContext {
    pub epoch: u64,
    pub batch_id: Hash,
    pub evaluation_height: u32,
    pub valid_until_height: u32,
    pub accepted_contracts_root: Hash,
    pub old_nullifier_root: Hash,
    pub new_nullifier_root: Hash,
    pub batch_tx_digest: Hash,
    pub row_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlcSummary {
    pub salt: Hash,
    pub contract_id: Hash,
    pub plan_digest: Hash,
    pub recovery_digest: Hash,
    /// Display-order txid bytes; transaction serialization reverses them.
    pub funding_txid: Hash,
    pub funding_vout: u32,
    pub collateral_sats: u64,
    pub funding_script: Script,
    pub trader_key: Hash,
    pub maker_key: Hash,
    pub trader_script: Script,
    pub maker_script: Script,
    pub anchor_script: Script,
    /// Strictly increasing x-only public keys.
    pub oracle_keys: [Hash; 3],
    pub oracle_event_id: Hash,
    pub outcome_root: Hash,
    pub outcome_count: u32,
    pub maturity_height: u32,
    pub refund_height: u32,
    pub refund_csv: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub index: u32,
    pub message: Hash,
    pub trader_sats: u64,
    pub maker_sats: u64,
    pub anchor_sats: u64,
    pub fee_sats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleAttestation {
    pub oracle_index: u8,
    pub signature: Sig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub summary: DlcSummary,
    pub summary_signatures: [Sig; 2],
    pub outcome: Outcome,
    /// Leaf-to-root, with canonical padded-tree depth determined by count.
    pub outcome_siblings: Vec<Hash>,
    pub oracle_attestations: [OracleAttestation; 2],
    pub batch_signatures: [Sig; 2],
    /// Exactly 256 leaf-to-root siblings against the current intermediate root.
    pub nullifier_siblings: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchWitness {
    pub context: BatchContext,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    pub domain: Hash,
    pub epoch: u64,
    pub batch_id: Hash,
    pub evaluation_height: u32,
    pub valid_until_height: u32,
    pub row_count: u32,
    pub accepted_contracts_root: Hash,
    pub old_nullifier_root: Hash,
    pub new_nullifier_root: Hash,
    pub batch_tx_digest: Hash,
    pub batch_txid: Hash,
    pub total_collateral_sats: u64,
    /// Includes the committed anchor outputs.
    pub total_payout_sats: u64,
    pub total_fee_sats: u64,
}

/// Values retained by the receiving application before accepting the result.
/// The receiver must atomically advance old->new nullifier state once, after
/// verifying the exact guest program identity and proof. These pins cannot be
/// copied from an untrusted newly supplied journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalPins {
    pub epoch: u64,
    pub batch_id: Hash,
    pub evaluation_height: u32,
    pub valid_until_height: u32,
    pub row_count: u32,
    pub accepted_contracts_root: Hash,
    pub old_nullifier_root: Hash,
    pub batch_tx_digest: Hash,
}

pub fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

pub fn tagged_hash(label: &str, bytes: &[u8]) -> Hash {
    let tag = sha256(format!("{DOMAIN}{label}").as_bytes());
    let mut h = Sha256::new();
    h.update(tag);
    h.update(tag);
    h.update(bytes);
    h.finalize().into()
}

pub fn statement_domain() -> Hash {
    tagged_hash("statement-domain", b"co-signed-batch-proposal-certificate")
}

pub fn summary_digest(summary: &DlcSummary) -> Hash {
    tagged_hash("dlc-summary", &codec::summary_bytes(summary))
}

pub fn oracle_message(summary: &DlcSummary, outcome: &Outcome) -> Hash {
    let mut bytes = Vec::with_capacity(76);
    bytes.extend_from_slice(&summary.oracle_event_id);
    bytes.extend_from_slice(&summary.maturity_height.to_le_bytes());
    bytes.extend_from_slice(&summary.outcome_count.to_le_bytes());
    bytes.extend_from_slice(&outcome.index.to_le_bytes());
    bytes.extend_from_slice(&outcome.message);
    tagged_hash("oracle-attestation", &bytes)
}

pub fn batch_consent_message(context: &BatchContext, summary: &DlcSummary) -> Hash {
    let mut bytes = codec::context_bytes(context);
    bytes.extend_from_slice(&summary_digest(summary));
    tagged_hash("batch-consent", &bytes)
}

pub fn outpoint_nullifier(summary: &DlcSummary) -> Hash {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&summary.funding_txid);
    bytes.extend_from_slice(&summary.funding_vout.to_le_bytes());
    tagged_hash("consumed-outpoint-authorization", &bytes)
}

pub fn verify_bip340(key: &Hash, message: &Hash, signature: &Sig) -> Result<()> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| "invalid BIP340 public key".to_owned())?;
    let signature = Signature::try_from(signature.as_slice())
        .map_err(|_| "invalid BIP340 signature encoding".to_owned())?;
    // verify_raw checks the provided 32-byte digest directly. The generic
    // Verifier trait would hash it again and change the application protocol.
    key.verify_raw(message, &signature)
        .map_err(|_| "BIP340 signature verification failed".to_owned())
}

fn nonzero(hash: &Hash, label: &str) -> Result<()> {
    if *hash == [0; 32] {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(())
}

fn amount(value: u64, label: &str) -> Result<()> {
    if value > MAX_MONEY {
        return Err(format!("{label} exceeds MAX_MONEY"));
    }
    Ok(())
}

fn money_add(left: u64, right: u64, label: &str) -> Result<u64> {
    let value = left
        .checked_add(right)
        .ok_or_else(|| format!("{label} overflow"))?;
    amount(value, label)?;
    Ok(value)
}

fn valid_script(script: &Script) -> Result<()> {
    if script[..2] != [0x51, 0x20] {
        return Err("only 34-byte P2TR output scripts are supported".to_owned());
    }
    VerifyingKey::from_bytes(&script[2..]).map_err(|_| "invalid P2TR output key".to_owned())?;
    Ok(())
}

fn validate_summary(s: &DlcSummary, context: &BatchContext) -> Result<()> {
    for (value, label) in [
        (&s.salt, "salt"),
        (&s.contract_id, "contract_id"),
        (&s.plan_digest, "plan_digest"),
        (&s.recovery_digest, "recovery_digest"),
        (&s.funding_txid, "funding_txid"),
        (&s.oracle_event_id, "oracle_event_id"),
        (&s.outcome_root, "outcome_root"),
    ] {
        nonzero(value, label)?;
    }
    amount(s.collateral_sats, "collateral")?;
    if s.collateral_sats < 3 * MIN_OUTPUT_SATS + 1 || s.funding_vout == u32::MAX {
        return Err("invalid collateral or reserved funding output index".to_owned());
    }
    for key in [&s.trader_key, &s.maker_key]
        .into_iter()
        .chain(s.oracle_keys.iter())
    {
        VerifyingKey::from_bytes(key).map_err(|_| "invalid pinned public key".to_owned())?;
    }
    if s.trader_key == s.maker_key
        || !(s.oracle_keys[0] < s.oracle_keys[1] && s.oracle_keys[1] < s.oracle_keys[2])
    {
        return Err(
            "party keys must differ and oracle keys must be distinct and sorted".to_owned(),
        );
    }
    for script in [
        &s.funding_script,
        &s.trader_script,
        &s.maker_script,
        &s.anchor_script,
    ] {
        valid_script(script)?;
    }
    if s.trader_script == s.maker_script
        || s.trader_script == s.anchor_script
        || s.maker_script == s.anchor_script
    {
        return Err("party and anchor output scripts must differ".to_owned());
    }
    if s.outcome_count == 0 || s.outcome_count > MAX_OUTCOMES {
        return Err("outcome count must be in 1..1024".to_owned());
    }
    if s.maturity_height == 0
        || s.maturity_height >= 500_000_000
        || s.refund_height <= s.maturity_height
        || s.refund_height >= 500_000_000
        || s.refund_csv == 0
    {
        return Err("invalid block-height maturity/refund policy".to_owned());
    }
    if context.evaluation_height < s.maturity_height {
        return Err("contract maturity exceeds supplied evaluation height".to_owned());
    }
    if derive_funding_script(&s.trader_key, &s.maker_key, s.refund_csv)? != s.funding_script {
        return Err("funding script differs from the derived two-party NUMS template".to_owned());
    }
    Ok(())
}

fn validate_context(context: &BatchContext, rows: usize) -> Result<()> {
    if rows == 0 || rows > MAX_ROWS || context.row_count as usize != rows {
        return Err("batch requires 1..32 rows and an exact row count".to_owned());
    }
    if context.epoch == 0 {
        return Err("epoch must be positive".to_owned());
    }
    nonzero(&context.batch_id, "batch_id")?;
    if context.evaluation_height == 0
        || context.valid_until_height >= 500_000_000
        || context.evaluation_height > context.valid_until_height
    {
        return Err("invalid evaluation/expiry block-height window".to_owned());
    }
    Ok(())
}

/// Build the exact unsigned Bitcoin batch proposal. This contains no witness
/// signatures. Rows are in display-txid/vout order; outputs aggregate identical
/// scripts and are sorted by script bytes. The statement checks these bytes.
pub fn unsigned_batch_transaction(rows: &[Row]) -> Result<Vec<u8>> {
    if rows.is_empty() || rows.len() > MAX_ROWS {
        return Err("invalid row count".to_owned());
    }
    let mut outputs = BTreeMap::<Script, u64>::new();
    let mut maturity = 0;
    for row in rows {
        maturity = maturity.max(row.summary.maturity_height);
        for (script, value) in [
            (row.summary.trader_script, row.outcome.trader_sats),
            (row.summary.maker_script, row.outcome.maker_sats),
            (row.summary.anchor_script, row.outcome.anchor_sats),
        ] {
            let previous = outputs.get(&script).copied().unwrap_or(0);
            outputs.insert(script, money_add(previous, value, "aggregated output")?);
        }
    }
    let mut bytes = Vec::with_capacity(16 + rows.len() * 180);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.push(rows.len() as u8); // 1..32, canonical CompactSize
    for row in rows {
        bytes.extend(row.summary.funding_txid.iter().rev());
        bytes.extend_from_slice(&row.summary.funding_vout.to_le_bytes());
        bytes.push(0); // empty scriptSig
        bytes.extend_from_slice(&0xfffffffdu32.to_le_bytes());
    }
    bytes.push(outputs.len() as u8); // at most 96, canonical CompactSize
    for (script, value) in outputs {
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.push(34);
        bytes.extend_from_slice(&script);
    }
    bytes.extend_from_slice(&maturity.to_le_bytes());
    Ok(bytes)
}

pub fn verify_batch(batch: &BatchWitness) -> Result<Journal> {
    let context = &batch.context;
    validate_context(context, batch.rows.len())?;
    let mut previous_outpoint = None;
    let mut ids = BTreeSet::new();
    let mut current_nullifier_root = context.old_nullifier_root;
    let mut total_collateral = 0;
    let mut total_payout = 0;
    let mut total_fee = 0;

    for row in &batch.rows {
        let s = &row.summary;
        validate_summary(s, context)?;
        let outpoint = (s.funding_txid, s.funding_vout);
        if previous_outpoint.is_some_and(|previous| previous >= outpoint) {
            return Err("funding outpoints must be unique and canonically sorted".to_owned());
        }
        previous_outpoint = Some(outpoint);
        if !ids.insert(s.contract_id) {
            return Err("duplicate contract ID".to_owned());
        }
        let summary_hash = summary_digest(s);
        verify_bip340(&s.trader_key, &summary_hash, &row.summary_signatures[0])?;
        verify_bip340(&s.maker_key, &summary_hash, &row.summary_signatures[1])?;

        let o = &row.outcome;
        if o.index >= s.outcome_count || o.message == [0; 32] {
            return Err("invalid selected outcome".to_owned());
        }
        for value in [o.trader_sats, o.maker_sats, o.anchor_sats] {
            if !(MIN_OUTPUT_SATS..=MAX_MONEY).contains(&value) {
                return Err("payout/anchor must be a bounded non-dust P2TR amount".to_owned());
            }
        }
        if o.fee_sats == 0 || o.fee_sats > MAX_ROW_FEE_SATS {
            return Err("invalid committed miner fee".to_owned());
        }
        let payout = money_add(
            money_add(o.trader_sats, o.maker_sats, "payout")?,
            o.anchor_sats,
            "payout",
        )?;
        if money_add(payout, o.fee_sats, "collateral tie-out")? != s.collateral_sats {
            return Err("selected payout and fee do not conserve collateral".to_owned());
        }
        merkle::verify_outcome_membership(s, o, &row.outcome_siblings)?;
        let a = &row.oracle_attestations;
        if a[0].oracle_index >= a[1].oracle_index || a[1].oracle_index >= 3 {
            return Err(
                "exactly two distinct sorted pinned oracle indices are required".to_owned(),
            );
        }
        let oracle_hash = oracle_message(s, o);
        for attestation in a {
            verify_bip340(
                &s.oracle_keys[attestation.oracle_index as usize],
                &oracle_hash,
                &attestation.signature,
            )?;
        }
        let consent = batch_consent_message(context, s);
        verify_bip340(&s.trader_key, &consent, &row.batch_signatures[0])?;
        verify_bip340(&s.maker_key, &consent, &row.batch_signatures[1])?;

        current_nullifier_root = merkle::consume_nullifier(
            &outpoint_nullifier(s),
            &row.nullifier_siblings,
            &current_nullifier_root,
        )?;
        total_collateral = money_add(total_collateral, s.collateral_sats, "total collateral")?;
        total_payout = money_add(total_payout, payout, "total payout")?;
        total_fee = money_add(total_fee, o.fee_sats, "total fee")?;
    }
    if accepted_contracts_root(&batch.rows)? != context.accepted_contracts_root {
        return Err("accepted contracts root does not cover exactly all submitted rows".to_owned());
    }
    if current_nullifier_root != context.new_nullifier_root {
        return Err("final consumed-authorization root mismatch".to_owned());
    }
    let tx = unsigned_batch_transaction(&batch.rows)?;
    let tx_digest = sha256(&tx);
    if tx_digest != context.batch_tx_digest {
        return Err("unsigned batch transaction digest mismatch".to_owned());
    }
    let mut txid = sha256(&tx_digest);
    txid.reverse();
    Ok(Journal {
        domain: statement_domain(),
        epoch: context.epoch,
        batch_id: context.batch_id,
        evaluation_height: context.evaluation_height,
        valid_until_height: context.valid_until_height,
        row_count: context.row_count,
        accepted_contracts_root: context.accepted_contracts_root,
        old_nullifier_root: context.old_nullifier_root,
        new_nullifier_root: context.new_nullifier_root,
        batch_tx_digest: tx_digest,
        batch_txid: txid,
        total_collateral_sats: total_collateral,
        total_payout_sats: total_payout,
        total_fee_sats: total_fee,
    })
}

/// Shared entry point used by native validation and the zkVM guest.
pub fn verify_batch_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let witness = decode_batch(bytes)?;
    Ok(encode_journal(&verify_batch(&witness)?))
}

pub fn verify_expected_journal(bytes: &[u8], pins: &JournalPins) -> Result<Journal> {
    let j = decode_journal(bytes)?;
    if j.domain != statement_domain()
        || j.epoch != pins.epoch
        || j.batch_id != pins.batch_id
        || j.evaluation_height != pins.evaluation_height
        || j.valid_until_height != pins.valid_until_height
        || j.row_count != pins.row_count
        || j.accepted_contracts_root != pins.accepted_contracts_root
        || j.old_nullifier_root != pins.old_nullifier_root
        || j.batch_tx_digest != pins.batch_tx_digest
    {
        return Err("journal differs from independently retained application pins".to_owned());
    }
    if j.row_count == 0
        || j.row_count as usize > MAX_ROWS
        || j.epoch == 0
        || j.evaluation_height == 0
        || j.evaluation_height > j.valid_until_height
        || j.valid_until_height >= 500_000_000
        || j.batch_id == [0; 32]
    {
        return Err("invalid journal context".to_owned());
    }
    if money_add(j.total_payout_sats, j.total_fee_sats, "journal tie-out")?
        != j.total_collateral_sats
    {
        return Err("journal collateral tie-out mismatch".to_owned());
    }
    Ok(j)
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
