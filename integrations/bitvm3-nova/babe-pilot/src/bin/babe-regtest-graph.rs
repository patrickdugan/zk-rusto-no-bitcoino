//! Staged JSON adapter for the isolated Bitcoin Core regtest harness.
//! Role secrets arrive on stdin and are never included in output. This binary constructs
//! and verifies connector signatures; Core supplies chain observation and script execution.

use std::{
    io::{self, Read},
    str::FromStr,
};

use anyhow::{ensure, Context, Result};
use babe_pilot::transaction_graph::{
    tx_hex, wrong_response_label, ChallengerPreSignatures, GraphChoice, GraphConfig,
    OperatorPreSignatures, PreparedGraph,
};
use bitcoin::{
    consensus::{deserialize, serialize},
    secp256k1::{Keypair, Secp256k1, SecretKey},
    OutPoint, Transaction, Witness,
};
use serde::Deserialize;
use serde_json::{json, Value};

const MAX_REQUEST_BYTES: u64 = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicFixture {
    session_id: String,
    commit1: String,
    catalog_hash: String,
    rows: Vec<GraphChoice>,
    base_hashlocks: Vec<[String; 2]>,
    retained_refute_hashes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refutation {
    slot: usize,
    preimage: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: String,
    fixture: PublicFixture,
    operator_secret: String,
    challenger_secret: String,
    operator_destination: String,
    challenger_destination: String,
    funding_sats: u64,
    challenge_fee_sats: u64,
    response_fee_sats: u64,
    terminal_fee_sats: u64,
    assertion_csv: u16,
    labels_csv: u16,
    payout_csv: u16,
    funding_outpoint: Option<String>,
    funding_transaction_hex: Option<String>,
    operator_presignatures: Option<OperatorPreSignatures>,
    challenger_presignatures: Option<ChallengerPreSignatures>,
    selected_index: Option<usize>,
    observed_challenge_hex: Option<String>,
    selected_active_labels: Option<Vec<String>>,
    refute: Option<Refutation>,
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(value.len() == N * 2, "hex field length mismatch");
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("hex field width mismatch"))
}

fn key(value: &str) -> Result<Keypair> {
    let secret = SecretKey::from_slice(&fixed::<32>(value)?)?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &secret))
}

fn summary(tx: &Transaction) -> Value {
    json!({
        "hex": tx_hex(tx), "txid": tx.compute_txid().to_string(),
        "wtxid": tx.compute_wtxid().to_string(), "vsize": tx.vsize(),
        "weight_wu": tx.weight().to_wu(), "serialized_bytes": serialize(tx).len(),
        "witness_items": tx.input[0].witness.len(),
    })
}

fn run(request: Request) -> Result<Value> {
    let operator = key(&request.operator_secret)?;
    let challenger = key(&request.challenger_secret)?;
    let config = GraphConfig {
        session_id: fixed(&request.fixture.session_id)?,
        commit1: fixed(&request.fixture.commit1)?,
        catalog_hash: fixed(&request.fixture.catalog_hash)?,
        choices: request.fixture.rows,
        base_hashlocks: request
            .fixture
            .base_hashlocks
            .iter()
            .map(|pair| Ok((fixed(&pair[0])?, fixed(&pair[1])?)))
            .collect::<Result<_>>()?,
        refute_hashes: request
            .fixture
            .retained_refute_hashes
            .iter()
            .map(|v| fixed(v))
            .collect::<Result<_>>()?,
        operator_key: operator.x_only_public_key().0.serialize(),
        challenger_key: challenger.x_only_public_key().0.serialize(),
        operator_destination: hex::decode(&request.operator_destination)?,
        challenger_destination: hex::decode(&request.challenger_destination)?,
        funding_sats: request.funding_sats,
        challenge_fee_sats: request.challenge_fee_sats,
        response_fee_sats: request.response_fee_sats,
        terminal_fee_sats: request.terminal_fee_sats,
        assertion_csv: request.assertion_csv,
        labels_csv: request.labels_csv,
        payout_csv: request.payout_csv,
    };
    config.validate()?;
    let digest = hex::encode(config.digest()?);
    if request.mode == "address" {
        ensure!(
            request.selected_index.is_none() && request.selected_active_labels.is_none(),
            "address phase must precede selection and delivery"
        );
        return Ok(
            json!({"address":config.regtest_address()?.to_string(), "script_pubkey":hex::encode(config.assertion_script_pubkey()?.as_bytes()), "graph_digest":digest}),
        );
    }
    let funding = OutPoint::from_str(
        request
            .funding_outpoint
            .as_deref()
            .context("funding outpoint required")?,
    )?;
    let graph = PreparedGraph::new(config, funding)?;
    match request.mode.as_str() {
        "prepare" => {
            ensure!(
                request.selected_index.is_none() && request.selected_active_labels.is_none(),
                "pre-signatures must precede selection and delivery"
            );
            let funding_hex = request
                .funding_transaction_hex
                .as_deref()
                .context("unbroadcast funding transaction required")?;
            ensure!(
                funding_hex.len() <= 100_000,
                "funding transaction exceeds bound"
            );
            let raw = hex::decode(funding_hex)?;
            let funding_tx: Transaction = deserialize(&raw)?;
            ensure!(
                serialize(&funding_tx) == raw && funding_tx.compute_txid() == funding.txid,
                "funding transaction id mismatch"
            );
            ensure!(
                funding_tx.output.get(funding.vout as usize) == Some(graph.funding_output()),
                "funding output differs from agreed graph"
            );
            let op = graph.presign_operator(&operator)?;
            // Rebuild from the expected configuration as an independent receiving role does.
            let verifier = PreparedGraph::new(graph.config().clone(), funding)?;
            verifier.verify_operator_presignatures(&op)?;
            let ch = verifier.presign_challenger(&op, &challenger)?;
            graph.verify_challenger_presignatures(&ch)?;
            let branches: Vec<_> = (0..graph.config().choices.len()).map(|index| {
                Ok(json!({"index":index, "challenge":summary(graph.unsigned_challenge(index)?), "response":summary(graph.unsigned_response(index)?)}))
            }).collect::<Result<_>>()?;
            Ok(
                json!({"graph_digest":digest, "graph_config":graph.config(), "operator_presignatures":op, "challenger_presignatures":ch, "branches":branches, "assertion_timeout":summary(&graph.assertion_timeout(&operator)?)}),
            )
        }
        "select" => {
            ensure!(
                request.selected_active_labels.is_none(),
                "selection phase cannot reveal labels"
            );
            let selected = request.selected_index.context("selected index required")?;
            let op = request
                .operator_presignatures
                .context("operator pre-signatures required")?;
            let ch = request
                .challenger_presignatures
                .context("challenger pre-signatures required")?;
            graph.verify_challenger_presignatures(&ch)?;
            let challenge = graph.complete_challenge(selected, &op, &challenger)?;
            ensure!(
                graph.observe_challenge(&tx_hex(&challenge))? == selected,
                "selected transaction mismatch"
            );
            let alternate = if graph.config().choices.len() > 1 {
                Some(summary(&graph.complete_challenge(
                    (selected + 1) % graph.config().choices.len(),
                    &op,
                    &challenger,
                )?))
            } else {
                None
            };
            Ok(
                json!({"graph_digest":digest, "selected_index":selected, "challenge":summary(&challenge), "alternate_challenge":alternate, "withholding":summary(&graph.withholding(selected, &challenger)?)}),
            )
        }
        "respond" => {
            let observed = request
                .observed_challenge_hex
                .context("Core-observed challenge required")?;
            let selected = graph.observe_challenge(&observed)?;
            ensure!(
                request.selected_index == Some(selected),
                "observed index differs from authorized selection"
            );
            let ch = request
                .challenger_presignatures
                .context("challenger pre-signatures required")?;
            let labels: Vec<[u8; 16]> = request
                .selected_active_labels
                .context("active labels required")?
                .iter()
                .map(|v| fixed(v))
                .collect::<Result<_>>()?;
            let response = graph.complete_response(selected, &ch, &operator, &labels)?;
            let redirected = graph.redirected_response_attempt(selected, &response, &operator)?;
            ensure!(
                graph
                    .verify_response_presignature_for(selected, &redirected, &ch)
                    .is_err(),
                "redirect unexpectedly retained authorization"
            );
            let (disprove, wrong_refute) = if let Some(refute) = request.refute {
                let tx =
                    graph.disprove(selected, refute.slot, fixed(&refute.preimage)?, &challenger)?;
                let mut changed = tx.clone();
                let mut stack: Vec<Vec<u8>> = changed.input[0]
                    .witness
                    .iter()
                    .map(|v| v.to_vec())
                    .collect();
                ensure!(
                    stack.len() == 4 && stack[1].len() == 16,
                    "unexpected disprove witness shape"
                );
                stack[1][0] ^= 1;
                changed.input[0].witness = Witness::from_slice(&stack);
                (Some(summary(&tx)), Some(summary(&changed)))
            } else {
                (None, None)
            };
            Ok(
                json!({"graph_digest":digest, "selected_index":selected, "response":summary(&response), "wrong_label_response":summary(&wrong_response_label(&response)?), "redirected_response":summary(&redirected), "operator_payout":summary(&graph.operator_payout(selected, &operator)?), "withholding":summary(&graph.withholding(selected, &challenger)?), "disprove":disprove, "wrong_refute":wrong_refute}),
            )
        }
        _ => anyhow::bail!("unknown phase; expected address, prepare, select, or respond"),
    }
}

fn main() -> Result<()> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_REQUEST_BYTES as usize,
        "JSON request exceeds bound"
    );
    let request: Request = serde_json::from_slice(&bytes).context("invalid graph request")?;
    let output = run(request)?;
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
