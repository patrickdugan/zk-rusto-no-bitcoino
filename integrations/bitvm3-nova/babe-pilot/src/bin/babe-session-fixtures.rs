//! Real Nova sessions for the funded regtest, with durable post-confirmation release.
//! The CLI and datadir in a release request are trusted local operator configuration.
//! Requests and public fixtures are bounded; role keys never enter this process.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

use anyhow::{ensure, Context, Result};
use babe_pilot::{
    challenge::{AuthenticatedCatalogue, CatalogueRow, ChainObservation, ChallengeChain},
    dispute_circuit::{IndexedDisputeInput, IndexedDisputeSpec},
    durable::{decode_bounded, DurableGarblerSession},
    journal::{read_private_blob, write_private_blob_once, JournalPins},
    protocol::{resolve_dispute, verify_public_setup, DisputeResolution, PreChallengeManifest},
    transaction_graph::{GraphConfig, PreparedGraph},
};
use bitcoin::{
    consensus::{deserialize, serialize},
    Amount, BlockHash, Denomination, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_CONTEXT: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct SavedContext {
    manifest: PreChallengeManifest,
    nonce: [u8; 32],
    openings: Vec<IndexedDisputeInput>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicFixture {
    session_id: String,
    commit1: String,
    catalog_hash: String,
    rows: Vec<CatalogueRow>,
    base_hashlocks: Vec<[String; 2]>,
    retained_refute_hashes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitRequest {
    state_path: PathBuf,
    public_fixture_path: PathBuf,
    scenario: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindGraphRequest {
    state_path: PathBuf,
    public_fixture_path: PathBuf,
    graph_config: GraphConfig,
    graph_digest: String,
    funding_outpoint: String,
}

#[derive(Serialize, Deserialize)]
struct BoundGraph {
    pins: JournalPins,
    config: GraphConfig,
    funding_outpoint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequest {
    state_path: PathBuf,
    public_fixture_path: PathBuf,
    graph_config: GraphConfig,
    graph_digest: String,
    funding_outpoint: String,
    selected_index: usize,
    challenge_transaction_hex: String,
    challenge_txid: String,
    block_hash: String,
    confirmation_height: u32,
    confirmations: u32,
    current_height: u32,
    bitcoin_cli_path: PathBuf,
    bitcoin_datadir: PathBuf,
}

fn anchor_path(state: &Path) -> PathBuf {
    let mut sibling = state.as_os_str().to_os_string();
    sibling.push(".authority");
    PathBuf::from(sibling).join("head.journal")
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create fresh private directory {}", path.display()))
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) -> Result<()> {
    anyhow::bail!("the private session fixture adapter requires a Unix filesystem")
}

fn random32() -> [u8; 32] {
    let mut out = [0; 32];
    OsRng.fill_bytes(&mut out);
    out
}

fn public_fixture(
    catalogue: &AuthenticatedCatalogue,
    setup: &babe_pilot::protocol::FinalizedPublicSetup,
) -> PublicFixture {
    PublicFixture {
        session_id: hex::encode(catalogue.pins().session_id),
        commit1: hex::encode(catalogue.pins().commit1),
        catalog_hash: hex::encode(catalogue.digest()),
        rows: catalogue.rows().to_vec(),
        base_hashlocks: setup
            .base_tap_hashlocks
            .iter()
            .map(|(a, b)| [hex::encode(a), hex::encode(b)])
            .collect(),
        retained_refute_hashes: catalogue.refute_hashes().iter().map(hex::encode).collect(),
    }
}

fn init(request: InitRequest) -> Result<Value> {
    ensure!(
        matches!(request.scenario.as_str(), "honest" | "refute"),
        "scenario must be honest or refute"
    );
    ensure!(
        request.state_path.is_absolute() && request.public_fixture_path.is_absolute(),
        "fixture paths must be absolute"
    );
    private_directory(&request.state_path)?;
    let authority = anchor_path(&request.state_path);
    private_directory(authority.parent().context("authority parent missing")?)?;
    let (mut spec, mut openings) = IndexedDisputeSpec::sample_honest_trace(random32());
    if request.scenario == "refute" {
        openings[5].s_out ^= 1;
        spec.commit_step(&openings[5]);
        ensure!(
            spec.native_refutes(&openings[5]),
            "fixture fault failed to change relation"
        );
    }
    let session_id = random32();
    let nonce = random32();
    let mut durable = DurableGarblerSession::create(
        &request.state_path,
        &authority,
        session_id,
        spec.clone(),
        random32(),
    )?;
    let manifest = durable.manifest();
    let context = SavedContext {
        manifest: manifest.clone(),
        nonce,
        openings: openings.to_vec(),
    };
    write_private_blob_once(
        request.state_path.join("context.bin"),
        &bincode::serialize(&context)?,
        MAX_CONTEXT,
    )?;
    let (setup, timings) = durable.finalize(nonce)?;
    let verified = verify_public_setup(
        &session_id,
        &spec,
        &manifest.commit1_digest()?,
        &nonce,
        &setup,
    )?;
    let catalogue = AuthenticatedCatalogue::from_openings(&verified, &openings)?;
    let public = public_fixture(&catalogue, &setup);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&request.public_fixture_path)?;
    output.write_all(&serde_json::to_vec_pretty(&public)?)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    let snapshot = durable.snapshot();
    // Deliberately end the process with the input unreserved. Release reconstructs
    // the session from private files and an independent authority after mining.
    ensure!(
        snapshot.input_sha256.is_none(),
        "initialization released an input"
    );
    Ok(
        json!({"scenario":request.scenario,"state_path":request.state_path,"anchor_path":authority,"public_fixture_path":request.public_fixture_path,"session_id":public.session_id,"commit1":public.commit1,"catalog_hash":public.catalog_hash,"journal_sequence":snapshot.head.sequence,"input_released":false,"timings":timings}),
    )
}

/// The operator invokes this while exchanging connector signatures, before
/// funding is broadcast. Its immutable file belongs to the trusted authority.
fn bind_graph(request: BindGraphRequest) -> Result<Value> {
    let context: SavedContext = decode_bounded(
        &read_private_blob(request.state_path.join("context.bin"), MAX_CONTEXT)?,
        MAX_CONTEXT,
    )?;
    let public: PublicFixture =
        serde_json::from_slice(&bounded_public_file(&request.public_fixture_path)?)?;
    let pins = JournalPins {
        session_id: context.manifest.session_id,
        circuit_id: context.manifest.spec.circuit_id,
        commit1: context.manifest.commit1_digest()?,
    };
    ensure!(
        hex::encode(pins.session_id) == public.session_id
            && hex::encode(pins.commit1) == public.commit1,
        "public pre-challenge pins differ from session"
    );
    let durable = DurableGarblerSession::open(
        &request.state_path,
        anchor_path(&request.state_path),
        pins,
        context.manifest.spec.clone(),
    )?;
    ensure!(
        durable.snapshot().input_sha256.is_none(),
        "session already released labels"
    );
    let setup = durable
        .public_setup()
        .context("session setup was not finalized")?;
    let verified = verify_public_setup(
        &pins.session_id,
        &context.manifest.spec,
        &pins.commit1,
        &context.nonce,
        setup,
    )?;
    let catalogue = AuthenticatedCatalogue::from_openings(&verified, &context.openings)?;
    ensure!(
        serde_json::to_value(&public)? == serde_json::to_value(public_fixture(&catalogue, setup))?,
        "public catalogue differs from verified setup"
    );
    catalogue.verify_graph(&request.graph_config)?;
    ensure!(
        hex::encode(request.graph_config.digest()?) == request.graph_digest,
        "graph digest mismatch"
    );
    let funding = OutPoint::from_str(&request.funding_outpoint)?;
    PreparedGraph::new(request.graph_config.clone(), funding)?;
    let bound = BoundGraph {
        pins,
        config: request.graph_config,
        funding_outpoint: funding.to_string(),
    };
    let authority = anchor_path(&request.state_path);
    write_private_blob_once(
        authority
            .parent()
            .context("authority directory missing")?
            .join("graph-reservation.bin"),
        &bincode::serialize(&bound)?,
        MAX_CONTEXT,
    )?;
    Ok(
        json!({"graph_digest":request.graph_digest,"funding_outpoint":bound.funding_outpoint,"commit1":hex::encode(pins.commit1),"graph_bound_before_release":true,"input_released":false}),
    )
}

fn bounded_public_file(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "public fixture must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_REQUEST, "public fixture exceeds limit");
    Ok(bytes)
}

struct CoreObserver {
    cli: PathBuf,
    datadir: PathBuf,
}

impl CoreObserver {
    fn rpc(&self, method: &str, args: &[String]) -> Result<Value> {
        let result = Command::new(&self.cli)
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg("-rpcclienttimeout=20")
            .arg(method)
            .args(args)
            .output()
            .context("invoke configured Bitcoin Core CLI")?;
        ensure!(
            result.stdout.len() <= 4 * MAX_REQUEST && result.stderr.len() <= MAX_REQUEST,
            "Core response exceeds limit"
        );
        ensure!(
            result.status.success(),
            "Core {method} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        if matches!(method, "getbestblockhash" | "getblockhash") {
            let value = std::str::from_utf8(&result.stdout)?.trim();
            BlockHash::from_str(value).context("invalid Core block hash")?;
            return Ok(Value::String(value.to_owned()));
        }
        serde_json::from_slice(&result.stdout).context("parse Core JSON response")
    }
    fn number(value: &Value, name: &str) -> Result<u32> {
        u32::try_from(
            value
                .get(name)
                .and_then(Value::as_u64)
                .with_context(|| format!("missing Core {name}"))?,
        )
        .context("Core height/count exceeds bound")
    }
}

impl ChallengeChain for CoreObserver {
    fn observe_challenge(&mut self, txid: Txid, output_index: u32) -> Result<ChainObservation> {
        let info = self.rpc("getblockchaininfo", &[])?;
        ensure!(
            info["chain"] == "regtest",
            "release adapter requires an isolated regtest node"
        );
        let tip_before = self.rpc("getbestblockhash", &[])?;
        let result = self.rpc("getrawtransaction", &[txid.to_string(), "true".into()])?;
        let raw_hex = result["hex"]
            .as_str()
            .context("Core omitted raw challenge")?;
        ensure!(
            raw_hex.len() <= MAX_REQUEST,
            "challenge transaction exceeds limit"
        );
        let raw = hex::decode(raw_hex)?;
        let transaction: Transaction = deserialize(&raw)?;
        ensure!(
            serialize(&transaction) == raw && transaction.compute_txid() == txid,
            "Core transaction identity mismatch"
        );
        let confirmations = Self::number(&result, "confirmations")?;
        ensure!(confirmations > 0, "challenge is unconfirmed");
        let block_hash = BlockHash::from_str(
            result["blockhash"]
                .as_str()
                .context("Core omitted confirming block")?,
        )?;
        let header = self.rpc("getblockheader", &[block_hash.to_string(), "true".into()])?;
        ensure!(
            Self::number(&header, "confirmations")? == confirmations,
            "confirming block is outside active chain"
        );
        let confirmation_height = Self::number(&header, "height")?;
        let active_hash = self.rpc("getblockhash", &[confirmation_height.to_string()])?;
        ensure!(
            active_hash.as_str() == Some(block_hash.to_string().as_str()),
            "challenge block is stale"
        );
        let unspent = self.rpc(
            "gettxout",
            &[txid.to_string(), output_index.to_string(), "true".into()],
        )?;
        let unspent_output = if unspent.is_null() {
            None
        } else {
            ensure!(
                unspent["bestblock"] == tip_before,
                "UTXO view changed during observation"
            );
            let sats =
                Amount::from_str_in(&unspent["value"].to_string(), Denomination::Bitcoin)?.to_sat();
            let script = hex::decode(
                unspent["scriptPubKey"]["hex"]
                    .as_str()
                    .context("Core omitted output script")?,
            )?;
            Some(TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::from_bytes(script),
            })
        };
        let tip_after = self.rpc("getbestblockhash", &[])?;
        ensure!(
            tip_after == tip_before && info["bestblockhash"] == tip_before,
            "chain changed during observation; retry"
        );
        Ok(ChainObservation {
            transaction,
            block_hash,
            confirmation_height,
            confirmations,
            current_height: Self::number(&info, "blocks")?,
            unspent_output,
        })
    }
}

fn release(request: ReleaseRequest) -> Result<Value> {
    ensure!(
        request.state_path.is_absolute()
            && request.bitcoin_cli_path.is_absolute()
            && request.bitcoin_datadir.is_absolute(),
        "release requires absolute trusted paths"
    );
    let context: SavedContext = decode_bounded(
        &read_private_blob(request.state_path.join("context.bin"), MAX_CONTEXT)?,
        MAX_CONTEXT,
    )?;
    let public_bytes = bounded_public_file(&request.public_fixture_path)?;
    let public: PublicFixture = serde_json::from_slice(&public_bytes)?;
    let pins = JournalPins {
        session_id: context.manifest.session_id,
        circuit_id: context.manifest.spec.circuit_id,
        commit1: context.manifest.commit1_digest()?,
    };
    ensure!(
        hex::encode(pins.session_id) == public.session_id
            && hex::encode(pins.commit1) == public.commit1,
        "public pre-challenge pins differ from recovery state"
    );
    let mut durable = DurableGarblerSession::open(
        &request.state_path,
        anchor_path(&request.state_path),
        pins,
        context.manifest.spec.clone(),
    )?;
    let authority = anchor_path(&request.state_path);
    let bound: BoundGraph = decode_bounded(
        &read_private_blob(
            authority
                .parent()
                .context("authority directory missing")?
                .join("graph-reservation.bin"),
            MAX_CONTEXT,
        )?,
        MAX_CONTEXT,
    )?;
    ensure!(
        bound.pins == pins
            && bound.funding_outpoint == request.funding_outpoint
            && bincode::serialize(&bound.config)? == bincode::serialize(&request.graph_config)?,
        "release graph differs from independent pre-funding reservation"
    );
    let setup = durable
        .public_setup()
        .context("session setup was not finalized")?
        .clone();
    let verified = verify_public_setup(
        &pins.session_id,
        &context.manifest.spec,
        &pins.commit1,
        &context.nonce,
        &setup,
    )?;
    let catalogue = AuthenticatedCatalogue::from_openings(&verified, &context.openings)?;
    ensure!(
        serde_json::to_value(&public)? == serde_json::to_value(public_fixture(&catalogue, &setup))?,
        "public catalogue differs from verified setup"
    );
    ensure!(
        hex::encode(request.graph_config.digest()?) == request.graph_digest,
        "graph digest mismatch"
    );
    let graph = PreparedGraph::new(bound.config, OutPoint::from_str(&bound.funding_outpoint)?)?;
    let mut observer = CoreObserver {
        cli: request.bitcoin_cli_path,
        datadir: request.bitcoin_datadir,
    };
    let authorized = catalogue.authorize_confirmed(
        &graph,
        &request.challenge_transaction_hex,
        &mut observer,
        1,
    )?;
    ensure!(
        authorized.selected_index() == request.selected_index
            && authorized.transaction_id().to_string() == request.challenge_txid,
        "observed challenge differs from requested selection"
    );
    ensure!(
        authorized.block_hash().to_string() == request.block_hash
            && authorized.confirmation_height() == request.confirmation_height,
        "confirmation location mismatch"
    );
    ensure!(
        request.confirmations > 0
            && request
                .current_height
                .checked_sub(request.confirmation_height)
                .and_then(|n| n.checked_add(1))
                == Some(request.confirmations),
        "claimed confirmation counts disagree"
    );
    let before = durable.snapshot();
    let delivery = durable.release(&authorized)?;
    let after = durable.snapshot();
    let resolution = resolve_dispute(&verified, authorized.input_bits(), Some(&delivery))?;
    let refute = match resolution {
        DisputeResolution::AuthenticatedRefutation {
            winning_instance_index,
            refute_preimage,
            ..
        } => {
            let slot = verified
                .partition()
                .retained_indices()
                .iter()
                .position(|&index| index == winning_instance_index)
                .context("retained refutation slot absent")?;
            Some(json!({"slot":slot,"preimage":hex::encode(refute_preimage)}))
        }
        DisputeResolution::NoAuthenticatedRefutation => None,
        other => anyhow::bail!("label delivery did not produce an evaluable dispute: {other:?}"),
    };
    Ok(
        json!({"selected_active_labels":delivery.active_labels.iter().map(hex::encode).collect::<Vec<_>>(), "refute":refute, "journal_sequence":after.head.sequence,"recovered_before_release":before.finalized_setup_sha256.is_some(),"release_was_exact_retry":before.input_sha256.is_some(),"authorization_sha256":hex::encode(authorized.digest()),"challenge_txid":authorized.transaction_id().to_string()}),
    )
}

fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .context("usage: babe-session-fixtures init|bind-graph|release < request.json")?;
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_REQUEST, "request exceeds limit");
    let result = match mode.as_str() {
        "init" => init(serde_json::from_slice(&bytes)?)?,
        "bind-graph" => bind_graph(serde_json::from_slice(&bytes)?)?,
        "release" => release(serde_json::from_slice(&bytes)?)?,
        _ => anyhow::bail!("unknown mode"),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
