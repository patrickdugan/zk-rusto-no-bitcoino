//! CPU measurements of authenticated local predicates and the N=7/M=3 soldering pilot.
//! Bitcoin samples measure serialization; the Pasta relation covers one local EC step.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{ensure, Context, Result};
use babe_pilot::{
    bitcoin_script::{
        build_assert_labels_taptree, build_disprove_taptree, measure_pilot_bitcoin_paths,
        sample_xonly_pubkey, BitcoinDisputeMeasurements, TxMeasurement,
        MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
    },
    dispute_circuit::{
        eval_indexed_dispute_circuit, eval_pasta_window_ec_step, execute_boolean_circuit,
        IndexedDisputeSpec, PastaWindowTable, PILOT_INPUT_BITS,
    },
    gates::W,
    protocol::{
        resolve_dispute, verify_public_setup, CutAndChoosePartition, DisputeResolution,
        GarblerSession, PILOT_OPENED_INSTANCES, PILOT_RETAINED_INSTANCES, PILOT_TOTAL_INSTANCES,
    },
    soldering::{pilot_soldering_keys, SolderingTimings},
};
use bitcoin::{
    absolute::LockTime, hashes::Hash, secp256k1::XOnlyPublicKey, taproot::LeafVersion,
    transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use garbled_snark_verifier::{
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitContext, CircuitInput,
        CircuitMode, EncodeInput, EvaluateMode, StreamingResult,
    },
    AesCcrGateHasher, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, S,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_CONSENSUS_TAPSCRIPT_STACK_ITEMS: usize = 1_000;
const MAX_STANDARD_TX_WEIGHT_WU: u64 = 400_000;
const CHUNK_WIRES_PER_INPUT: usize = 480; // local cap; 1 signature + 480 labels

// --------------------------------------------------------------------------------------------
// Standalone Single-Circuit Garble / Evaluate Harness (for isolated per-circuit timings)
// --------------------------------------------------------------------------------------------

struct BenchGInput(usize);
impl CircuitInput for BenchGInput {
    type WireRepr = Vec<W>;
    fn allocate(&self, mut issue: impl FnMut() -> W) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<W> {
        w.clone()
    }
}
impl<H: GateHasher, CTH: CiphertextHandler> EncodeInput<GarbleMode<H, CTH>> for BenchGInput {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut GarbleMode<H, CTH>) {
        for &w in wires {
            let gw = mode.issue_garbled_wire();
            mode.feed_wire(w, gw);
        }
    }
}

struct BenchEInput<'a> {
    labels: &'a [S],
    bits: &'a [bool],
}
impl CircuitInput for BenchEInput<'_> {
    type WireRepr = Vec<W>;
    fn allocate(&self, mut issue: impl FnMut() -> W) -> Self::WireRepr {
        (0..self.bits.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<W> {
        w.clone()
    }
}
impl<H: GateHasher, SRC: CiphertextSource> EncodeInput<EvaluateMode<H, SRC>> for BenchEInput<'_> {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut EvaluateMode<H, SRC>) {
        for (i, &w) in wires.iter().enumerate() {
            mode.feed_wire(w, EvaluatedWire::new(self.labels[i], self.bits[i]));
        }
    }
}

#[derive(Default)]
struct BenchCtSink {
    entries: Vec<[u8; 16]>,
}
impl CiphertextHandler for BenchCtSink {
    type Result = Vec<[u8; 16]>;
    fn handle(&mut self, ct: S) {
        self.entries.push(ct.to_le_bytes());
    }
    fn finalize(self) -> Self::Result {
        self.entries
    }
}

struct BenchCtSource<'a> {
    entries: &'a [[u8; 16]],
    cursor: usize,
}
impl CiphertextSource for BenchCtSource<'_> {
    type Result = usize;
    fn recv(&mut self) -> Option<S> {
        let bytes = self.entries.get(self.cursor)?;
        self.cursor += 1;
        Some(S::from_le_bytes(*bytes))
    }
    fn finalize(self) -> Self::Result {
        self.cursor
    }
}

#[derive(Debug, Clone, Serialize)]
struct SingleCircuitMeasurement {
    circuit_name: String,
    scope: &'static str,
    measurement_kind: &'static str,
    input_wires: usize,
    non_free_gates_execute: usize,
    non_free_gates_garble_ciphertexts: usize,
    ciphertext_bytes_per_circuit: u64,
    base_tap_hashlock_bytes_per_circuit: u64,
    active_label_delivery_raw_bytes: u64,
    plain_execute_seconds: f64,
    single_garble_seconds: f64,
    single_evaluate_seconds: f64,
}

trait BenchCircuit {
    fn eval<C: CircuitContext>(&self, c: &mut C, wires: &[W]) -> Vec<W>;
}

struct PilotBenchCircuit<'a>(&'a IndexedDisputeSpec);
impl BenchCircuit for PilotBenchCircuit<'_> {
    fn eval<C: CircuitContext>(&self, c: &mut C, wires: &[W]) -> Vec<W> {
        eval_indexed_dispute_circuit(c, self.0, wires)
    }
}

struct PastaEcBenchCircuit<'a>(&'a PastaWindowTable);
impl BenchCircuit for PastaEcBenchCircuit<'_> {
    fn eval<C: CircuitContext>(&self, c: &mut C, wires: &[W]) -> Vec<W> {
        eval_pasta_window_ec_step(c, self.0, wires)
    }
}

fn benchmark_single_circuit<B: BenchCircuit>(
    name: &str,
    input_bits: &[bool],
    capacity: usize,
    circuit: &B,
) -> Result<SingleCircuitMeasurement> {
    let t_exec = Instant::now();
    let (plain_out, non_free_gates_execute) =
        execute_boolean_circuit(input_bits.to_vec(), |c, w| circuit.eval(c, w));
    let plain_execute_seconds = t_exec.elapsed().as_secs_f64();

    let seed = [0x42u8; 32];
    let t_garble = Instant::now();
    let mode =
        GarbleMode::<AesCcrGateHasher, _>::new_with_seed(capacity, seed, BenchCtSink::default());
    let salt = *mode.gate_hasher_seed();
    let garbled: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::run_streaming(BenchGInput(input_bits.len()), mode, |c, w| {
            circuit.eval(c, w)
        });
    let single_garble_seconds = t_garble.elapsed().as_secs_f64();

    let ciphertexts = garbled.ciphertext_handler_result;
    let non_free_gates_garble_ciphertexts = ciphertexts.len();
    ensure!(
        non_free_gates_execute == non_free_gates_garble_ciphertexts,
        "{name}: ExecuteMode gate count ({non_free_gates_execute}) != GarbleMode ciphertexts ({non_free_gates_garble_ciphertexts})"
    );

    let active_labels: Vec<S> = garbled
        .input_wire_values
        .iter()
        .zip(input_bits)
        .map(|(gw, &b)| gw.select(b))
        .collect();
    let expected_out_label = garbled.output_value[0].select(plain_out[0]);
    let true_const = garbled.true_wire_constant.select(true).to_u128();
    let false_const = garbled.false_wire_constant.select(false).to_u128();

    let t_eval = Instant::now();
    let evaluated: StreamingResult<_, _, Vec<EvaluatedWire>> = CircuitBuilder::streaming_evaluation(
        BenchEInput {
            labels: &active_labels,
            bits: input_bits,
        },
        capacity,
        true_const,
        false_const,
        AesCcrGateHasher::from_seed(salt),
        BenchCtSource {
            entries: &ciphertexts,
            cursor: 0,
        },
        |c, w| circuit.eval(c, w),
    );
    let single_evaluate_seconds = t_eval.elapsed().as_secs_f64();
    ensure!(
        evaluated.ciphertext_handler_result == ciphertexts.len(),
        "{name}: evaluator did not consume full ciphertext stream"
    );
    ensure!(
        evaluated.output_value[0].active_label == expected_out_label,
        "{name}: evaluated active output label mismatch"
    );

    let w = input_bits.len() as u64;
    let ct_bytes = (non_free_gates_garble_ciphertexts as u64) * 16;
    Ok(SingleCircuitMeasurement {
        circuit_name: name.into(),
        scope: "single_garbled_circuit",
        measurement_kind: "measured_cpu_execution",
        input_wires: input_bits.len(),
        non_free_gates_execute,
        non_free_gates_garble_ciphertexts,
        ciphertext_bytes_per_circuit: ct_bytes,
        base_tap_hashlock_bytes_per_circuit: w * 64,
        active_label_delivery_raw_bytes: w * 16,
        plain_execute_seconds,
        single_garble_seconds,
        single_evaluate_seconds,
    })
}

// --------------------------------------------------------------------------------------------
// Linux Process Memory (`VmHWM` / `VmRSS`) & Disk Footprint Helpers
// --------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct SystemResourceMetrics {
    peak_rss_kib: Option<u64>,
    current_rss_kib: Option<u64>,
    peak_rss_mib: Option<f64>,
    on_disk_public_setup_bytes: u64,
    on_disk_verifier_key_bytes: u64,
    on_disk_active_label_delivery_bytes: u64,
    on_disk_total_artifact_dir_bytes: u64,
}

fn read_linux_proc_kib(key: &str) -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let num_str = rest.split_whitespace().next()?;
            return num_str.parse::<u64>().ok();
        }
    }
    None
}

// --------------------------------------------------------------------------------------------
// Scaled Bitcoin Taproot Witness Construction (`W = 3,832` Chunked + `M = 39` Taptree)
// --------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct MultiInputTxMeasurement {
    name: String,
    measurement_kind: &'static str,
    num_inputs: usize,
    wires_per_input_max: usize,
    total_wires: usize,
    vsize: usize,
    weight_wu: u64,
    total_bytes: usize,
    total_script_bytes: usize,
    max_initial_stack_items_per_input: usize,
    max_initial_stack_item_bytes: usize,
    initial_stack_count_within_limit: bool,
    initial_stack_items_within_policy_bounds: bool,
    transaction_weight_within_policy_bound: bool,
    consensus_verified: bool,
    standardness_verified: bool,
}

fn measure_chunked_assert_labels_tx(
    name: &str,
    total_wires: usize,
    chunk_wires: usize,
) -> MultiInputTxMeasurement {
    let op_pk: XOnlyPublicKey = sample_xonly_pubkey(11);
    let ch_pk: XOnlyPublicKey = sample_xonly_pubkey(12);
    let dummy_sig = vec![0x42u8; 64];

    let num_chunks = total_wires.div_ceil(chunk_wires);
    let mut tx_inputs = Vec::with_capacity(num_chunks);
    let mut total_script_bytes = 0usize;
    let mut max_stack_items_per_input = 0usize;
    let mut max_item_bytes = 0usize;

    let mut last_output_script = None;

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_wires;
        let end = ((chunk_idx + 1) * chunk_wires).min(total_wires);
        let w_len = end - start;

        let mut hashlocks = Vec::with_capacity(w_len);
        let mut labels = Vec::with_capacity(w_len);
        let mut bits = Vec::with_capacity(w_len);

        for i in start..end {
            let mut l0 = [0u8; 16];
            let mut l1 = [0u8; 16];
            l0[..8].copy_from_slice(&(i as u64).to_le_bytes());
            l1[..8].copy_from_slice(&((i as u64) ^ 0xffff_ffff_ffff_ffff).to_le_bytes());
            let h0: [u8; 32] = Sha256::digest(l0).into();
            let h1: [u8; 32] = Sha256::digest(l1).into();
            let bit = (i & 1) == 1;
            hashlocks.push((h0, h1));
            labels.push(if bit { l1 } else { l0 });
            bits.push(bit);
        }

        let (spend_info, lamp_script, _) =
            build_assert_labels_taptree(&hashlocks, &bits, &op_pk, &ch_pk, 6)
                .expect("fixed benchmark input within local construction limits");
        let cb = spend_info
            .control_block(&(lamp_script.clone(), LeafVersion::TapScript))
            .expect("lamp_script in Taptree")
            .serialize();

        let mut stack: Vec<Vec<u8>> = Vec::with_capacity(1 + w_len + 2);
        stack.push(dummy_sig.clone());
        for j in (0..w_len).rev() {
            stack.push(labels[j].to_vec());
        }
        let initial_items = stack.len();
        max_stack_items_per_input = max_stack_items_per_input.max(initial_items);
        for it in &stack {
            max_item_bytes = max_item_bytes.max(it.len());
        }
        total_script_bytes += lamp_script.len();

        stack.push(lamp_script.to_bytes());
        stack.push(cb);

        let mut witness = Witness::new();
        for item in &stack {
            witness.push(item.as_slice());
        }

        if last_output_script.is_none() {
            last_output_script = Some(ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        }

        tx_inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: chunk_idx as u32,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        });
    }

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: vec![TxOut {
            value: Amount::from_sat(198_000),
            script_pubkey: last_output_script.expect("at least one chunk"),
        }],
    };
    let weight_wu = tx.weight().to_wu();

    MultiInputTxMeasurement {
        name: name.into(),
        measurement_kind: "serialization-only",
        num_inputs: num_chunks,
        wires_per_input_max: chunk_wires,
        total_wires,
        vsize: tx.vsize(),
        weight_wu,
        total_bytes: bitcoin::consensus::serialize(&tx).len(),
        total_script_bytes,
        max_initial_stack_items_per_input: max_stack_items_per_input,
        max_initial_stack_item_bytes: max_item_bytes,
        initial_stack_count_within_limit: max_stack_items_per_input
            <= MAX_CONSENSUS_TAPSCRIPT_STACK_ITEMS,
        initial_stack_items_within_policy_bounds: max_item_bytes
            <= MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
        transaction_weight_within_policy_bound: weight_wu <= MAX_STANDARD_TX_WEIGHT_WU,
        consensus_verified: false,
        standardness_verified: false,
    }
}

fn measure_m39_disprove_and_payout() -> (TxMeasurement, TxMeasurement) {
    let op_pk = sample_xonly_pubkey(21);
    let ch_pk = sample_xonly_pubkey(22);
    let dummy_sig = vec![0x42u8; 64];

    // 39 retained instances + 1 CSV payout leaf = 40-leaf balanced Taptree (depths 5 and 6).
    // Measure worst-case deepest leaf (`slot = 38`, depth 6).
    let preimage_38 = [0xaau8; 16];
    let mut refute_hashes: Vec<[u8; 32]> = (0..39u8)
        .map(|idx| Sha256::digest([idx; 16]).into())
        .collect();
    refute_hashes[38] = Sha256::digest(preimage_38).into();

    let (info, disprove_scripts, payout_script) =
        build_disprove_taptree(&refute_hashes, &ch_pk, &op_pk, 6);
    let p2tr_dest = ScriptBuf::new_p2tr_tweaked(info.output_key());

    let build_meas =
        |name: &str, seq: Sequence, mut stack: Vec<Vec<u8>>, leaf: &ScriptBuf| -> TxMeasurement {
            let max_initial_stack_item_bytes = stack.iter().map(|it| it.len()).max().unwrap_or(0);
            let cb = info
                .control_block(&(leaf.clone(), LeafVersion::TapScript))
                .expect("leaf present")
                .serialize();
            let initial_stack_items = stack.len();
            stack.push(leaf.to_bytes());
            stack.push(cb.clone());
            let mut wit = Witness::new();
            for it in &stack {
                wit.push(it.as_slice());
            }
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::all_zeros(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: seq,
                    witness: wit,
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(198_000),
                    script_pubkey: p2tr_dest.clone(),
                }],
            };
            TxMeasurement {
                name: name.into(),
                vsize: tx.vsize(),
                weight_wu: tx.weight().to_wu(),
                total_bytes: bitcoin::consensus::serialize(&tx).len(),
                witness_items: stack.len(),
                script_bytes: leaf.len(),
                control_block_bytes: cb.len(),
                max_initial_stack_item_bytes,
                initial_stack_items,
                initial_stack_items_within_policy_bounds: max_initial_stack_item_bytes
                    <= MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
                consensus_verified: false,
                standardness_verified: false,
                evidence_kind: "serialization-only".into(),
            }
        };

    let disprove_m39 = build_meas(
        "DisproveTx_M39_worst_case_depth6 (1-of-39 refute hashlock)",
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        vec![dummy_sig.clone(), preimage_38.to_vec()],
        &disprove_scripts[38],
    );
    let payout_m39 = build_meas(
        "OperatorPayoutTx_M39_depth6 (CSV D_3=6)",
        Sequence::from_height(6),
        vec![dummy_sig],
        &payout_script,
    );
    (disprove_m39, payout_m39)
}

// --------------------------------------------------------------------------------------------
// Top-Level JSON Report Schema
// --------------------------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct LocalProtocolMetrics {
    scope: &'static str,
    measurement_kind: &'static str,
    total_instances_n: usize,
    retained_instances_m: usize,
    opened_instances: usize,
    input_wires: usize,
    total_generated_ciphertext_bytes: u64,
    generated_ciphertexts_headers_and_hashlocks_bytes_all_n: u64,
    retained_ciphertext_bytes: u64,
    opened_seeds_payload_bytes: u64,
    base_tap_hashlock_table_bytes: u64,
    soldering_deltas_payload_bytes: u64,
    compressed_snark_proof_bytes: usize,
    compressed_snark_vk_bytes: usize,
    finalized_public_setup_bincode_bytes: u64,
    active_base_label_delivery_raw_bytes: u64,
    active_base_label_delivery_bincode_bytes: u64,
    naive_unsoldered_m_label_delivery_raw_bytes: u64,
    active_label_payload_reduction_factor: f64,
    garble_all_n_seconds: f64,
    nova_certificate_timings: SolderingTimings,
    challenger_setup_verify_total_seconds: f64,
    challenger_dispute_eval_all_m_seconds: f64,
    public_setup_and_verifier_key_bytes: u64,
}

#[derive(Debug, Serialize)]
struct PilotReport {
    protocol_id: &'static str,
    schema_version: u32,
    provenance: serde_json::Value,
    scope_limitations: Vec<&'static str>,
    single_circuit_measurements: Vec<SingleCircuitMeasurement>,
    local_protocol: LocalProtocolMetrics,
    system_resources: SystemResourceMetrics,
    bitcoin_witness_measured_pilot_n7_m3_w128: BitcoinDisputeMeasurements,
    bitcoin_witness_measured_pasta_ec_w3832_chunked: MultiInputTxMeasurement,
    bitcoin_witness_measured_m39_disprove: TxMeasurement,
    bitcoin_witness_measured_m39_operator_payout: TxMeasurement,
}

fn source_provenance(crate_dir: &Path) -> Result<serde_json::Value> {
    fn add_sources(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                add_sources(&path, paths)?;
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                paths.push(path);
            }
        }
        Ok(())
    }
    let mut paths = vec![crate_dir.join("Cargo.toml"), crate_dir.join("Cargo.lock")];
    add_sources(&crate_dir.join("src"), &mut paths)?;
    add_sources(&crate_dir.join("tests"), &mut paths)?;
    paths.sort();
    let mut aggregate = Sha256::new();
    let mut files = Vec::new();
    for path in paths {
        let name = path.strip_prefix(crate_dir)?.to_string_lossy();
        let digest = hex::encode(Sha256::digest(fs::read(&path)?));
        aggregate.update(name.as_bytes());
        aggregate.update([0]);
        aggregate.update(digest.as_bytes());
        aggregate.update([0]);
        files.push(serde_json::json!({"path": name, "sha256": digest}));
    }
    let command = |program: &str, args: &[&str]| -> Option<String> {
        let out = Command::new(program)
            .args(args)
            .current_dir(crate_dir)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    Ok(serde_json::json!({
        "source_commit": command("git", &["rev-parse", "HEAD"]),
        "source_files_sha256": hex::encode(aggregate.finalize()),
        "source_files": files,
        "rustc": command("rustc", &["--version"]),
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "rayon_num_threads": std::env::var("RAYON_NUM_THREADS").ok(),
        "available_cpu_parallelism": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "gpu_used": false,
        "optimized_build": !cfg!(debug_assertions),
        "unix_timestamp_seconds": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs()),
        "fixture_randomness": "deterministic test seeds; unsuitable for funded sessions"
    }))
}

fn main() -> Result<()> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let out_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| crate_dir.join("RESULTS.json"));

    // 1. Measure single-circuit costs on both `IndexedDisputeCircuit` (W=128) and
    //    `PastaWindowEcStep` (255-bit Pallas/Vesta `w = 4`-bit witness-assisted affine step, W=3,832):
    let (mut spec, honest_inputs) = IndexedDisputeSpec::sample_honest_trace([0xa5u8; 32]);
    let mut bad_inp = honest_inputs[5].clone();
    bad_inp.s_out ^= 1;
    spec.commit_step(&bad_inp); // invalid operator claim committed before setup
    let pilot_bits = bad_inp.to_bits();
    ensure!(pilot_bits.len() == PILOT_INPUT_BITS);

    let single_pilot = benchmark_single_circuit(
        "babe_pilot::eval_indexed_dispute_circuit (16-slot SHA-256 + M31 witness check)",
        &pilot_bits,
        32_768,
        &PilotBenchCircuit(&spec),
    )?;

    let (pasta_tbl, pasta_wit) = PastaWindowTable::sample_valid();
    let pasta_bits = pasta_wit.to_bits();
    let single_pasta_ec = benchmark_single_circuit(
        "babe_pilot::eval_pasta_window_ec_step (255-bit Pasta w=4 witness-assisted affine EC + SHA-256)",
        &pasta_bits,
        65_536,
        &PastaEcBenchCircuit(&pasta_tbl),
    )?;

    // 2. Measure full `(N=7, M=3)` adversarial C&C + transparent Nova/Spartan `CompressedSNARK` protocol:
    let session_id = [0x33u8; 32];
    let nonce = [0x44u8; 32];

    let t_garble_n = Instant::now();
    let mut garbler = GarblerSession::setup(session_id, spec.clone(), [0x88u8; 32]);
    let garble_all_n_seconds = t_garble_n.elapsed().as_secs_f64();

    let expected_commit1 = garbler.pre_challenge_manifest().commit1_digest()?;
    let (public_setup, mut timings) = garbler.finalize_cut_and_choose(nonce)?;
    let delivery = garbler.release_active_base_labels(nonce, &pilot_bits)?;
    drop(garbler);

    let t_ch_setup = Instant::now();
    let verified =
        verify_public_setup(&session_id, &spec, &expected_commit1, &nonce, &public_setup)?;
    let challenger_setup_verify_total_seconds = t_ch_setup.elapsed().as_secs_f64();
    timings.verify_seconds = verified.snark_verify_seconds();

    let t_ch_eval = Instant::now();
    let resolution = resolve_dispute(&verified, &pilot_bits, Some(&delivery))?;
    let challenger_dispute_eval_all_m_seconds = t_ch_eval.elapsed().as_secs_f64();

    let (win_inst, refute_preimage) = match resolution {
        DisputeResolution::AuthenticatedRefutation {
            winning_instance_index,
            refute_preimage,
            ..
        } => (winning_instance_index, refute_preimage),
        other => anyhow::bail!("expected AuthenticatedRefutation, got {other:?}"),
    };

    // 3. Serialize artifacts to temporary directory on disk to measure exact disk usage + RSS:
    let tmp_dir = std::env::temp_dir().join(format!("babe-pilot-bench-{}", std::process::id()));
    if tmp_dir.exists() {
        let _ = fs::remove_dir_all(&tmp_dir);
    }
    fs::create_dir_all(&tmp_dir)?;
    let setup_bytes = bincode::serialize(&public_setup)?;
    let delivery_bytes = bincode::serialize(&delivery)?;
    let setup_file = tmp_dir.join("finalized_public_setup.bin");
    let delivery_file = tmp_dir.join("active_base_labels.bin");
    let vk_bytes = bincode::serialize(&pilot_soldering_keys().vk)?;
    ensure!(
        vk_bytes.len() == timings.vk_bytes,
        "verifier key size mismatch"
    );
    let vk_file = tmp_dir.join("verifier_key.bin");
    fs::write(&setup_file, &setup_bytes)?;
    fs::write(&delivery_file, &delivery_bytes)?;
    fs::write(&vk_file, &vk_bytes)?;

    let on_disk_public_setup_bytes = fs::metadata(&setup_file)?.len();
    let on_disk_active_label_delivery_bytes = fs::metadata(&delivery_file)?.len();
    let on_disk_verifier_key_bytes = fs::metadata(&vk_file)?.len();
    let on_disk_total_artifact_dir_bytes = on_disk_public_setup_bytes
        + on_disk_active_label_delivery_bytes
        + on_disk_verifier_key_bytes;
    let _ = fs::remove_dir_all(&tmp_dir);

    let peak_rss_kib = read_linux_proc_kib("VmHWM:");
    let current_rss_kib = read_linux_proc_kib("VmRSS:");
    let peak_rss_mib = peak_rss_kib.map(|k| (k as f64) / 1024.0);

    // 4. Measure serialized Bitcoin Taproot witness sizes (Pilot W=128 M=3, Pasta W=3,832 chunked, and M=39 Disprove):
    let commit1 = public_setup.manifest.commit1_digest()?;
    let part = CutAndChoosePartition::derive(commit1, nonce);
    let retained = part.retained_indices();
    let win_slot = retained
        .iter()
        .position(|&idx| idx == win_inst)
        .expect("winning instance in retained");
    let refute_hashes: Vec<[u8; 32]> = retained
        .iter()
        .map(|&idx| public_setup.manifest.headers[idx].refute_output_sha256)
        .collect();

    let btc_pilot = measure_pilot_bitcoin_paths(
        &public_setup.base_tap_hashlocks,
        &pilot_bits,
        &delivery.active_labels,
        &refute_hashes,
        win_slot,
        &refute_preimage,
    )?;
    let btc_pasta_chunked = measure_chunked_assert_labels_tx(
        "AssertLabelsTx_PastaWindowEC_W3832_chunked480 (8 Taproot inputs)",
        pasta_bits.len(),
        CHUNK_WIRES_PER_INPUT,
    );
    let (btc_m39_disprove, btc_m39_payout) = measure_m39_disprove_and_payout();

    // 5. Byte totals for the executed local N=7/M=3 pilot:
    let ct_per = single_pilot.ciphertext_bytes_per_circuit;
    let manifest_bytes = bincode::serialize(&public_setup.manifest)?.len() as u64;
    let total_generated_ct_bytes = (PILOT_TOTAL_INSTANCES as u64) * ct_per;
    let generated_ciphertexts_headers_and_hashlocks_bytes_all_n = total_generated_ct_bytes
        + manifest_bytes
        + (PILOT_TOTAL_INSTANCES as u64) * single_pilot.base_tap_hashlock_bytes_per_circuit;
    let retained_ct_bytes = (PILOT_RETAINED_INSTANCES as u64) * ct_per;
    let soldering_deltas_bytes =
        ((PILOT_RETAINED_INSTANCES - 1) as u64) * ((PILOT_INPUT_BITS as u64) * 16 + 16);
    let active_raw_bytes = (PILOT_INPUT_BITS as u64) * 16;
    let naive_unsoldered_raw_bytes = (PILOT_RETAINED_INSTANCES as u64) * active_raw_bytes;

    let report = PilotReport {
        protocol_id: "RBZK-BABE-NOVA-PILOT-AUTHENTICATED-V2",
        schema_version: 2,
        provenance: source_provenance(&crate_dir)?,
        scope_limitations: vec![
            "N=7/M=3 CPU label-soldering and local-adjudication experiment; weak C&C parameters",
            "Pasta sample checks one authenticated Pallas addition; no complete Nova verifier or application proof",
            "Bitcoin measurements use dummy outpoints/signatures; consensus and relay acceptance unverified",
            "Fixed-input label leaf requires an enclosing graph to bind the selected input before funding",
            "Session nonce and input reservations are process-local; no crash/restart persistence",
            "No end-to-end speed or security comparison with M14, FC03, or BABE",
        ],
        single_circuit_measurements: vec![single_pilot, single_pasta_ec],
        local_protocol: LocalProtocolMetrics {
            scope: "local_authenticated_adjudication_and_soldering_N7_M3",
            measurement_kind: "measured_cpu_execution",
            total_instances_n: PILOT_TOTAL_INSTANCES,
            retained_instances_m: PILOT_RETAINED_INSTANCES,
            opened_instances: PILOT_OPENED_INSTANCES,
            input_wires: PILOT_INPUT_BITS,
            total_generated_ciphertext_bytes: total_generated_ct_bytes,
            generated_ciphertexts_headers_and_hashlocks_bytes_all_n,
            retained_ciphertext_bytes: retained_ct_bytes,
            opened_seeds_payload_bytes: (PILOT_OPENED_INSTANCES as u64) * 40,
            base_tap_hashlock_table_bytes: (PILOT_INPUT_BITS as u64) * 64,
            soldering_deltas_payload_bytes: soldering_deltas_bytes,
            compressed_snark_proof_bytes: timings.proof_bytes,
            compressed_snark_vk_bytes: timings.vk_bytes,
            finalized_public_setup_bincode_bytes: on_disk_public_setup_bytes,
            active_base_label_delivery_raw_bytes: active_raw_bytes,
            active_base_label_delivery_bincode_bytes: on_disk_active_label_delivery_bytes,
            naive_unsoldered_m_label_delivery_raw_bytes: naive_unsoldered_raw_bytes,
            active_label_payload_reduction_factor: (naive_unsoldered_raw_bytes as f64)
                / (active_raw_bytes as f64),
            garble_all_n_seconds,
            nova_certificate_timings: timings,
            challenger_setup_verify_total_seconds,
            challenger_dispute_eval_all_m_seconds,
            public_setup_and_verifier_key_bytes: on_disk_public_setup_bytes
                + on_disk_verifier_key_bytes,
        },
        system_resources: SystemResourceMetrics {
            peak_rss_kib,
            current_rss_kib,
            peak_rss_mib,
            on_disk_public_setup_bytes,
            on_disk_verifier_key_bytes,
            on_disk_active_label_delivery_bytes,
            on_disk_total_artifact_dir_bytes,
        },
        bitcoin_witness_measured_pilot_n7_m3_w128: btc_pilot,
        bitcoin_witness_measured_pasta_ec_w3832_chunked: btc_pasta_chunked,
        bitcoin_witness_measured_m39_disprove: btc_m39_disprove,
        bitcoin_witness_measured_m39_operator_payout: btc_m39_payout,

    };

    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&out_path, format!("{json}\n"))
        .with_context(|| format!("write {}", out_path.display()))?;
    println!(
        "Wrote authenticated pilot measurements to {}",
        out_path.display()
    );
    println!(
        "Indexed gates: {}; Pasta gates: {}; certificate bytes: {}",
        report.single_circuit_measurements[0].non_free_gates_execute,
        report.single_circuit_measurements[1].non_free_gates_execute,
        report.local_protocol.compressed_snark_proof_bytes
    );
    Ok(())
}
