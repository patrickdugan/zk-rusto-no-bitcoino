//! Phase 4 Architecture Benchmark Runner for the BABE-Inspired Transparent Nova Pilot.
//!
//! Measures and contrasts:
//! 1. Committed `M14` full garbled BLAKE3/STARK final verifier (`785,442,492` non-free gates);
//! 2. `FC03` (`flatcheck-lab`) authenticated local Nova checks (`7,285,647`-gate 1-bit `BindingStep`);
//! 3. `babe-pilot` transparent Nova/Spartan (`CompressedSNARK`) soldering pilot (`(N=7, M=3)` full
//!    adversarial C&C protocol vs single garbled circuit);
//! 4. Full 255-bit Pasta `w = 4`-bit windowed witness-assisted complete affine EC step (`W = 3,832` wires),
//!    including real multi-input chunked `AssertLabelsTx` and `40`-leaf `(M=39)` `DisproveTx` measurements.

use std::{
    fs,
    path::{Path, PathBuf},
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
    soldering::SolderingTimings,
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
const CHUNK_WIRES_PER_INPUT: usize = 480; // 1 sig + 2*480 = 961 <= 1,000 consensus stack items

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
    consensus_valid_stack_count: bool,
    core_31_standard_stack_items: bool,
    core_31_standard_tx_weight: bool,
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
            build_assert_labels_taptree(&hashlocks, &op_pk, &ch_pk, 6);
        let cb = spend_info
            .control_block(&(lamp_script.clone(), LeafVersion::TapScript))
            .expect("lamp_script in Taptree")
            .serialize();

        let mut stack: Vec<Vec<u8>> = Vec::with_capacity(1 + 2 * w_len + 2);
        stack.push(dummy_sig.clone());
        for j in (0..w_len).rev() {
            stack.push(labels[j].to_vec());
            stack.push(if bits[j] { vec![1u8] } else { vec![] });
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
        measurement_kind: "measured_constructed_taproot_tx",
        num_inputs: num_chunks,
        wires_per_input_max: chunk_wires,
        total_wires,
        vsize: tx.vsize(),
        weight_wu,
        total_bytes: bitcoin::consensus::serialize(&tx).len(),
        total_script_bytes,
        max_initial_stack_items_per_input: max_stack_items_per_input,
        max_initial_stack_item_bytes: max_item_bytes,
        consensus_valid_stack_count: max_stack_items_per_input
            <= MAX_CONSENSUS_TAPSCRIPT_STACK_ITEMS,
        core_31_standard_stack_items: max_item_bytes <= MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
        core_31_standard_tx_weight: weight_wu <= MAX_STANDARD_TX_WEIGHT_WU,
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
                core_31_standard_stack_items: max_initial_stack_item_bytes
                    <= MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
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
struct CommittedBaselineSummary {
    name: &'static str,
    proof_system: &'static str,
    setup_assumption: &'static str,
    source: &'static str,
    non_free_gates_per_circuit: u64,
    ciphertext_bytes_per_circuit: u64,
    input_wires: u64,
    single_circuit_active_label_bytes: u64,
    single_circuit_tap_hashlock_bytes: u64,
    analytical_cc_115_39_generated_ciphertext_bytes: u64,
    analytical_cc_115_39_retained_ciphertext_bytes: u64,
    notes: &'static str,
}

#[derive(Debug, Serialize)]
struct FullAdversarialPilotProtocolMetrics {
    scope: &'static str,
    measurement_kind: &'static str,
    total_instances_n: usize,
    retained_instances_m: usize,
    opened_instances: usize,
    input_wires: usize,
    total_generated_ciphertext_bytes: u64,
    total_generated_setup_bytes_all_n: u64,
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
    onchain_label_delivery_reduction_factor: f64,
    garble_all_n_seconds: f64,
    nova_certificate_timings: SolderingTimings,
    challenger_setup_verify_total_seconds: f64,
    challenger_dispute_eval_all_m_seconds: f64,
    challenger_public_data_download_bytes: u64,
}

#[derive(Debug, Serialize)]
struct AnalyticalProductionProjection {
    target_name: &'static str,
    measurement_kind: &'static str,
    cc_total_instances_n: u64,
    cc_retained_instances_m: u64,
    non_free_gates_per_circuit: u64,
    input_wires: u64,
    generated_ciphertext_bytes_all_n: u64,
    retained_ciphertext_bytes_m: u64,
    soldering_deltas_bytes_m_minus_1: u64,
    soldered_active_base_label_bytes: u64,
    unsoldered_active_label_bytes_all_m: u64,
    taproot_assert_labels_chunks_at_480_wires: u64,
    estimated_assert_labels_vbytes: u64,
    binding_trace_steps_for_n_2pow17: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Phase4ArchitectureReport {
    protocol_id: &'static str,
    committed_baselines: Vec<CommittedBaselineSummary>,
    single_circuit_measurements: Vec<SingleCircuitMeasurement>,
    pilot_full_adversarial_protocol: FullAdversarialPilotProtocolMetrics,
    system_resources: SystemResourceMetrics,
    bitcoin_witness_measured_pilot_n7_m3_w128: BitcoinDisputeMeasurements,
    bitcoin_witness_measured_pasta_ec_w3832_chunked: MultiInputTxMeasurement,
    bitcoin_witness_measured_m39_disprove: TxMeasurement,
    bitcoin_witness_measured_m39_operator_payout: TxMeasurement,
    analytical_production_projections_cc_115_39: Vec<AnalyticalProductionProjection>,
}

fn verify_m14_committed_results(crate_dir: &Path) -> Result<()> {
    let m14_results_path = crate_dir.join("../m14/circuit/RESULTS.json");
    if m14_results_path.exists() {
        let raw = fs::read_to_string(&m14_results_path)
            .with_context(|| format!("read {}", m14_results_path.display()))?;
        let val: serde_json::Value = serde_json::from_str(&raw)?;
        let tx_v2 = val["non_free_gates"]["transcript_c4_v2_real_verification"]
            .as_u64()
            .context("missing transcript_c4_v2_real_verification in M14 RESULTS.json")?;
        ensure!(
            tx_v2 == 11_198_078,
            "unexpected M14 transcript_c4_v2_real_verification gate count {tx_v2}"
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    verify_m14_committed_results(&crate_dir)?;

    let out_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| crate_dir.join("RESULTS.json"));

    // 1. Measure single-circuit costs on both `IndexedDisputeCircuit` (W=128) and
    //    `PastaWindowEcStep` (255-bit Pallas/Vesta `w = 4`-bit witness-assisted affine step, W=3,832):
    let (spec, honest_inputs) = IndexedDisputeSpec::sample_honest_trace([0xa5u8; 32]);
    let mut bad_inp = honest_inputs[5].clone();
    bad_inp.s_out ^= 1;
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

    let (public_setup, mut timings) = garbler.finalize_cut_and_choose(nonce)?;
    let delivery = garbler.release_active_base_labels(nonce, &pilot_bits)?;
    drop(garbler);

    let t_ch_setup = Instant::now();
    let snark_verify_secs = verify_public_setup(&session_id, &spec, &nonce, &public_setup)?;
    let challenger_setup_verify_total_seconds = t_ch_setup.elapsed().as_secs_f64();
    timings.verify_seconds = snark_verify_secs;

    let t_ch_eval = Instant::now();
    let resolution = resolve_dispute(&public_setup, &pilot_bits, Some(&delivery))?;
    let challenger_dispute_eval_all_m_seconds = t_ch_eval.elapsed().as_secs_f64();

    let (win_inst, refute_preimage) = match resolution {
        DisputeResolution::ChallengerSlashesViaDisprove {
            winning_instance_index,
            refute_preimage,
            ..
        } => (winning_instance_index, refute_preimage),
        other => anyhow::bail!("expected ChallengerSlashesViaDisprove, got {other:?}"),
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
    let vk_placeholder_bytes = vec![0u8; timings.vk_bytes];
    let vk_file = tmp_dir.join("verifier_key.bin");
    fs::write(&setup_file, &setup_bytes)?;
    fs::write(&delivery_file, &delivery_bytes)?;
    fs::write(&vk_file, &vk_placeholder_bytes)?;

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

    // 4. Measure real Bitcoin Taproot witness sizes (Pilot W=128 M=3, Pasta W=3,832 chunked, and M=39 Disprove):
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

    // 5. Compute exact protocol byte breakdowns & `(N=115, M=39)` projections:
    let ct_per = single_pilot.ciphertext_bytes_per_circuit;
    let manifest_bytes = bincode::serialize(&public_setup.manifest)?.len() as u64;
    let total_generated_ct_bytes = (PILOT_TOTAL_INSTANCES as u64) * ct_per;
    let total_generated_setup_bytes_all_n = total_generated_ct_bytes
        + manifest_bytes
        + (PILOT_TOTAL_INSTANCES as u64) * single_pilot.base_tap_hashlock_bytes_per_circuit;
    let retained_ct_bytes = (PILOT_RETAINED_INSTANCES as u64) * ct_per;
    let soldering_deltas_bytes =
        ((PILOT_RETAINED_INSTANCES - 1) as u64) * ((PILOT_INPUT_BITS as u64) * 16 + 16);
    let active_raw_bytes = (PILOT_INPUT_BITS as u64) * 16;
    let naive_unsoldered_raw_bytes = (PILOT_RETAINED_INSTANCES as u64) * active_raw_bytes;

    let m14_gates = 785_442_492u64;
    let m14_ct = m14_gates * 16;
    let m14_wires = 8_635_080u64;

    let fc03_bind_gates = 7_285_647u64;
    let fc03_bind_ct = fc03_bind_gates * 16;
    let fc03_bind_wires = 2_840u64;

    let fc03_p99_gates = 50_177_670u64;
    let fc03_p99_ct = fc03_p99_gates * 16;
    let fc03_p99_wires = 19_500u64;

    let babe_groth16_gates = 1_452_278u64;
    let babe_groth16_ct = babe_groth16_gates * 16;
    let babe_groth16_wires = 2_816u64;

    let pasta_ec_gates = single_pasta_ec.non_free_gates_garble_ciphertexts as u64;
    let pasta_ec_wires = pasta_bits.len() as u64;

    // Empirical Tapscript AssertLabels cost per wire (from measured 480-wire chunk): ~20.12 vB/wire.
    let project_cc = |target_name: &'static str,
                      gates: u64,
                      wires: u64,
                      trace_steps: Option<u64>|
     -> AnalyticalProductionProjection {
        let ct = gates * 16;
        let chunks = wires.div_ceil(CHUNK_WIRES_PER_INPUT as u64);
        // Each 480-wire chunk input adds `75` bytes/wire script + `~18.5` bytes/wire witness = `~23.4` vB/wire + tx framing.
        let est_vbytes = chunks * 68 + wires * 24;
        AnalyticalProductionProjection {
            target_name,
            measurement_kind: "analytical_estimate_from_measured_per_circuit_constants",
            cc_total_instances_n: 115,
            cc_retained_instances_m: 39,
            non_free_gates_per_circuit: gates,
            input_wires: wires,
            generated_ciphertext_bytes_all_n: 115 * ct,
            retained_ciphertext_bytes_m: 39 * ct,
            soldering_deltas_bytes_m_minus_1: 38 * (16 * wires + 16),
            soldered_active_base_label_bytes: 16 * wires,
            unsoldered_active_label_bytes_all_m: 39 * 16 * wires,
            taproot_assert_labels_chunks_at_480_wires: chunks,
            estimated_assert_labels_vbytes: est_vbytes,
            binding_trace_steps_for_n_2pow17: trace_steps,
        }
    };

    let n_witness_elems = (1u64 << 17) + 1; // 131,073 Pedersen generators
    let report = Phase4ArchitectureReport {
        protocol_id: "RBZK-BABE-NOVA-PILOT-2026-11",
        committed_baselines: vec![
            CommittedBaselineSummary {
                name: "M14 Monolithic Garbled SP1 Wrap Verifier (c4 / Guest A / M16)",
                proof_system: "Nova (Pallas/Vesta) -> SP1 BLAKE3/KoalaBear STARK Wrap (transcript v2)",
                setup_assumption: "Transparent (zero trusted setup)",
                source: "integrations/bitvm3-nova/m14/README.md & m14/circuit/RESULTS.json",
                non_free_gates_per_circuit: m14_gates,
                ciphertext_bytes_per_circuit: m14_ct,
                input_wires: m14_wires,
                single_circuit_active_label_bytes: m14_wires * 16,
                single_circuit_tap_hashlock_bytes: m14_wires * 64,
                analytical_cc_115_39_generated_ciphertext_bytes: 115 * m14_ct,
                analytical_cc_115_39_retained_ciphertext_bytes: 39 * m14_ct,
                notes: "Single garbled circuit verified in M14 CI; full (115,39) C&C requires 1.445 TB generated / 490.1 GB retained ciphertexts and 17,990 AssertLabels inputs.",
            },
            CommittedBaselineSummary {
                name: "FC03 Authenticated Local Nova Check (1-bit Projective RCB BindingStep)",
                proof_system: "Transparent Nova (Pallas/Vesta) + FlatMerkle SHA-256 local check",
                setup_assumption: "Transparent (zero trusted setup)",
                source: "PR #23 (flatcheck-lab FC03 reference)",
                non_free_gates_per_circuit: fc03_bind_gates,
                ciphertext_bytes_per_circuit: fc03_bind_ct,
                input_wires: fc03_bind_wires,
                single_circuit_active_label_bytes: fc03_bind_wires * 16,
                single_circuit_tap_hashlock_bytes: fc03_bind_wires * 64,
                analytical_cc_115_39_generated_ciphertext_bytes: 115 * fc03_bind_ct,
                analytical_cc_115_39_retained_ciphertext_bytes: 39 * fc03_bind_ct,
                notes: "107.8x smaller per circuit than M14, but 1-bit projective RCB EC addition uses 7.29M gates/step across 256*(n+1) = 33,554,688 steps (for n=2^17) and lacks multi-instance C&C soldering.",
            },
            CommittedBaselineSummary {
                name: "FC03 Modelled R1CS Row Check (p99 width)",
                proof_system: "Transparent Nova (Pallas/Vesta) + FlatMerkle local row check",
                setup_assumption: "Transparent (zero trusted setup)",
                source: "PR #23 (flatcheck-lab FC03 width model)",
                non_free_gates_per_circuit: fc03_p99_gates,
                ciphertext_bytes_per_circuit: fc03_p99_ct,
                input_wires: fc03_p99_wires,
                single_circuit_active_label_bytes: fc03_p99_wires * 16,
                single_circuit_tap_hashlock_bytes: fc03_p99_wires * 64,
                analytical_cc_115_39_generated_ciphertext_bytes: 115 * fc03_p99_ct,
                analytical_cc_115_39_retained_ciphertext_bytes: 39 * fc03_p99_ct,
                notes: "Max unsplit R1CS row reaches 1,150,138,072 gates unless term-accumulated into bounded fan-in steps.",
            },
            CommittedBaselineSummary {
                name: "Babylon BABE Groth16 Verifier (Optional Literature Reference)",
                proof_system: "Groth16 over BN254 + Witness-Assisted Garbled Pairing/MSM",
                setup_assumption: "TRUSTED SETUP REQUIRED (circuit-specific CRS toxic waste; excluded from primary stack)",
                source: "Babylon Labs BABE Research Paper (January 2026)",
                non_free_gates_per_circuit: babe_groth16_gates,
                ciphertext_bytes_per_circuit: babe_groth16_ct,
                input_wires: babe_groth16_wires,
                single_circuit_active_label_bytes: babe_groth16_wires * 16,
                single_circuit_tap_hashlock_bytes: babe_groth16_wires * 64,
                analytical_cc_115_39_generated_ciphertext_bytes: 115 * babe_groth16_ct,
                analytical_cc_115_39_retained_ciphertext_bytes: 39 * babe_groth16_ct,
                notes: "Compact 22.16 MiB/circuit, but relies on BN254 Groth16 circuit-specific trusted setup rather than transparent Nova/Spartan.",
            },
        ],
        single_circuit_measurements: vec![single_pilot, single_pasta_ec],
        pilot_full_adversarial_protocol: FullAdversarialPilotProtocolMetrics {
            scope: "full_adversarial_protocol_N7_M3",
            measurement_kind: "measured_cpu_execution",
            total_instances_n: PILOT_TOTAL_INSTANCES,
            retained_instances_m: PILOT_RETAINED_INSTANCES,
            opened_instances: PILOT_OPENED_INSTANCES,
            input_wires: PILOT_INPUT_BITS,
            total_generated_ciphertext_bytes: total_generated_ct_bytes,
            total_generated_setup_bytes_all_n,
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
            onchain_label_delivery_reduction_factor: (naive_unsoldered_raw_bytes as f64)
                / (active_raw_bytes as f64),
            garble_all_n_seconds,
            nova_certificate_timings: timings,
            challenger_setup_verify_total_seconds,
            challenger_dispute_eval_all_m_seconds,
            challenger_public_data_download_bytes: on_disk_public_setup_bytes
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
        analytical_production_projections_cc_115_39: vec![
            project_cc(
                "BABE-Nova 255-bit Pasta w=4 Windowed Witness-Assisted EC Step",
                pasta_ec_gates,
                pasta_ec_wires,
                Some(64 * n_witness_elems),
            ),
            project_cc(
                "FC03 1-bit Projective RCB BindingStep",
                fc03_bind_gates,
                fc03_bind_wires,
                Some(256 * n_witness_elems),
            ),
            project_cc(
                "M14 Monolithic Garbled SP1 BLAKE3/STARK Final Verifier",
                m14_gates,
                m14_wires,
                None,
            ),
        ],
    };

    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&out_path, format!("{json}\n"))
        .with_context(|| format!("write {}", out_path.display()))?;
    println!(
        "Wrote Phase 4 architecture measurements to {}",
        out_path.display()
    );
    println!("{json}");
    Ok(())
}
