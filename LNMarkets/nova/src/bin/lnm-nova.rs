//! Native fixture, real Nova 0.76 recursive fold, optional compressed fold.
//! This is a PROOF OF AGGREGATION of native-validated private row digests,
//! not a self-contained SNARK of secp256k1 signature or Bitcoin consensus rules.
use lnm_bitvm3_nova::{validated_trace, NovaSettlementStep};
use m18_utxo_window::elem::f_to_le;
use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK};
use nova_snark::provider::ipa_pc::EvaluationEngine;
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use serde_json::json;
use std::{env, time::Instant};

type Pp = PublicParams<PallasEngine, VestaEngine, NovaSettlementStep>;
type Rs = RecursiveSNARK<PallasEngine, VestaEngine, NovaSettlementStep>;
type S1 = RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>;
type S2 = RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>;
type Cs = CompressedSNARK<PallasEngine, VestaEngine, NovaSettlementStep, S1, S2>;

fn main_run() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.is_empty() || args.len() > 3 {
        return Err("usage: lnm-nova trace|prove ROWS [--compressed] (ROWS=1,2,8,32)".into());
    }
    let action = args[0].as_str();
    if action != "trace" && action != "prove" {
        return Err("action must be trace or prove".into());
    }
    let count: usize = args
        .get(1)
        .ok_or("missing row count")?
        .parse()
        .map_err(|_| "invalid row count")?;
    if ![1, 2, 8, 32].contains(&count) {
        return Err("ROWS must be 1,2,8,32".into());
    }
    let compressed = args.get(2).is_some_and(|s| s == "--compressed");
    if args.get(2).is_some() && !compressed || (compressed && action != "prove") {
        return Err("only prove accepts --compressed".into());
    }
    let fixture = lnm_batch_statement::fixture::demo_batch(count)?;
    let trace = validated_trace(&fixture)?;
    let initial_sha256 = lnm_batch_statement::sha256(&trace.journal_bytes);
    let initial_root = hex::encode(f_to_le(&trace.initial[4]));
    let final_root = hex::encode(f_to_le(&trace.final_state[4]));
    let native = json!({
        "schema":"lnmarkets-bitvm3-nova/v1",
        "rows":count,
        "native_bip340_and_oracle_checks":true,
        "sha256_nullifier_and_transaction_checks_outside_nova":true,
        "row_transcript_digests_constrained_as_opaque_witnesses":true,
        "bitcoin_spendability_proved":false,
        "standalone_signature_snark_proved":false,
        "native_journal_sha256":hex::encode(initial_sha256),
        "nova_poseidon_root_z0":initial_root,
        "nova_poseidon_root_zn":final_root,
        "native_journal_bytes":trace.journal_bytes.len(),
        "nova_state_arity":trace.initial.len(),
        "nova_step_count":trace.steps.len(),
    });
    if action == "trace" {
        println!(
            "{}",
            serde_json::to_string_pretty(&native).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let start = Instant::now();
    let pp = Pp::setup(
        &NovaSettlementStep::blank(),
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .map_err(|e| format!("Nova setup: {e:?}"))?;
    let setup = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let mut recursive = Rs::new(&pp, &trace.steps[0], &trace.initial)
        .map_err(|e| format!("Nova initialization: {e:?}"))?;
    for (i, step) in trace.steps.iter().enumerate() {
        recursive
            .prove_step(&pp, step)
            .map_err(|e| format!("Nova step {i}: {e:?}"))?;
    }
    let prove = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let output = recursive
        .verify(&pp, trace.steps.len(), &trace.initial)
        .map_err(|e| format!("Nova recursive verification: {e:?}"))?;
    if output != trace.final_state {
        return Err("Nova folded output differs from independently computed native trace".into());
    }
    let verify = start.elapsed().as_secs_f64();
    let mut report = native;
    report["proof"] = json!("recursive_nova_0_76");
    report["nova_recursive_verified"] = json!(true);
    report["nova_setup_seconds"] = json!(setup);
    report["nova_prove_seconds"] = json!(prove);
    report["nova_verify_seconds"] = json!(verify);
    if compressed {
        let t = Instant::now();
        let (pk, vk) = Cs::setup(&pp).map_err(|e| format!("Nova compressed setup: {e:?}"))?;
        report["compressed_setup_seconds"] = json!(t.elapsed().as_secs_f64());
        let t = Instant::now();
        let proof =
            Cs::prove(&pp, &pk, &recursive).map_err(|e| format!("Nova compressed proof: {e:?}"))?;
        report["compressed_prove_seconds"] = json!(t.elapsed().as_secs_f64());
        let t = Instant::now();
        let checked = proof
            .verify(&vk, trace.steps.len(), &trace.initial)
            .map_err(|e| format!("Nova compressed verification: {e:?}"))?;
        if checked != trace.final_state {
            return Err("compressed Nova proof differs from pinned native trace".into());
        }
        report["compressed_verify_seconds"] = json!(t.elapsed().as_secs_f64());
        report["compressed_bytes"] =
            json!(bincode::serialize(&proof).map_err(|e| e.to_string())?.len());
        report["proof"] = json!("compressed_nova_spartan_ipa");
        report["nova_compressed_verified"] = json!(true);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() {
    if let Err(e) = main_run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
