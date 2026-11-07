//! M25b: exact trace shape of SP1 6.9.0's shrink program, the recursion
//! circuit that verifies one compressed proof.
//!
//! The program is built exactly as `ShrinkProver::new` builds it: from the
//! fixed compress (reduce) proof shape's dummy input, so its event counts do
//! not depend on which compressed proof is later shrunk. Nothing is set up or
//! proved; the compiled program's per-chip event counts are its trace heights.
use slop_air::BaseAir;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::air::MachineAir;
use sp1_prover::{
    recursion::{recursive_verifier, shrink_program_from_input},
    shapes::{build_shape_from_recursion_air_event_count, SP1RecursionProofShape, DEFAULT_ARITY},
    worker::SP1LightNode,
    CpuSP1ProverComponents, SP1ProverComponents,
};
use sp1_recursion_compiler::config::InnerConfig;
use std::collections::BTreeSet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let output = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: sp1_shrink_shape OUTPUT_JSON"))?;
    let client = SP1LightNode::new().await;
    let vk_verification = client.inner().vk_verification();
    let allowed_vk_height = client.inner().allowed_vk_height();

    let verifier = CpuSP1ProverComponents::compress_verifier();
    // Public route to the same embedded compress_shape.json ShrinkProver uses.
    let reduce_shape = SP1RecursionProofShape::retrieve_or_compute_reduce_shape(
        RiscvAir::machine(),
        DEFAULT_ARITY,
    );
    let chips = verifier
        .shard_verifier()
        .machine()
        .chips()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let input = reduce_shape.dummy_input(
        1,
        allowed_vk_height,
        chips.clone(),
        verifier.max_log_row_count(),
        *verifier.fri_config(),
        verifier.log_stacking_height() as usize,
    );
    let program = shrink_program_from_input(
        &recursive_verifier::<_, _, InnerConfig>(verifier.shard_verifier()),
        vk_verification,
        &input,
    );
    let counts = program.event_counts;
    let shape = build_shape_from_recursion_air_event_count(&counts);

    let mut rows = Vec::new();
    let (mut main_area, mut preprocessed_area, mut max_height) = (0usize, 0usize, 0usize);
    for chip in &chips {
        let height = shape.shape.height(chip).unwrap_or(0);
        let width = <_ as BaseAir<_>>::width(chip);
        main_area += height * width;
        preprocessed_area += height * chip.preprocessed_width();
        max_height = max_height.max(height);
        rows.push(serde_json::json!({"chip": chip.name(), "height": height,
            "main_width": width, "preprocessed_width": chip.preprocessed_width()}));
    }
    let compress_rows: Vec<_> = chips
        .iter()
        .map(|chip| serde_json::json!({"chip": chip.name(), "height": reduce_shape.shape.height(chip)}))
        .collect();
    let report = serde_json::json!({
        "schema": "bitvm2-nova-sp1-shrink-shape/v1", "sp1_version": "6.9.0",
        "vk_verification": vk_verification, "allowed_vk_height": allowed_vk_height,
        "event_counts": format!("{counts:?}"), "chips": rows,
        "main_area": main_area, "preprocessed_area": preprocessed_area, "max_height": max_height,
        "log_stacking_height": verifier.log_stacking_height(),
        "max_log_row_count": verifier.max_log_row_count(),
        "compress_shape_heights": compress_rows,
        "setup_run": false, "proof_generated": false
    });
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
