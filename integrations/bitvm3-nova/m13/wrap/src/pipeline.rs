//! Shrink, then wrap with BLAKE3.
//!
//! SP1 6.9.0 turns a compressed proof into its final STARK in two recursion
//! steps: *shrink* (re-prove the compress verifier with a smaller shape,
//! still Poseidon2-KoalaBear) and *wrap* (prove the root verifier of the
//! shrink proof under the outer configuration, BN254 Poseidon2, for gnark).
//!
//! This module runs SP1's own shrink step unchanged and SP1's own wrap
//! program, but proves the wrap program under [`Blake3KoalaBear`]: same AIR,
//! same PCS, same FRI parameters (`wrap_fri_config`), BLAKE3 instead of
//! BN254 Poseidon2. `wrap_program` is a copy of sp1-prover 6.9.0's
//! crate-private `wrap_program_from_input`; [`bn254_wrap_vk_matches_sp1`]
//! checks it builds the program SP1 ships by comparing the BN254 key it
//! yields with SP1's embedded `WRAP_VK_BYTES`.

use std::{collections::BTreeMap, collections::BTreeSet, sync::Arc, time::Instant};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use slop_challenger::IopCtx;
use slop_merkle_tree::FieldMerkleTreeProver;
use slop_stacked::StackedPcsProver;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    inner_perm,
    prover::{AirProver, CpuShardProver, ProverSemaphore},
    HashableKey, MachineVerifyingKey, SP1Pcs, SP1PcsProofInner, SP1RecursionProof, SP1WrapProof,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};
use sp1_prover::{
    recursion::{recursive_verifier, shrink_program_from_input, RecursionVks},
    shapes::SP1RecursionProofShape,
    CompressAir, CpuSP1ProverComponents, SP1ProverComponents, WrapAir,
};
use sp1_recursion_circuit::{
    machine::{
        PublicValuesOutputDigest, SP1CompressRootVerifierWithVKey, SP1CompressWithVKeyWitnessValues,
        SP1MerkleProofWitnessValues, SP1ShapedWitnessValues,
    },
    shard::RecursiveShardVerifier,
    witness::Witnessable,
    WrapConfig,
};
use sp1_recursion_compiler::{
    circuit::AsmCompiler,
    config::InnerConfig,
    ir::{Builder, DslIrProgram},
};
use sp1_recursion_executor::{shape::RecursionShape, Block, Executor, RecursionProgram};

pub use m13_verify::{
    final_statement, verify_final, verify_wrap_proof, verify_wrap_proof_v2, vk_sha256, wrap_verifier, wrap_verifier_v2,
    Blake3KoalaBear, Blake3KoalaBearV2, Blake3WrapProof, Blake3WrapProofV2, Blake3WrapSC, FinalStatement,
};

/// The verifier crate names the wrap AIR itself; it must be sp1-prover's.
const _: fn(WrapAir<SP1Field>) -> m13_verify::WrapAir = |x| x;

/// sp1-prover 6.9.0 `worker::config::DEFAULT_MAX_COMPOSE_ARITY` (crate-private there).
pub const MAX_COMPOSE_ARITY: usize = 4;

pub type Blake3MerkleProver = FieldMerkleTreeProver<SP1Field, u8, Blake3KoalaBear, 32>;
pub type Blake3PcsProver = StackedPcsProver<Blake3MerkleProver, Blake3KoalaBear>;
pub type Blake3WrapProver =
    CpuShardProver<Blake3KoalaBear, SP1Pcs<Blake3KoalaBear>, Blake3PcsProver, WrapAir<SP1Field>>;
pub type ShrinkProof = SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>;

type C = CpuSP1ProverComponents;
type RecursionProver = <C as SP1ProverComponents>::RecursionProver;

pub fn recursion_vks() -> RecursionVks {
    RecursionVks::new(None, MAX_COMPOSE_ARITY, true)
}

/// Copy of sp1-prover 6.9.0 `recursion::wrap_program_from_input`.
pub fn wrap_program(
    recursive: &RecursiveShardVerifier<SP1GlobalContext, CompressAir<SP1Field>, WrapConfig>,
    input: &SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>,
) -> RecursionProgram<SP1Field> {
    let mut builder = Builder::<WrapConfig>::default();
    let input = input.read(&mut builder);
    SP1CompressRootVerifierWithVKey::<WrapConfig, _>::verify(
        &mut builder,
        recursive,
        input,
        true,
        PublicValuesOutputDigest::Root,
    );
    let block = builder.into_root_block();
    // SAFETY: as in sp1-prover: the circuit uses no synchronization primitives.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };
    AsmCompiler::default().compile(dsl_program)
}

fn run_program(
    program: &Arc<RecursionProgram<SP1Field>>,
    witness: Vec<Block<SP1Field>>,
) -> Result<sp1_recursion_executor::ExecutionRecord<SP1Field>> {
    let mut runtime = Executor::<SP1Field, SP1ExtensionField, _>::new(program.clone(), inner_perm());
    runtime.witness_stream = witness.into();
    runtime.run().map_err(|e| anyhow!("recursion executor: {e:?}"))?;
    Ok(runtime.record)
}

fn with_vk_merkle(
    vks: &RecursionVks,
    vk: MachineVerifyingKey<SP1GlobalContext>,
    proof: sp1_hypercube::ShardProof<SP1GlobalContext, SP1PcsProofInner>,
    merkle: sp1_hypercube::MerkleProof<SP1GlobalContext>,
) -> SP1CompressWithVKeyWitnessValues<SP1PcsProofInner> {
    let values = vec![vk.hash_koalabear()];
    SP1CompressWithVKeyWitnessValues {
        compress_val: SP1ShapedWitnessValues { vks_and_proofs: vec![(vk, proof)], is_complete: true },
        merkle_val: SP1MerkleProofWitnessValues { root: vks.root(), values, vk_merkle_proofs: vec![merkle] },
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PhaseTimes {
    pub shrink_program_build_s: f64,
    pub shrink_setup_s: f64,
    pub shrink_execute_s: f64,
    pub shrink_prove_s: f64,
    pub wrap_program_build_s: f64,
    pub wrap_setup_s: f64,
    pub wrap_execute_s: f64,
    pub wrap_prove_s: f64,
    pub wrap_verify_s: f64,
}

/// Shrink a compressed proof with SP1's own shrink program and prover.
pub async fn shrink(
    compressed: ShrinkProof,
    vks: &RecursionVks,
    t: &mut PhaseTimes,
) -> Result<(ShrinkProof, BTreeMap<String, usize>)> {
    let compress_verifier = C::compress_verifier();
    let shrink_verifier = C::shrink_verifier();

    let s = Instant::now();
    let reduce_shape =
        SP1RecursionProofShape::retrieve_or_compute_reduce_shape(RiscvAir::machine(), MAX_COMPOSE_ARITY);
    let input = reduce_shape.dummy_input(
        1,
        vks.height(),
        compress_verifier.shard_verifier().machine().chips().iter().cloned().collect::<BTreeSet<_>>(),
        compress_verifier.max_log_row_count(),
        *compress_verifier.fri_config(),
        compress_verifier.log_stacking_height() as usize,
    );
    let program = Arc::new(shrink_program_from_input(
        &recursive_verifier::<SP1GlobalContext, _, InnerConfig>(compress_verifier.shard_verifier()),
        true,
        &input,
    ));
    t.shrink_program_build_s = s.elapsed().as_secs_f64();

    let prover: Arc<RecursionProver> = Arc::new(CpuShardProver::new(shrink_verifier.shard_verifier().clone()));
    let s = Instant::now();
    let (pk, vk) = prover.setup(program.clone(), ProverSemaphore::new(1)).await;
    let shrink_shape = <RecursionProver as AirProver<SP1GlobalContext, _>>::preprocessed_table_heights(pk.pk).await;
    t.shrink_setup_s = s.elapsed().as_secs_f64();

    let SP1RecursionProof { vk: cvk, proof: cproof, vk_merkle_proof } = compressed;
    let s = Instant::now();
    let witness = with_vk_merkle(vks, cvk, cproof, vk_merkle_proof);
    let mut stream = Vec::new();
    Witnessable::<InnerConfig>::write(&witness, &mut stream);
    let record = run_program(&program, stream)?;
    t.shrink_execute_s = s.elapsed().as_secs_f64();

    let s = Instant::now();
    let (_, proof, permit) =
        prover.setup_and_prove_shard(program, record, Some(vk.clone()), ProverSemaphore::new(1)).await;
    let _ = permit.release();
    t.shrink_prove_s = s.elapsed().as_secs_f64();
    mem_note("shrink proved");

    // The shrink key must be one SP1's recursion key map admits.
    let (_, vk_merkle_proof) =
        vks.open(&vk).map_err(|e| anyhow!("shrink key not in SP1's recursion key map: {e:?}"))?;
    let mut challenger = SP1GlobalContext::default_challenger();
    vk.observe_into(&mut challenger);
    shrink_verifier.verify_shard(&vk, &proof, &mut challenger).context("shrink proof does not verify")?;
    Ok((SP1RecursionProof { vk, proof, vk_merkle_proof }, shrink_shape))
}

/// Build SP1's wrap program for a shrink shape.
pub fn build_wrap_program(vks: &RecursionVks, shrink_shape: BTreeMap<String, usize>) -> Arc<RecursionProgram<SP1Field>> {
    let verifier = C::shrink_verifier();
    let shape = SP1RecursionProofShape { shape: RecursionShape::new(shrink_shape) };
    let input = shape.dummy_input(
        1,
        vks.height(),
        verifier.shard_verifier().machine().chips().iter().cloned().collect::<BTreeSet<_>>(),
        verifier.max_log_row_count(),
        *verifier.fri_config(),
        verifier.log_stacking_height() as usize,
    );
    Arc::new(wrap_program(&recursive_verifier::<SP1GlobalContext, _, WrapConfig>(verifier.shard_verifier()), &input))
}

/// Transcript v2 prover types ([`m13_verify::ctx::Blake3ChallengerV2`]).
pub type Blake3WrapProverV2 = CpuShardProver<
    Blake3KoalaBearV2,
    SP1Pcs<Blake3KoalaBearV2>,
    StackedPcsProver<FieldMerkleTreeProver<SP1Field, u8, Blake3KoalaBearV2, 32>, Blake3KoalaBearV2>,
    WrapAir<SP1Field>,
>;

macro_rules! wrap_with {
    ($(#[$doc:meta])* $name:ident, $prover:ty, $proof:ty, $verifier:path, $verify:path) => {
        $(#[$doc])*
        pub async fn $name(
            shrink: ShrinkProof,
            shrink_shape: BTreeMap<String, usize>,
            vks: &RecursionVks,
            t: &mut PhaseTimes,
        ) -> Result<$proof> {
            let s = Instant::now();
            let program = build_wrap_program(vks, shrink_shape);
            t.wrap_program_build_s = s.elapsed().as_secs_f64();

            mem_note("wrap program built");
            let prover = Arc::new(<$prover>::new($verifier().shard_verifier().clone()));
            let s = Instant::now();
            let (_, vk) = prover.setup(program.clone(), ProverSemaphore::new(1)).await;
            t.wrap_setup_s = s.elapsed().as_secs_f64();
            mem_note("wrap setup done");

            let SP1RecursionProof { vk: svk, proof: sproof, vk_merkle_proof } = shrink;
            let s = Instant::now();
            let witness = with_vk_merkle(vks, svk, sproof, vk_merkle_proof);
            let mut stream = Vec::new();
            Witnessable::<WrapConfig>::write(&witness, &mut stream);
            let record = run_program(&program, stream)?;
            t.wrap_execute_s = s.elapsed().as_secs_f64();
            mem_note("wrap program executed");

            let s = Instant::now();
            let (_, proof, permit) =
                prover.setup_and_prove_shard(program, record, Some(vk.clone()), ProverSemaphore::new(1)).await;
            let _ = permit.release();
            t.wrap_prove_s = s.elapsed().as_secs_f64();
            mem_note("wrap proved");

            let wrap: $proof = SP1WrapProof { vk, proof };
            let s = Instant::now();
            $verify(&wrap)?;
            t.wrap_verify_s = s.elapsed().as_secs_f64();
            Ok(wrap)
        }
    };
}

wrap_with!(
    /// Prove SP1's wrap program over the shrink proof under BLAKE3 (transcript v1).
    wrap_blake3, Blake3WrapProver, Blake3WrapProof, wrap_verifier, verify_wrap_proof
);
wrap_with!(
    /// [`wrap_blake3`] with transcript v2 (fixed-cost challenges).
    wrap_blake3_v2, Blake3WrapProverV2, Blake3WrapProofV2, wrap_verifier_v2, verify_wrap_proof_v2
);

/// Build SP1's BN254 wrap key from [`build_wrap_program`] and compare it with
/// the key sp1-prover 6.9.0 embeds (`verify::WRAP_VK_BYTES`). Equality means
/// the program proved under BLAKE3 is the program SP1 ships.
pub async fn bn254_wrap_vk_matches_sp1(shrink_shape: BTreeMap<String, usize>) -> Result<(bool, String, String)> {
    let vks = recursion_vks();
    let program = build_wrap_program(&vks, shrink_shape);
    let prover = Arc::new(CpuShardProver::<
        sp1_primitives::SP1OuterGlobalContext,
        sp1_hypercube::SP1OuterPcs,
        sp1_hypercube::prover::SP1OuterPcsProver,
        WrapAir<SP1Field>,
    >::new(C::wrap_verifier().shard_verifier().clone()));
    let (_, vk) = prover.setup(program, ProverSemaphore::new(1)).await;
    let expected: MachineVerifyingKey<sp1_primitives::SP1OuterGlobalContext> =
        bincode::deserialize(sp1_prover::verify::WRAP_VK_BYTES)?;
    Ok((vk == expected, vk_sha256(&vk), vk_sha256(&expected)))
}

/// Resident and peak memory of this process (Linux), for phase logs.
pub fn mem_note(phase: &str) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |k: &str| {
        status
            .lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .map(|kb| kb as f64 / 1048576.0)
            .unwrap_or(0.0)
    };
    eprintln!("[m13-mem] {phase}: rss {:.2} GiB, peak {:.2} GiB", field("VmRSS:"), field("VmHWM:"));
}
