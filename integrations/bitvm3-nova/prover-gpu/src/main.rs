//! nb3-prove-gpu: `nb3-prove` (resumable, disk-backed SP1 6.9 proving) over SP1's CUDA shard
//! provers. Same command line as `nb3-prove`, plus:
//!
//!   --trace-buffers N   pinned host trace buffers per core and recursion prover (default 2)
//!
//! SP1's own GPU setup (`sp1_gpu_prover::cuda_worker_builder`, via `local_gpu_opts`) refuses GPUs
//! with less than 24 GB and sizes the core trace buffer for its largest shard (about 4 × 10^8
//! field elements). Device memory comes from CUDA's stream-ordered pool and follows the shard
//! actually proved, so this builder takes the core trace size from the run's
//! `--element-threshold` instead; smaller shards fit smaller GPUs, or a GPU shared with another
//! job. The recursion, shrink and wrap provers keep SP1's allocations, which the fixed recursion
//! programs need.
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use nb3_prover::backend::Backend;
use sp1_core_executor::SP1CoreOpts;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{cuda_memory_info, run_in_place, TaskScope};
use sp1_gpu_prover::{
    new_cuda_prover, SP1CudaProverComponents, RECURSION_TRACE_ALLOCATION, SHRINK_TRACE_ALLOCATION,
    WRAP_TRACE_ALLOCATION,
};
use sp1_hypercube::{prover::ProverSemaphore, Machine};
use sp1_primitives::SP1Field;
use sp1_prover::{worker::SP1WorkerBuilder, ReadyWrapProverBuilder, SP1ProverComponents, CORE_LOG_STACKING_HEIGHT};

struct Cuda {
    scope: TaskScope,
    trace_buffers: usize,
}

impl Backend for Cuda {
    type C = SP1CudaProverComponents;

    fn name(&self) -> &'static str {
        "cuda"
    }

    fn adjust_opts(&self, opts: &mut SP1CoreOpts) {
        // As SP1's GPU options, except the shard size, which the run configuration decides.
        opts.global_dependencies_opt = true;
        opts.recompute_gkr_trace = false;
        opts.drop_ldes = false;
    }

    async fn worker_builder(
        &self,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
        opts: &SP1CoreOpts,
        permits: usize,
    ) -> Result<SP1WorkerBuilder<SP1CudaProverComponents>> {
        let (free, total) = cuda_memory_info()?;
        tracing::info!("GPU memory: {} MiB free of {} MiB", free >> 20, total >> 20);
        let (free, total) = (free as u64, total as u64);
        ensure!(permits > 0, "--permits must be positive");
        ensure!((1..=4).contains(&self.trace_buffers), "--trace-buffers must be between 1 and 4");
        let base = usize::try_from(opts.sharding_threshold.element_threshold).context("element threshold exceeds usize")?;
        ensure!(base > 0, "--element-threshold must be positive");
        let stack = 1usize.checked_shl(CORE_LOG_STACKING_HEIGHT as u32).context("stacking height overflow")?;
        let core_elements = base.checked_add(stack).context("core trace allocation overflow")?;
        // Lower bound only: FRI, recursion, CUDA graphs and other buffers also consume VRAM.
        let min_trace_bytes = (core_elements as u64)
            .checked_mul(std::mem::size_of::<SP1Field>() as u64)
            .context("core trace byte count overflow")?;
        let reserve = (total / 4).min(512 * 1024 * 1024);
        ensure!(free > reserve && min_trace_bytes <= free - reserve,
            "core trace alone needs {} MiB with {} MiB free; reduce --element-threshold or free GPU memory",
            min_trace_bytes >> 20, free >> 20);
        tracing::info!("core trace {} MiB minimum, GPU reserve {} MiB; this does not bound peak usage",
            min_trace_bytes >> 20, reserve >> 20);
        let permits = ProverSemaphore::new(permits);
        let s = &self.scope;
        let core_verifier = SP1CudaProverComponents::core_verifier(machine.clone());
        let core = new_cuda_prover(
            &core_verifier,
            core_elements,
            self.trace_buffers,
            opts.recompute_gkr_trace,
            opts.drop_ldes,
            s.clone(),
        )
        .await;
        let compress_verifier = SP1CudaProverComponents::compress_verifier();
        let compress =
            new_cuda_prover(&compress_verifier, RECURSION_TRACE_ALLOCATION, self.trace_buffers, false, false, s.clone())
                .await;
        let shrink_verifier = SP1CudaProverComponents::shrink_verifier();
        let shrink = new_cuda_prover(&shrink_verifier, SHRINK_TRACE_ALLOCATION, 1, false, false, s.clone()).await;
        let wrap_verifier = SP1CudaProverComponents::wrap_verifier();
        let wrap = new_cuda_prover(&wrap_verifier, WRAP_TRACE_ALLOCATION, 1, false, false, s.clone()).await;
        Ok(SP1WorkerBuilder::<SP1CudaProverComponents>::new_with_machine(machine)
            .with_core_opts(opts.clone())
            .with_core_air_prover(Arc::new(core), permits.clone())
            .with_compress_air_prover(Arc::new(compress), permits.clone())
            .with_shrink_air_prover(Arc::new(shrink), permits.clone())
            .with_wrap_air_prover(ReadyWrapProverBuilder::new(Arc::new(wrap)), permits))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let trace_buffers = args
        .iter()
        .position(|a| a == "--trace-buffers")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(2);
    let handle = run_in_place(|scope| async move { nb3_prover::cli::main_with(Cuda { scope, trace_buffers }).await }).await;
    handle.await.map_err(|e| anyhow::anyhow!("CUDA task: {e:?}"))?
}
