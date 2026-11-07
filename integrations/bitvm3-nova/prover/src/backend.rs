//! The provers a node runs on. The CPU backend is SP1's CPU prover; a GPU backend lives in
//! `nova-bitvm3/prover-gpu` and implements the same trait over SP1's CUDA shard provers.
use std::{future::Future, sync::Arc};

use anyhow::Result;
use sp1_core_executor::SP1CoreOpts;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    prover::{CpuShardProver, ProverSemaphore},
    Machine,
};
use sp1_primitives::SP1Field;
use sp1_prover::{worker::SP1WorkerBuilder, CpuSP1ProverComponents, CpuWrapProverBuilder, SP1ProverComponents};

pub trait Backend: Send + Sync + 'static {
    type C: SP1ProverComponents;

    fn name(&self) -> &'static str;

    /// SP1 options this backend needs beyond the run's sharding options (which it must not
    /// change: they decide the shards, and the memo keys with them).
    fn adjust_opts(&self, _opts: &mut SP1CoreOpts) {}

    /// A worker builder with this backend's core, compress, shrink and wrap provers set, each
    /// behind a semaphore of `permits`.
    fn worker_builder(
        &self,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
        opts: &SP1CoreOpts,
        permits: usize,
    ) -> impl Future<Output = Result<SP1WorkerBuilder<Self::C>>>;
}

/// SP1's CPU provers.
pub struct Cpu;

impl Backend for Cpu {
    type C = CpuSP1ProverComponents;

    fn name(&self) -> &'static str {
        "cpu"
    }

    async fn worker_builder(
        &self,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
        opts: &SP1CoreOpts,
        permits: usize,
    ) -> Result<SP1WorkerBuilder<CpuSP1ProverComponents>> {
        let permits = ProverSemaphore::new(permits);
        let core_verifier = CpuSP1ProverComponents::core_verifier(machine.clone());
        let core = Arc::new(CpuShardProver::new(core_verifier.shard_verifier().clone()));
        let compress = Arc::new(CpuShardProver::new(CpuSP1ProverComponents::compress_verifier().shard_verifier().clone()));
        let shrink = Arc::new(CpuShardProver::new(CpuSP1ProverComponents::shrink_verifier().shard_verifier().clone()));
        Ok(SP1WorkerBuilder::<CpuSP1ProverComponents>::new_with_machine(machine)
            .with_core_opts(opts.clone())
            .with_core_air_prover(core, permits.clone())
            .with_compress_air_prover(compress, permits.clone())
            .with_shrink_air_prover(shrink, permits.clone())
            .with_wrap_air_prover(CpuWrapProverBuilder, permits))
    }
}
