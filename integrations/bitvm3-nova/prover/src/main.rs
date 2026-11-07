//! nb3-prove: resumable, memory-bounded SP1 6.9 compressed proofs on one machine (CPU provers).
//! Usage: see `src/cli.rs`.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nb3_prover::cli::main_with(nb3_prover::backend::Cpu).await
}
