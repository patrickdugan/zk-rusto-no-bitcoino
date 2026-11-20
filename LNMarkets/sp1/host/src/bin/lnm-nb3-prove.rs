//! Existing resumable CPU prover, resolved through this workspace's SP1 lock.
//! The LNMarkets runner supplies external pins and performs final verification.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nb3_prover::cli::main_with(nb3_prover::backend::Cpu).await
}
