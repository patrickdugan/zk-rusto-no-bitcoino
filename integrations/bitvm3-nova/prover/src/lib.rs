//! Resumable, memory-bounded SP1 6.9 compressed proving on a single machine.
//!
//! - [`store::DiskArtifactClient`]: SP1's artifact store on disk instead of in RAM.
//! - [`memo::Memo`]: finished shard and recursion tasks keyed by what they prove, so a rerun of
//!   the same command replays them instead of proving them again.
//! - [`node::ShardedNode`]: an SP1 node over both (SP1's own controller, executor and provers).
//! - [`config::RunConfig`]: everything that decides the shards, pinned per run directory.
pub mod backend;
pub mod cli;
pub mod config;
pub mod memo;
pub mod node;
pub mod store;
