//! The run configuration: every input that decides how the program is cut into shards. It is
//! written to `RUN_DIR/run.json` on the first run; a later run in the same directory must present
//! the same configuration, so memo entries are only replayed into the run that produced them.
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_core_executor::SP1CoreOpts;

pub const SP1_VERSION: &str = "6.9.0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunConfig {
    pub sp1_version: String,
    pub elf_sha256: String,
    /// SHA-256 of each stdin input, in the order they are written (`SP1Stdin::write_vec`).
    pub inputs_sha256: Vec<String>,
    pub element_threshold: u64,
    pub height_threshold: u64,
    pub shard_size: usize,
    pub minimal_trace_chunk_threshold: u64,
    pub trace_chunk_slots: usize,
    pub full_size_shards: bool,
    /// The proof nonce, chosen on the first run and kept for every resume.
    pub nonce: [u32; 4],
}

impl RunConfig {
    /// The digest every memo key starts from.
    pub fn digest(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("config serializes");
        Sha256::digest([b"nb3-prover/run/v1".as_slice(), &json].concat()).into()
    }

    /// SP1's options with every sharding field taken from this configuration (and none from the
    /// environment, which could otherwise change the shards between a run and its resume).
    pub fn core_opts(&self) -> SP1CoreOpts {
        let mut o = SP1CoreOpts::default();
        o.sharding_threshold.element_threshold = self.element_threshold;
        o.sharding_threshold.height_threshold = self.height_threshold;
        o.shard_size = self.shard_size;
        o.minimal_trace_chunk_threshold = self.minimal_trace_chunk_threshold;
        o.trace_chunk_slots = self.trace_chunk_slots;
        o.full_size_shards = self.full_size_shards;
        o
    }

    /// Loads `run.json` from `run_dir` if present and checks it against `fresh` (ignoring the
    /// nonce, which the stored file decides); otherwise writes `fresh`.
    pub fn load_or_init(run_dir: &Path, fresh: RunConfig) -> Result<(RunConfig, bool)> {
        let path = run_dir.join("run.json");
        if path.exists() {
            let stored: RunConfig =
                serde_json::from_slice(&std::fs::read(&path)?).with_context(|| format!("reading {}", path.display()))?;
            let mut want = fresh.clone();
            want.nonce = stored.nonce;
            if want != stored {
                bail!(
                    "{} holds a different run:\n  stored  {}\n  request {}\nuse another run directory",
                    path.display(),
                    serde_json::to_string(&stored)?,
                    serde_json::to_string(&want)?
                );
            }
            Ok((stored, true))
        } else {
            std::fs::create_dir_all(run_dir)?;
            std::fs::write(&path, serde_json::to_string_pretty(&fresh)? + "\n")?;
            Ok((fresh, false))
        }
    }
}

/// A nonce that differs between runs (SP1's SDK picks a fresh one per proof).
pub fn fresh_nonce() -> [u32; 4] {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let d = Sha256::digest(format!("{}:{}:{:?}", t.as_nanos(), std::process::id(), std::thread::current().id()));
    core::array::from_fn(|i| u32::from_le_bytes(d[4 * i..4 * i + 4].try_into().unwrap()))
}
