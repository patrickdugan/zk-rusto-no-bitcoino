//! Content-keyed memo of finished proving tasks.
//!
//! SP1's controller names every artifact with a fresh random id, so ids say nothing across
//! processes. A task is instead identified by what it proves:
//! - a shard task (`ProveShard`) by the run digest and the content of its trace record. A
//!   precompile shard's record points at chunk artifacts, so their contents are hashed in place of
//!   their ids;
//! - a recursion task (`RecursionReduce`) by the run digest, its literal inputs (completion flag and
//!   shard ranges) and the contents of the proofs it folds.
//!
//! The run digest covers the ELF, the stdin, the sharding options and the proof nonce, so a memo
//! entry is only ever replayed into the run configuration that produced it. Replaying an entry
//! uploads the recorded outputs under the new request's output ids. For a core shard that also
//! means re-uploading its deferred precompile chunks under their recorded ids and completing the
//! request's deferred-marker task, as the live prover does.
//!
//! Shard leaves always match on a rerun, since execution is deterministic. Recursion tasks match
//! when the controller groups the same proofs, which depends on arrival order; a recursion task
//! that does not match is simply proved again. A memo entry never stands in for a task whose inputs
//! differ.
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_prover::worker::{DeferredEvents, RawTaskRequest, TraceData};
use sp1_prover_types::{ArtifactClient, ArtifactId, ArtifactType};

use crate::store::{write_atomic, DiskArtifactClient};

pub type Key = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Shard,
    Reduce,
}

impl Kind {
    fn dir(self) -> &'static str {
        match self {
            Kind::Shard => "shard",
            Kind::Reduce => "reduce",
        }
    }
}

/// The recorded outputs of one finished task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The task's first output (the shard's lifted proof, or the folded recursion proof).
    pub out0: Vec<u8>,
    /// A core shard's deferred precompile events (`DeferredEvents`), if it has any.
    pub out1: Option<Vec<u8>>,
    /// The chunk artifacts `out1` points at, under their recorded ids.
    pub chunks: Vec<(String, Vec<u8>)>,
}

#[derive(Serialize, Deserialize)]
struct ChunkIndex {
    ids: Vec<String>,
}

#[derive(Default)]
pub struct Counters {
    pub shard_proved: AtomicU64,
    pub shard_replayed: AtomicU64,
    pub reduce_proved: AtomicU64,
    pub reduce_replayed: AtomicU64,
    pub shard_prove_ms: AtomicU64,
    pub reduce_prove_ms: AtomicU64,
}

pub struct Memo {
    dir: PathBuf,
    run_digest: Key,
    log: Mutex<std::fs::File>,
    pub counters: Counters,
}

fn sha(b: &[u8]) -> Key {
    Sha256::digest(b).into()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Memo {
    pub fn open(run_dir: &Path, run_digest: Key) -> Result<Self> {
        let dir = run_dir.join("memo");
        for k in [Kind::Shard, Kind::Reduce] {
            std::fs::create_dir_all(dir.join(k.dir()))?;
        }
        let log = OpenOptions::new().create(true).append(true).open(run_dir.join("progress.jsonl"))?;
        Ok(Self { dir, run_digest, log: Mutex::new(log), counters: Counters::default() })
    }

    fn entry_dir(&self, kind: Kind, key: &Key) -> PathBuf {
        self.dir.join(kind.dir()).join(hex::encode(key))
    }

    /// Number of finished entries of `kind` on disk.
    pub fn count(run_dir: &Path, kind: Kind) -> usize {
        std::fs::read_dir(run_dir.join("memo").join(kind.dir()))
            .map(|it| it.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('.')).count())
            .unwrap_or(0)
    }

    /// The key of a `ProveShard` request: inputs are [elf, common input, record, marker task].
    /// The ELF and common input are fixed by the run digest; the marker task id is random.
    pub async fn key_shard(&self, store: &DiskArtifactClient, request: &RawTaskRequest) -> Result<Key> {
        let record = store.download_raw(&request.inputs[2], ArtifactType::UnspecifiedArtifactType).await?;
        let mut h = Sha256::new();
        h.update(b"nb3-memo/v1/shard");
        h.update(self.run_digest);
        h.update((request.outputs.len() as u64).to_le_bytes());
        let td: TraceData = bincode::deserialize(&record).context("decoding the shard record")?;
        match td {
            TraceData::Core(bytes) => {
                h.update(b"core");
                h.update(sha(&bytes));
            }
            TraceData::Memory(_) => {
                h.update(b"memory");
                h.update(sha(&record));
            }
            TraceData::Precompile(slices, code) => {
                h.update(b"precompile");
                h.update(format!("{code:?}").as_bytes());
                for s in slices {
                    let chunk = store.download_raw(&s.artifact, ArtifactType::UnspecifiedArtifactType).await?;
                    h.update(sha(&chunk));
                    h.update((s.start_idx as u64).to_le_bytes());
                    h.update((s.end_idx as u64).to_le_bytes());
                }
            }
        }
        Ok(h.finalize().into())
    }

    /// The key of a `RecursionReduce` request: inputs are [is_complete, range, (range, proof)*],
    /// literals except the proofs at odd positions from 3 on.
    pub async fn key_reduce(&self, store: &DiskArtifactClient, request: &RawTaskRequest) -> Result<Key> {
        let mut h = Sha256::new();
        h.update(b"nb3-memo/v1/reduce");
        h.update(self.run_digest);
        if request.inputs.len() < 4 || request.inputs.len() % 2 != 0 {
            bail!("unexpected reduce request with {} inputs", request.inputs.len());
        }
        for (i, a) in request.inputs.iter().enumerate() {
            if i >= 3 && i % 2 == 1 {
                let proof = store.download_raw(a, ArtifactType::UnspecifiedArtifactType).await?;
                h.update(b"P");
                h.update(sha(&proof));
            } else {
                h.update(b"L");
                h.update((a.id().len() as u64).to_le_bytes());
                h.update(a.id().as_bytes());
            }
        }
        Ok(h.finalize().into())
    }

    pub fn get(&self, kind: Kind, key: &Key) -> Option<Entry> {
        let d = self.entry_dir(kind, key);
        let out0 = std::fs::read(d.join("out0")).ok()?;
        let out1 = std::fs::read(d.join("out1")).ok();
        let mut chunks = Vec::new();
        if let Ok(idx) = std::fs::read(d.join("chunks.json")) {
            let idx: ChunkIndex = serde_json::from_slice(&idx).ok()?;
            for (n, id) in idx.ids.into_iter().enumerate() {
                chunks.push((id, std::fs::read(d.join(format!("chunk{n}"))).ok()?));
            }
        }
        Some(Entry { out0, out1, chunks })
    }

    /// Records an entry. Files go to a temporary directory that is renamed into place, so an entry
    /// is either complete or absent.
    pub fn put(&self, kind: Kind, key: &Key, e: &Entry) -> Result<()> {
        let fin = self.entry_dir(kind, key);
        if fin.exists() {
            return Ok(());
        }
        let tmp = self.dir.join(kind.dir()).join(format!(".tmp-{}-{}", hex::encode(key), std::process::id()));
        if tmp.exists() {
            std::fs::remove_dir_all(&tmp)?;
        }
        std::fs::create_dir_all(&tmp)?;
        write_atomic(&tmp.join("out0"), &e.out0)?;
        if let Some(b) = &e.out1 {
            write_atomic(&tmp.join("out1"), b)?;
        }
        if !e.chunks.is_empty() {
            for (n, (_, b)) in e.chunks.iter().enumerate() {
                write_atomic(&tmp.join(format!("chunk{n}")), b)?;
            }
            let idx = ChunkIndex { ids: e.chunks.iter().map(|(id, _)| id.clone()).collect() };
            write_atomic(&tmp.join("chunks.json"), &serde_json::to_vec(&idx)?)?;
        }
        match std::fs::rename(&tmp, &fin) {
            Ok(()) => Ok(()),
            Err(_) if fin.exists() => {
                std::fs::remove_dir_all(&tmp)?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Appends one line to `progress.jsonl` and updates the counters.
    pub fn record(&self, kind: Kind, key: &Key, replayed: bool, millis: u64) {
        let c = &self.counters;
        match (kind, replayed) {
            (Kind::Shard, false) => {
                c.shard_proved.fetch_add(1, Ordering::Relaxed);
                c.shard_prove_ms.fetch_add(millis, Ordering::Relaxed);
            }
            (Kind::Shard, true) => {
                c.shard_replayed.fetch_add(1, Ordering::Relaxed);
            }
            (Kind::Reduce, false) => {
                c.reduce_proved.fetch_add(1, Ordering::Relaxed);
                c.reduce_prove_ms.fetch_add(millis, Ordering::Relaxed);
            }
            (Kind::Reduce, true) => {
                c.reduce_replayed.fetch_add(1, Ordering::Relaxed);
            }
        }
        let line = serde_json::json!({
            "t": now_secs(), "kind": kind.dir(), "replayed": replayed, "ms": millis,
            "key": hex::encode(&key[..8]),
        });
        if let Ok(mut f) = self.log.lock() {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Reads a finished `ProveShard` task's outputs, including the deferred chunks its `DeferredEvents`
/// names (which the controller may already have consumed; see `store.rs`).
pub async fn capture_shard(store: &DiskArtifactClient, request: &RawTaskRequest) -> Result<Entry> {
    let out0 = store.read_live_or_trash(request.outputs[0].id()).await?;
    let (out1, chunks) = match request.outputs.get(1) {
        None => (None, Vec::new()),
        Some(d) => {
            let b = store.read_live_or_trash(d.id()).await?;
            let ev: DeferredEvents = bincode::deserialize(&b).context("decoding DeferredEvents")?;
            let mut ids: Vec<String> = ev.0.values().flatten().map(|s| s.artifact.id().to_string()).collect();
            ids.sort();
            ids.dedup();
            let mut chunks = Vec::with_capacity(ids.len());
            for id in ids {
                let c = store.read_live_or_trash(&id).await?;
                chunks.push((id, c));
            }
            (Some(b), chunks)
        }
    };
    Ok(Entry { out0, out1, chunks })
}
