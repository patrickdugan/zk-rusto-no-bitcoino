//! A disk-backed implementation of SP1's `ArtifactClient`.
//!
//! SP1's local node keeps every artifact (execution chunks, shard records, shard proofs, recursion
//! proofs) in a `HashMap` in RAM. For a program of billions of instructions that map, not the
//! prover, sets the memory floor. This store writes each artifact to its own file, so resident
//! memory is bounded by what the provers hold, not by the run's length.
//!
//! Deletes move the file to `trash/` (stamping the deletion time) instead of unlinking it. The memo
//! (see `memo.rs`) reads finished task outputs through [`DiskArtifactClient::read_live_or_trash`]:
//! a core shard uploads its deferred precompile chunks early, the controller can consume and delete
//! them while the shard is still proving, and the memo reads them only when the shard finishes.
//! A chunk is needed only by the shard that wrote it, which was already running when the chunk was
//! written; so the sweep removes trash deleted before the oldest shard task still in flight
//! started ([`DiskArtifactClient::task_started`]), and at least a grace period ago.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use sp1_prover_types::{ArtifactClient, ArtifactId, ArtifactType, ProofArtifacts};

#[derive(Clone)]
pub struct DiskArtifactClient {
    inner: Arc<Inner>,
}

struct Inner {
    live: PathBuf,
    trash: PathBuf,
    index: ProofArtifacts,
    /// Start times of shard tasks in flight, by token.
    inflight: Mutex<BTreeMap<u64, SystemTime>>,
    next_token: AtomicU64,
}

impl DiskArtifactClient {
    /// Opens a store under `dir`, discarding anything a previous process left there: artifact ids
    /// are random per run, so nothing in the store outlives the process that wrote it. What does
    /// persist across runs lives in the memo, not here.
    pub fn open(dir: &Path, index: ProofArtifacts) -> Result<Self> {
        let live = dir.join("live");
        let trash = dir.join("trash");
        for d in [&live, &trash] {
            if d.exists() {
                std::fs::remove_dir_all(d).with_context(|| format!("clearing {}", d.display()))?;
            }
            std::fs::create_dir_all(d)?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                live,
                trash,
                index,
                inflight: Mutex::new(BTreeMap::new()),
                next_token: AtomicU64::new(0),
            }),
        })
    }

    /// Records that a shard task started; trash deleted after this moment is kept until
    /// [`Self::task_finished`] is called with the returned token.
    pub fn task_started(&self) -> u64 {
        let t = self.inner.next_token.fetch_add(1, Ordering::Relaxed);
        self.inner.inflight.lock().unwrap().insert(t, SystemTime::now());
        t
    }

    pub fn task_finished(&self, token: u64) {
        self.inner.inflight.lock().unwrap().remove(&token);
    }

    /// Trash deleted before this moment is no longer needed by any capture.
    fn sweep_cutoff(&self, grace: Duration) -> SystemTime {
        let now = SystemTime::now();
        let oldest = self.inner.inflight.lock().unwrap().values().min().copied().unwrap_or(now);
        oldest.min(now - grace)
    }

    /// Starts the sweep that removes trash no capture can still need (see the module docs).
    pub fn spawn_trash_sweeper(&self, grace: Duration) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let (trash, cutoff) = (this.inner.trash.clone(), this.sweep_cutoff(grace));
                let _ = tokio::task::spawn_blocking(move || sweep(&trash, cutoff)).await;
            }
        });
    }

    /// Runs one sweep now (tests).
    pub fn sweep_now(&self, grace: Duration) {
        sweep(&self.inner.trash, self.sweep_cutoff(grace));
    }

    fn file_name(id: &str) -> String {
        // Ids are opaque strings; hash them into safe, fixed-length file names.
        hex::encode(&Sha256::digest(id.as_bytes())[..20])
    }

    fn live_path(&self, id: &str) -> PathBuf {
        self.inner.live.join(Self::file_name(id))
    }

    fn trash_path(&self, id: &str) -> PathBuf {
        self.inner.trash.join(Self::file_name(id))
    }

    /// Reads an artifact that may already have been deleted (within the trash grace period).
    pub async fn read_live_or_trash(&self, id: &str) -> Result<Vec<u8>> {
        let (live, trash) = (self.live_path(id), self.trash_path(id));
        tokio::task::spawn_blocking(move || match std::fs::read(&live) {
            Ok(b) => Ok(b),
            Err(_) => std::fs::read(&trash).map_err(|e| anyhow!("artifact neither live nor in trash: {e}")),
        })
        .await?
    }

    /// Bytes currently held in the live directory (for progress reports).
    pub fn live_bytes(&self) -> u64 {
        dir_bytes(&self.inner.live)
    }
}

fn dir_bytes(d: &Path) -> u64 {
    std::fs::read_dir(d)
        .map(|it| it.filter_map(|e| e.ok()?.metadata().ok()).map(|m| m.len()).sum())
        .unwrap_or(0)
}

/// Removes trash whose deletion stamp (its modification time) is before `cutoff`.
fn sweep(trash: &Path, cutoff: SystemTime) {
    let Ok(entries) = std::fs::read_dir(trash) else { return };
    for e in entries.flatten() {
        let old = e.metadata().and_then(|m| m.modified()).map(|t| t < cutoff).unwrap_or(false);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Writes `data` to `path` through a temporary file and a rename, so a crash never leaves a
/// truncated artifact under its final name.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

impl ArtifactClient for DiskArtifactClient {
    async fn upload_raw(&self, artifact: &impl ArtifactId, _t: ArtifactType, data: Vec<u8>) -> Result<()> {
        let path = self.live_path(artifact.id());
        tokio::task::spawn_blocking(move || write_atomic(&path, &data)).await?
    }

    async fn download_raw(&self, artifact: &impl ArtifactId, _t: ArtifactType) -> Result<Vec<u8>> {
        let path = self.live_path(artifact.id());
        let id = artifact.id().to_string();
        tokio::task::spawn_blocking(move || std::fs::read(&path).map_err(|e| anyhow!("artifact {id} not found: {e}")))
            .await?
    }

    async fn exists(&self, artifact: &impl ArtifactId, _t: ArtifactType) -> Result<bool> {
        Ok(tokio::fs::try_exists(self.live_path(artifact.id())).await.unwrap_or(false))
    }

    async fn delete(&self, artifact: &impl ArtifactId, _t: ArtifactType) -> Result<()> {
        let (live, trash) = (self.live_path(artifact.id()), self.trash_path(artifact.id()));
        self.inner.index.untrack(artifact.id());
        // Deleting an artifact that is already gone is not an error: cleanup passes run over
        // artifacts that the controller deleted inline. The modification time becomes the
        // deletion stamp the sweep reads.
        if tokio::fs::rename(&live, &trash).await.is_ok() {
            let _ = tokio::task::spawn_blocking(move || {
                std::fs::File::options().write(true).open(&trash).and_then(|f| f.set_modified(SystemTime::now()))
            })
            .await;
        }
        Ok(())
    }

    async fn delete_batch(&self, artifacts: &[impl ArtifactId], t: ArtifactType) -> Result<()> {
        for a in artifacts {
            self.delete(a, t).await?;
        }
        Ok(())
    }
}
