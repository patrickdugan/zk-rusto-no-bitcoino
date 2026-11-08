//! An SP1 6.9 proving node over the disk store, with memoized shard and recursion tasks.
//!
//! The task handlers follow `sp1_prover::worker::SP1LocalNodeBuilder::build` (SP1 6.9.0,
//! MIT/Apache-2.0, crates/prover/src/worker/node/full/init.rs): the same controller, executor,
//! setup, shard, recursion and deferred handlers over SP1's public worker API. Two things differ:
//! the artifact client is [`DiskArtifactClient`], and the `ProveShard` and `RecursionReduce`
//! handlers consult the [`Memo`] before proving and record into it after.
use std::{fmt::Debug, path::Path, sync::Arc, time::Duration, time::Instant};

use anyhow::{anyhow, Result};
use sp1_core_executor::{SP1Context, SP1CoreOpts};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    worker::{
        CoreExecuteTaskRequest, LocalWorkerClient, ProofFromNetwork, ProofId, RawTaskRequest, RequesterId,
        SP1NodeCore, SP1Worker, SP1WorkerBuilder, TaskContext, TaskError, TaskId, TaskMetadata, WorkerClient,
    },
    SP1ProverComponents, SP1VerifyingKey,
};
use sp1_prover_types::{
    network_base_types::ProofMode, Artifact, ArtifactClient, ArtifactId, ArtifactType, ProofArtifacts,
    ProofRequestStatus, TaskStatus, TaskType,
};
use tokio::{sync::mpsc, task::JoinSet};

use crate::{
    memo::{capture_shard, rebind_deferred_chunks, Entry, Kind, Memo},
    store::DiskArtifactClient,
};

pub struct ShardedNode {
    pub store: DiskArtifactClient,
    worker_client: LocalWorkerClient,
    pub core: SP1NodeCore,
    pub memo: Arc<Memo>,
    _tasks: JoinSet<()>,
}

/// Minimum time deleted artifacts stay readable (see `store.rs`).
const TRASH_GRACE: Duration = Duration::from_secs(120);

impl ShardedNode {
    /// Builds the node from a worker builder whose provers are set (see [`crate::backend`]).
    pub async fn build<C: SP1ProverComponents>(
        run_dir: &Path,
        memo: Arc<Memo>,
        opts: SP1CoreOpts,
        builder: SP1WorkerBuilder<C>,
    ) -> Result<Self> {
        let index = ProofArtifacts::default();
        let store = DiskArtifactClient::open(&run_dir.join("artifacts"), index.clone())?;
        store.spawn_trash_sweeper(TRASH_GRACE);
        let (worker_client, mut channels) = LocalWorkerClient::init_with_index(index);

        let worker: SP1Worker<DiskArtifactClient, LocalWorkerClient, C> =
            builder.with_artifact_client(store.clone()).with_worker_client(worker_client.clone()).build().await?;

        let mut tasks = JoinSet::new();
        let mut take = |t: TaskType| channels.task_receivers.remove(&t).ok_or_else(|| anyhow!("no receiver for {t:?}"));

        // Controller: runs the whole proof request, then deletes its inputs.
        {
            let mut rx = take(TaskType::Controller)?;
            let worker = worker.clone();
            tasks.spawn(async move {
                while let Some((task_id, request)) = rx.recv().await {
                    if let Err(e) = worker.controller().run(request.clone()).await {
                        tracing::error!("controller task failed: {e:?}");
                    }
                    if let Err(e) = worker
                        .worker_client()
                        .complete_task(request.context.proof_id.clone(), task_id, TaskMetadata { gpu_ms: None })
                        .await
                    {
                        tracing::error!("controller completion failed: {e:?}");
                    }
                    for input in request.inputs {
                        let _ = worker.artifact_client().delete(&input, ArtifactType::UnspecifiedArtifactType).await;
                    }
                }
            });
        }

        // CoreExecute.
        {
            let mut rx = take(TaskType::CoreExecute)?;
            let worker = worker.clone();
            tasks.spawn(async move {
                while let Some((task_id, request)) = rx.recv().await {
                    let proof_id = request.context.proof_id.clone();
                    match CoreExecuteTaskRequest::from_raw(request) {
                        Ok(req) => {
                            if let Err(e) = worker.controller().execute(task_id.clone(), req).await {
                                tracing::error!("core execute task failed: {e:?}");
                            }
                        }
                        Err(e) => tracing::error!("core execute request: {e:?}"),
                    }
                    if let Err(e) =
                        worker.worker_client().complete_task(proof_id, task_id, TaskMetadata { gpu_ms: None }).await
                    {
                        tracing::error!("core execute completion failed: {e:?}");
                    }
                }
            });
        }

        // SetupVkey.
        {
            let mut rx = take(TaskType::SetupVkey)?;
            let worker = worker.clone();
            let wc = worker.worker_client().clone();
            tasks.spawn(async move {
                let mut set = JoinSet::new();
                let (tx, mut out_rx) = mpsc::unbounded_channel::<TaskOutput>();
                loop {
                    tokio::select! {
                        Some((id, request)) = rx.recv() => {
                            let proof_id = request.context.proof_id.clone();
                            let (elf, output) = (request.inputs[0].clone(), request.outputs[0].clone());
                            match worker.prover_engine().submit_setup(id.clone(), elf, output).await {
                                Ok(handle) => {
                                    let tx = tx.clone();
                                    set.spawn(async move {
                                        let r = handle.await.map(|res| res.map(|(_, m)| m));
                                        TaskOutput::send(r, &tx, proof_id, id, request, TaskType::SetupVkey);
                                    });
                                }
                                Err(e) => TaskOutput::send(Ok::<_, String>(Err(e.into())), &tx, proof_id, id, request, TaskType::SetupVkey),
                            }
                        }
                        Some(o) = out_rx.recv() => o.handle(&wc).await,
                        else => break,
                    }
                }
            });
        }

        // ProveShard, memoized.
        {
            let mut rx = take(TaskType::ProveShard)?;
            let worker = worker.clone();
            let wc = worker.worker_client().clone();
            let (memo, store) = (memo.clone(), store.clone());
            tasks.spawn(async move {
                let mut set = JoinSet::new();
                let (tx, mut out_rx) = mpsc::unbounded_channel::<TaskOutput>();
                loop {
                    tokio::select! {
                        Some((id, request)) = rx.recv() => {
                            let proof_id = request.context.proof_id.clone();
                            let key = match memo.key_shard(&store, &request).await {
                                Ok(k) => Some(k),
                                Err(e) => { tracing::warn!("shard memo key: {e:#}"); None }
                            };
                            let hit = key.as_ref().and_then(|k| memo.get(Kind::Shard, k))
                                .filter(|e| e.out1.is_some() == (request.outputs.len() == 2));
                            let tx = tx.clone();
                            match (key, hit) {
                                (Some(key), Some(entry)) => {
                                    let (store, wc, memo) = (store.clone(), wc.clone(), memo.clone());
                                    set.spawn(async move {
                                        let r = replay_shard(&store, &wc, &request, entry).await;
                                        if r.is_ok() { memo.record(Kind::Shard, &key, true, 0); }
                                        TaskOutput::send(Ok::<_, String>(r), &tx, proof_id, id, request, TaskType::ProveShard);
                                    });
                                }
                                (key, _) => {
                                    let t0 = Instant::now();
                                    // Keeps this shard's deferred chunks out of the trash sweep until captured.
                                    let token = store.task_started();
                                    match worker.prover_engine().submit_prove_core_shard(request.clone()).await {
                                        Ok(handle) => {
                                            let (store, memo) = (store.clone(), memo.clone());
                                            set.spawn(async move {
                                                let r = match handle.await {
                                                    Ok(r) => Ok(request.recover_if_complete(r, &store).await),
                                                    Err(e) => Err(e),
                                                };
                                                if let (Ok(Ok(_)), Some(key)) = (&r, key) {
                                                    match capture_shard(&store, &request).await.and_then(|e| memo.put(Kind::Shard, &key, &e)) {
                                                        Ok(()) => memo.record(Kind::Shard, &key, false, t0.elapsed().as_millis() as u64),
                                                        Err(e) => tracing::warn!("shard memo capture: {e:#}"),
                                                    }
                                                }
                                                store.task_finished(token);
                                                TaskOutput::send(r, &tx, proof_id, id, request, TaskType::ProveShard);
                                            });
                                        }
                                        Err(e) => {
                                            store.task_finished(token);
                                            TaskOutput::send(Ok::<_, String>(Err(e)), &tx, proof_id, id, request, TaskType::ProveShard)
                                        }
                                    }
                                }
                            }
                        }
                        Some(o) = out_rx.recv() => o.handle(&wc).await,
                        else => break,
                    }
                }
            });
        }

        // RecursionReduce, memoized.
        {
            let mut rx = take(TaskType::RecursionReduce)?;
            let worker = worker.clone();
            let wc = worker.worker_client().clone();
            let (memo, store) = (memo.clone(), store.clone());
            tasks.spawn(async move {
                let mut set = JoinSet::new();
                let (tx, mut out_rx) = mpsc::unbounded_channel::<TaskOutput>();
                loop {
                    tokio::select! {
                        Some((id, request)) = rx.recv() => {
                            let proof_id = request.context.proof_id.clone();
                            let key = match memo.key_reduce(&store, &request).await {
                                Ok(k) => Some(k),
                                Err(e) => { tracing::warn!("reduce memo key: {e:#}"); None }
                            };
                            let hit = key.as_ref().and_then(|k| memo.get(Kind::Reduce, k));
                            let tx = tx.clone();
                            match (key, hit) {
                                (Some(key), Some(entry)) => {
                                    let (store, memo) = (store.clone(), memo.clone());
                                    set.spawn(async move {
                                        let r = store
                                            .upload_raw(&request.outputs[0], ArtifactType::UnspecifiedArtifactType, entry.out0)
                                            .await
                                            .map(|()| TaskMetadata::default())
                                            .map_err(TaskError::Fatal);
                                        if r.is_ok() { memo.record(Kind::Reduce, &key, true, 0); }
                                        TaskOutput::send(Ok::<_, String>(r), &tx, proof_id, id, request, TaskType::RecursionReduce);
                                    });
                                }
                                (key, _) => {
                                    let t0 = Instant::now();
                                    match worker.prover_engine().submit_recursion_reduce(request.clone()).await {
                                        Ok(handle) => {
                                            let (store, memo) = (store.clone(), memo.clone());
                                            set.spawn(async move {
                                                let r = match handle.await {
                                                    Ok(r) => Ok(request.recover_if_complete(r, &store).await),
                                                    Err(e) => Err(e),
                                                };
                                                if let (Ok(Ok(_)), Some(key)) = (&r, key) {
                                                    let captured = store.read_live_or_trash(request.outputs[0].id()).await.and_then(|out0| {
                                                        memo.put(Kind::Reduce, &key, &Entry { out0, out1: None, chunks: Vec::new() })
                                                    });
                                                    match captured {
                                                        Ok(()) => memo.record(Kind::Reduce, &key, false, t0.elapsed().as_millis() as u64),
                                                        Err(e) => tracing::warn!("reduce memo capture: {e:#}"),
                                                    }
                                                }
                                                TaskOutput::send(r, &tx, proof_id, id, request, TaskType::RecursionReduce);
                                            });
                                        }
                                        Err(e) => TaskOutput::send(Ok::<_, String>(Err(e)), &tx, proof_id, id, request, TaskType::RecursionReduce),
                                    }
                                }
                            }
                        }
                        Some(o) = out_rx.recv() => o.handle(&wc).await,
                        else => break,
                    }
                }
            });
        }

        // RecursionDeferred (proofs verified inside the guest); not memoized.
        {
            let mut rx = take(TaskType::RecursionDeferred)?;
            let worker = worker.clone();
            let wc = worker.worker_client().clone();
            tasks.spawn(async move {
                let mut set = JoinSet::new();
                let (tx, mut out_rx) = mpsc::unbounded_channel::<TaskOutput>();
                loop {
                    tokio::select! {
                        Some((id, request)) = rx.recv() => {
                            let proof_id = request.context.proof_id.clone();
                            match worker.prover_engine().submit_prove_deferred(request.clone()).await {
                                Ok(handle) => {
                                    let tx = tx.clone();
                                    set.spawn(async move {
                                        let r = handle.await;
                                        TaskOutput::send(r, &tx, proof_id, id, request, TaskType::RecursionDeferred);
                                    });
                                }
                                Err(e) => TaskOutput::send(Ok::<_, String>(Err(e)), &tx, proof_id, id, request, TaskType::RecursionDeferred),
                            }
                        }
                        Some(o) = out_rx.recv() => o.handle(&wc).await,
                        else => break,
                    }
                }
            });
        }

        // Deferred-marker tasks are completed by the shard that owns them; drain the queue.
        {
            let mut rx = take(TaskType::MarkerDeferredRecord)?;
            tasks.spawn(async move { while rx.recv().await.is_some() {} });
        }

        // This node stops at the compressed proof: shrink, wrap and key-map tasks are not served.
        for (t, mut rx) in std::mem::take(&mut channels.task_receivers) {
            tasks.spawn(async move {
                while let Some((id, _)) = rx.recv().await {
                    tracing::error!("task {id} of type {t:?} is not served by this node");
                }
            });
        }

        let core = SP1NodeCore::new(worker.verifier().clone(), opts);
        Ok(Self { store, worker_client, core, memo, _tasks: tasks })
    }

    fn context(proof_id: &str) -> TaskContext {
        TaskContext {
            proof_id: ProofId::new(proof_id),
            parent_id: None,
            parent_context: None,
            requester_id: RequesterId::new(format!("nb3-prover-{}", std::process::id())),
        }
    }

    /// The program's verifying key (SP1's setup task).
    pub async fn setup(&self, elf: &[u8]) -> Result<SP1VerifyingKey> {
        let elf_artifact = self.store.create_artifact()?;
        self.store.upload_program(&elf_artifact, elf.to_vec()).await?;
        let vk_artifact = self.store.create_artifact()?;
        let context = Self::context("setup");
        let request = RawTaskRequest {
            inputs: vec![elf_artifact.clone()],
            outputs: vec![vk_artifact.clone()],
            context: context.clone(),
        };
        let id = self.worker_client.submit_task(TaskType::SetupVkey, request).await?;
        let status = self.worker_client.subscriber(context.proof_id.clone()).await?.per_task().wait_task(id).await?;
        if status != TaskStatus::Succeeded {
            return Err(anyhow!("setup task failed"));
        }
        let vk = self.store.download::<SP1VerifyingKey>(&vk_artifact).await?;
        self.store.try_delete(&elf_artifact, ArtifactType::Program).await?;
        self.store.try_delete(&vk_artifact, ArtifactType::UnspecifiedArtifactType).await?;
        Ok(vk)
    }

    /// A compressed proof of `elf` on `stdin` with the given proof nonce.
    pub async fn prove_compressed(&self, elf: &[u8], stdin: SP1Stdin, nonce: [u32; 4]) -> Result<ProofFromNetwork> {
        let elf_artifact = self.store.create_artifact()?;
        let nonce_artifact = self.store.create_artifact()?;
        let stdin_artifact = self.store.create_artifact()?;
        let output_artifact = self.store.create_artifact()?;
        let proof_id = format!("proof-{}", std::process::id());
        let context = Self::context(&proof_id);
        let result = async {
            self.store.upload_program(&elf_artifact, elf.to_vec()).await?;
            self.store.upload::<[u32; 4]>(&nonce_artifact, nonce).await?;
            self.store.upload_with_type(&stdin_artifact, ArtifactType::Stdin, stdin).await?;
            let mode = Artifact((ProofMode::Compressed as i32).to_string());
            let request = RawTaskRequest {
                inputs: vec![elf_artifact.clone(), stdin_artifact.clone(), mode, nonce_artifact.clone()],
                outputs: vec![output_artifact.clone()],
                context: context.clone(),
            };
            let id = self.worker_client.submit_task(TaskType::Controller, request).await?;
            let status = self.worker_client.subscriber(context.proof_id.clone()).await?.per_task().wait_task(id).await?;
            if status != TaskStatus::Succeeded {
                return Err(anyhow!("controller task failed"));
            }
            self.store.download::<ProofFromNetwork>(&output_artifact).await
        }
        .await;
        let status = if result.is_ok() { ProofRequestStatus::Completed } else { ProofRequestStatus::Failed };
        let _ = self.worker_client.complete_proof(context.proof_id.clone(), None, status, "").await;
        self.worker_client.cleanup(&context.proof_id, &self.store).await;
        result
    }

    /// Executes `elf` on `stdin` without proving.
    pub async fn execute(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<(sp1_primitives::io::SP1PublicValues, sp1_core_executor::ExecutionReport)> {
        let (pv, _digest, report) = self.core.execute(elf, stdin, SP1Context::default()).await?;
        Ok((pv, report))
    }
}

/// Replays a memoized `ProveShard`: deferred chunks under fresh ids, the deferred events
/// into this request's deferred output (completing its marker task), then the proof.
async fn replay_shard(
    store: &DiskArtifactClient,
    wc: &LocalWorkerClient,
    request: &RawTaskRequest,
    e: Entry,
) -> Result<TaskMetadata, TaskError> {
    let fatal = |e: anyhow::Error| TaskError::Fatal(e);
    match (request.outputs.get(1), e.out1) {
        (Some(d), Some(b)) => {
            let (events, chunks) = rebind_deferred_chunks(&b, e.chunks, || {
                Ok(store.create_artifact()?.id().to_string())
            }).map_err(fatal)?;
            for (id, bytes) in chunks {
                store.upload_raw(&id, ArtifactType::UnspecifiedArtifactType, bytes).await.map_err(fatal)?;
            }
            store.upload_raw(d, ArtifactType::UnspecifiedArtifactType, events).await.map_err(fatal)?;
            let marker = TaskId::new(request.inputs[3].id().to_string());
            wc.complete_task(request.context.proof_id.clone(), marker, TaskMetadata::default()).await.map_err(fatal)?;
        }
        (None, None) if e.chunks.is_empty() => {}
        _ => return Err(TaskError::Fatal(anyhow!("memo entry and request disagree on the deferred output"))),
    }
    store.upload_raw(&request.outputs[0], ArtifactType::UnspecifiedArtifactType, e.out0).await.map_err(fatal)?;
    Ok(TaskMetadata::default())
}



/// A finished task's status on its way back to the worker client (as in SP1's local node).
struct TaskOutput {
    proof_id: ProofId,
    task_id: TaskId,
    status: TaskStatus,
    metadata: TaskMetadata,
    retry: Option<(TaskType, RawTaskRequest)>,
}

impl TaskOutput {
    fn send<E: Debug>(
        result: Result<Result<TaskMetadata, TaskError>, E>,
        tx: &mpsc::UnboundedSender<TaskOutput>,
        proof_id: ProofId,
        task_id: TaskId,
        request: RawTaskRequest,
        task_type: TaskType,
    ) {
        let (status, metadata, retry) = match result {
            Ok(Ok(m)) => (TaskStatus::Succeeded, m, None),
            Ok(Err(TaskError::Retryable(e))) => {
                tracing::error!("{task_type:?} {task_id} failed (retryable): {e:?}");
                (TaskStatus::FailedRetryable, TaskMetadata::default(), Some((task_type, request)))
            }
            Ok(Err(e)) => {
                tracing::error!("{task_type:?} {task_id} failed: {e:?}");
                (TaskStatus::FailedFatal, TaskMetadata::default(), None)
            }
            Err(e) => {
                tracing::error!("{task_type:?} {task_id} panicked: {e:?}");
                (TaskStatus::FailedFatal, TaskMetadata::default(), None)
            }
        };
        let _ = tx.send(TaskOutput { proof_id, task_id, status, metadata, retry });
    }

    async fn handle(self, wc: &LocalWorkerClient) {
        let TaskOutput { proof_id, task_id, status, metadata, retry } = self;
        match status {
            TaskStatus::Succeeded => {
                if let Err(e) = wc.complete_task(proof_id, task_id.clone(), metadata).await {
                    tracing::error!("completing task {task_id}: {e:?}");
                }
            }
            TaskStatus::FailedRetryable => {
                let (t, request) = retry.expect("retryable output carries its request");
                match wc.resubmit_task(t, request).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        tracing::error!("task {task_id} exhausted its retries");
                        let _ = wc.update_task_status(task_id, TaskStatus::FailedFatal).await;
                    }
                    Err(e) => tracing::error!("resubmitting task {task_id}: {e:?}"),
                }
            }
            _ => {
                let _ = wc.update_task_status(task_id, TaskStatus::FailedFatal).await;
            }
        }
    }
}
