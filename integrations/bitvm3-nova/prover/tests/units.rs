//! Store, memo and run-configuration behaviour that does not need a prover.
use std::path::PathBuf;

use nb3_prover::{
    config::RunConfig,
    memo::{capture_shard, Entry, Kind, Memo},
    store::DiskArtifactClient,
};
use sp1_core_executor::SyscallCode;
use sp1_prover::worker::{
    DeferredEvents, PrecompileArtifactSlice, ProofId, RawTaskRequest, RequesterId, TaskContext, TraceData,
};
use sp1_prover_types::{Artifact, ArtifactClient, ArtifactType, ProofArtifacts};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nb3-prover-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn config() -> RunConfig {
    RunConfig {
        sp1_version: "6.9.0".into(),
        elf_sha256: "00".repeat(32),
        inputs_sha256: vec!["11".repeat(32)],
        element_threshold: 1 << 26,
        height_threshold: 1 << 20,
        shard_size: 1 << 24,
        minimal_trace_chunk_threshold: 1 << 24,
        trace_chunk_slots: 2,
        full_size_shards: false,
        nonce: [1, 2, 3, 4],
    }
}

fn request(inputs: &[&str], outputs: &[&str]) -> RawTaskRequest {
    RawTaskRequest {
        inputs: inputs.iter().map(|s| Artifact::from(s.to_string())).collect(),
        outputs: outputs.iter().map(|s| Artifact::from(s.to_string())).collect(),
        context: TaskContext {
            proof_id: ProofId::new("p"),
            parent_id: None,
            parent_context: None,
            requester_id: RequesterId::new("t"),
        },
    }
}

const U: ArtifactType = ArtifactType::UnspecifiedArtifactType;

#[tokio::test]
async fn store_round_trip_and_trash() {
    let d = tmp("store");
    let s = DiskArtifactClient::open(&d, ProofArtifacts::default()).unwrap();
    let a = Artifact::from("artifact_x".to_string());
    s.upload_raw(&a, U, b"hello".to_vec()).await.unwrap();
    assert!(s.exists(&a, U).await.unwrap());
    assert_eq!(s.download_raw(&a, U).await.unwrap(), b"hello");
    s.delete(&a, U).await.unwrap();
    assert!(!s.exists(&a, U).await.unwrap());
    assert!(s.download_raw(&a, U).await.is_err(), "a deleted artifact is not downloadable");
    assert_eq!(s.read_live_or_trash("artifact_x").await.unwrap(), b"hello", "but stays readable from trash");
    s.delete(&a, U).await.unwrap(); // deleting twice is not an error

    // Reopening discards everything: artifact ids are per process.
    let s2 = DiskArtifactClient::open(&d, ProofArtifacts::default()).unwrap();
    assert!(s2.read_live_or_trash("artifact_x").await.is_err());
}

#[tokio::test]
async fn memo_entries_round_trip_atomically() {
    let d = tmp("memo");
    let m = Memo::open(&d, config().digest()).unwrap();
    let key = [7u8; 32];
    assert!(m.get(Kind::Shard, &key).is_none());
    let e = Entry {
        out0: vec![1, 2, 3],
        out1: Some(vec![4, 5]),
        chunks: vec![("artifact_a".into(), vec![6]), ("artifact_b".into(), vec![7, 8])],
    };
    m.put(Kind::Shard, &key, &e).unwrap();
    m.put(Kind::Shard, &key, &e).unwrap(); // idempotent
    assert_eq!(m.get(Kind::Shard, &key).unwrap(), e);
    assert!(m.get(Kind::Reduce, &key).is_none(), "kinds are separate");
    assert_eq!(Memo::count(&d, Kind::Shard), 1);
    m.record(Kind::Shard, &key, false, 1500);
    let log = std::fs::read_to_string(d.join("progress.jsonl")).unwrap();
    assert!(log.contains("\"kind\":\"shard\"") && log.contains("\"ms\":1500"));
}

#[tokio::test]
async fn shard_keys_follow_content_not_ids() {
    let d = tmp("keys");
    let s = DiskArtifactClient::open(&d.join("a"), ProofArtifacts::default()).unwrap();
    let m = Memo::open(&d, config().digest()).unwrap();

    // Core record: the key ignores the marker task id and the artifact ids.
    let core = bincode::serialize(&TraceData::Core(vec![9; 100])).unwrap();
    s.upload_raw(&Artifact::from("rec1".to_string()), U, core.clone()).await.unwrap();
    s.upload_raw(&Artifact::from("rec2".to_string()), U, core).await.unwrap();
    let k1 = m.key_shard(&s, &request(&["elf", "ci", "rec1", "marker1"], &["o", "d"])).await.unwrap();
    let k2 = m.key_shard(&s, &request(&["elf2", "ci2", "rec2", "marker2"], &["o2", "d2"])).await.unwrap();
    assert_eq!(k1, k2);
    let other = bincode::serialize(&TraceData::Core(vec![8; 100])).unwrap();
    s.upload_raw(&Artifact::from("rec3".to_string()), U, other).await.unwrap();
    let k3 = m.key_shard(&s, &request(&["elf", "ci", "rec3", "marker1"], &["o", "d"])).await.unwrap();
    assert_ne!(k1, k3, "different records, different keys");

    // Precompile record: chunk ids differ, chunk contents equal, so keys are equal.
    for (id, body) in [("c1", b"chunk".to_vec()), ("c2", b"chunk".to_vec()), ("c3", b"other".to_vec())] {
        s.upload_raw(&Artifact::from(id.to_string()), U, body).await.unwrap();
    }
    let pre = |chunk: &str| {
        bincode::serialize(&TraceData::Precompile(
            vec![PrecompileArtifactSlice { artifact: Artifact::from(chunk.to_string()), start_idx: 0, end_idx: 4 }],
            SyscallCode::SHA_COMPRESS,
        ))
        .unwrap()
    };
    for (rec, chunk) in [("p1", "c1"), ("p2", "c2"), ("p3", "c3")] {
        s.upload_raw(&Artifact::from(rec.to_string()), U, pre(chunk)).await.unwrap();
    }
    let kp = |rec: &'static str| {
        let (m, s) = (&m, &s);
        async move { m.key_shard(s, &request(&["e", "c", rec, "mk"], &["o"])).await.unwrap() }
    };
    assert_eq!(kp("p1").await, kp("p2").await);
    assert_ne!(kp("p1").await, kp("p3").await);

    // A different run configuration gives different keys for the same record.
    let mut c2 = config();
    c2.element_threshold += 1;
    let m2 = Memo::open(&tmp("keys2"), c2.digest()).unwrap();
    let k4 = m2.key_shard(&s, &request(&["elf", "ci", "rec1", "marker1"], &["o", "d"])).await.unwrap();
    assert_ne!(k1, k4);
}

#[tokio::test]
async fn reduce_keys_hash_proofs_and_keep_literals() {
    let d = tmp("reduce");
    let s = DiskArtifactClient::open(&d.join("a"), ProofArtifacts::default()).unwrap();
    let m = Memo::open(&d, config().digest()).unwrap();
    for (id, body) in [("pa", b"proof-a".to_vec()), ("pb", b"proof-a".to_vec()), ("pc", b"proof-c".to_vec())] {
        s.upload_raw(&Artifact::from(id.to_string()), U, body).await.unwrap();
    }
    let req = |p: &str, range: &str| request(&["false", "R", range, p], &["out"]);
    let ka = m.key_reduce(&s, &req("pa", "r1")).await.unwrap();
    assert_eq!(ka, m.key_reduce(&s, &req("pb", "r1")).await.unwrap(), "same proof bytes under another id");
    assert_ne!(ka, m.key_reduce(&s, &req("pc", "r1")).await.unwrap());
    assert_ne!(ka, m.key_reduce(&s, &req("pa", "r2")).await.unwrap(), "shard ranges are part of the key");
    assert!(m.key_reduce(&s, &request(&["false", "R", "r1"], &["out"])).await.is_err());
}

#[tokio::test]
async fn capture_reads_deferred_chunks_from_trash() {
    let d = tmp("capture");
    let s = DiskArtifactClient::open(&d, ProofArtifacts::default()).unwrap();
    let mut map = std::collections::HashMap::new();
    map.insert(
        SyscallCode::SHA_EXTEND,
        vec![
            PrecompileArtifactSlice { artifact: Artifact::from("chunkA".to_string()), start_idx: 0, end_idx: 2 },
            PrecompileArtifactSlice { artifact: Artifact::from("chunkA".to_string()), start_idx: 2, end_idx: 3 },
        ],
    );
    let ev = bincode::serialize(&DeferredEvents(map.into_iter().collect())).unwrap();
    s.upload_raw(&Artifact::from("proof".to_string()), U, b"P".to_vec()).await.unwrap();
    s.upload_raw(&Artifact::from("deferred".to_string()), U, ev.clone()).await.unwrap();
    s.upload_raw(&Artifact::from("chunkA".to_string()), U, b"A".to_vec()).await.unwrap();
    // The controller consumed the chunk before the shard reported completion.
    s.delete(&Artifact::from("chunkA".to_string()), U).await.unwrap();
    let e = capture_shard(&s, &request(&["e", "c", "r", "m"], &["proof", "deferred"])).await.unwrap();
    assert_eq!(e.out0, b"P");
    assert_eq!(e.out1.as_deref(), Some(ev.as_slice()));
    assert_eq!(e.chunks, vec![("chunkA".to_string(), b"A".to_vec())], "chunk ids are deduplicated");
}

/// The c4 run lost a core shard's deferred chunks: written when the shard started, consumed and
/// trashed while it proved, swept (by write time) before the shard finished. The sweep now reads
/// the deletion stamp and keeps everything deleted after the oldest in-flight shard started.
#[tokio::test]
async fn sweep_keeps_trash_an_in_flight_shard_may_capture() {
    let d = tmp("sweep");
    let s = DiskArtifactClient::open(&d, ProofArtifacts::default()).unwrap();
    let chunk = Artifact::from("chunk".to_string());
    let token = s.task_started();
    s.upload_raw(&chunk, U, b"C".to_vec()).await.unwrap();
    // Age the written file well past any grace period, as a long shard does.
    let live = std::fs::read_dir(d.join("live")).unwrap().next().unwrap().unwrap().path();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options().write(true).open(&live).unwrap().set_modified(old).unwrap();
    s.delete(&chunk, U).await.unwrap();
    s.sweep_now(std::time::Duration::ZERO);
    assert_eq!(s.read_live_or_trash("chunk").await.unwrap(), b"C", "kept while its shard is in flight");
    s.task_finished(token);
    std::thread::sleep(std::time::Duration::from_millis(20));
    s.sweep_now(std::time::Duration::ZERO);
    assert!(s.read_live_or_trash("chunk").await.is_err(), "swept once no shard can need it");
}

#[test]
fn run_config_pins_a_run_directory() {
    let d = tmp("config");
    let (c, resumed) = RunConfig::load_or_init(&d, config()).unwrap();
    assert!(!resumed);
    let mut again = config();
    again.nonce = [9, 9, 9, 9];
    let (c2, resumed) = RunConfig::load_or_init(&d, again).unwrap();
    assert!(resumed);
    assert_eq!(c2.nonce, c.nonce, "the stored nonce wins on resume");
    let mut other = config();
    other.height_threshold = 1 << 21;
    assert!(RunConfig::load_or_init(&d, other).is_err(), "another configuration is refused");
    let o = c.core_opts();
    assert_eq!(o.sharding_threshold.element_threshold, 1 << 26);
    assert_eq!(o.sharding_threshold.height_threshold, 1 << 20);
    assert_eq!(o.trace_chunk_slots, 2);
    assert_ne!(config().digest(), {
        let mut x = config();
        x.nonce[0] ^= 1;
        x.digest()
    });
}
