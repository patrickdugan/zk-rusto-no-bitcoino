//! Streaming, resumable Nova header-chain prover with durable continuations.
//!
//! nova-chain anchor --network N
//!     The genesis-anchored initial state (17 elements) and its SHA-256.
//! nova-chain native-check --network N --headers FILE --core-ref TSV [--to H]
//!     Differential check of the native rules against Bitcoin Core's own
//!     per-height hash, chainwork, bits and median time, from genesis.
//! nova-chain run --network N --k K --headers FILE --out DIR --to H
//!                [--start H0] [--every STEPS] [--max-steps N]
//!     Fold headers (H0+1)..=H into a new continuation chain. H0 = 0 (default)
//!     anchors at the consensus genesis header. H0 > 0 starts from the state
//!     the native rules derive from genesis over FILE; that start is checked,
//!     not proven, and the manifest says so.
//! nova-chain resume --dir DIR --headers FILE --to H [--every STEPS] [--max-steps N]
//!     Verify the newest durable generation, then keep folding.
//! nova-chain verify-continuation --dir DIR
//!     Cold verification of the newest generation that verifies.
//! nova-chain export --dir DIR --bundle OUT [--vk-out FILE]
//!     Spartan-compress the verified continuation into an NHC1/NHT4 bundle
//!     for `btc-header-fold verify-bundle`.
//!
//! HEADERS FILE: raw 80-byte headers, height-indexed from genesis (byte
//! offset = height * 80), as written by scripts/dump-core-headers.py. Only
//! one fold step of headers is in memory at a time.
//!
//! A continuation directory holds generations/gen-NNNNNN/{accumulator.bin,
//! manifest.json} and a LATEST pointer. A generation is written to a .tmp
//! directory, fsynced, verified, renamed, and only then made LATEST; the
//! previous generation is kept. The accumulator is the live RecursiveSNARK:
//! it contains witness material and is not zero knowledge.
//!
//! NOVA_CHAIN_CRASH=<phase>:<n> aborts the process for interruption tests:
//! ingest:<step>, fold:<step>, payload:<gen>, manifest:<gen>, publish:<gen>.
use ff::PrimeField;
use nova_header_chain::native::{self, genesis_hash_display, Header, Network, State, ARITY};
use nova_header_chain::HeaderStep;
use nova_snark::{
  nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
  provider::{ipa_pc, PallasEngine, VestaEngine},
  spartan::snark::RelaxedR1CSSNARK,
  traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

type E1 = PallasEngine;
type E2 = VestaEngine;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type C = HeaderStep;
type F1 = <E1 as Engine>::Scalar;
type Rs = RecursiveSNARK<E1, E2, C>;
type Pp = PublicParams<E1, E2, C>;

const SCHEMA: &str = "nova-ivc-continuation/v2";
const BACKEND: &str = "nova-pallas-vesta-ipa-spartan";
const MAX_PAYLOAD: u64 = 128 << 20;
const MAX_MANIFEST: u64 = 64 << 10;
const KEEP: usize = 2;

fn die(msg: impl std::fmt::Display) -> ! {
  eprintln!("error: {msg}");
  println!("{}", json!({"ok": false, "error": msg.to_string()}));
  std::process::exit(1)
}

fn arg(args: &[String], name: &str) -> Option<String> {
  args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}
fn req(args: &[String], name: &str) -> String {
  arg(args, name).unwrap_or_else(|| die(format!("missing {name}")))
}
fn num<T: std::str::FromStr>(args: &[String], name: &str) -> Option<T> {
  arg(args, name).map(|v| v.parse().unwrap_or_else(|_| die(format!("bad {name}"))))
}
fn sha(b: &[u8]) -> String {
  hex::encode(Sha256::digest(b))
}

// ---------- measurement ----------

/// (VmHWM, VmRSS) of this process in MiB; Linux only.
fn mem() -> (u64, u64) {
  let s = fs::read_to_string("/proc/self/status").unwrap_or_default();
  let get = |k: &str| {
    s.lines()
      .find(|l| l.starts_with(k))
      .and_then(|l| l.split_whitespace().nth(1))
      .and_then(|v| v.parse::<u64>().ok())
      .map(|kb| kb / 1024)
      .unwrap_or(0)
  };
  (get("VmHWM:"), get("VmRSS:"))
}
/// The cgroup's memory.peak and memory.max in MiB (the OS-enforced cap,
/// which also charges page cache written by this process).
fn cgroup() -> Value {
  let path = fs::read_to_string("/proc/self/cgroup")
    .ok()
    .and_then(|s| s.lines().find_map(|l| l.strip_prefix("0::").map(str::to_owned)));
  let read = |f: &str| {
    path.as_ref().and_then(|p| fs::read_to_string(format!("/sys/fs/cgroup{p}/{f}")).ok()).map(|v| v.trim().to_owned())
  };
  let mib = |v: Option<String>| v.and_then(|s| s.parse::<u64>().ok()).map(|b| b >> 20);
  json!({"path": path, "memory_peak_mib": mib(read("memory.peak")), "memory_max_mib": mib(read("memory.max")),
         "memory_swap_max": read("memory.swap.max")})
}
fn phase(name: &str, secs: f64) -> Value {
  let (hwm, rss) = mem();
  json!({"phase": name, "seconds": (secs * 1000.0).round() / 1000.0, "vm_hwm_mib": hwm, "vm_rss_mib": rss})
}

fn crash_at(phase: &str, n: u64) {
  if let Ok(spec) = std::env::var("NOVA_CHAIN_CRASH") {
    if spec == format!("{phase}:{n}") {
      eprintln!("NOVA_CHAIN_CRASH: aborting at {spec}");
      std::process::abort();
    }
  }
}

// ---------- headers ----------

/// Height-indexed raw header file read one batch at a time.
struct Headers {
  f: File,
  count: u64,
}
impl Headers {
  fn open(path: &str, net: Network) -> Headers {
    let mut f = File::open(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len == 0 || len % 80 != 0 {
      die("header file length is not a positive multiple of 80");
    }
    let mut g = [0u8; 80];
    f.read_exact(&mut g).unwrap();
    if g != native::genesis_header(net) {
      die(format!("header file does not start with the {} genesis block", net.name()));
    }
    Headers { f, count: len / 80 }
  }
  fn read(&mut self, height: u32, n: usize) -> Vec<Header> {
    if height as u64 + n as u64 > self.count {
      die(format!("header file ends at {} (wanted {}..{})", self.count - 1, height, height as usize + n - 1));
    }
    self.f.seek(SeekFrom::Start(height as u64 * 80)).unwrap();
    let mut buf = vec![0u8; n * 80];
    self.f.read_exact(&mut buf).unwrap();
    buf.chunks(80).map(|c| c.try_into().unwrap()).collect()
  }
}

/// Apply headers natively; the error names the rule and height.
fn apply_all(net: Network, mut s: State, hs: &[Header]) -> Result<State, String> {
  for h in hs {
    s = s.apply_on(net, h).map_err(|e| format!("height {}: native rule {e}", s.height + 1))?;
  }
  Ok(s)
}

// ---------- state encoding ----------

fn z_bytes(z: &[F1]) -> Vec<u8> {
  z.iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect()
}
fn z_from_hex(h: &str) -> Result<Vec<F1>, String> {
  let b = hex::decode(h).map_err(|_| "state hex")?;
  if b.len() != ARITY * 32 {
    return Err("state must hold 17 elements".into());
  }
  b.chunks(32)
    .map(|c| {
      let mut r = <F1 as PrimeField>::Repr::default();
      r.as_mut().copy_from_slice(c);
      Option::<F1>::from(F1::from_repr(r)).ok_or_else(|| "non-canonical field element".to_string())
    })
    .collect()
}
fn display(prev: &[u8; 32]) -> String {
  let mut b = *prev;
  b.reverse();
  hex::encode(b)
}
fn describe(s: &State) -> Value {
  json!({"height": s.height, "hash": display(&s.prev), "chainwork": format!("0x{}", s.chainwork.to_str_radix(16)),
         "epoch_bits": format!("{:08x}", s.epoch_bits), "epoch_start": s.epoch_start, "mtp": s.mtp()})
}

// ---------- identity ----------

fn expected_vk(net: Network, k: usize) -> Option<&'static str> {
  native::pinned_verifier_key(net, k)
}

struct Ident {
  pp: Pp,
  pp_digest: String,
  circuit: String,
}
fn setup(net: Network, k: usize) -> (Ident, Value) {
  let t = Instant::now();
  let pp = Pp::setup(&HeaderStep::on(net, vec![[0u8; 80]; k]), &*S1::ck_floor(), &*S2::ck_floor())
    .unwrap_or_else(|e| die(format!("setup: {e:?}")));
  let pp_digest = hex::encode(pp.digest().to_repr().as_ref());
  let (c1, c2) = pp.num_constraints();
  let (v1, v2) = pp.num_variables();
  let circuit = sha(format!("nova-header-chain/{}/k={k}/constraints={c1},{c2}/variables={v1},{v2}", net.name()).as_bytes());
  let p = phase("setup", t.elapsed().as_secs_f64());
  (Ident { pp, pp_digest, circuit }, p)
}
fn binary_sha() -> String {
  std::env::current_exe().ok().and_then(|p| fs::read(p).ok()).map(|b| sha(&b)).unwrap_or_default()
}

fn anchor_policy(net: Network, start: &State, native_from_genesis: bool) -> String {
  if start.height == 0 {
    format!("genesis/{}/{}", net.name(), genesis_hash_display(net))
  } else {
    assert!(native_from_genesis);
    format!(
      "native-from-genesis/{}/{}/{}/unproven-checkpoint",
      net.name(),
      start.height,
      sha(&z_bytes(&start.to_z::<F1>()))
    )
  }
}

// ---------- durable generations ----------

fn fsync_dir(p: &Path) {
  #[cfg(unix)]
  if let Ok(d) = File::open(p) {
    let _ = d.sync_all();
  }
  let _ = p;
}
fn write_synced(path: &Path, bytes: &[u8], crash: Option<(&str, u64)>) {
  let mut f = OpenOptions::new().write(true).create_new(true).open(path).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
  if let Some((phase, n)) = crash {
    // Leave a torn file behind, as a crash mid-write would.
    f.write_all(&bytes[..bytes.len() / 2]).unwrap();
    f.sync_all().unwrap();
    crash_at(phase, n);
  }
  f.write_all(bytes).unwrap();
  f.sync_all().unwrap();
}
fn gen_name(n: u64) -> String {
  format!("gen-{n:06}")
}
fn complete_generations(dir: &Path) -> Vec<(u64, PathBuf)> {
  let mut v: Vec<(u64, PathBuf)> = fs::read_dir(dir.join("generations"))
    .map(|it| {
      it.filter_map(|e| e.ok())
        .filter_map(|e| {
          let name = e.file_name().into_string().ok()?;
          let n = name.strip_prefix("gen-")?.parse::<u64>().ok()?;
          (name.len() == 10).then_some((n, e.path()))
        })
        .collect()
    })
    .unwrap_or_default();
  v.sort();
  v
}

struct Chain {
  net: Network,
  k: usize,
  ident: Ident,
  z0: Vec<F1>,
  anchor: String,
  initial: State,
  state: State,
  rs: Option<Rs>,
  steps: u64,
  input_chain: [u8; 32],
  parent: Option<String>,
  generation: u64,
}

fn publish(dir: &Path, c: &mut Chain, timings: &mut Vec<Value>) -> Value {
  let rs = c.rs.as_ref().expect("at least one step");
  // Never persist i == 0: Nova's first prove_step after `new` is a no-op, so a
  // resumed i == 0 accumulator would silently skip a transition.
  assert!(rs.num_steps() >= 1 && rs.num_steps() as u64 == c.steps);
  let t = Instant::now();
  let zn = rs.verify(&c.ident.pp, c.steps as usize, &c.z0).unwrap_or_else(|e| die(format!("pre-publish verify: {e:?}")));
  if zn != c.state.to_z::<F1>() {
    die("accumulator output differs from the native state");
  }
  timings.push(phase("verify_before_publish", t.elapsed().as_secs_f64()));

  let n = c.generation + 1;
  let gens = dir.join("generations");
  fs::create_dir_all(&gens).unwrap();
  let tmp = gens.join(format!("{}.tmp", gen_name(n)));
  let _ = fs::remove_dir_all(&tmp);
  fs::create_dir(&tmp).unwrap();
  let t = Instant::now();
  let payload = bincode::serialize(rs).unwrap();
  if payload.len() as u64 > MAX_PAYLOAD {
    die(format!("accumulator is {} bytes, above the {MAX_PAYLOAD} cap", payload.len()));
  }
  write_synced(&tmp.join("accumulator.bin"), &payload, std::env::var("NOVA_CHAIN_CRASH").ok().filter(|s| s == &format!("payload:{n}")).map(|_| ("payload", n)));
  let manifest = json!({
    "schema": SCHEMA, "backend": BACKEND, "network": c.net.name(),
    "source_commit": option_env!("NOVA_CHAIN_SOURCE_COMMIT").unwrap_or("unknown"),
    "binary_sha256": binary_sha(),
    "circuit_identity_sha256": c.ident.circuit, "public_params_digest": c.ident.pp_digest,
    "expected_verifier_key_sha256": expected_vk(c.net, c.k),
    "anchor_policy": c.anchor, "anchor_policy_sha256": sha(c.anchor.as_bytes()),
    "k": c.k, "completed_steps": c.steps,
    "initial_height": c.initial.height, "end_height": c.state.height,
    "initial_state_hex": hex::encode(z_bytes(&c.z0)), "end_state_hex": hex::encode(z_bytes(&zn)),
    "initial_state_sha256": sha(&z_bytes(&c.z0)), "end_state_sha256": sha(&z_bytes(&zn)),
    "end": describe(&c.state),
    "input_chain_sha256": hex::encode(c.input_chain),
    "parent_manifest_sha256": c.parent, "generation": n,
    "payload": {"file": "accumulator.bin", "size_bytes": payload.len(), "sha256": sha(&payload)},
  });
  let mbytes = serde_json::to_vec_pretty(&manifest).unwrap();
  write_synced(&tmp.join("manifest.json"), &mbytes, std::env::var("NOVA_CHAIN_CRASH").ok().filter(|s| s == &format!("manifest:{n}")).map(|_| ("manifest", n)));
  fsync_dir(&tmp);
  let final_dir = gens.join(gen_name(n));
  // A directory with this name can only be left by a crash between its rename
  // and the LATEST update: it was never published, so it is replaced.
  let latest = fs::read_to_string(dir.join("LATEST")).unwrap_or_default();
  if final_dir.exists() {
    assert_ne!(latest.trim(), gen_name(n), "refusing to replace the published generation");
    fs::remove_dir_all(&final_dir).unwrap();
  }
  fs::rename(&tmp, &final_dir).unwrap();
  fsync_dir(&gens);
  crash_at("publish", n);
  let latest_tmp = dir.join("LATEST.tmp");
  let _ = fs::remove_file(&latest_tmp);
  write_synced(&latest_tmp, format!("{}\n", gen_name(n)).as_bytes(), None);
  fs::rename(&latest_tmp, dir.join("LATEST")).unwrap();
  fsync_dir(dir);
  timings.push(phase("serialize_and_publish", t.elapsed().as_secs_f64()));
  // Keep this generation and the previous one.
  let all = complete_generations(dir);
  if all.len() > KEEP {
    for (_, p) in &all[..all.len() - KEEP] {
      let _ = fs::remove_dir_all(p);
    }
  }
  c.generation = n;
  c.parent = Some(sha(&mbytes));
  json!({"generation": n, "end_height": c.state.height, "payload_bytes": payload.len(), "manifest_sha256": c.parent})
}

/// Load and verify one generation directory.
fn load_generation(gdir: &Path) -> Result<(Value, Chain, Value), String> {
  let read_capped = |p: PathBuf, cap: u64| -> Result<Vec<u8>, String> {
    let m = fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !m.is_file() || m.len() > cap {
      return Err(format!("{} is not a regular file under {cap} bytes", p.display()));
    }
    fs::read(&p).map_err(|e| e.to_string())
  };
  let mbytes = read_capped(gdir.join("manifest.json"), MAX_MANIFEST)?;
  let m: Value = serde_json::from_slice(&mbytes).map_err(|e| format!("manifest: {e}"))?;
  let s = |k: &str| m[k].as_str().ok_or_else(|| format!("manifest.{k}"));
  let u = |k: &str| m[k].as_u64().ok_or_else(|| format!("manifest.{k}"));
  if s("schema")? != SCHEMA || s("backend")? != BACKEND {
    return Err("unknown manifest schema or backend".into());
  }
  let net = Network::parse(s("network")?).ok_or("manifest.network")?;
  let k = u("k")? as usize;
  if !(1..=64).contains(&k) {
    return Err("k out of range".into());
  }
  let steps = u("completed_steps")?;
  let (h0, h1) = (u("initial_height")?, u("end_height")?);
  if steps == 0 || h0.checked_add(steps * k as u64) != Some(h1) {
    return Err("completed_steps * k != end_height - initial_height".into());
  }
  // Identity first, before touching the payload.
  let (ident, setup_phase) = setup(net, k);
  if s("circuit_identity_sha256")? != ident.circuit || s("public_params_digest")? != ident.pp_digest {
    return Err("circuit or public-parameter identity differs from this build".into());
  }
  let z0 = z_from_hex(s("initial_state_hex")?)?;
  let zn = z_from_hex(s("end_state_hex")?)?;
  if sha(&z_bytes(&z0)) != s("initial_state_sha256")? || sha(&z_bytes(&zn)) != s("end_state_sha256")? {
    return Err("state digests do not match the state hex".into());
  }
  let initial = State::from_z(&z0).ok_or("initial state out of range")?;
  let state = State::from_z(&zn).ok_or("end state out of range")?;
  if initial.height as u64 != h0 || state.height as u64 != h1 {
    return Err("state heights disagree with the manifest".into());
  }
  let anchor = s("anchor_policy")?.to_owned();
  if sha(anchor.as_bytes()) != s("anchor_policy_sha256")? {
    return Err("anchor policy digest mismatch".into());
  }
  if h0 == 0 {
    if z0 != State::genesis(net).to_z::<F1>() || anchor != anchor_policy(net, &initial, false) {
      return Err("genesis-anchored chain does not start at the consensus genesis state".into());
    }
  } else if !anchor.starts_with(&format!("native-from-genesis/{}/{h0}/{}/", net.name(), sha(&z_bytes(&z0)))) {
    return Err("anchor policy does not name this initial state".into());
  }
  let pay = &m["payload"];
  if pay["file"] != "accumulator.bin" {
    return Err("payload file name".into());
  }
  let payload = read_capped(gdir.join("accumulator.bin"), MAX_PAYLOAD)?;
  if Some(payload.len() as u64) != pay["size_bytes"].as_u64() || Some(sha(&payload).as_str()) != pay["sha256"].as_str() {
    return Err("payload size or SHA-256 mismatch".into());
  }
  let t = Instant::now();
  let rs: Rs = bincode::deserialize(&payload).map_err(|e| format!("payload decode: {e}"))?;
  drop(payload);
  if rs.num_steps() as u64 != steps {
    return Err("accumulator step count differs from the manifest".into());
  }
  let out = rs.verify(&ident.pp, steps as usize, &z0).map_err(|e| format!("accumulator rejected: {e:?}"))?;
  if out != zn {
    return Err("accumulator output differs from the manifest end state".into());
  }
  let verify_phase = phase("restore_and_verify", t.elapsed().as_secs_f64());
  let input_chain: [u8; 32] = hex::decode(s("input_chain_sha256")?).ok().and_then(|v| v.try_into().ok()).ok_or("input chain")?;
  let chain = Chain {
    net,
    k,
    ident,
    z0,
    anchor,
    initial,
    state,
    rs: Some(rs),
    steps,
    input_chain,
    parent: Some(sha(&mbytes)),
    generation: u("generation")?,
  };
  Ok((m, chain, json!([setup_phase, verify_phase])))
}

/// The newest generation that verifies; LATEST first, then older ones.
fn load_latest(dir: &Path) -> (Value, Chain, Value) {
  let latest = fs::read_to_string(dir.join("LATEST")).ok().map(|s| s.trim().to_owned());
  let mut tried = vec![];
  let mut order: Vec<PathBuf> = latest.iter().map(|n| dir.join("generations").join(n)).collect();
  for (_, p) in complete_generations(dir).into_iter().rev() {
    if !order.contains(&p) {
      order.push(p);
    }
  }
  for g in order {
    match load_generation(&g) {
      Ok((m, c, p)) => {
        let note = json!({"loaded": g.file_name().map(|s| s.to_string_lossy().to_string()), "latest_pointer": latest, "rejected": tried});
        return (m, c, json!({"phases": p, "selection": note}));
      }
      Err(e) => tried.push(json!({"generation": g.file_name().map(|s| s.to_string_lossy().to_string()), "error": e})),
    }
  }
  die(format!("no generation verifies: {}", Value::Array(tried)))
}

// ---------- proving loop ----------

fn fold(
  dir: &Path,
  c: &mut Chain,
  headers: &mut Headers,
  to: u32,
  every: u64,
  max_steps: Option<u64>,
) -> Value {
  if (to - c.state.height) as usize % c.k != 0 {
    die(format!("{} headers from {} is not a multiple of k={}", to - c.state.height, c.state.height, c.k));
  }
  let mut timings = vec![];
  let mut gens = vec![];
  let (mut fold_s, mut ingest_s) = (0.0f64, 0.0f64);
  let mut new_steps = 0u64;
  let t_all = Instant::now();
  while c.state.height < to {
    if max_steps.is_some_and(|m| new_steps >= m) {
      break;
    }
    let step = c.steps + 1;
    let t = Instant::now();
    let batch = headers.read(c.state.height + 1, c.k);
    crash_at("ingest", step);
    let next = apply_all(c.net, c.state.clone(), &batch).unwrap_or_else(|e| die(e));
    let circuit = HeaderStep::on(c.net, batch.clone());
    ingest_s += t.elapsed().as_secs_f64();
    let t = Instant::now();
    match c.rs.as_mut() {
      None => {
        let mut rs = Rs::new(&c.ident.pp, &circuit, &c.z0).unwrap_or_else(|e| die(format!("new: {e:?}")));
        // Completes the first step (Nova's first prove_step after new is a no-op).
        rs.prove_step(&c.ident.pp, &circuit).unwrap_or_else(|e| die(format!("step: {e:?}")));
        c.rs = Some(rs);
      }
      Some(rs) => rs.prove_step(&c.ident.pp, &circuit).unwrap_or_else(|e| die(format!("step {step}: {e:?}"))),
    }
    fold_s += t.elapsed().as_secs_f64();
    crash_at("fold", step);
    let mut h = Sha256::new();
    h.update(c.input_chain);
    for b in &batch {
      h.update(b);
    }
    c.input_chain = h.finalize().into();
    c.state = next;
    c.steps = step;
    new_steps += 1;
    if c.steps % every == 0 || c.state.height == to {
      gens.push(publish(dir, c, &mut timings));
      eprintln!("generation {} at height {} ({} steps, {:.1}s)", c.generation, c.state.height, c.steps, t_all.elapsed().as_secs_f64());
    }
  }
  if c.rs.is_some() && gens.last().map(|g| g["end_height"] != c.state.height).unwrap_or(true) && new_steps > 0 {
    gens.push(publish(dir, c, &mut timings));
  }
  let (hwm, rss) = mem();
  json!({
    "new_steps": new_steps, "new_headers": new_steps * c.k as u64,
    "fold_seconds": fold_s, "ingest_seconds": ingest_s,
    "fold_seconds_per_header": if new_steps > 0 { fold_s / (new_steps * c.k as u64) as f64 } else { 0.0 },
    "wall_seconds": t_all.elapsed().as_secs_f64(),
    "generations": gens, "phases": timings, "vm_hwm_mib": hwm, "vm_rss_mib": rss,
  })
}

fn summary(c: &Chain) -> Value {
  json!({
    "network": c.net.name(), "k": c.k, "anchor_policy": c.anchor,
    "start": describe(&c.initial), "end": describe(&c.state),
    "completed_steps": c.steps, "headers": c.steps * c.k as u64,
    "circuit_identity_sha256": c.ident.circuit, "public_params_digest": c.ident.pp_digest,
    "initial_state_sha256": sha(&z_bytes(&c.z0)), "end_state_sha256": sha(&z_bytes(&c.state.to_z::<F1>())),
    "generation": c.generation,
  })
}

// ---------- commands ----------

fn native_check(args: &[String]) {
  let net = Network::parse(&req(args, "--network")).unwrap_or_else(|| die("--network"));
  let mut headers = Headers::open(&req(args, "--headers"), net);
  let to: u32 = num(args, "--to").unwrap_or((headers.count - 1) as u32);
  let refs = BufReader::new(File::open(req(args, "--core-ref")).unwrap_or_else(|e| die(e)));
  let mut lines = refs.lines().skip(1);
  let mut s = State::genesis(net);
  let mut stats = json!({"min_difficulty_blocks": 0, "retargets": 0, "min_timewarp_margin_s": null});
  let (mut min_diff, mut retargets, mut min_margin) = (0u64, 0u64, i64::MAX);
  let t = Instant::now();
  for h in 0..=to {
    let line = lines.next().and_then(|l| l.ok()).unwrap_or_else(|| die(format!("core_ref ends before {h}")));
    let f: Vec<&str> = line.trim_end().split('\t').collect();
    if f.len() != 6 || f[0].parse::<u32>().ok() != Some(h) {
      die(format!("core_ref row for {h} malformed"));
    }
    if h > 0 {
      let hdr = headers.read(h, 1)[0];
      let prev_t = s.ts[10];
      if h % native::INTERVAL == 0 {
        retargets += 1;
        min_margin = min_margin.min(native::time(&hdr) as i64 + native::MAX_TIMEWARP as i64 - prev_t as i64);
      } else if native::bits(&hdr) == native::POW_LIMIT_BITS && native::time(&hdr) > prev_t + native::MIN_DIFF_GAP {
        min_diff += 1;
      }
      s = s.apply_on(net, &hdr).unwrap_or_else(|e| die(format!("height {h}: native rule {e} rejects a block Core accepted")));
    }
    let core_work = num_bigint::BigUint::parse_bytes(f[2].as_bytes(), 16).unwrap();
    let ok = display(&s.prev) == f[1]
      && s.chainwork == core_work
      && format!("{:08x}", u32::from_le_bytes(headers.read(h, 1)[0][72..76].try_into().unwrap())) == f[3]
      && s.ts[10].to_string() == f[4]
      && s.mtp().to_string() == f[5];
    if !ok {
      die(format!("height {h}: native state {} differs from Core row {line}", describe(&s)));
    }
  }
  stats["min_difficulty_blocks"] = json!(min_diff);
  stats["retargets"] = json!(retargets);
  stats["min_timewarp_margin_s"] = json!(min_margin);
  println!(
    "{}",
    json!({"ok": true, "network": net.name(), "checked_heights": format!("0..={to}"), "agrees_with_core": ["hash", "chainwork", "bits", "time", "mediantime"],
           "end": describe(&s), "stats": stats, "seconds": t.elapsed().as_secs_f64()})
  );
}

fn run(args: &[String]) {
  let net = Network::parse(&req(args, "--network")).unwrap_or_else(|| die("--network"));
  let k: usize = num(args, "--k").unwrap_or_else(|| die("--k"));
  let to: u32 = num(args, "--to").unwrap_or_else(|| die("--to"));
  let start: u32 = num(args, "--start").unwrap_or(0);
  let every: u64 = num(args, "--every").unwrap_or(200);
  let dir = PathBuf::from(req(args, "--out"));
  if dir.join("LATEST").exists() || !complete_generations(&dir).is_empty() {
    die("output directory already holds a continuation; use resume");
  }
  fs::create_dir_all(&dir).unwrap();
  let mut headers = Headers::open(&req(args, "--headers"), net);
  let t = Instant::now();
  let mut initial = State::genesis(net);
  let mut h = 1;
  while initial.height < start {
    let n = ((start - initial.height) as usize).min(4096);
    initial = apply_all(net, initial, &headers.read(h, n)).unwrap_or_else(|e| die(e));
    h += n as u32;
  }
  let anchor_phase = phase("native_anchor", t.elapsed().as_secs_f64());
  let (ident, setup_phase) = setup(net, k);
  let z0 = initial.to_z::<F1>();
  let mut c = Chain {
    net,
    k,
    ident,
    anchor: anchor_policy(net, &initial, true),
    z0,
    initial: initial.clone(),
    state: initial,
    rs: None,
    steps: 0,
    input_chain: [0u8; 32],
    parent: None,
    generation: 0,
  };
  let f = fold(&dir, &mut c, &mut headers, to, every, num(args, "--max-steps"));
  println!("{}", json!({"ok": true, "command": "run", "chain": summary(&c), "fold": f, "phases": [anchor_phase, setup_phase], "cgroup": cgroup()}));
}

fn resume(args: &[String]) {
  let dir = PathBuf::from(req(args, "--dir"));
  let to: u32 = num(args, "--to").unwrap_or_else(|| die("--to"));
  let every: u64 = num(args, "--every").unwrap_or(200);
  let (_, mut c, load) = load_latest(&dir);
  if let Some(k) = num::<usize>(args, "--k") {
    if k != c.k {
      die(format!("k is fixed for a continuation chain ({} != {k})", c.k));
    }
  }
  if let Some(n) = arg(args, "--network") {
    if n != c.net.name() {
      die("network is fixed for a continuation chain");
    }
  }
  if to < c.state.height {
    die("target height is below the continuation's end");
  }
  let mut headers = Headers::open(&req(args, "--headers"), c.net);
  // The input must continue the proven chain exactly.
  let tip = headers.read(c.state.height, 1)[0];
  if native::hash(&tip) != c.state.prev {
    die(format!("header file's block {} is not the continuation's end block", c.state.height));
  }
  let f = fold(&dir, &mut c, &mut headers, to, every, num(args, "--max-steps"));
  println!("{}", json!({"ok": true, "command": "resume", "load": load, "chain": summary(&c), "fold": f, "cgroup": cgroup()}));
}

fn verify_continuation(args: &[String]) {
  let dir = PathBuf::from(req(args, "--dir"));
  let (m, c, load) = load_latest(&dir);
  println!(
    "{}",
    json!({"ok": true, "command": "verify-continuation", "verified": true, "load": load, "chain": summary(&c),
           "manifest_payload": m["payload"], "cgroup": cgroup()})
  );
}

fn export(args: &[String]) {
  let dir = PathBuf::from(req(args, "--dir"));
  let out = PathBuf::from(req(args, "--bundle"));
  let (_, c, load) = load_latest(&dir);
  let rs = c.rs.as_ref().unwrap();
  let t = Instant::now();
  let (pk, vk) = CompressedSNARK::<E1, E2, C, S1, S2>::setup(&c.ident.pp).unwrap_or_else(|e| die(format!("{e:?}")));
  let p_setup = phase("compress_setup", t.elapsed().as_secs_f64());
  let t = Instant::now();
  let snark = CompressedSNARK::<E1, E2, C, S1, S2>::prove(&c.ident.pp, &pk, rs).unwrap_or_else(|e| die(format!("{e:?}")));
  let p_prove = phase("compress_prove", t.elapsed().as_secs_f64());
  drop(pk);
  let t = Instant::now();
  let zn = snark.verify(&vk, c.steps as usize, &c.z0).unwrap_or_else(|e| die(format!("compressed proof rejected: {e:?}")));
  if zn != c.state.to_z::<F1>() {
    die("compressed proof output differs from the continuation end state");
  }
  let p_verify = phase("compress_self_verify", t.elapsed().as_secs_f64());
  let proof = bincode::serialize(&snark).unwrap();
  let vk_b = bincode::serialize(&vk).unwrap();
  let vk_sha = sha(&vk_b);
  if let Some(e) = expected_vk(c.net, c.k) {
    if e != vk_sha {
      die(format!("verifier key {vk_sha} differs from the pinned {e}"));
    }
  }
  let mut b = match c.net {
    Network::Mainnet => b"NHC1".to_vec(),
    Network::Testnet4 => b"NHT4".to_vec(),
  };
  b.extend((c.steps as u32).to_le_bytes());
  b.extend((c.k as u32).to_le_bytes());
  b.extend(z_bytes(&c.z0));
  b.extend(&proof);
  fs::write(&out, &b).unwrap();
  if let Some(p) = arg(args, "--vk-out") {
    fs::write(p, &vk_b).unwrap();
  }
  println!(
    "{}",
    json!({"ok": true, "command": "export", "chain": summary(&c), "bundle": out, "bundle_bytes": b.len(), "bundle_sha256": sha(&b),
           "proof_sha256": sha(&proof), "vk_sha256": vk_sha, "vk_bytes": vk_b.len(), "expected_vk_sha256": expected_vk(c.net, c.k),
           "load": load, "phases": [p_setup, p_prove, p_verify], "cgroup": cgroup()})
  );
}

fn anchor(args: &[String]) {
  let net = Network::parse(&req(args, "--network")).unwrap_or_else(|| die("--network"));
  let s = State::genesis(net);
  let z = z_bytes(&s.to_z::<F1>());
  println!(
    "{}",
    json!({"network": net.name(), "anchor_policy": anchor_policy(net, &s, false), "genesis": describe(&s),
           "genesis_header_hex": hex::encode(native::genesis_header(net)),
           "initial_state_hex": hex::encode(&z), "initial_state_sha256": sha(&z)})
  );
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  match args.get(1).map(String::as_str) {
    Some("anchor") => anchor(&args),
    Some("native-check") => native_check(&args),
    Some("run") => run(&args),
    Some("resume") => resume(&args),
    Some("verify-continuation") => verify_continuation(&args),
    Some("export") => export(&args),
    _ => die("usage: nova-chain anchor|native-check|run|resume|verify-continuation|export (see the source header)"),
  }
}
