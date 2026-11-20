//! Nova folding, Spartan/IPA compression, and the native verifier.

use crate::circuit::{check_plan, num_constraints, ArkStep};
use crate::elem::{f_from_hex, f_hex, fu, sha256_hex, F};
use crate::engine::{self, z, Plan, State, ARITY};
use crate::witness::{check_semantics, tallies, Expect, Parsed, PItem};
use nova_snark::nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use ff::Field;
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub type E1 = nova_snark::provider::PallasEngine;
pub type E2 = nova_snark::provider::VestaEngine;
pub type Pp = PublicParams<E1, E2, ArkStep>;
pub type Rs = RecursiveSNARK<E1, E2, ArkStep>;
pub type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, nova_snark::provider::ipa_pc::EvaluationEngine<E1>>;
pub type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, nova_snark::provider::ipa_pc::EvaluationEngine<E2>>;
pub type Cs = CompressedSNARK<E1, E2, ArkStep, S1, S2>;
pub type Pk = ProverKey<E1, E2, ArkStep, S1, S2>;
pub type Vk = VerifierKey<E1, E2, ArkStep, S1, S2>;

pub const PUBLIC_SCHEMA: &str = "ark-transition-nova-public-v1";
pub const VERDICT_SCHEMA: &str = "ark-transition-nova-verdict-v1";

pub struct Keys {
  pub pp: Pp,
  pub pk: Pk,
  pub vk: Vk,
  pub vk_digest: String,
  pub setup_s: f64,
}

impl Keys {
  /// Public parameters and Spartan keys, all derived from the circuit shape.
  pub fn new() -> Keys {
    let t = Instant::now();
    let pp = Pp::setup(&ArkStep::default(), &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
    let (pk, vk) = Cs::setup(&pp).unwrap();
    let vk_digest = sha256_hex(&bincode::serialize(&vk).unwrap());
    Keys { pp, pk, vk, vk_digest, setup_s: t.elapsed().as_secs_f64() }
  }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Timings {
  pub setup_s: f64,
  pub fold_s: f64,
  pub compress_s: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Public {
  pub schema: String,
  pub statement_digest: String,
  pub fee_bound_sat: u64,
  pub steps: usize,
  pub z0: Vec<String>,
  pub zn: Vec<String>,
  pub r1: String,
  pub gamma: String,
  pub vk_digest: String,
  pub expect: Expect,
  pub timings: Timings,
  pub proof_bytes: usize,
  pub constraints_per_step: usize,
}

/// Peak resident set size of this process in KiB (VmHWM).
pub fn peak_rss_kb() -> u64 {
  std::fs::read_to_string("/proc/self/status")
    .ok()
    .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok())))
    .unwrap_or(0)
}

fn hexes(s: &State) -> Vec<String> {
  s.iter().map(f_hex).collect()
}

fn parse_state(v: &[String]) -> Option<State> {
  if v.len() != ARITY {
    return None;
  }
  let mut s = [F::from(0u64); ARITY];
  for (i, h) in v.iter().enumerate() {
    s[i] = f_from_hex(h)?;
  }
  Some(s)
}

/// Native precheck, circuit check, Nova fold, compression. Refuses an invalid witness.
pub fn prove(keys: &Keys, p: &Parsed) -> Result<(Public, Vec<u8>), String> {
  let tl = check_semantics(p).map_err(|e| format!("precheck: {e}"))?;
  let _ = tl;
  let pl = engine::plan(p);
  prove_plan(keys, p, &pl)
}

/// Folds an already-built plan. The circuit check runs first so an unsatisfiable plan fails
/// with the step index instead of inside the folding.
pub fn prove_plan(keys: &Keys, p: &Parsed, pl: &Plan) -> Result<(Public, Vec<u8>), String> {
  check_plan(&pl.z0, &pl.steps).map_err(|(i, c)| format!("circuit: step {i} unsatisfied (constraint {c:?})"))?;
  let t = Instant::now();
  let circuits: Vec<ArkStep> = pl.steps.iter().map(|w| ArkStep { w: w.clone() }).collect();
  let mut rs = Rs::new(&keys.pp, &circuits[0], &pl.z0).map_err(|e| format!("nova new: {e:?}"))?;
  for c in &circuits {
    rs.prove_step(&keys.pp, c).map_err(|e| format!("nova prove_step: {e:?}"))?;
  }
  let fold_s = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let snark = Cs::prove(&keys.pp, &keys.pk, &rs).map_err(|e| format!("compress: {e:?}"))?;
  let compress_s = t.elapsed().as_secs_f64();
  let bytes = bincode::serialize(&snark).map_err(|e| e.to_string())?;
  let public = Public {
    schema: PUBLIC_SCHEMA.into(),
    statement_digest: hex::encode(p.statement),
    fee_bound_sat: p.fee_bound,
    steps: pl.steps.len(),
    z0: hexes(&pl.z0),
    zn: hexes(&pl.zn),
    r1: f_hex(&pl.zn[z::R1]),
    gamma: f_hex(&pl.gamma),
    vk_digest: keys.vk_digest.clone(),
    expect: p.expect.clone(),
    timings: Timings { setup_s: keys.setup_s, fold_s, compress_s },
    proof_bytes: bytes.len(),
    constraints_per_step: num_constraints(),
  };
  Ok((public, bytes))
}

/// What the verifier checks the proof against.
pub enum Source {
  /// The full witness: the record chain is recomputed from the items.
  Full(Parsed),
  /// Public inputs only: the expected record chain and tallies are given.
  Succinct { statement: [u8; 32], fee_bound: u64, r1: F, expect: Expect },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Check {
  pub name: String,
  pub ok: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Verdict {
  pub schema: String,
  pub accepted: bool,
  pub mode: String,
  pub checks: Vec<Check>,
  pub verify_s: f64,
  pub vk_digest: String,
}

impl Verdict {
  /// Name of the first failing check.
  pub fn failed(&self) -> Option<&str> {
    self.checks.iter().find(|c| !c.ok).map(|c| c.name.as_str())
  }
}

struct Log(Vec<Check>);

impl Log {
  /// Records a check; false stops the caller.
  fn ok(&mut self, name: &str, ok: bool) -> bool {
    self.0.push(Check { name: name.into(), ok });
    ok
  }
}

pub fn verify(keys: &Keys, public: &Public, proof: &[u8], src: &Source) -> Verdict {
  let t = Instant::now();
  let mut log = Log(vec![]);
  let accepted = verify_inner(keys, public, proof, src, &mut log);
  Verdict {
    schema: VERDICT_SCHEMA.into(),
    accepted,
    mode: match src {
      Source::Full(_) => "full",
      Source::Succinct { .. } => "succinct",
    }
    .into(),
    checks: log.0,
    verify_s: t.elapsed().as_secs_f64(),
    vk_digest: keys.vk_digest.clone(),
  }
}

fn verify_inner(keys: &Keys, public: &Public, proof: &[u8], src: &Source, log: &mut Log) -> bool {
  if !log.ok("schema", public.schema == PUBLIC_SCHEMA) {
    return false;
  }
  if !log.ok("vk_digest", public.vk_digest == keys.vk_digest) {
    return false;
  }
  let (statement, fee_bound, expect) = match src {
    Source::Full(p) => (p.statement, p.fee_bound, p.expect.clone()),
    Source::Succinct { statement, fee_bound, expect, .. } => (*statement, *fee_bound, expect.clone()),
  };
  if !log.ok("statement_digest", public.statement_digest == hex::encode(statement)) {
    return false;
  }
  if !log.ok("fee_bound", public.fee_bound_sat == fee_bound) {
    return false;
  }
  if !log.ok("expect_block", public.expect == expect) {
    return false;
  }
  let (Some(pz0), Some(pzn), Some(gamma), Some(pr1)) =
    (parse_state(&public.z0), parse_state(&public.zn), f_from_hex(&public.gamma), f_from_hex(&public.r1))
  else {
    log.ok("public_fields_wellformed", false);
    return false;
  };
  log.ok("public_fields_wellformed", true);
  if !log.ok("z0_recomputed", pz0 == engine::z0(&statement, fee_bound, gamma)) {
    return false;
  }
  if let Source::Full(p) = src {
    let n_in = p.items.iter().filter(|i| matches!(i, PItem::In { .. })).count();
    if !log.ok("steps_match_items", public.steps == p.items.len() + n_in) {
      return false;
    }
    if !log.ok("expect_matches_items", tallies(&p.items).matches(&expect)) {
      return false;
    }
  }
  let snark: Cs = match bincode::deserialize(proof) {
    Ok(s) => s,
    Err(_) => {
      log.ok("proof_decodes", false);
      return false;
    }
  };
  let canonical = bincode::serialized_size(&snark).map(|n| n as usize == proof.len()).unwrap_or(false);
  if !log.ok("proof_decodes", canonical) {
    return false;
  }
  let zn = match snark.verify(&keys.vk, public.steps, &pz0) {
    Ok(zn) => {
      log.ok("nova_verify", true);
      zn
    }
    Err(_) => {
      log.ok("nova_verify", false);
      return false;
    }
  };
  if !log.ok("zn_matches_public", zn.len() == ARITY && zn.iter().zip(pzn.iter()).all(|(a, b)| a == b)) {
    return false;
  }
  let zn: State = pzn;
  let fin = zn[z::PHASE] == F::ONE
    && zn[z::ACC] == F::ZERO
    && zn[z::N_IN1] == zn[z::N_IN2]
    && zn[z::P1] == zn[z::P2]
    && zn[z::GAMMA] == engine::gamma_of(zn[z::R1], zn[z::R2]);
  if !log.ok("final_state", fin) {
    return false;
  }
  let tal = zn[z::N_TX] == fu(expect.tx_count)
    && zn[z::N_IN1] == fu(expect.input_count)
    && zn[z::SUM_IN] == fu(expect.sum_in_sat)
    && zn[z::SUM_OUT] == fu(expect.sum_out_sat)
    && zn[z::SUM_FEE] == fu(expect.sum_fee_sat);
  if !log.ok("tallies_match_expect", tal) {
    return false;
  }
  let want_r1 = match src {
    Source::Full(p) => engine::chain_r1(p),
    Source::Succinct { r1, .. } => *r1,
  };
  log.ok("record_chain", zn[z::R1] == want_r1 && pr1 == want_r1)
}
