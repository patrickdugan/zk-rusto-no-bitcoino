//! ark-nova: prove, verify, mutate and bench the Ark transition proof.
//!
//!   ark-nova prove  --witness W.json --out DIR
//!   ark-nova verify --public DIR/public.json --proof DIR/proof.bin [--witness W.json | --expect E.json]
//!   ark-nova mutate --witness W.json --out DIR
//!   ark-nova bench  --sizes 4,16,64,256 [--out results/bench.json]

use ark_transition_nova::bench::synth;
use ark_transition_nova::elem::{f_from_hex, f_hex};
use ark_transition_nova::engine::{self, z};
use ark_transition_nova::proof::{peak_rss_kb, prove, prove_plan, verify, Check, Keys, Public, Source, Verdict, VERDICT_SCHEMA};
use ark_transition_nova::witness::{check_semantics, parse, parse_str, Expect, Parsed, PItem};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use std::time::Instant;

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
  args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn need<'a>(args: &'a [String], name: &str) -> &'a str {
  flag(args, name).unwrap_or_else(|| {
    eprintln!("missing {name}");
    std::process::exit(2)
  })
}

fn read(path: &str) -> Vec<u8> {
  std::fs::read(path).unwrap_or_else(|e| {
    eprintln!("cannot read {path}: {e}");
    std::process::exit(2)
  })
}

fn load_witness(path: &str) -> Parsed {
  let s = String::from_utf8(read(path)).unwrap_or_else(|_| {
    eprintln!("witness is not utf-8");
    std::process::exit(2)
  });
  match parse_str(&s) {
    Ok((_, p)) => p,
    Err(e) => {
      eprintln!("{e}");
      std::process::exit(2)
    }
  }
}

fn write(path: &Path, bytes: &[u8]) {
  std::fs::write(path, bytes).unwrap_or_else(|e| {
    eprintln!("cannot write {}: {e}", path.display());
    std::process::exit(2)
  });
}

fn cmd_prove(args: &[String]) {
  let p = load_witness(need(args, "--witness"));
  let out = Path::new(need(args, "--out"));
  std::fs::create_dir_all(out).unwrap();
  let keys = Keys::new();
  match prove(&keys, &p) {
    Ok((public, proof)) => {
      write(&out.join("proof.bin"), &proof);
      write(&out.join("public.json"), serde_json::to_string_pretty(&public).unwrap().as_bytes());
      println!(
        "{}",
        json!({"proved": true, "steps": public.steps, "constraints_per_step": public.constraints_per_step, "proof_bytes": public.proof_bytes, "timings": public.timings, "vk_digest": public.vk_digest})
      );
    }
    Err(e) => {
      println!("{}", json!({"proved": false, "error": e}));
      std::process::exit(1);
    }
  }
}

#[derive(Deserialize)]
struct ExpectFile {
  statement_digest: String,
  fee_bound_sat: u64,
  r1: String,
  expect: Expect,
}

fn reject(why: &str, vk: &str) -> ! {
  let v = Verdict {
    schema: VERDICT_SCHEMA.into(),
    accepted: false,
    mode: "none".into(),
    checks: vec![Check { name: why.into(), ok: false }],
    verify_s: 0.0,
    vk_digest: vk.into(),
  };
  println!("{}", serde_json::to_string_pretty(&v).unwrap());
  std::process::exit(1)
}

fn cmd_verify(args: &[String]) {
  let keys = Keys::new();
  let public: Public = match serde_json::from_slice(&read(need(args, "--public"))) {
    Ok(p) => p,
    Err(_) => reject("public_json_parses", &keys.vk_digest),
  };
  let proof = read(need(args, "--proof"));
  let src = if let Some(w) = flag(args, "--witness") {
    match std::str::from_utf8(&read(w)).ok().and_then(|s| parse_str(s).ok()) {
      Some((_, p)) => Source::Full(p),
      None => reject("witness_parses", &keys.vk_digest),
    }
  } else if let Some(e) = flag(args, "--expect") {
    let ef: ExpectFile = match serde_json::from_slice(&read(e)) {
      Ok(x) => x,
      Err(_) => reject("expect_file_parses", &keys.vk_digest),
    };
    let st: Option<[u8; 32]> = hex::decode(&ef.statement_digest).ok().and_then(|b| b.try_into().ok());
    match (st, f_from_hex(&ef.r1)) {
      (Some(statement), Some(r1)) => Source::Succinct { statement, fee_bound: ef.fee_bound_sat, r1, expect: ef.expect },
      _ => reject("expect_file_parses", &keys.vk_digest),
    }
  } else {
    // No external reference: the public.json fields are the expected values.
    let st: Option<[u8; 32]> = hex::decode(&public.statement_digest).ok().and_then(|b| b.try_into().ok());
    match (st, f_from_hex(&public.r1)) {
      (Some(statement), Some(r1)) => Source::Succinct { statement, fee_bound: public.fee_bound_sat, r1, expect: public.expect.clone() },
      _ => reject("public_fields_wellformed", &keys.vk_digest),
    }
  };
  let v = verify(&keys, &public, &proof, &src);
  println!("{}", serde_json::to_string_pretty(&v).unwrap());
  if !v.accepted {
    std::process::exit(1);
  }
}

#[derive(Serialize)]
struct Mut {
  name: String,
  expected_stage: String,
  observed_stage: String,
  rejected: bool,
  detail: String,
}

fn vrej(name: &str, keys: &Keys, public: &Public, proof: &[u8], src: &Source) -> Mut {
  let v = verify(keys, public, proof, src);
  let (stage, rejected) = match v.failed() {
    Some(c) => (format!("verify:{c}"), !v.accepted),
    None => ("accepted".to_string(), false),
  };
  Mut { name: name.into(), expected_stage: "verify".into(), observed_stage: stage, rejected, detail: format!("{} checks run", v.checks.len()) }
}

/// A mutated witness: prove must refuse it at the native precheck, and (precheck bypassed) at the circuit.
fn prove_rejections(name: &str, keys: &Keys, m: &Parsed, out: &mut Vec<Mut>) {
  let pre = check_semantics(m);
  out.push(Mut {
    name: format!("{name}/precheck"),
    expected_stage: "prove".into(),
    observed_stage: if pre.is_err() { "prove:precheck".into() } else { "accepted".into() },
    rejected: pre.is_err(),
    detail: pre.err().unwrap_or_default(),
  });
  let r = prove_plan(keys, m, &engine::plan(m));
  out.push(Mut {
    name: format!("{name}/circuit"),
    expected_stage: "prove".into(),
    observed_stage: if r.is_err() { "prove:circuit".into() } else { "accepted".into() },
    rejected: r.is_err(),
    detail: r.err().unwrap_or_default(),
  });
}

fn flip_last_hex(s: &str) -> String {
  let mut c: Vec<char> = s.chars().collect();
  let l = c.len() - 1;
  c[l] = if c[l] == '0' { '1' } else { '0' };
  c.into_iter().collect()
}

fn cmd_mutate(args: &[String]) {
  let x = load_witness(need(args, "--witness"));
  let outdir = Path::new(need(args, "--out"));
  std::fs::create_dir_all(outdir).unwrap();
  if let Err(e) = check_semantics(&x) {
    eprintln!("base witness fails the precheck: {e}");
    std::process::exit(2);
  }
  let keys = Keys::new();
  let (px, bx) = prove(&keys, &x).expect("base witness proves");
  let base = verify(&keys, &px, &bx, &Source::Full(x.clone()));
  let mut out: Vec<Mut> = vec![];

  // (a) one output value changed.
  let mut m = x.clone();
  let i = m.items.iter().position(|it| matches!(it, PItem::Out { .. })).unwrap();
  if let PItem::Out { value, .. } = &mut m.items[i] {
    *value += 1;
  }
  prove_rejections("a_output_value_changed", &keys, &m, &mut out);

  // (b) duplicated spend_id.
  let mut m = x.clone();
  let ins: Vec<usize> = m.items.iter().enumerate().filter(|(_, it)| matches!(it, PItem::In { .. })).map(|(i, _)| i).collect();
  let first = if let PItem::In { spend, .. } = &m.items[ins[0]] { *spend } else { unreachable!() };
  if let PItem::In { spend, .. } = &mut m.items[ins[1]] {
    *spend = first;
  }
  prove_rejections("b_duplicate_spend_id", &keys, &m, &mut out);

  // (c) fee above the bound, conservation kept by raising the first input.
  let mut m = x.clone();
  let c = m.items.iter().position(|it| matches!(it, PItem::Close { .. })).unwrap();
  let old = if let PItem::Close { fee } = m.items[c] { fee } else { unreachable!() };
  let new = m.fee_bound + 1;
  if let PItem::Close { fee } = &mut m.items[c] {
    *fee = new;
  }
  if let PItem::In { value, .. } = &mut m.items[0] {
    *value += new - old;
  }
  prove_rejections("c_fee_above_bound", &keys, &m, &mut out);

  // (d) the proof against a different statement_digest.
  let mut y = x.clone();
  y.statement[0] ^= 1;
  out.push(vrej("d1_other_statement_digest", &keys, &px, &bx, &Source::Full(y.clone())));
  let (py, by) = prove(&keys, &y).expect("Y proves");
  // d2: public.json rewritten for Y (statement and z0 consistent), proof of X.
  let mut pf = px.clone();
  pf.statement_digest = hex::encode(y.statement);
  pf.z0 = engine::z0(&y.statement, y.fee_bound, f_from_hex(&px.gamma).unwrap()).iter().map(f_hex).collect();
  out.push(vrej("d2_public_rewritten_for_other_statement", &keys, &pf, &bx, &Source::Full(y.clone())));

  // (e) truncated proof bytes, appended bytes, flipped byte.
  out.push(vrej("e1_truncated_half", &keys, &px, &bx[..bx.len() / 2], &Source::Full(x.clone())));
  out.push(vrej("e2_truncated_last_byte", &keys, &px, &bx[..bx.len() - 1], &Source::Full(x.clone())));
  let mut longer = bx.clone();
  longer.push(0);
  out.push(vrej("e3_appended_byte", &keys, &px, &longer, &Source::Full(x.clone())));
  let mut flipped = bx.clone();
  let mid = flipped.len() / 2;
  flipped[mid] ^= 1;
  out.push(vrej("e4_flipped_byte", &keys, &px, &flipped, &Source::Full(x.clone())));

  // (f) zn field flipped.
  for (name, idx) in [("f1_zn_sum_out", z::SUM_OUT), ("f2_zn_r1", z::R1), ("f3_zn_phase", z::PHASE)] {
    let mut pz = px.clone();
    pz.zn[idx] = flip_last_hex(&pz.zn[idx]);
    out.push(vrej(name, &keys, &pz, &bx, &Source::Full(x.clone())));
  }

  // (g) proof of one witness with the public.json of another.
  out.push(vrej("g1_proof_of_Y_with_public_of_X", &keys, &px, &by, &Source::Full(x.clone())));
  out.push(vrej("g2_proof_of_X_with_public_of_Y", &keys, &py, &bx, &Source::Full(y.clone())));

  // Other public fields.
  let mut pz = px.clone();
  pz.steps += 1;
  out.push(vrej("h1_steps_altered", &keys, &pz, &bx, &Source::Full(x.clone())));
  let mut pz = px.clone();
  pz.vk_digest = flip_last_hex(&pz.vk_digest);
  out.push(vrej("h2_vk_digest_altered", &keys, &pz, &bx, &Source::Full(x.clone())));
  let mut pz = px.clone();
  pz.schema = "ark-transition-nova-public-v0".into();
  out.push(vrej("h3_unknown_schema", &keys, &pz, &bx, &Source::Full(x.clone())));
  let mut pz = px.clone();
  pz.expect.sum_fee_sat += 1;
  out.push(vrej("h4_expect_altered", &keys, &pz, &bx, &Source::Full(x.clone())));
  let mut pz = px.clone();
  pz.z0[z::GAMMA] = flip_last_hex(&pz.z0[z::GAMMA]);
  out.push(vrej("h5_z0_gamma_altered", &keys, &pz, &bx, &Source::Full(x.clone())));

  let all = out.iter().all(|m| m.rejected) && base.accepted;
  let doc = json!({"baseline_accepted": base.accepted, "all_rejected": all, "count": out.len(), "mutations": out});
  write(&outdir.join("mutations.json"), serde_json::to_string_pretty(&doc).unwrap().as_bytes());
  for m in &out {
    println!("{:48} {:22} rejected={}", m.name, m.observed_stage, m.rejected);
  }
  println!("baseline accepted: {}; {} mutations, all rejected: {}", base.accepted, out.len(), all);
  if !all {
    std::process::exit(1);
  }
}

fn cmd_bench(args: &[String]) {
  let sizes: Vec<u64> = flag(args, "--sizes").unwrap_or("4,16,64,256").split(',').map(|s| s.trim().parse().expect("size")).collect();
  let keys = Keys::new();
  println!("setup {:.1} s, vk {}", keys.setup_s, keys.vk_digest);
  let mut rows = vec![];
  let mut jobs: Vec<(String, u64, Parsed)> = sizes.iter().map(|&n| ("synthetic".to_string(), n, parse(&synth(n)).unwrap())).collect();
  for path in flag(args, "--witnesses").map(|s| s.split(',').collect::<Vec<_>>()).unwrap_or_default() {
    let p = load_witness(path);
    check_semantics(&p).expect("real witness passes the precheck");
    jobs.push((path.to_string(), 0, p));
  }
  for (source, n, p) in jobs {
    let items = p.items.len();
    let t = Instant::now();
    let (public, proof) = prove(&keys, &p).expect("synthesized witness proves");
    let prove_total = t.elapsed().as_secs_f64();
    let rss_prove = peak_rss_kb();
    let v = verify(
      &keys,
      &public,
      &proof,
      &Source::Succinct { statement: p.statement, fee_bound: p.fee_bound, r1: engine::chain_r1(&p), expect: p.expect.clone() },
    );
    let vf = verify(&keys, &public, &proof, &Source::Full(p.clone()));
    let row = json!({
      "source": source, "users": n, "items": items, "steps": public.steps, "constraints_per_step": public.constraints_per_step,
      "setup_s": keys.setup_s, "fold_s": public.timings.fold_s, "compress_s": public.timings.compress_s,
      "prove_total_s": prove_total, "verify_succinct_s": v.verify_s, "verify_full_s": vf.verify_s,
      "accepted_succinct": v.accepted, "accepted_full": vf.accepted,
      "proof_bytes": public.proof_bytes, "peak_rss_kb_after_prove": rss_prove, "peak_rss_kb": peak_rss_kb()
    });
    println!("{row}");
    rows.push(row);
  }
  let doc = json!({"schema": "ark-transition-nova-bench-v1", "threads": std::env::var("RAYON_NUM_THREADS").ok(), "vk_digest": keys.vk_digest, "rows": rows});
  if let Some(out) = flag(args, "--out") {
    write(Path::new(out), serde_json::to_string_pretty(&doc).unwrap().as_bytes());
  }
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  match args.get(1).map(String::as_str) {
    Some("prove") => cmd_prove(&args[2..]),
    Some("verify") => cmd_verify(&args[2..]),
    Some("mutate") => cmd_mutate(&args[2..]),
    Some("bench") => cmd_bench(&args[2..]),
    _ => {
      eprintln!("usage: ark-nova prove|verify|mutate|bench ...");
      std::process::exit(2);
    }
  }
}
