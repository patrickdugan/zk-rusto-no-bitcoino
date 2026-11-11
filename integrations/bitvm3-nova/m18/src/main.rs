use m18_utxo_window::cost::*;
use m18_utxo_window::elem::{f_to_le, fu, F};
use m18_utxo_window::circuit::M18Step;
use m18_utxo_window::machine::{run_window, State, StepWitness, NZ};
use m18_utxo_window::native::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Instant;

fn die(m: &str) -> ! {
  eprintln!("{m}");
  std::process::exit(1)
}

fn hex_rev(h: &[u8]) -> String {
  let mut v = h.to_vec();
  v.reverse();
  hex::encode(v)
}

fn unhex_rev(s: &str) -> [u8; 32] {
  let mut v = hex::decode(s).unwrap();
  v.reverse();
  v.try_into().unwrap()
}

const HEIGHTS: std::ops::RangeInclusive<u64> = 975_067..=975_072;

/// fixtures <data-dir> <out.json>: heights, hashes, raw sizes and SHA-256 of each raw file.
fn fixtures(dir: &str, out: &str) {
  let heights = std::fs::read_to_string(format!("{dir}/heights.txt")).unwrap();
  let hash_of = |h: u64| -> String {
    heights.lines().find_map(|l| l.strip_prefix(&format!("{h} "))).unwrap().trim().to_string()
  };
  let mut blocks = vec![];
  for h in HEIGHTS {
    let raw = std::fs::read(format!("{dir}/{h}.raw")).unwrap();
    let hdr: [u8; 80] = raw[..80].try_into().unwrap();
    assert_eq!(hex_rev(&sha256d(&hdr)), hash_of(h), "header hash of {h}");
    blocks.push(json!({
      "height": h, "hash": hash_of(h), "prev_hash": hex_rev(&hdr[4..36]),
      "raw_bytes": raw.len(), "raw_sha256": hex::encode(Sha256::digest(&raw)),
    }));
  }
  let doc = json!({
    "source": "mempool.space /api/block-height/{h} and /api/block/{hash}/raw, mainnet",
    "note": "raw blocks are not committed; headers match the six headers of the M16 payment input",
    "previous_block": {"height": 975_066, "hash": hash_of(975_066)},
    "blocks": blocks,
  });
  std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
}

struct Pay1 {
  txid: [u8; 32],
  vout: u32,
  value: u64,
  script_len: u32,
  script_sha: [u8; 32],
}

fn read_pay1(path: &str) -> Pay1 {
  let b = std::fs::read(path).unwrap();
  let p = b.windows(4).position(|w| w == b"PAY1").expect("PAY1 record");
  Pay1 {
    txid: b[p + 48..p + 80].try_into().unwrap(),
    vout: u32::from_le_bytes(b[p + 80..p + 84].try_into().unwrap()),
    value: u64::from_le_bytes(b[p + 84..p + 92].try_into().unwrap()),
    script_len: u32::from_le_bytes(b[p + 92..p + 96].try_into().unwrap()),
    script_sha: b[p + 96..p + 128].try_into().unwrap(),
  }
}

/// run <data-dir> <blocks.json> <m16-public.bin> <out.json>
fn run(dir: &str, fix: &str, m16: &str, out: &str) {
  let fx: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(fix).unwrap()).unwrap();
  let prev = unhex_rev(fx["previous_block"]["hash"].as_str().unwrap());
  let t0 = Instant::now();
  let mut raws = vec![];
  for b in fx["blocks"].as_array().unwrap() {
    let h = b["height"].as_u64().unwrap();
    let raw = std::fs::read(format!("{dir}/{h}.raw")).unwrap();
    if hex::encode(Sha256::digest(&raw)) != b["raw_sha256"].as_str().unwrap() {
      die(&format!("raw file of {h} does not match the fixture"));
    }
    raws.push(raw);
  }
  let last_hash = sha256d(&raws.last().unwrap()[..80]);
  let r_s = derive_r_s(&prev, &last_hash);
  let mut w = Window::new(prev, r_s, true);
  let mut stats = vec![];
  for (b, raw) in fx["blocks"].as_array().unwrap().iter().zip(&raws) {
    let h = b["height"].as_u64().unwrap();
    let st = w.process_block(h, raw).unwrap_or_else(|e| die(&e));
    if st.hash != b["hash"].as_str().unwrap() {
      die(&format!("block {h} hash differs from the fixture"));
    }
    eprintln!("{h}: {} txs, {} creates, {} in-window spends, {:.1} s", st.transactions, st.creates, st.spends_in_window, st.seconds);
    stats.push(st);
  }
  let wall = t0.elapsed().as_secs_f64();
  let root = w.map.root();

  // The M16 payment output and every window output paying the same script.
  let pay = read_pay1(m16);
  let mut script: Option<Vec<u8>> = None;
  for raw in &raws {
    for tx in &parse_block(raw).unwrap().txs {
      for o in &tx.outputs {
        if o.script.len() == pay.script_len as usize && Sha256::digest(&o.script)[..] == pay.script_sha {
          script.get_or_insert(o.script.clone());
        }
      }
    }
  }
  let script = script.unwrap_or_else(|| die("no window output has the PAY1 script"));
  let m16_proof = w.map.membership(&pay.txid, pay.vout);
  let m16_status = match &m16_proof {
    None => json!({"in_map": false}),
    Some(p) => json!({
      "in_map": true, "spent": p.leaf.spent, "leaf_index": p.path.index,
      "membership_proof_verifies": verify_membership(&root, &outpoint_key(&pay.txid, pay.vout), p),
      "value_sats": p.leaf.value, "matches_pay1_value": p.leaf.value == pay.value,
    }),
  };
  let bal = w.map.balance_of_script(&script);
  let bal_sum = verify_balance(&root, &r_s, &bal, Some(&script)).unwrap_or_else(|e| die(&format!("balance proof: {e:?}")));
  assert_eq!(bal_sum, bal.unspent_sum);
  let entries: Vec<_> = bal
    .entries
    .iter()
    .map(|e| {
      json!({
        "txid": display_hex(&e.txid), "vout": e.vout, "value_sats": e.proof.leaf.value,
        "spent": e.proof.leaf.spent, "leaf_index": e.proof.path.index,
      })
    })
    .collect();
  let sum = |f: fn(&BlockStats) -> u64| stats.iter().map(f).sum::<u64>();
  let doc = json!({
    "window": {"first": 975_067, "last": 975_072, "previous_hash": display_hex(&prev), "r_s_le_hex": hex::encode(f_to_le(&r_s))},
    "blocks": stats,
    "totals": {
      "transactions": sum(|s| s.transactions), "nonwitness_bytes": sum(|s| s.nonwitness_bytes),
      "sha256_blocks_txs": sum(|s| s.sha256_blocks_txs),
      "sha256_blocks_txid_final": sum(|s| s.sha256_blocks_txid_final),
      "inputs": sum(|s| s.inputs), "outputs": sum(|s| s.outputs), "creates": sum(|s| s.creates),
      "spends_in_window": sum(|s| s.spends_in_window), "spends_before_window": sum(|s| s.spends_before_window),
      "merkle_merges": sum(|s| s.merkle_merges), "sha256_blocks_merkle": sum(|s| s.sha256_blocks_merkle),
      "sha256_blocks_header": sum(|s| s.sha256_blocks_header),
      "absorb_steps_c1": sum(|s| s.absorb_steps_c1), "absorb_steps_c4": sum(|s| s.absorb_steps_c4),
      "absorb_steps_c8": sum(|s| s.absorb_steps_c8),
    },
    "final_map": {
      "root_le_hex": hex::encode(f_to_le(&root)), "leaves": w.map.len(), "depth": D,
      "last_block_hash": display_hex(&w.prev_hash),
    },
    "wall_seconds_all_blocks_with_proof_checks": wall,
    "m16_output": {
      "txid_display": display_hex(&pay.txid), "vout": pay.vout, "pay1_value_sats": pay.value, "status": m16_status,
    },
    "same_script": {
      "script_hex": hex::encode(&script), "script_sha256": hex::encode(pay.script_sha),
      "entries": entries, "count": bal.entries.len(),
      "unspent_count": bal.entries.iter().filter(|e| !e.proof.leaf.spent).count(),
      "balance_at_975072_sats": bal_sum, "balance_proof_verifies": true,
    },
  });
  std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{}", serde_json::to_string_pretty(&doc["totals"]).unwrap());
  println!("m16 output: {}", doc["m16_output"]);
  println!("script: {}", doc["same_script"]);
  println!("wall {wall:.1} s, root {}", doc["final_map"]["root_le_hex"]);
}

/// cost <out.json>: constraint counts.
fn cost(out: &str) {
  let sha = sha256_compression_constraints();
  let p2 = poseidon_constraints(2);
  let p3 = poseidon_constraints(3);
  let p6 = poseidon_constraints(6);
  // One map op at depth 32, on a native map with a few hundred leaves, witness checked.
  let mut m = UtxoMap::new();
  let mk = |n: u32| {
    let mut t = [0u8; 32];
    t[..4].copy_from_slice(&n.to_le_bytes());
    t[31] = (n % 251) as u8;
    t
  };
  for i in 0..300 {
    m.create(&mk(i), i % 4, 1000 + i as u64, &[i as u8]).unwrap();
  }
  let cp = m.create(&mk(1000), 0, 4242, &[7, 7]).unwrap();
  let cw = CreateWit::from_proof(&cp, &mk(1000), 0);
  let rb = cp.root_before;
  let ra = cp.root_after;
  let (create_n, create_ok, got) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rb);
    create_gadget(&mut g, &cw, &r).get_value().unwrap()
  });
  assert!(create_ok, "create gadget unsatisfied");
  assert_eq!(got, ra, "create gadget root differs from native");
  let sp = m.spend_in_window(&mk(5), 1).unwrap();
  let sw = SpendWit::from_proof(&sp, &mk(5), 1);
  let (rb2, ra2) = (sp.root_before, sp.root_after);
  let (spend_n, spend_ok, got2) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rb2);
    spend_gadget(&mut g, &sw, &r).get_value().unwrap()
  });
  assert!(spend_ok, "spend gadget unsatisfied");
  assert_eq!(got2, ra2);
  let (key, np) = m.spend_before_window(&mk(2000), 3).unwrap();
  let _ = key;
  let nw = SpendWit {
    txid_lo: m18_utxo_window::elem::f_from_le(&mk(2000)[..16]),
    txid_hi: m18_utxo_window::elem::f_from_le(&mk(2000)[16..]),
    vout: 3,
    leaf: LeafW::from(&np.leaf),
    idx: np.path.index,
    sibs: np.path.siblings.clone(),
  };
  let rn = m.root();
  let (non_n, non_ok, _) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rn);
    nonmember_gadget(&mut g, &nw, &r);
  });
  assert!(non_ok, "non-membership gadget unsatisfied");
  // A false claim must not satisfy: the key's predecessor proof against a present key.
  let present = mk(10);
  let pp = m.membership(&present, 10 % 4).unwrap();
  let bad = SpendWit {
    txid_lo: m18_utxo_window::elem::f_from_le(&present[..16]),
    txid_hi: m18_utxo_window::elem::f_from_le(&present[16..]),
    vout: (10 % 4) as u64,
    leaf: LeafW::from(&pp.leaf),
    idx: pp.path.index,
    sibs: pp.path.siblings.clone(),
  };
  let (_, bad_ok, _) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rn);
    nonmember_gadget(&mut g, &bad, &r);
  });
  assert!(!bad_ok, "a before-window claim for a present key satisfied the circuit");
  let step: Vec<_> = [0usize, 1, 4, 8].iter().map(|&c| (c, bench_step_constraints(c))).collect();
  let doc = json!({
    "sha256_compression": sha,
    "poseidon_2_inputs": p2, "poseidon_3_inputs": p3, "poseidon_6_inputs": p6,
    "depth": D,
    "map_create": create_n, "map_spend_in_window": spend_n, "map_nonmember_before_window": non_n,
    "create_gadget_satisfied_and_root_matches_native": true,
    "false_before_window_claim_unsatisfiable": true,
    "m18_step_constraints": m18_utxo_window::circuit::step_constraints(),
    "bench_step_constraints_by_c": step.iter().map(|(c, n)| json!({"c": c, "constraints": n})).collect::<Vec<_>>(),
  });
  std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}

type E1 = nova_snark::provider::PallasEngine;
type E2 = nova_snark::provider::VestaEngine;
type Pp = nova_snark::nova::PublicParams<E1, E2, BenchStep>;
type Rs = nova_snark::nova::RecursiveSNARK<E1, E2, BenchStep>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, nova_snark::provider::ipa_pc::EvaluationEngine<E1>>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, nova_snark::provider::ipa_pc::EvaluationEngine<E2>>;

/// fold <steps> <out.json>: time Nova folding of c compressions + one create.
fn fold(steps: usize, cs: &[usize], out: &str) {
  use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
  let mut rows = vec![];
  for &c in cs {
    let mut m = UtxoMap::new();
    let mk = |n: u32| {
      let mut t = [0u8; 32];
      t[..4].copy_from_slice(&n.to_le_bytes());
      t[31] = 0x5a;
      t
    };
    for i in 0..100 {
      m.create(&mk(i), 0, 500, &[i as u8]).unwrap();
    }
    let z0root = m.root();
    let mut seed = 0x9e3779b97f4a7c15u64;
    let mut next = || {
      seed ^= seed << 13;
      seed ^= seed >> 7;
      seed ^= seed << 17;
      seed
    };
    let witnesses: Vec<BenchStep> = (0..steps)
      .map(|i| {
        let id = mk(10_000 + i as u32);
        let p = m.create(&id, (i % 3) as u32, 1000 + i as u64, &[1, 2, 3, i as u8]).unwrap();
        let mut blocks = vec![[0u8; 64]; c];
        for b in blocks.iter_mut() {
          for byte in b.iter_mut() {
            *byte = next() as u8;
          }
        }
        BenchStep { blocks, op: CreateWit::from_proof(&p, &id, (i % 3) as u32) }
      })
      .collect();
    let n_cons = bench_step_constraints(c);
    let (iv_lo, iv_hi) = sha_iv_halves();
    let z0 = vec![z0root, iv_lo, iv_hi];
    let t = Instant::now();
    let pp = Pp::setup(&BenchStep::blank(c), &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
    let setup = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut rs = Rs::new(&pp, &witnesses[0], &z0).unwrap();
    let mut times = vec![];
    for w in &witnesses {
      let ts = Instant::now();
      rs.prove_step(&pp, w).unwrap_or_else(|e| die(&format!("prove_step: {e:?}")));
      times.push(ts.elapsed().as_secs_f64());
    }
    let total = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let zn = rs.verify(&pp, steps, &z0).unwrap_or_else(|e| die(&format!("verify: {e:?}")));
    let verify = t.elapsed().as_secs_f64();
    assert_eq!(zn[0], m.root(), "folded root differs from the native root");
    let steady: Vec<f64> = times[1..].to_vec();
    let per_step = steady.iter().sum::<f64>() / steady.len() as f64;
    let row = json!({
      "c": c, "steps": steps, "step_constraints": n_cons, "setup_seconds": setup,
      "total_prove_seconds": total, "first_step_seconds": times[0],
      "seconds_per_step_steady": per_step,
      "seconds_per_million_constraints": per_step / (n_cons as f64 / 1e6),
      "verify_seconds": verify, "final_root_matches_native": true, "step_seconds": times,
    });
    println!("{row}");
    rows.push(row);
    let _ = fu(0);
  }
  std::fs::write(out, serde_json::to_string_pretty(&json!({"rows": rows})).unwrap() + "\n").unwrap();
}


type PpM = nova_snark::nova::PublicParams<E1, E2, M18Step>;
type RsM = nova_snark::nova::RecursiveSNARK<E1, E2, M18Step>;
type CsM = nova_snark::nova::CompressedSNARK<E1, E2, M18Step, S1, S2>;

/// fold-window <data-dir> <first-height> <last-height> <out.json>: folds every step of a real
/// window (`<h>.raw` for each height, `<first-1>.hash` the display hash of the block before),
/// verifies the recursive SNARK, then proves and verifies a CompressedSNARK.
fn fold_window(dir: &str, first: u64, last: u64, out: &str) {
  use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
  let prev_hex = std::fs::read_to_string(format!("{dir}/{}.hash", first - 1)).unwrap_or_else(|_| die("previous block hash file missing"));
  let prev = unhex_rev(prev_hex.trim());
  let raws: Vec<Vec<u8>> = (first..=last).map(|h| std::fs::read(format!("{dir}/{h}.raw")).unwrap_or_else(|_| die(&format!("{h}.raw missing")))).collect();
  let mut wits: Vec<StepWitness> = vec![];
  let mut z0: Option<Vec<F>> = None;
  let t = Instant::now();
  let rs = run_window(&raws, prev, first, &mut |_, s, w, _| {
    if z0.is_none() {
      z0 = Some(s.to_vec());
    }
    wits.push(w.clone());
    Ok(())
  })
  .unwrap_or_else(|e| die(&e));
  let native_seconds = t.elapsed().as_secs_f64();
  let z0 = z0.unwrap();
  let steps = wits.len();
  let n_cons = m18_utxo_window::circuit::step_constraints();
  eprintln!("{steps} steps, {n_cons} constraints per step, native run {native_seconds:.2} s");

  let t = Instant::now();
  let pp = PpM::setup(&M18Step::blank(), &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
  let setup = t.elapsed().as_secs_f64();
  eprintln!("public params {setup:.1} s");
  let t = Instant::now();
  let mut snark = RsM::new(&pp, &M18Step { w: wits[0].clone() }, &z0).unwrap();
  let mut times = vec![];
  for (i, w) in wits.iter().enumerate() {
    let ts = Instant::now();
    snark.prove_step(&pp, &M18Step { w: w.clone() }).unwrap_or_else(|e| die(&format!("prove_step {i}: {e:?}")));
    times.push(ts.elapsed().as_secs_f64());
  }
  let total = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let zn = snark.verify(&pp, steps, &z0).unwrap_or_else(|e| die(&format!("verify: {e:?}")));
  let verify = t.elapsed().as_secs_f64();
  let want = rs.state.to_vec();
  if zn != want {
    die("folded output differs from the native final state");
  }
  let fin = State::from_vec(&zn).unwrap();
  assert!(fin.sealed, "window not sealed");
  assert_eq!(fin.root, rs.map.root(), "folded root differs from the native map root");
  eprintln!("recursive verify {verify:.2} s, sealed, root {}", hex::encode(f_to_le(&fin.root)));

  let t = Instant::now();
  let (pk, vk) = CsM::setup(&pp).unwrap();
  let c_setup = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let proof = CsM::prove(&pp, &pk, &snark).unwrap_or_else(|e| die(&format!("compressed prove: {e:?}")));
  let c_prove = t.elapsed().as_secs_f64();
  let bytes = bincode::serialize(&proof).unwrap().len();
  let t = Instant::now();
  let zc = proof.verify(&vk, steps, &z0).unwrap_or_else(|e| die(&format!("compressed verify: {e:?}")));
  let c_verify = t.elapsed().as_secs_f64();
  assert_eq!(zc, want);
  let steady: f64 = times[1..].iter().sum::<f64>() / (times.len() - 1).max(1) as f64;
  let doc = json!({
    "window": {"first": first, "last": last, "previous_hash": display_hex(&prev), "last_hash": display_hex(&sha256d(&raws.last().unwrap()[..80]))},
    "steps": steps, "step_constraints": n_cons, "state_length": NZ,
    "blocks": rs.blocks.iter().map(|b| json!({"height": b.height, "steps": b.steps, "compressions": b.compressions, "leaf_updates": b.leaf_updates, "idle_steps": b.idle_steps, "transactions": b.transactions})).collect::<Vec<_>>(),
    "public_params_seconds": setup, "recursive_prove_seconds": total, "first_step_seconds": times[0],
    "seconds_per_step_steady": steady, "recursive_verify_seconds": verify,
    "compressed_setup_seconds": c_setup, "compressed_prove_seconds": c_prove, "compressed_verify_seconds": c_verify,
    "compressed_bytes": bytes,
    "sealed": true, "final_root_le_hex": hex::encode(f_to_le(&fin.root)), "final_root_matches_native": true,
    "leaves": fin.leaf_count, "r_s_le_hex": hex::encode(f_to_le(&fin.r_s)), "r_le_hex": hex::encode(f_to_le(&fin.r)),
    "step_seconds": times,
  });
  std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
// ---------------------------------------------------------------------------------------------
// Segmented folding (see src/segment.rs)
// ---------------------------------------------------------------------------------------------

fn sha_hex(b: &[u8]) -> String {
  hex::encode(Sha256::digest(b))
}

fn read_or_die(p: &str) -> Vec<u8> {
  std::fs::read(p).unwrap_or_else(|e| die(&format!("{p}: {e}")))
}

/// Writes through a temporary file and a rename, so a crash never leaves a torn file.
fn write_atomic(p: &str, b: &[u8]) {
  let tmp = format!("{p}.tmp");
  std::fs::write(&tmp, b).unwrap_or_else(|e| die(&format!("{tmp}: {e}")));
  std::fs::rename(&tmp, p).unwrap_or_else(|e| die(&format!("{p}: {e}")));
}

/// A balance entry with the transaction's non-witness serialization: the verifier takes the
/// script and value from the transaction, bound to the leaf by its txid.
fn entry_json(e: &BalanceEntry, tx: &[u8]) -> serde_json::Value {
  assert_eq!(sha256d(tx), e.txid);
  let l = &e.proof.leaf;
  json!({
    "txid_internal": hex::encode(e.txid), "txid_display": display_hex(&e.txid), "vout": e.vout,
    "tx_nonwit_hex": hex::encode(tx),
    "leaf": {
      "key": hex::encode(f_to_le(&l.key)), "next_key": hex::encode(f_to_le(&l.next_key)),
      "next_index": l.next_index, "value": l.value, "script_fp": hex::encode(f_to_le(&l.script_fp)), "spent": l.spent,
    },
    "index": e.proof.path.index,
    "siblings": e.proof.path.siblings.iter().map(|s| hex::encode(f_to_le(s))).collect::<Vec<_>>(),
  })
}

/// (vout, transaction bytes, proof) of a balance entry; the txid is recomputed from the bytes.
fn entry_from_json(v: &serde_json::Value) -> (u32, Vec<u8>, Proof) {
  use m18_utxo_window::segment::f_from_canonical;
  let fe = |s: &serde_json::Value| f_from_canonical(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap_or_else(|e| die(&e));
  let l = &v["leaf"];
  (
    v["vout"].as_u64().unwrap() as u32,
    hex::decode(v["tx_nonwit_hex"].as_str().unwrap_or_else(|| die("balance entry without its transaction"))).unwrap(),
    Proof {
      leaf: Leaf {
        key: fe(&l["key"]),
        next_key: fe(&l["next_key"]),
        next_index: l["next_index"].as_u64().unwrap(),
        value: l["value"].as_u64().unwrap(),
        script_fp: fe(&l["script_fp"]),
        spent: l["spent"].as_bool().unwrap(),
      },
      path: Path { index: v["index"].as_u64().unwrap(), siblings: v["siblings"].as_array().unwrap().iter().map(fe).collect() },
    },
  )
}

/// trace <data-dir> <first> <last> <segment-steps> <work-dir> [m16-public.bin]: runs the window
/// natively and writes each segment's witnesses, z0 and expected zn, a manifest, and (with the
/// M16 statement) the balance proof of the PAY1 output and of every window output paying its
/// script.
fn trace(dir: &str, first: u64, last: u64, seg: usize, work: &str, m16: Option<&str>) {
  use m18_utxo_window::segment::{wit_to_bytes, z_to_bytes};
  use std::io::Write;
  std::fs::create_dir_all(work).unwrap();
  let prev_hex = String::from_utf8(read_or_die(&format!("{dir}/{}.hash", first - 1))).unwrap();
  let prev = unhex_rev(prev_hex.trim());
  let raws: Vec<Vec<u8>> = (first..=last).map(|h| read_or_die(&format!("{dir}/{h}.raw"))).collect();
  let mut cur: Option<std::io::BufWriter<std::fs::File>> = None;
  let mut starts: Vec<usize> = vec![];
  let mut zs: Vec<Vec<u8>> = vec![];
  let t = Instant::now();
  let rs = run_window(&raws, prev, first, &mut |i, s, w, _| {
    if i % seg == 0 {
      if let Some(mut f) = cur.take() {
        f.flush().map_err(|e| e.to_string())?;
      }
      let k = starts.len();
      let f = std::fs::File::create(format!("{work}/seg-{k}.wit")).map_err(|e| e.to_string())?;
      cur = Some(std::io::BufWriter::new(f));
      starts.push(i);
      zs.push(z_to_bytes(&s.to_vec()));
      if i > 0 && i % 20_000 == 0 {
        eprintln!("trace: step {i}, {:.0} s", t.elapsed().as_secs_f64());
      }
    }
    cur.as_mut().unwrap().write_all(&wit_to_bytes(w)).map_err(|e| e.to_string())
  })
  .unwrap_or_else(|e| die(&e));
  cur.take().unwrap().flush().unwrap();
  let native_seconds = t.elapsed().as_secs_f64();
  zs.push(z_to_bytes(&rs.state.to_vec()));
  let mut segs = vec![];
  for k in 0..starts.len() {
    let steps = starts.get(k + 1).copied().unwrap_or(rs.steps) - starts[k];
    std::fs::write(format!("{work}/seg-{k}.z0"), &zs[k]).unwrap();
    std::fs::write(format!("{work}/seg-{k}.zn"), &zs[k + 1]).unwrap();
    segs.push(json!({"index": k, "start": starts[k], "steps": steps, "z0_sha256": sha_hex(&zs[k]), "zn_sha256": sha_hex(&zs[k + 1])}));
  }
  let fin = &rs.state;
  assert!(fin.sealed && fin.root == rs.map.root());
  let mut doc = json!({
    "window": {"first": first, "last": last, "previous_hash": display_hex(&prev), "last_hash": display_hex(&sha256d(&raws.last().unwrap()[..80]))},
    "steps": rs.steps, "segment_steps": seg, "segments": segs, "native_seconds": native_seconds,
    "blocks": rs.blocks.iter().map(|b| json!({"height": b.height, "steps": b.steps, "compressions": b.compressions, "leaf_updates": b.leaf_updates, "idle_steps": b.idle_steps, "transactions": b.transactions})).collect::<Vec<_>>(),
    "final": {"root": hex::encode(f_to_le(&fin.root)), "leaves": fin.leaf_count, "r_s": hex::encode(f_to_le(&fin.r_s)), "r": hex::encode(f_to_le(&fin.r)), "zn_sha256": sha_hex(&zs[starts.len()])},
  });
  if let Some(m16) = m16 {
    let pay = read_pay1(m16);
    let txs: std::collections::HashMap<[u8; 32], Tx> =
      raws.iter().flat_map(|r| parse_block(r).unwrap().txs).map(|t| (t.txid, t)).collect();
    let script = txs
      .values()
      .flat_map(|tx| tx.outputs.iter())
      .find(|o| o.script.len() == pay.script_len as usize && Sha256::digest(&o.script)[..] == pay.script_sha)
      .map(|o| o.script.clone())
      .unwrap_or_else(|| die("no window output has the PAY1 script"));
    let one = rs.map.balance_of_outpoints(&[(pay.txid, pay.vout)]).unwrap_or_else(|e| die(&format!("PAY1 output: {e:?}")));
    let all = rs.map.balance_of_script(&script);
    let ej = |e: &BalanceEntry| entry_json(e, &txs[&e.txid].nonwit);
    let bal = json!({
      "script_hex": hex::encode(&script),
      "pay1_output": ej(&one.entries[0]),
      "script_outputs": all.entries.iter().map(ej).collect::<Vec<_>>(),
    });
    std::fs::write(format!("{work}/balance.json"), serde_json::to_string_pretty(&bal).unwrap() + "\n").unwrap();
    doc["balance"] = json!({"pay1_unspent_value": one.unspent_sum, "script_outputs": all.entries.len(), "script_unspent_sum": all.unspent_sum});
  }
  std::fs::write(format!("{work}/manifest.json"), serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}

fn load_pp(work: &str) -> PpM {
  let t = Instant::now();
  let pp: PpM = bincode::deserialize(&read_or_die(&format!("{work}/pp.bin"))).unwrap_or_else(|e| die(&format!("pp.bin: {e}")));
  eprintln!("public params loaded in {:.1} s", t.elapsed().as_secs_f64());
  pp
}

/// params <work-dir>: public parameters for M18Step, written once and shared by every segment.
fn params(work: &str) {
  use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
  std::fs::create_dir_all(work).unwrap();
  let t = Instant::now();
  let pp = PpM::setup(&M18Step::blank(), &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
  let setup = t.elapsed().as_secs_f64();
  let b = bincode::serialize(&pp).unwrap();
  write_atomic(&format!("{work}/pp.bin"), &b);
  let back: PpM = bincode::deserialize(&b).unwrap();
  assert_eq!(back.digest(), pp.digest(), "public params do not survive serialization");
  let (c1, c2) = pp.num_constraints();
  let doc = json!({"setup_seconds": setup, "bytes": b.len(), "sha256": sha_hex(&b), "digest": hex::encode(f_to_le(&pp.digest())), "constraints": {"primary": c1, "secondary": c2}, "step_constraints": m18_utxo_window::circuit::step_constraints()});
  std::fs::write(format!("{work}/pp.json"), serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{doc}");
}

/// fold-seg <work-dir> <segment> <checkpoint-every>: folds one segment, resuming from its
/// checkpoint if there is one, verifies the RecursiveSNARK against the expected zn and writes it.
fn fold_seg(work: &str, i: usize, every: usize) {
  use m18_utxo_window::segment::{wit_from_bytes, z_from_bytes, WIT_BYTES};
  use std::io::Write;
  let done = format!("{work}/seg-{i}.rs.bin");
  if std::path::Path::new(&done).exists() {
    eprintln!("segment {i} already folded");
    return;
  }
  let log_path = format!("{work}/seg-{i}.log");
  let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap();
  let pp = load_pp(work);
  let z0 = z_from_bytes(&read_or_die(&format!("{work}/seg-{i}.z0"))).unwrap_or_else(|e| die(&e));
  let want = z_from_bytes(&read_or_die(&format!("{work}/seg-{i}.zn"))).unwrap_or_else(|e| die(&e));
  let wb = read_or_die(&format!("{work}/seg-{i}.wit"));
  if wb.len() % WIT_BYTES != 0 {
    die("witness file is not a whole number of records");
  }
  let n = wb.len() / WIT_BYTES;
  let wit = |k: usize| M18Step { w: wit_from_bytes(&wb[k * WIT_BYTES..(k + 1) * WIT_BYTES]).unwrap_or_else(|e| die(&e)) };
  let ck = format!("{work}/seg-{i}.ckpt");
  let mut rs: RsM = if std::path::Path::new(&ck).exists() {
    bincode::deserialize(&read_or_die(&ck)).unwrap_or_else(|e| die(&format!("checkpoint: {e}")))
  } else {
    RsM::new(&pp, &wit(0), &z0).unwrap_or_else(|e| die(&format!("new: {e:?}")))
  };
  let start = rs.num_steps();
  writeln!(log, "start {start} of {n}, threads {}", std::env::var("RAYON_NUM_THREADS").unwrap_or_default()).unwrap();
  let t = Instant::now();
  let mut tl = Instant::now();
  for k in start..n {
    rs.prove_step(&pp, &wit(k)).unwrap_or_else(|e| die(&format!("segment {i} step {k}: {e:?}")));
    if (k + 1) % every == 0 && k + 1 < n {
      write_atomic(&ck, &bincode::serialize(&rs).unwrap());
      let per = tl.elapsed().as_secs_f64() / every as f64;
      tl = Instant::now();
      writeln!(log, "{} / {n}  {:.0} s  {per:.2} s/step", k + 1, t.elapsed().as_secs_f64()).unwrap();
    }
  }
  let fold_seconds = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let zn = rs.verify(&pp, n, &z0).unwrap_or_else(|e| die(&format!("segment {i} recursive verify: {e:?}")));
  let verify_seconds = t.elapsed().as_secs_f64();
  if zn != want {
    die(&format!("segment {i}: folded zn differs from the traced state"));
  }
  write_atomic(&done, &bincode::serialize(&rs).unwrap());
  let _ = std::fs::remove_file(&ck);
  let doc = json!({"segment": i, "steps": n, "resumed_at": start, "fold_seconds_this_run": fold_seconds, "recursive_verify_seconds": verify_seconds, "zn_matches_trace": true});
  std::fs::write(format!("{work}/seg-{i}.fold.json"), serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  writeln!(log, "done: {doc}").unwrap();
  println!("{doc}");
}

/// compress-seg <work-dir> <segment>: CompressedSNARK of a folded segment, verified.
fn compress_seg(work: &str, i: usize) {
  use m18_utxo_window::segment::z_from_bytes;
  let pp = load_pp(work);
  let rs: RsM = bincode::deserialize(&read_or_die(&format!("{work}/seg-{i}.rs.bin"))).unwrap();
  let z0 = z_from_bytes(&read_or_die(&format!("{work}/seg-{i}.z0"))).unwrap();
  let want = z_from_bytes(&read_or_die(&format!("{work}/seg-{i}.zn"))).unwrap();
  let n = rs.num_steps();
  let t = Instant::now();
  let (pk, vk) = CsM::setup(&pp).unwrap();
  let setup = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let proof = CsM::prove(&pp, &pk, &rs).unwrap_or_else(|e| die(&format!("compressed prove: {e:?}")));
  let prove = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let zc = proof.verify(&vk, n, &z0).unwrap_or_else(|e| die(&format!("compressed verify: {e:?}")));
  let verify = t.elapsed().as_secs_f64();
  if zc != want {
    die("compressed output differs from the traced state");
  }
  let pb = bincode::serialize(&proof).unwrap();
  let vb = bincode::serialize(&vk).unwrap();
  write_atomic(&format!("{work}/seg-{i}.proof"), &pb);
  let vk_path = format!("{work}/vk.bin");
  if !std::path::Path::new(&vk_path).exists() {
    write_atomic(&vk_path, &vb);
  }
  let doc = json!({"segment": i, "steps": n, "setup_seconds": setup, "prove_seconds": prove, "verify_seconds": verify, "proof_bytes": pb.len(), "proof_sha256": sha_hex(&pb), "vk_sha256": sha_hex(&vb)});
  std::fs::write(format!("{work}/seg-{i}.compress.json"), serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{doc}");
}

/// verify-window <work-dir> [m16-public.bin] [--vk-sha256=<hex>]: verifies every segment's
/// compressed proof, the chaining of the segments, the initial state and the seal; with the M16
/// statement, binds hash(T) to its tip and checks the balance proofs in balance.json against the
/// folded root. The verifier key is rebuilt from M18Step (about 75 s); with --vk-sha256 the
/// work directory's vk.bin is used instead, and only if its SHA-256 is the one given. The M16
/// statement's bytes are taken as given: its wrap proof is checked by m13-verify.
fn verify_window(work: &str, m16: Option<&str>, vk_pin: Option<&str>) {
  use m18_utxo_window::segment::{check_initial, hash_of_limbs, window_result, z_from_bytes};
  use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
  let man: serde_json::Value = serde_json::from_slice(&read_or_die(&format!("{work}/manifest.json"))).unwrap();
  let first = man["window"]["first"].as_u64().unwrap();
  let prev = unhex_rev(man["window"]["previous_hash"].as_str().unwrap());
  let t = Instant::now();
  let vk: nova_snark::nova::VerifierKey<E1, E2, M18Step, S1, S2> = match vk_pin {
    None => {
      let pp = PpM::setup(&M18Step::blank(), &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
      CsM::setup(&pp).unwrap().1
    }
    Some(pin) => {
      let b = read_or_die(&format!("{work}/vk.bin"));
      if sha_hex(&b) != pin.to_lowercase() {
        die("vk.bin is not the pinned verifier key");
      }
      bincode::deserialize(&b).unwrap()
    }
  };
  let from_circuit = vk_pin.is_none();
  let vk_sha = sha_hex(&bincode::serialize(&vk).unwrap());
  let key_seconds = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let segs = man["segments"].as_array().unwrap();
  let mut prev_zn: Option<Vec<F>> = None;
  let mut s0 = None;
  for (i, sg) in segs.iter().enumerate() {
    let z0 = z_from_bytes(&read_or_die(&format!("{work}/seg-{i}.z0"))).unwrap_or_else(|e| die(&e));
    match &prev_zn {
      None => s0 = Some(check_initial(&z0, &prev, first).unwrap_or_else(|e| die(&e))),
      Some(p) if *p != z0 => die(&format!("segment {i} does not start where segment {} ended", i - 1)),
      _ => {}
    }
    let proof: CsM = bincode::deserialize(&read_or_die(&format!("{work}/seg-{i}.proof"))).unwrap_or_else(|e| die(&format!("segment {i} proof: {e}")));
    let zn = proof.verify(&vk, sg["steps"].as_u64().unwrap() as usize, &z0).unwrap_or_else(|e| die(&format!("segment {i} verify: {e:?}")));
    prev_zn = Some(zn);
  }
  let verify_seconds = t.elapsed().as_secs_f64();
  let res = window_result(&s0.unwrap(), &prev_zn.unwrap()).unwrap_or_else(|e| die(&e));
  let mut doc = json!({
    "segments": segs.len(), "steps": man["steps"], "vk_sha256": vk_sha, "vk_from_circuit": from_circuit,
    "key_seconds": key_seconds, "verify_seconds": verify_seconds,
    "window": {"first": res.first_height, "last": res.last_height, "previous_hash": display_hex(&hash_of_limbs(&res.prev_hash)), "tip_hash": display_hex(&hash_of_limbs(&res.tip_hash))},
    "root": hex::encode(f_to_le(&res.root)), "leaves": res.leaves, "r_s": hex::encode(f_to_le(&res.r_s)),
  });
  if let Some(m16) = m16 {
    for (k, v) in bind_m16(work, m16, &res).as_object().unwrap() {
      doc[k] = v.clone();
    }
  }
  std::fs::write(format!("{work}/verify.json"), serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}

/// check-trace <work-dir> <m16-public.bin>: the checks of verify-window that follow the proofs,
/// run on the traced states (no proofs), so the binding and balance.json are tested before the
/// fold finishes.
fn check_trace(work: &str, m16: &str) {
  use m18_utxo_window::segment::{check_initial, window_result, z_from_bytes};
  let man: serde_json::Value = serde_json::from_slice(&read_or_die(&format!("{work}/manifest.json"))).unwrap();
  let first = man["window"]["first"].as_u64().unwrap();
  let prev = unhex_rev(man["window"]["previous_hash"].as_str().unwrap());
  let n = man["segments"].as_array().unwrap().len();
  let z0 = z_from_bytes(&read_or_die(&format!("{work}/seg-0.z0"))).unwrap();
  let s0 = check_initial(&z0, &prev, first).unwrap_or_else(|e| die(&e));
  for i in 1..n {
    if read_or_die(&format!("{work}/seg-{i}.z0")) != read_or_die(&format!("{work}/seg-{}.zn", i - 1)) {
      die(&format!("segment {i} does not start where segment {} ends", i - 1));
    }
  }
  let zn = z_from_bytes(&read_or_die(&format!("{work}/seg-{}.zn", n - 1))).unwrap();
  let res = window_result(&s0, &zn).unwrap_or_else(|e| die(&e));
  println!("{}", serde_json::to_string_pretty(&bind_m16(work, m16, &res)).unwrap());
}

/// The window ends at the M16 statement's tip, and the balance proofs in balance.json hold
/// against the folded root.
fn bind_m16(work: &str, m16: &str, res: &m18_utxo_window::segment::WindowResult) -> serde_json::Value {
  use m18_utxo_window::segment::m16_tip;
  let stmt = read_or_die(m16);
  let tip = m16_tip(&stmt).unwrap_or_else(|e| die(&e));
  if &tip.magic != b"NHC1" {
    die("the M16 statement is not a mainnet statement");
  }
  if tip.hash != res.tip_hash || tip.height != res.last_height {
    die("the window does not end at the M16 tip");
  }

  // Balance proofs against the folded root. Each entry's script and value come from its
  // transaction, which must hash to the leaf's txid; the PAY1 script is pinned by its SHA-256.
  let pay = read_pay1(m16);
  let bal: serde_json::Value = serde_json::from_slice(&read_or_die(&format!("{work}/balance.json"))).unwrap();
  let pay_script = |s: &[u8]| s.len() == pay.script_len as usize && Sha256::digest(s)[..] == pay.script_sha;
  // (txid, vout, value, spent) of a verified entry paying the PAY1 script.
  let check = |v: &serde_json::Value| -> ([u8; 32], u32, u64, bool) {
    let (vout, tx, proof) = entry_from_json(v);
    let (value, script, spent) = verify_output(&res.root, &res.r_s, &tx, vout, &proof).unwrap_or_else(|e| die(&format!("balance entry: {e}")));
    if !pay_script(&script) {
      die("a balance entry does not pay the PAY1 script");
    }
    (sha256d(&tx), vout, value, spent)
  };
  let (t1, v1, p1_value, p1_spent) = check(&bal["pay1_output"]);
  if t1 != pay.txid || v1 != pay.vout {
    die("balance.json PAY1 entry is not the PAY1 outpoint");
  }
  if p1_spent || p1_value != pay.value {
    die("the PAY1 output is spent or its value differs from PAY1");
  }
  let mut seen = std::collections::HashSet::new();
  let mut sum = 0u64;
  let outs = bal["script_outputs"].as_array().unwrap();
  for v in outs {
    let (t, vout, value, spent) = check(v);
    if !seen.insert((t, vout)) {
      die("an output is counted twice");
    }
    if !spent {
      sum = sum.checked_add(value).unwrap_or_else(|| die("balance overflows u64"));
    }
  }
  json!({
    "m16_tip": {"height": tip.height, "statement_sha256": sha_hex(&stmt[..1292.min(stmt.len())]), "matches": true},
    "pay1_output": {"txid": display_hex(&pay.txid), "vout": pay.vout, "unspent_at_tip": true, "value_sats": p1_value},
    "script_outputs": {"count": outs.len(), "unspent_sum_sats": sum},
  })
}

fn main() {
  let a: Vec<String> = std::env::args().collect();
  match a.get(1).map(|s| s.as_str()) {
    Some("fixtures") => fixtures(&a[2], &a[3]),
    Some("run") => run(&a[2], &a[3], &a[4], &a[5]),
    Some("cost") => cost(&a[2]),
    Some("fold-window") => fold_window(&a[2], a[3].parse().unwrap(), a[4].parse().unwrap(), &a[5]),
    Some("fold") => {
      let cs: Vec<usize> = a[3].split(',').map(|x| x.parse().unwrap()).collect();
      fold(a[2].parse().unwrap(), &cs, &a[4])
    }
    Some("trace") => trace(&a[2], a[3].parse().unwrap(), a[4].parse().unwrap(), a[5].parse().unwrap(), &a[6], a.get(7).map(|s| s.as_str())),
    Some("params") => params(&a[2]),
    Some("check-trace") => check_trace(&a[2], &a[3]),
    Some("fold-seg") => fold_seg(&a[2], a[3].parse().unwrap(), a[4].parse().unwrap()),
    Some("compress-seg") => compress_seg(&a[2], a[3].parse().unwrap()),
    Some("verify-window") => {
      let pin = a[3..].iter().find_map(|s| s.strip_prefix("--vk-sha256="));
      let m16 = a[3..].iter().find(|s| !s.starts_with("--")).map(|s| s.as_str());
      verify_window(&a[2], m16, pin)
    }
    _ => die("usage: m18 fixtures|run|cost|fold|fold-window|trace|params|check-trace|fold-seg|compress-seg|verify-window ..."),
  }
  let _: Option<F> = None;
}
