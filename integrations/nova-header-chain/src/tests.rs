use super::native::*;
use super::HeaderStep;
use nova_snark::frontend::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::{circuit::StepCircuit, Engine};
use std::collections::BTreeMap;
use std::path::Path;

type F = <PallasEngine as Engine>::Scalar;

fn hs() -> BTreeMap<u32, Header> {
  load_headers(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data"))
}

fn cp(h: u32, hs: &BTreeMap<u32, Header>) -> State {
  State::checkpoint(h, hs, early_chainwork(h))
}

struct Out {
  ok: bool,
  first_fail: String,
  constraints: usize,
  z: Vec<F>,
}

fn synth(state: &State, headers: &[Header]) -> Out {
  synth_on(Network::Mainnet, state, headers)
}

fn synth_on(net: Network, state: &State, headers: &[Header]) -> Out {
  let mut cs = TestConstraintSystem::<F>::new();
  let z: Vec<AllocatedNum<F>> = state
    .to_z::<F>()
    .iter()
    .enumerate()
    .map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(*v)).unwrap())
    .collect();
  let c = HeaderStep::on(net, headers.to_vec());
  let out = <HeaderStep as StepCircuit<F>>::synthesize(&c, &mut cs, &z).unwrap();
  Out {
    ok: cs.is_satisfied(),
    first_fail: cs.which_is_unsatisfied().unwrap_or("").to_string(),
    constraints: cs.num_constraints(),
    z: out.iter().map(|n| n.get_value().unwrap()).collect(),
  }
}

fn range(hs: &BTreeMap<u32, Header>, from: u32, n: u32) -> Vec<Header> {
  (from..from + n).map(|h| hs[&h]).collect()
}

fn native_after(state: &State, headers: &[Header]) -> State {
  headers.iter().fold(state.clone(), |s, h| s.apply(h).unwrap())
}

#[test]
fn ten_valid_headers_match_native_state() {
  let hs = hs();
  let s = cp(1000, &hs);
  let hdrs = range(&hs, 1001, 10);
  let o = synth(&s, &hdrs);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
  assert_eq!(o.z, native_after(&s, &hdrs).to_z::<F>());
}

#[test]
fn boundary_2016_capped_at_pow_limit() {
  let hs = hs();
  let s = cp(2010, &hs);
  let hdrs = range(&hs, 2011, 10);
  assert_eq!(next_bits(s.epoch_bits, time(&hs[&2015]), time(&hs[&0])), 0x1d00_ffff);
  let o = synth(&s, &hdrs);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
  assert_eq!(o.z, native_after(&s, &hdrs).to_z::<F>());
}

#[test]
fn first_real_retarget_32256() {
  let hs = hs();
  if !hs.contains_key(&32_256) {
    eprintln!("data/retarget.txt missing; skipped");
    return;
  }
  let s = cp(32_250, &hs);
  let hdrs = range(&hs, 32_251, 10);
  assert_eq!(bits(&hs[&32_256]), 0x1d00_d86a);
  let o = synth(&s, &hdrs);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
  assert_eq!(o.z, native_after(&s, &hdrs).to_z::<F>());

  let mut bad = hdrs.clone();
  bad[5][72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes()); // keeps the old difficulty
  let o = synth(&s, &bad);
  assert!(!o.ok);
  assert!(o.first_fail.contains("retarget"), "{}", o.first_fail);
}

#[test]
fn wrong_bits_at_2016_rejected() {
  let hs = hs();
  let s = cp(2015, &hs);
  let mut h = hs[&2016];
  h[72..76].copy_from_slice(&0x1d00_fffeu32.to_le_bytes());
  assert_eq!(s.apply(&h), Err("retarget"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("retarget"), "{}", o.first_fail);
}

#[test]
fn invalid_pow_rejected() {
  let hs = hs();
  let s = cp(1000, &hs);
  let mut h = hs[&1001];
  h[76] ^= 1; // nonce
  assert_eq!(s.apply(&h), Err("pow"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("pow"), "{}", o.first_fail);
}

#[test]
fn wrong_prev_link_rejected() {
  let hs = hs();
  let mut s = cp(1000, &hs);
  s.prev[0] ^= 1;
  let o = synth(&s, &[hs[&1001]]);
  assert!(!o.ok && o.first_fail.contains("prev_link"), "{}", o.first_fail);
}

#[test]
fn mtp_violation_rejected() {
  let hs = hs();
  let s = cp(1000, &hs);
  let mut h = hs[&1001];
  h[68..72].copy_from_slice(&s.mtp().to_le_bytes());
  assert_eq!(s.apply(&h), Err("mtp"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("mtp"), "{}", o.first_fail);
}

#[test]
fn bits_change_inside_epoch_rejected() {
  let hs = hs();
  let s = cp(1000, &hs);
  let mut h = hs[&1001];
  h[72..76].copy_from_slice(&0x1d00_fffeu32.to_le_bytes());
  assert_eq!(s.apply(&h), Err("bits_continuity"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("bits_continuity"), "{}", o.first_fail);
}

#[test]
fn easier_than_pow_limit_rejected() {
  let hs = hs();
  let mut s = cp(1000, &hs);
  s.epoch_bits = 0x1d01_0000; // checkpoint epoch above powLimit
  let o = synth(&s, &[hs[&1001]]);
  assert!(!o.ok && o.first_fail.contains("e0_le_pl"), "{}", o.first_fail);
}

#[test]
fn version_1_after_bip34_rejected() {
  let hs = hs();
  let mut s = cp(1000, &hs);
  s.height = BIP34 - 1; // pretend the next header is at the BIP34 height
  s.chainwork = early_chainwork(1000);
  let h = hs[&1001];
  assert_eq!(version(&h), 1);
  assert_eq!(s.apply(&h), Err("version"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("version"), "{}", o.first_fail);
}

#[test]
fn native_rules_accept_all_fixture_headers() {
  let hs = hs();
  let mut s = cp(10, &hs);
  for h in 11..=2100u32 {
    s = s.apply(&hs[&h]).unwrap_or_else(|e| panic!("height {h}: {e}"));
  }
  assert_eq!(s.chainwork, early_chainwork(2100));
}

#[test]
#[ignore]
fn constraint_counts() {
  let hs = hs();
  let s = cp(1000, &hs);
  let c1 = synth(&s, &range(&hs, 1001, 1)).constraints;
  let c10 = synth(&s, &range(&hs, 1001, 10)).constraints;
  println!("constraints k=1: {c1}  k=10: {c10}  marginal/header: {}", (c10 - c1) / 9);
  let t = t4();
  let s = t4_cp(100_794, &t);
  let t1 = synth_on(Network::Testnet4, &s, &range(&t, 100_795, 1)).constraints;
  let t10 = synth_on(Network::Testnet4, &s, &range(&t, 100_795, 10)).constraints;
  println!("testnet4 constraints k=1: {t1}  k=10: {t10}  marginal/header: {}", (t10 - t1) / 9);
}

// ---- testnet4 (fixtures/testnet4/headers_100690_100900.txt, plus 98784) ----

fn t4() -> BTreeMap<u32, Header> {
  let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/testnet4/headers_100690_100900.txt");
  let mut hs = BTreeMap::new();
  for line in std::fs::read_to_string(p).unwrap().lines().filter(|l| !l.trim().is_empty()) {
    let mut it = line.split_whitespace();
    let h: u32 = it.next().unwrap().parse().unwrap();
    hs.insert(h, hex::decode(it.next().unwrap()).unwrap().try_into().unwrap());
  }
  for (h, hdr) in hs.iter() {
    if let Some(next) = hs.get(&(h + 1)) {
      assert_eq!(prev(next), hash(hdr), "testnet4 header {} does not link", h + 1);
    }
  }
  hs
}

/// Chainwork is not checked by the circuit beyond addition; tests start at 0.
fn t4_cp(h: u32, hs: &BTreeMap<u32, Header>) -> State {
  State::checkpoint(h, hs, num_bigint::BigUint::from(0u32))
}

fn t4_after(state: &State, headers: &[Header]) -> State {
  headers.iter().fold(state.clone(), |s, h| s.apply_on(Network::Testnet4, h).unwrap())
}

#[test]
fn testnet4_native_rules_accept_fixture_and_mainnet_rules_do_not() {
  let hs = t4();
  assert_eq!(bits(&hs[&98_784]), 0x1901_c065, "epoch nBits");
  assert_eq!(bits(&hs[&100_799]), POW_LIMIT_BITS, "the block before the boundary is min-difficulty");
  assert_eq!(bits(&hs[&100_800]), 0x1901_88a9, "BIP94 retarget from the epoch's first block");
  let start = t4_cp(100_700, &hs);
  let mut s = start.clone();
  for h in 100_701..=100_900u32 {
    s = s.apply_on(Network::Testnet4, &hs[&h]).unwrap_or_else(|e| panic!("height {h}: {e}"));
  }
  assert_eq!(s.height, 100_900);
  assert_eq!(s.epoch_bits, 0x1901_88a9);
  let first_mainnet_failure = (100_701..=100_900u32).try_fold(start, |s, h| s.apply(&hs[&h]).map_err(|e| (h, e)));
  assert!(first_mainnet_failure.is_err(), "mainnet rules must reject testnet4 min-difficulty blocks");
}

#[test]
fn testnet4_boundary_with_min_difficulty_blocks_matches_native() {
  let hs = t4();
  let s = t4_cp(100_794, &hs);
  let hdrs = range(&hs, 100_795, 10); // 100795..100804, boundary at 100800
  assert!(hdrs.iter().filter(|h| bits(h) == POW_LIMIT_BITS).count() >= 5);
  let o = synth_on(Network::Testnet4, &s, &hdrs);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
  assert_eq!(o.z, t4_after(&s, &hdrs).to_z::<F>());
  // The mainnet circuit rejects the same headers.
  assert!(!synth(&s, &hdrs).ok);
}

#[test]
fn testnet4_min_difficulty_block_must_use_pow_limit() {
  let hs = t4();
  let h0 = (100_701..100_900u32)
    .find(|h| h % INTERVAL != 0 && bits(&hs[h]) == POW_LIMIT_BITS)
    .unwrap();
  let s = t4_cp(h0 - 1, &hs);
  assert!(time(&hs[&h0]) > s.ts[10] + MIN_DIFF_GAP);
  let mut h = hs[&h0];
  h[72..76].copy_from_slice(&s.epoch_bits.to_le_bytes()); // epoch nBits after a 20-minute gap
  assert_eq!(s.apply_on(Network::Testnet4, &h), Err("bits_continuity"));
  let o = synth_on(Network::Testnet4, &s, &[h]);
  assert!(!o.ok && o.first_fail.contains("bits_continuity"), "{}", o.first_fail);
}

#[test]
fn testnet4_min_difficulty_needs_more_than_1200_seconds() {
  // A real min-difficulty block (valid PoW at powLimit). Moving the
  // predecessor's timestamp in the state isolates the gap rule's edge.
  let hs = t4();
  let h0 = (100_701..100_900u32)
    .find(|h| h % INTERVAL != 0 && bits(&hs[h]) == POW_LIMIT_BITS)
    .unwrap();
  let h = hs[&h0];
  let mut s = t4_cp(h0 - 1, &hs);
  s.ts[10] = time(&h) - MIN_DIFF_GAP; // exactly 1200 s: not min-difficulty
  assert!(time(&h) > s.mtp());
  assert_eq!(s.apply_on(Network::Testnet4, &h), Err("bits_continuity"));
  let o = synth_on(Network::Testnet4, &s, &[h]);
  assert!(!o.ok && o.first_fail.contains("bits_continuity"), "{}", o.first_fail);

  s.ts[10] = time(&h) - MIN_DIFF_GAP - 1; // 1201 s: min-difficulty allowed
  assert!(s.apply_on(Network::Testnet4, &h).is_ok());
  let o = synth_on(Network::Testnet4, &s, &[h]);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
}

#[test]
fn testnet4_boundary_timewarp_limit_is_600_seconds() {
  let hs = t4();
  let s = t4_cp(100_799, &hs);
  let prev_t = s.ts[10];
  let mut h = hs[&100_800];
  // 601 s early: rejected by BIP94 before PoW is checked.
  h[68..72].copy_from_slice(&(prev_t - MAX_TIMEWARP - 1).to_le_bytes());
  assert!(prev_t - MAX_TIMEWARP - 1 > s.mtp());
  assert_eq!(s.apply_on(Network::Testnet4, &h), Err("timewarp"));
  let o = synth_on(Network::Testnet4, &s, &[h]);
  assert!(!o.ok && o.first_fail.contains("timewarp"), "{}", o.first_fail);
  // Exactly 600 s early passes the timewarp rule (it then fails only PoW).
  h[68..72].copy_from_slice(&(prev_t - MAX_TIMEWARP).to_le_bytes());
  assert_eq!(s.apply_on(Network::Testnet4, &h), Err("pow"));
  let o = synth_on(Network::Testnet4, &s, &[h]);
  assert!(!o.ok && o.first_fail.contains("pow"), "{}", o.first_fail);
}

#[test]
fn testnet4_retarget_ignores_min_difficulty_predecessor() {
  let hs = t4();
  let s = t4_cp(100_799, &hs);
  // Mainnet's rule would retarget from the last block's powLimit nBits.
  assert_ne!(next_bits(POW_LIMIT_BITS, s.ts[10], s.epoch_start), bits(&hs[&100_800]));
  let mut h = hs[&100_800];
  h[72..76].copy_from_slice(&next_bits(POW_LIMIT_BITS, s.ts[10], s.epoch_start).to_le_bytes());
  assert_eq!(s.apply_on(Network::Testnet4, &h), Err("retarget"));
  let o = synth_on(Network::Testnet4, &s, &[h]);
  assert!(!o.ok && o.first_fail.contains("retarget"), "{}", o.first_fail);
}

#[test]
fn testnet4_version_4_required_from_height_1() {
  let hs = t4();
  let s = t4_cp(100_700, &hs);
  let mut h = hs[&100_701];
  h[0..4].copy_from_slice(&3u32.to_le_bytes());
  assert_eq!(s.apply_on(Network::Testnet4, &h), Err("version"));
  let o = synth_on(Network::Testnet4, &s, &[h]);
  assert!(!o.ok && o.first_fail.contains("version"), "{}", o.first_fail);
}
