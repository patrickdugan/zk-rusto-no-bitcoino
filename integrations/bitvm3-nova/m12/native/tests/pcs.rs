//! The hash-based multilinear PCS: openings equal direct multilinear
//! evaluation, and each altered part of an opening is refused.
use nova_bitvm3_m12::{
  nova_io::F1 as F,
  pcs::{self, Transcript},
};

fn rand_vec(tr: &mut Transcript, n: usize) -> Vec<F> {
  tr.challenges(b"test-vector", n)
}

fn open(v: &[F], nv: usize, seed: &[u8]) -> (pcs::Committed, Vec<F>, F, pcs::Opening) {
  let c = pcs::commit(v, nv);
  let mut tr = Transcript::new(seed);
  tr.absorb(b"root", &c.root);
  let point = tr.challenges(b"point", nv);
  let (value, op) = pcs::open(&c, &point, &mut tr);
  (c, point, value, op)
}

fn check(root: &[u8; 32], nv: usize, point: &[F], value: F, op: &pcs::Opening, seed: &[u8]) -> Result<(), String> {
  let mut tr = Transcript::new(seed);
  tr.absorb(b"root", root);
  let _ = tr.challenges(b"point", nv);
  pcs::verify(root, nv, point, value, op, &mut tr)
}

#[test]
fn ntt_matches_naive_evaluation() {
  let mut tr = Transcript::new(b"ntt");
  for log in 0..6 {
    let n = 1usize << log;
    let coeffs = rand_vec(&mut tr, n);
    let mut a = coeffs.clone();
    pcs::ntt(&mut a);
    let mut w = <F as ff::PrimeField>::ROOT_OF_UNITY;
    for _ in log..<F as ff::PrimeField>::S {
      w = ff::Field::square(&w);
    }
    let mut x = <F as ff::Field>::ONE;
    for ai in a.iter() {
      let mut acc = <F as ff::Field>::ZERO;
      let mut p = <F as ff::Field>::ONE;
      for c in &coeffs {
        acc += *c * p;
        p *= x;
      }
      assert_eq!(*ai, acc);
      x *= w;
    }
  }
}

#[test]
fn openings_equal_multilinear_evaluation() {
  let mut tr = Transcript::new(b"pcs-test");
  for nv in 1..=11 {
    let n = (1usize << nv) - (nv % 3);
    let v = rand_vec(&mut tr, n);
    let (c, point, value, op) = open(&v, nv, b"seed");
    let mut padded = v.clone();
    padded.resize(1 << nv, <F as ff::Field>::ZERO);
    assert_eq!(value, pcs::mle_eval(&padded, &point), "nv={nv}");
    check(&c.root, nv, &point, value, &op, b"seed").unwrap();
  }
}

#[test]
fn altered_openings_are_refused() {
  let mut tr = Transcript::new(b"pcs-mut");
  let nv = 10;
  let v = rand_vec(&mut tr, 1 << nv);
  let (c, point, value, op) = open(&v, nv, b"seed");
  let one = <F as ff::Field>::ONE;
  assert!(check(&c.root, nv, &point, value + one, &op, b"seed").is_err(), "wrong value");
  let mut m = op.clone();
  m.u[3] += one;
  assert!(check(&c.root, nv, &point, value, &m, b"seed").is_err(), "u altered");
  let mut m = op.clone();
  m.t[5] += one;
  assert!(check(&c.root, nv, &point, value, &m, b"seed").is_err(), "t altered");
  let mut m = op.clone();
  m.columns[7].1[2] += one;
  assert!(check(&c.root, nv, &point, value, &m, b"seed").is_err(), "column entry altered");
  let mut m = op.clone();
  m.columns[7].2[0][0] ^= 1;
  assert!(check(&c.root, nv, &point, value, &m, b"seed").is_err(), "Merkle sibling altered");
  let mut m = op.clone();
  m.columns[0].0 ^= 1;
  assert!(check(&c.root, nv, &point, value, &m, b"seed").is_err(), "query position altered");
  let mut m = op.clone();
  m.columns.pop();
  assert!(check(&c.root, nv, &point, value, &m, b"seed").is_err(), "missing query");
  let mut root = c.root;
  root[0] ^= 1;
  assert!(check(&root, nv, &point, value, &op, b"seed").is_err(), "other root");
  assert!(check(&c.root, nv, &point, value, &op, b"other-seed").is_err(), "other transcript");
  // A different vector under a different root opens to its own value only.
  let mut w = v.clone();
  w[17] += one;
  let (cw, pw, vw, ow) = open(&w, nv, b"seed");
  check(&cw.root, nv, &pw, vw, &ow, b"seed").unwrap();
  assert!(check(&c.root, nv, &pw, vw, &ow, b"seed").is_err(), "opening of w against v's root");
}
