//! Circuit gadgets for the map operations and SHA-256 absorption, with constraint counting
//! (Nova's TestConstraintSystem) and a fold-timing step circuit. The gadgets check the same
//! relations as `native::{CreateProof, SpendProof}::check`.

use crate::elem::{constants, f_from_le, fu, F};
use crate::native::{CreateProof, Leaf, SpendProof, D};
use ff::{Field, PrimeFieldBits};
use nova_snark::frontend::gadgets::boolean::{AllocatedBit, Boolean};
use nova_snark::frontend::gadgets::num::{AllocatedNum, Num};
use nova_snark::frontend::gadgets::poseidon::{Elt, IOPattern, Simplex, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait};
use nova_snark::frontend::gadgets::sha256::sha256_compression_function;
use nova_snark::frontend::gadgets::uint32::UInt32;
use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

pub(crate) fn pow2(k: u32) -> F {
  F::from(2u64).pow_vartime([k as u64])
}

// ---------------------------------------------------------------------------------------------
// Gadgets
// ---------------------------------------------------------------------------------------------

pub struct G<'a, CS: ConstraintSystem<F>> {
  pub cs: &'a mut CS,
  pub(crate) n: usize,
}

impl<'a, CS: ConstraintSystem<F>> G<'a, CS> {
  pub fn new(cs: &'a mut CS) -> Self {
    G { cs, n: 0 }
  }
  pub(crate) fn nm(&mut self) -> String {
    self.n += 1;
    format!("g{}", self.n)
  }
  pub fn alloc(&mut self, v: F) -> AllocatedNum<F> {
    let nm = self.nm();
    AllocatedNum::alloc_infallible(self.cs.namespace(|| nm), || v)
  }
  pub(crate) fn val(a: &AllocatedNum<F>) -> F {
    a.get_value().unwrap_or(F::ZERO)
  }
  /// A witness fixed to a constant: one constraint.
  pub(crate) fn constant(&mut self, v: F) -> AllocatedNum<F> {
    let a = self.alloc(v);
    let nm = self.nm();
    let var = a.get_variable();
    self.cs.enforce(|| nm, |l| l + var, |l| l + CS::one(), |l| l + (v, CS::one()));
    a
  }
  pub(crate) fn enforce_eq(&mut self, a: &AllocatedNum<F>, b: &AllocatedNum<F>) {
    let nm = self.nm();
    let (x, y) = (a.get_variable(), b.get_variable());
    self.cs.enforce(|| nm, |l| l + x, |l| l + CS::one(), |l| l + y);
  }
  pub(crate) fn bit(&mut self, b: bool) -> AllocatedBit {
    let nm = self.nm();
    AllocatedBit::alloc(self.cs.namespace(|| nm), Some(b)).unwrap()
  }
  /// Poseidon over elements (sponge, absorb n, squeeze 1), as `elem::hash`.
  pub fn hash_e(&mut self, elts: Vec<Elt<F>>) -> AllocatedNum<F> {
    let nm = self.nm();
    let mut ns = self.cs.namespace(|| nm);
    let mut sponge = SpongeCircuit::new_with_constants(constants(), Simplex);
    sponge.start(IOPattern(vec![SpongeOp::Absorb(elts.len() as u32), SpongeOp::Squeeze(1)]), None, &mut ns);
    SpongeAPI::absorb(&mut sponge, elts.len() as u32, &elts, &mut ns);
    let out = SpongeAPI::squeeze(&mut sponge, 1, &mut ns);
    sponge.finish(&mut ns).unwrap();
    let x = Elt::ensure_allocated(&out[0], &mut ns.namespace(|| "out")).unwrap();
    x
  }
  pub fn hash(&mut self, xs: &[AllocatedNum<F>]) -> AllocatedNum<F> {
    self.hash_e(xs.iter().cloned().map(Elt::Allocated).collect())
  }
  /// Bits of v, little-endian, n of them, constrained to recompose to the variable `x` shifted
  /// by `k` (sum 2^i b_i = x + k as field elements).
  pub(crate) fn bits_of(&mut self, v: F, n: usize, x: &LinearCombination<F>) -> Vec<AllocatedBit> {
    let le: Vec<bool> = v.to_le_bits().iter().take(n).map(|b| *b).collect();
    let bits: Vec<AllocatedBit> = le.iter().map(|&b| self.bit(b)).collect();
    let mut lc = LinearCombination::zero();
    let mut c = F::ONE;
    for b in &bits {
      lc = lc + (c, b.get_variable());
      c = c.double();
    }
    let nm = self.nm();
    let x = x.clone();
    self.cs.enforce(|| nm, |l| l, |l| l, |_| lc - &x);
    bits
  }
  /// Range check: x < 2^n.
  pub fn range(&mut self, x: &AllocatedNum<F>, n: usize) -> Vec<AllocatedBit> {
    let lc = LinearCombination::zero() + x.get_variable();
    self.bits_of(Self::val(x), n, &lc)
  }
  /// a < b as a bit, for a, b below 2^248: the top bit of the 249-bit decomposition of
  /// b - a - 1 + 2^248.
  pub(crate) fn lt_bit(&mut self, a: &AllocatedNum<F>, b: &AllocatedNum<F>) -> AllocatedBit {
    let v = Self::val(b) - Self::val(a) - F::ONE + pow2(248);
    let lc = LinearCombination::zero() + b.get_variable() - a.get_variable() + (pow2(248) - F::ONE, CS::one());
    let bits = self.bits_of(v, 249, &lc);
    bits[248].clone()
  }
  /// 1 when x = 0: two constraints.
  pub(crate) fn is_zero(&mut self, x: &AllocatedNum<F>) -> AllocatedNum<F> {
    let xv = Self::val(x);
    let inv = self.alloc(xv.invert().unwrap_or(F::ZERO));
    let z = self.alloc(if bool::from(xv.is_zero()) { F::ONE } else { F::ZERO });
    let nm = self.nm();
    let (xx, ii, zz) = (x.get_variable(), inv.get_variable(), z.get_variable());
    // x * inv = 1 - z
    self.cs.enforce(|| nm, |l| l + xx, |l| l + ii, |l| l + CS::one() - zz);
    let nm = self.nm();
    self.cs.enforce(|| nm, |l| l + xx, |l| l + zz, |l| l);
    z
  }
  /// One path walk: leaf hash up to the root, directions from `bits` (leaf level first).
  pub(crate) fn path_root(&mut self, leaf: &AllocatedNum<F>, bits: &[AllocatedBit], sibs: &[AllocatedNum<F>]) -> AllocatedNum<F> {
    let mut cur = leaf.clone();
    for (b, s) in bits.iter().zip(sibs) {
      let bv = b.get_value().unwrap_or(false);
      let (cv, sv) = (Self::val(&cur), Self::val(s));
      let d = self.alloc(if bv { sv - cv } else { F::ZERO });
      let nm = self.nm();
      let (bb, ss, cc, dd) = (b.get_variable(), s.get_variable(), cur.get_variable(), d.get_variable());
      // b * (sib - cur) = d
      self.cs.enforce(|| nm, |l| l + bb, |l| l + ss - cc, |l| l + dd);
      let l = Num::from(cur.clone()).add(&Num::from(d.clone()));
      let r = Num::from(s.clone()).add(&Num::from(d).scale(-F::ONE));
      cur = self.hash_e(vec![Elt::Num(l), Elt::Num(r)]);
    }
    cur
  }
  pub(crate) fn key_of(&mut self, lo: &AllocatedNum<F>, hi: &AllocatedNum<F>, vout: &AllocatedNum<F>) -> AllocatedNum<F> {
    let kfull = self.hash(&[lo.clone(), hi.clone(), vout.clone()]);
    // The canonical bit decomposition: a non-canonical one would change the low 248 bits.
    let nm = self.nm();
    let bits = kfull.to_bits_le_strict(self.cs.namespace(|| nm)).unwrap();
    let key = self.alloc(crate::elem::low248(&Self::val(&kfull)));
    let mut lc = LinearCombination::zero();
    let mut c = F::ONE;
    for b in bits.iter().take(248) {
      lc = b.lc(CS::one(), c) + &lc;
      c = c.double();
    }
    let kv = key.get_variable();
    let nm = self.nm();
    self.cs.enforce(|| nm, |l| l, |l| l, |_| lc - kv);
    key
  }
  pub(crate) fn leaf_hash(&mut self, f: &[AllocatedNum<F>; 6]) -> AllocatedNum<F> {
    self.hash(f)
  }
}

/// A leaf as witness values: key, next_key, next_index, value, script_fp, spent.
#[derive(Clone)]
pub struct LeafW(pub [F; 6]);

impl Default for LeafW {
  fn default() -> Self {
    LeafW([F::ZERO; 6])
  }
}

impl From<&Leaf> for LeafW {
  fn from(l: &Leaf) -> Self {
    LeafW([l.key, l.next_key, fu(l.next_index), fu(l.value), l.script_fp, fu(l.spent as u64)])
  }
}

pub(crate) fn idx_bits(i: u64) -> Vec<bool> {
  (0..D).map(|k| (i >> k) & 1 == 1).collect()
}

#[derive(Clone)]
pub struct CreateWit {
  pub txid_lo: F,
  pub txid_hi: F,
  pub vout: u64,
  pub low: LeafW,
  pub low_idx: u64,
  pub low_sibs: Vec<F>,
  pub new_idx: u64,
  pub app_sibs: Vec<F>,
  pub value: u64,
  pub script_fp: F,
}

impl Default for CreateWit {
  fn default() -> Self {
    CreateWit {
      txid_lo: F::ZERO,
      txid_hi: F::ZERO,
      vout: 0,
      low: LeafW::default(),
      low_idx: 0,
      low_sibs: vec![F::ZERO; D],
      new_idx: 1,
      app_sibs: vec![F::ZERO; D],
      value: 0,
      script_fp: F::ZERO,
    }
  }
}

impl CreateWit {
  pub fn from_proof(p: &CreateProof, txid: &[u8; 32], vout: u32) -> Self {
    CreateWit {
      txid_lo: f_from_le(&txid[..16]),
      txid_hi: f_from_le(&txid[16..]),
      vout: vout as u64,
      low: LeafW::from(&p.low.leaf),
      low_idx: p.low.path.index,
      low_sibs: p.low.path.siblings.clone(),
      new_idx: p.append.index,
      app_sibs: p.append.siblings.clone(),
      value: p.new_leaf.value,
      script_fp: p.new_leaf.script_fp,
    }
  }
}

/// Create: non-membership of the key, update of the low leaf, append at `new_idx`.
/// Returns the new root.
pub fn create_gadget<CS: ConstraintSystem<F>>(g: &mut G<CS>, w: &CreateWit, root_in: &AllocatedNum<F>) -> AllocatedNum<F> {
  let lo = g.alloc(w.txid_lo);
  let hi = g.alloc(w.txid_hi);
  let vout = g.alloc(fu(w.vout));
  let key = g.key_of(&lo, &hi, &vout);

  let l: Vec<AllocatedNum<F>> = w.low.0.iter().map(|v| g.alloc(*v)).collect();

  let low_bits: Vec<AllocatedBit> = idx_bits(w.low_idx).into_iter().map(|b| g.bit(b)).collect();
  let low_sibs: Vec<AllocatedNum<F>> = w.low_sibs.iter().map(|v| g.alloc(*v)).collect();
  let new_bits: Vec<AllocatedBit> = idx_bits(w.new_idx).into_iter().map(|b| g.bit(b)).collect();
  let app_sibs: Vec<AllocatedNum<F>> = w.app_sibs.iter().map(|v| g.alloc(*v)).collect();
  // new_idx as a number, recomposed from its bits.
  let new_idx = g.alloc(fu(w.new_idx));
  {
    let mut lc = LinearCombination::zero();
    let mut c = F::ONE;
    for b in &new_bits {
      lc = lc + (c, b.get_variable());
      c = c.double();
    }
    let nm = g.nm();
    let v = new_idx.get_variable();
    g.cs.enforce(|| nm, |x| x, |x| x, |_| lc - v);
  }

  // The low leaf is in the tree.
  let low_hash = g.leaf_hash(&[l[0].clone(), l[1].clone(), l[2].clone(), l[3].clone(), l[4].clone(), l[5].clone()]);
  let r0 = g.path_root(&low_hash, &low_bits, &low_sibs);
  g.enforce_eq(&r0, root_in);

  // low.key < key < low.next_key, or low.next_key = 0.
  let lt1 = g.lt_bit(&l[0], &key);
  let one = lt1.get_variable();
  let nm = g.nm();
  g.cs.enforce(|| nm, |x| x + one, |x| x + CS::one(), |x| x + CS::one());
  let lt2 = g.lt_bit(&key, &l[1]);
  let inf = g.is_zero(&l[1]);
  let (iv, tv) = (inf.get_variable(), lt2.get_variable());
  let nm = g.nm();
  g.cs.enforce(|| nm, |x| x + CS::one() - iv, |x| x + CS::one() - tv, |x| x);

  // Update the low leaf: next = (key, new_idx).
  let upd = g.leaf_hash(&[l[0].clone(), key.clone(), new_idx.clone(), l[3].clone(), l[4].clone(), l[5].clone()]);
  let mid = g.path_root(&upd, &low_bits, &low_sibs);

  // The slot at new_idx is empty under the updated root.
  let zero = g.constant(F::ZERO);
  let e = g.path_root(&zero, &new_bits, &app_sibs);
  g.enforce_eq(&e, &mid);

  // Append the new leaf (key, low.next_key, low.next_index, value, script_fp, unspent).
  let value = g.alloc(fu(w.value));
  g.range(&value, 64);
  let sh = g.alloc(w.script_fp);
  let nl = g.leaf_hash(&[key, l[1].clone(), l[2].clone(), value, sh, zero]);
  g.path_root(&nl, &new_bits, &app_sibs)
}

#[derive(Clone)]
pub struct SpendWit {
  pub txid_lo: F,
  pub txid_hi: F,
  pub vout: u64,
  pub leaf: LeafW,
  pub idx: u64,
  pub sibs: Vec<F>,
}

impl Default for SpendWit {
  fn default() -> Self {
    SpendWit { txid_lo: F::ZERO, txid_hi: F::ZERO, vout: 0, leaf: LeafW::default(), idx: 0, sibs: vec![F::ZERO; D] }
  }
}

impl SpendWit {
  pub fn from_proof(p: &SpendProof, txid: &[u8; 32], vout: u32) -> Self {
    SpendWit {
      txid_lo: f_from_le(&txid[..16]),
      txid_hi: f_from_le(&txid[16..]),
      vout: vout as u64,
      leaf: LeafW::from(&p.proof.leaf),
      idx: p.proof.path.index,
      sibs: p.proof.path.siblings.clone(),
    }
  }
}

/// Spend in window: membership of the key with spent = 0, then spent = 1. Returns the new root.
pub fn spend_gadget<CS: ConstraintSystem<F>>(g: &mut G<CS>, w: &SpendWit, root_in: &AllocatedNum<F>) -> AllocatedNum<F> {
  let lo = g.alloc(w.txid_lo);
  let hi = g.alloc(w.txid_hi);
  let vout = g.alloc(fu(w.vout));
  let key = g.key_of(&lo, &hi, &vout);
  let l: Vec<AllocatedNum<F>> = w.leaf.0.iter().map(|v| g.alloc(*v)).collect();
  let bits: Vec<AllocatedBit> = idx_bits(w.idx).into_iter().map(|b| g.bit(b)).collect();
  let sibs: Vec<AllocatedNum<F>> = w.sibs.iter().map(|v| g.alloc(*v)).collect();
  g.enforce_eq(&l[0], &key);
  let zero = g.constant(F::ZERO);
  g.enforce_eq(&l[5], &zero); // not yet spent
  let h = g.leaf_hash(&[l[0].clone(), l[1].clone(), l[2].clone(), l[3].clone(), l[4].clone(), l[5].clone()]);
  let r0 = g.path_root(&h, &bits, &sibs);
  g.enforce_eq(&r0, root_in);
  let one = g.constant(F::ONE);
  let h2 = g.leaf_hash(&[l[0].clone(), l[1].clone(), l[2].clone(), l[3].clone(), l[4].clone(), one]);
  g.path_root(&h2, &bits, &sibs)
}

/// Spend before the window: non-membership of the key. The root is unchanged.
pub fn nonmember_gadget<CS: ConstraintSystem<F>>(g: &mut G<CS>, w: &SpendWit, root_in: &AllocatedNum<F>) {
  let lo = g.alloc(w.txid_lo);
  let hi = g.alloc(w.txid_hi);
  let vout = g.alloc(fu(w.vout));
  let key = g.key_of(&lo, &hi, &vout);
  let l: Vec<AllocatedNum<F>> = w.leaf.0.iter().map(|v| g.alloc(*v)).collect();
  let bits: Vec<AllocatedBit> = idx_bits(w.idx).into_iter().map(|b| g.bit(b)).collect();
  let sibs: Vec<AllocatedNum<F>> = w.sibs.iter().map(|v| g.alloc(*v)).collect();
  let h = g.leaf_hash(&[l[0].clone(), l[1].clone(), l[2].clone(), l[3].clone(), l[4].clone(), l[5].clone()]);
  let r0 = g.path_root(&h, &bits, &sibs);
  g.enforce_eq(&r0, root_in);
  let lt1 = g.lt_bit(&l[0], &key);
  let one = lt1.get_variable();
  let nm = g.nm();
  g.cs.enforce(|| nm, |x| x + one, |x| x + CS::one(), |x| x + CS::one());
  let lt2 = g.lt_bit(&key, &l[1]);
  let inf = g.is_zero(&l[1]);
  let (iv, tv) = (inf.get_variable(), lt2.get_variable());
  let nm = g.nm();
  g.cs.enforce(|| nm, |x| x + CS::one() - iv, |x| x + CS::one() - tv, |x| x);
}

// ---------------------------------------------------------------------------------------------
// SHA-256 absorption
// ---------------------------------------------------------------------------------------------

/// The state's two 128-bit halves as numbers <-> eight words.
pub(crate) fn state_to_words<CS: ConstraintSystem<F>>(g: &mut G<CS>, lo: &AllocatedNum<F>, hi: &AllocatedNum<F>) -> Vec<UInt32> {
  let mut words = vec![];
  for half in [lo, hi] {
    let v = G::<CS>::val(half);
    let le: Vec<bool> = v.to_le_bits().iter().take(128).map(|b| *b).collect();
    let bits: Vec<AllocatedBit> = (0..128).map(|j| g.bit(le[127 - j])).collect(); // big-endian
    let mut lc = LinearCombination::zero();
    for (j, b) in bits.iter().enumerate() {
      lc = lc + (pow2(127 - j as u32), b.get_variable());
    }
    let nm = g.nm();
    let hv = half.get_variable();
    g.cs.enforce(|| nm, |x| x, |x| x, |_| lc - hv);
    let bools: Vec<Boolean> = bits.into_iter().map(Boolean::from).collect();
    for k in 0..4 {
      words.push(UInt32::from_bits_be(&bools[32 * k..32 * k + 32]));
    }
  }
  words
}

pub(crate) fn words_to_state<CS: ConstraintSystem<F>>(g: &mut G<CS>, words: &[UInt32]) -> (AllocatedNum<F>, AllocatedNum<F>) {
  let mut out = vec![];
  for half in words.chunks(4) {
    let bits: Vec<Boolean> = half.iter().flat_map(|w| w.clone().into_bits_be()).collect();
    let mut lc = LinearCombination::zero();
    let mut val = F::ZERO;
    for (j, b) in bits.iter().enumerate() {
      let c = pow2(127 - j as u32);
      lc = b.lc(CS::one(), c) + &lc;
      if b.get_value().unwrap_or(false) {
        val += c;
      }
    }
    let a = g.alloc(val);
    let nm = g.nm();
    let av = a.get_variable();
    g.cs.enforce(|| nm, |x| x, |x| x, |_| lc - av);
    out.push(a);
  }
  (out[0].clone(), out[1].clone())
}

/// c compressions over witness blocks, from a state carried as two field elements.
pub fn absorb_gadget<CS: ConstraintSystem<F>>(
  g: &mut G<CS>,
  blocks: &[[u8; 64]],
  lo: &AllocatedNum<F>,
  hi: &AllocatedNum<F>,
) -> (AllocatedNum<F>, AllocatedNum<F>) {
  let mut state = state_to_words(g, lo, hi);
  for (i, blk) in blocks.iter().enumerate() {
    let bits: Vec<Boolean> = (0..512).map(|j| Boolean::from(g.bit((blk[j / 8] >> (7 - j % 8)) & 1 == 1))).collect();
    let nm = format!("compress{i}");
    state = sha256_compression_function(g.cs.namespace(|| nm), &bits, &state).unwrap();
  }
  words_to_state(g, &state)
}

pub fn sha_iv_halves() -> (F, F) {
  const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  let pack = |ws: &[u32]| {
    let mut b = [0u8; 16];
    for (k, w) in ws.iter().enumerate() {
      b[12 - 4 * k..16 - 4 * k].copy_from_slice(&w.to_le_bytes());
    }
    f_from_le(&b)
  };
  (pack(&IV[..4]), pack(&IV[4..]))
}

// ---------------------------------------------------------------------------------------------
// Counting
// ---------------------------------------------------------------------------------------------

pub fn count<R>(f: impl FnOnce(&mut TestConstraintSystem<F>) -> R) -> (usize, bool, R) {
  let mut cs = TestConstraintSystem::<F>::new();
  let r = f(&mut cs);
  (cs.num_constraints(), cs.is_satisfied(), r)
}

/// Constraints of one compression of 512 witness bits from a constant IV, excluding the 512
/// input-bit allocations.
pub fn sha256_compression_constraints() -> usize {
  let mut cs = TestConstraintSystem::<F>::new();
  let bits: Vec<Boolean> = (0..512)
    .map(|i| Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("b{i}")), Some(i % 3 == 0)).unwrap()))
    .collect();
  let before = cs.num_constraints();
  let iv: Vec<UInt32> = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    .iter()
    .map(|&v| UInt32::constant(v))
    .collect();
  sha256_compression_function(cs.namespace(|| "c"), &bits, &iv).unwrap();
  assert!(cs.is_satisfied());
  cs.num_constraints() - before
}

/// Constraints of the Poseidon sponge on n allocated inputs.
pub fn poseidon_constraints(n: usize) -> usize {
  let mut cs = TestConstraintSystem::<F>::new();
  let mut g = G::new(&mut cs);
  let xs: Vec<AllocatedNum<F>> = (0..n).map(|i| g.alloc(fu(i as u64 + 1))).collect();
  g.hash(&xs);
  let c = cs.num_constraints();
  assert!(cs.is_satisfied());
  c
}

// ---------------------------------------------------------------------------------------------
// The fold-timing step
// ---------------------------------------------------------------------------------------------

/// State: [map root, SHA-256 state low half, high half]. One step: c compressions of witness
/// blocks and one create.
#[derive(Clone)]
pub struct BenchStep {
  pub blocks: Vec<[u8; 64]>,
  pub op: CreateWit,
}

impl BenchStep {
  pub fn blank(c: usize) -> Self {
    BenchStep { blocks: vec![[0u8; 64]; c], op: CreateWit::default() }
  }
}

impl StepCircuit<F> for BenchStep {
  fn arity(&self) -> usize {
    3
  }
  fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut g = G::new(cs);
    let (lo, hi) = absorb_gadget(&mut g, &self.blocks, &z[1], &z[2]);
    let root = create_gadget(&mut g, &self.op, &z[0]);
    Ok(vec![root, lo, hi])
  }
}

/// Constraints of a step with c compressions and one create (and with c compressions only).
pub fn bench_step_constraints(c: usize) -> usize {
  let mut cs = TestConstraintSystem::<F>::new();
  let z: Vec<AllocatedNum<F>> = (0..3).map(|i| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || F::ZERO)).collect();
  BenchStep::blank(c).synthesize(&mut cs, &z).unwrap();
  cs.num_constraints()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::native::{outpoint_key, UtxoMap};

  fn mk(n: u32) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[..4].copy_from_slice(&n.to_le_bytes());
    t[31] = (n % 251) as u8;
    t
  }

  #[test]
  fn poseidon_gadget_matches_native() {
    for n in [1usize, 2, 3, 6, 9] {
      let mut cs = TestConstraintSystem::<F>::new();
      let mut g = G::new(&mut cs);
      let xs: Vec<F> = (0..n).map(|i| fu(i as u64 * 7 + 3)).collect();
      let a: Vec<_> = xs.iter().map(|x| g.alloc(*x)).collect();
      let h = g.hash(&a);
      assert_eq!(h.get_value().unwrap(), crate::elem::hash(&xs));
      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn key_gadget_matches_native() {
    let t = mk(77);
    let mut cs = TestConstraintSystem::<F>::new();
    let mut g = G::new(&mut cs);
    let (lo, hi, v) = (g.alloc(f_from_le(&t[..16])), g.alloc(f_from_le(&t[16..])), g.alloc(fu(3)));
    let k = g.key_of(&lo, &hi, &v);
    assert_eq!(k.get_value().unwrap(), outpoint_key(&t, 3));
    assert!(cs.is_satisfied());
  }

  #[test]
  fn create_and_spend_gadgets_match_native() {
    let mut m = UtxoMap::new();
    for i in 0..40 {
      m.create(&mk(i), i % 3, 10 + i as u64, &[i as u8]).unwrap();
    }
    let cp = m.create(&mk(500), 1, 99, &[9, 9, 9]).unwrap();
    let w = CreateWit::from_proof(&cp, &mk(500), 1);
    let (n, ok, root) = count(|cs| {
      let mut g = G::new(cs);
      let r = g.alloc(cp.root_before);
      create_gadget(&mut g, &w, &r).get_value().unwrap()
    });
    assert!(ok && n > 0);
    assert_eq!(root, cp.root_after);
    // A wrong input root is refused.
    let (_, ok, _) = count(|cs| {
      let mut g = G::new(cs);
      let r = g.alloc(cp.root_after);
      create_gadget(&mut g, &w, &r).get_value().unwrap()
    });
    assert!(!ok);
    // A low leaf that is not the predecessor is refused.
    let mut bad = w.clone();
    let other = m.membership(&mk(3), 0).unwrap();
    bad.low = LeafW::from(&other.leaf);
    bad.low_idx = other.path.index;
    bad.low_sibs = other.path.siblings.clone();
    let (_, ok, _) = count(|cs| {
      let mut g = G::new(cs);
      let r = g.alloc(cp.root_before);
      create_gadget(&mut g, &bad, &r).get_value().unwrap()
    });
    assert!(!ok);
    let sp = m.spend_in_window(&mk(5), 2).unwrap();
    let sw = SpendWit::from_proof(&sp, &mk(5), 2);
    let (_, ok, root) = count(|cs| {
      let mut g = G::new(cs);
      let r = g.alloc(sp.root_before);
      spend_gadget(&mut g, &sw, &r).get_value().unwrap()
    });
    assert!(ok);
    assert_eq!(root, sp.root_after);
    // Spending the same leaf again (already spent in the proof) is unsatisfiable.
    let again = m.membership(&mk(5), 2).unwrap();
    let sw2 = SpendWit { leaf: LeafW::from(&again.leaf), ..sw.clone() };
    let (_, ok, _) = count(|cs| {
      let mut g = G::new(cs);
      let r = g.alloc(sp.root_after);
      spend_gadget(&mut g, &sw2, &r).get_value().unwrap()
    });
    assert!(!ok);
  }

  #[test]
  fn sha_compression_gadget_matches_native() {
    let blk: [u8; 64] = std::array::from_fn(|i| (i * 5 + 1) as u8);
    let (lo, hi) = sha_iv_halves();
    let mut cs = TestConstraintSystem::<F>::new();
    let mut g = G::new(&mut cs);
    let (a, b) = (g.alloc(lo), g.alloc(hi));
    let (ol, oh) = absorb_gadget(&mut g, &[blk], &a, &b);
    let mut st = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    sha2::compress256(&mut st, &[sha2::digest::generic_array::GenericArray::clone_from_slice(&blk)]);
    let (el, eh) = {
      let pack = |ws: &[u32]| {
        let mut b = [0u8; 16];
        for (k, w) in ws.iter().enumerate() {
          b[12 - 4 * k..16 - 4 * k].copy_from_slice(&w.to_le_bytes());
        }
        f_from_le(&b)
      };
      (pack(&st[..4]), pack(&st[4..]))
    };
    assert_eq!(ol.get_value().unwrap(), el);
    assert_eq!(oh.get_value().unwrap(), eh);
    assert!(cs.is_satisfied());
  }
}
