//! The M18 Nova step circuit. It mirrors `machine::step` one-to-one: the state vector `z` is
//! `State::to_vec`, the witness is a `StepWitness`, and every relation `step` checks is a
//! constraint here. Values are linear combinations (`V`); a multiplication allocates one variable.

use crate::cost::{idx_bits, state_to_words, G};
use crate::elem::{fu, F};
use crate::machine::*;
use ff::Field;
use nova_snark::frontend::gadgets::boolean::{AllocatedBit, Boolean};
use nova_snark::frontend::gadgets::num::{AllocatedNum, Num};
use nova_snark::frontend::gadgets::poseidon::Elt;
use nova_snark::frontend::gadgets::sha256::sha256_compression_function;
use nova_snark::frontend::gadgets::uint32::UInt32;
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

// ---------------------------------------------------------------------------------------------
// Values and the small gadget layer
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct V {
  num: Num<F>,
  var: Option<AllocatedNum<F>>,
}

fn vfrom(a: &AllocatedNum<F>) -> V {
  V { num: Num::from(a.clone()), var: Some(a.clone()) }
}

fn val(x: &V) -> F {
  x.num.get_value().unwrap_or(F::ZERO)
}

fn uval(x: &V) -> u64 {
  to_u64(&val(x)).unwrap_or(0)
}

fn lc(x: &V) -> LinearCombination<F> {
  x.num.lc(F::ONE)
}

fn add(a: &V, b: &V) -> V {
  V { num: a.num.clone().add(&b.num), var: None }
}

fn scale(a: &V, c: F) -> V {
  V { num: a.num.clone().scale(c), var: None }
}

fn sub(a: &V, b: &V) -> V {
  add(a, &scale(b, -F::ONE))
}

fn sum(xs: &[V]) -> V {
  let mut acc = zero_v();
  for x in xs {
    acc = add(&acc, x);
  }
  acc
}

fn zero_v() -> V {
  V { num: Num::zero(), var: None }
}

impl<'a, CS: ConstraintSystem<F>> G<'a, CS> {
  fn v_k(&self, c: F) -> V {
    V { num: Num::zero().add_bool_with_coeff(CS::one(), &Boolean::constant(true), c), var: None }
  }

  fn v_alloc(&mut self, x: F) -> V {
    let a = self.alloc(x);
    vfrom(&a)
  }

  fn v_mul(&mut self, a: &V, b: &V) -> V {
    let c = self.alloc(val(a) * val(b));
    let (la, lb) = (lc(a), lc(b));
    let nm = self.nm();
    let cv = c.get_variable();
    self.cs.enforce(|| nm, |l| l + &la, |l| l + &lb, |l| l + cv);
    vfrom(&c)
  }

  /// a * b = 0.
  fn v_zero_prod(&mut self, a: &V, b: &V) {
    let (la, lb) = (lc(a), lc(b));
    let nm = self.nm();
    self.cs.enforce(|| nm, |l| l + &la, |l| l + &lb, |l| l);
  }

  /// a = b.
  fn v_eq(&mut self, a: &V, b: &V) {
    let (la, lb) = (lc(a), lc(b));
    let nm = self.nm();
    self.cs.enforce(|| nm, |l| l + &la, |l| l + CS::one(), |l| l + &lb);
  }

  fn v_bit(&mut self, b: bool) -> V {
    let ab = self.bit(b);
    self.v_bit_of(&ab)
  }

  fn v_bit_of(&self, ab: &AllocatedBit) -> V {
    let b = ab.get_value().unwrap_or(false);
    vfrom(&AllocatedNum::from_parts(ab.get_variable(), Some(if b { F::ONE } else { F::ZERO })))
  }

  /// b + s * (a - b): `a` when s = 1.
  fn v_sel(&mut self, s: &V, a: &V, b: &V) -> V {
    let d = sub(a, b);
    let m = self.v_mul(s, &d);
    add(b, &m)
  }

  /// 1 when x = 0.
  fn v_iszero(&mut self, x: &V) -> V {
    let xv = val(x);
    let inv = self.alloc(xv.invert().unwrap_or(F::ZERO));
    let z = self.alloc(if bool::from(xv.is_zero()) { F::ONE } else { F::ZERO });
    let (lx, li, lz) = (lc(x), inv.get_variable(), z.get_variable());
    let nm = self.nm();
    self.cs.enforce(|| nm, |l| l + &lx, |l| l + li, |l| l + CS::one() - lz);
    let nm = self.nm();
    self.cs.enforce(|| nm, |l| l + &lx, |l| l + lz, |l| l);
    vfrom(&z)
  }

  fn v_num(&mut self, x: &V) -> AllocatedNum<F> {
    if let Some(a) = &x.var {
      return a.clone();
    }
    let a = self.alloc(val(x));
    let lx = lc(x);
    let nm = self.nm();
    let av = a.get_variable();
    self.cs.enforce(|| nm, |l| l + &lx, |l| l + CS::one(), |l| l + av);
    a
  }

  fn v_hash(&mut self, xs: &[V]) -> V {
    let elts: Vec<Elt<F>> = xs.iter().map(|x| Elt::Num(x.num.clone())).collect();
    let h = self.hash_e(elts);
    vfrom(&h)
  }

  /// One-hot decomposition of x over 0..n: n bits with sum 1 and sum k*bit_k = x.
  fn v_onehot(&mut self, x: &V, n: usize) -> Vec<V> {
    let idx = uval(x) as usize;
    let bits = self.v_onehot_free(idx, n);
    let mut w = zero_v();
    for (k, b) in bits.iter().enumerate() {
      w = add(&w, &scale(b, fu(k as u64)));
    }
    self.v_eq(&w, x);
    bits
  }

  /// A one-hot witness over 0..n with no value to tie to: bits, sum 1.
  fn v_onehot_free(&mut self, idx: usize, n: usize) -> Vec<V> {
    let bits: Vec<V> = (0..n).map(|k| self.v_bit(k == idx)).collect();
    let ls = lc(&sum(&bits));
    let nm = self.nm();
    self.cs.enforce(|| nm, |l| l + &ls, |l| l + CS::one(), |l| l + CS::one());
    bits
  }

  /// `n` little-endian bits of x with their recomposition.
  fn v_bits(&mut self, x: &V, n: usize) -> Vec<V> {
    use ff::PrimeFieldBits;
    let le: Vec<bool> = val(x).to_le_bits().iter().take(n).map(|b| *b).collect();
    let bits: Vec<V> = le.iter().map(|&b| self.v_bit(b)).collect();
    let mut w = zero_v();
    let mut c = F::ONE;
    for b in &bits {
      w = add(&w, &scale(b, c));
      c = c.double();
    }
    self.v_eq(&w, x);
    bits
  }

  /// Big-endian bits (most significant first) of a 128-bit number, with their recomposition.
  fn v_bits_be128(&mut self, x: &V) -> Vec<V> {
    let mut b = self.v_bits(x, 128);
    b.reverse();
    b
  }
}

fn pow2f(k: usize) -> F {
  F::from(2u64).pow_vartime([k as u64])
}

/// sum_j 2^(n-1-j) bits[j]: the big-endian number of the bits.
fn lc_be(bits: &[V]) -> V {
  let n = bits.len();
  let mut w = zero_v();
  for (j, b) in bits.iter().enumerate() {
    w = add(&w, &scale(b, pow2f(n - 1 - j)));
  }
  w
}

/// The bits are whole bytes, most significant bit of each byte first; the number is the
/// little-endian integer of the bytes.
fn lc_le(bits: &[V]) -> V {
  let mut w = zero_v();
  for (j, b) in bits.iter().enumerate() {
    let (byte, q) = (j / 8, j % 8);
    w = add(&w, &scale(b, pow2f(8 * byte + 7 - q)));
  }
  w
}

// ---------------------------------------------------------------------------------------------
// State as values
// ---------------------------------------------------------------------------------------------

struct Zv {
  phase: V,
  fresh: V,
  sha: [V; 2],
  prev: [V; 2],
  height: V,
  n: V,
  frontier: Vec<[V; 2]>,
  carry: [V; 2],
  mlevel: V,
  lastf: V,
  ps: V,
  rem: V,
  acc: V,
  vmul: V,
  n_in: V,
  n_out: V,
  out_idx: V,
  pl: V,
  ph: V,
  val: V,
  sfp: V,
  tx_len: V,
  lenacc: V,
  fp: V,
  root: V,
  leaf_count: V,
  fc: V,
  gc: V,
  open: V,
  tx: [V; 2],
  pending: V,
  pend: V,
  h0: [V; 2],
  r_s: V,
  r: V,
  sealed: V,
}

fn parse_z(z: &[AllocatedNum<F>]) -> Zv {
  let mut i = 0;
  let mut nx = || {
    i += 1;
    vfrom(&z[i - 1])
  };
  let phase = nx();
  let fresh = nx();
  let sha = [nx(), nx()];
  let prev = [nx(), nx()];
  let height = nx();
  let n = nx();
  let frontier: Vec<[V; 2]> = (0..NF).map(|_| [nx(), nx()]).collect();
  let carry = [nx(), nx()];
  let mlevel = nx();
  let lastf = nx();
  Zv {
    phase,
    fresh,
    sha,
    prev,
    height,
    n,
    frontier,
    carry,
    mlevel,
    lastf,
    ps: nx(),
    rem: nx(),
    acc: nx(),
    vmul: nx(),
    n_in: nx(),
    n_out: nx(),
    out_idx: nx(),
    pl: nx(),
    ph: nx(),
    val: nx(),
    sfp: nx(),
    tx_len: nx(),
    lenacc: nx(),
    fp: nx(),
    root: nx(),
    leaf_count: nx(),
    fc: nx(),
    gc: nx(),
    open: nx(),
    tx: [nx(), nx()],
    pending: nx(),
    pend: nx(),
    h0: [nx(), nx()],
    r_s: nx(),
    r: nx(),
    sealed: nx(),
  }
}

/// The powers of the fingerprint challenge.
struct Pw {
  r: V,
  r2: V,
  r3: V,
  r4: V,
}

/// F' = F + gate * (F r^4 + x0 r^3 + x1 r^2 + x2 r + x3 - F).
fn fold_gated<CS: ConstraintSystem<F>>(g: &mut G<CS>, f: &V, pw: &Pw, x: &[V; 4], gate: &V) -> V {
  let a = g.v_mul(f, &pw.r4);
  let b0 = g.v_mul(&x[0], &pw.r3);
  let b1 = g.v_mul(&x[1], &pw.r2);
  let b2 = g.v_mul(&x[2], &pw.r);
  let new = sum(&[a, b0, b1, b2, x[3].clone()]);
  let d = sub(&new, f);
  let m = g.v_mul(gate, &d);
  add(f, &m)
}

// ---------------------------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct M18Step {
  pub w: StepWitness,
}

impl M18Step {
  pub fn blank() -> Self {
    M18Step { w: StepWitness::default() }
  }
}

fn const_pad32(i: usize) -> bool {
  i == 256 || i == 503
}
fn const_pad64(i: usize) -> bool {
  i == 0 || i == 502
}
fn const_hdr2(i: usize) -> bool {
  i == 128 || i == 502 || i == 504
}

/// A number from Boolean bits with a weight per bit, as one allocated variable.
fn bool_number<CS: ConstraintSystem<F>>(g: &mut G<CS>, bits: &[Boolean], weights: &[F]) -> V {
  let mut l = LinearCombination::<F>::zero();
  let mut v = F::ZERO;
  for (b, w) in bits.iter().zip(weights) {
    l = l + &b.lc(CS::one(), *w);
    if b.get_value().unwrap_or(false) {
      v += *w;
    }
  }
  let a = g.alloc(v);
  let nm = g.nm();
  let av = a.get_variable();
  g.cs.enforce(|| nm, |x| x + &l, |x| x + CS::one(), |x| x + av);
  vfrom(&a)
}

/// The two big-endian halves and the two little-endian limbs of eight words.
fn digest_numbers<CS: ConstraintSystem<F>>(g: &mut G<CS>, words: &[UInt32]) -> ([V; 2], [V; 2]) {
  let bits: Vec<Boolean> = words.iter().flat_map(|w| w.clone().into_bits_be()).collect();
  let be_w: Vec<F> = (0..128).map(|j| pow2f(127 - j)).collect();
  let le_w: Vec<F> = (0..128).map(|j| pow2f(8 * (j / 8) + 7 - j % 8)).collect();
  let be = [bool_number(g, &bits[..128], &be_w), bool_number(g, &bits[128..], &be_w)];
  let le = [bool_number(g, &bits[..128], &le_w), bool_number(g, &bits[128..], &le_w)];
  (be, le)
}

impl StepCircuit<F> for M18Step {
  fn arity(&self) -> usize {
    NZ
  }

  fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut gg_ = G::new(cs);
    let g = &mut gg_;
    let w = &self.w;
    let zv = parse_z(z);
    let one = g.v_k(F::ONE);
    let zero = zero_v();
    let not = |x: &V| sub(&one, x);

    // challenge powers
    let r = zv.r.clone();
    let r2 = g.v_mul(&r, &r);
    let r3 = g.v_mul(&r2, &r);
    let r4 = g.v_mul(&r3, &r);
    let pw = Pw { r: r.clone(), r2, r3, r4 };

    // ---- phase selectors: s[p] = onehot(phase)[p] * (1 - idle)
    let ph_oh = g.v_onehot(&zv.phase, phase::COUNT);
    let idle = g.v_bit(w.idle);
    let nidle = not(&idle);
    let s: Vec<V> = (0..8).map(|p| g.v_mul(&ph_oh[p], &nidle)).collect();
    let (s_body, s_txid, s_m1, s_m2, s_m3, s_h1, s_h2, s_h3) =
      (s[0].clone(), s[1].clone(), s[2].clone(), s[3].clone(), s[4].clone(), s[5].clone(), s[6].clone(), s[7].clone());
    let s_any = sum(&s);

    // ---- witness bits of the message block, most significant bit of each byte first
    let mb: Vec<AllocatedBit> = (0..512).map(|i| g.bit((w.block[i / 8] >> (7 - i % 8)) & 1 == 1)).collect();
    let mv: Vec<V> = mb.iter().map(|b| g.v_bit_of(b)).collect();
    // constant parts of the derived blocks
    for i in 0..512 {
      let mut zs = vec![];
      let mut os = vec![];
      let mut put = |p: usize, c: bool| {
        if c {
          os.push(s[p].clone())
        } else {
          zs.push(s[p].clone())
        }
      };
      if i >= 256 {
        for p in [1usize, 4, 7] {
          put(p, const_pad32(i));
        }
      }
      put(3, const_pad64(i));
      if i >= 128 {
        put(6, const_hdr2(i));
      }
      if !zs.is_empty() {
        let z_ = sum(&zs);
        g.v_zero_prod(&z_, &mv[i]);
      }
      if !os.is_empty() {
        let o_ = sum(&os);
        g.v_zero_prod(&o_, &not(&mv[i]));
      }
    }

    // ---- frontier: n's bits, the merge level, slot selection
    let nb = g.v_bits(&zv.n, NF);
    let ohm = g.v_onehot(&zv.mlevel, NF);
    let mut slot_sel = [zero.clone(), zero.clone()];
    for k in 0..NF {
      for l in 0..2 {
        let m = g.v_mul(&ohm[k], &zv.frontier[k][l]);
        slot_sel[l] = add(&slot_sel[l], &m);
      }
    }
    // a merge reads an occupied slot
    {
      let mut occ_m = zero.clone();
      for k in 0..NF {
        let m = g.v_mul(&ohm[k], &nb[k]);
        occ_m = add(&occ_m, &m);
      }
      g.v_zero_prod(&s_m1, &not(&occ_m));
    }

    // ---- message-block relations per phase
    let carry_hi_be = g.v_bits_be128(&zv.carry[1]);
    {
      // the SHA register is the first half of the message (TXID, MERGE3, HDR3)
      let sel_r = add(&add(&s_txid, &s_m3), &s_h3);
      for l in 0..2 {
        let n_ = lc_be(&mv[128 * l..128 * l + 128]);
        g.v_zero_prod(&sel_r, &sub(&n_, &zv.sha[l]));
      }
      // MERGE1: slot || carry
      for l in 0..2 {
        let n_ = lc_be(&mv[128 * l..128 * l + 128]);
        g.v_zero_prod(&s_m1, &sub(&n_, &slot_sel[l]));
        let n_ = lc_be(&mv[256 + 128 * l..256 + 128 * l + 128]);
        g.v_zero_prod(&s_m1, &sub(&n_, &zv.carry[l]));
      }
      // HDR1: bytes 4..36 are the previous hash, bytes 36..64 the first 28 bytes of the root
      for l in 0..2 {
        let n_ = lc_le(&mv[32 + 128 * l..32 + 128 * l + 128]);
        g.v_zero_prod(&s_h1, &sub(&n_, &zv.prev[l]));
      }
      let n_ = lc_be(&mv[288..416]);
      g.v_zero_prod(&s_h1, &sub(&n_, &zv.carry[0]));
      for j in 0..96 {
        g.v_zero_prod(&s_h1, &sub(&mv[416 + j], &carry_hi_be[j]));
      }
      // HDR2: bytes 64..68 are the last 4 bytes of the root
      for j in 0..32 {
        g.v_zero_prod(&s_h2, &sub(&mv[j], &carry_hi_be[96 + j]));
      }
    }

    // ---- the compression
    let iv = iv_halves();
    let sb_fresh = g.v_mul(&s_body, &not(&zv.fresh));
    let use_reg = sum(&[sb_fresh, s_m2.clone(), s_h2.clone()]);
    let mut chain = vec![];
    for l in 0..2 {
      let ivk = g.v_k(iv[l]);
      let d = sub(&zv.sha[l], &ivk);
      let m = g.v_mul(&use_reg, &d);
      chain.push(add(&ivk, &m));
    }
    let lo_a = g.v_num(&chain[0]);
    let hi_a = g.v_num(&chain[1]);
    let state_words = state_to_words(g, &lo_a, &hi_a);
    let bools: Vec<Boolean> = mb.iter().map(|b| Boolean::from(b.clone())).collect();
    let out_words = sha256_compression_function(g.cs.namespace(|| "compress"), &bools, &state_words)?;
    let (out_be, out_le) = digest_numbers(g, &out_words);

    // ---- the byte parser (BODY)
    let mut ps_eff = {
      let sink = g.v_k(fu(pst::SINK));
      g.v_sel(&s_body, &zv.ps, &sink)
    };
    let (mut rem, mut acc, mut vmul, mut n_in, mut n_out, mut out_idx, mut pl, mut ph, mut pval, mut sfp, mut tx_len, mut lenacc) = (
      zv.rem.clone(),
      zv.acc.clone(),
      zv.vmul.clone(),
      zv.n_in.clone(),
      zv.n_out.clone(),
      zv.out_idx.clone(),
      zv.pl.clone(),
      zv.ph.clone(),
      zv.val.clone(),
      zv.sfp.clone(),
      zv.tx_len.clone(),
      zv.lenacc.clone(),
    );
    let mut fp = zv.fp.clone();
    let mut sv = g.v_onehot(&ps_eff, pst::COUNT + 1);
    for pos in 0..64usize {
      let bits: Vec<V> = (0..8).map(|j| mv[8 * pos + 7 - j].clone()).collect();
      let mut b = zero_v();
      for (j, bj) in bits.iter().enumerate() {
        b = add(&b, &scale(bj, fu(1 << j)));
      }
      let st = |k: u64| sv[k as usize].clone();
      // no byte follows the end of a transaction
      g.v_zero_prod(&st(pst::DONE), &one);
      let s_len = if pos == 56 { add(&st(pst::LEN), &st(pst::PADZ)) } else { st(pst::LEN) };
      let s_padz = if pos == 56 { zero_v() } else { st(pst::PADZ) };

      let e = g.v_iszero(&sub(&rem, &one));
      // compact-size first byte
      let mut hi6 = g.v_mul(&bits[7], &bits[6]);
      for j in (2..6).rev() {
        hi6 = g.v_mul(&hi6, &bits[j]);
      }
      let q = g.v_mul(&bits[1], &bits[0]);
      let is_ff = g.v_mul(&hi6, &q);
      let is_fd = g.v_mul(&hi6, &sub(&bits[0], &q));
      let is_fe = g.v_mul(&hi6, &sub(&bits[1], &q));
      let small = sub(&one, &sum(&[is_fd.clone(), is_fe.clone(), is_ff.clone()]));
      let a_first = sum(&[st(pst::INCNT_FIRST), st(pst::SSLEN_FIRST), st(pst::OUTCNT_FIRST), st(pst::SPKLEN_FIRST)]);
      g.v_zero_prod(&a_first, &is_ff);
      let g_fd = g.v_mul(&a_first, &is_fd);
      let g_fe = g.v_mul(&a_first, &is_fe);
      let gfs_in = g.v_mul(&st(pst::INCNT_FIRST), &small);
      let gfs_ss = g.v_mul(&st(pst::SSLEN_FIRST), &small);
      let gfs_out = g.v_mul(&st(pst::OUTCNT_FIRST), &small);
      let gfs_sp = g.v_mul(&st(pst::SPKLEN_FIRST), &small);

      // end-of-field guards
      let le_states = [
        pst::VER,
        pst::INCNT_REST,
        pst::PTXLO,
        pst::PTXHI,
        pst::PVOUT,
        pst::SSLEN_REST,
        pst::SEQ,
        pst::OUTCNT_REST,
        pst::VALUE,
        pst::SPKLEN_REST,
        pst::LOCK,
      ];
      let mut gk: Vec<Option<V>> = vec![None; pst::COUNT];
      for &k in le_states.iter().chain([pst::SS, pst::SPK].iter()) {
        let m = g.v_mul(&st(k), &e);
        gk[k as usize] = Some(m);
      }
      let gg = |k: u64| gk[k as usize].clone().unwrap();
      let g_len_e = g.v_mul(&s_len, &e);
      let le = sum(&le_states.iter().map(|&k| st(k)).collect::<Vec<_>>());
      let g_le_e = sum(&le_states.iter().map(|&k| gg(k)).collect::<Vec<_>>());

      // little-endian accumulation
      let bv = g.v_mul(&b, &vmul);
      let t = g.v_mul(&le, &bv);
      let accn = add(&acc, &t);
      let m = g.v_mul(&le, &vmul);
      let vmul_n = add(&vmul, &scale(&m, fu(255)));
      let acc_next = sub(&accn, &g.v_mul(&g_le_e, &accn));
      let vmul_next = add(&vmul_n, &g.v_mul(&g_le_e, &sub(&one, &vmul_n)));

      // compact size value
      let a_rest = sum(&[gg(pst::INCNT_REST), gg(pst::SSLEN_REST), gg(pst::OUTCNT_REST), gg(pst::SPKLEN_REST)]);
      let a_f = sum(&[gfs_in.clone(), gfs_ss.clone(), gfs_out.clone(), gfs_sp.clone()]);
      let cv = add(&g.v_mul(&a_f, &b), &g.v_mul(&a_rest, &accn));
      let cvz = g.v_iszero(&cv);
      let ready_in = add(&gfs_in, &gg(pst::INCNT_REST));
      let ready_ss = add(&gfs_ss, &gg(pst::SSLEN_REST));
      let ready_out = add(&gfs_out, &gg(pst::OUTCNT_REST));
      let ready_sp = add(&gfs_sp, &gg(pst::SPKLEN_REST));
      g.v_zero_prod(&add(&ready_in, &ready_out), &cvz);
      let w_ss = g.v_mul(&ready_ss, &cvz);
      let w_sp = g.v_mul(&ready_sp, &cvz);
      let z_in = g.v_iszero(&sub(&n_in, &one));
      let gz_seq = g.v_mul(&gg(pst::SEQ), &z_in);
      let z_out = g.v_iszero(&sub(&n_out, &one));
      let ao = add(&w_sp, &gg(pst::SPK));
      let aoz = g.v_mul(&ao, &z_out);
      let k64 = g.v_k(fu(64));
      let z64 = g.v_iszero(&sub(&tx_len, &k64));
      g.v_zero_prod(&g_len_e, &z64);

      // padding states
      let k128 = g.v_k(fu(128));
      g.v_zero_prod(&st(pst::PAD80), &sub(&b, &k128));
      g.v_zero_prod(&s_padz, &b);
      // length
      let lm = g.v_mul(&s_len, &add(&scale(&lenacc, fu(255)), &b));
      let lenacc_next = add(&lenacc, &lm);
      g.v_zero_prod(&g_len_e, &sub(&lenacc_next, &scale(&tx_len, fu(8))));

      // script fingerprint
      let m1 = g.v_mul(&sfp, &zv.r_s);
      let sfpn = add(&m1, &b);
      let ma = g.v_mul(&st(pst::SPK), &sub(&sfpn, &sfp));
      let mb_ = g.v_mul(&ready_sp, &sub(&cv, &sfp));
      let sfp_next = sum(&[sfp.clone(), ma, mb_]);

      // registers
      let pl_next = add(&pl, &g.v_mul(&gg(pst::PTXLO), &sub(&accn, &pl)));
      let ph_next = add(&ph, &g.v_mul(&gg(pst::PTXHI), &sub(&accn, &ph)));
      let val_next = add(&pval, &g.v_mul(&gg(pst::VALUE), &sub(&accn, &pval)));
      let n_in_next = sub(&add(&n_in, &g.v_mul(&ready_in, &cv)), &gg(pst::SEQ));
      let n_out_next = sub(&add(&n_out, &g.v_mul(&ready_out, &cv)), &ao);
      let out_idx_next = add(&out_idx, &ao);
      let tx_len_next = add(&tx_len, &sum(&(0..=pst::LOCK).map(|k| st(k)).collect::<Vec<_>>()));

      // remaining bytes
      let p_ss = g.v_mul(&ready_ss, &cv);
      let p_sp = g.v_mul(&ready_sp, &cv);
      let cnt = sum(&[le.clone(), st(pst::SS), st(pst::SPK), s_len.clone()]);
      let rem_next = sum(&[
        sub(&rem, &cnt),
        scale(&g_fd, fu(2)),
        scale(&g_fe, fu(4)),
        scale(&ready_in, fu(16)),
        scale(&gg(pst::PTXLO), fu(16)),
        scale(&gg(pst::PTXHI), fu(4)),
        scale(&w_ss, fu(4)),
        p_ss,
        scale(&gg(pst::SS), fu(4)),
        scale(&sub(&gg(pst::SEQ), &gz_seq), fu(16)),
        scale(&ready_out, fu(8)),
        p_sp,
        scale(&ao, fu(8)),
        scale(&aoz, -fu(4)),
        scale(&st(pst::PAD80), fu(8)),
      ]);

      // next state
      let mut nps = ps_eff.clone();
      let mut dl = |x: &V, c: i64| {
        let k = if c >= 0 { fu(c as u64) } else { -fu((-c) as u64) };
        nps = add(&nps, &scale(x, k));
      };
      dl(&gg(pst::VER), 1);
      dl(&g_fd, 1);
      dl(&g_fe, 1);
      dl(&gfs_in, 2);
      dl(&gg(pst::INCNT_REST), 1);
      dl(&gg(pst::PTXLO), 1);
      dl(&gg(pst::PTXHI), 1);
      dl(&gg(pst::PVOUT), 1);
      dl(&ready_ss, 8);
      dl(&w_ss, 1);
      dl(&gfs_ss, -6);
      dl(&gg(pst::SSLEN_REST), -7);
      dl(&gg(pst::SS), 1);
      dl(&gg(pst::SEQ), -6);
      dl(&gz_seq, 7);
      dl(&gfs_out, 2);
      dl(&gg(pst::OUTCNT_REST), 1);
      dl(&gg(pst::VALUE), 1);
      dl(&ready_sp, 15);
      dl(&w_sp, -15);
      dl(&gfs_sp, -13);
      dl(&gg(pst::SPKLEN_REST), -14);
      dl(&ao, 12);
      dl(&aoz, 4);
      dl(&gg(pst::SPK), -15);
      dl(&gg(pst::LOCK), 1);
      dl(&st(pst::PAD80), 1);
      if pos == 56 {
        dl(&st(pst::PADZ), 1);
      }
      dl(&g_len_e, 1);

      // events
      let ev_in = gg(pst::PVOUT);
      let u = g.v_mul(&fp, &pw.r4);
      let xi = sum(&[u.clone(), pw.r3.clone(), g.v_mul(&pl, &pw.r2), g.v_mul(&ph, &pw.r), accn.clone()]);
      let xfp = g.v_mul(&gg(pst::SPK), &sfpn);
      let xo = sum(&[u, scale(&pw.r3, fu(2)), g.v_mul(&out_idx, &pw.r2), g.v_mul(&pval, &pw.r), xfp]);
      let fp_next = sum(&[fp.clone(), g.v_mul(&ev_in, &sub(&xi, &fp)), g.v_mul(&ao, &sub(&xo, &fp))]);

      rem = rem_next;
      acc = acc_next;
      vmul = vmul_next;
      n_in = n_in_next;
      n_out = n_out_next;
      out_idx = out_idx_next;
      pl = pl_next;
      ph = ph_next;
      pval = val_next;
      sfp = sfp_next;
      tx_len = tx_len_next;
      lenacc = lenacc_next;
      fp = fp_next;
      ps_eff = nps;
      sv = g.v_onehot(&ps_eff, pst::COUNT + 1);
    }
    let done = sv[pst::DONE as usize].clone();
    let ps_out = {
      let d = sub(&ps_eff, &zv.ps);
      let m = g.v_mul(&s_body, &d);
      add(&zv.ps, &m)
    };

    // ---- TXID: the event, the parser reset
    let tx_ev = [g.v_k(fu(3)), out_le[0].clone(), out_le[1].clone(), zero.clone()];
    let fp_txid = fold_gated(g, &fp, &pw, &tx_ev, &s_txid);
    let init = |k: usize| -> F {
      match k {
        1 => fu(4), // rem
        3 => F::ONE, // vmul
        _ => F::ZERO,
      }
    };
    let par_now = [ps_out.clone(), rem, acc, vmul, n_in, n_out, out_idx, pl, ph, pval, sfp, tx_len, lenacc];
    let mut par_out = vec![];
    for (k, x) in par_now.iter().enumerate() {
      let c = g.v_k(init(k));
      let d = sub(&c, x);
      let m = g.v_mul(&s_txid, &d);
      par_out.push(add(x, &m));
    }

    // ---- placement of a node (TXID, MERGE3)
    let last_w = g.v_bit(w.last);
    let lastf_eff = {
      let d = sub(&last_w, &zv.lastf);
      let m = g.v_mul(&s_txid, &d);
      add(&zv.lastf, &m)
    };
    let mut oh_place = vec![s_txid.clone()];
    for k in 1..NF {
      oh_place.push(g.v_mul(&s_m3, &ohm[k - 1]));
    }
    g.v_zero_prod(&s_m3, &ohm[NF - 1]);
    let mut prod = vec![];
    for k in 0..NF {
      prod.push(g.v_mul(&oh_place[k], &nb[k]));
    }
    let occ = sum(&prod);
    let placed: Vec<V> = (0..NF).map(|k| sub(&oh_place[k], &prod[k])).collect();
    let act_place = add(&s_txid, &s_m3);
    let mut pw_m1 = zero_v();
    for k in 0..NF {
      pw_m1 = add(&pw_m1, &scale(&ohm[k], pow2f(k)));
    }
    let m1pw = g.v_mul(&s_m1, &pw_m1);
    let mut n_mid = zv.n.clone();
    for k in 0..NF {
      n_mid = add(&n_mid, &scale(&placed[k], pow2f(k)));
    }
    n_mid = sub(&n_mid, &m1pw);
    let nb2 = g.v_bits(&n_mid, NF);
    let mut low = vec![];
    let mut pfx = zero_v();
    for k in 0..NF {
      let t = g.v_mul(&nb2[k], &pfx);
      let l = sub(&nb2[k], &t);
      pfx = add(&pfx, &l);
      low.push(l);
    }
    let cnt1 = sum(&nb2);
    let pow2 = g.v_iszero(&sub(&cnt1, &one));
    let mut level_num = zero_v();
    let mut j_num = zero_v();
    for k in 0..NF {
      level_num = add(&level_num, &scale(&oh_place[k], fu(k as u64)));
      j_num = add(&j_num, &scale(&low[k], fu(k as u64)));
    }
    let mut new_slot: Vec<[V; 2]> = vec![];
    for k in 0..NF {
      let mut sl = [zero.clone(), zero.clone()];
      for l in 0..2 {
        let d = sub(&out_be[l], &zv.frontier[k][l]);
        let m = g.v_mul(&placed[k], &d);
        sl[l] = add(&zv.frontier[k][l], &m);
      }
      new_slot.push(sl);
    }
    let mut slot_j = [zero.clone(), zero.clone()];
    for k in 0..NF {
      for l in 0..2 {
        let m = g.v_mul(&low[k], &new_slot[k][l]);
        slot_j[l] = add(&slot_j[l], &m);
      }
    }
    let q1 = g.v_mul(&lastf_eff, &pow2);
    let pp_inner = add(&scale(&q1, fu(5)), &scale(&sub(&lastf_eff, &q1), fu(2)));
    let pp_t = g.v_mul(&not(&occ), &pp_inner);
    let pp = add(&scale(&occ, fu(2)), &pp_t);
    let m_pp = g.v_mul(&act_place, &pp);
    let end_w = g.v_bit(w.end);
    let sh3e = g.v_mul(&s_h3, &end_w);
    let phase_next = sum(&[
      zv.phase.clone(),
      done.clone(),
      s_m1.clone(),
      s_m2.clone(),
      s_h1.clone(),
      s_h2.clone(),
      scale(&sh3e, fu(8)),
      scale(&s_h3, -fu(7)),
      m_pp,
      scale(&s_txid, -fu(1)),
      scale(&s_m3, -fu(4)),
    ]);
    let mlevel_next = {
      let c1 = g.v_mul(&occ, &level_num);
      let c2 = g.v_mul(&occ, &j_num);
      let newm = sub(&add(&c1, &j_num), &c2);
      let m = g.v_mul(&act_place, &sub(&newm, &zv.mlevel));
      add(&zv.mlevel, &m)
    };
    let mut carry_next = [zero.clone(), zero.clone()];
    for l in 0..2 {
      let m = g.v_mul(&lastf_eff, &sub(&slot_j[l], &zv.carry[l]));
      let y = add(&zv.carry[l], &m);
      let m2 = g.v_mul(&occ, &sub(&out_be[l], &y));
      let newc = add(&y, &m2);
      let m3 = g.v_mul(&act_place, &sub(&newc, &zv.carry[l]));
      carry_next[l] = add(&zv.carry[l], &m3);
    }
    let n_next = {
      let m = g.v_mul(&s_h3, &n_mid);
      sub(&n_mid, &m)
    };
    let mut sha_next = [zero.clone(), zero.clone()];
    for l in 0..2 {
      let m = g.v_mul(&s_any, &sub(&out_be[l], &zv.sha[l]));
      sha_next[l] = add(&zv.sha[l], &m);
    }
    let fresh_next = {
      let a = g.v_mul(&add(&s_txid, &s_h3), &not(&zv.fresh));
      let b = g.v_mul(&s_body, &zv.fresh);
      sub(&add(&zv.fresh, &a), &b)
    };
    let mut prev_next = [zero.clone(), zero.clone()];
    for l in 0..2 {
      let m = g.v_mul(&s_h3, &sub(&out_le[l], &zv.prev[l]));
      prev_next[l] = add(&zv.prev[l], &m);
    }
    let height_next = add(&zv.height, &s_h3);

    // =============================== the consumer ===============================
    let close = g.v_bit(w.close);
    let open_w = g.v_bit(w.open);
    let oh = g.v_onehot_free(w.op as usize, opk::COUNT);
    let (oh_none, oh_si, oh_sp, oh_cl, oh_cn) = (oh[0].clone(), oh[1].clone(), oh[2].clone(), oh[3].clone(), oh[4].clone());
    let ev_op = sum(&[oh_si.clone(), oh_sp.clone(), oh_cl.clone()]);
    // a sealed window changes nothing
    g.v_zero_prod(&zv.sealed, &sum(&[close.clone(), open_w.clone(), ev_op.clone(), oh_cn.clone()]));
    // close
    g.v_zero_prod(&close, &not(&zv.open));
    g.v_zero_prod(&close, &zv.pending);
    let close_ev = [g.v_k(fu(3)), zv.tx[0].clone(), zv.tx[1].clone(), zero.clone()];
    let fc1 = fold_gated(g, &zv.fc, &pw, &close_ev, &close);
    let hc = g.v_hash(&[zv.gc.clone(), close_ev[0].clone(), close_ev[1].clone(), close_ev[2].clone(), close_ev[3].clone()]);
    let gc1 = add(&zv.gc, &g.v_mul(&close, &sub(&hc, &zv.gc)));
    let open_mid = sub(&zv.open, &close);
    // open
    g.v_zero_prod(&open_w, &open_mid);
    let open_after = add(&open_mid, &open_w);
    let open_tx = [g.v_alloc(w.open_tx[0]), g.v_alloc(w.open_tx[1])];
    let mut tx_next = [zero.clone(), zero.clone()];
    for l in 0..2 {
      let m = g.v_mul(&open_w, &sub(&open_tx[l], &zv.tx[l]));
      tx_next[l] = add(&zv.tx[l], &m);
    }
    // op preconditions
    g.v_zero_prod(&ev_op, &not(&open_after));
    g.v_zero_prod(&ev_op, &zv.pending);
    g.v_zero_prod(&oh_cn, &not(&zv.pending));
    // the key
    let ev: Vec<V> = w.ev.iter().map(|x| g.v_alloc(*x)).collect();
    let lo_in = add(&ev[0], &g.v_mul(&oh_cl, &sub(&tx_next[0], &ev[0])));
    let hi_in = add(&ev[1], &g.v_mul(&oh_cl, &sub(&tx_next[1], &ev[1])));
    let vout_in = add(&ev[2], &g.v_mul(&oh_cl, &sub(&ev[0], &ev[2])));
    let (lo_a, hi_a, vo_a) = (g.v_num(&lo_in), g.v_num(&hi_in), g.v_num(&vout_in));
    let key_a = g.key_of(&lo_a, &hi_a, &vo_a);
    let key = vfrom(&key_a);
    // the leaf and its path
    let leaf: Vec<V> = w.leaf.iter().map(|x| g.v_alloc(*x)).collect();
    let leaf_a: Vec<AllocatedNum<F>> = leaf.iter().map(|x| g.v_num(x)).collect();
    let ibits: Vec<AllocatedBit> = idx_bits(w.idx).into_iter().map(|b| g.bit(b)).collect();
    let ibv: Vec<V> = ibits.iter().map(|b| g.v_bit_of(b)).collect();
    let mut idx_num = zero_v();
    for (k, b) in ibv.iter().enumerate() {
      idx_num = add(&idx_num, &scale(b, pow2f(k)));
    }
    let sibs: Vec<AllocatedNum<F>> = w.sibs.iter().map(|x| g.alloc(*x)).collect();
    let h_old = g.v_hash(&leaf);
    let h_old_eff = g.v_mul(&h_old, &not(&oh_cn));
    let h_old_a = g.v_num(&h_old_eff);
    let r_old = g.path_root(&h_old_a, &ibits, &sibs);
    g.v_zero_prod(&not(&oh_none), &sub(&vfrom(&r_old), &zv.root));
    // non-membership: spend before window and the low leaf of a create
    let nm_sel = add(&oh_sp, &oh_cl);
    let lt1 = g.lt_bit(&leaf_a[0], &key_a);
    let lt1v = g.v_bit_of(&lt1);
    g.v_zero_prod(&nm_sel, &not(&lt1v));
    let lt2 = g.lt_bit(&key_a, &leaf_a[1]);
    let lt2v = g.v_bit_of(&lt2);
    let inf = g.v_iszero(&leaf[1]);
    let t_nm = g.v_mul(&not(&inf), &not(&lt2v));
    g.v_zero_prod(&nm_sel, &t_nm);
    // spend in window: the leaf is the unspent leaf of the key
    g.v_zero_prod(&oh_si, &sub(&leaf[0], &key));
    g.v_zero_prod(&oh_si, &leaf[5]);
    // create new: the slot is the next leaf
    g.v_zero_prod(&oh_cn, &sub(&idx_num, &zv.leaf_count));
    // the new leaf
    let nk = add(&leaf[1], &g.v_mul(&oh_cl, &sub(&key, &leaf[1])));
    let ni = add(&leaf[2], &g.v_mul(&oh_cl, &sub(&zv.leaf_count, &leaf[2])));
    let sp = add(&leaf[5], &g.v_mul(&oh_si, &sub(&one, &leaf[5])));
    let h_mod = g.v_hash(&[leaf[0].clone(), nk, ni, leaf[3].clone(), leaf[4].clone(), sp]);
    let pend_hash = g.v_hash(&[key.clone(), leaf[1].clone(), leaf[2].clone(), ev[1].clone(), ev[2].clone(), zero.clone()]);
    let h_new = add(&h_mod, &g.v_mul(&oh_cn, &sub(&zv.pend, &h_mod)));
    let h_new_a = g.v_num(&h_new);
    let r_new = vfrom(&g.path_root(&h_new_a, &ibits, &sibs));
    let root_next = add(&r_new, &g.v_mul(&oh_none, &sub(&zv.root, &r_new)));
    let pend_next = add(&zv.pend, &g.v_mul(&oh_cl, &sub(&pend_hash, &zv.pend)));
    let pending_next = sub(&add(&zv.pending, &oh_cl), &oh_cn);
    let leaf_count_next = add(&zv.leaf_count, &oh_cn);
    // the op's event
    let tag = add(&add(&oh_si, &oh_sp), &scale(&oh_cl, fu(2)));
    let op_ev = [tag, ev[0].clone(), ev[1].clone(), ev[2].clone()];
    let fc2 = fold_gated(g, &fc1, &pw, &op_ev, &ev_op);
    let hg = g.v_hash(&[gc1.clone(), op_ev[0].clone(), op_ev[1].clone(), op_ev[2].clone(), op_ev[3].clone()]);
    let gc2 = add(&gc1, &g.v_mul(&ev_op, &sub(&hg, &gc1)));

    // =============================== HDR3: synchronisation and seal ===============================
    g.v_zero_prod(&s_h3, &sub(&fc2, &fp_txid));
    g.v_zero_prod(&s_h3, &open_after);
    g.v_zero_prod(&s_h3, &pending_next);
    let k1 = g.v_k(fu(1));
    let k2 = g.v_k(fu(2));
    let hs = g.v_hash(&[k1, zv.h0[0].clone(), zv.h0[1].clone(), prev_next[0].clone(), prev_next[1].clone()]);
    let hr = g.v_hash(&[k2, zv.r_s.clone(), gc2.clone()]);
    g.v_zero_prod(&sh3e, &sub(&zv.r_s, &hs));
    g.v_zero_prod(&sh3e, &sub(&zv.r, &hr));
    let sealed_next = add(&zv.sealed, &sh3e);

    // =============================== outputs ===============================
    let mut out: Vec<V> = vec![];
    out.push(phase_next);
    out.push(fresh_next);
    out.extend(sha_next);
    out.extend(prev_next);
    out.push(height_next);
    out.push(n_next);
    for k in 0..NF {
      out.extend(new_slot[k].iter().cloned());
    }
    out.extend(carry_next);
    out.push(mlevel_next);
    out.push(lastf_eff);
    out.extend(par_out);
    out.push(fp_txid);
    out.push(root_next);
    out.push(leaf_count_next);
    out.push(fc2);
    out.push(gc2);
    out.push(open_after);
    out.extend(tx_next);
    out.push(pending_next);
    out.push(pend_next);
    out.push(zv.h0[0].clone());
    out.push(zv.h0[1].clone());
    out.push(zv.r_s.clone());
    out.push(zv.r.clone());
    out.push(sealed_next);
    assert_eq!(out.len(), NZ);
    let res: Vec<AllocatedNum<F>> = out.iter().map(|x| g.v_num(x)).collect();
    Ok(res)
  }
}

/// Constraints of one step (the blank witness).
pub fn step_constraints() -> usize {
  use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
  let mut cs = TestConstraintSystem::<F>::new();
  let z: Vec<AllocatedNum<F>> = (0..NZ).map(|i| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || F::ZERO)).collect();
  M18Step::blank().synthesize(&mut cs, &z).unwrap();
  cs.num_constraints()
}

#[cfg(test)]
pub mod tests {
  use super::*;
  use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
  use std::collections::HashSet;

  /// Synthesizes one step on TestConstraintSystem: (constraints, satisfied, outputs).
  pub fn synth_step(s: &State, w: &StepWitness) -> (usize, bool, Vec<F>) {
    let mut cs = TestConstraintSystem::<F>::new();
    let z: Vec<AllocatedNum<F>> =
      s.to_vec().iter().enumerate().map(|(i, v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || *v)).collect();
    let out = M18Step { w: w.clone() }.synthesize(&mut cs, &z).unwrap();
    let got: Vec<F> = out.iter().map(|o| o.get_value().unwrap()).collect();
    let ok = cs.is_satisfied();
    if !ok {
      eprintln!("unsatisfied: {:?}", cs.which_is_unsatisfied());
    }
    (cs.num_constraints(), ok, got)
  }

  fn parser_mask(s: &State, w: &StepWitness) -> u32 {
    if s.phase != phase::BODY || w.idle {
      return 0;
    }
    let mut p = s.par.clone();
    let mut m = 0u32;
    for i in 0..64 {
      m |= 1 << p.ps;
      if par_byte(&mut p, w.block[i], i, s.r_s).is_err() {
        break;
      }
    }
    if p.ps == pst::DONE {
      m |= 1 << pst::DONE;
    }
    m
  }

  type Key = (u64, u8, bool, bool, bool, bool, bool, bool, u32);

  /// One step per distinct (phase, op, close, open, idle, end, last, occupied level, new parser
  /// states): every phase, every op kind and every parser state appears.
  pub fn sample_steps() -> Vec<(State, StepWitness, State)> {
    let mut seen: HashSet<Key> = HashSet::new();
    let mut picked: Vec<(State, StepWitness, State)> = vec![];
    let mut cover_states = 0u32;
    let mut add_from = |raws: &[Vec<u8>], prev: [u8; 32], h0: u64| {
      run_window(raws, prev, h0, &mut |_, s, w, n| {
        let mask = parser_mask(s, w);
        let occ = matches!(s.phase, phase::TXID | phase::MERGE3) && {
          let level = if s.phase == phase::TXID { 0 } else { s.mlevel + 1 };
          level < 16 && (s.n >> level) & 1 == 1
        };
        let new_states = mask & !cover_states;
        cover_states |= mask;
        let key: Key = (s.phase, w.op, w.close, w.open, w.idle, w.end, w.last, occ, new_states);
        if seen.insert(key) && picked.len() < 160 {
          picked.push((s.clone(), w.clone(), n.clone()));
        }
        Ok(())
      })
      .unwrap();
    };
    let (raws, prev) = synth::coverage_window();
    add_from(&raws, prev, 700);
    if let Some((raws, prev)) = early_blocks() {
      add_from(&raws, prev, 170);
    }
    picked
  }

  /// Mainnet blocks 170 and 171 and the hash of block 169, when present (`M18_EARLY`, default
  /// /root/m18-data/early with 170.raw, 171.raw and 169.hash).
  pub fn early_blocks() -> Option<(Vec<Vec<u8>>, [u8; 32])> {
    let dir = std::env::var("M18_EARLY").unwrap_or_else(|_| "/root/m18-data/early".into());
    let r169 = std::fs::read_to_string(format!("{dir}/169.hash")).ok()?;
    let mut prev = hex::decode(r169.trim()).ok()?;
    prev.reverse();
    let b170 = std::fs::read(format!("{dir}/170.raw")).ok()?;
    let b171 = std::fs::read(format!("{dir}/171.raw")).ok()?;
    Some((vec![b170, b171], prev.try_into().ok()?))
  }

  #[test]
  fn circuit_matches_native_on_every_phase_op_and_parser_state() {
    let steps = sample_steps();
    let mut phases = HashSet::new();
    let mut ops = HashSet::new();
    let mut pstates = 0u32;
    let mut n_cons = 0;
    for (s, w, n) in &steps {
      let (c, ok, got) = synth_step(s, w);
      n_cons = c;
      let want = n.to_vec();
      let bad: Vec<usize> = (0..NZ).filter(|&i| got[i] != want[i]).collect();
      assert!(ok, "step in phase {} op {} is unsatisfied", s.phase, w.op);
      assert!(bad.is_empty(), "outputs differ from the native next state at {bad:?} (phase {}, op {})", s.phase, w.op);
      if !w.idle {
        phases.insert(s.phase);
      }
      ops.insert(w.op);
      pstates |= parser_mask(s, w);
    }
    eprintln!("{} sampled steps, {n_cons} constraints per step", steps.len());
    assert_eq!(phases.len(), 8, "phases covered: {phases:?}");
    assert_eq!(ops.len(), opk::COUNT);
    assert_eq!(pstates.count_ones() as usize, pst::COUNT, "parser states covered: {pstates:b}");
  }

  #[test]
  fn mutated_witnesses_are_unsatisfiable() {
    let steps = sample_steps();
    let mut tried = 0;
    let mut done: HashSet<String> = HashSet::new();
    for (s, w, _) in &steps {
      let mut muts: Vec<(String, StepWitness)> = vec![];
      let tag = |k: &str| format!("{}-{}-{}", s.phase, w.op, k);
      if !w.idle {
        match s.phase {
          phase::TXID | phase::MERGE1 | phase::MERGE2 | phase::MERGE3 | phase::HDR2 | phase::HDR3 => {
            let mut m = w.clone();
            m.block[3] ^= 0x10;
            muts.push((tag("block"), m));
          }
          phase::HDR1 => {
            let mut m = w.clone();
            m.block[10] ^= 0x01; // previous-hash byte
            muts.push((tag("prev"), m));
            let mut m = w.clone();
            m.block[40] ^= 0x01; // Merkle-root byte
            muts.push((tag("root"), m));
          }
          phase::BODY => {
            // a bit of the last byte: padding or the bit length, or transaction data
            if s.par.ps >= pst::PAD80 {
              let mut m = w.clone();
              m.block[63] ^= 0x01;
              muts.push((tag("tail"), m));
            }
          }
          _ => {}
        }
        if s.phase == phase::HDR3 && !w.end {
          let mut m = w.clone();
          m.end = true;
          muts.push((tag("early-end"), m));
        }
      }
      if w.op != opk::NONE {
        let mut m = w.clone();
        m.sibs[3] += F::ONE;
        muts.push((tag("sibling"), m));
        if w.op != opk::CREATE_NEW {
          let mut m = w.clone();
          m.leaf[3] += F::ONE;
          muts.push((tag("leaf"), m));
          let mut m = w.clone();
          m.op = match w.op {
            opk::SPEND_IN => opk::SPEND_PRE,
            opk::SPEND_PRE => opk::SPEND_IN,
            _ => opk::SPEND_IN,
          };
          muts.push((tag("op"), m));
        }
        if w.op == opk::SPEND_IN {
          let mut m = w.clone();
          m.ev[0] += F::ONE;
          muts.push((tag("event"), m));
        }
      }
      for (name, m) in muts {
        if !done.insert(name.clone()) {
          continue;
        }
        assert!(step(s, &m).is_err(), "native step accepts mutation {name}");
        let (_, ok, _) = synth_step(s, &m);
        assert!(!ok, "mutation {name} is satisfiable");
        tried += 1;
      }
    }
    eprintln!("{tried} mutations, all refused by the native step and unsatisfiable");
    assert!(tried >= 12);
  }

  #[test]
  fn constraints_per_step() {
    let n = step_constraints();
    eprintln!("constraints per step: {n}");
    assert!(n > 50_000);
  }
}
