//! The step circuit: one dispatch code of the step machine per Nova step.
//!
//! The state vector (engine::z) commits to the remaining program, the three stacks, the saved
//! stack, the condition stack, the counters and the claim accumulator. A step opens the current
//! instruction, decodes its dispatch code one-hot, and applies the control row: pops (each a
//! Poseidon preimage check), the functional units (numeric decoders, comparators, number encoder,
//! castbool, equality), pushes, register updates, and at most one claim.

use crate::compile::Program;
use crate::elem::{constants, fu, pow2, F};
use crate::engine::{self, z, Ctx, Machine, State, Wit, ARITY};
use crate::isa::{self, ctrl, dispatch_codes, Bool, CSrc, ClaimMode, Cnt, Cond, Ctrl, Enc, Hold, Hold2, Pseudo, Rc, Src};
use crate::{run_case, Case, Verdict};
use ff::{Field, PrimeFieldBits};
use nova_snark::frontend::gadgets::poseidon::{Elt, IOPattern, Simplex, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait};
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use nova_snark::traits::circuit::StepCircuit;
use std::time::Instant;

fn one() -> Variable {
  Variable::new_unchecked(Index::Input(0))
}

/// A linear combination with its value (zero when synthesizing the shape).
#[derive(Clone)]
pub struct V {
  lc: LinearCombination<F>,
  val: F,
}

impl V {
  fn c(x: F) -> V {
    V { lc: LinearCombination::zero() + (x, one()), val: x }
  }
  fn cu(x: u64) -> V {
    V::c(fu(x))
  }
  fn zero() -> V {
    V { lc: LinearCombination::zero(), val: F::ZERO }
  }
  fn var(n: &AllocatedNum<F>) -> V {
    V { lc: LinearCombination::zero() + n.get_variable(), val: n.get_value().unwrap_or(F::ZERO) }
  }
  fn add(&self, o: &V) -> V {
    V { lc: self.lc.clone() + &o.lc, val: self.val + o.val }
  }
  fn sub(&self, o: &V) -> V {
    V { lc: self.lc.clone() - &o.lc, val: self.val - o.val }
  }
  fn scale(&self, k: F) -> V {
    let mut lc = LinearCombination::zero();
    for (v, c) in self.lc.iter() {
      lc = lc + (*c * k, v);
    }
    V { lc, val: self.val * k }
  }
  fn addc(&self, k: F) -> V {
    self.add(&V::c(k))
  }
  fn neg(&self) -> V {
    self.scale(-F::ONE)
  }
}

fn sum(vs: impl IntoIterator<Item = V>) -> V {
  vs.into_iter().fold(V::zero(), |a, b| a.add(&b))
}

fn bits_of(x: &F, n: usize) -> Vec<bool> {
  x.to_le_bits().iter().take(n).map(|b| *b).collect()
}

/// Constraint-system wrapper with unique gadget names.
struct Cx<'a, CS: ConstraintSystem<F>> {
  cs: &'a mut CS,
  n: usize,
}

impl<'a, CS: ConstraintSystem<F>> Cx<'a, CS> {
  fn name(&mut self) -> String {
    self.n += 1;
    format!("g{}", self.n)
  }
  fn alloc(&mut self, val: F) -> V {
    let nm = self.name();
    let a = AllocatedNum::alloc_infallible(self.cs.namespace(|| nm), || val);
    V { lc: LinearCombination::zero() + a.get_variable(), val }
  }
  fn alloc_num(&mut self, val: F) -> AllocatedNum<F> {
    let nm = self.name();
    AllocatedNum::alloc_infallible(self.cs.namespace(|| nm), || val)
  }
  /// a * b = c
  fn enforce(&mut self, a: &V, b: &V, c: &V) {
    let nm = self.name();
    self.cs.enforce(|| nm, |l| l + &a.lc, |l| l + &b.lc, |l| l + &c.lc);
  }
  fn zero(&mut self, a: &V) {
    self.enforce(a, &V::cu(1), &V::zero());
  }
  fn eq(&mut self, a: &V, b: &V) {
    self.zero(&a.sub(b));
  }
  fn mul(&mut self, a: &V, b: &V) -> V {
    let c = self.alloc(a.val * b.val);
    self.enforce(a, b, &c);
    c
  }
  /// a * b = 0
  fn prod_zero(&mut self, a: &V, b: &V) {
    self.enforce(a, b, &V::zero());
  }
  fn bit(&mut self, b: bool) -> V {
    let v = self.alloc(if b { F::ONE } else { F::ZERO });
    self.prod_zero(&v, &V::cu(1).sub(&v));
    v
  }
  /// Little-endian bits of x (as an integer below 2^n), constrained to recompose to x.
  fn bits(&mut self, x: &V, n: usize) -> Vec<V> {
    let bs = bits_of(&x.val, n);
    let vs: Vec<V> = bs.iter().map(|&b| self.bit(b)).collect();
    let mut acc = V::zero();
    for (i, b) in vs.iter().enumerate() {
      acc = acc.add(&b.scale(pow2(i as u32)));
    }
    self.eq(&acc, x);
    vs
  }
  /// 1 if x = 0 else 0.
  fn is_zero(&mut self, x: &V) -> V {
    let inv = x.val.invert().unwrap_or(F::ZERO);
    let z = if x.val == F::ZERO { F::ONE } else { F::ZERO };
    let iv = self.alloc(inv);
    let zv = self.alloc(z);
    self.enforce(x, &iv, &V::cu(1).sub(&zv));
    self.prod_zero(x, &zv);
    zv
  }
  /// a + c * (b - a): b when c = 1, a when c = 0.
  fn sel(&mut self, c: &V, a: &V, b: &V) -> V {
    let d = self.mul(c, &b.sub(a));
    a.add(&d)
  }
  /// Poseidon over xs, as elem::hash.
  fn hash(&mut self, xs: &[V]) -> V {
    let nums: Vec<AllocatedNum<F>> = xs
      .iter()
      .map(|x| {
        let a = self.alloc_num(x.val);
        let v = V::var(&a);
        self.eq(&v, x);
        a
      })
      .collect();
    let nm = self.name();
    let mut ns = self.cs.namespace(|| nm);
    let mut sponge = SpongeCircuit::new_with_constants(constants(), Simplex);
    sponge.start(IOPattern(vec![SpongeOp::Absorb(nums.len() as u32), SpongeOp::Squeeze(1)]), None, &mut ns);
    let elts: Vec<Elt<F>> = nums.into_iter().map(Elt::Allocated).collect();
    SpongeAPI::absorb(&mut sponge, elts.len() as u32, &elts, &mut ns);
    let out = SpongeAPI::squeeze(&mut sponge, 1, &mut ns);
    sponge.finish(&mut ns).unwrap();
    let a = Elt::ensure_allocated(&out[0], &mut ns.namespace(|| "out")).unwrap();
    V::var(&a)
  }
}

/// One step of the machine. `w` is the witness (default for the shape).
#[derive(Clone, Default)]
pub struct ScriptStep {
  pub w: Wit,
}

struct Num {
  val: V,
  mag: V,
}

/// CScriptNum decode of x (at most 4 bytes; x = 0 decodes to 0). Returns the value and whether
/// the encoding is non-minimal.
fn decode<CS: ConstraintSystem<F>>(cx: &mut Cx<CS>, x: &V) -> (Num, V) {
  let b = cx.bits(x, 40);
  let lval = sum((0..8).map(|t| b[t].scale(pow2(t as u32))));
  let lv = crate::elem::f_to_u64(&lval.val).unwrap_or(0);
  let l: Vec<V> = (0..5).map(|k| cx.bit(lv == k)).collect();
  cx.eq(&sum(l.iter().cloned()), &V::cu(1));
  cx.eq(&sum(l.iter().enumerate().map(|(k, v)| v.scale(fu(k as u64)))), &lval);
  let byte = |i: usize| sum((0..8).map(|t| b[8 * (i + 1) + t].scale(pow2(t as u32))));
  // bytes at index >= L are zero
  for i in 0..4 {
    let le = sum((0..=i).map(|k| l[k].clone()));
    cx.prod_zero(&byte(i), &le);
  }
  // sign: bit 7 of byte L-1
  let signs: Vec<V> = (1..5).map(|k| cx.mul(&l[k], &b[8 * k + 7])).collect();
  let sign = sum(signs.iter().cloned());
  let data = sum((0..4).map(|i| byte(i).scale(pow2(8 * i as u32))));
  let topw = sum((1..5).map(|k| l[k].scale(fu(128) * pow2(8 * (k as u32 - 1)))));
  let st = cx.mul(&sign, &topw);
  let mag = data.sub(&st);
  let sm = cx.mul(&sign, &mag);
  let val = mag.sub(&sm.scale(fu(2)));
  // minimal: L = 0, or the top byte's low 7 bits are nonzero, or bit 7 of the byte below is set
  let tops: Vec<V> = (1..5).map(|k| cx.mul(&l[k], &byte(k - 1))).collect();
  let top = sum(tops.iter().cloned());
  let low7 = top.sub(&sign.scale(fu(128)));
  let low7z = cx.is_zero(&low7);
  let below: Vec<V> = (2..5).map(|k| cx.mul(&l[k], &b[8 * (k - 1) + 7])).collect();
  let below7 = sum(below.iter().cloned());
  let a = cx.mul(&V::cu(1).sub(&l[0]), &low7z);
  let nonmin = cx.mul(&a, &V::cu(1).sub(&below7));
  (Num { val, mag }, nonmin)
}

/// lt(a, b) = [a < b] for |a|, |b| < 2^31.
fn lt<CS: ConstraintSystem<F>>(cx: &mut Cx<CS>, a: &V, b: &V) -> V {
  let d = b.sub(a).addc(pow2(32) - F::ONE);
  let bs = cx.bits(&d, 33);
  bs[32].clone()
}

/// Minimal CScriptNum encoding of v (|v| < 2^32) as a stack element.
fn encode<CS: ConstraintSystem<F>>(cx: &mut Cx<CS>, v: &V) -> V {
  let neg = v.val != F::ZERO && crate::elem::f_to_u64(&v.val).is_none();
  let m = if neg { -v.val } else { v.val };
  let s = cx.bit(neg);
  let mv = cx.alloc(m);
  let sm = cx.mul(&s, &mv);
  cx.eq(v, &mv.sub(&sm.scale(fu(2))));
  let mb = cx.bits(&mv, 32);
  let byte = |i: usize| sum((0..8).map(|t| mb[8 * i + t].scale(pow2(t as u32))));
  let mu = crate::elem::f_to_u64(&m).unwrap_or(0);
  let nb = (0..5).find(|&k| mu >> (8 * k) == 0).unwrap_or(4) as u64;
  let q: Vec<V> = (0..5).map(|k| cx.bit(nb == k)).collect();
  cx.eq(&sum(q.iter().cloned()), &V::cu(1));
  for i in 0..4 {
    let le = sum((0..=i).map(|k| q[k].clone()));
    cx.prod_zero(&byte(i), &le);
  }
  for k in 1..5 {
    let bt = byte(k - 1);
    let inv = cx.alloc(bt.val.invert().unwrap_or(F::ZERO));
    let p = cx.mul(&bt, &inv);
    cx.prod_zero(&q[k], &V::cu(1).sub(&p));
  }
  cx.prod_zero(&s, &q[0]);
  let tbs: Vec<V> = (1..5).map(|k| cx.mul(&q[k], &mb[8 * (k - 1) + 7])).collect();
  let tb = sum(tbs.iter().cloned());
  let nbv = sum(q.iter().enumerate().map(|(k, x)| x.scale(fu(k as u64))));
  let lout = nbv.add(&tb);
  let pos0 = sum(q.iter().enumerate().map(|(k, x)| x.scale(pow2(8 * k as u32 + 7))));
  let pos = cx.mul(&pos0, &V::cu(1).add(&tb.scale(fu(255))));
  let sp = cx.mul(&s, &pos);
  let data = sum((0..4).map(|i| byte(i).scale(pow2(8 * (i as u32 + 1)))));
  lout.add(&data).add(&sp)
}

impl StepCircuit<F> for ScriptStep {
  fn arity(&self) -> usize {
    ARITY
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    zin: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut cx = Cx { cs, n: 0 };
    let w = &self.w;
    let zv: Vec<V> = zin.iter().map(V::var).collect();
    let g = |i: usize| zv[i].clone();

    // Instruction opening.
    let iop_v = cx.alloc(fu(w.iop));
    let data = cx.alloc(w.data);
    let auxv = cx.alloc(fu(w.aux));
    let next = cx.alloc(w.next);
    let hi = cx.hash(&[iop_v.clone(), data.clone(), auxv.clone(), next.clone()]);
    cx.eq(&hi, &g(z::P));
    let a0 = cx.bit(w.aux & 1 != 0);
    let a1 = cx.bit(w.aux & 2 != 0);
    let arest = cx.alloc(fu(w.aux >> 2));
    cx.eq(&auxv, &a0.add(&a1.scale(fu(2))).add(&arest.scale(fu(4))));

    // Dispatch code and its one-hot row selector.
    let pz = cx.is_zero(&g(z::PH));
    let cz = cx.is_zero(&g(z::CNT));
    let alt_dc = g(z::PH).add(&cz);
    let dc = cx.sel(&pz, &alt_dc, &iop_v);
    let codes = dispatch_codes();
    let dcu = crate::elem::f_to_u64(&dc.val).unwrap_or(u64::MAX);
    let o: Vec<V> = codes.iter().map(|&c| cx.bit(c == dcu)).collect();
    cx.eq(&sum(o.iter().cloned()), &V::cu(1));
    cx.eq(&sum(o.iter().zip(&codes).map(|(x, &c)| x.scale(fu(c)))), &dc);
    let rows: Vec<Ctrl> = codes.iter().map(|&c| ctrl(c).unwrap()).collect();
    let exv = g(z::FF).addc(-fu(isa::NO_FALSE));
    let ex = cx.is_zero(&exv);
    let eff: Vec<V> = o.iter().zip(&rows).map(|(x, r)| if r.gated { cx.mul(x, &ex) } else { x.clone() }).collect();
    // L: effective (gated) signal; R: raw row signal.
    let lsig = |f: &dyn Fn(&Ctrl) -> u64| -> V {
      sum(eff.iter().zip(&rows).filter_map(|(e, r)| {
        let k = f(r);
        (k != 0).then(|| e.scale(fu(k)))
      }))
    };
    let rsig = |f: &dyn Fn(&Ctrl) -> u64| -> V {
      sum(o.iter().zip(&rows).filter_map(|(e, r)| {
        let k = f(r);
        (k != 0).then(|| e.scale(fu(k)))
      }))
    };
    let lb = |f: &dyn Fn(&Ctrl) -> bool| lsig(&|r| f(r) as u64);
    let rb = |f: &dyn Fn(&Ctrl) -> bool| rsig(&|r| f(r) as u64);

    // Pops.
    let p: Vec<V> = (0..6).map(|j| cx.alloc(w.p[j])).collect();
    let s: Vec<V> = (0..6).map(|j| cx.alloc(w.s[j])).collect();
    let mut prev = g(z::S);
    let mut kk = V::zero();
    for j in 0..6 {
      let popj = lb(&|r| r.k as usize > j);
      kk = kk.add(&popj);
      let h = cx.hash(&[s[j].clone(), p[j].clone()]);
      cx.prod_zero(&popj, &prev.sub(&h));
      cx.prod_zero(&V::cu(1).sub(&popj), &s[j].sub(&prev));
      prev = s[j].clone();
    }
    let base = prev;

    // Numeric operands.
    let mut nums = vec![];
    let mut nonmin_any = V::zero();
    for j in 0..3 {
      let used = lb(&|r| r.nnum as usize > j);
      let x = cx.mul(&used, &p[j]);
      let (n, nonmin) = decode(&mut cx, &x);
      nonmin_any = nonmin_any.add(&nonmin);
      nums.push(n);
    }
    // a1 (require minimal) applies to every decoded operand; unused operands decode 0, which is
    // minimal.
    cx.prod_zero(&a1, &nonmin_any);
    let (n1, n2, n3) = (nums[0].val.clone(), nums[1].val.clone(), nums[2].val.clone());
    let z1 = cx.is_zero(&n1);
    let z2 = cx.is_zero(&n2);
    let c21 = lt(&mut cx, &n2, &n1);
    let c12 = lt(&mut cx, &n1, &n2);
    let c32 = lt(&mut cx, &n3, &n2);
    let c31 = lt(&mut cx, &n3, &n1);

    // Bits of p1: long flag, length, castbool.
    let ub = lb(&|r| r.bits);
    let xb = cx.mul(&ub, &p[0]);
    let bb = cx.bits(&xb, 250);
    cx.zero(&bb[248]);
    let lf = bb[249].clone();
    let lbv = sum((0..8).map(|t| bb[t].scale(pow2(t as u32))));
    let lbu = if lf.val == F::ZERO { crate::elem::f_to_u64(&lbv.val).unwrap_or(0) } else { 99 };
    let lh: Vec<V> = (0..31).map(|k| cx.bit(lbu == k)).collect();
    cx.eq(&sum(lh.iter().cloned()), &V::cu(1).sub(&lf));
    let lsum = sum(lh.iter().enumerate().map(|(k, x)| x.scale(fu(k as u64))));
    let lsr = cx.mul(&lbv, &V::cu(1).sub(&lf));
    cx.eq(&lsum, &lsr);
    let tops: Vec<V> = (1..31).map(|k| cx.mul(&lh[k], &bb[8 * k + 7])).collect();
    let masked = xb.sub(&lbv).sub(&sum(tops.iter().enumerate().map(|(i, t)| t.scale(pow2(8 * (i as u32 + 1) + 7)))));
    let mz = cx.is_zero(&masked);
    let cb_short = V::cu(1).sub(&mz);
    let wv = cx.alloc(w.w);
    let cb = cx.sel(&lf, &cb_short, &wv);
    let lsz = cx.sel(&lf, &lbv, &wv);
    let w2 = cx.mul(&wv, &wv);
    let cbrows = lb(&|r| r.bool_ == Bool::Cb);
    let cbl = cx.mul(&cbrows, &lf);
    let need_wbool = cbl.add(&lb(&|r| r.w_bool));
    cx.prod_zero(&need_wbool, &wv.sub(&w2));

    // IF_MIN condition bit.
    let bmin = cx.bit(w.p[0] == fu(257));
    let rmin = lb(&|r| matches!(r.cond, Cond::IfMin | Cond::NotIfMin));
    cx.prod_zero(&rmin, &p[0].sub(&bmin.scale(fu(257))));

    // Booleans.
    let eq12 = cx.is_zero(&p[1].sub(&p[0]));
    let numeq = cx.is_zero(&n2.sub(&n1));
    let band = cx.mul(&V::cu(1).sub(&z2), &V::cu(1).sub(&z1));
    let z12 = cx.mul(&z1, &z2);
    let within = cx.mul(&V::cu(1).sub(&c32), &c31);
    let bcand = |b: Bool| -> V {
      match b {
        Bool::Not => z1.clone(),
        Bool::Nz => V::cu(1).sub(&z1),
        Bool::BAnd => band.clone(),
        Bool::BOr => V::cu(1).sub(&z12),
        Bool::NumEq => numeq.clone(),
        Bool::NumNe => V::cu(1).sub(&numeq),
        Bool::Lt => c21.clone(),
        Bool::Gt => c12.clone(),
        Bool::Le => V::cu(1).sub(&c12),
        Bool::Ge => V::cu(1).sub(&c21),
        Bool::Within => within.clone(),
        Bool::Equal => eq12.clone(),
        Bool::Cb => cb.clone(),
        Bool::W => wv.clone(),
        Bool::None => V::zero(),
      }
    };
    let mut bsel = V::zero();
    for b in isa::BOOLS {
      let wt = lb(&|r| r.bool_ == b);
      let c = bcand(b);
      let t = cx.mul(&wt, &c);
      bsel = bsel.add(&t);
    }
    let vrf = lb(&|r| r.verify);
    cx.prod_zero(&vrf, &V::cu(1).sub(&bsel));
    let bout = bsel.scale(fu(257));

    // Number encoder.
    let minv = cx.sel(&c21, &n1, &n2);
    let maxv = cx.sel(&c12, &n1, &n2);
    let ecand = |e: Enc| -> V {
      match e {
        Enc::Inc => n1.addc(F::ONE),
        Enc::Dec => n1.addc(-F::ONE),
        Enc::Neg => n1.neg(),
        Enc::Abs => nums[0].mag.clone(),
        Enc::Add => n2.add(&n1),
        Enc::Sub => n2.sub(&n1),
        Enc::Min => minv.clone(),
        Enc::Max => maxv.clone(),
        Enc::Depth => g(z::D),
        Enc::Size => lsz.clone(),
        Enc::None => V::zero(),
      }
    };
    let mut ev = V::zero();
    for e in isa::ENCS {
      let wt = lb(&|r| r.enc == e);
      let c = ecand(e);
      let t = cx.mul(&wt, &c);
      ev = ev.add(&t);
    }
    let nout = encode(&mut cx, &ev);

    // Alt stack (one shared hash: pop check or push).
    let a = cx.alloc(w.a);
    let a1w = cx.alloc(w.a1);
    let apop = lb(&|r| r.alt_pop);
    let apush = lb(&|r| r.alt_push);
    let ax = cx.sel(&apop, &g(z::A), &a1w);
    let ay = cx.sel(&apop, &p[0], &a);
    let ah = cx.hash(&[ax, ay]);
    cx.prod_zero(&apop, &ah.sub(&g(z::A)));
    let rbe = rb(&|r| matches!(r.pseudo, Pseudo::Begin | Pseudo::End));
    let a_pre = {
      let t1 = cx.mul(&apop, &a1w.sub(&g(z::A)));
      let t2 = cx.mul(&apush, &ah.sub(&g(z::A)));
      g(z::A).add(&t1).add(&t2)
    };
    let a_new = cx.mul(&a_pre, &V::cu(1).sub(&rbe));
    let ad_new = cx.mul(&g(z::AD).sub(&apop).add(&apush), &V::cu(1).sub(&rbe));

    // Temporary stack.
    let t = cx.alloc(w.t);
    let t1w = cx.alloc(w.t1);
    let tpop = lb(&|r| r.tmp_pop);
    let tpush = lb(&|r| r.tmp_push);
    let tx = cx.sel(&tpop, &g(z::T), &t1w);
    let ty = cx.sel(&tpop, &p[0], &t);
    let th = cx.hash(&[tx, ty]);
    cx.prod_zero(&tpop, &th.sub(&g(z::T)));
    let t_new = {
      let t1 = cx.mul(&tpop, &t1w.sub(&g(z::T)));
      let t2 = cx.mul(&tpush, &th.sub(&g(z::T)));
      g(z::T).add(&t1).add(&t2)
    };
    let td_new = g(z::TD).sub(&tpop).add(&tpush);

    // Pushes.
    let ifd = {
      let r = lb(&|r| r.ifdup);
      cx.mul(&r, &cb)
    };
    let cand = |src: Src| -> V {
      match src {
        Src::P1 => p[0].clone(),
        Src::P2 => p[1].clone(),
        Src::P3 => p[2].clone(),
        Src::P4 => p[3].clone(),
        Src::P5 => p[4].clone(),
        Src::P6 => p[5].clone(),
        Src::D => data.clone(),
        Src::N => nout.clone(),
        Src::B => bout.clone(),
        Src::W => wv.clone(),
        Src::A => a.clone(),
        Src::T => t.clone(),
        Src::H => g(z::HOLD),
      }
    };
    let mut u = base;
    let mut mm = V::zero();
    for j in 0..6 {
      let mut pe = lb(&|r| r.m as usize > j);
      if j == 1 {
        pe = pe.add(&ifd);
      }
      mm = mm.add(&pe);
      let mut oj = V::zero();
      for src in isa::SRCS {
        let mut wt = lb(&|r| r.m as usize > j && r.out[j] == src);
        if j == 1 && src == Src::P1 {
          wt = wt.add(&ifd);
        }
        if wt.lc.iter().next().is_none() {
          continue;
        }
        let c = cand(src);
        let tt = cx.mul(&wt, &c);
        oj = oj.add(&tt);
      }
      let h = cx.hash(&[u.clone(), oj]);
      u = cx.sel(&pe, &u, &h);
    }
    let rrestore = rb(&|r| r.pseudo == Pseudo::Restore);
    let rreset = rb(&|r| r.pseudo == Pseudo::Reset);
    let rsetd1 = rb(&|r| r.pseudo == Pseudo::SetD1);
    let rsave = rb(&|r| r.pseudo == Pseudo::Save);
    let s1 = cx.sel(&rrestore, &u, &g(z::SV));
    let s_new = cx.sel(&rreset, &s1, &V::zero());
    let dpre = g(z::D).sub(&kk).add(&mm);
    let d1 = cx.sel(&rrestore, &dpre, &g(z::SVD));
    let d2 = cx.sel(&rreset, &d1, &V::zero());
    let d_new = cx.sel(&rsetd1, &d2, &V::cu(1));
    let sv_new = cx.sel(&rsave, &g(z::SV), &g(z::S));
    let svd_new = cx.sel(&rsave, &g(z::SVD), &g(z::D));

    // Condition stack.
    let rif = rb(&|r| matches!(r.cond, Cond::If | Cond::NotIf | Cond::IfMin | Cond::NotIfMin));
    let relse = rb(&|r| r.cond == Cond::Else);
    let rendif = rb(&|r| r.cond == Cond::EndIf);
    let fv = {
      let i1 = lb(&|r| r.cond == Cond::If);
      let i2 = lb(&|r| r.cond == Cond::NotIf);
      let i3 = lb(&|r| r.cond == Cond::IfMin);
      let i4 = lb(&|r| r.cond == Cond::NotIfMin);
      let a = cx.mul(&i1, &cb);
      let b = cx.mul(&i2, &V::cu(1).sub(&cb));
      let c = cx.mul(&i3, &bmin);
      let d = cx.mul(&i4, &V::cu(1).sub(&bmin));
      a.add(&b).add(&c).add(&d)
    };
    let cs_ = g(z::CS);
    let ff = g(z::FF);
    let csinv = cx.alloc(cs_.val.invert().unwrap_or(F::ZERO));
    let csx = cx.mul(&cs_, &csinv);
    cx.prod_zero(&relse.add(&rendif), &V::cu(1).sub(&csx));
    let eqtop = cx.is_zero(&ff.sub(&cs_).addc(F::ONE));
    let cif = cx.mul(&ex, &V::cu(1).sub(&fv));
    let ff_if = cx.sel(&cif, &ff, &cs_);
    let inner = cx.sel(&eqtop, &ff, &V::cu(isa::NO_FALSE));
    let ff_else = cx.sel(&ex, &inner, &cs_.addc(-F::ONE));
    let ff_endif = inner.clone();
    let f1 = cx.sel(&rif, &ff, &ff_if);
    let f2 = cx.sel(&relse, &f1, &ff_else);
    let ff_new = cx.sel(&rendif, &f2, &ff_endif);
    let cs_new = cs_.add(&rif).sub(&rendif);
    let rbegin = rb(&|r| r.pseudo == Pseudo::Begin);
    cx.prod_zero(&rbe, &cs_);

    // Registers.
    let h_hold = cx.hash(&[g(z::HOLD), p[0].clone()]);
    let hold_new = {
      let mut v = g(z::HOLD);
      for (h, c) in [(Hold::Zero, V::zero()), (Hold::Hash, h_hold.clone()), (Hold::P1, p[0].clone())] {
        let wt = lb(&|r| r.hold == h);
        let d = cx.mul(&wt, &c.sub(&g(z::HOLD)));
        v = v.add(&d);
      }
      v
    };
    let hold2_new = {
      let mut v = g(z::HOLD2);
      for (h, c) in [(Hold2::Zero, V::zero()), (Hold2::N1, n1.clone()), (Hold2::AddSigs, g(z::HOLD2).add(&n1.scale(fu(256))))] {
        let wt = lb(&|r| r.hold2 == h);
        let d = cx.mul(&wt, &c.sub(&g(z::HOLD2)));
        v = v.add(&d);
      }
      v
    };
    let cnt_new = {
      let mut v = g(z::CNT);
      for (h, c) in [(Cnt::N1, n1.clone()), (Cnt::Dec, g(z::CNT).addc(-F::ONE)), (Cnt::Td, g(z::TD))] {
        let wt = lb(&|r| r.cnt == h);
        let d = cx.mul(&wt, &c.sub(&g(z::CNT)));
        v = v.add(&d);
      }
      v
    };
    let ph_new = lsig(&|r| if r.stay { r.next_phase } else { 0 });
    let stay = lb(&|r| r.stay);
    let adv = V::cu(1).sub(&stay);
    let p_new = cx.sel(&adv, &g(z::P), &next);

    // Range checks.
    let rcv = {
      let r1 = lb(&|r| r.rc == Rc::PickRoll);
      let r2 = lb(&|r| r.rc == Rc::MsKeys);
      let r3 = lb(&|r| r.rc == Rc::MsSigs);
      let x1 = cx.mul(&r1, &g(z::D).addc(-fu(2)).sub(&n1));
      let x2 = cx.mul(&r2, &V::cu(20).sub(&n1));
      let x3 = cx.mul(&r3, &g(z::HOLD2).sub(&n1));
      x1.add(&x2).add(&x3)
    };
    cx.bits(&rcv, 11);
    let nn = lb(&|r| r.nonneg1);
    let nnv = cx.mul(&nn, &n1);
    cx.bits(&nnv, 11);

    // Opcode count, stack size.
    let counted = rb(&|r| r.counted);
    let ocadd = {
      let r = lb(&|r| r.oc_add_n1);
      cx.mul(&r, &n1)
    };
    let oc_pre = g(z::OC).add(&counted).add(&ocadd);
    let oc_new = cx.mul(&oc_pre, &V::cu(1).sub(&rbegin));
    cx.bits(&V::cu(isa::MAX_OPS).sub(&oc_new), 8);
    cx.bits(&V::cu(isa::MAX_STACK).sub(&d_new).sub(&ad_new).sub(&td_new), 10);

    // Failures and pseudo checks.
    cx.zero(&lb(&|r| r.fail));
    let pf = lb(&|r| r.push_fail_aux);
    cx.prod_zero(&pf, &a0);
    cx.prod_zero(&rb(&|r| r.pseudo == Pseudo::Clean1), &g(z::D).addc(-F::ONE));
    cx.prod_zero(&rb(&|r| r.pseudo == Pseudo::PopEq), &p[0].sub(&data));

    // Script id and codeseparator.
    let sid_new = cx.sel(&rbegin, &g(z::SID), &arest);
    let csp1 = cx.sel(&rbegin, &g(z::CSP), &V::zero());
    let csp_new = cx.sel(&lb(&|r| r.codesep), &csp1, &arest);

    // Claim.
    let always = lb(&|r| r.claim == ClaimMode::Always);
    let iflong = lb(&|r| r.claim == ClaimMode::IfLong);
    let il = cx.mul(&iflong, &lf);
    let active = always.add(&il);
    let kindv = lsig(&|r| if r.claim != ClaimMode::None { r.claim_kind } else { 0 });
    let csrc = |c: CSrc| -> V {
      match c {
        CSrc::P1 => p[0].clone(),
        CSrc::P2 => p[1].clone(),
        CSrc::W => wv.clone(),
        CSrc::Hold => g(z::HOLD),
        CSrc::Hold2 => g(z::HOLD2),
        CSrc::Sid => g(z::SID),
        CSrc::Csp => g(z::CSP),
        CSrc::Zero => V::zero(),
      }
    };
    let mut fields = vec![g(z::CL), kindv];
    for i in 0..6 {
      let mut fv = V::zero();
      for c in isa::CSRCS {
        let wt = lb(&|r| r.claim != ClaimMode::None && r.cf[i] == c);
        if wt.lc.iter().next().is_none() {
          continue;
        }
        let x = csrc(c);
        let t = cx.mul(&wt, &x);
        fv = fv.add(&t);
      }
      fields.push(fv);
    }
    let hcl = cx.hash(&fields);
    let cl_new = cx.sel(&active, &g(z::CL), &hcl);

    let mut out = vec![V::zero(); ARITY];
    out[z::P] = p_new;
    out[z::S] = s_new;
    out[z::D] = d_new;
    out[z::A] = a_new;
    out[z::AD] = ad_new;
    out[z::T] = t_new;
    out[z::TD] = td_new;
    out[z::SV] = sv_new;
    out[z::SVD] = svd_new;
    out[z::CS] = cs_new;
    out[z::FF] = ff_new;
    out[z::OC] = oc_new;
    out[z::CL] = cl_new;
    out[z::SID] = sid_new;
    out[z::CSP] = csp_new;
    out[z::PH] = ph_new;
    out[z::CNT] = cnt_new;
    out[z::HOLD] = hold_new;
    out[z::HOLD2] = hold2_new;
    let res = out
      .iter()
      .map(|v| {
        let a = cx.alloc_num(v.val);
        let av = V::var(&a);
        cx.eq(&av, v);
        a
      })
      .collect();
    Ok(res)
  }
}

// ---------------------------------------------------------------- testing and proving

/// A constraint system that checks each constraint as it is enforced, without names: the step
/// circuit's satisfiability test for whole vector suites.
pub struct CheckCS {
  inputs: Vec<F>,
  aux: Vec<F>,
  n: usize,
  first_failure: Option<usize>,
}

impl ConstraintSystem<F> for CheckCS {
  type Root = Self;
  fn new() -> Self {
    CheckCS { inputs: vec![F::ONE], aux: vec![], n: 0, first_failure: None }
  }
  fn alloc<Fn_, A, AR>(&mut self, _a: A, f: Fn_) -> Result<Variable, SynthesisError>
  where
    Fn_: FnOnce() -> Result<F, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    self.aux.push(f()?);
    Ok(Variable::new_unchecked(Index::Aux(self.aux.len() - 1)))
  }
  fn alloc_input<Fn_, A, AR>(&mut self, _a: A, f: Fn_) -> Result<Variable, SynthesisError>
  where
    Fn_: FnOnce() -> Result<F, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    self.inputs.push(f()?);
    Ok(Variable::new_unchecked(Index::Input(self.inputs.len() - 1)))
  }
  fn enforce<A, AR, LA, LB, LC>(&mut self, _a: A, a: LA, b: LB, c: LC)
  where
    A: FnOnce() -> AR,
    AR: Into<String>,
    LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
  {
    let ev = |l: LinearCombination<F>| l.eval(&self.inputs, &self.aux);
    let (x, y, zc) = (ev(a(LinearCombination::zero())), ev(b(LinearCombination::zero())), ev(c(LinearCombination::zero())));
    if x * y != zc && self.first_failure.is_none() {
      self.first_failure = Some(self.n);
    }
    self.n += 1;
  }
  fn push_namespace<NR, N>(&mut self, _n: N)
  where
    NR: Into<String>,
    N: FnOnce() -> NR,
  {
  }
  fn pop_namespace(&mut self) {}
  fn get_root(&mut self) -> &mut Self {
    self
  }
}

/// Runs one step: (satisfied, output state, index of the first failing constraint).
pub fn run_step(zin: &State, w: &Wit) -> (bool, State, Option<String>) {
  let mut cs = CheckCS::new();
  let zs: Vec<AllocatedNum<F>> =
    zin.iter().enumerate().map(|(i, v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || *v)).collect();
  let out = ScriptStep { w: w.clone() }.synthesize(&mut cs, &zs).unwrap();
  let mut zo = [F::ZERO; ARITY];
  for (i, a) in out.iter().enumerate() {
    zo[i] = a.get_value().unwrap();
  }
  let ok = cs.first_failure.is_none();
  (ok, zo, cs.first_failure.map(|i| format!("constraint {i}")))
}

pub fn num_constraints() -> usize {
  let mut cs = CheckCS::new();
  let zs: Vec<AllocatedNum<F>> =
    (0..ARITY).map(|i| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || F::ZERO)).collect();
  ScriptStep::default().synthesize(&mut cs, &zs).unwrap();
  cs.n
}

/// Every step of the valid cases: satisfied, and the circuit's next state equals the engine's.
/// Every invalid case whose failure is a machine step: the failing step's witness is refused.
pub fn check_cases(cases: &[Case], limit: usize) {
  println!("step circuit: {} constraints", num_constraints());
  let t0 = Instant::now();
  let (mut valid, mut steps, mut refused, mut by_claim, mut static_, mut unsupported) = (0, 0, 0, 0, 0, 0);
  let mut bad = vec![];
  for c in cases.iter() {
    if valid + refused + by_claim >= limit {
      break;
    }
    match run_case(c, true) {
      Verdict::Unsupported(_) => unsupported += 1,
      Verdict::Valid(tr, ..) => {
        if !c.expect_valid {
          bad.push(format!("{}: native accepts a Core-invalid case", c.id));
          continue;
        }
        valid += 1;
        let mut zin = tr.z0;
        for (i, (w, zo)) in tr.wits.iter().zip(&tr.zs).enumerate() {
          let (ok, got, why) = run_step(&zin, w);
          steps += 1;
          if !ok || got != *zo {
            bad.push(format!("{} step {i} iop {} sat {ok} same_state {} {:?}", c.id, w.iop, got == *zo, why));
            break;
          }
          zin = *zo;
        }
      }
      Verdict::Invalid(_) => {
        // Re-run to the failing step and feed its witness to the circuit.
        let tx = crate::sigcheck::parse_tx(&hex::decode(&c.tx).unwrap()).unwrap();
        let (amount, spk) = &c.prevouts[c.index];
        let spk = hex::decode(spk).unwrap();
        let prog: Program = match crate::compile::compile(&tx, c.index, &spk, c.flag_bits) {
          Ok(p) => p,
          Err(_) => {
            static_ += 1;
            continue;
          }
        };
        let mut m = Machine::new(&prog, Ctx { tx: &tx, n_in: c.index, amount: *amount, flags: c.flag_bits });
        loop {
          let zin = m.state();
          let mut w = Wit::default();
          match m.step_into(&mut w) {
            Ok(()) => continue,
            Err(e) => {
              if m.claim_failed {
                by_claim += 1;
              } else {
                let (ok, _, _) = run_step(&zin, &w);
                if ok {
                  bad.push(format!("{}: circuit accepts the failing step ({e}, iop {}) | {}", c.id, w.iop, c.description));
                } else {
                  refused += 1;
                }
              }
              break;
            }
          }
        }
      }
    }
  }
  for b in &bad {
    println!("BAD {b}");
  }
  println!(
    "valid cases {valid} ({steps} steps, all satisfied with the engine's next state: {}); invalid: failing step refused {refused}, rejected by a claim check {by_claim}, rejected by the compiler {static_}; taproot skipped {unsupported}; {:.1} s",
    bad.is_empty(),
    t0.elapsed().as_secs_f64()
  );
  if !bad.is_empty() {
    std::process::exit(1);
  }
}

type E1 = nova_snark::provider::PallasEngine;
type E2 = nova_snark::provider::VestaEngine;
type Pp = nova_snark::nova::PublicParams<E1, E2, ScriptStep>;
type Rs = nova_snark::nova::RecursiveSNARK<E1, E2, ScriptStep>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, nova_snark::provider::ipa_pc::EvaluationEngine<E1>>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, nova_snark::provider::ipa_pc::EvaluationEngine<E2>>;

pub fn setup() -> Pp {
  use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
  Pp::setup(&ScriptStep::default(), &*S1::ck_floor(), &*S2::ck_floor()).unwrap()
}

/// Proves each named case with Nova, then verifies as the checker would: z0 from the compiled
/// program, the folded proof, the final state (program consumed, no phase), and the claims.
pub fn prove_cases(cases: &[Case], ids: &[String]) {
  let t = Instant::now();
  let pp = setup();
  println!("setup {:.1} s, {} constraints per step", t.elapsed().as_secs_f64(), num_constraints());
  for id in ids {
    let c = cases.iter().find(|c| &c.id == id).unwrap_or_else(|| panic!("no case {id}"));
    let Verdict::Valid(tr, prog, tx) = run_case(c, true) else { panic!("{id} is not valid natively") };
    let n = tr.wits.len();
    let t = Instant::now();
    let steps: Vec<ScriptStep> = tr.wits.iter().map(|w| ScriptStep { w: w.clone() }).collect();
    let mut rs = Rs::new(&pp, &steps[0], &tr.z0).unwrap();
    for s in &steps {
      rs.prove_step(&pp, s).unwrap();
    }
    let prove = t.elapsed().as_secs_f64();
    // The checker.
    let t = Instant::now();
    let (amount, _) = &c.prevouts[c.index];
    let z0 = engine::initial_state(&prog);
    assert_eq!(z0, tr.z0);
    let zn = rs.verify(&pp, n, &z0).expect("Nova verify");
    assert_eq!(zn[z::P], F::ZERO, "program not consumed");
    assert_eq!(zn[z::PH], F::ZERO, "operation in progress");
    let ctx = Ctx { tx: &tx, n_in: c.index, amount: *amount, flags: c.flag_bits };
    engine::verify_claims(&tr.claims, &prog, &ctx, zn[z::CL]).expect("claims");
    // A wrong step count must not verify.
    let wrong = rs.verify(&pp, n + 1, &z0).is_err();
    println!(
      "{id}: {} instructions, {n} steps, {} claims, prove {prove:.2} s ({:.1} ms/step), verify {:.2} s, wrong step count refused {wrong} | {}",
      prog.instrs.len(),
      tr.claims.len(),
      1000.0 * prove / n as f64,
      t.elapsed().as_secs_f64(),
      c.description
    );
  }
}

/// Tampers with one witness field per step of valid cases. The instruction opening and the
/// commitments below the pops are always read, and so is every popped element: changing any of
/// them must leave the step unsatisfied. W, the alt-stack and temporary-stack witnesses are read
/// only by some rows; a change there must either be refused or change the committed state.
pub fn mutate_cases(cases: &[Case], ids: &[String]) {
  let (mut n, mut refused) = (0, 0);
  for id in ids {
    let c = cases.iter().find(|c| &c.id == id).unwrap();
    let Verdict::Valid(tr, ..) = run_case(c, true) else { panic!() };
    let mut zin = tr.z0;
    for (i, (w, zo)) in tr.wits.iter().zip(&tr.zs).enumerate() {
      let ph = crate::elem::f_to_u64(&zin[z::PH]).unwrap();
      let cnt = crate::elem::f_to_u64(&zin[z::CNT]).unwrap();
      let dc = if ph == 0 { w.iop } else { ph + (cnt == 0) as u64 };
      let row = ctrl(dc).unwrap();
      let exec = zin[z::FF] == fu(isa::NO_FALSE);
      let k = if !row.gated || exec { row.k } else { 0 };
      let mut muts: Vec<(&str, Wit, bool)> = vec![
        ("s1", Wit { s: { let mut s = w.s; s[0] += F::ONE; s }, ..w.clone() }, true),
        ("iop", Wit { iop: w.iop ^ 1, ..w.clone() }, true),
        ("data", Wit { data: w.data + F::ONE, ..w.clone() }, true),
        ("aux", Wit { aux: w.aux ^ 1, ..w.clone() }, true),
        ("next", Wit { next: w.next + F::ONE, ..w.clone() }, true),
        ("w", Wit { w: w.w + F::ONE, ..w.clone() }, false),
        ("a", Wit { a: w.a + F::ONE, ..w.clone() }, false),
        ("t", Wit { t: w.t + F::ONE, ..w.clone() }, false),
      ];
      for j in 0..k as usize {
        let mut m = w.clone();
        m.p[j] += F::ONE;
        muts.push(("p", m, true));
      }
      for (name, m, must) in muts {
        let (ok, got, _) = run_step(&zin, &m);
        n += 1;
        if !ok {
          refused += 1;
        } else if must || got == *zo && name == "w" && row.bool_ == Bool::W {
          println!("MUTATION ACCEPTED {id} step {i} {name} (dispatch {dc})");
          std::process::exit(1);
        }
      }
      zin = *zo;
    }
  }
  println!("mutations: {n} tampered steps, {refused} unsatisfied; every change to a read field was refused");
}

/// Compresses the folded proof of one case (Spartan over IPA) and reports its size.
pub fn compress_case(cases: &[Case], id: &str) {
  use nova_snark::nova::CompressedSNARK;
  let c = cases.iter().find(|c| c.id == id).unwrap();
  let Verdict::Valid(tr, prog, _) = run_case(c, true) else { panic!() };
  let pp = setup();
  let steps: Vec<ScriptStep> = tr.wits.iter().map(|w| ScriptStep { w: w.clone() }).collect();
  let mut rs = Rs::new(&pp, &steps[0], &tr.z0).unwrap();
  for s in &steps {
    rs.prove_step(&pp, s).unwrap();
  }
  let t = Instant::now();
  let (pk, vk) = CompressedSNARK::<E1, E2, ScriptStep, S1, S2>::setup(&pp).unwrap();
  let ts = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let snark = CompressedSNARK::<E1, E2, ScriptStep, S1, S2>::prove(&pp, &pk, &rs).unwrap();
  let tp = t.elapsed().as_secs_f64();
  let bytes = bincode::serialize(&snark).unwrap();
  let t = Instant::now();
  let zn = snark.verify(&vk, steps.len(), &engine::initial_state(&prog)).unwrap();
  assert_eq!(zn[z::P], F::ZERO);
  println!(
    "{id}: compressed setup {ts:.1} s, prove {tp:.1} s, {} bytes, verify {:.2} s",
    bytes.len(),
    t.elapsed().as_secs_f64()
  );
}
