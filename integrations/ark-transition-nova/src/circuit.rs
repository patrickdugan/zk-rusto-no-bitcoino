//! The uniform step circuit: one item per step, the kind selected by four boolean flags.
//!
//! Constraints of a kind apply only when its flag is 1: every non-selected constraint is a
//! product with its flag (or with a quantity that the flag zeroes), so it is vacuous.

use crate::elem::{constants, fu, pow2, F};
use crate::engine::{z, Wit, ARITY, K_CLOSE, K_IN, K_OUT, K_SORTED};
use ff::{Field, PrimeFieldBits};
use nova_snark::frontend::gadgets::poseidon::{Elt, IOPattern, Simplex, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait};
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use nova_snark::traits::circuit::StepCircuit;

fn one() -> Variable {
  Variable::new_unchecked(Index::Input(0))
}

/// A linear combination with its value (zero when synthesizing the shape).
#[derive(Clone)]
struct V {
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
}

fn bits_of(x: &F, n: usize) -> Vec<bool> {
  x.to_le_bits().iter().take(n).map(|b| *b).collect()
}

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
  fn enforce(&mut self, a: &V, b: &V, c: &V) {
    let nm = self.name();
    self.cs.enforce(|| nm, |l| l + &a.lc, |l| l + &b.lc, |l| l + &c.lc);
  }
  fn eq(&mut self, a: &V, b: &V) {
    self.enforce(&a.sub(b), &V::cu(1), &V::zero());
  }
  fn mul(&mut self, a: &V, b: &V) -> V {
    let c = self.alloc(a.val * b.val);
    self.enforce(a, b, &c);
    c
  }
  fn prod_zero(&mut self, a: &V, b: &V) {
    self.enforce(a, b, &V::zero());
  }
  fn bit(&mut self, b: bool) -> V {
    let v = self.alloc(if b { F::ONE } else { F::ZERO });
    self.prod_zero(&v, &V::cu(1).sub(&v));
    v
  }
  /// x as an integer below 2^n: n boolean bits that recompose to x.
  fn range(&mut self, x: &V, n: usize) {
    let bs = bits_of(&x.val, n);
    let mut acc = V::zero();
    for (i, &b) in bs.iter().enumerate() {
      let v = self.bit(b);
      acc = acc.add(&v.scale(pow2(i as u32)));
    }
    self.eq(&acc, x);
  }
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
  /// a when c = 0, b when c = 1.
  fn sel(&mut self, c: &V, a: &V, b: &V) -> V {
    let d = self.mul(c, &b.sub(a));
    a.add(&d)
  }
}

#[derive(Clone, Default)]
pub struct ArkStep {
  pub w: Wit,
}

impl StepCircuit<F> for ArkStep {
  fn arity(&self) -> usize {
    ARITY
  }

  fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, zin: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut cx = Cx { cs, n: 0 };
    let w = &self.w;
    let zv: Vec<V> = zin.iter().map(V::var).collect();
    let g = |i: usize| zv[i].clone();
    let one_v = V::cu(1);

    // Kind flags: four booleans that sum to 1.
    let b_in = cx.bit(w.kind == K_IN);
    let b_out = cx.bit(w.kind == K_OUT);
    let b_cl = cx.bit(w.kind == K_CLOSE);
    let b_so = cx.bit(w.kind == K_SORTED);
    cx.eq(&b_in.add(&b_out).add(&b_cl).add(&b_so), &one_v);
    let is_rec = b_in.add(&b_out).add(&b_cl);

    let val = cx.alloc(w.val);
    let spend = cx.alloc(w.spend);
    let commit = cx.alloc(w.commit);

    // Records are only accepted in phase 0, so the phase never returns to 0 once a sorted step ran.
    cx.prod_zero(&is_rec, &g(z::PHASE));

    // val is a 64-bit integer (value or fee; 0 in sorted steps).
    cx.range(&val, 64);

    // Selected products.
    let m_in = cx.mul(&b_in, &val);
    let m_out = cx.mul(&b_out, &val);
    let m_cl = cx.mul(&b_cl, &val);
    let in_spend = cx.mul(&b_in, &spend);
    let out_commit = cx.mul(&b_out, &commit);
    let cl_acc = cx.mul(&b_cl, &g(z::ACC));

    // CLOSE: acc == fee, and fee_bound - fee is a 64-bit integer.
    cx.eq(&cl_acc, &m_cl);
    let slack = cx.mul(&b_cl, &g(z::FEE_BOUND).sub(&val));
    cx.range(&slack, 64);

    let acc_n = g(z::ACC).add(&m_in).sub(&m_out).sub(&cl_acc);
    let sum_in_n = g(z::SUM_IN).add(&m_in);
    let sum_out_n = g(z::SUM_OUT).add(&m_out);
    let sum_fee_n = g(z::SUM_FEE).add(&m_cl);

    // Record chain.
    let tag = b_in.add(&b_out.scale(fu(2))).add(&b_cl.scale(fu(3)));
    let ha = in_spend.add(&m_out).add(&m_cl);
    let hb = m_in.add(&out_commit);
    let h1 = cx.hash(&[g(z::R1), tag, ha, hb]);
    let r1_n = cx.sel(&is_rec, &g(z::R1), &h1);

    // Sorted chain.
    let h2 = cx.hash(&[g(z::R2), spend.clone()]);
    let r2_n = cx.sel(&b_so, &g(z::R2), &h2);

    // Grand products at gamma.
    let t1 = cx.mul(&b_in, &g(z::GAMMA).sub(&spend));
    let f1 = t1.add(&one_v).sub(&b_in);
    let p1_n = cx.mul(&g(z::P1), &f1);
    let t2 = cx.mul(&b_so, &g(z::GAMMA).sub(&spend));
    let f2 = t2.add(&one_v).sub(&b_so);
    let p2_n = cx.mul(&g(z::P2), &f2);

    // SORTED: spend - last - 1 is a 248-bit integer (strictly increasing).
    let m = cx.mul(&b_so, &spend.sub(&g(z::LAST)));
    let d = m.sub(&b_so);
    cx.range(&d, 248);
    let last_n = g(z::LAST).add(&m);

    let ph_gain = cx.mul(&b_so, &one_v.sub(&g(z::PHASE)));
    let phase_n = g(z::PHASE).add(&ph_gain);

    let mut out: Vec<V> = (0..ARITY).map(|i| g(i)).collect();
    out[z::ACC] = acc_n;
    out[z::SUM_IN] = sum_in_n;
    out[z::SUM_OUT] = sum_out_n;
    out[z::SUM_FEE] = sum_fee_n;
    out[z::R1] = r1_n;
    out[z::P1] = p1_n;
    out[z::R2] = r2_n;
    out[z::P2] = p2_n;
    out[z::LAST] = last_n;
    out[z::N_IN1] = g(z::N_IN1).add(&b_in);
    out[z::N_IN2] = g(z::N_IN2).add(&b_so);
    out[z::N_TX] = g(z::N_TX).add(&b_cl);
    out[z::PHASE] = phase_n;

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

/// A constraint system that evaluates each constraint as it is enforced: the fast satisfiability test.
pub struct CheckCS {
  inputs: Vec<F>,
  aux: Vec<F>,
  pub n: usize,
  pub first_failure: Option<usize>,
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

/// Runs one step through the checker: (satisfied, circuit's next state, first failing constraint).
pub fn run_step(zin: &[F; ARITY], w: &Wit) -> (bool, [F; ARITY], Option<usize>) {
  let mut cs = CheckCS::new();
  let zs: Vec<AllocatedNum<F>> = zin.iter().enumerate().map(|(i, v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || *v)).collect();
  let out = ArkStep { w: w.clone() }.synthesize(&mut cs, &zs).unwrap();
  let mut zo = [F::ZERO; ARITY];
  for (i, a) in out.iter().enumerate() {
    zo[i] = a.get_value().unwrap();
  }
  (cs.first_failure.is_none(), zo, cs.first_failure)
}

/// Runs every step of a plan through the checker, from z0. Returns the index of the first
/// unsatisfied step, or the final circuit state.
pub fn check_plan(z0: &[F; ARITY], steps: &[Wit]) -> Result<[F; ARITY], (usize, Option<usize>)> {
  let mut z = *z0;
  for (i, w) in steps.iter().enumerate() {
    let (ok, zo, f) = run_step(&z, w);
    if !ok {
      return Err((i, f));
    }
    z = zo;
  }
  Ok(z)
}

pub fn num_constraints() -> usize {
  let mut cs = CheckCS::new();
  let zs: Vec<AllocatedNum<F>> = (0..ARITY).map(|i| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || F::ZERO)).collect();
  ArkStep::default().synthesize(&mut cs, &zs).unwrap();
  cs.n
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::engine::{self, plan, record_steps, step};
  use crate::witness::{check_semantics, parse_str};

  fn sample() -> crate::witness::Parsed {
    let s = include_str!("../fixtures/ark4-sample.json");
    let (_, p) = parse_str(s).unwrap();
    check_semantics(&p).unwrap();
    p
  }

  #[test]
  fn native_chain_equals_circuit_chain() {
    let p = sample();
    let pl = plan(&p);
    let zn = check_plan(&pl.z0, &pl.steps).expect("all steps satisfied");
    assert_eq!(zn, pl.zn);
    assert_eq!(zn[z::R1], engine::chain_r1(&p));
    assert_eq!(pl.zn[z::PHASE], F::ONE);
    assert_eq!(pl.zn[z::ACC], F::ZERO);
    assert_eq!(pl.zn[z::P1], pl.zn[z::P2]);
    assert_eq!(pl.zn[z::N_IN1], pl.zn[z::N_IN2]);
    assert_eq!(pl.gamma, engine::gamma_of(pl.zn[z::R1], pl.zn[z::R2]));
  }

  #[test]
  fn each_kind_matches_engine() {
    let p = sample();
    let pl = plan(&p);
    let mut seen = [false; 4];
    let mut s = pl.z0;
    for w in &pl.steps {
      let (ok, zo, _) = run_step(&s, w);
      assert!(ok);
      assert_eq!(zo, step(&s, w));
      seen[w.kind as usize] = true;
      s = zo;
    }
    assert_eq!(seen, [true; 4]);
  }

  fn first_of(kind: u8, steps: &[Wit]) -> usize {
    steps.iter().position(|w| w.kind == kind).unwrap()
  }

  #[test]
  fn unsorted_step_unsatisfied() {
    let p = sample();
    let mut pl = plan(&p);
    let i = first_of(K_SORTED, &pl.steps);
    pl.steps.swap(i, i + 1);
    assert_eq!(check_plan(&pl.z0, &pl.steps).unwrap_err().0, i + 1);
  }

  #[test]
  fn duplicate_sorted_unsatisfied() {
    let p = sample();
    let mut pl = plan(&p);
    let i = first_of(K_SORTED, &pl.steps);
    pl.steps[i + 1] = pl.steps[i].clone();
    assert_eq!(check_plan(&pl.z0, &pl.steps).unwrap_err().0, i + 1);
  }

  #[test]
  fn value_at_2_64_unsatisfied() {
    let p = sample();
    let mut pl = plan(&p);
    let i = first_of(K_IN, &pl.steps);
    pl.steps[i].val = crate::elem::pow2(64);
    assert_eq!(check_plan(&pl.z0, &pl.steps).unwrap_err().0, i);
  }

  #[test]
  fn fee_above_bound_unsatisfied() {
    let p = sample();
    let mut steps = record_steps(&p.items);
    let i = first_of(K_CLOSE, &steps);
    // Raise the first input by the same amount so only the bound fails.
    let bump = fu(5001) - steps[i].val;
    steps[0].val += bump;
    steps[i].val = fu(5001);
    let z0 = engine::z0(&p.statement, p.fee_bound, F::ONE);
    assert_eq!(check_plan(&z0, &steps).unwrap_err().0, i);
  }

  #[test]
  fn close_with_nonzero_acc_unsatisfied() {
    let p = sample();
    let mut steps = record_steps(&p.items);
    let i = first_of(K_OUT, &steps);
    steps[i].val += F::ONE;
    let c = first_of(K_CLOSE, &steps);
    let z0 = engine::z0(&p.statement, p.fee_bound, F::ONE);
    assert_eq!(check_plan(&z0, &steps).unwrap_err().0, c);
  }

  #[test]
  fn record_after_phase_one_unsatisfied() {
    let p = sample();
    let pl = plan(&p);
    let mut s = pl.z0;
    s[z::PHASE] = F::ONE;
    for k in [K_IN, K_OUT, K_CLOSE] {
      let w = pl.steps[first_of(k, &pl.steps)].clone();
      assert!(!run_step(&s, &w).0);
    }
  }

  #[test]
  fn unknown_kind_unsatisfied() {
    let p = sample();
    let pl = plan(&p);
    let w = Wit { kind: 9, ..pl.steps[0].clone() };
    assert!(!run_step(&pl.z0, &w).0);
  }
}
