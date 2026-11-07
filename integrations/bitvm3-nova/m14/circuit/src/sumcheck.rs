//! SP1's sumcheck verifier (`slop_sumcheck::partially_verify_sumcheck_proof`) as a circuit.
//!
//! Native checks, in order: p_0(0) + p_0(1) = claimed sum; for each later round i, after
//! sampling alpha_{i-1}: p_{i-1}(alpha_{i-1}) = p_i(0) + p_i(1); a last alpha; the proof's point
//! equals the alphas (SP1 inserts each new alpha at the front); the proof's evaluation equals
//! p_last(alpha_last). Each polynomial's coefficients are observed before the next alpha.
//!
//! The point and the final evaluation are not circuit inputs: the circuit derives them and
//! returns them to the caller, which uses them where the native verifier uses the proof's copies.
//! A proof whose copies differ from the derived values is one the native verifier rejects.
use garbled_snark_verifier::CircuitContext;
use m12_gates::W;

use crate::{
    ext::{self, Ext},
    field::{self as f, Fe},
    hash::Transcript,
    sample,
};

/// p(0) + p(1) = 2 c_0 + c_1 + ... + c_d.
pub fn eval_zero_plus_one<C: CircuitContext>(c: &mut C, coeffs: &[Ext]) -> Ext {
    let mut acc = coeffs[0].clone();
    for x in coeffs {
        acc = ext::add(c, &acc, x);
    }
    acc
}

/// p(x) by Horner's rule (as SP1: highest coefficient first).
pub fn eval_at<C: CircuitContext>(c: &mut C, coeffs: &[Ext], x: &Ext) -> Ext {
    let Some((top, rest)) = coeffs.split_last() else { return Ext::zero() };
    let mut acc = top.clone();
    for k in rest.iter().rev() {
        let t = ext::mul(c, &acc, x);
        acc = ext::add(c, &t, k);
    }
    acc
}

/// Round consistency for given alphas (in sampling order): (all checks hold, final evaluation).
pub fn check_rounds<C: CircuitContext>(c: &mut C, claimed_sum: &Ext, polys: &[Vec<Ext>], alphas: &[Ext]) -> (W, Ext) {
    assert_eq!(polys.len(), alphas.len());
    assert!(!polys.is_empty());
    let mut oks = Vec::with_capacity(polys.len());
    let s0 = eval_zero_plus_one(c, &polys[0]);
    oks.push(ext::eq(c, &s0, claimed_sum));
    for i in 1..polys.len() {
        let e = eval_at(c, &polys[i - 1], &alphas[i - 1]);
        let s = eval_zero_plus_one(c, &polys[i]);
        oks.push(ext::eq(c, &e, &s));
    }
    let eval = eval_at(c, &polys[polys.len() - 1], &alphas[alphas.len() - 1]);
    (f::and_all(c, &oks), eval)
}

/// Observe one extension element (its 4 coefficients, 4 little-endian bytes each).
pub fn observe_ext(t: &mut Transcript, x: &Ext) {
    for k in &x.0 {
        t.observe_fe(k);
    }
}

/// v2 extension challenge: 4 base challenges of 8 bytes each.
pub fn sample_ext<C: CircuitContext>(c: &mut C, t: &mut Transcript) -> Ext {
    let bytes = t.sample_bytes(c, 32);
    sample::ext_from_le256(c, &bytes)
}

/// The whole sumcheck verifier with transcript v2. Returns (ok, point in SP1's order, evaluation).
pub fn verify<C: CircuitContext>(c: &mut C, t: &mut Transcript, claimed_sum: &Ext, polys: &[Vec<Ext>]) -> (W, Vec<Ext>, Ext) {
    let mut alphas = Vec::with_capacity(polys.len());
    for (i, p) in polys.iter().enumerate() {
        if i > 0 {
            alphas.push(sample_ext(c, t));
        }
        p.iter().for_each(|x| observe_ext(t, x));
    }
    alphas.push(sample_ext(c, t));
    let (ok, eval) = check_rounds(c, claimed_sum, polys, &alphas);
    let point: Vec<Ext> = alphas.into_iter().rev().collect();
    (ok, point, eval)
}

/// Inputs as wires: a polynomial of degree d is d + 1 extension elements.
pub fn ext_from_wires(w: &[W]) -> Ext {
    Ext(std::array::from_fn(|i| Fe::from_wires(&w[i * f::BITS..(i + 1) * f::BITS])))
}

/// 1 iff all four coefficients of every input element are canonical.
pub fn all_canonical<C: CircuitContext>(c: &mut C, xs: &[Ext]) -> W {
    let oks: Vec<W> = xs.iter().flat_map(|x| x.0.iter()).map(|k| f::is_canonical(c, &k.0)).collect();
    f::and_all(c, &oks)
}
