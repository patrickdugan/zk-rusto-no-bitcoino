//! Measured R1CS cost of the IPA generator MSM inside an outer circuit.
//!
//! The circuit field is the Pallas base field Fp (Vesta's scalar field), so
//! Pallas point arithmetic is native, using Nova 0.76's own ECC gadget. The
//! IPA weights s_i live in the Pallas scalar field Fq and are non-native here:
//! each term pays one Fq multiplication s_i = s_parent * u (Nova's BigNat,
//! 4 x 64-bit limbs) and a bit decomposition. The generators are verifier-key
//! constants, so the multiplication is fixed-base with constant window tables.
//!
//! Every unit is synthesized twice: into a counting constraint system
//! (constraints, variables, exact A/B/C nonzeros) and into Nova's
//! TestConstraintSystem with real values, whose satisfaction and output are
//! checked against native Pasta arithmetic. The Vesta side of the MSM lives in
//! the other field and needs its own circuit; it is not measured here.
use ff::{Field, PrimeField, PrimeFieldBits};
use group::{prime::PrimeCurveAffine, Curve, Group};
use halo2curves::{
    pasta::{Fp, Fq},
    CurveAffine,
};
mod pallas {
    pub type Point = halo2curves::pasta::Pallas;
}
use nova_snark::{
    frontend::{
        gadgets::{boolean::AllocatedBit, num::AllocatedNum},
        test_cs::TestConstraintSystem,
        ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
    },
    gadgets::{ecc::AllocatedPoint, nonnative::bignat::BigNat, utils::alloc_bignat_constant},
    provider::PallasEngine,
};
use num_bigint::BigInt;
use rand_core::OsRng;
use serde_json::{json, Value};

type Point = AllocatedPoint<PallasEngine>;
const LIMB_WIDTH: usize = 64;
const LIMBS: usize = 4;

/// Counts constraints, variables and A/B/C nonzeros without storing them.
#[derive(Default)]
struct CountCS {
    aux: usize,
    inputs: usize,
    constraints: usize,
    nnz: [usize; 3],
}
impl ConstraintSystem<Fp> for CountCS {
    type Root = Self;
    fn alloc<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Fp, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.aux += 1;
        Ok(Variable::new_unchecked(Index::Aux(self.aux - 1)))
    }
    fn alloc_input<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Fp, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.inputs += 1;
        Ok(Variable::new_unchecked(Index::Input(self.inputs)))
    }
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Fp>) -> LinearCombination<Fp>,
        LB: FnOnce(LinearCombination<Fp>) -> LinearCombination<Fp>,
        LC: FnOnce(LinearCombination<Fp>) -> LinearCombination<Fp>,
    {
        self.constraints += 1;
        self.nnz[0] += a(LinearCombination::zero()).len();
        self.nnz[1] += b(LinearCombination::zero()).len();
        self.nnz[2] += c(LinearCombination::zero()).len();
    }
    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }
    fn pop_namespace(&mut self) {}
    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}
impl CountCS {
    fn json(&self) -> Value {
        json!({"constraints":self.constraints,"aux_variables":self.aux,"inputs":self.inputs,
            "nnz_a":self.nnz[0],"nnz_b":self.nnz[1],"nnz_c":self.nnz[2],
            "nnz_total":self.nnz.iter().sum::<usize>()})
    }
}

fn coords(p: &pallas::Point) -> (Fp, Fp, bool) {
    let a = p.to_affine();
    if bool::from(a.is_identity()) {
        (Fp::ZERO, Fp::ZERO, true)
    } else {
        let c = a.coordinates().unwrap();
        (*c.x(), *c.y(), false)
    }
}

fn fq_bigint(x: &Fq) -> BigInt {
    BigInt::from_bytes_le(num_bigint::Sign::Plus, x.to_repr().as_ref())
}
fn q_modulus() -> BigInt {
    fq_bigint(&(-Fq::ONE)) + 1
}

/// A bit as a linear combination plus its witness value.
#[derive(Clone)]
struct Bit {
    lc: LinearCombination<Fp>,
    value: Option<bool>,
}

/// Fixed-base windowed scalar multiplication with constant tables.
/// Each c-bit window selects d * 2^(c w) * G from 2^c constants via the
/// multilinear extension of the table (2^c - c - 1 bit products), allocates
/// the selected (x, y, infinity) with one constraint each, and adds it to the
/// accumulator with Nova's complete addition, so no exceptional case is
/// assumed away.
fn fixed_base_mul<CS: ConstraintSystem<Fp>>(
    mut cs: CS,
    base: &pallas::Point,
    bits: &[Bit],
    window: usize,
) -> Result<Point, SynthesisError> {
    let mut acc = Point::default(cs.namespace(|| "acc0"))?;
    let mut step = *base;
    for (w, chunk) in bits.chunks(window).enumerate() {
        let k = chunk.len();
        let entries: Vec<(Fp, Fp, bool)> = (0..1u64 << k)
            .map(|d| coords(&(step * Fq::from(d))))
            .collect();
        // Monomials m_S over subsets S of the chunk, indexed by bitmask.
        let mut mono: Vec<(LinearCombination<Fp>, Option<bool>)> = Vec::with_capacity(1 << k);
        mono.push((LinearCombination::from_variable(CS::one()), Some(true)));
        for s in 1usize..(1 << k) {
            let top = usize::BITS as usize - 1 - s.leading_zeros() as usize;
            let rest = s & !(1 << top);
            let bit = &chunk[top];
            if rest == 0 {
                mono.push((bit.lc.clone(), bit.value));
                continue;
            }
            let value = match (mono[rest].1, bit.value) {
                (Some(a), Some(b)) => Some(a && b),
                _ => None,
            };
            let var = cs.alloc(
                || format!("w{w} m{s}"),
                || {
                    value
                        .map(|v| if v { Fp::ONE } else { Fp::ZERO })
                        .ok_or(SynthesisError::AssignmentMissing)
                },
            )?;
            let (left, right) = (mono[rest].0.clone(), bit.lc.clone());
            cs.enforce(
                || format!("w{w} m{s} product"),
                |lc| lc + &left,
                |lc| lc + &right,
                |lc| lc + var,
            );
            mono.push((LinearCombination::from_variable(var), value));
        }
        let digit: Option<usize> = chunk.iter().enumerate().try_fold(0usize, |d, (i, b)| {
            b.value.map(|v| d | (usize::from(v) << i))
        });
        let mut coordinate = |name: &str, f: &dyn Fn(&(Fp, Fp, bool)) -> Fp| {
            // Moebius transform: coefficient of m_S.
            let mut coeff: Vec<Fp> = entries.iter().map(f).collect();
            for i in 0..k {
                for s in 0..(1usize << k) {
                    if s & (1 << i) != 0 {
                        coeff[s] = coeff[s] - coeff[s ^ (1 << i)];
                    }
                }
            }
            let value = digit.map(|d| f(&entries[d]));
            let num = AllocatedNum::alloc(cs.namespace(|| format!("w{w} {name}")), || {
                value.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let mut lc = LinearCombination::zero();
            for (s, c) in coeff.iter().enumerate() {
                if !bool::from(c.is_zero()) {
                    for (var, coefficient) in mono[s].0.iter() {
                        lc = lc + (*coefficient * c, var);
                    }
                }
            }
            cs.enforce(
                || format!("w{w} {name} select"),
                |l| l + &lc,
                |l| l + CS::one(),
                |l| l + num.get_variable(),
            );
            Ok::<_, SynthesisError>(num)
        };
        let x = coordinate("x", &|e| e.0)?;
        let y = coordinate("y", &|e| e.1)?;
        let inf = coordinate("inf", &|e| if e.2 { Fp::ONE } else { Fp::ZERO })?;
        let p = Point {
            x,
            y,
            is_infinity: inf,
        };
        acc = acc.add(cs.namespace(|| format!("w{w} add")), &p)?;
        step *= Fq::from(1u64 << k);
    }
    Ok(acc)
}

fn bignat_fq<CS: ConstraintSystem<Fp>>(
    mut cs: CS,
    value: Option<Fq>,
) -> Result<BigNat<Fp>, SynthesisError> {
    BigNat::alloc_from_nat(
        cs.namespace(|| "fq"),
        || {
            value
                .map(|v| fq_bigint(&v))
                .ok_or(SynthesisError::AssignmentMissing)
        },
        LIMB_WIDTH,
        LIMBS,
    )
}

/// One MSM term: s = parent * u mod q (non-native), its 256 bits, s * G_i
/// (fixed-base), accumulated with a complete addition.
fn msm_term<CS: ConstraintSystem<Fp>>(
    mut cs: CS,
    acc: &Point,
    parent: &BigNat<Fp>,
    u: &BigNat<Fp>,
    modulus: &BigNat<Fp>,
    generator: &pallas::Point,
    window: usize,
) -> Result<(Point, BigNat<Fp>), SynthesisError> {
    let (_, s) = parent.mult_mod(cs.namespace(|| "s = parent*u"), u, modulus)?;
    let bits = s.decompose(cs.namespace(|| "s bits"))?;
    let values = bits.values.clone();
    let bits: Vec<Bit> = bits
        .bits
        .iter()
        .enumerate()
        .map(|(i, lc)| Bit {
            lc: lc.clone(),
            value: values.as_ref().map(|v| v[i]),
        })
        .collect();
    let term = fixed_base_mul(cs.namespace(|| "s*G"), generator, &bits, window)?;
    let next = acc.add(cs.namespace(|| "accumulate"), &term)?;
    Ok((next, s))
}

struct Fixture {
    generators: Vec<pallas::Point>,
    challenges: Vec<Fq>,
    root: Fq,
}
fn fixture(n: usize) -> Fixture {
    Fixture {
        generators: (0..n).map(|_| pallas::Point::random(OsRng)).collect(),
        challenges: (0..n).map(|_| Fq::random(OsRng)).collect(),
        root: Fq::random(OsRng),
    }
}

/// Builds an n-term MSM chain: s_0 = root*u_0, s_i = s_{i-1}*u_i.
fn msm_circuit<CS: ConstraintSystem<Fp>>(
    cs: &mut CS,
    f: &Fixture,
    window: usize,
    witness: bool,
) -> Result<Point, SynthesisError> {
    let modulus = alloc_bignat_constant(cs.namespace(|| "q"), &q_modulus(), LIMB_WIDTH, LIMBS)?;
    let mut parent = bignat_fq(cs.namespace(|| "root"), witness.then_some(f.root))?;
    let mut acc = Point::default(cs.namespace(|| "acc"))?;
    for (i, (g, u)) in f.generators.iter().zip(&f.challenges).enumerate() {
        let u = bignat_fq(cs.namespace(|| format!("u{i}")), witness.then_some(*u))?;
        let (next, s) = msm_term(
            cs.namespace(|| format!("term{i}")),
            &acc,
            &parent,
            &u,
            &modulus,
            g,
            window,
        )?;
        acc = next;
        parent = s;
    }
    Ok(acc)
}

fn native_msm(f: &Fixture) -> pallas::Point {
    let mut s = f.root;
    let mut acc = pallas::Point::identity();
    for (g, u) in f.generators.iter().zip(&f.challenges) {
        s *= u;
        acc += g * s;
    }
    acc
}

fn check_point(cs: &TestConstraintSystem<Fp>, p: &Point, expected: &pallas::Point) -> bool {
    let (x, y, inf) = coords(expected);
    cs.is_satisfied()
        && p.x.get_value() == Some(x)
        && p.y.get_value() == Some(y)
        && p.is_infinity.get_value() == Some(if inf { Fp::ONE } else { Fp::ZERO })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args()
        .nth(1)
        .ok_or("usage: msm_gadget_bench OUTPUT_JSON")?;
    let mut report = serde_json::Map::new();

    // Primitive Nova gadgets.
    let scalar = Fq::random(OsRng);
    let base = pallas::Point::random(OsRng);
    let scalar_bits: Vec<bool> = (0..255).map(|i| scalar.to_le_bits()[i]).collect();
    {
        let mut count = CountCS::default();
        let p = Point::alloc(count.namespace(|| "p"), None)?;
        let bits = (0..255)
            .map(|i| AllocatedBit::alloc(count.namespace(|| format!("b{i}")), None))
            .collect::<Result<Vec<_>, _>>()?;
        let before = count.constraints;
        p.scalar_mul(count.namespace(|| "mul"), &bits)?;
        let mut row = count.json();
        row["bit_allocation_constraints"] = json!(before);
        let mut test = TestConstraintSystem::<Fp>::new();
        let (x, y, inf) = coords(&base);
        let p = Point::alloc(test.namespace(|| "p"), Some((x, y, inf)))?;
        let bits = scalar_bits
            .iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(test.namespace(|| format!("b{i}")), Some(*b)))
            .collect::<Result<Vec<_>, _>>()?;
        let r = p.scalar_mul(test.namespace(|| "mul"), &bits)?;
        row["satisfied_and_correct"] = json!(check_point(&test, &r, &(base * scalar)));
        report.insert("nova_variable_base_scalar_mul_255".into(), row);
    }
    for (name, double) in [("nova_complete_add", false), ("nova_double", true)] {
        let mut count = CountCS::default();
        let a = Point::alloc(count.namespace(|| "a"), None)?;
        let b = Point::alloc(count.namespace(|| "b"), None)?;
        let before = count.constraints;
        if double {
            a.double(count.namespace(|| "op"))?;
        } else {
            a.add(count.namespace(|| "op"), &b)?;
        }
        let mut row = count.json();
        row["operation_constraints"] = json!(count.constraints - before);
        report.insert(name.into(), row);
    }
    // Fixed-base multiplication by window width.
    let mut windows = Vec::new();
    for window in 1..=7 {
        let mut count = CountCS::default();
        let bits = (0..255)
            .map(|i| {
                AllocatedBit::alloc(count.namespace(|| format!("b{i}")), None).map(|b| Bit {
                    lc: LinearCombination::from_variable(b.get_variable()),
                    value: None,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let before = count.constraints;
        fixed_base_mul(count.namespace(|| "fb"), &base, &bits, window)?;
        let mut row = count.json();
        row["window"] = json!(window);
        row["multiplication_constraints"] = json!(count.constraints - before);
        let mut test = TestConstraintSystem::<Fp>::new();
        let bits = scalar_bits
            .iter()
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(test.namespace(|| format!("b{i}")), Some(*b)).map(|a| Bit {
                    lc: LinearCombination::from_variable(a.get_variable()),
                    value: Some(*b),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let r = fixed_base_mul(test.namespace(|| "fb"), &base, &bits, window)?;
        row["satisfied_and_correct"] = json!(check_point(&test, &r, &(base * scalar)));
        windows.push(row);
    }
    let best = windows
        .iter()
        .min_by_key(|r| r["multiplication_constraints"].as_u64().unwrap())
        .cloned()
        .unwrap();
    let window = best["window"].as_u64().unwrap() as usize;
    report.insert("fixed_base_scalar_mul_255".into(), json!(windows));
    // Non-native Fq multiplication and decomposition.
    {
        let mut count = CountCS::default();
        let m = alloc_bignat_constant(count.namespace(|| "q"), &q_modulus(), LIMB_WIDTH, LIMBS)?;
        let a = bignat_fq(count.namespace(|| "a"), None)?;
        let b = bignat_fq(count.namespace(|| "b"), None)?;
        let before = count.constraints;
        let (_, r) = a.mult_mod(count.namespace(|| "mul"), &b, &m)?;
        let mul = count.constraints - before;
        let before = count.constraints;
        r.decompose(count.namespace(|| "bits"))?;
        let mut row = count.json();
        row["mult_mod_constraints"] = json!(mul);
        row["decompose_constraints"] = json!(count.constraints - before);
        report.insert("nonnative_fq_mult_mod_and_bits".into(), row);
    }
    // Composed MSM terms; per-term cost from the slope.
    let mut terms = Vec::new();
    for n in [1usize, 2, 4, 8] {
        let f = fixture(n);
        let mut count = CountCS::default();
        msm_circuit(&mut count, &f, window, false)?;
        let mut row = count.json();
        row["terms"] = json!(n);
        let mut test = TestConstraintSystem::<Fp>::new();
        let r = msm_circuit(&mut test, &f, window, true)?;
        row["satisfied_and_correct"] = json!(check_point(&test, &r, &native_msm(&f)));
        terms.push(row);
    }
    let slope = |key: &str| {
        (terms[3][key].as_u64().unwrap() - terms[0][key].as_u64().unwrap()) as f64 / 7.0
    };
    let per_term = json!({"constraints":slope("constraints"),"aux_variables":slope("aux_variables"),
        "nnz_total":slope("nnz_total"),"window":window});
    let primary = 524_288f64;
    report.insert("msm_terms".into(), json!(terms));
    report.insert("per_term".into(), per_term.clone());
    report.insert(
        "primary_ipa_msm_projection".into(),
        json!({"generators":524288,
            "constraints":per_term["constraints"].as_f64().unwrap()*primary,
            "aux_variables":per_term["aux_variables"].as_f64().unwrap()*primary,
            "nnz_total":per_term["nnz_total"].as_f64().unwrap()*primary,
            "witness_bytes":per_term["aux_variables"].as_f64().unwrap()*primary*32.0,
            "measured":false,"basis":"measured per-term slope x 524,288; Vesta side, transcript and rest of the verifier excluded"}),
    );
    report.insert("schema".into(), json!("bitvm2-nova-msm-gadget-bench/v1"));
    report.insert("nova_version".into(), json!("0.76.0"));
    report.insert(
        "circuit_field".into(),
        json!("Pallas base Fp (Vesta scalar)"),
    );
    report.insert(
        "scalar_field_handling".into(),
        json!("non-native Fq BigNat, 4 x 64-bit limbs"),
    );
    let raw = serde_json::to_vec_pretty(&Value::Object(report))?;
    std::fs::write(&output, &raw)?;
    println!("{}", String::from_utf8(raw)?);
    Ok(())
}
