//! FC03 circuits against the native adjudicator: field gadgets, then every row and binding-step
//! case of the adversarial suite executed as a Boolean circuit, then garbling and evaluation of
//! an honest and a refuted case on both Pasta engines.
use flatcheck_fc03::{
    cases::{self, Suite},
    circuit::{
        field::{PField, N},
        inputs,
        row::RowKnown,
        run::{self, Which},
        step::StepKnown,
        W,
    },
    field::FieldId,
    protocol::*,
};
use garbled_snark_verifier::circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult};
use garbled_snark_verifier::WireId;
use nova_snark::provider::{PallasEngine, VestaEngine};
use num_bigint::BigUint;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::sync::OnceLock;

fn suites() -> &'static (Suite<PallasEngine>, Suite<VestaEngine>) {
    static S: OnceLock<(Suite<PallasEngine>, Suite<VestaEngine>)> = OnceLock::new();
    S.get_or_init(|| (Suite::<PallasEngine>::build(0xFC03_0001), Suite::<VestaEngine>::build(0xFC03_0002)))
}

struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, v) in w.iter().zip(&self.0) {
            mode.feed_wire(*id, *v);
        }
    }
}

macro_rules! run {
    ($bits:expr, $f:expr) => {{
        let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain($bits), 1 << 20, $f);
        (r.output_value, r.gate_count.nonfree_gate_count())
    }};
}

fn bits_of(v: &BigUint, n: usize) -> Vec<bool> {
    (0..n).map(|i| v.bit(i as u64)).collect()
}
fn val(b: &[bool]) -> BigUint {
    b.iter().enumerate().fold(BigUint::default(), |a, (i, &x)| if x { a | (BigUint::from(1u8) << i) } else { a })
}

#[test]
fn pasta_field_gadgets_match_native() {
    let mut rng = ChaChaRng::seed_from_u64(7);
    for f in [FieldId::PallasScalar, FieldId::VestaScalar] {
        for p in [f.modulus(), f.base_modulus()] {
            let pf = PField::new(p.clone());
            let r = BigUint::from(1u8) << N;
            let rinv = pf.rinv.clone();
            let mut counts = (0u64, 0u64, 0u64);
            for t in 0..12 {
                let mut rnd = || {
                    let mut b = [0u8; 32];
                    rng.fill_bytes(&mut b);
                    BigUint::from_bytes_le(&b) % &p
                };
                let (a, b) = if t == 0 { (&p - 1u8, &p - 1u8) } else if t == 1 { (BigUint::default(), &p - 1u8) } else { (rnd(), rnd()) };
                let mut bits = bits_of(&a, N);
                bits.extend(bits_of(&b, N));
                let (out, nf) = run!(bits, |c, w: &Vec<WireId>| {
                    let (x, y) = (&w[..N], &w[N..]);
                    let mut o = pf.mul(c, x, y);
                    o.extend(pf.add(c, x, y));
                    o.extend(pf.sub(c, x, y));
                    o
                });
                let want_mul = (&a * &b * &rinv) % &p;
                assert_eq!(val(&out[..N]), want_mul);
                assert_eq!(val(&out[N..2 * N]), (&a + &b) % &p);
                assert_eq!(val(&out[2 * N..]), (&a + &p - &b) % &p);
                let _ = &r;
                if t == 2 {
                    let (_, m) = run!(bits_of(&a, N).into_iter().chain(bits_of(&b, N)).collect(), |c, w: &Vec<WireId>| pf.mul(c, &w[..N], &w[N..]));
                    let (_, ad) = run!(bits_of(&a, N).into_iter().chain(bits_of(&b, N)).collect(), |c, w: &Vec<WireId>| pf.add(c, &w[..N], &w[N..]));
                    let (_, cm) = run!(bits_of(&a, N), |c, w: &Vec<WireId>| pf.to_mont(c, w));
                    counts = (m, ad, cm);
                }
                let _ = nf;
            }
            eprintln!("FC03-GATES field p={}.. mont_mul={} add={} mul_const(R^2)={}", &p.to_str_radix(16)[..8], counts.0, counts.1, counts.2);
        }
    }
}

#[test]
fn flatmerkle_circuit_matches_native() {
    use flatcheck_fc03::{circuit as cc, flatmerkle};
    for n in [4usize, 8, 2048] {
        let items: Vec<[u8; 64]> = (0..n).map(|i| [((i * 13) % 255) as u8; 64]).collect();
        let s = flatmerkle::build(&items).unwrap();
        for &i in &[0usize, 1, n / 2 + 1, n - 1] {
            let o = flatmerkle::open(&s, i);
            for tamper in [false, true] {
                let mut bytes = Vec::new();
                bytes.extend((i as u32).to_be_bytes());
                bytes.extend(o.pair[0]);
                bytes.extend(o.pair[1]);
                for r in inputs::level_order(n, i, &o.reveals).unwrap() {
                    bytes.extend(r);
                }
                if tamper {
                    let l = bytes.len();
                    bytes[l - 3] ^= 4;
                }
                let root = s.digest;
                let item = items[i];
                let (out, nf) = run!(inputs::bits(&bytes), |c, w: &Vec<WireId>| {
                    let mut cur = cc::Cur::new(w);
                    let op = cur.opening(n);
                    let idx: Vec<W> = (0..32).map(|b| cc::const_bit((i >> b) & 1 == 1)).collect();
                    let rootw = cc::words_of_bytes(&cc::const_bytes(&root));
                    let itw = cc::const_bytes(&item);
                    // index as input-dependent wires: take them from the opening itself
                    let _ = &idx;
                    let idxw = op.index.clone();
                    vec![cc::flat_verify(c, n, &rootw, &idxw, &itw, &op)]
                });
                assert_eq!(out[0], !tamper || n == 4 && false, "n={n} i={i} tamper={tamper}");
                if !tamper && i == 0 {
                    eprintln!("FC03-GATES flatmerkle_verify n={n} nonfree={nf} compressions={}", 2 * n.trailing_zeros() + 1);
                }
            }
        }
    }
}

fn which_for(c: &cases::Case, pallas: &TrustedConfig, vesta: &TrustedConfig) -> Option<(Which, Vec<u8>)> {
    let tc = match c.tc_field {
        FieldId::PallasScalar => pallas,
        FieldId::VestaScalar => vesta,
    };
    match c.challenge.kind {
        ChallengeKind::Row { .. } => inputs::row_input(tc, &c.claim, &c.challenge, c.response.as_ref()).ok().map(|b| (Which::Row(RowKnown::new(tc)), b)),
        ChallengeKind::BindingStep { vec, .. } => {
            inputs::step_input(tc, &c.claim, &c.challenge, c.response.as_ref(), vec).ok().map(|b| (Which::Step(StepKnown::new(tc, vec)), b))
        }
        _ => None,
    }
}

#[test]
fn circuit_verdicts_match_native_on_the_suite() {
    let (p, v) = suites();
    let (ptc, vtc) = (&p.toy.pinned.tc, &v.toy.pinned.tc);
    let mut all = p.cases.clone();
    all.extend(v.cases.clone());
    all.extend(cases::cross_field_cases(p, v));
    let (mut compared, mut skipped, mut mismatches) = (0, 0, Vec::new());
    let mut gates: std::collections::BTreeMap<String, u64> = Default::default();
    for c in &all {
        let native = cases::run_native(c, ptc, vtc);
        let Some((w, bytes)) = which_for(c, ptc, vtc) else {
            skipped += 1;
            continue;
        };
        let (out, nf, _) = run::execute(&w, inputs::bits(&bytes));
        let out = [out];
        let key = match &w {
            Which::Row(_) => format!("row/{:?}", c.tc_field),
            Which::Step(k) => format!("step-{:?}/{:?}", k.v, c.tc_field),
        };
        gates.entry(key).and_modify(|g| assert_eq!(*g, nf, "fixed circuit: gate count independent of inputs")).or_insert(nf);
        compared += 1;
        if out[0] != native.refutes() {
            mismatches.push(format!("{}: circuit refutes={} native={:?}", c.name, out[0], native));
        }
    }
    eprintln!("FC03-CIRCUIT compared={compared} skipped={skipped} mismatches={} gates={gates:?}", mismatches.len());
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn garbled_row_and_step_circuits_both_fields() {
    let (p, v) = suites();
    let (ptc, vtc) = (&p.toy.pinned.tc, &v.toy.pinned.tc);
    let mut all = p.cases.clone();
    all.extend(v.cases.clone());
    for name in ["/honest/row3", "/W2-changed-row3", "/honest/binding-step-W-255", "/forged-WE-end-patched/last-step-W"] {
        for f in [FieldId::PallasScalar, FieldId::VestaScalar] {
            let c = all.iter().find(|c| c.field == f && c.name.ends_with(name)).unwrap();
            let (w, bytes) = which_for(c, ptc, vtc).unwrap();
            let bits = inputs::bits(&bytes);
            let nf = run::garble_count(&w, bits.len(), 3);
            let rep = run::garble_and_evaluate(&w, bits, 0xFC03);
            let (_, exec_nf, _) = run::execute(&w, inputs::bits(&bytes));
            eprintln!(
                "FC03-GARBLE {} ciphertexts={} garbler={} execute={} bytes={} input_labels={} seconds={:.2} refutes={:?}",
                c.name, rep.ciphertexts, nf, exec_nf, rep.ciphertext_bytes, rep.input_labels, rep.garble_and_evaluate_seconds, rep.refutes()
            );
            assert_eq!(rep.refutes(), Some(c.expected_refutes), "{}", c.name);
            assert_eq!(rep.ciphertexts, nf, "garbler ciphertext count is seed-independent");
            assert!(rep.evaluator_nonfree >= rep.ciphertexts && rep.evaluator_nonfree - rep.ciphertexts < 64);
        }
    }
}
