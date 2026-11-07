//! M14 gadgets against SP1's own field types (p3-koala-bear 0.4.3-succinct, and
//! `BinomialExtensionField<KoalaBear, 4>`, which is `sp1_primitives::SP1ExtensionField`):
//! - every gadget's output equals the native result on edge and random inputs;
//! - non-free gate counts, taken in ExecuteMode and as GarbleMode ciphertexts (both must agree),
//!   equal `RESULTS.json` (`M14_WRITE_RESULTS=1` rewrites it);
//! - garbling then evaluating gives, on every output wire, the garbler's label of the native value.
use std::collections::BTreeMap;

use crossbeam::channel;
use garbled_snark_verifier::{
    AesCcrGateHasher, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, EvaluateMode,
        ExecuteMode, StreamingResult,
    },
};
use m14_circuit::{
    ext::{self, DTH_ROOT, Ext},
    field::{self as f, Fe, P},
    hash,
    sumcheck,
    sample,
};
use p3_field::{
    AbstractExtensionField, AbstractField, Field, PrimeField32, TwoAdicField,
    extension::{BinomialExtensionField, BinomiallyExtendable, HasFrobenius},
};
use p3_koala_bear::KoalaBear as KB;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

type EF = BinomialExtensionField<KB, 4>;
const CAP: usize = 1 << 22;
const TRIALS: usize = 48;

// ------------------------------------------------------------------ harness
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
struct GIn(usize);
impl CircuitInput for GIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, CTH: CiphertextHandler> EncodeInput<GarbleMode<H, CTH>> for GIn {
    fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<H, CTH>) {
        for id in w {
            let v = mode.issue_garbled_wire();
            mode.feed_wire(*id, v);
        }
    }
}
struct EIn {
    labels: Vec<GarbledWire>,
    bits: Vec<bool>,
}
impl CircuitInput for EIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.bits.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, SRC: CiphertextSource> EncodeInput<EvaluateMode<H, SRC>> for EIn {
    fn encode(&self, w: &Self::WireRepr, mode: &mut EvaluateMode<H, SRC>) {
        for (i, id) in w.iter().enumerate() {
            mode.feed_wire(*id, EvaluatedWire::new_from_garbled(&self.labels[i], self.bits[i]));
        }
    }
}
struct Count(u64);
impl CiphertextHandler for Count {
    type Result = u64;
    fn handle(&mut self, _ct: S) {
        self.0 += 1;
    }
    fn finalize(self) -> u64 {
        self.0
    }
}

// ------------------------------------------------------------------ operations under test
#[derive(Clone, Copy, Debug)]
enum Op {
    Canonical,
    Add,
    Sub,
    Neg,
    Double,
    Halve,
    Mul,
    Square,
    MulConst(u32),
    Inv,
    ExpPow2(usize),
    ExpConst(u64),
    Eq,
    IsZero,
    Select,
    Reduce(usize),
    Barrett62,
    SampleBase,
    PowConstBase(u32, usize),
    ExtAdd,
    ExtSub,
    ExtMul,
    ExtSquare,
    ExtMulBase,
    ExtMulConst([u32; 4]),
    ExtFrobenius(usize),
    ExtInv,
    ExtEq,
    ExtSelect,
    SampleExt,
    /// BLAKE3 of n bytes.
    Blake3(usize),
    /// The transcript script `SCRIPT`: all observed bytes in, all sampled bytes out.
    Script,
    /// Leaf hash of a row of n elements.
    LeafHash(usize),
    /// (row length, depth): row, index bits, siblings, expected root -> computed root, match bit.
    MerklePath(usize, usize),
    /// Replay of a recorded transcript of a real verification (1 = v1, 2 = v2 fixture):
    /// all observed bytes in, all sampled bytes out.
    Trace(u8),
    /// Sumcheck round checks (rounds, degree): claimed sum, polynomials, alphas -> ok, evaluation.
    SumcheckRounds(usize, usize),
}

/// A recorded transcript (`m13-verify` with `M13_TRANSCRIPT_TRACE`): runs of (sampled?, bytes).
fn trace_runs(v: u8) -> Vec<(bool, Vec<u8>)> {
    let path = format!("{}/fixtures/c4-v{v}-transcript.bin", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read(path).expect("transcript fixture");
    let (mut at, mut runs) = (0, Vec::new());
    while at < raw.len() {
        let kind = raw[at] == 1;
        let n = u32::from_le_bytes(raw[at + 1..at + 5].try_into().unwrap()) as usize;
        runs.push((kind, raw[at + 5..at + 5 + n].to_vec()));
        at += 5 + n;
    }
    runs
}

const FB: usize = f::BITS;

/// Transcript script: (observe n bytes) or (sample n bytes), in order.
#[derive(Clone, Copy, Debug)]
enum Step {
    Observe(usize),
    Sample(usize),
}
const SCRIPT: &[Step] = &[
    Step::Observe(4),
    Step::Sample(4),
    Step::Sample(8),
    Step::Observe(32),
    Step::Observe(16),
    Step::Sample(32),
    Step::Sample(33),
    Step::Observe(1100),
    Step::Sample(4),
    Step::Observe(1),
    Step::Sample(8),
];
fn script_lens() -> (usize, usize) {
    SCRIPT.iter().fold((0, 0), |(o, s), st| match st {
        Step::Observe(n) => (o + n, s),
        Step::Sample(n) => (o, s + n),
    })
}

impl Op {
    fn n_in(self) -> usize {
        use Op::*;
        match self {
            Canonical | Neg | Double | Halve | Square | MulConst(_) | Inv | ExpPow2(_) | ExpConst(_) | IsZero => FB,
            Add | Sub | Mul | Eq => 2 * FB,
            Select => 2 * FB + 1,
            Reduce(w) => w,
            Barrett62 => 62,
            SampleBase => 64,
            PowConstBase(_, n) => n,
            ExtAdd | ExtSub | ExtMul | ExtEq => 8 * FB,
            ExtSquare | ExtMulConst(_) | ExtFrobenius(_) | ExtInv => 4 * FB,
            ExtMulBase => 5 * FB,
            ExtSelect => 8 * FB + 1,
            SampleExt => 256,
            Blake3(n) => 8 * n,
            Script => 8 * script_lens().0,
            LeafHash(n) => n * FB,
            MerklePath(n, d) => n * FB + d + 256 * d + 256,
            Trace(v) => 8 * trace_runs(v).iter().filter(|r| !r.0).map(|r| r.1.len()).sum::<usize>(),
            SumcheckRounds(r, d) => (4 + r * (d + 1) * 4 + r * 4) * FB,
        }
    }
    fn build<C: garbled_snark_verifier::CircuitContext>(self, c: &mut C, w: &[WireId]) -> Vec<WireId> {
        use Op::*;
        let fe = |i: usize| Fe::from_wires(&w[FB * i..FB * (i + 1)]);
        let ex = |i: usize| Ext(std::array::from_fn(|j| fe(4 * i + j)));
        match self {
            Canonical => vec![f::is_canonical(c, w)],
            Add => f::add(c, &fe(0), &fe(1)).0,
            Sub => f::sub(c, &fe(0), &fe(1)).0,
            Neg => f::neg(c, &fe(0)).0,
            Double => f::double(c, &fe(0)).0,
            Halve => f::halve(c, &fe(0)).0,
            Mul => f::mul(c, &fe(0), &fe(1)).0,
            Square => f::square(c, &fe(0)).0,
            MulConst(k) => f::mul_const(c, &fe(0), k).0,
            Inv => f::inv(c, &fe(0)).0,
            ExpPow2(n) => f::exp_power_of_2(c, &fe(0), n).0,
            ExpConst(e) => f::exp_const(c, &fe(0), e).0,
            Eq => vec![f::eq(c, &fe(0), &fe(1))],
            IsZero => vec![f::is_zero(c, &fe(0))],
            Select => f::select(c, w[2 * FB], &fe(0), &fe(1)).0,
            Reduce(_) => f::reduce_wide(c, w).0,
            Barrett62 => f::reduce62(c, w).0,
            SampleBase => sample::base_from_le64(c, w).0,
            PowConstBase(b, _) => f::pow_const_base(c, b, w).0,
            ExtAdd => ext_wires(&ext::add(c, &ex(0), &ex(1))),
            ExtSub => ext_wires(&ext::sub(c, &ex(0), &ex(1))),
            ExtMul => ext_wires(&ext::mul(c, &ex(0), &ex(1))),
            ExtSquare => ext_wires(&ext::square(c, &ex(0))),
            ExtMulBase => ext_wires(&ext::mul_base(c, &ex(0), &fe(4))),
            ExtMulConst(k) => ext_wires(&ext::mul_const(c, &ex(0), k)),
            ExtFrobenius(k) => ext_wires(&ext::frobenius_k(c, &ex(0), k)),
            ExtInv => ext_wires(&ext::inv(c, &ex(0))),
            ExtEq => vec![ext::eq(c, &ex(0), &ex(1))],
            ExtSelect => ext_wires(&ext::select(c, w[8 * FB], &ex(0), &ex(1))),
            SampleExt => ext_wires(&sample::ext_from_le256(c, w)),
            Blake3(_) => hash::blake3(c, w),
            Script => {
                let mut t = hash::Transcript::new(hash::DOMAIN_V1);
                let (mut at, mut out) = (0, Vec::new());
                for st in SCRIPT {
                    match *st {
                        Step::Observe(n) => {
                            t.observe_bytes(&w[8 * at..8 * (at + n)]);
                            at += n;
                        }
                        Step::Sample(n) => out.extend(t.sample_bytes(c, n)),
                    }
                }
                out
            }
            LeafHash(n) => {
                let row: Vec<Fe> = (0..n).map(fe).collect();
                hash::leaf_hash(c, &row)
            }
            SumcheckRounds(r, d) => {
                let claim = ex(0);
                let polys: Vec<Vec<Ext>> = (0..r).map(|i| (0..=d).map(|k| ex(1 + i * (d + 1) + k)).collect()).collect();
                let alphas: Vec<Ext> = (0..r).map(|i| ex(1 + r * (d + 1) + i)).collect();
                let (ok, eval) = sumcheck::check_rounds(c, &claim, &polys, &alphas);
                let mut out = vec![ok];
                out.extend(ext_wires(&eval));
                out
            }
            Trace(v) => {
                let mut t = hash::Transcript::new(if v == 1 { hash::DOMAIN_V1 } else { hash::DOMAIN_V2 });
                let (mut at, mut out) = (0, Vec::new());
                for (sampled, bytes) in trace_runs(v) {
                    if sampled {
                        out.extend(t.sample_bytes(c, bytes.len()));
                    } else {
                        t.observe_bytes(&w[8 * at..8 * (at + bytes.len())]);
                        at += bytes.len();
                    }
                }
                out
            }
            MerklePath(n, d) => {
                let row: Vec<Fe> = (0..n).map(fe).collect();
                let mut at = n * FB;
                let index = w[at..at + d].to_vec();
                at += d;
                let sibs: Vec<Vec<WireId>> = (0..d).map(|i| w[at + 256 * i..at + 256 * (i + 1)].to_vec()).collect();
                at += 256 * d;
                let expect = &w[at..at + 256];
                let leaf = hash::leaf_hash(c, &row);
                let root = hash::path_root(c, &leaf, &index, &sibs);
                let ok = hash::digest_eq(c, &root, expect);
                let mut out = root;
                out.push(ok);
                out
            }
        }
    }
}

fn ext_wires(e: &Ext) -> Vec<WireId> {
    e.0.iter().flat_map(|x| x.0.iter().copied()).collect()
}

fn exec(op: Op, bits: Vec<bool>) -> Vec<bool> {
    assert_eq!(bits.len(), op.n_in(), "{op:?}");
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(Plain(bits), CAP, |c, w| op.build(c, w));
    r.output_value
}

/// Non-free gates, counted in ExecuteMode and as GarbleMode ciphertexts.
fn count(op: Op) -> u64 {
    let n = op.n_in();
    let e: StreamingResult<ExecuteMode, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(Plain(vec![false; n]), CAP, |c, w| op.build(c, w));
    let nf = e.gate_count.nonfree_gate_count();
    let g: StreamingResult<GarbleMode<AesCcrGateHasher, Count>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(n), CAP, 12, Count(0), |c, w| op.build(c, w));
    assert_eq!(nf, g.ciphertext_handler_result, "{op:?}: execute vs garble count");
    nf
}

/// Garble, then evaluate with the input labels of `bits`: every output label must be the garbler's
/// label for the plain output bit. Returns the plain output.
fn garble_evaluate(op: Op, bits: Vec<bool>) -> Vec<bool> {
    let seed = 7;
    let (tx, rx) = channel::unbounded();
    let g: StreamingResult<GarbleMode<AesCcrGateHasher, _>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(op.n_in()), CAP, seed, tx, |c, w| op.build(c, w));
    let mut rng = ChaChaRng::seed_from_u64(seed);
    let hasher = AesCcrGateHasher::from_rng(&mut rng);
    let e: StreamingResult<EvaluateMode<AesCcrGateHasher, _>, _, Vec<EvaluatedWire>> =
        CircuitBuilder::streaming_evaluation(
            EIn { labels: g.input_wire_values.clone(), bits: bits.clone() },
            CAP,
            g.true_wire_constant.select(true).to_u128(),
            g.false_wire_constant.select(false).to_u128(),
            hasher,
            rx,
            |c, w| op.build(c, w),
        );
    let plain = exec(op, bits);
    assert_eq!(e.output_value.len(), plain.len());
    for (i, b) in plain.iter().enumerate() {
        assert!(e.output_value[i].active_label == g.output_value[i].select(*b), "{op:?} output wire {i}");
        assert!(e.output_value[i].active_label != g.output_value[i].select(!*b), "{op:?} output wire {i}");
    }
    plain
}

// ------------------------------------------------------------------ encodings
fn bits(v: u128, n: usize) -> Vec<bool> {
    (0..n).map(|i| (v >> i) & 1 == 1).collect()
}
fn val(b: &[bool]) -> u128 {
    b.iter().enumerate().fold(0, |a, (i, &x)| a | ((x as u128) << i))
}
fn fe_bits(xs: &[u32]) -> Vec<bool> {
    xs.iter().flat_map(|&x| bits(x as u128, FB)).collect()
}
fn out_fes(b: &[bool]) -> Vec<u32> {
    b.chunks(FB).map(|c| val(c) as u32).collect()
}
fn kb(x: u32) -> KB {
    KB::from_canonical_u32(x)
}
fn ef(x: [u32; 4]) -> EF {
    EF::from_base_slice(&x.map(kb))
}
fn ef_vals(e: EF) -> [u32; 4] {
    let s: &[KB] = <EF as AbstractExtensionField<KB>>::as_base_slice(&e);
    [s[0].as_canonical_u32(), s[1].as_canonical_u32(), s[2].as_canonical_u32(), s[3].as_canonical_u32()]
}

fn edge_values() -> Vec<u32> {
    vec![0, 1, 2, 3, P - 1, P - 2, (P - 1) / 2, (P + 1) / 2, 1 << 24, (1 << 24) - 1, 1 << 30, (1 << 30) + 12345, DTH_ROOT]
}
fn samples(rng: &mut ChaChaRng) -> Vec<u32> {
    let mut v = edge_values();
    v.extend((0..TRIALS).map(|_| rng.gen_range(0..P)));
    v
}
fn pairs(rng: &mut ChaChaRng) -> Vec<(u32, u32)> {
    let e = edge_values();
    let mut v: Vec<(u32, u32)> = e.iter().flat_map(|&a| e.iter().map(move |&b| (a, b))).collect();
    v.extend((0..TRIALS).map(|_| (rng.gen_range(0..P), rng.gen_range(0..P))));
    v
}
fn ext_samples(rng: &mut ChaChaRng) -> Vec<[u32; 4]> {
    let mut v = vec![[0; 4], [1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [P - 1; 4], [P - 1, 0, 0, 0], [5, P - 1, 7, 1 << 24]];
    v.extend((0..TRIALS).map(|_| std::array::from_fn(|_| rng.gen_range(0..P))));
    v
}

fn constants() -> Vec<u32> {
    let mut rng = ChaChaRng::seed_from_u64(99);
    vec![2, 3, 11, 255, 256, P - 1, P - 2, P - 255, 1 << 24, DTH_ROOT, KB::two_adic_generator(24).as_canonical_u32(), rng.gen_range(256..P - 256)]
}

// ------------------------------------------------------------------ native agreement
#[test]
fn input_canonical_check() {
    let mut rng = ChaChaRng::seed_from_u64(1);
    let mut vals: Vec<u32> = vec![0, 1, P - 1, P, P + 1, 0x7fff_ffff, 0x7f00_0000, 0x7eff_ffff, 1 << 24, (1 << 24) - 1];
    vals.extend((0..256).map(|_| rng.gen_range(0..1u32 << 31)));
    vals.extend((0..256).map(|_| rng.gen_range(P..1u32 << 31)));
    for v in vals {
        assert_eq!(exec(Op::Canonical, bits(v as u128, FB))[0], v < P, "is_canonical({v:#x})");
    }
}

#[test]
fn base_field_matches_sp1() {
    let mut rng = ChaChaRng::seed_from_u64(2);
    for (a, b) in pairs(&mut rng) {
        let (x, y) = (kb(a), kb(b));
        let one = |op| out_fes(&exec(op, fe_bits(&[a, b])))[0];
        assert_eq!(one(Op::Add), (x + y).as_canonical_u32(), "add {a} {b}");
        assert_eq!(one(Op::Sub), (x - y).as_canonical_u32(), "sub {a} {b}");
        assert_eq!(one(Op::Mul), (x * y).as_canonical_u32(), "mul {a} {b}");
        assert_eq!(exec(Op::Eq, fe_bits(&[a, b]))[0], a == b);
        for s in [false, true] {
            let mut i = fe_bits(&[a, b]);
            i.push(s);
            assert_eq!(out_fes(&exec(Op::Select, i))[0], if s { b } else { a });
        }
    }
    for a in samples(&mut rng) {
        let x = kb(a);
        let one = |op| out_fes(&exec(op, fe_bits(&[a])))[0];
        assert_eq!(one(Op::Neg), (-x).as_canonical_u32(), "neg {a}");
        assert_eq!(one(Op::Double), x.double().as_canonical_u32(), "double {a}");
        assert_eq!(one(Op::Halve), x.halve().as_canonical_u32(), "halve {a}");
        assert_eq!(one(Op::Square), x.square().as_canonical_u32(), "square {a}");
        assert_eq!(one(Op::Inv), x.try_inverse().map_or(0, |v| v.as_canonical_u32()), "inv {a}");
        assert_eq!(one(Op::ExpPow2(5)), x.exp_power_of_2(5).as_canonical_u32());
        assert_eq!(one(Op::ExpConst(0x1234_5678_9abc)), x.exp_u64(0x1234_5678_9abc).as_canonical_u32());
        assert_eq!(exec(Op::IsZero, fe_bits(&[a]))[0], a == 0);
        for k in constants() {
            assert_eq!(one(Op::MulConst(k)), (x * kb(k)).as_canonical_u32(), "mul_const {a} {k}");
        }
    }
}

/// `reduce62` (M12's circuit) keeps 31 bits of the Barrett quotient, so it is exact for
/// x < p * 2^31; every caller passes less than p^2 (products, 61-bit low halves). The native model
/// with 2 corrections is exact below p^2 (sweeps below); the circuit is checked at the boundaries
/// and shown wrong at 2^62 - 1, where the quotient needs 32 bits.
#[test]
fn barrett_reduction_domain() {
    let p2 = (P as u128) * (P as u128);
    let mut rng = ChaChaRng::seed_from_u64(30);
    let model = |x: u128| assert_eq!(m12_gates::KOALA.barrett_native(x).0 as u128, x % P as u128, "model {x:#x}");
    (p2 - (1 << 22)..p2).for_each(model);
    ((1u128 << 61) - (1 << 22)..(1u128 << 61) + (1 << 22)).for_each(model);
    (0..1 << 22).for_each(|_| model(rng.r#gen::<u128>() % p2));
    let circuit = |x: u128| val(&exec(Op::Barrett62, bits(x, 62))) as u32;
    let mut edge: Vec<u128> = (p2 - 512..p2).chain((1u128 << 61) - 256..(1u128 << 61) + 256).collect();
    edge.extend((0..512).map(|_| rng.r#gen::<u128>() % p2));
    for x in edge {
        assert_eq!(circuit(x) as u128, x % P as u128, "reduce62 circuit {x:#x}");
    }
    let top = (1u128 << 62) - 1;
    assert_ne!(circuit(top) as u128, top % P as u128);
}

#[test]
fn reduction_sampler_and_powers() {
    let mut rng = ChaChaRng::seed_from_u64(3);
    for w in [61usize, 62, 64, 66, 69] {
        let mut vals: Vec<u128> = vec![0, 1, P as u128, (1u128 << w) - 1, (P as u128) * (P as u128) - 1];
        vals.extend((0..TRIALS).map(|_| rng.r#gen::<u128>() & ((1u128 << w) - 1)));
        for v in vals {
            let v = v & ((1u128 << w) - 1);
            assert_eq!(val(&exec(Op::Reduce(w), bits(v, w))) as u32, (v % P as u128) as u32, "reduce{w} {v:#x}");
        }
    }
    for _ in 0..TRIALS {
        let b: [u8; 8] = rng.r#gen();
        let v = u64::from_le_bytes(b) as u128;
        assert_eq!(out_fes(&exec(Op::SampleBase, bits(v, 64)))[0], sample::base_from_le64_native(b));
    }
    let g = KB::two_adic_generator(24);
    for _ in 0..16 {
        let idx: u32 = rng.gen_range(0..1 << 24);
        let got = out_fes(&exec(Op::PowConstBase(g.as_canonical_u32(), 24), bits(idx as u128, 24)))[0];
        assert_eq!(got, g.exp_u64(idx as u64).as_canonical_u32(), "g^{idx}");
    }
    assert_eq!(DTH_ROOT, <KB as BinomiallyExtendable<4>>::dth_root().as_canonical_u32());
}

#[test]
fn extension_field_matches_sp1() {
    let mut rng = ChaChaRng::seed_from_u64(4);
    let xs = ext_samples(&mut rng);
    for (i, a) in xs.iter().enumerate() {
        let b = xs[(i * 7 + 3) % xs.len()];
        let (x, y) = (ef(*a), ef(b));
        let two: Vec<bool> = fe_bits(a).into_iter().chain(fe_bits(&b)).collect();
        let res = |op, inp: Vec<bool>| -> [u32; 4] { out_fes(&exec(op, inp)).try_into().unwrap() };
        assert_eq!(res(Op::ExtAdd, two.clone()), ef_vals(x + y));
        assert_eq!(res(Op::ExtSub, two.clone()), ef_vals(x - y));
        assert_eq!(res(Op::ExtMul, two.clone()), ef_vals(x * y), "ext mul {a:?} {b:?}");
        assert_eq!(exec(Op::ExtEq, two.clone())[0], a == &b);
        let mut sel = two.clone();
        sel.push(true);
        assert_eq!(res(Op::ExtSelect, sel), b);
        assert_eq!(res(Op::ExtSquare, fe_bits(a)), ef_vals(x.square()), "ext square {a:?}");
        assert_eq!(res(Op::ExtInv, fe_bits(a)), x.try_inverse().map_or([0; 4], ef_vals), "ext inv {a:?}");
        for k in 0..4 {
            assert_eq!(res(Op::ExtFrobenius(k), fe_bits(a)), ef_vals(x.repeated_frobenius(k)), "frobenius^{k}");
        }
        let s = b[1];
        let mb: Vec<bool> = fe_bits(a).into_iter().chain(fe_bits(&[s])).collect();
        assert_eq!(res(Op::ExtMulBase, mb), ef_vals(x * kb(s)));
        let k = [b[0], b[3], 0, 17];
        assert_eq!(res(Op::ExtMulConst(k), fe_bits(a)), ef_vals(x * ef(k)), "ext mul_const");
    }
    for _ in 0..TRIALS {
        let b: [u8; 32] = rng.r#gen();
        let inp: Vec<bool> = b.iter().flat_map(|y| bits(*y as u128, 8)).collect();
        let want: [u32; 4] = std::array::from_fn(|i| sample::base_from_le64_native(b[8 * i..8 * i + 8].try_into().unwrap()));
        assert_eq!(out_fes(&exec(Op::SampleExt, inp)), want.to_vec());
    }
}

// ------------------------------------------------------------------ BLAKE3, transcript, Merkle
fn bytes_bits(b: &[u8]) -> Vec<bool> {
    b.iter().flat_map(|y| bits(*y as u128, 8)).collect()
}
fn bits_bytes(b: &[bool]) -> Vec<u8> {
    b.chunks(8).map(|c| val(c) as u8).collect()
}

/// m13 `Blake3Transcript` semantics (nova-bitvm3/m13/verify/src/ctx.rs), natively.
struct NativeTranscript {
    input: Vec<u8>,
    output: Vec<u8>,
    compressions: u64,
}
impl NativeTranscript {
    fn new(init: &[u8]) -> Self {
        NativeTranscript { input: init.to_vec(), output: Vec::new(), compressions: 0 }
    }
    fn observe(&mut self, b: u8) {
        self.output.clear();
        self.input.push(b);
    }
    fn sample(&mut self) -> u8 {
        if self.output.is_empty() {
            let inputs: Vec<u8> = self.input.drain(..).collect();
            self.compressions += hash::compressions(inputs.len());
            let out = *blake3::hash(&inputs).as_bytes();
            self.output = out.to_vec();
            self.input.extend(out);
        }
        self.output.pop().unwrap()
    }
}

#[test]
fn blake3_any_length_matches_crate() {
    let mut rng = ChaChaRng::seed_from_u64(6);
    for n in [0usize, 1, 31, 32, 63, 64, 65, 127, 128, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 5000] {
        let msg: Vec<u8> = (0..n).map(|_| rng.r#gen()).collect();
        let got = bits_bytes(&exec(Op::Blake3(n), bytes_bits(&msg)));
        assert_eq!(got, blake3::hash(&msg).as_bytes().to_vec(), "blake3 of {n} bytes");
    }
}

#[test]
fn transcript_matches_m13_semantics() {
    let mut rng = ChaChaRng::seed_from_u64(8);
    let (n_obs, n_smp) = script_lens();
    for _ in 0..4 {
        let observed: Vec<u8> = (0..n_obs).map(|_| rng.r#gen()).collect();
        let mut t = NativeTranscript::new(hash::DOMAIN_V1);
        let (mut at, mut want) = (0, Vec::new());
        for st in SCRIPT {
            match *st {
                Step::Observe(n) => {
                    observed[at..at + n].iter().for_each(|b| t.observe(*b));
                    at += n;
                }
                Step::Sample(n) => want.extend((0..n).map(|_| t.sample())),
            }
        }
        assert_eq!(want.len(), n_smp);
        assert_eq!(bits_bytes(&exec(Op::Script, bytes_bits(&observed))), want);
    }
}

/// The transcripts of the two real verifications of the c4 final proof (v1 and v2 fixtures in
/// nova-bitvm3/m13/fixtures), recorded byte by byte by `m13-verify`: given every observed byte,
/// the circuit transcript produces every sampled byte.
#[test]
fn transcript_replays_real_verifications() {
    for v in [1u8, 2] {
        let runs = trace_runs(v);
        let observed: Vec<u8> = runs.iter().filter(|r| !r.0).flat_map(|r| r.1.clone()).collect();
        let sampled: Vec<u8> = runs.iter().filter(|r| r.0).flat_map(|r| r.1.clone()).collect();
        // Same proof shape, so the same observed bytes; v2 samples 8 bytes per field challenge.
        assert_eq!((observed.len(), sampled.len()), if v == 1 { (39_568, 8_836) } else { (39_568, 17_124) });
        assert_eq!(bits_bytes(&exec(Op::Trace(v), bytes_bits(&observed))), sampled, "v{v} transcript");
    }
}

/// The c4 v2 proof's zerocheck sumcheck (`m13-verify dump-zerocheck-v2`): (claimed sum,
/// polynomials, point in SP1's order, evaluation).
fn zerocheck_fixture() -> ([u32; 4], Vec<Vec<[u32; 4]>>, Vec<[u32; 4]>, [u32; 4]) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/c4-v2-zerocheck.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let e = |x: &serde_json::Value| -> [u32; 4] { serde_json::from_value(x["value"].clone()).unwrap() };
    let polys = v["univariate_polys"].as_array().unwrap().iter().map(|p| p["coefficients"].as_array().unwrap().iter().map(e).collect()).collect();
    let point = v["point_and_eval"][0]["values"].as_array().unwrap().iter().map(e).collect();
    (e(&v["claimed_sum"]), polys, point, e(&v["point_and_eval"][1]))
}

#[test]
fn sumcheck_rounds_accept_the_real_zerocheck() {
    let (claim, polys, point, eval) = zerocheck_fixture();
    let (r, d) = (polys.len(), polys[0].len() - 1);
    assert_eq!((r, d), (21, 4));
    // SP1 inserts each alpha at the front of the point: sampling order is the reverse.
    let alphas: Vec<[u32; 4]> = point.iter().rev().copied().collect();
    let input = |claim: [u32; 4], polys: &[Vec<[u32; 4]>]| -> Vec<bool> {
        let mut xs = vec![claim];
        polys.iter().for_each(|p| xs.extend(p.iter().copied()));
        xs.extend(alphas.iter().copied());
        xs.iter().flat_map(|x| fe_bits(x)).collect()
    };
    // native cross-check with SP1's extension type
    let ev = |p: &[[u32; 4]], x: EF| p.iter().rev().fold(EF::zero(), |acc, k| acc * x + ef(*k));
    let s01 = |p: &[[u32; 4]]| ef(p[0]) + p.iter().map(|k| ef(*k)).sum::<EF>();
    assert_eq!(s01(&polys[0]), ef(claim));
    for i in 1..r {
        assert_eq!(ev(&polys[i - 1], ef(alphas[i - 1])), s01(&polys[i]));
    }
    assert_eq!(ev(&polys[r - 1], ef(alphas[r - 1])), ef(eval));

    let out = exec(Op::SumcheckRounds(r, d), input(claim, &polys));
    assert!(out[0], "real zerocheck rounds rejected");
    assert_eq!(out_fes(&out[1..]), eval.to_vec(), "final evaluation");
    let mut bad = polys.clone();
    bad[7][2][1] = (bad[7][2][1] + 1) % P;
    assert!(!exec(Op::SumcheckRounds(r, d), input(claim, &bad))[0], "changed coefficient accepted");
    let mut c2 = claim;
    c2[0] = (c2[0] + 1) % P;
    assert!(!exec(Op::SumcheckRounds(r, d), input(c2, &polys))[0], "changed claim accepted");
}

fn native_leaf(row: &[u32]) -> [u8; 32] {
    let bytes: Vec<u8> = row.iter().flat_map(|x| x.to_le_bytes()).collect();
    *blake3::hash(&bytes).as_bytes()
}
fn native_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut b = l.to_vec();
    b.extend_from_slice(r);
    *blake3::hash(&b).as_bytes()
}

#[test]
fn merkle_path_matches_native_tree() {
    let mut rng = ChaChaRng::seed_from_u64(9);
    let (n, depth) = (5usize, 4usize);
    let rows: Vec<Vec<u32>> = (0..1 << depth).map(|_| (0..n).map(|_| rng.gen_range(0..P)).collect()).collect();
    let mut levels: Vec<Vec<[u8; 32]>> = vec![rows.iter().map(|r| native_leaf(r)).collect()];
    for _ in 0..depth {
        let prev = levels.last().unwrap();
        levels.push(prev.chunks(2).map(|p| native_node(&p[0], &p[1])).collect());
    }
    let root = levels[depth][0];
    for idx in [0usize, 5, 10, 15] {
        let sibs: Vec<[u8; 32]> = (0..depth).map(|h| levels[h][(idx >> h) ^ 1]).collect();
        let mk = |root: [u8; 32], sibs: &[[u8; 32]]| -> Vec<bool> {
            let mut inp = fe_bits(&rows[idx]);
            inp.extend((0..depth).map(|h| (idx >> h) & 1 == 1));
            sibs.iter().for_each(|s| inp.extend(bytes_bits(s)));
            inp.extend(bytes_bits(&root));
            inp
        };
        let out = exec(Op::MerklePath(n, depth), mk(root, &sibs));
        assert_eq!(bits_bytes(&out[..256]), root.to_vec(), "root from leaf {idx}");
        assert!(out[256], "path {idx} accepted");
        let mut bad = sibs.clone();
        bad[2][7] ^= 1;
        assert!(!exec(Op::MerklePath(n, depth), mk(root, &bad))[256], "tampered sibling rejected");
        let mut other = root;
        other[0] ^= 0x80;
        assert!(!exec(Op::MerklePath(n, depth), mk(other, &sibs))[256], "wrong root rejected");
    }
}

// ------------------------------------------------------------------ garbled evaluation
#[test]
fn garble_then_evaluate() {
    let mut rng = ChaChaRng::seed_from_u64(5);
    for _ in 0..3 {
        let (a, b): ([u32; 4], [u32; 4]) = (std::array::from_fn(|_| rng.gen_range(0..P)), std::array::from_fn(|_| rng.gen_range(0..P)));
        let inp: Vec<bool> = fe_bits(&a).into_iter().chain(fe_bits(&b)).collect();
        let got: [u32; 4] = out_fes(&garble_evaluate(Op::ExtMul, inp)).try_into().unwrap();
        assert_eq!(got, ef_vals(ef(a) * ef(b)));
        let x = rng.gen_range(1..P);
        assert_eq!(out_fes(&garble_evaluate(Op::Inv, fe_bits(&[x])))[0], kb(x).inverse().as_canonical_u32());
        let s: [u8; 8] = rng.r#gen();
        let got = out_fes(&garble_evaluate(Op::SampleBase, bits(u64::from_le_bytes(s) as u128, 64)))[0];
        assert_eq!(got, sample::base_from_le64_native(s));
    }
    // the canonical check on a non-canonical input
    assert!(!garble_evaluate(Op::Canonical, bits((P + 5) as u128, FB))[0]);
    // a transcript script with a multi-chunk absorb
    let observed: Vec<u8> = (0..script_lens().0).map(|_| rng.r#gen()).collect();
    let mut t = NativeTranscript::new(hash::DOMAIN_V1);
    let (mut at, mut want) = (0, Vec::new());
    for st in SCRIPT {
        match *st {
            Step::Observe(n) => {
                observed[at..at + n].iter().for_each(|b| t.observe(*b));
                at += n;
            }
            Step::Sample(n) => want.extend((0..n).map(|_| t.sample())),
        }
    }
    assert_eq!(bits_bytes(&garble_evaluate(Op::Script, bytes_bits(&observed))), want);
    // the real zerocheck sumcheck of the c4 v2 proof: accepted, with SP1's final evaluation
    let (claim, polys, point, eval) = zerocheck_fixture();
    let mut xs = vec![claim];
    polys.iter().for_each(|p| xs.extend(p.iter().copied()));
    xs.extend(point.iter().rev().copied());
    let out = garble_evaluate(Op::SumcheckRounds(21, 4), xs.iter().flat_map(|x| fe_bits(x)).collect());
    assert!(out[0]);
    assert_eq!(out_fes(&out[1..]), eval.to_vec());
}

// ------------------------------------------------------------------ gate counts
fn measured() -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    let mut put = |k: &str, op: Op| {
        let n = count(op);
        eprintln!("M14 {k} nonfree={n}");
        m.insert(k.to_string(), n);
    };
    put("base_is_canonical", Op::Canonical);
    put("base_add", Op::Add);
    put("base_sub", Op::Sub);
    put("base_neg", Op::Neg);
    put("base_double", Op::Double);
    put("base_halve", Op::Halve);
    put("base_mul", Op::Mul);
    put("base_square", Op::Square);
    put("base_mul_const_3", Op::MulConst(3));
    put("base_mul_const_11", Op::MulConst(11));
    put("base_mul_const_neg1", Op::MulConst(P - 1));
    put("base_mul_const_2pow24", Op::MulConst(1 << 24));
    put("base_mul_const_dth_root", Op::MulConst(DTH_ROOT));
    put("base_mul_const_two_adic_gen24", Op::MulConst(KB::two_adic_generator(24).as_canonical_u32()));
    put("base_inv", Op::Inv);
    put("base_eq", Op::Eq);
    put("base_is_zero", Op::IsZero);
    put("base_select", Op::Select);
    put("reduce_wide_62", Op::Reduce(62));
    put("reduce_wide_66", Op::Reduce(66));
    put("sample_base_v2_u64_mod_p", Op::SampleBase);
    put("pow_two_adic_gen24_by_24bit_index", Op::PowConstBase(KB::two_adic_generator(24).as_canonical_u32(), 24));
    put("ext_add", Op::ExtAdd);
    put("ext_sub", Op::ExtSub);
    put("ext_mul", Op::ExtMul);
    put("ext_square", Op::ExtSquare);
    put("ext_mul_base", Op::ExtMulBase);
    put("ext_frobenius", Op::ExtFrobenius(1));
    put("ext_inv", Op::ExtInv);
    put("ext_eq", Op::ExtEq);
    put("ext_select", Op::ExtSelect);
    put("sample_ext_v2", Op::SampleExt);
    put("blake3_64_bytes_node", Op::Blake3(64));
    put("blake3_1025_bytes", Op::Blake3(1025));
    put("leaf_hash_row_of_16", Op::LeafHash(16));
    put("merkle_path_depth_4_row_of_5_with_root_check", Op::MerklePath(5, 4));
    put("transcript_script", Op::Script);
    put("transcript_c4_v1_real_verification", Op::Trace(1));
    put("transcript_c4_v2_real_verification", Op::Trace(2));
    put("sumcheck_rounds_21_degree4_zerocheck_shape", Op::SumcheckRounds(21, 4));
    m
}

#[test]
fn gate_counts() {
    let got = measured();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/RESULTS.json");
    if std::env::var("M14_WRITE_RESULTS").as_deref() == Ok("1") {
        let doc = serde_json::json!({
            "metric": "non-free gates (AND-class) = ExecuteMode nonfree_gate_count = GarbleMode ciphertexts; XOR/NOT free; constants folded",
            "non_free_gates": got,
        });
        std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    }
    let rec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).expect("RESULTS.json")).unwrap();
    let rec: BTreeMap<String, u64> = serde_json::from_value(rec["non_free_gates"].clone()).unwrap();
    assert_eq!(rec, got, "gate counts differ from RESULTS.json");
}
