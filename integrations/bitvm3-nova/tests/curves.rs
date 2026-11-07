#![cfg(feature = "curve-reference")]

use ff::PrimeField;
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire, GarbledWire, GateHasher,
    S, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, EvaluateMode,
        ExecuteMode, FileSource, GarbleMode, StreamingResult,
    },
    nova::{
        Word,
        curve::{self, AffinePoint, PastaCurve},
    },
};
use halo2curves::{
    CurveAffine,
    group::Curve,
    pasta::{Fp, Fq, Pallas, Vesta},
};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::io::{BufWriter, Write};

const N: usize = 3 * 513 + 256;
const CAP: usize = 65536; // allocator reservation, not an RSS limit

#[derive(Clone, Debug, PartialEq, Eq)]
struct Point {
    x: BigUint,
    y: BigUint,
    infinity: bool,
}

fn point<A: CurveAffine>(p: A) -> Point {
    // halo2curves permits Coordinates::from_xy(0,0) for the identity.
    // The presence of coordinates therefore cannot determine infinity.
    if bool::from(p.is_identity()) {
        return Point { x: 0u8.into(), y: 0u8.into(), infinity: true };
    }
    let coords = Option::<halo2curves::Coordinates<A>>::from(p.coordinates())
        .expect("finite oracle point has coordinates");
    Point {
        x: BigUint::from_bytes_le(coords.x().to_repr().as_ref()),
        y: BigUint::from_bytes_le(coords.y().to_repr().as_ref()),
        infinity: false,
    }
}

fn modulus(curve: PastaCurve) -> BigUint {
    BigUint::from_bytes_le(
        &curve.base_field().modulus_le().iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>()
    )
}

fn slope(p: &Point, q: &Point, m: &BigUint) -> BigUint {
    if p.infinity || q.infinity || (p.x == q.x && (&p.y + &q.y) % m == BigUint::from(0u8)) {
        return 0u8.into();
    }
    let (num, den) = if p.x == q.x {
        ((&p.x * &p.x * 3u8) % m, (&p.y * 2u8) % m)
    } else {
        ((&q.y + m - &p.y) % m, (&q.x + m - &p.x) % m)
    };
    (num * den.modpow(&(m - 2u8), m)) % m
}

fn bits(p: &Point, q: &Point, r: &Point, s: &BigUint) -> [bool; N] {
    std::array::from_fn(|i| {
        if i >= 1539 { return s.bit((i - 1539) as u64); }
        let point = [p, q, r][i / 513];
        match i % 513 {
            512 => point.infinity,
            j if j < 256 => point.x.bit(j as u64),
            j => point.y.bit((j - 256) as u64),
        }
    })
}

fn circuit<C: CircuitContext>(ctx: &mut C, curve: PastaCurve, w: &[WireId; N]) -> WireId {
    let p = |offset: usize| AffinePoint {
        x: w[offset..offset + 256].try_into().unwrap(),
        y: w[offset + 256..offset + 512].try_into().unwrap(),
        infinity: w[offset + 512],
    };
    let s: Word = w[1539..].try_into().unwrap();
    curve::check_add(ctx, curve, &p(0), &p(513), &p(1026), &s)
}

fn execute(curve: PastaCurve, p: &Point, q: &Point, r: &Point, s: &BigUint) -> bool {
    let run: StreamingResult<ExecuteMode, _, bool> = CircuitBuilder::streaming_execute(
        bits(p, q, r, s), CAP, |ctx, w| circuit(ctx, curve, w)
    );
    run.output_value
}

const PAIRS: [(i64, i64); 14] = [
    (0, 0), (0, 1), (1, 0), (1, 1), (1, 2), (2, 1), (1, -1),
    (2, -2), (2, 2), (3, 5), (8, 13), (17, 31), (-3, 5), (-7, -11),
];

fn fixtures(curve: PastaCurve) -> Vec<(Point, Point, Point)> {
    macro_rules! build {
        ($group:ty, $scalar:ty) => {{
            let at = |i: i64| {
                let p = <$group>::generator() * <$scalar>::from(i.unsigned_abs());
                if i < 0 { -p } else { p }
            };
            PAIRS.iter().map(|(a, b)| {
                let p = at(*a);
                let q = at(*b);
                (point(p.to_affine()), point(q.to_affine()), point((p + q).to_affine()))
            }).collect()
        }};
    }
    match curve {
        PastaCurve::Pallas => build!(Pallas, Fq),
        PastaCurve::Vesta => build!(Vesta, Fp),
    }
}

#[test]
fn oracle_identity_encoding_is_explicit() {
    let identity = Point { x: 0u8.into(), y: 0u8.into(), infinity: true };
    for curve in [PastaCurve::Pallas, PastaCurve::Vesta] {
        let cases = fixtures(curve);
        assert_eq!(cases[0], (identity.clone(), identity.clone(), identity.clone()));
        assert_eq!(cases[1].0, identity);
        assert!(!cases[1].1.infinity);
        assert_eq!(cases[1].1, cases[1].2);
        assert_eq!(cases[6].2, identity);
        for (p, q, r) in &cases {
            for v in [p, q, r] {
                let m = modulus(curve);
                assert!(v.x < m && v.y < m);
                if v.infinity {
                    assert_eq!(v, &identity);
                } else {
                    assert_eq!((&v.y * &v.y) % &m, (&v.x * &v.x * &v.x + 5u8) % &m);
                }
            }
        }
    }
}

#[test]
fn complete_addition_matches_halo2curves() {
    for curve in [PastaCurve::Pallas, PastaCurve::Vesta] {
        let m = modulus(curve);
        let cases = fixtures(curve);
        for (i, (p, q, r)) in cases.iter().enumerate() {
            let s = slope(p, q, &m);
            assert!(execute(curve, p, q, r, &s), "valid {curve:?} case {i}: {p:?} + {q:?} = {r:?}");
            assert!(!execute(curve, p, q, r, &((&s + 1u8) % &m)), "slope {curve:?} case {i}");
            // Substitute another on-curve output, ensuring membership alone is insufficient.
            let wrong = if r.infinity { &cases[1].2 } else { &cases[0].2 };
            assert!(!execute(curve, p, q, wrong, &s), "output {curve:?} case {i}");
        }
    }
}

#[test]
fn rejects_noncanonical_coordinates_flags_and_off_curve_points() {
    for curve in [PastaCurve::Pallas, PastaCurve::Vesta] {
        let m = modulus(curve);
        let (p, q, r) = fixtures(curve)[4].clone();
        let s = slope(&p, &q, &m);
        for port in 0..7 {
            let mut pts = [p.clone(), q.clone(), r.clone()];
            let mut bad_s = s.clone();
            if port == 6 { bad_s = m.clone(); }
            else if port % 2 == 0 { pts[port / 2].x = m.clone(); }
            else { pts[port / 2].y = m.clone(); }
            assert!(!execute(curve, &pts[0], &pts[1], &pts[2], &bad_s));
        }
        for port in 0..3 {
            let mut pts = [p.clone(), q.clone(), r.clone()];
            pts[port].infinity = true; // nonzero coordinates attached to infinity
            assert!(!execute(curve, &pts[0], &pts[1], &pts[2], &s));
            pts[port] = Point { x: 0u8.into(), y: 0u8.into(), infinity: false };
            assert!(!execute(curve, &pts[0], &pts[1], &pts[2], &s));
        }
    }
}

struct GarbleInput;
impl CircuitInput for GarbleInput {
    type WireRepr = [WireId; N];
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        std::array::from_fn(|_| issue())
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.to_vec() }
}
impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H, T>> for GarbleInput {
    fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<H, T>) {
        for id in w {
            let value = mode.issue_garbled_wire();
            mode.feed_wire(*id, value);
        }
    }
}
struct EvalInput(Vec<EvaluatedWire>);
impl CircuitInput for EvalInput {
    type WireRepr = [WireId; N];
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        std::array::from_fn(|_| issue())
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.to_vec() }
}
impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvalInput {
    fn encode(&self, w: &Self::WireRepr, mode: &mut M) {
        assert_eq!(w.len(), self.0.len());
        for (id, v) in w.iter().zip(&self.0) { mode.feed_wire(*id, v.clone()); }
    }
}
struct Sink {
    writer: BufWriter<std::fs::File>,
    hash: Blake3AccumulatingHash,
    count: u64,
}
impl CiphertextHandler for Sink {
    type Result = ([u8; 32], u64);
    fn handle(&mut self, ct: S) {
        self.writer.write_all(&ct.to_bytes()).unwrap();
        self.hash.update(ct);
        self.count += 1;
    }
    fn finalize(mut self) -> Self::Result {
        self.writer.flush().unwrap();
        (self.hash.finalize(), self.count)
    }
}

#[test]
fn disk_streamed_curve_garbling_matches_native_for_all_branches() {
    for curve in [PastaCurve::Pallas, PastaCurve::Vesta] {
        // Reusing the test circuit with both input labels is for conformance only.
        let seed = 6003u64;
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let hasher = AesCcrGateHasher::from_rng(&mut rng);
        let path = std::env::temp_dir().join(format!("nova-m3-{}-{curve:?}.ct", std::process::id()));
        let sink = Sink {
            writer: BufWriter::with_capacity(65536, std::fs::File::create(&path).unwrap()),
            hash: Blake3AccumulatingHash::default(), count: 0,
        };
        let g: StreamingResult<GarbleMode<AesCcrGateHasher, Sink>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling(GarbleInput, CAP, seed, sink,
                |ctx, w| circuit(ctx, curve, w));
        let (digest, count) = g.ciphertext_handler_result;
        let bytes = std::fs::metadata(&path).unwrap().len();
        assert_eq!(bytes, count * 16);
        eprintln!("M3 curve={curve:?} nonfree={count} ciphertext_bytes={bytes} gates={}", g.gate_count);
        let m = modulus(curve);
        let cases = fixtures(curve);
        for i in [0, 1, 2, 3, 4, 6] {
            let (p, q, r) = &cases[i];
            let s = slope(p, q, &m);
            for (candidate, expected) in [(s.clone(), true), ((&s + 1u8) % &m, false)] {
                let input = EvalInput(g.input_wire_values.iter().zip(bits(p, q, r, &candidate))
                    .map(|(w, b)| EvaluatedWire::new_from_garbled(w, b)).collect());
                let e: StreamingResult<EvaluateMode<AesCcrGateHasher, FileSource>, _, EvaluatedWire> =
                    CircuitBuilder::streaming_evaluation(input, CAP,
                        g.true_wire_constant.label1.to_u128(), g.false_wire_constant.label0.to_u128(),
                        hasher.clone(), FileSource::from_path(&path).unwrap(),
                        |ctx, w| circuit(ctx, curve, w));
                assert_eq!(e.output_value.active_label, g.output_value.select(expected));
                assert_eq!(e.ciphertext_handler_result, digest);
            }
        }
        std::fs::remove_file(path).unwrap();
    }
}
