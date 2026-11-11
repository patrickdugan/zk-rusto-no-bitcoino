//! The complete final verifier garbled and evaluated: the garbler streams its ciphertexts through a
//! bounded channel to an evaluator running at the same time, which holds only the input labels of
//! a proof's bits. For the real proof the evaluator's output label must be the garbler's label
//! for "accept"; for a mutated proof, the label for "reject".
use crossbeam::channel;
use garbled_snark_verifier::{
    AesCcrGateHasher, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, EvaluateMode,
        StreamingResult,
    },
};
use m14_e2e::{
    full::{self, Known},
    native,
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

const CAP: usize = 1 << 24;
const SEED: u64 = 0x6d31_345f_6532_65;

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
struct Discard;
impl CiphertextHandler for Discard {
    type Result = ();
    fn handle(&mut self, _ct: garbled_snark_verifier::S) {}
    fn finalize(self) {}
}

/// Garble and evaluate concurrently; returns (evaluator's label == garbler's accept label,
/// == reject label, ciphertexts).
fn garble_and_evaluate(proof: &native::Proof, expect: &m13_verify::FinalStatement, bits: Vec<bool>) -> (bool, bool, u64) {
    let n = bits.len();
    // The garbler's input and constant labels depend only on the seed: a trivial garbling with the
    // same seed reproduces them (the evaluator receives the labels of its bits up front).
    let pre: StreamingResult<GarbleMode<AesCcrGateHasher, Discard>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(n), 1 << 20, SEED, Discard, |_c, w| vec![w[0]]);
    let labels = pre.input_wire_values.clone();
    let (t_label, f_label) = (pre.true_wire_constant.select(true).to_u128(), pre.false_wire_constant.select(false).to_u128());

    let (tx, rx) = channel::bounded(1 << 20);
    let labels_g = labels.clone();
    std::thread::scope(|s| {
        let garbler = s.spawn(move || {
            let k = &Known::new(proof, expect);
            let g: StreamingResult<GarbleMode<AesCcrGateHasher, _>, _, Vec<GarbledWire>> =
                CircuitBuilder::streaming_garbling(GIn(n), CAP, SEED, tx, |c, w| vec![full::final_verifier(c, k, w)]);
            assert!(g.input_wire_values == labels_g, "input labels differ from the reproduced ones");
            g.output_value[0].clone()
        });
        let evaluator = s.spawn(move || {
            let k = &Known::new(proof, expect);
            let mut rng = ChaChaRng::seed_from_u64(SEED);
            let hasher = AesCcrGateHasher::from_rng(&mut rng);
            let e: StreamingResult<EvaluateMode<AesCcrGateHasher, _>, _, Vec<EvaluatedWire>> = CircuitBuilder::streaming_evaluation(
                EIn { labels: labels.clone(), bits },
                CAP,
                t_label,
                f_label,
                hasher,
                rx,
                |c, w| vec![full::final_verifier(c, k, w)],
            );
            (e.output_value[0].active_label, e.gate_count.nonfree_gate_count())
        });
        let out = garbler.join().unwrap();
        let (label, gates) = evaluator.join().unwrap();
        (label == out.select(true), label == out.select(false), gates)
    })
}

const STATEMENT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/c4-statement.json");

#[test]
fn garbled_final_verifier_accepts_the_real_proof_and_rejects_a_mutation() {
    let proof = native::load(native::FIXTURE_V2);
    let expect: m13_verify::FinalStatement = serde_json::from_slice(&std::fs::read(STATEMENT).unwrap()).unwrap();

    let bits = native::bits(&full::items(&proof));

    let t = std::time::Instant::now();
    let (accept, reject, gates) = garble_and_evaluate(&proof, &expect, bits.clone());
    eprintln!("M14-E2E garbled+evaluated: {gates} ciphertexts, {:.1} s", t.elapsed().as_secs_f64());
    assert!(accept && !reject, "evaluator did not obtain the accept label for the real proof");

    let mut bad = bits;
    let at = bad.len() - 40;
    bad[at] = !bad[at];
    let (accept, reject, _) = garble_and_evaluate(&proof, &expect, bad);
    assert!(reject && !accept, "evaluator did not obtain the reject label for a mutated proof");
}

const A_PROOF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/a-wrap-blake3-v2.bin");
const A_STATEMENT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/a-statement.json");

/// Guest A (the Nova verifier): the circuit is garbled from the control proof's shape and A's
/// statement, and the evaluator holding only the labels of A's proof bits obtains "accept".
#[test]
fn garbled_final_verifier_accepts_guest_a() {
    let reference = native::load(native::FIXTURE_V2);
    let a = native::load(A_PROOF);
    let expect: m13_verify::FinalStatement = serde_json::from_slice(&std::fs::read(A_STATEMENT).unwrap()).unwrap();
    let t = std::time::Instant::now();
    let (accept, reject, gates) = garble_and_evaluate(&reference, &expect, native::bits(&full::items(&a)));
    eprintln!("M14-E2E guest A garbled+evaluated: {gates} ciphertexts, {:.1} s", t.elapsed().as_secs_f64());
    assert!(accept && !reject, "evaluator did not obtain the accept label for guest A's proof");
}

const M16_PROOF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/m16-wrap-blake3-v2.bin");
const M16_STATEMENT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/m16-statement.json");

/// M16 on mainnet (Nova chain from genesis to 975,072 and a payment at 975,067): garbled from the
/// control proof's shape and M16's statement; the evaluator holding only the labels of the M16
/// proof's bits obtains "accept".
#[test]
fn garbled_final_verifier_accepts_m16_mainnet() {
    let reference = native::load(native::FIXTURE_V2);
    let p = native::load(M16_PROOF);
    let expect: m13_verify::FinalStatement = serde_json::from_slice(&std::fs::read(M16_STATEMENT).unwrap()).unwrap();
    let t = std::time::Instant::now();
    let (accept, reject, gates) = garble_and_evaluate(&reference, &expect, native::bits(&full::items(&p)));
    eprintln!("M14-E2E M16 mainnet garbled+evaluated: {gates} ciphertexts, {:.1} s", t.elapsed().as_secs_f64());
    assert!(accept && !reject, "evaluator did not obtain the accept label for the M16 mainnet proof");
}
