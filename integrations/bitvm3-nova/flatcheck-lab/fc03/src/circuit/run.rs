//! Execute, count, garble and evaluate the FC03 circuits (the M12/M14 harness pattern).
use super::{row::RowKnown, row::row_circuit, step::step_circuit, step::StepKnown, W};
use crossbeam::channel;
use garbled_snark_verifier::{
    circuit::{CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, EvaluateMode, ExecuteMode, StreamingResult},
    AesCcrGateHasher, CircuitContext, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, WireId, S,
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::time::Instant;

const CAP: usize = 1 << 22;

pub enum Which {
    Row(RowKnown),
    Step(StepKnown),
}

pub fn build<C: CircuitContext>(c: &mut C, k: &Which, w: &[W]) -> Vec<W> {
    vec![match k {
        Which::Row(k) => row_circuit(c, k, w),
        Which::Step(k) => step_circuit(c, k, w),
    }]
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

pub struct GIn(pub usize);
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
/// Counts the ciphertexts the garbler really emits while forwarding them.
struct CountFwd<H: CiphertextHandler> {
    inner: H,
    n: u64,
}
impl<H: CiphertextHandler> CiphertextHandler for CountFwd<H> {
    type Result = (H::Result, u64);
    fn handle(&mut self, ct: S) {
        self.n += 1;
        self.inner.handle(ct);
    }
    fn finalize(self) -> (H::Result, u64) {
        (self.inner.finalize(), self.n)
    }
}
struct Discard;
impl CiphertextHandler for Discard {
    type Result = ();
    fn handle(&mut self, _ct: S) {}
    fn finalize(self) {}
}

/// (output bit, non-free gate count, total gate count).
pub fn execute(k: &Which, bits: Vec<bool>) -> (bool, u64, u64) {
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(bits), CAP, |c, w| build(c, k, w));
    (r.output_value[0], r.gate_count.nonfree_gate_count(), r.gate_count.total_gate_count())
}

/// Ciphertexts the garbler emits for this circuit (must equal the non-free count).
pub fn garble_count(k: &Which, n_inputs: usize, seed: u64) -> u64 {
    let g: StreamingResult<GarbleMode<AesCcrGateHasher, Count>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(n_inputs), CAP, seed, Count(0), |c, w| build(c, k, w));
    g.ciphertext_handler_result
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct GarbleReport {
    /// Ciphertexts the garbler emitted (one per non-free gate it could not fold).
    pub ciphertexts: u64,
    /// The evaluator's non-free gate count (ExecuteMode semantics; counts AND(x, NOT x) gates
    /// the garbler folds, so it can exceed `ciphertexts` by a few gates).
    pub evaluator_nonfree: u64,
    pub ciphertext_bytes: u64,
    pub input_labels: usize,
    pub garble_and_evaluate_seconds: f64,
    /// Label of output 0 ("no refutation") and output 1 ("refute"), as the garbler holds them.
    pub accept_label: u128,
    pub refute_label: u128,
    /// The label the evaluator obtained from the input labels of `bits`.
    pub evaluated_label: u128,
}

impl GarbleReport {
    pub fn refutes(&self) -> Option<bool> {
        if self.evaluated_label == self.refute_label {
            Some(true)
        } else if self.evaluated_label == self.accept_label {
            Some(false)
        } else {
            None
        }
    }
}

/// The garbler's output labels for a seed (no evaluation): what the dispute script commits to.
pub fn output_labels(k: &Which, n_inputs: usize, seed: u64) -> (u128, u128) {
    let g: StreamingResult<GarbleMode<AesCcrGateHasher, Discard>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(n_inputs), CAP, seed, Discard, |c, w| build(c, k, w));
    (g.output_value[0].select(false).to_u128(), g.output_value[0].select(true).to_u128())
}

/// Garble (streaming ciphertexts through a bounded channel) and evaluate concurrently. The
/// evaluator holds only the active input labels of `bits`.
pub fn garble_and_evaluate(k: &Which, bits: Vec<bool>, seed: u64) -> GarbleReport {
    let n = bits.len();
    let pre: StreamingResult<GarbleMode<AesCcrGateHasher, Discard>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(n), 1 << 16, seed, Discard, |_c, w: &Vec<WireId>| vec![w[0]]);
    let labels = pre.input_wire_values.clone();
    let (t_label, f_label) = (pre.true_wire_constant.select(true).to_u128(), pre.false_wire_constant.select(false).to_u128());
    let (tx, rx) = channel::bounded(1 << 20);
    let labels_g = labels.clone();
    let t = Instant::now();
    let (accept, refute, got, ev_nf, cts) = std::thread::scope(|s| {
        let garbler = s.spawn(move || {
            let g: StreamingResult<GarbleMode<AesCcrGateHasher, _>, _, Vec<GarbledWire>> =
                CircuitBuilder::streaming_garbling(GIn(n), CAP, seed, CountFwd { inner: tx, n: 0 }, |c, w| build(c, k, w));
            assert!(g.input_wire_values == labels_g, "input labels differ from the reproduced ones");
            (g.output_value[0].clone(), g.ciphertext_handler_result.1)
        });
        let evaluator = s.spawn(move || {
            let mut rng = ChaChaRng::seed_from_u64(seed);
            let hasher = AesCcrGateHasher::from_rng(&mut rng);
            let e: StreamingResult<EvaluateMode<AesCcrGateHasher, _>, _, Vec<EvaluatedWire>> =
                CircuitBuilder::streaming_evaluation(EIn { labels, bits }, CAP, t_label, f_label, hasher, rx, |c, w| build(c, k, w));
            (e.output_value[0].active_label, e.gate_count.nonfree_gate_count())
        });
        let (out, cts) = garbler.join().unwrap();
        let (label, gates) = evaluator.join().unwrap();
        (out.select(false).to_u128(), out.select(true).to_u128(), label.to_u128(), gates, cts)
    });
    GarbleReport {
        ciphertexts: cts,
        evaluator_nonfree: ev_nf,
        ciphertext_bytes: cts * std::mem::size_of::<S>() as u64,
        input_labels: n,
        garble_and_evaluate_seconds: t.elapsed().as_secs_f64(),
        accept_label: accept,
        refute_label: refute,
        evaluated_label: got,
    }
}
