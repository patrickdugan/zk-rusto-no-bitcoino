//! M14 as a claim instance: the complete final verifier garbled under one seed for one pinned
//! statement, and evaluated on a proof by a party holding only the labels of the proof's bits.
//!
//!   m14-claim setup    SEED_HEX STATEMENT.json OUT.json
//!   m14-claim evaluate SEED_HEX STATEMENT.json PROOF.bin OUT.json [FLIP_BIT]
//!
//! `setup` garbles once and writes the commitment a dispute graph needs before any proof is
//! evaluated: the BLAKE3 commitment of the ciphertext stream, SHA-256 of the "accept" and
//! "reject" output labels, and the gate count. It runs the garbler alone.
//!
//! `evaluate` garbles again under the same seed and streams the ciphertexts to an evaluator
//! thread holding the input labels of PROOF's bits (the garbler hands those over; that hand-over
//! is off-chain). It writes the evaluator's output label, which of the two committed labels it
//! equals, and the stream commitment both ends computed. A disprove spends with the reject label;
//! the accept label opens nothing.
//!
//! The circuit is built from the committed c4 proof's shape (`native::FIXTURE_V2`) and the given
//! statement, as in `tests/garbled.rs`; the statement is a constant of the circuit, so a valid proof
//! of any other statement evaluates to reject.
use crossbeam::channel;
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, S, WireId,
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
use sha2::{Digest, Sha256};

const CAP: usize = 1 << 24;

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

/// Garbler side: commit to every ciphertext, and forward it when an evaluator is attached.
struct Tee {
    tx: Option<channel::Sender<S>>,
    h: Blake3AccumulatingHash,
}
impl CiphertextHandler for Tee {
    type Result = [u8; 32];
    fn handle(&mut self, ct: S) {
        self.h.update(ct);
        if let Some(tx) = &self.tx {
            tx.send(ct).unwrap();
        }
    }
    fn finalize(self) -> [u8; 32] {
        self.h.finalize()
    }
}
/// Evaluator side: the same commitment over the stream it received.
struct Rx {
    rx: channel::Receiver<S>,
    h: Blake3AccumulatingHash,
}
impl CiphertextSource for Rx {
    type Result = [u8; 32];
    fn recv(&mut self) -> Option<S> {
        let ct = self.rx.recv().ok()?;
        self.h.update(ct);
        Some(ct)
    }
    fn finalize(self) -> [u8; 32] {
        self.h.finalize()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn label_bytes(s: &S) -> [u8; 16] {
    s.to_u128().to_le_bytes()
}
fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn parse_seed(s: &str) -> u64 {
    let raw: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("seed hex")).collect();
    assert_eq!(raw.len(), 8, "seed must be 8 bytes of hex");
    u64::from_be_bytes(raw.try_into().unwrap())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: m14-claim setup SEED_HEX STATEMENT.json OUT.json | evaluate SEED_HEX STATEMENT.json PROOF.bin OUT.json [FLIP_BIT]";
    anyhow::ensure!(args.len() >= 5, usage);
    let seed = parse_seed(&args[2]);
    let statement_bytes = std::fs::read(&args[3])?;
    let expect: m13_verify::FinalStatement = serde_json::from_slice(&statement_bytes)?;
    let reference = native::load(native::FIXTURE_V2);
    let n = native::bits(&full::items(&reference)).len();
    let t0 = std::time::Instant::now();

    // The input and constant labels depend only on the seed.
    let pre: StreamingResult<GarbleMode<AesCcrGateHasher, ()>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(n), 1 << 20, seed, (), |_c, w| vec![w[0]]);
    let labels = pre.input_wire_values.clone();
    let (t_label, f_label) = (pre.true_wire_constant.select(true).to_u128(), pre.false_wire_constant.select(false).to_u128());

    match args[1].as_str() {
        "setup" => {
            anyhow::ensure!(args.len() == 5, usage);
            let k = &Known::new(&reference, &expect);
            let g: StreamingResult<GarbleMode<AesCcrGateHasher, Tee>, _, Vec<GarbledWire>> = CircuitBuilder::streaming_garbling(
                GIn(n),
                CAP,
                seed,
                Tee { tx: None, h: Blake3AccumulatingHash::default() },
                |c, w| vec![full::final_verifier(c, k, w)],
            );
            assert!(g.input_wire_values == labels, "input labels differ from the reproduced ones");
            let out = &g.output_value[0];
            let report = serde_json::json!({
                "tool": "m14-claim setup",
                "seed_sha256": sha(&seed.to_be_bytes()),
                "statement_sha256": sha(&statement_bytes),
                "statement": expect,
                "input_bits": n,
                "ciphertexts": g.gate_count.nonfree_gate_count(),
                "ciphertext_commitment_blake3": hex(&g.ciphertext_handler_result),
                "accept_label_sha256": sha(&label_bytes(&out.select(true))),
                "reject_label_sha256": sha(&label_bytes(&out.select(false))),
                "seconds": t0.elapsed().as_secs_f64(),
            });
            std::fs::write(&args[4], serde_json::to_string_pretty(&report)? + "\n")?;
            println!("{report}");
        }
        "evaluate" => {
            anyhow::ensure!(args.len() == 6 || args.len() == 7, usage);
            let proof = native::load(&args[4]);
            let proof_bytes = std::fs::read(&args[4])?;
            let mut bits = native::bits(&full::items(&proof));
            anyhow::ensure!(bits.len() == n, "proof has {} input bits, the circuit {}", bits.len(), n);
            // Optional FLIP_BIT: the claimant hands over labels for this proof with one input bit
            // changed (the counterexample of a tampered proof, as in tests/garbled.rs).
            let flipped: Option<usize> = args.get(6).map(|s| s.parse().expect("FLIP_BIT"));
            if let Some(i) = flipped {
                anyhow::ensure!(i < n, "FLIP_BIT out of range");
                bits[i] = !bits[i];
            }
            let (tx, rx) = channel::bounded(1 << 20);
            let labels_g = labels.clone();
            let (out, (label, ev_commit, gates), g_commit) = std::thread::scope(|s| {
                let garbler = s.spawn(|| {
                    let k = &Known::new(&reference, &expect);
                    let g: StreamingResult<GarbleMode<AesCcrGateHasher, Tee>, _, Vec<GarbledWire>> = CircuitBuilder::streaming_garbling(
                        GIn(n),
                        CAP,
                        seed,
                        Tee { tx: Some(tx), h: Blake3AccumulatingHash::default() },
                        |c, w| vec![full::final_verifier(c, k, w)],
                    );
                    assert!(g.input_wire_values == labels_g, "input labels differ from the reproduced ones");
                    (g.output_value[0].clone(), g.ciphertext_handler_result)
                });
                let evaluator = s.spawn(|| {
                    let k = &Known::new(&reference, &expect);
                    let mut rng = ChaChaRng::seed_from_u64(seed);
                    let hasher = AesCcrGateHasher::from_rng(&mut rng);
                    let e: StreamingResult<EvaluateMode<AesCcrGateHasher, Rx>, _, Vec<EvaluatedWire>> = CircuitBuilder::streaming_evaluation(
                        EIn { labels: labels.clone(), bits },
                        CAP,
                        t_label,
                        f_label,
                        hasher,
                        Rx { rx, h: Blake3AccumulatingHash::default() },
                        |c, w| vec![full::final_verifier(c, k, w)],
                    );
                    (e.output_value[0].active_label, e.ciphertext_handler_result, e.gate_count.nonfree_gate_count())
                });
                let (out, g_commit) = garbler.join().unwrap();
                (out, evaluator.join().unwrap(), g_commit)
            });
            let lb = label_bytes(&label);
            let verdict = if label == out.select(true) {
                "accept"
            } else if label == out.select(false) {
                "reject"
            } else {
                "neither"
            };
            let report = serde_json::json!({
                "tool": "m14-claim evaluate",
                "seed_sha256": sha(&seed.to_be_bytes()),
                "statement_sha256": sha(&statement_bytes),
                "proof_sha256": sha(&proof_bytes),
                "flipped_input_bit": flipped,
                "input_bits": n,
                "ciphertexts": gates,
                "ciphertext_commitment_blake3": hex(&g_commit),
                "evaluator_commitment_blake3": hex(&ev_commit),
                "verdict": verdict,
                "output_label": hex(&lb),
                "output_label_sha256": sha(&lb),
                "accept_label_sha256": sha(&label_bytes(&out.select(true))),
                "reject_label_sha256": sha(&label_bytes(&out.select(false))),
                "seconds": t0.elapsed().as_secs_f64(),
            });
            std::fs::write(&args[5], serde_json::to_string_pretty(&report)? + "\n")?;
            println!("{report}");
        }
        _ => anyhow::bail!(usage),
    }
    Ok(())
}
