//! The complete final verifier circuit (`m14_e2e::full`) against `m13_verify::verify_final` on the
//! committed v2 final proof, with mutations of the proof, its encoding and the pinned statement.
use garbled_snark_verifier::{
    WireId,
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult},
};
use m13_verify::FinalStatement;
use m14_e2e::{
    full::{self, Known},
    native::{self, Item},
};

const CAP: usize = 1 << 24;

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

fn run(k: &Known, input: Vec<bool>) -> (bool, u64) {
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(Plain(input), CAP, |c, w| vec![full::final_verifier(c, k, w)]);
    (r.output_value[0], r.gate_count.nonfree_gate_count())
}

fn statement(path: &str) -> FinalStatement {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

const STATEMENT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/c4-statement.json");

#[test]
fn final_verifier_circuit_on_the_real_proof() {
    let proof = native::load(native::FIXTURE_V2);
    let expect = statement(STATEMENT);
    m13_verify::verify_final(&proof, &expect).expect("SP1 (m13-verify) accepts the proof");
    let k = Known::new(&proof, &expect);
    let items = full::items(&proof);
    let bits = native::bits(&items);
    let t = std::time::Instant::now();
    let (ok, gates) = run(&k, bits.clone());
    eprintln!(
        "M14-E2E final verifier: {} input items, {} input bits, {gates} non-free gates, {:.1} s",
        items.len(),
        bits.len(),
        t.elapsed().as_secs_f64()
    );
    assert!(ok, "the circuit rejects the real final proof");

    // A flipped bit in the last Merkle path digest.
    let mut b = bits.clone();
    let last = b.len() - 5;
    b[last] = !b[last];
    assert!(!run(&k, b).0, "flipped Merkle path bit accepted");

    // A public value changed (the first one).
    let mut it = items.clone();
    if let Item::Fe(v) = &mut it[0] {
        *v = (*v + 1) % 0x7f00_0001;
    }
    assert!(!run(&k, native::bits(&it)).0, "changed public value accepted");

    // A FRI row value changed (an extension coordinate in the last third of the inputs).
    let mut it = items.clone();
    let at = it.iter().enumerate().rev().find(|(_, x)| matches!(x, Item::Fe(_))).map(|(i, _)| i).unwrap();
    if let Item::Fe(v) = &mut it[at] {
        *v = (*v + 3) % 0x7f00_0001;
    }
    assert!(!run(&k, native::bits(&it)).0, "changed FRI row value accepted");

    // A non-canonical encoding: a field element written as itself + p (31 bits, >= p).
    let mut b = bits.clone();
    let first_fe = 0; // the first public value
    let v = match items[first_fe] {
        Item::Fe(v) => v,
        _ => unreachable!(),
    };
    let nc = v as u64 + 0x7f00_0001;
    assert!(nc < 1 << 31, "value too large to re-encode");
    for i in 0..31 {
        b[i] = (nc >> i) & 1 == 1;
    }
    assert!(!run(&k, b).0, "non-canonical encoding accepted");

    // A different pinned statement.
    let mut e2 = expect.clone();
    e2.committed_values_sha256 = m13_verify::sha_hex(b"another statement");
    let k2 = Known::new(&proof, &e2);
    assert!(!run(&k2, bits).0, "proof accepted under another statement");
}

/// A second real proof (another guest, same wrap key and shape), if present locally: the circuit
/// built from the committed proof's shape verifies it under its own statement.
#[test]
fn final_verifier_circuit_on_a_second_proof() {
    let Ok(dir) = std::env::var("M14_SECOND_PROOF_DIR") else {
        eprintln!("M14_SECOND_PROOF_DIR not set: skipped");
        return;
    };
    let reference = native::load(native::FIXTURE_V2);
    let second = native::load(&format!("{dir}/wrap-v2.bin"));
    let expect = statement(&format!("{dir}/statement-v2.json"));
    m13_verify::verify_final(&second, &expect).expect("SP1 accepts the second proof");
    let k = Known::new(&reference, &expect);
    let (ok, _) = run(&k, native::bits(&full::items(&second)));
    assert!(ok, "the circuit built from the committed proof's shape rejects the second proof");
}

#[test]
#[ignore]
fn which_checks_fail() {
    let proof = native::load(native::FIXTURE_V2);
    let expect = statement(STATEMENT);
    let k = Known::new(&proof, &expect);
    let bits = native::bits(&full::items(&proof));
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(Plain(bits), CAP, |c, w| full::final_verifier_parts(c, &k, w));
    let v = r.output_value;
    eprintln!("logup {} zerocheck {} statement {} canonical {}", v[0], v[1], v[2], v[3]);
    let failed: Vec<usize> = (4..v.len()).filter(|&i| !v[i]).map(|i| i - 4).collect();
    eprintln!("pcs checks {} failed {} first failing indices {:?}", v.len() - 4, failed.len(), &failed[..failed.len().min(40)]);
}
