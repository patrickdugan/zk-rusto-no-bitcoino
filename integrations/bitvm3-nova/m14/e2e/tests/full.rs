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

const A_PROOF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/a-wrap-blake3-v2.bin");
const A_STATEMENT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/a-statement.json");

/// Guest A (M12's complete Nova verifier): its real final proof is accepted by the circuit built
/// from the committed control proof's shape, under A's own pinned statement, and rejected under the
/// control's statement or with a flipped bit. The control proof is rejected under A's statement.
#[test]
fn final_verifier_circuit_on_guest_a() {
    let reference = native::load(native::FIXTURE_V2);
    let a = native::load(A_PROOF);
    let expect_a = statement(A_STATEMENT);
    let expect_c4 = statement(STATEMENT);
    m13_verify::verify_final(&a, &expect_a).expect("SP1 (m13-verify) accepts guest A's proof");
    let bits_a = native::bits(&full::items(&a));
    let k_a = Known::new(&reference, &expect_a);
    let t = std::time::Instant::now();
    let (ok, gates) = run(&k_a, bits_a.clone());
    eprintln!("M14-E2E guest A: {} input bits, {gates} non-free gates, {:.1} s", bits_a.len(), t.elapsed().as_secs_f64());
    assert!(ok, "the circuit rejects guest A's final proof");

    let mut b = bits_a.clone();
    let at = b.len() - 5;
    b[at] = !b[at];
    assert!(!run(&k_a, b).0, "guest A proof with a flipped bit accepted");

    let k_c4 = Known::new(&reference, &expect_c4);
    assert!(!run(&k_c4, bits_a).0, "guest A proof accepted under the control statement");
    let bits_c4 = native::bits(&full::items(&reference));
    assert!(!run(&k_a, bits_c4).0, "control proof accepted under guest A's statement");
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
