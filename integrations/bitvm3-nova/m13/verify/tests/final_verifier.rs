//! The committed M13 fixture: a BLAKE3 final proof of SP1's wrap layer over a
//! real compressed proof. The honest proof verifies; altered bytes, altered
//! public values and altered pins are refused.
use std::borrow::BorrowMut;

use m13_verify::{final_statement, verify_final, Blake3WrapProof, Blake3WrapProofV2, FinalStatement};
use slop_algebra::AbstractField;
use sp1_primitives::SP1Field;
use sp1_recursion_executor::RecursionPublicValues;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/");

fn load() -> (Vec<u8>, Blake3WrapProof, FinalStatement) {
    let bytes = std::fs::read(format!("{FIXTURE}c4-wrap-blake3.bin")).expect("fixture");
    let wrap: Blake3WrapProof = bincode::deserialize(&bytes).expect("decodes");
    let expect: FinalStatement =
        serde_json::from_slice(&std::fs::read(format!("{FIXTURE}c4-statement.json")).expect("statement")).unwrap();
    (bytes, wrap, expect)
}

#[test]
fn honest_final_proof_verifies_and_decodes_the_pinned_statement() {
    let (_, wrap, expect) = load();
    let got = verify_final(&wrap, &expect).expect("honest proof verifies");
    assert_eq!(got, expect);
    assert_eq!(got.exit_code, 0);
    assert_eq!(got.is_complete, 1);
}

#[test]
fn flipped_bytes_are_refused() {
    let (bytes, _, expect) = load();
    for frac in [0.02, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99] {
        let mut b = bytes.clone();
        let at = ((b.len() as f64) * frac) as usize;
        b[at] ^= 1;
        let accepted = bincode::deserialize::<Blake3WrapProof>(&b)
            .ok()
            .map(|w| verify_final(&w, &expect).is_ok())
            .unwrap_or(false);
        assert!(!accepted, "byte {at} flipped was accepted");
    }
}

#[test]
fn altered_public_values_are_refused() {
    let (_, wrap, expect) = load();
    let one = SP1Field::one();
    for case in 0..5 {
        let mut w = wrap.clone();
        {
            let pv: &mut RecursionPublicValues<SP1Field> = w.proof.public_values.as_mut_slice().borrow_mut();
            match case {
                0 => pv.exit_code = one,
                1 => pv.committed_value_digest[0][0] += one,
                2 => pv.sp1_vk_digest[0] += one,
                3 => pv.is_complete = SP1Field::zero(),
                _ => pv.vk_root[0] += one,
            }
        }
        assert!(verify_final(&w, &expect).is_err(), "public value case {case} accepted");
        // The STARK itself refuses, not only the statement comparison.
        assert!(m13_verify::verify_wrap_proof(&w).is_err(), "STARK accepted altered public values, case {case}");
    }
}

#[test]
fn altered_pins_and_statement_are_refused() {
    let (_, wrap, expect) = load();
    let mut e = expect.clone();
    e.committed_values_sha256 = m13_verify::sha_hex(b"another statement");
    assert!(verify_final(&wrap, &e).is_err());
    let mut e = expect.clone();
    e.program_vk_digest = "00".repeat(32);
    assert!(verify_final(&wrap, &e).is_err());
    let mut e = expect.clone();
    e.wrap_vk_sha256 = m13_verify::sha_hex(b"another key");
    assert!(verify_final(&wrap, &e).is_err());
    let mut e = expect.clone();
    e.recursion_vk_root = "00".repeat(32);
    assert!(verify_final(&wrap, &e).is_err());
    assert_eq!(final_statement(&wrap).unwrap(), expect);
}

// ------------------------------------------------------------------ transcript v2
// c4-wrap-blake3-v2.bin: the same shrink proof wrapped under transcript v2 (fixed-cost
// challenges, `ctx::Blake3ChallengerV2`); same key and statement as the v1 fixture.

fn load_v2() -> (Vec<u8>, Blake3WrapProofV2, FinalStatement) {
    let bytes = std::fs::read(format!("{FIXTURE}c4-wrap-blake3-v2.bin")).expect("fixture");
    let wrap: Blake3WrapProofV2 = bincode::deserialize(&bytes).expect("decodes");
    let (_, _, expect) = load();
    (bytes, wrap, expect)
}

#[test]
fn v2_honest_proof_verifies_with_the_same_key_and_statement() {
    let (_, wrap, expect) = load_v2();
    assert_eq!(verify_final(&wrap, &expect).expect("v2 proof verifies"), expect);
}

#[test]
fn v2_mutations_are_refused() {
    let (bytes, wrap, expect) = load_v2();
    for frac in [0.02, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99] {
        let mut b = bytes.clone();
        let at = ((b.len() as f64) * frac) as usize;
        b[at] ^= 1;
        let accepted = bincode::deserialize::<Blake3WrapProofV2>(&b)
            .ok()
            .map(|w| verify_final(&w, &expect).is_ok())
            .unwrap_or(false);
        assert!(!accepted, "v2: byte {at} flipped was accepted");
    }
    let one = SP1Field::one();
    for case in 0..5 {
        let mut w = wrap.clone();
        {
            let pv: &mut RecursionPublicValues<SP1Field> = w.proof.public_values.as_mut_slice().borrow_mut();
            match case {
                0 => pv.exit_code = one,
                1 => pv.committed_value_digest[0][0] += one,
                2 => pv.sp1_vk_digest[0] += one,
                3 => pv.is_complete = SP1Field::zero(),
                _ => pv.vk_root[0] += one,
            }
        }
        assert!(m13_verify::verify_wrap_proof_v2(&w).is_err(), "v2 STARK accepted altered public values, case {case}");
    }
}

#[test]
fn v1_and_v2_transcripts_do_not_cross_verify() {
    let (v1_bytes, _, expect) = load();
    let (v2_bytes, _, _) = load_v2();
    let v1_as_v2: Blake3WrapProofV2 = bincode::deserialize(&v1_bytes).unwrap();
    let v2_as_v1: Blake3WrapProof = bincode::deserialize(&v2_bytes).unwrap();
    assert!(verify_final(&v1_as_v2, &expect).is_err(), "v1 proof accepted under v2");
    assert!(verify_final(&v2_as_v1, &expect).is_err(), "v2 proof accepted under v1");
}
