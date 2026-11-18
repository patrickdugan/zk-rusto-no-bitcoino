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
    let expect: FinalStatement = serde_json::from_slice(&std::fs::read(format!("{FIXTURE}c4-statement.json")).expect("statement")).unwrap();
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
        assert!(
            m13_verify::verify_wrap_proof(&w).is_err(),
            "STARK accepted altered public values, case {case}"
        );
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
        assert!(
            m13_verify::verify_wrap_proof_v2(&w).is_err(),
            "v2 STARK accepted altered public values, case {case}"
        );
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

/// Pin validation must also cover Rust callers that edit the public wire representation after
/// deserialization. Destroy the proof's public-value shape to demonstrate that pins are checked
/// before proof parsing or verification begins.
#[test]
fn malformed_expected_pins_are_rejected_before_the_proof_is_read() {
    let (_, mut wrap, expect) = load_v2();
    wrap.proof.public_values.clear();
    for field in [
        "wrap_vk_sha256",
        "program_vk_digest",
        "committed_values_sha256",
        "recursion_vk_root",
    ] {
        for value in [String::new(), "00".repeat(31), "00".repeat(33), "g".repeat(64), "é".repeat(32)] {
            let mut e = expect.clone();
            match field {
                "wrap_vk_sha256" => e.wrap_vk_sha256 = value,
                "program_vk_digest" => e.program_vk_digest = value,
                "committed_values_sha256" => e.committed_values_sha256 = value,
                _ => e.recursion_vk_root = value,
            }
            let error = verify_final(&wrap, &e).unwrap_err().to_string();
            assert!(error.contains(field), "expected a {field} error before parsing the proof: {error}");
        }
    }
}

#[test]
fn expected_execution_status_cannot_differ_from_the_circuit_policy() {
    let (_, wrap, expect) = load_v2();
    for (exit_code, is_complete) in [(1, 1), (0, 0), (0, 2)] {
        let mut e = expect.clone();
        e.exit_code = exit_code;
        e.is_complete = is_complete;
        assert!(verify_final(&wrap, &e).is_err());
    }
}

#[test]
fn noncanonical_expected_limbs_are_rejected_before_the_proof_is_read() {
    let (_, mut wrap, expect) = load_v2();
    wrap.proof.public_values.clear();
    for field in ["program_vk_digest", "recursion_vk_root"] {
        for limb in 0..8 {
            let mut bytes = [0; 32];
            bytes[limb * 4..limb * 4 + 4].copy_from_slice(&m13_statement::KOALABEAR_MODULUS.to_le_bytes());
            let mut e = expect.clone();
            match field {
                "program_vk_digest" => e.program_vk_digest = hex::encode(bytes),
                _ => e.recursion_vk_root = hex::encode(bytes),
            }
            let error = verify_final(&wrap, &e).unwrap_err().to_string();
            assert!(error.contains(field) && error.contains("limb"), "{error}");
        }
    }
}

#[test]
fn native_pin_comparison_uses_decoded_fixed_width_values() {
    let (_, wrap, mut expect) = load_v2();
    expect.wrap_vk_sha256.make_ascii_uppercase();
    expect.program_vk_digest.make_ascii_uppercase();
    expect.committed_values_sha256.make_ascii_uppercase();
    expect.recursion_vk_root.make_ascii_uppercase();
    let got = verify_final(&wrap, &expect).unwrap();
    assert_eq!(got.validate().unwrap(), expect.validate().unwrap());
}
