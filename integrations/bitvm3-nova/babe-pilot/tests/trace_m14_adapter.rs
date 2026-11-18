#![cfg(feature = "m14-trace")]

use babe_pilot::trace::{digest, m14, TraceLimits};

fn fixtures() -> (Vec<u8>, Vec<u8>) {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../m13/fixtures");
    (
        std::fs::read(base.join("c4-wrap-blake3-v2.bin")).unwrap(),
        std::fs::read(base.join("c4-statement.json")).unwrap(),
    )
}

#[test]
fn complete_m14_entry_point_refuses_a_partial_program_at_the_explicit_cap() {
    let (proof, statement) = fixtures();
    let limits = TraceLimits {
        max_gates: 100,
        ..TraceLimits::default()
    };
    let result = m14::compile(
        &proof,
        digest(&proof),
        &proof,
        digest(&proof),
        &statement,
        digest(&statement),
        limits,
    );
    let error = match result {
        Ok(_) => panic!("complete M14 unexpectedly fit in 100 gates"),
        Err(error) => error,
    };
    let chain = format!("{error:#}");
    assert!(
        chain.contains("complete M14 trace compilation failed"),
        "{chain}"
    );
    assert!(
        chain.contains("gate limit") || chain.contains("wire allocation limit"),
        "{chain}"
    );
}

#[test]
fn m14_independent_pins_are_checked_before_parsing_or_compilation() {
    let limits = TraceLimits::default();
    let bytes = b"malformed proof";
    let statement = b"{}";
    let cases = [
        (
            [0; 32],
            digest(bytes),
            digest(statement),
            "reference proof pin",
        ),
        (
            digest(bytes),
            [0; 32],
            digest(statement),
            "challenged proof pin",
        ),
        (
            digest(bytes),
            digest(bytes),
            [0; 32],
            "public statement pin",
        ),
    ];
    for (reference_hash, proof_hash, statement_hash, expected) in cases {
        let result = m14::compile(
            bytes,
            reference_hash,
            bytes,
            proof_hash,
            statement,
            statement_hash,
            limits,
        );
        let error = match result {
            Ok(_) => panic!("incorrect pin accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}
