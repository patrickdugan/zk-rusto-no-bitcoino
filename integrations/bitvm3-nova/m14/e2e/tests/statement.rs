//! Small statement-only circuit regressions. These tests never build the 785M-gate verifier.
use std::borrow::BorrowMut;

use garbled_snark_verifier::{
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult},
    WireId,
};
use m13_verify::{FinalStatement, ValidatedFinalStatement};
use m14_circuit::field::{Fe, P};
use m14_e2e::{
    full::{self, Known},
    native,
};
use sp1_recursion_executor::RecursionPublicValues;

fn fixture() -> FinalStatement {
    serde_json::from_str(include_str!("../../../m13/fixtures/c4-statement.json")).unwrap()
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
        for (id, value) in w.iter().zip(&self.0) {
            mode.feed_wire(*id, *value);
        }
    }
}

fn run_statement(values: &[u32], expect: &ValidatedFinalStatement) -> bool {
    let bits = values
        .iter()
        .flat_map(|value| (0..31).map(move |bit| (value >> bit) & 1 != 0))
        .collect();
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(bits), 1 << 16, |c, w| {
        let pv = w.chunks_exact(31).map(Fe::from_wires).collect::<Vec<_>>();
        vec![full::statement(c, &pv, expect)]
    });
    assert!(
        r.gate_count.nonfree_gate_count() < 10_000,
        "statement test built more than the isolated predicate"
    );
    r.output_value[0]
}

fn public_values(expect: &ValidatedFinalStatement) -> Vec<u32> {
    let mut values = vec![0; std::mem::size_of::<RecursionPublicValues<u8>>()];
    let pv: &mut RecursionPublicValues<u32> = values.as_mut_slice().borrow_mut();
    pv.exit_code = 0;
    pv.is_complete = 1;
    pv.sp1_vk_digest.copy_from_slice(expect.program_vk_digest());
    pv.vk_root.copy_from_slice(expect.recursion_vk_root());
    for (dst, &src) in pv.committed_value_digest.iter_mut().flatten().zip(expect.committed_values_sha256()) {
        *dst = src as u32;
    }
    values
}

#[test]
fn all_statement_fields_are_bound_including_the_last_digest_limb_and_byte() {
    let expect = fixture().validate().unwrap();
    let values = public_values(&expect);
    assert!(run_statement(&values, &expect));

    let mut indices = (0..values.len() as u32).collect::<Vec<_>>();
    let o: &mut RecursionPublicValues<u32> = indices.as_mut_slice().borrow_mut();
    let mut checked = vec![o.exit_code, o.is_complete];
    checked.extend(o.sp1_vk_digest);
    checked.extend(o.vk_root);
    checked.extend(o.committed_value_digest.iter().flatten().copied());
    assert_eq!(checked.len(), 50);
    for index in checked {
        let mut altered = values.clone();
        altered[index as usize] = (altered[index as usize] + 1) % P;
        assert!(
            !run_statement(&altered, &expect),
            "public value {index} escaped the statement equality checks"
        );
    }
}

#[test]
fn malformed_pins_are_rejected_before_reference_shape_construction() {
    let mut reference = native::load(native::FIXTURE_V2);
    reference.proof.public_values.clear();
    for field in [
        "wrap_vk_sha256",
        "program_vk_digest",
        "committed_values_sha256",
        "recursion_vk_root",
    ] {
        for value in [String::new(), "00".repeat(31), "00".repeat(33), "g".repeat(64), "é".repeat(32)] {
            let mut expect = fixture();
            match field {
                "wrap_vk_sha256" => expect.wrap_vk_sha256 = value,
                "program_vk_digest" => expect.program_vk_digest = value,
                "committed_values_sha256" => expect.committed_values_sha256 = value,
                _ => expect.recursion_vk_root = value,
            }
            let error = match Known::try_new(&reference, &expect) {
                Ok(_) => panic!("malformed {field} admitted"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(field),
                "expected {field} validation before reading the broken reference: {error}"
            );
        }
    }
}

#[test]
fn another_wrap_key_is_rejected_before_reference_shape_construction() {
    let mut reference = native::load(native::FIXTURE_V2);
    reference.proof.public_values.clear();
    for byte in 0..32 {
        let mut expect = fixture();
        let at = byte * 2;
        let value = u8::from_str_radix(&expect.wrap_vk_sha256[at..at + 2], 16).unwrap() ^ 1;
        expect.wrap_vk_sha256.replace_range(at..at + 2, &format!("{value:02x}"));
        let error = match Known::try_new(&reference, &expect) {
            Ok(_) => panic!("different wrap key admitted after changing byte {byte}"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("pinned key"), "{error}");
    }
}

#[test]
fn noncanonical_expected_limbs_are_rejected_before_reference_shape_construction() {
    let mut reference = native::load(native::FIXTURE_V2);
    reference.proof.public_values.clear();
    for field in ["program_vk_digest", "recursion_vk_root"] {
        for limb in 0..8 {
            let mut bytes = [0; 32];
            bytes[limb * 4..limb * 4 + 4].copy_from_slice(&P.to_le_bytes());
            let value = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let mut expect = fixture();
            match field {
                "program_vk_digest" => expect.program_vk_digest = value,
                _ => expect.recursion_vk_root = value,
            }
            let error = match Known::try_new(&reference, &expect) {
                Ok(_) => panic!("noncanonical {field} limb {limb} admitted"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(field) && error.contains("limb"), "{error}");
        }
    }
}
