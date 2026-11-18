use m13_statement::{FinalStatement, KOALABEAR_MODULUS};

const FIXTURE: &str = include_str!("../../fixtures/c4-statement.json");
const PIN_FIELDS: [&str; 4] = [
    "wrap_vk_sha256",
    "program_vk_digest",
    "committed_values_sha256",
    "recursion_vk_root",
];

fn fixture() -> FinalStatement {
    serde_json::from_str(FIXTURE).unwrap()
}

fn pin<'a>(statement: &'a mut FinalStatement, field: &str) -> &'a mut String {
    match field {
        "wrap_vk_sha256" => &mut statement.wrap_vk_sha256,
        "program_vk_digest" => &mut statement.program_vk_digest,
        "committed_values_sha256" => &mut statement.committed_values_sha256,
        "recursion_vk_root" => &mut statement.recursion_vk_root,
        _ => unreachable!(),
    }
}

fn rejected_at_both_boundaries(field: &str, value: &str) {
    // A caller can edit the wire value without going through serde. Entry-point validation must
    // reject it as well as the JSON parser, so malformed pins cannot bypass the checked type.
    let mut direct = fixture();
    *pin(&mut direct, field) = value.to_owned();
    assert!(direct.validate().is_err(), "direct {field} accepted {value:?}");

    let mut json = serde_json::to_value(fixture()).unwrap();
    json[field] = value.into();
    assert!(
        serde_json::from_value::<FinalStatement>(json).is_err(),
        "JSON {field} accepted {value:?}"
    );
}

fn encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn existing_fixture_json_round_trips_without_a_wire_format_change() {
    for json in [
        FIXTURE,
        include_str!("../../fixtures/a-statement.json"),
        include_str!("../../fixtures/m16-statement.json"),
    ] {
        let statement: FinalStatement = serde_json::from_str(json).unwrap();
        statement.validate().unwrap();
        assert_eq!(
            serde_json::to_value(statement).unwrap(),
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
    }
}

#[test]
fn every_digest_rejects_empty_truncated_and_extended_encodings() {
    for field in PIN_FIELDS {
        for len in [0, 1, 2, 7, 8, 31, 32, 62, 63, 65, 66, 128, 1024] {
            rejected_at_both_boundaries(field, &"0".repeat(len));
        }
    }
}

#[test]
fn every_digest_rejects_bad_hex_without_string_index_panics() {
    for field in PIN_FIELDS {
        for at in [0, 1, 31, 62, 63] {
            let mut bytes = [b'0'; 64];
            bytes[at] = b'g';
            rejected_at_both_boundaries(field, std::str::from_utf8(&bytes).unwrap());
        }
        for value in [
            "é".repeat(32),
            format!("{}é", "0".repeat(62)),
            format!("{} ", "0".repeat(63)),
            format!("0x{}", "0".repeat(62)),
        ] {
            rejected_at_both_boundaries(field, &value);
        }
    }
}

#[test]
fn each_field_limb_must_be_canonical_without_modular_aliasing() {
    for field in ["program_vk_digest", "recursion_vk_root"] {
        for limb in 0..8 {
            for value in [KOALABEAR_MODULUS, KOALABEAR_MODULUS + 1, u32::MAX] {
                let mut bytes = [0; 32];
                bytes[limb * 4..limb * 4 + 4].copy_from_slice(&value.to_le_bytes());
                rejected_at_both_boundaries(field, &encode_bytes(&bytes));
            }
        }
        let valid = encode_bytes(&(0..8).flat_map(|_| (KOALABEAR_MODULUS - 1).to_le_bytes()).collect::<Vec<_>>());
        let mut statement = fixture();
        *pin(&mut statement, field) = valid;
        statement.validate().unwrap();
    }
}

#[test]
fn expected_status_is_the_same_for_native_and_circuit_admission() {
    for (exit_code, is_complete) in [(1, 1), (u32::MAX, 1), (0, 0), (0, 2), (0, u32::MAX)] {
        let mut statement = fixture();
        statement.exit_code = exit_code;
        statement.is_complete = is_complete;
        assert!(statement.validate().is_err());
        assert!(serde_json::from_value::<FinalStatement>(serde_json::to_value(statement).unwrap()).is_err());
    }
}

#[test]
fn validated_pins_have_fixed_width_and_are_detached_from_mutable_wire_values() {
    let mut wire = fixture();
    let checked = wire.validate().unwrap();
    assert_eq!(checked.wrap_vk_sha256().len(), 32);
    assert_eq!(checked.program_vk_digest().len(), 8);
    assert_eq!(checked.committed_values_sha256().len(), 32);
    assert_eq!(checked.recursion_vk_root().len(), 8);
    wire.program_vk_digest.clear();
    wire.committed_values_sha256.clear();
    assert!(wire.validate().is_err());
    assert_eq!(checked, fixture().validate().unwrap());
}

#[test]
fn hex_case_is_normalized_for_semantic_pin_equality() {
    let lower = fixture();
    let mut upper = lower.clone();
    for field in PIN_FIELDS {
        pin(&mut upper, field).make_ascii_uppercase();
    }
    assert_eq!(lower.validate().unwrap(), upper.validate().unwrap());
}

#[test]
fn all_hash_bytes_and_all_field_limbs_participate_in_pin_equality() {
    let reference = fixture();
    let checked = reference.validate().unwrap();
    for field in ["wrap_vk_sha256", "committed_values_sha256"] {
        for byte in 0..32 {
            let mut changed = reference.clone();
            let text = pin(&mut changed, field);
            let value = u8::from_str_radix(&text[byte * 2..byte * 2 + 2], 16).unwrap() ^ 1;
            text.replace_range(byte * 2..byte * 2 + 2, &format!("{value:02x}"));
            assert_ne!(checked, changed.validate().unwrap(), "omitted {field} byte {byte}");
        }
    }
    for field in ["program_vk_digest", "recursion_vk_root"] {
        for limb in 0..8 {
            let mut changed = reference.clone();
            let text = pin(&mut changed, field);
            let mut bytes = [0; 4];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&text[limb * 8 + i * 2..limb * 8 + i * 2 + 2], 16).unwrap();
            }
            let value = (u32::from_le_bytes(bytes) + 1) % KOALABEAR_MODULUS;
            text.replace_range(limb * 8..limb * 8 + 8, &encode_bytes(&value.to_le_bytes()));
            assert_ne!(checked, changed.validate().unwrap(), "omitted {field} limb {limb}");
        }
    }
}

#[test]
fn duplicate_unknown_and_missing_statement_fields_are_rejected() {
    let mut json: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    json["unexpected"] = true.into();
    assert!(serde_json::from_value::<FinalStatement>(json).is_err());
    let mut json: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    json.as_object_mut().unwrap().remove("program_vk_digest");
    assert!(serde_json::from_value::<FinalStatement>(json).is_err());
    let duplicate = FIXTURE.replacen('{', "{\"exit_code\":0,", 1);
    assert!(serde_json::from_str::<FinalStatement>(&duplicate).is_err());
}
