//! Hosted TEST-ONLY key material and local-tree checks for the closed74 probes.
//!
//! Before calling material the worker independently checks each exact source,
//! topology and numeric recipe. The full main-key set must come from the actual
//! immutable155146-entry positive pool, not an imported receipt. Private probe
//! words get a separate domain and all public keys are checked before any value
//! is signed. This helper neither executes Script nor accepts a proof verdict.
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::XOnlyPublicKey,
    taproot::TapNodeHash,
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    registry::{GraphSpec, Registry, Signature},
    taproot_commitment::{verify_opening, TaprootCommitment},
    wots::{id32, PublicKey, Result},
};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

const MAIN_KEYS: usize = 155_146;
const PAYLOAD_BYTES: usize = 200;
const KEY_DOMAIN: &[u8] = b"BITVM2-NOVA/TEST-ONLY-RETAINED-SCALAR-SOURCES-PROBE-WOTS/v1\0";
const FOREIGN_DOMAIN: &[u8] = b"BITVM2-NOVA/TEST-ONLY-RETAINED-SCALAR-SOURCES-PROBE-FOREIGN/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Exception {
    slot: usize,
    word: &'static str,
    bound: u32,
    value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Policy {
    exceptional_slot: Option<Exception>,
}

fn admission(
    name: &str,
    component: Option<usize>,
    role: &str,
    words: usize,
    leaves: usize,
    values: usize,
    main_keys: usize,
) -> Result<Policy> {
    if main_keys != MAIN_KEYS {
        return Err("complete155146-key positive catalogue required before probe keygen".into());
    }
    let text = name.as_bytes();
    if text.len() < 3 || !matches!(text[0], b'p' | b'v') || text[1] != b'/' {
        return Err("closed p/v probe identity required".into());
    }
    let (point, expected, exceptional_slot) = match text {
        [_, b'/', b'q', i] if i.is_ascii_digit() => (
            false,
            if *i <= b'5' {
                (Some(3), 187, 111)
            } else {
                (Some(5), 23, 9)
            },
            None,
        ),
        [_, b'/', b'e', i] if (b'0'..=b'5').contains(i) => (true, (Some(10), 7498, 6161), None),
        [_, b'/', b'n', i] if (b'0'..=b'8').contains(i) => (
            true,
            (Some(10), 7498, 6161),
            match *i {
                b'3' => Some(Exception {
                    slot: 7479,
                    word: "selected/infinity",
                    bound: 2,
                    value: 2,
                }),
                b'6' => Some(Exception {
                    slot: 7476,
                    word: "select/bit",
                    bound: 2,
                    value: 2,
                }),
                _ => None,
            },
        ),
        [_, b'/', b's'] => (false, (None, 634, 254), None),
        [_, b'/', b'u', i] if (b'0'..=b'6').contains(i) => (
            false,
            (Some(12), 55, 17),
            (*i == b'6').then_some(Exception {
                slot: 9,
                word: "scalar/encoding/byte/0",
                bound: 256,
                value: u32::MAX,
            }),
        ),
        [_, b'/', b't', i] if (b'0'..=b'3').contains(i) => (
            false,
            (Some(11), 112, 112),
            (*i == b'3').then_some(Exception {
                slot: 0,
                word: "block/byte/0",
                bound: 256,
                value: 256,
            }),
        ),
        _ => return Err("closed q0..9/e0..5/n0..8/s/u0..6/t0..3 probe identity required".into()),
    };
    let expected_role = match (text[0], point) {
        (b'p', false) => "pallas_scalar",
        (b'v', false) => "vesta_scalar",
        (b'p', true) => "pallas_base",
        (b'v', true) => "vesta_base",
        _ => return Err("probe role".into()),
    };
    if role != expected_role || (component, words, leaves) != expected || values != words {
        return Err("closed probe component/census/role NAME or exact value count differs".into());
    }
    Ok(Policy { exceptional_slot })
}

fn value_admitted(policy: Policy, slot: usize, name: &str, bound: u32, value: u32) -> Result<()> {
    if let Some(exception) = policy.exceptional_slot {
        if slot == exception.slot {
            if name != exception.word || bound != exception.bound || value != exception.value {
                return Err(
                    "closed signed out-of-bound probe must retain its exact slot/name/bound/value"
                        .into(),
                );
            }
            return Ok(());
        }
    }
    if value >= bound {
        return Err("probe value exceeds an undeclared out-of-bound exception".into());
    }
    Ok(())
}
fn digest(value: &str) -> Result<[u8; 32]> {
    let bytes = id32(value)?;
    if hex::encode(bytes) != value {
        return Err("canonical lowercase32 probe source identity required".into());
    }
    Ok(bytes)
}
fn framed(h: &mut sha256::HashEngine, text: &str) {
    // Probe IDs have3/4 ASCII bytes and admitted local names at most192 bytes.
    h.input(&(text.len() as u16).to_le_bytes());
    h.input(text.as_bytes());
}
fn seed(source: &[u8; 32], name: &str, local: &str) -> [u8; 32] {
    let mut h = sha256::Hash::engine();
    h.input(KEY_DOMAIN);
    h.input(source);
    framed(&mut h, name);
    framed(&mut h, local);
    sha256::Hash::from_engine(h).to_byte_array()
}
fn payload_hash(payload: &[u8], seen: &mut HashSet<[u8; 32]>) -> Result<[u8; 32]> {
    if payload.len() != PAYLOAD_BYTES {
        return Err("probe WOTS key/signature payload must be exactly200 bytes".into());
    }
    let hash = sha256::Hash::hash(payload).to_byte_array();
    if !seen.insert(hash) {
        return Err("distinct probe words have duplicate WOTS payload hashes".into());
    }
    Ok(hash)
}
fn separate_key(hash: [u8; 32], main: &HashSet<[u8; 32]>) -> Result<()> {
    if main.contains(&hash) {
        return Err("private probe key collides with the complete positive main catalogue".into());
    }
    Ok(())
}

/// Generate one private test key/signature per probe-local word. The caller
/// invokes each closed ID once and independently authenticates the SMALL/point
/// source relationship before this function. Seeds exclude both values/bounds.
pub fn material(
    spec: &GraphSpec,
    values: &[u32],
    source_sha256: &str,
    probe_name: &str,
    source_component: Option<usize>,
    main_key_hashes: &HashSet<[u8; 32]>,
) -> Result<(Registry, Vec<PublicKey>, Vec<Signature>)> {
    let policy = admission(
        probe_name,
        source_component,
        &spec.field_role,
        spec.words.len(),
        spec.leaves.len(),
        values.len(),
        main_key_hashes.len(),
    )?;
    let source = digest(source_sha256)?;
    digest(&spec.context)?;
    digest(&spec.program_sha256)?;
    let catalogue = spec.identity()?;
    for (slot, (word, value)) in spec.words.iter().zip(values).enumerate() {
        value_admitted(policy, slot, &word.name, word.bound, *value)?;
    }
    let mut seeds = HashSet::new();
    let mut secrets = Vec::with_capacity(spec.words.len());
    for word in &spec.words {
        let secret = seed(&source, probe_name, &word.name);
        if !seeds.insert(secret) {
            return Err("duplicate private probe word seed".into());
        }
        secrets.push(secret.to_vec());
    }
    // Complete every key/collision check before the FIRST compact_sign call.
    let mut key_hashes = HashSet::new();
    let mut keys = Vec::with_capacity(spec.words.len());
    for secret in &secrets {
        let key = Wots4::generate_public_key(secret);
        let payload: Vec<_> = key.iter().flat_map(|p| p.iter().copied()).collect();
        let hash = payload_hash(&payload, &mut key_hashes)?;
        separate_key(hash, main_key_hashes)?;
        keys.push(key);
    }
    let registry_id = spec.key_identity(&keys)?;
    let registry = Registry::new(spec.clone(), keys.clone(), catalogue, registry_id)?;
    let mut hashes = HashSet::new();
    let mut signatures = Vec::with_capacity(spec.words.len());
    for (secret, value) in secrets.iter().zip(values) {
        let signature = Wots4::compact_sign(secret, &value.to_le_bytes());
        let payload: Vec<_> = signature.iter().flat_map(|p| p.iter().copied()).collect();
        payload_hash(&payload, &mut hashes)?;
        signatures.push(signature);
    }
    Ok((registry, keys, signatures))
}

fn foreign_seed(catalogue: &[u8; 32], registry: &[u8; 32], purpose: &str) -> [u8; 32] {
    let mut h = sha256::Hash::engine();
    h.input(FOREIGN_DOMAIN);
    h.input(catalogue);
    h.input(registry);
    framed(&mut h, purpose);
    sha256::Hash::from_engine(h).to_byte_array()
}
fn reject<T>(
    result: Result<T>,
    name: &'static str,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    if result.is_ok() {
        return Err(format!("negative private tree opening accepted: {name}").into());
    }
    *counts.entry(name).or_default() += 1;
    Ok(())
}

/// Twelve actual local Taproot membership rejection classes. This never runs
/// Script or catches an interpreter panic as a successful rejection.
pub fn tree_negatives(
    tree: &TaprootCommitment,
    registry: &Registry,
    keys: &[PublicKey],
) -> Result<Value> {
    let spec = registry.spec();
    let catalogue = spec.identity()?;
    let leaves = spec.leaves.len();
    let ordinal = tree.selected_ordinal();
    if leaves < 2
        || ordinal >= leaves
        || tree.leaf_count() != leaves
        || spec.key_identity(keys)? != registry.identity()
    {
        return Err(
            "local tree checks require the actual selected registry and complete keys".into(),
        );
    }
    let root = tree.merkle_root();
    let key = tree.output_key();
    tree.verify_member(registry, root, key, ordinal)?;
    let script = tree.selected_script();
    let control = tree.control_block_bytes();
    let mut counts = BTreeMap::new();
    let mut bad = script.as_bytes().to_vec();
    *bad.first_mut().ok_or("empty selected tree script")? ^= 1;
    reject(
        verify_opening(
            registry,
            root,
            key,
            ordinal,
            ScriptBuf::from_bytes(bad).as_script(),
            &control,
        ),
        "altered_script",
        &mut counts,
    )?;
    for (name, index, mask) in [
        ("branch", 33, 1),
        ("parity", 0, 1),
        ("internal_key", 1, 1),
        ("leaf_version", 0, 2),
    ] {
        let mut bad = control.clone();
        *bad.get_mut(index).ok_or("local control mutation bound")? ^= mask;
        reject(
            verify_opening(registry, root, key, ordinal, script, &bad),
            name,
            &mut counts,
        )?;
    }
    reject(
        verify_opening(
            registry,
            root,
            key,
            ordinal,
            script,
            &control[..control.len() - 1],
        ),
        "truncated_control",
        &mut counts,
    )?;
    let mut bad = control.clone();
    bad.push(0);
    reject(
        verify_opening(registry, root, key, ordinal, script, &bad),
        "appended_control",
        &mut counts,
    )?;
    let mut raw = root.to_byte_array();
    raw[0] ^= 1;
    reject(
        tree.verify_member(registry, TapNodeHash::assume_hidden(raw), key, ordinal),
        "root",
        &mut counts,
    )?;
    let wrong = XOnlyPublicKey::from_slice(&hex::decode(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )?)?;
    if wrong == key {
        return Err("negative output key equals actual local tree key".into());
    }
    reject(
        tree.verify_member(registry, root, wrong, ordinal),
        "output_key",
        &mut counts,
    )?;
    reject(
        tree.verify_member(registry, root, key, (ordinal + 1) % leaves),
        "ordinal",
        &mut counts,
    )?;
    let mut foreign = keys.to_vec();
    let foreign_key = Wots4::generate_public_key(
        &foreign_seed(&catalogue, &registry.identity(), "tree/registry").to_vec(),
    );
    if keys.contains(&foreign_key) {
        return Err("foreign registry key collides with actual private probe keys".into());
    }
    foreign[0] = foreign_key;
    let id = spec.key_identity(&foreign)?;
    let other = Registry::new(spec.clone(), foreign, catalogue, id)?;
    reject(
        tree.verify_member(&other, root, key, ordinal),
        "registry",
        &mut counts,
    )?;
    drop(other);
    let mut changed = spec.clone();
    changed.context = hex::encode(foreign_seed(
        &catalogue,
        &registry.identity(),
        "tree/catalogue",
    ));
    if changed.context == spec.context {
        return Err("foreign catalogue context equals actual context".into());
    }
    let other_catalogue = changed.identity()?;
    let id = changed.key_identity(keys)?;
    let other = Registry::new(changed, keys.to_vec(), other_catalogue, id)?;
    reject(
        tree.verify_member(&other, root, key, ordinal),
        "catalogue",
        &mut counts,
    )?;
    if counts.len() != 12 || counts.values().any(|v| *v != 1) {
        return Err("exactly12 local tree rejection classes required".into());
    }
    Ok(serde_json::to_value(counts)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_seventy_four_profile_inventory_is_closed_before_crypto() {
        let mut count = 0;
        for (prefix, scalar, base) in [
            ("p", "pallas_scalar", "pallas_base"),
            ("v", "vesta_scalar", "vesta_base"),
        ] {
            for i in 0..10 {
                let (component, words, leaves) = if i < 6 {
                    (Some(3), 187, 111)
                } else {
                    (Some(5), 23, 9)
                };
                assert_eq!(
                    admission(
                        &format!("{prefix}/q{i}"),
                        component,
                        scalar,
                        words,
                        leaves,
                        words,
                        MAIN_KEYS
                    )
                    .unwrap()
                    .exceptional_slot,
                    None
                );
                count += 1;
            }
            for i in 0..6 {
                admission(
                    &format!("{prefix}/e{i}"),
                    Some(10),
                    base,
                    7498,
                    6161,
                    7498,
                    MAIN_KEYS,
                )
                .unwrap();
                count += 1;
            }
            for i in 0..9 {
                let policy = admission(
                    &format!("{prefix}/n{i}"),
                    Some(10),
                    base,
                    7498,
                    6161,
                    7498,
                    MAIN_KEYS,
                )
                .unwrap();
                assert_eq!(
                    policy.exceptional_slot,
                    match i {
                        3 => Some(Exception {
                            slot: 7479,
                            word: "selected/infinity",
                            bound: 2,
                            value: 2
                        }),
                        6 => Some(Exception {
                            slot: 7476,
                            word: "select/bit",
                            bound: 2,
                            value: 2
                        }),
                        _ => None,
                    }
                );
                count += 1;
            }
            admission(
                &format!("{prefix}/s"),
                None,
                scalar,
                634,
                254,
                634,
                MAIN_KEYS,
            )
            .unwrap();
            count += 1;
            for i in 0..7 {
                let policy = admission(
                    &format!("{prefix}/u{i}"),
                    Some(12),
                    scalar,
                    55,
                    17,
                    55,
                    MAIN_KEYS,
                )
                .unwrap();
                assert_eq!(
                    policy.exceptional_slot,
                    (i == 6).then_some(Exception {
                        slot: 9,
                        word: "scalar/encoding/byte/0",
                        bound: 256,
                        value: u32::MAX
                    })
                );
                count += 1;
            }
            for i in 0..4 {
                let policy = admission(
                    &format!("{prefix}/t{i}"),
                    Some(11),
                    scalar,
                    112,
                    112,
                    112,
                    MAIN_KEYS,
                )
                .unwrap();
                assert_eq!(
                    policy.exceptional_slot,
                    (i == 3).then_some(Exception {
                        slot: 0,
                        word: "block/byte/0",
                        bound: 256,
                        value: 256
                    })
                );
                count += 1;
            }
        }
        assert_eq!(count, 74);
    }

    #[test]
    fn aliases_wrong_roles_dimensions_and_incomplete_main_key_sets_fail_before_crypto() {
        for name in [
            "", "p/", "p/q", "p/q00", "p/q10", "p/e6", "p/n9", "p/s0", "p/S", "x/q0", "p/q-1",
            "p/\u{e9}", "p/u7", "p/t4", "p/u00", "p/t00", "v/u-1", "v/t-1",
        ] {
            assert!(admission(name, Some(3), "pallas_scalar", 187, 111, 187, MAIN_KEYS).is_err());
        }
        for main_keys in [0, 1, MAIN_KEYS - 1, MAIN_KEYS + 1] {
            assert!(admission("p/q0", Some(3), "pallas_scalar", 187, 111, 187, main_keys).is_err());
        }
        assert!(admission("p/q0", Some(3), "vesta_scalar", 187, 111, 187, MAIN_KEYS).is_err());
        assert!(admission(
            "p/e0",
            Some(10),
            "pallas_scalar",
            7498,
            6161,
            7498,
            MAIN_KEYS
        )
        .is_err());
        assert!(admission("p/q6", Some(3), "pallas_scalar", 23, 9, 23, MAIN_KEYS).is_err());
        assert!(admission("p/s", Some(9), "pallas_scalar", 634, 254, 634, MAIN_KEYS).is_err());
        assert!(admission("p/s", None, "pallas_scalar", 633, 254, 633, MAIN_KEYS).is_err());
        assert!(admission("p/n0", Some(10), "pallas_base", 7498, 6160, 7498, MAIN_KEYS).is_err());
        assert!(admission("v/n0", Some(10), "vesta_base", 7498, 6161, 7497, MAIN_KEYS).is_err());
    }

    #[test]
    fn signed_boolean_two_exceptions_are_exact_and_other_values_keep_their_full_u32() {
        let ordinary = Policy {
            exceptional_slot: None,
        };
        for bound in [1, 2, 256, 1 << 29] {
            value_admitted(ordinary, 0, "word", bound, bound - 1).unwrap();
            assert!(value_admitted(ordinary, 0, "word", bound, bound).is_err());
            assert!(value_admitted(ordinary, 0, "word", bound, u32::MAX).is_err());
        }
        for (name, slot, word) in [
            ("p/n3", 7479, "selected/infinity"),
            ("v/n6", 7476, "select/bit"),
        ] {
            let role = if name.starts_with('p') {
                "pallas_base"
            } else {
                "vesta_base"
            };
            let policy = admission(name, Some(10), role, 7498, 6161, 7498, MAIN_KEYS).unwrap();
            value_admitted(policy, slot, word, 2, 2).unwrap();
            assert!(value_admitted(policy, slot, word, 2, 1).is_err());
            assert!(value_admitted(policy, slot, word, 2, 3).is_err());
            assert!(value_admitted(policy, slot, word, 5, 2).is_err());
            assert!(value_admitted(policy, slot, "wrong/word", 2, 2).is_err());
            assert!(value_admitted(policy, slot + 1, word, 2, 2).is_err());
            value_admitted(policy, slot + 1, "other", 2, 1).unwrap();
        }
    }

    #[test]
    fn eval_w_and_tape_exceptions_fix_slot_name_bound_and_full_unsigned_value() {
        for (name, component, role, words, leaves, slot, word, value) in [
            (
                "p/u6",
                Some(12),
                "pallas_scalar",
                55,
                17,
                9,
                "scalar/encoding/byte/0",
                u32::MAX,
            ),
            (
                "v/t3",
                Some(11),
                "vesta_scalar",
                112,
                112,
                0,
                "block/byte/0",
                256,
            ),
        ] {
            let policy = admission(name, component, role, words, leaves, words, MAIN_KEYS).unwrap();
            value_admitted(policy, slot, word, 256, value).unwrap();
            for changed in [0, 255, value - 1] {
                assert!(value_admitted(policy, slot, word, 256, changed).is_err());
            }
            assert!(value_admitted(policy, slot, "different/byte", 256, value).is_err());
            assert!(value_admitted(policy, slot, word, 2, value).is_err());
            assert!(value_admitted(policy, slot + 1, word, 256, value).is_err());
            value_admitted(policy, slot + 1, "other/byte", 256, 255).unwrap();
        }
        for name in ["p/u0", "p/u5"] {
            let ordinary =
                admission(name, Some(12), "pallas_scalar", 55, 17, 55, MAIN_KEYS).unwrap();
            assert!(value_admitted(ordinary, 9, "scalar/encoding/byte/0", 256, u32::MAX).is_err());
        }
        let ordinary =
            admission("v/t2", Some(11), "vesta_scalar", 112, 112, 112, MAIN_KEYS).unwrap();
        assert!(value_admitted(ordinary, 0, "block/byte/0", 256, 256).is_err());
        for (name, component, role, words, leaves, values) in [
            ("p/u0", Some(11), "pallas_scalar", 55, 17, 55),
            ("v/u0", Some(12), "vesta_base", 55, 17, 55),
            ("p/u0", Some(12), "pallas_scalar", 54, 17, 54),
            ("p/u0", Some(12), "pallas_scalar", 55, 16, 55),
            ("p/u0", Some(12), "pallas_scalar", 55, 17, 54),
            ("v/t0", Some(12), "vesta_scalar", 112, 112, 112),
            ("v/t0", Some(11), "vesta_base", 112, 112, 112),
            ("v/t0", Some(11), "vesta_scalar", 111, 112, 111),
            ("v/t0", Some(11), "vesta_scalar", 112, 111, 112),
            ("v/t0", Some(11), "vesta_scalar", 112, 112, 111),
        ] {
            assert!(admission(name, component, role, words, leaves, values, MAIN_KEYS).is_err());
        }
    }

    #[test]
    fn seed_domains_frame_source_probe_and_local_names_without_values_or_bounds() {
        let source = digest(&"00".repeat(32)).unwrap();
        let other = digest(&"01".repeat(32)).unwrap();
        let original = seed(&source, "p/n3", "selected/infinity");
        assert_eq!(original, seed(&source, "p/n3", "selected/infinity"));
        for changed in [
            seed(&other, "p/n3", "selected/infinity"),
            seed(&source, "v/n3", "selected/infinity"),
            seed(&source, "p/n6", "selected/infinity"),
            seed(&source, "p/n3", "select/bit"),
        ] {
            assert_ne!(original, changed);
        }
        assert_ne!(seed(&source, "a", "bc"), seed(&source, "ab", "c"));
        assert_ne!(
            original,
            foreign_seed(&source, &source, "p/n3/selected/infinity")
        );
        assert!(digest(&"AA".repeat(32)).is_err());
        assert!(digest(&"00".repeat(31)).is_err());
    }

    #[test]
    fn duplicate_payloads_and_main_collisions_are_rejected_without_key_generation() {
        let mut seen = HashSet::new();
        let zero = payload_hash(&[0; 200], &mut seen).unwrap();
        assert!(payload_hash(&[0; 200], &mut seen).is_err());
        let one = payload_hash(&[1; 200], &mut seen).unwrap();
        assert_ne!(zero, one);
        assert!(payload_hash(&[2; 199], &mut seen).is_err());
        assert!(payload_hash(&[2; 201], &mut seen).is_err());
        let main = HashSet::from([zero]);
        assert!(separate_key(zero, &main).is_err());
        separate_key(one, &main).unwrap();
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn rejection_counters_never_count_success_or_convert_panics() {
        let mut counts = BTreeMap::new();
        assert!(reject(Ok(()), "ordinal", &mut counts).is_err());
        assert!(counts.is_empty());
        reject::<()>(
            Err("known ordinary membership failure".into()),
            "ordinal",
            &mut counts,
        )
        .unwrap();
        assert_eq!(counts.get("ordinal"), Some(&1));
    }
}
