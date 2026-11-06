//! Hosted TEST-ONLY material and local tree rejection checks for small chain probes.
//!
//! The caller independently checks the positive component's source metadata and
//! the probe's exact topology/assignment before calling `material`. This helper
//! admits only the closed small-probe inventory, validates catalogue identities
//! and ranges, then creates a separate WOTS namespace. It does not establish
//! proof-byte provenance, execute Script, or implement production key lifecycle.

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
use std::collections::{BTreeMap, HashSet};

const MAIN_UNIQUE_WORDS: usize = 147_355;
const WOTS_PAYLOAD_BYTES: usize = 200;
const KEY_DOMAIN: &[u8] = b"BITVM2-NOVA/TEST-ONLY-BYTE-RHO-CHAIN-PROBE-WOTS/v1\0";
const FOREIGN_DOMAIN: &[u8] = b"BITVM2-NOVA/TEST-ONLY-BYTE-RHO-CHAIN-PROBE-FOREIGN/v1\0";

fn admission(
    probe_name: &str,
    component: usize,
    role: &str,
    words: usize,
    leaves: usize,
    values: usize,
    main_keys: usize,
) -> Result<()> {
    let name = probe_name.as_bytes();
    if name.len() != 4
        || name[1..3] != *b"/q"
        || !matches!(name[0], b'p' | b'v')
        || !name[3].is_ascii_digit()
    {
        return Err("closed p/q0..q9 or v/q0..q9 probe identity required".into());
    }
    let expected_role = if name[0] == b'p' {
        "pallas_scalar"
    } else {
        "vesta_scalar"
    };
    let expected = if name[3] <= b'5' {
        (3, 187, 111)
    } else {
        (5, 23, 9)
    };
    if role != expected_role
        || (component, words, leaves) != expected
        || values != words
        || main_keys != MAIN_UNIQUE_WORDS
    {
        return Err("probe role/component/census or complete main-key catalogue differs".into());
    }
    Ok(())
}

fn source_digest(value: &str) -> Result<[u8; 32]> {
    let digest = id32(value)?;
    if hex::encode(digest) != value {
        return Err("probe source SHA must be canonical lowercase32 hex".into());
    }
    Ok(digest)
}

fn framed(h: &mut sha256::HashEngine, value: &str) {
    // All admitted IDs are ASCII and at most 192 bytes; the closed probe ID is
    // exactly four bytes. The u16 length cannot truncate either input.
    h.input(&(value.len() as u16).to_le_bytes());
    h.input(value.as_bytes());
}

fn seed(source: &[u8; 32], probe_name: &str, local_name: &str) -> [u8; 32] {
    let mut h = sha256::Hash::engine();
    h.input(KEY_DOMAIN);
    h.input(source);
    framed(&mut h, probe_name);
    framed(&mut h, local_name);
    sha256::Hash::from_engine(h).to_byte_array()
}

fn payload_hash(payload: &[u8], seen: &mut HashSet<[u8; 32]>) -> Result<[u8; 32]> {
    if payload.len() != WOTS_PAYLOAD_BYTES {
        return Err("probe WOTS payload must be exactly 200 bytes".into());
    }
    let hash = sha256::Hash::hash(payload).to_byte_array();
    if !seen.insert(hash) {
        return Err("distinct probe words have duplicate WOTS payload hashes".into());
    }
    Ok(hash)
}

/// Create one new key/signature per local probe word, never re-sign main keys.
///
/// `source_sha256` is the freshly checked positive SMALL COMPONENT source SHA,
/// not a claimed whole-chain receipt. Its metadata-to-catalogue relationship is
/// checked by the caller; only its canonical encoding can be checked here.
/// The caller invokes each closed probe ID once and supplies the complete
/// immutable positive source-case key set. Bounds and values are deliberately
/// excluded from seeds, so they cannot silently select a replacement key.
pub fn material(
    spec: &GraphSpec,
    values: &[u32],
    source_sha256: &str,
    probe_name: &str,
    source_component: usize,
    source_main_key_hashes: &HashSet<[u8; 32]>,
) -> Result<(Registry, Vec<PublicKey>, Vec<Signature>)> {
    admission(
        probe_name,
        source_component,
        &spec.field_role,
        spec.words.len(),
        spec.leaves.len(),
        values.len(),
        source_main_key_hashes.len(),
    )?;
    let source = source_digest(source_sha256)?;
    source_digest(&spec.program_sha256)?;
    source_digest(&spec.context)?;
    let catalogue = spec.identity()?;
    if spec
        .words
        .iter()
        .zip(values)
        .any(|(word, value)| *value >= word.bound)
    {
        return Err("small probe assignment exceeds its exact declared word bound".into());
    }

    // Validate every seed and every generated key before signing any value.
    // The full positive-case set also rejects a collision with a main word in
    // any other component, including words absent from this small catalogue.
    let mut seeds = HashSet::new();
    let mut secrets = Vec::with_capacity(spec.words.len());
    for word in &spec.words {
        let secret = seed(&source, probe_name, &word.name);
        if !seeds.insert(secret) {
            return Err("distinct probe local words have duplicate seeds".into());
        }
        secrets.push(secret.to_vec());
    }
    let mut key_hashes = HashSet::new();
    let mut keys = Vec::with_capacity(spec.words.len());
    for secret in &secrets {
        let key = Wots4::generate_public_key(secret);
        let payload: Vec<_> = key.iter().flat_map(|part| part.iter().copied()).collect();
        let hash = payload_hash(&payload, &mut key_hashes)?;
        if source_main_key_hashes.contains(&hash) {
            return Err("probe WOTS key collides with the positive source-case catalogue".into());
        }
        keys.push(key);
    }
    let registry_id = spec.key_identity(&keys)?;
    let registry = Registry::new(spec.clone(), keys.clone(), catalogue, registry_id)?;
    let mut signature_hashes = HashSet::new();
    let mut signatures = Vec::with_capacity(spec.words.len());
    for (secret, value) in secrets.iter().zip(values) {
        let signature = Wots4::compact_sign(secret, &value.to_le_bytes());
        let payload: Vec<_> = signature
            .iter()
            .flat_map(|part| part.iter().copied())
            .collect();
        payload_hash(&payload, &mut signature_hashes)?;
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
        return Err(format!("negative probe tree opening accepted: {name}").into());
    }
    *counts.entry(name).or_default() += 1;
    Ok(())
}

/// Exercise the same twelve local membership rejection classes as the frozen
/// full-permutation worker, using the actual local leaf count. No Script engine
/// execution or panic-to-rejection conversion occurs here.
pub fn tree_negatives(
    tree: &TaprootCommitment,
    registry: &Registry,
    keys: &[PublicKey],
) -> Result<BTreeMap<&'static str, usize>> {
    let spec = registry.spec();
    let catalogue = spec.identity()?;
    let leaf_count = spec.leaves.len();
    let ordinal = tree.selected_ordinal();
    if leaf_count < 2
        || ordinal >= leaf_count
        || tree.leaf_count() != leaf_count
        || spec.key_identity(keys)? != registry.identity()
    {
        return Err("tree negatives require the actual selected registry/key catalogue".into());
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
        *bad.get_mut(index)
            .ok_or("selected control mutation bound")? ^= mask;
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
        return Err("negative output key equals actual tree key".into());
    }
    reject(
        tree.verify_member(registry, root, wrong, ordinal),
        "output_key",
        &mut counts,
    )?;
    reject(
        tree.verify_member(registry, root, key, (ordinal + 1) % leaf_count),
        "ordinal",
        &mut counts,
    )?;
    let mut foreign = keys.to_vec();
    let foreign_key = Wots4::generate_public_key(
        &foreign_seed(&catalogue, &registry.identity(), "tree/registry").to_vec(),
    );
    if keys.contains(&foreign_key) {
        return Err("foreign tree key collides with an actual registry key".into());
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
    let mut changed_spec = spec.clone();
    changed_spec.context = hex::encode(foreign_seed(
        &catalogue,
        &registry.identity(),
        "tree/catalogue",
    ));
    if changed_spec.context == spec.context {
        return Err("foreign catalogue context equals the actual context".into());
    }
    let changed_catalogue = changed_spec.identity()?;
    let id = changed_spec.key_identity(keys)?;
    let other = Registry::new(changed_spec, keys.to_vec(), changed_catalogue, id)?;
    reject(
        tree.verify_member(&other, root, key, ordinal),
        "catalogue",
        &mut counts,
    )?;
    if counts.len() != 12 || counts.values().any(|count| *count != 1) {
        return Err("exactly 12 local tree rejection classes required".into());
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_twenty_probe_inventory_is_admitted_without_crypto() {
        for (prefix, role) in [("p", "pallas_scalar"), ("v", "vesta_scalar")] {
            for index in 0..10 {
                let (component, words, leaves) = if index < 6 { (3, 187, 111) } else { (5, 23, 9) };
                admission(
                    &format!("{prefix}/q{index}"),
                    component,
                    role,
                    words,
                    leaves,
                    words,
                    MAIN_UNIQUE_WORDS,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn aliases_and_out_of_inventory_names_are_rejected_without_crypto() {
        for name in [
            "",
            "p/q",
            "p/q00",
            "p/q10",
            "p/Q0",
            "x/q0",
            "p/q/0",
            "p/q0/",
            "p/q:",
            "v/q-1",
            "p/q\u{e9}",
        ] {
            assert!(admission(name, 3, "pallas_scalar", 187, 111, 187, MAIN_UNIQUE_WORDS).is_err());
        }
    }

    #[test]
    fn role_component_dimensions_and_complete_main_catalogue_are_mandatory() {
        for (component, role, words, leaves, values, main_keys) in [
            (5, "pallas_scalar", 187, 111, 187, MAIN_UNIQUE_WORDS),
            (3, "vesta_scalar", 187, 111, 187, MAIN_UNIQUE_WORDS),
            (3, "pallas_base", 187, 111, 187, MAIN_UNIQUE_WORDS),
            (3, "pallas_scalar", 186, 111, 186, MAIN_UNIQUE_WORDS),
            (3, "pallas_scalar", 187, 110, 187, MAIN_UNIQUE_WORDS),
            (3, "pallas_scalar", 187, 111, 186, MAIN_UNIQUE_WORDS),
            (3, "pallas_scalar", 187, 111, 188, MAIN_UNIQUE_WORDS),
            (3, "pallas_scalar", 187, 111, 187, 0),
            (3, "pallas_scalar", 187, 111, 187, 187),
            (3, "pallas_scalar", 187, 111, 187, MAIN_UNIQUE_WORDS - 1),
            (3, "pallas_scalar", 187, 111, 187, MAIN_UNIQUE_WORDS + 1),
        ] {
            assert!(admission("p/q0", component, role, words, leaves, values, main_keys).is_err());
        }
        assert!(admission("p/q6", 3, "pallas_scalar", 187, 111, 187, MAIN_UNIQUE_WORDS).is_err());
        assert!(admission("v/q5", 5, "vesta_scalar", 23, 9, 23, MAIN_UNIQUE_WORDS).is_err());
    }
}
