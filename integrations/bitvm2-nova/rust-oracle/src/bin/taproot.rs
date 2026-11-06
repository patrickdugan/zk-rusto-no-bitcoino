//! Offline Taproot commitment checks over the unchanged global-registry fixtures.
//! Deterministic TEST-ONLY WOTS public keys match bin/registry.rs byte for byte.
//! Membership is not Script execution, an assertion UTXO or a Bitcoin transaction.
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::XOnlyPublicKey,
    taproot::TapNodeHash,
    ScriptBuf,
};
use bitvm::signatures::{Wots, Wots4};
use bitvm2_nova_script_oracle::{
    registry::{GraphSpec, Registry},
    taproot_commitment::{verify_opening, TaprootCommitment},
    wots::{id32, PublicKey, Result},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::Read,
    time::Instant,
};

const INPUT_CAP: usize = 32 * 1024 * 1024;
const OUTPUT_CAP: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    ordinal: usize,
    expected_correct: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    spec: GraphSpec,
    expected_spec_id: String,
    words: Vec<u32>,
    checks: Vec<Check>,
    measure_all: bool,
}

struct Constructed {
    case_name: String,
    registry: Registry,
    commitments: Vec<(TaprootCommitment, f64)>,
}

fn baseline(name: &str) -> Option<(u64, &'static str)> {
    // The same eight immutable streams independently executed by bin/registry.rs.
    match name {
        "pallas_base/honest-full-multiplication" => Some((
            16_798_073,
            "b0971c94594cebb5134b4f70786a97a1d9b8202afeea6236c3b42c456914bec4",
        )),
        "vesta_base/honest-full-multiplication" => Some((
            16_798_073,
            "61eeed34e6541bb89df28625a47f92ecf2c2929be474207bf22de03f943fda75",
        )),
        "pallas/point-graph" => Some((
            219_498_908,
            "39744f1ea8961aa36a0f3ffc472baaebb2363def55c3c684cf56c8b0d642a7c4",
        )),
        "vesta/point-graph" => Some((
            219_498_908,
            "a2c5d28cd29a32daa31d61eae07cebf927f6cf823b0b5528df666e606c67deef",
        )),
        "pallas_base/convolution-mul" => Some((
            6_993_315,
            "23bf6823a5cc8bc0ec20d3c95462827cb45d01d92b356c59442e3480cf1e8d7a",
        )),
        "vesta_base/convolution-mul" => Some((
            7_001_191,
            "ca7ea7653dfbb426ea80aecb531e6f1a002777c9600fcccbaf39860fc87d1c6e",
        )),
        "pallas/convolution-point" => Some((
            88_586_200,
            "b89b9aef5be9e089717cdf3a4355a5ac4b3d1ca3a3d455ab7c108aa55ad81a75",
        )),
        "vesta/convolution-point" => Some((
            88_688_588,
            "8b606dd645fe43c3c6c620a5f0c519fba4192e3bd46fd0719f8c4a2dbe1bb4ce",
        )),
        _ => None,
    }
}

fn validate_case(case: &Case, names: &mut HashSet<String>) -> Result<()> {
    if case.name.is_empty()
        || case.name.len() > 192
        || !case
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
        || !names.insert(case.name.clone())
        || case.words.len() != case.spec.words.len()
        || case.spec.words.is_empty()
        || case.spec.words.len() > 100_000
        || case.spec.leaves.is_empty()
        || case.spec.leaves.len() > 30_000
        || case.checks.len() > 30_000
        || case
            .checks
            .iter()
            .any(|c| c.ordinal >= case.spec.leaves.len())
    {
        return Err("malformed case or duplicate test-key session".into());
    }
    if case.measure_all
        && (baseline(&case.name).is_none() || case.checks.iter().any(|c| !c.expected_correct))
    {
        return Err("measured case is not a recognized honest fixture".into());
    }
    Ok(())
}

fn parse_cases(raw: &[u8]) -> Result<(Vec<Case>, &'static str)> {
    if raw.is_empty() || raw.len() > INPUT_CAP {
        return Err("registry fixture byte budget".into());
    }
    let cases: Vec<Case> = serde_json::from_slice(raw)?;
    if cases.is_empty() || cases.len() > 64 {
        return Err("registry fixture case count bound".into());
    }
    let mut names = HashSet::new();
    for case in &cases {
        validate_case(case, &mut names)?;
    }
    let measured: HashSet<&str> = cases
        .iter()
        .filter(|case| case.measure_all)
        .map(|case| case.name.as_str())
        .collect();
    let convolution: HashSet<_> = [
        "pallas_base/convolution-mul",
        "vesta_base/convolution-mul",
        "pallas/convolution-point",
        "vesta/convolution-point",
    ]
    .into_iter()
    .collect();
    let horner: HashSet<_> = [
        "pallas_base/honest-full-multiplication",
        "vesta_base/honest-full-multiplication",
        "pallas/point-graph",
        "vesta/point-graph",
    ]
    .into_iter()
    .collect();
    let family = if measured == convolution {
        "convolution"
    } else if measured == horner {
        "horner-baseline"
    } else {
        return Err("exactly four unchanged measured fixture cases required".into());
    };
    Ok((cases, family))
}

fn test_keys(case: &Case, expected: &[u8; 32]) -> Vec<PublicKey> {
    case.spec
        .words
        .iter()
        .map(|word| {
            let mut h = sha256::Hash::engine();
            h.input(b"BITVM2-NOVA/TEST-ONLY-GLOBAL-WOTS/v1\0");
            h.input(expected);
            h.input(case.name.as_bytes());
            h.input(&[0]);
            h.input(word.name.as_bytes());
            let secret = sha256::Hash::from_engine(h).to_byte_array().to_vec();
            Wots4::generate_public_key(&secret)
        })
        .collect()
}

fn depth(mut count: usize, mut ordinal: usize) -> Result<usize> {
    if count == 0 || ordinal >= count || count > 30_000 {
        return Err("tree ordinal/count bound".into());
    }
    let mut result = 0;
    while count > 1 {
        let base = 1usize << (usize::BITS - 1 - count.leading_zeros());
        let half = base / 2;
        let left = half + (count - base).min(half);
        if ordinal < left {
            count = left;
        } else {
            ordinal -= left;
            count -= left;
        }
        result += 1;
    }
    Ok(result)
}

fn must_reject<T>(
    result: Result<T>,
    kind: &'static str,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    if result.is_ok() {
        return Err(format!("Taproot negative accepted: {kind}").into());
    }
    *counts.entry(kind).or_default() += 1;
    Ok(())
}

fn opening_negatives(
    tree: &TaprootCommitment,
    registry: &Registry,
    other: &Constructed,
    wrong_output: XOnlyPublicKey,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    let root = tree.merkle_root();
    let output = tree.output_key();
    let ordinal = tree.selected_ordinal();
    let script = tree.selected_script();
    let control = tree.control_block_bytes();
    let mut code = script.as_bytes().to_vec();
    *code.first_mut().ok_or("empty selected script")? ^= 1;
    must_reject(
        verify_opening(
            registry,
            root,
            output,
            ordinal,
            &ScriptBuf::from_bytes(code),
            &control,
        ),
        "altered_script",
        counts,
    )?;
    for (kind, index, mask) in [
        ("altered_branch", 33, 1),
        ("altered_parity", 0, 1),
        ("altered_internal_key", 1, 1),
        ("altered_leaf_version", 0, 2),
    ] {
        let mut bad = control.clone();
        *bad.get_mut(index)
            .ok_or("control block too short for mutation")? ^= mask;
        must_reject(
            verify_opening(registry, root, output, ordinal, script, &bad),
            kind,
            counts,
        )?;
    }
    must_reject(
        verify_opening(
            registry,
            root,
            output,
            ordinal,
            script,
            &control[..control.len() - 1],
        ),
        "truncated_control",
        counts,
    )?;
    let mut appended = control.clone();
    appended.push(0);
    must_reject(
        verify_opening(registry, root, output, ordinal, script, &appended),
        "appended_control",
        counts,
    )?;
    let wrong_ordinal = (ordinal + 1) % tree.leaf_count();
    must_reject(
        verify_opening(registry, root, output, wrong_ordinal, script, &control),
        "altered_ordinal",
        counts,
    )?;
    must_reject(
        verify_opening(registry, root, output, usize::MAX, script, &control),
        "out_of_range_ordinal",
        counts,
    )?;
    let mut wrong_root = root.to_byte_array();
    wrong_root[0] ^= 1;
    must_reject(
        tree.verify_member(
            registry,
            TapNodeHash::assume_hidden(wrong_root),
            output,
            ordinal,
        ),
        "altered_expected_root",
        counts,
    )?;
    if wrong_output == output {
        return Err("fixed alternate output key unexpectedly equals tree key".into());
    }
    must_reject(
        tree.verify_member(registry, root, wrong_output, ordinal),
        "altered_expected_output_key",
        counts,
    )?;
    let other_tree = &other.commitments[0].0;
    if root == other_tree.merkle_root() {
        return Err("distinct fixture catalogues unexpectedly share a tree root".into());
    }
    must_reject(
        tree.verify_member(
            registry,
            other_tree.merkle_root(),
            other_tree.output_key(),
            ordinal,
        ),
        "other_catalogue_root",
        counts,
    )?;
    must_reject(
        tree.verify_member(&other.registry, root, output, ordinal),
        "other_registry",
        counts,
    )?;
    Ok(())
}

fn run() -> Result<Value> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: taproot INPUTS_JSON OUTPUT_JSON".into());
    }
    // Resource guard only. The environment does not authenticate a tree root.
    if !matches!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true")) {
        return Err("complete Taproot catalogue compilation is hosted-CI-only".into());
    }
    let started = Instant::now();
    let metadata = fs::metadata(&args[1])?;
    if !metadata.is_file() || metadata.len() > INPUT_CAP as u64 {
        return Err("registry fixture exceeds regular-file/32MiB bound".into());
    }
    let mut raw = Vec::new();
    fs::File::open(&args[1])?
        .take((INPUT_CAP + 1) as u64)
        .read_to_end(&mut raw)?;
    let input_sha = sha256::Hash::hash(&raw).to_string();
    let (cases, family) = parse_cases(&raw)?;
    let source_case_count = cases.len();
    drop(raw);
    let mut constructed = Vec::new();
    let mut keys_generated = 0;
    let mut native_rejections = BTreeMap::new();
    for case in cases.into_iter().filter(|case| case.measure_all) {
        let expected = id32(&case.expected_spec_id)?;
        let keys = test_keys(&case, &expected);
        keys_generated += keys.len();
        let id = case.spec.key_identity(&keys)?;
        let registry = Registry::new(case.spec, keys, expected, id)?;
        let leaf_count = registry.spec().leaves.len();
        let mut commitments = Vec::new();
        for selected in [0, leaf_count - 1] {
            let start = Instant::now();
            let tree = TaprootCommitment::new(&registry, selected)?;
            let seconds = start.elapsed().as_secs_f64();
            let (bytes, stream) = baseline(&case.name).ok_or("missing baseline")?;
            if tree.compiled_script_bytes() != bytes
                || hex::encode(tree.compiled_stream_sha256()) != stream
                || tree.leaf_count() != leaf_count
                || tree.selected_ordinal() != selected
                || tree.registry_id() != id
                || tree.catalogue_id() != expected
                || tree.control_block_bytes().len() != 33 + 32 * depth(leaf_count, selected)?
            {
                return Err("Taproot tree changed the immutable compiled catalogue".into());
            }
            commitments.push((tree, seconds));
        }
        if commitments[0].0.merkle_root() != commitments[1].0.merkle_root()
            || commitments[0].0.output_key() != commitments[1].0.output_key()
        {
            return Err("selected ordinal changed full-tree root/output key".into());
        }
        must_reject(
            TaprootCommitment::new(&registry, usize::MAX),
            "constructor_ordinal",
            &mut native_rejections,
        )?;
        constructed.push(Constructed {
            case_name: case.name,
            registry,
            commitments,
        });
    }
    let wrong_output = XOnlyPublicKey::from_slice(&hex::decode(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )?)?;
    let mut ledger = Vec::new();
    let mut unique_bytes = 0u64;
    let mut compiled_bytes = 0u64;
    for (index, case) in constructed.iter().enumerate() {
        let other = &constructed[(index + 1) % constructed.len()];
        let expected_root = case.commitments[0].0.merkle_root();
        let expected_output = case.commitments[0].0.output_key();
        unique_bytes += case.commitments[0].0.compiled_script_bytes();
        for (tree, seconds) in &case.commitments {
            let ordinal = tree.selected_ordinal();
            tree.verify_member(&case.registry, expected_root, expected_output, ordinal)?;
            verify_opening(
                &case.registry,
                expected_root,
                expected_output,
                ordinal,
                tree.selected_script(),
                &tree.control_block_bytes(),
            )?;
            opening_negatives(
                tree,
                &case.registry,
                other,
                wrong_output,
                &mut native_rejections,
            )?;
            compiled_bytes += tree.compiled_script_bytes();
            ledger.push(json!({"case":case.case_name,"registry_id":hex::encode(tree.registry_id()),
                "catalogue_id":hex::encode(tree.catalogue_id()),"selected_ordinal":ordinal,
                "leaf_count":tree.leaf_count(),"all_disproof_script_bytes":tree.compiled_script_bytes(),
                "leaf_stream_sha256":hex::encode(tree.compiled_stream_sha256()),
                "merkle_root":expected_root.to_string(),"output_key":expected_output.to_string(),
                "depth":depth(tree.leaf_count(),ordinal)?,"control_block_bytes":tree.control_block_bytes().len(),
                "control_block_sha256":sha256::Hash::hash(&tree.control_block_bytes()).to_string(),
                "selected_script_bytes":tree.selected_script().len(),
                "selected_script_sha256":sha256::Hash::hash(tree.selected_script().as_bytes()).to_string(),
                "construction_seconds":seconds,
                "control_membership_verified":true,"script_execution_verified":false}));
        }
    }
    let result = json!({"schema":"bitvm2-nova-offline-taproot-commitments/v1","passed":true,
        "fixture_family":family,"source_fixture_sha256":input_sha,"source_cases":source_case_count,
        "measured_cases":constructed.len(),"tree_constructions":ledger.len(),"ledger":ledger,
        "unique_catalogue_script_bytes":unique_bytes,"compiled_script_bytes_over_tree_constructions":compiled_bytes,
        "native_negative_counts":native_rejections,"test_wots_public_keys_generated":keys_generated,
        "test_keys_only":true,"assertion_signatures_created":0,"transactions_broadcast":0,
        "compiled_stream_goldens_verified":true,"taproot_control_membership_verified":true,
        "taproot_roots_independently_pinned":false,"script_execution_verified":false,
        "wots_witness_verified":false,"native_nova_proofs_verified":0,"bitcoin_script_verified":false,
        "assertion_utxo_binding":false,"bitcoin_transaction_binding":false,"bitcoin_transaction_graph":false,
        "complete_nova_verifier":false,"complete_bitvm2_verifier":false,
        "wall_seconds":started.elapsed().as_secs_f64(),
        "scope":"offline test-key script catalogue commitment and selected control membership only"});
    let encoded = serde_json::to_vec(&result)?;
    if encoded.len() > OUTPUT_CAP {
        return Err("Taproot summary exceeds 1MiB bound".into());
    }
    fs::write(&args[2], &encoded)?;
    Ok(result)
}

fn main() -> Result<()> {
    println!("{}", run()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_left_filled_depths_cover_boundary_ordinals() {
        for (count, first, last) in [
            (1, 0, 0),
            (2, 1, 1),
            (3, 2, 1),
            (5, 3, 2),
            (489, 9, 8),
            (6151, 13, 12),
        ] {
            assert_eq!(depth(count, 0).unwrap(), first);
            assert_eq!(depth(count, count - 1).unwrap(), last);
            assert!(depth(count, count).is_err());
        }
        assert!(depth(0, 0).is_err());
        assert!(depth(30_001, 0).is_err());
        assert!(depth(489, usize::MAX).is_err());
    }

    #[test]
    fn typed_case_transport_rejects_duplicate_unknown_and_wrong_scalar_types() {
        // Parser only: this empty graph is not admitted as a Registry.
        let base = r#"{"name":"x","spec":{"program_sha256":"","context":"","field_role":"pallas_base","operation_id":"x","words":[],"leaves":[],"bodies":{}},"expected_spec_id":"","words":[],"checks":[],"measure_all":false}"#;
        assert!(serde_json::from_str::<Case>(base).is_ok());
        for changed in [
            base.replace("\"name\":\"x\"", "\"name\":\"x\",\"name\":\"y\""),
            base.replace("\"measure_all\":false", "\"measure_all\":0"),
            base.replace(
                "\"checks\":[]",
                "\"checks\":[{\"ordinal\":-1,\"expected_correct\":true}]",
            ),
            base.replace("\"measure_all\":false", "\"extra\":1,\"measure_all\":false"),
        ] {
            assert!(serde_json::from_str::<Case>(&changed).is_err());
        }
        assert!(parse_cases(base.as_bytes()).is_err());
        assert!(parse_cases(b"[]").is_err());
    }
}
