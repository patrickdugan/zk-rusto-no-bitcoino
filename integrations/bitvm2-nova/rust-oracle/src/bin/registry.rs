//! Global signatures are created once per wire and reused across leaf openings.
//! Keys are deterministic TEST-ONLY fixtures, never production signing keys.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{emit, Metrics},
    registry::{GraphSpec, Registry, Signature, Word},
    taproot_commitment::TaprootCommitment,
    wots::{id32, PublicKey, Result},
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    io::{BufWriter, Write},
    time::Instant,
};

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

fn native_checks(
    spec: &GraphSpec,
    keys: &[PublicKey],
    expected: [u8; 32],
    id: [u8; 32],
) -> Result<usize> {
    let mut variants = Vec::new();
    let mut x = spec.clone();
    x.context = "01".repeat(32);
    variants.push(x);
    let mut x = spec.clone();
    x.program_sha256 = "02".repeat(32);
    variants.push(x);
    let mut x = spec.clone();
    x.field_role = if spec.field_role == "vesta_scalar" {
        "pallas_scalar"
    } else {
        "vesta_scalar"
    }
    .into();
    variants.push(x);
    let mut x = spec.clone();
    x.operation_id = "wrong-operation".into();
    variants.push(x);
    let mut x = spec.clone();
    x.words.swap(0, 1);
    variants.push(x);
    let mut x = spec.clone();
    x.words[0].name = x.words[1].name.clone();
    variants.push(x);
    let mut x = spec.clone();
    x.leaves.swap(18, 19);
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[18].wires.swap(0, 1);
    variants.push(x);
    let mut x = spec.clone();
    if x.leaves.iter().any(|leaf| leaf.kind == "field_valid") {
        x.leaves.retain(|leaf| leaf.kind != "field_valid");
    } else {
        // Boolean catalogues have no Fr validity leaf; remove a real predicate.
        x.leaves.remove(0);
    }
    variants.push(x);
    let mut x = spec.clone();
    x.bodies
        .insert(x.leaves[18].body_sha256.clone(), "51".into());
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[18].wires[0] = x.words.len();
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[18].kind = "unknown".into();
    variants.push(x);
    let mut count = 0;
    for other in variants {
        if Registry::new(other, keys.to_vec(), expected, id).is_ok() {
            return Err("catalogue substitution accepted".into());
        }
        count += 1;
    }
    let mut swapped = keys.to_vec();
    swapped.swap(0, 1);
    if Registry::new(spec.clone(), swapped, expected, id).is_ok() {
        return Err("registry key permutation accepted".into());
    }
    let mut duplicate = keys.to_vec();
    duplicate[1] = duplicate[0];
    if Registry::new(spec.clone(), duplicate, expected, id).is_ok() {
        return Err("one-time key reuse accepted".into());
    }
    if Registry::new(spec.clone(), keys[..keys.len() - 1].to_vec(), expected, id).is_ok() {
        return Err("missing registry key accepted".into());
    }
    let mut surplus = keys.to_vec();
    surplus.push(keys[0]);
    if Registry::new(spec.clone(), surplus, expected, id).is_ok() {
        return Err("surplus registry key accepted".into());
    }
    let mut wrong = id;
    wrong[0] ^= 1;
    if Registry::new(spec.clone(), keys.to_vec(), expected, wrong).is_ok() {
        return Err("wrong registry root accepted".into());
    }
    for input in [
        r#"{"name":"a","name":"b","bound":2}"#,
        r#"{"name":"a","bound":2,"extra":1}"#,
        r#"{"name":"a","bound":-1}"#,
        r#"{"name":"a","bound":1.0}"#,
    ] {
        if serde_json::from_str::<Word>(input).is_ok() {
            return Err("malformed wire JSON accepted".into());
        }
        count += 1;
    }
    if serde_json::from_str::<Check>(r#"{"ordinal":-1,"expected_correct":true}"#).is_ok() {
        return Err("negative leaf ordinal accepted".into());
    }
    for op in [0x50, 0x7e, 0x95] {
        if bitvm2_nova_script_oracle::engine::validate(&bitcoin::ScriptBuf::from_bytes(vec![op]))
            .is_ok()
        {
            return Err("OP_SUCCESS or disabled opcode accepted".into());
        }
        count += 1;
    }
    Ok(count + 6)
}

fn sumcheck_fragment_checks(
    case: &Case,
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    out: &mut impl Write,
    metrics: &mut Metrics,
) -> Result<(usize, serde_json::Value)> {
    let expected_role = match case.name.as_str() {
        "primary/sumcheck-two-outer-rounds" => "pallas_scalar",
        "secondary/sumcheck-two-outer-rounds" => "vesta_scalar",
        _ => return Err("unrecognized sumcheck fragment role".into()),
    };
    if !case.measure_all
        || case.spec.field_role != expected_role
        || case.checks.iter().any(|check| !check.expected_correct)
    {
        return Err("sumcheck fragment must measure its complete role-specific catalogue".into());
    }
    let field = |prefix: &str| -> Result<Vec<usize>> {
        (0..9)
            .map(|i| {
                case.spec
                    .words
                    .iter()
                    .position(|word| word.name == format!("{prefix}/l{i}") && word.bound == 1 << 29)
                    .ok_or_else(|| "missing sumcheck scalar wire".into())
            })
            .collect()
    };
    let shared = field("round/0/next")?;
    let linear = field("round/1/c1")?;
    let producers: Vec<_> = case
        .spec
        .leaves
        .iter()
        .enumerate()
        .filter(|(_, leaf)| {
            leaf.kind == "equal" && leaf.wires.len() == 18 && leaf.wires[9..] == shared
        })
        .collect();
    let consumers: Vec<_> = case
        .spec
        .leaves
        .iter()
        .enumerate()
        .filter(|(_, leaf)| {
            leaf.kind == "add"
                && leaf.wires.len() == 27
                && leaf.wires[9..18] == linear
                && leaf.wires[18..] == shared
        })
        .collect();
    if producers.len() != 1 || consumers.len() != 1 {
        return Err("sumcheck producer/consumer must share the exact prior-claim field".into());
    }
    let (producer, consumer) = (producers[0].0, consumers[0].0);
    let left_slots = registry.unique_slots(producer)?;
    let right_slots = registry.unique_slots(consumer)?;
    let left = registry.witness(producer, signatures)?;
    let right = registry.witness(consumer, signatures)?;
    let width = Wots4::TOTAL_DIGIT_LEN as usize;
    for wire in &shared {
        let a = left_slots
            .iter()
            .position(|slot| slot == wire)
            .ok_or("producer claim slot")?;
        let b = right_slots
            .iter()
            .position(|slot| slot == wire)
            .ok_or("consumer claim slot")?;
        if left[a * width..(a + 1) * width] != right[b * width..(b + 1) * width] {
            return Err("sumcheck shared claim did not reuse the same WOTS opening".into());
        }
    }
    let mut rejected = native_checks(
        &case.spec,
        keys,
        id32(&case.expected_spec_id)?,
        registry.identity(),
    )?;
    if registry
        .witness(0, &signatures[..signatures.len() - 1])
        .is_ok()
        || registry.script(usize::MAX, true).is_ok()
    {
        return Err("sumcheck signature-count/ordinal guard failed".into());
    }
    rejected += 2;
    // Keep empty/truncated/prepended/appended tests at the authenticated boundary,
    // including its arithmetic kinds and canonical field-validity predicate.
    let mut kinds = HashSet::new();
    for (ordinal, leaf) in case.spec.leaves.iter().enumerate() {
        if !kinds.insert(leaf.kind.as_str()) {
            continue;
        }
        let witness = registry.witness(ordinal, signatures)?;
        for disprove in [false, true] {
            let code = registry.script(ordinal, disprove)?;
            let lengths = [
                vec![],
                witness[..witness.len() - 1].to_vec(),
                [vec![vec![]], witness.clone()].concat(),
                [witness.clone(), vec![vec![]]].concat(),
            ];
            for (index, bad) in lengths.iter().enumerate() {
                emit(
                    out,
                    metrics,
                    &code,
                    bad,
                    false,
                    &format!("{}/length/{ordinal}/{index}/{disprove}", case.name),
                )?;
            }
            for position in [0, witness.len() - 1] {
                let mut forged = witness.clone();
                *forged[position].first_mut().ok_or("empty WOTS digit")? ^= 1;
                emit(
                    out,
                    metrics,
                    &code,
                    &forged,
                    false,
                    &format!("{}/forgery/{ordinal}/{position}/{disprove}", case.name),
                )?;
            }
            let slot = registry.unique_slots(ordinal)?[0];
            let mut substituted = signatures.to_vec();
            substituted[slot] = signatures[(slot + 1) % signatures.len()];
            emit(
                out,
                metrics,
                &code,
                &registry.witness(ordinal, &substituted)?,
                false,
                &format!("{}/cross-wire/{ordinal}/{disprove}", case.name),
            )?;
        }
    }
    let columns: Vec<_> = case
        .spec
        .leaves
        .iter()
        .enumerate()
        .filter(|(_, leaf)| leaf.kind == "conv_column")
        .collect();
    if columns.len() != 6 * 64 {
        return Err("two cubic rounds must contain six complete products".into());
    }
    let mut carry_links = 0;
    for product in columns.chunks_exact(64) {
        for pair in product.windows(2) {
            let (a, left) = pair[0];
            let (b, right) = pair[1];
            let left_index = (left.argument[0] + left.argument[1]) as usize;
            let right_index = (right.argument[0] + right.argument[1]) as usize;
            let shared = left.wires[left_index + 1];
            if shared != right.wires[right_index] {
                return Err("sumcheck convolution carry field is disconnected".into());
            }
            let a_slots = registry.unique_slots(a)?;
            let b_slots = registry.unique_slots(b)?;
            let ai = a_slots
                .iter()
                .position(|slot| *slot == shared)
                .ok_or("left carry slot")?;
            let bi = b_slots
                .iter()
                .position(|slot| *slot == shared)
                .ok_or("right carry slot")?;
            let aw = registry.witness(a, signatures)?;
            let bw = registry.witness(b, signatures)?;
            if aw[ai * width..(ai + 1) * width] != bw[bi * width..(bi + 1) * width] {
                return Err("sumcheck carry WOTS opening differs across adjacent columns".into());
            }
            carry_links += 1;
        }
    }
    let tree = TaprootCommitment::new(registry, producer)?;
    tree.verify_member(registry, tree.merkle_root(), tree.output_key(), producer)?;
    Ok((
        rejected,
        serde_json::json!({"case":case.name,
        "producer_ordinal":producer,"consumer_ordinal":consumer,
        "shared_claim_word_links_checked":shared.len(),"convolution_carry_links_checked":carry_links,
        "taproot_selected_ordinal":producer,"taproot_merkle_root":tree.merkle_root().to_string(),
        "taproot_output_key":tree.output_key().to_string(),
        "taproot_control_block_bytes":tree.control_block_bytes().len(),
        "taproot_compiled_script_bytes":tree.compiled_script_bytes(),
        "taproot_leaf_stream_sha256":hex::encode(tree.compiled_stream_sha256()),
        "offline_taproot_membership_verified":true,"taproot_roots_independently_pinned":false,
        "proof_source_ports_script_bound":false,"fiat_shamir_script_bound":false,
        "complete_nova_verifier":false,"bitcoin_transaction_binding":false}),
    ))
}

fn keccak_pair_checks(
    case: &Case,
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    out: &mut impl Write,
    metrics: &mut Metrics,
) -> Result<(usize, serde_json::Value)> {
    const FIRST_LEAVES: usize = 9602;
    const BOUNDARY_BITS: usize = 1600;
    if case.name != "keccak/pair-0-1"
        || !case.measure_all
        || case.spec.field_role != "pallas_scalar"
        || case.spec.words.len() != 20806
        || case.spec.leaves.len() != 19206
        || case.spec.words.iter().any(|word| word.bound != 2)
        || case.checks.iter().any(|check| !check.expected_correct)
    {
        return Err("exact Boolean Keccak round0/1 catalogue required".into());
    }
    let names: std::collections::HashMap<_, _> = case
        .spec
        .words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.name.as_str(), index))
        .collect();
    let mut shared = Vec::with_capacity(BOUNDARY_BITS);
    for lane in 0..25 {
        for bit in 0..64 {
            let name = format!("boundary/middle/l{lane}/b{bit}");
            shared.push(
                *names
                    .get(name.as_str())
                    .ok_or("missing ordered Keccak boundary bit")?,
            );
        }
    }
    let boundary: HashSet<_> = shared.iter().copied().collect();
    if boundary.len() != BOUNDARY_BITS {
        return Err("duplicate Keccak boundary slot".into());
    }
    let mut consumers: std::collections::HashMap<usize, Vec<usize>> = shared
        .iter()
        .copied()
        .map(|word| (word, Vec::new()))
        .collect();
    for (ordinal, leaf) in case.spec.leaves.iter().enumerate().skip(FIRST_LEAVES) {
        let arity = match leaf.kind.as_str() {
            "bool_xor" | "bool_and" => 2,
            "bool_not" => 1,
            "const" => 0,
            _ => return Err("unexpected Keccak Boolean predicate".into()),
        };
        if leaf.wires.len() != arity + 1 {
            return Err("Keccak predicate arity mismatch".into());
        }
        for word in &leaf.wires[..arity] {
            if let Some(uses) = consumers.get_mut(word) {
                uses.push(ordinal);
            }
        }
        if boundary.contains(&leaf.wires[arity]) {
            return Err("consumer round rewrites shared input word".into());
        }
    }
    let width = Wots4::TOTAL_DIGIT_LEN as usize;
    let mut links = 0;
    for (bit, wire) in shared.iter().enumerate() {
        let producer = FIRST_LEAVES - BOUNDARY_BITS + bit;
        let leaf = &case.spec.leaves[producer];
        if leaf.kind != "bool_xor" || leaf.wires.len() != 3 || leaf.wires[2] != *wire {
            return Err("ordered Keccak output is not the shared global input".into());
        }
        let slots = registry.unique_slots(producer)?;
        let source_position = slots
            .iter()
            .position(|slot| slot == wire)
            .ok_or("producer bit slot")?;
        let source = registry.witness(producer, signatures)?;
        let uses = &consumers[wire];
        // Each state bit occurs once in theta's parity and once in theta's state.
        if uses.len() != 2 {
            return Err("Keccak state input coverage differs from exact round".into());
        }
        for ordinal in uses {
            let target_slots = registry.unique_slots(*ordinal)?;
            let target_position = target_slots
                .iter()
                .position(|slot| slot == wire)
                .ok_or("consumer bit slot")?;
            let target = registry.witness(*ordinal, signatures)?;
            if source[source_position * width..(source_position + 1) * width]
                != target[target_position * width..(target_position + 1) * width]
            {
                return Err("shared Keccak state bit has different WOTS opening".into());
            }
            links += 1;
        }
    }
    let mut rejected = native_checks(
        &case.spec,
        keys,
        id32(&case.expected_spec_id)?,
        registry.identity(),
    )?;
    if registry
        .witness(0, &signatures[..signatures.len() - 1])
        .is_ok()
        || registry.script(usize::MAX, true).is_ok()
    {
        return Err("Keccak signature-count/ordinal guard failed".into());
    }
    rejected += 2;
    let mut kinds = HashSet::new();
    for (ordinal, leaf) in case.spec.leaves.iter().enumerate() {
        if !kinds.insert(leaf.kind.as_str()) {
            continue;
        }
        let witness = registry.witness(ordinal, signatures)?;
        for disprove in [false, true] {
            let code = registry.script(ordinal, disprove)?;
            let lengths = [
                vec![],
                witness[..witness.len() - 1].to_vec(),
                [vec![vec![]], witness.clone()].concat(),
                [witness.clone(), vec![vec![]]].concat(),
            ];
            for (index, bad) in lengths.iter().enumerate() {
                emit(
                    out,
                    metrics,
                    &code,
                    bad,
                    false,
                    &format!("{}/length/{ordinal}/{index}/{disprove}", case.name),
                )?;
            }
            for position in [0, witness.len() - 1] {
                let mut forged = witness.clone();
                *forged[position]
                    .first_mut()
                    .ok_or("empty Keccak signature digit")? ^= 1;
                emit(
                    out,
                    metrics,
                    &code,
                    &forged,
                    false,
                    &format!("{}/forgery/{ordinal}/{position}/{disprove}", case.name),
                )?;
            }
            let slot = registry.unique_slots(ordinal)?[0];
            let mut substituted = signatures.to_vec();
            substituted[slot] = signatures[(slot + 1) % signatures.len()];
            emit(
                out,
                metrics,
                &code,
                &registry.witness(ordinal, &substituted)?,
                false,
                &format!("{}/cross-wire/{ordinal}/{disprove}", case.name),
            )?;
        }
    }
    let selected = FIRST_LEAVES - BOUNDARY_BITS;
    let tree = TaprootCommitment::new(registry, selected)?;
    tree.verify_member(registry, tree.merkle_root(), tree.output_key(), selected)?;
    Ok((
        rejected,
        serde_json::json!({"case":case.name,"boundary_words_checked":shared.len(),
        "boundary_signature_links_checked":links,"producer_first_ordinal":selected,
        "consumer_round_first_ordinal":FIRST_LEAVES,
        "taproot_selected_ordinal":selected,"taproot_control_block_bytes":tree.control_block_bytes().len(),
        "taproot_merkle_root":tree.merkle_root().to_string(),"taproot_output_key":tree.output_key().to_string(),
        "taproot_compiled_script_bytes":tree.compiled_script_bytes(),
        "taproot_leaf_stream_sha256":hex::encode(tree.compiled_stream_sha256()),
        "offline_taproot_membership_verified":true,"taproot_roots_independently_pinned":false,
        "complete_keccak_permutation":false,"complete_hash_verified":false,
        "nova_transcript_verified_in_script":false,"complete_nova_verifier":false,
        "production_assertion_binding":false,"bitcoin_transaction_binding":false}),
    ))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: registry INPUTS_JSON OUTPUT_JSONL".into());
    }
    if fs::metadata(&args[1])?.len() > 32 * 1024 * 1024 {
        return Err("registry fixtures exceed 32 MiB".into());
    }
    let cases: Vec<Case> = serde_json::from_slice(&fs::read(&args[1])?)?;
    if cases.is_empty() || cases.len() > 64 {
        return Err("case count bound".into());
    }
    let start = Instant::now();
    let mut metrics = Metrics::default();
    let mut names = HashSet::new();
    let mut ledger = Vec::new();
    let mut native_rejections = 0;
    let mut shared_links = 0;
    let mut convolution_carry_links = 0;
    let mut assertion_signatures = 0;
    let mut sumcheck_fragments = Vec::new();
    let mut sumcheck_disproofs = Vec::new();
    let mut keccak_pair_fragments = Vec::new();
    let mut keccak_pair_disproofs = Vec::new();
    let mut out = BufWriter::new(fs::File::create(&args[2])?);
    for case in &cases {
        if case.name.len() > 192
            || case.name.is_empty()
            || !case
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
            || !names.insert(case.name.clone())
            || case.words.len() != case.spec.words.len()
        {
            return Err("malformed case or duplicate signing session".into());
        }
        let expected = id32(&case.expected_spec_id)?;
        let secrets: Vec<Vec<u8>> = case
            .spec
            .words
            .iter()
            .map(|word| {
                let mut h = sha256::Hash::engine();
                h.input(b"BITVM2-NOVA/TEST-ONLY-GLOBAL-WOTS/v1\0");
                h.input(&expected);
                h.input(case.name.as_bytes());
                h.input(&[0]);
                h.input(word.name.as_bytes());
                sha256::Hash::from_engine(h).to_byte_array().to_vec()
            })
            .collect();
        let keys: Vec<PublicKey> = secrets.iter().map(Wots4::generate_public_key).collect();
        let id = case
            .spec
            .key_identity(&keys)
            .map_err(|e| format!("{}: {e}", case.name))?;
        let registry = Registry::new(case.spec.clone(), keys.clone(), expected, id)?;
        let signatures: Vec<Signature> = secrets
            .iter()
            .zip(&case.words)
            .map(|(secret, word)| Wots4::compact_sign(secret, &word.to_le_bytes()))
            .collect();
        assertion_signatures += signatures.len();
        let checks: Vec<Check> = if case.checks.is_empty() {
            (0..case.spec.leaves.len())
                .map(|ordinal| Check {
                    ordinal,
                    expected_correct: true,
                })
                .collect()
        } else {
            case.checks
                .iter()
                .map(|c| Check {
                    ordinal: c.ordinal,
                    expected_correct: c.expected_correct,
                })
                .collect()
        };
        if case.measure_all {
            let mut sum = 0usize;
            let mut largest = 0usize;
            let mut h = sha256::Hash::engine();
            for i in 0..case.spec.leaves.len() {
                let code = registry.script(i, true)?;
                sum += code.len();
                largest = largest.max(code.len());
                h.input(&(code.len() as u32).to_le_bytes());
                h.input(code.as_bytes());
            }
            let stream_hash = sha256::Hash::from_engine(h).to_string();
            // Baselines captured at main7708a99 before decoder caching;
            // convolution streams independently executed at c3de2fc.
            // Future changes must preserve every versioned compiled leaf byte.
            let baseline = match case.name.as_str() {
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
            };
            if let Some((bytes, expected_hash)) = baseline {
                if sum != bytes || stream_hash != expected_hash {
                    return Err(
                        "compiled catalogue differs from independently executed baseline".into(),
                    );
                }
            }
            ledger.push(serde_json::json!({"case":case.name,"registry_id":hex::encode(id),"catalogue_id":case.expected_spec_id,
                "words":case.spec.words.len(),"leaves":case.spec.leaves.len(),"executed_leaves":checks.len(),
                "all_disproof_script_bytes":sum,"largest_disproof_leaf_bytes":largest,
                "global_public_key_payload_bytes":keys.len()*Wots4::TOTAL_DIGIT_LEN as usize*20,
                "global_signature_payload_bytes":signatures.len()*Wots4::TOTAL_DIGIT_LEN as usize*20,
                "leaf_stream_sha256":stream_hash}));
        }
        for check in &checks {
            let witness = registry.witness(check.ordinal, &signatures)?;
            for disprove in [false, true] {
                let code = registry.script(check.ordinal, disprove)?;
                emit(
                    &mut out,
                    &mut metrics,
                    &code,
                    &witness,
                    check.expected_correct != disprove,
                    &format!("{}/leaf/{}/{disprove}", case.name, check.ordinal),
                )?;
            }
        }
        if case.name.ends_with("/convolution-mul") || case.name.ends_with("/uniform-reduce512") {
            native_rejections += native_checks(&case.spec, &keys, expected, id)?;
            if registry
                .witness(0, &signatures[..signatures.len() - 1])
                .is_ok()
                || registry.script(usize::MAX, true).is_ok()
            {
                return Err("convolution signature count or ordinal guard failed".into());
            }
            native_rejections += 2;
            // Exercise every new predicate shape, field validity and anchors
            // through the same authenticated boundary as the baseline.
            let mut kinds = HashSet::new();
            for (ordinal, leaf) in case.spec.leaves.iter().enumerate() {
                if !kinds.insert(leaf.kind.as_str()) {
                    continue;
                }
                let witness = registry.witness(ordinal, &signatures)?;
                for disprove in [false, true] {
                    let code = registry.script(ordinal, disprove)?;
                    for (j, bad) in [
                        vec![],
                        witness[..witness.len() - 1].to_vec(),
                        [vec![vec![]], witness.clone()].concat(),
                        [witness.clone(), vec![vec![]]].concat(),
                    ]
                    .iter()
                    .enumerate()
                    {
                        emit(
                            &mut out,
                            &mut metrics,
                            &code,
                            bad,
                            false,
                            &format!("{}/length/{ordinal}/{j}/{disprove}", case.name),
                        )?;
                    }
                    for position in [0, witness.len() - 1] {
                        let mut bad = witness.clone();
                        *bad[position].first_mut().ok_or("empty signature digit")? ^= 1;
                        emit(
                            &mut out,
                            &mut metrics,
                            &code,
                            &bad,
                            false,
                            &format!("{}/forgery/{ordinal}/{position}/{disprove}", case.name),
                        )?;
                    }
                    let slot = registry.unique_slots(ordinal)?[0];
                    let mut substituted = signatures.clone();
                    substituted[slot] = signatures[(slot + 1) % signatures.len()];
                    emit(
                        &mut out,
                        &mut metrics,
                        &code,
                        &registry.witness(ordinal, &substituted)?,
                        false,
                        &format!("{}/cross-wire/{ordinal}/{disprove}", case.name),
                    )?;
                }
            }
            let columns: Vec<_> = case
                .spec
                .leaves
                .iter()
                .enumerate()
                .filter(|(_, leaf)| leaf.kind == "conv_column")
                .collect();
            let expected_columns = if case.name.ends_with("/uniform-reduce512") {
                65
            } else {
                64
            };
            if columns.len() != expected_columns {
                return Err("integer convolution column coverage".into());
            }
            for pair in columns.windows(2) {
                let (left_ordinal, left) = pair[0];
                let (right_ordinal, right) = pair[1];
                let left_offset = (left.argument[0] + left.argument[1]) as usize;
                let right_offset = (right.argument[0] + right.argument[1]) as usize;
                let shared = left.wires[left_offset + 1];
                if shared != right.wires[right_offset] {
                    return Err("shared convolution carry slot mismatch".into());
                }
                let left_slots = registry.unique_slots(left_ordinal)?;
                let right_slots = registry.unique_slots(right_ordinal)?;
                let a = left_slots
                    .iter()
                    .position(|slot| *slot == shared)
                    .ok_or("left carry slot")?;
                let b = right_slots
                    .iter()
                    .position(|slot| *slot == shared)
                    .ok_or("right carry slot")?;
                let left_witness = registry.witness(left_ordinal, &signatures)?;
                let right_witness = registry.witness(right_ordinal, &signatures)?;
                let width = Wots4::TOTAL_DIGIT_LEN as usize;
                if left_witness[a * width..(a + 1) * width]
                    != right_witness[b * width..(b + 1) * width]
                {
                    return Err("shared convolution carry signature mismatch".into());
                }
                convolution_carry_links += 1;
            }
        }
        if case.name == "keccak/pair-0-1" {
            let (rejections, fragment) =
                keccak_pair_checks(case, &registry, &keys, &signatures, &mut out, &mut metrics)?;
            native_rejections += rejections;
            let measured = ledger
                .last()
                .ok_or("missing complete Keccak catalogue ledger")?;
            if measured["all_disproof_script_bytes"] != fragment["taproot_compiled_script_bytes"]
                || measured["leaf_stream_sha256"] != fragment["taproot_leaf_stream_sha256"]
            {
                return Err("Keccak Taproot differs from exact compiled catalogue".into());
            }
            keccak_pair_fragments.push(fragment);
        }
        if case.name == "keccak/pair-coherent-middle" {
            let failed: Vec<_> = case
                .checks
                .iter()
                .filter(|check| !check.expected_correct)
                .collect();
            if case.measure_all || failed.len() != 1 || failed[0].ordinal != 8002 {
                return Err(
                    "coherent Keccak attack must refute first shared output bit only".into(),
                );
            }
            let tree = TaprootCommitment::new(&registry, 8002)?;
            tree.verify_member(&registry, tree.merkle_root(), tree.output_key(), 8002)?;
            keccak_pair_disproofs.push(serde_json::json!({"case":case.name,
                "catalogue_id":case.expected_spec_id,"registry_id":hex::encode(id),
                "selected_ordinal":8002,"script_disproof_executed":true,
                "offline_taproot_membership_verified":true,
                "taproot_control_block_bytes":tree.control_block_bytes().len(),
                "taproot_merkle_root":tree.merkle_root().to_string(),"taproot_output_key":tree.output_key().to_string(),
                "taproot_compiled_script_bytes":tree.compiled_script_bytes(),
                "taproot_leaf_stream_sha256":hex::encode(tree.compiled_stream_sha256()),
                "test_keys_only":true,"taproot_roots_independently_pinned":false,
                "complete_keccak_permutation":false,"complete_hash_verified":false,
                "nova_transcript_verified_in_script":false,"complete_nova_verifier":false,
                "production_assertion_binding":false,"bitcoin_transaction_binding":false}));
        }
        if case.name.ends_with("/sumcheck-two-outer-rounds") {
            let (rejections, fragment) = sumcheck_fragment_checks(
                case,
                &registry,
                &keys,
                &signatures,
                &mut out,
                &mut metrics,
            )?;
            native_rejections += rejections;
            let measured = ledger
                .last()
                .ok_or("missing full sumcheck catalogue measurement")?;
            if measured["all_disproof_script_bytes"] != fragment["taproot_compiled_script_bytes"]
                || measured["leaf_stream_sha256"] != fragment["taproot_leaf_stream_sha256"]
            {
                return Err(
                    "sumcheck Taproot tree differs from executed registry catalogue".into(),
                );
            }
            sumcheck_fragments.push(fragment);
        }
        if case.name.ends_with("/sumcheck-coherent-wrong-shared-claim") {
            // The ordinary check loop above actually executed both modes: this
            // one false equality accepts disproof and rejects correctness.
            let failed: Vec<_> = case
                .checks
                .iter()
                .filter(|check| !check.expected_correct)
                .collect();
            if case.measure_all
                || failed.len() != 1
                || case
                    .spec
                    .leaves
                    .get(failed[0].ordinal)
                    .map(|leaf| leaf.kind.as_str())
                    != Some("equal")
            {
                return Err("coherent shared-claim attack must refute exactly one equality".into());
            }
            let ordinal = failed[0].ordinal;
            let tree = TaprootCommitment::new(&registry, ordinal)?;
            tree.verify_member(&registry, tree.merkle_root(), tree.output_key(), ordinal)?;
            sumcheck_disproofs.push(serde_json::json!({"case":case.name,
                "catalogue_id":case.expected_spec_id,"registry_id":hex::encode(id),
                "selected_ordinal":ordinal,"script_disproof_executed":true,
                "offline_taproot_membership_verified":true,
                "taproot_merkle_root":tree.merkle_root().to_string(),
                "taproot_output_key":tree.output_key().to_string(),
                "taproot_control_block_bytes":tree.control_block_bytes().len(),
                "taproot_compiled_script_bytes":tree.compiled_script_bytes(),
                "taproot_leaf_stream_sha256":hex::encode(tree.compiled_stream_sha256()),
                "test_keys_only":true,"taproot_roots_independently_pinned":false,
                "proof_source_ports_script_bound":false,"fiat_shamir_script_bound":false,
                "complete_nova_verifier":false,"bitcoin_transaction_binding":false}));
        }
        if case.name.ends_with("honest-full-multiplication") {
            native_rejections += native_checks(&case.spec, &keys, expected, id)?;
            for i in 18..272 {
                if case.spec.leaves[i].wires[19..] != case.spec.leaves[i + 1].wires[..9] {
                    return Err("shared accumulator slot mismatch".into());
                }
                let a = registry.witness(i, &signatures)?;
                let b = registry.witness(i + 1, &signatures)?;
                if a[190..280] != b[..90] {
                    return Err("shared accumulator signature mismatch".into());
                }
                shared_links += 1;
            }
            let last = registry.witness(272, &signatures)?;
            let final_eq = registry.witness(273, &signatures)?;
            if last[190..280] != final_eq[..90] {
                return Err("final output signature mismatch".into());
            }
            shared_links += 1;
            if registry
                .witness(0, &signatures[..signatures.len() - 1])
                .is_ok()
                || registry.script(usize::MAX, true).is_ok()
            {
                return Err("signature count or ordinal guard failed".into());
            }
            native_rejections += 2;
            for i in [0, 9, 18, 273, 274] {
                let witness = registry.witness(i, &signatures)?;
                for disprove in [false, true] {
                    let code = registry.script(i, disprove)?;
                    let lengths = [
                        vec![],
                        witness[..witness.len() - 1].to_vec(),
                        [vec![vec![]], witness.clone()].concat(),
                        [witness.clone(), vec![vec![]]].concat(),
                    ];
                    for (j, bad) in lengths.iter().enumerate() {
                        emit(
                            &mut out,
                            &mut metrics,
                            &code,
                            bad,
                            false,
                            &format!("{}/length/{i}/{j}/{disprove}", case.name),
                        )?;
                    }
                    for j in [0, witness.len() - 1] {
                        let mut bad = witness.clone();
                        bad[j][0] ^= 1;
                        emit(
                            &mut out,
                            &mut metrics,
                            &code,
                            &bad,
                            false,
                            &format!("{}/forgery/{i}/{j}/{disprove}", case.name),
                        )?;
                    }
                }
            }
            // A signature valid for one global slot cannot be moved to another.
            let mut substituted = signatures.clone();
            substituted[1] = substituted[0];
            let witness = registry.witness(18, &substituted)?;
            for disprove in [false, true] {
                emit(
                    &mut out,
                    &mut metrics,
                    &registry.script(18, disprove)?,
                    &witness,
                    false,
                    &format!("{}/cross-wire-signature/{disprove}", case.name),
                )?;
            }
            // Even a registry change outside this leaf changes its compiled ID.
            let mut other_keys = keys.clone();
            let used: HashSet<usize> = registry.unique_slots(18)?.into_iter().collect();
            let unused = (0..keys.len())
                .find(|i| !used.contains(i))
                .ok_or("no unused slot")?;
            other_keys[unused] = Wots4::generate_public_key(&vec![0x42; 32]);
            let other_id = case.spec.key_identity(&other_keys)?;
            if Registry::new(case.spec.clone(), other_keys.clone(), expected, id).is_ok() {
                return Err("different global registry accepted under old root".into());
            }
            let other = Registry::new(case.spec.clone(), other_keys, expected, other_id)?;
            if other.script(18, true)? == registry.script(18, true)? {
                return Err("leaf omitted global registry identity".into());
            }
            native_rejections += 1;
        }
    }
    out.flush()?;
    if fs::metadata(&args[2])?.len() > 256 * 1024 * 1024 {
        return Err("executed vector file exceeds 256 MiB".into());
    }
    let mut report = serde_json::json!({"scope":"global-WOTS-wire-registry-and-arithmetic-catalogue","passed":true,
        "cases":cases.len(),"metrics":metrics,"ledger":ledger,"native_rejections":native_rejections,
        "shared_accumulator_and_final_links_checked":shared_links,"signatures_generated_once_per_wire":assertion_signatures,
        "shared_convolution_carry_links_checked":convolution_carry_links,
        "wall_seconds":start.elapsed().as_secs_f64(),"test_keys_only":true,"stack_limit_enabled":true,"op_cat_enabled":false,
        "complete_nova_verifier":false,"bitcoin_transaction_graph":false,"transactions_broadcast":0});
    if !sumcheck_fragments.is_empty() {
        report["sumcheck_fragments"] = serde_json::Value::Array(sumcheck_fragments);
    }
    if !sumcheck_disproofs.is_empty() {
        report["sumcheck_disproofs"] = serde_json::Value::Array(sumcheck_disproofs);
    }
    if !keccak_pair_fragments.is_empty() {
        report["keccak_pair_fragments"] = serde_json::Value::Array(keccak_pair_fragments);
    }
    if !keccak_pair_disproofs.is_empty() {
        report["keccak_pair_disproofs"] = serde_json::Value::Array(keccak_pair_disproofs);
    }
    println!("{report}");
    Ok(())
}
