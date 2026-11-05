//! Global signatures are created once per wire and reused across leaf openings.
//! Keys are deterministic TEST-ONLY fixtures, never production signing keys.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{emit, Metrics},
    registry::{GraphSpec, Registry, Signature, Word},
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
    x.field_role = "vesta_scalar".into();
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
    x.leaves.retain(|l| l.kind != "field_valid");
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
    let mut assertion_signatures = 0;
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
            ledger.push(serde_json::json!({"case":case.name,"registry_id":hex::encode(id),"catalogue_id":case.expected_spec_id,
                "words":case.spec.words.len(),"leaves":case.spec.leaves.len(),"executed_leaves":checks.len(),
                "all_disproof_script_bytes":sum,"largest_disproof_leaf_bytes":largest,
                "global_public_key_payload_bytes":keys.len()*Wots4::TOTAL_DIGIT_LEN as usize*20,
                "global_signature_payload_bytes":signatures.len()*Wots4::TOTAL_DIGIT_LEN as usize*20,
                "leaf_stream_sha256":sha256::Hash::from_engine(h).to_string()}));
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
    println!(
        "{}",
        serde_json::json!({"scope":"global-WOTS-wire-registry-and-arithmetic-catalogue","passed":true,
        "cases":cases.len(),"metrics":metrics,"ledger":ledger,"native_rejections":native_rejections,
        "shared_accumulator_and_final_links_checked":shared_links,"signatures_generated_once_per_wire":assertion_signatures,
        "wall_seconds":start.elapsed().as_secs_f64(),"test_keys_only":true,"stack_limit_enabled":true,"op_cat_enabled":false,
        "complete_nova_verifier":false,"bitcoin_transaction_graph":false,"transactions_broadcast":0})
    );
    Ok(())
}
