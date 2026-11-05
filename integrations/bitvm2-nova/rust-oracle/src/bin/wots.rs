//! Generate and execute actual upstream WOTS signatures with initial witnesses.
//! Deterministic test keys only. No production secrets, proving, RPC or spends.
use bitcoin::{
    hashes::{sha256, Hash},
    script::Instruction,
    taproot::TapLeafHash,
    ScriptBuf, Transaction,
};
use bitcoin_scriptexec::{Exec, ExecCtx, Experimental, Options, TxTemplate};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::wots::{id32, AuthenticatedLeaf, PublicKey, Result, Template};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{BufWriter, Write},
    time::Instant,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    template: Template,
    expected_template_id: String,
    words: Vec<u32>,
    expected_correct: bool,
}

#[derive(Serialize)]
struct Vector<'a> {
    name: &'a str,
    script_hex: String,
    witness_hex: Vec<String>,
    expected_success: bool,
}

#[derive(Default, Serialize)]
struct Metrics {
    vectors: usize,
    expected_rejections: usize,
    max_script_bytes: usize,
    max_witness_items: usize,
    max_witness_payload_bytes: usize,
    max_stack_items: usize,
}

fn execute(code: &ScriptBuf, witness: Vec<Vec<u8>>) -> Result<(bool, usize)> {
    if code.len() > 100_000 || witness.len() > 1000 || witness.iter().any(|w| w.len() > 520) {
        return Err("research execution bounds".into());
    }
    for instruction in code.instructions_minimal() {
        if let Instruction::Op(op) = instruction? {
            let op = op.to_u8();
            if !(op == 0x4f
                || (0x51..=0x60).contains(&op)
                || [
                    0x63, 0x67, 0x68, 0x69, 0x6b, 0x6c, 0x6d, 0x6e, 0x74, 0x75, 0x76, 0x78, 0x79,
                    0x7b, 0x7c, 0x7d, 0x82, 0x87, 0x88, 0x8f, 0x91, 0x93, 0x94, 0x9a, 0x9b, 0x9e,
                    0x9f, 0xa2, 0xa5, 0xa8, 0xa9,
                ]
                .contains(&op))
            {
                return Err(format!("unsupported opcode {op:#x}").into());
            }
        }
    }
    let options = Options {
        require_minimal: true,
        verify_cltv: true,
        verify_csv: true,
        verify_minimal_if: true,
        enforce_stack_limit: true,
        experimental: Experimental { op_cat: false },
    };
    let template = TxTemplate {
        tx: Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        },
        prevouts: vec![],
        input_idx: 0,
        taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
    };
    let mut exec = Exec::new(ExecCtx::Tapscript, options, template, code.clone(), witness)
        .map_err(|e| format!("interpreter initialization: {e:?}"))?;
    while exec.exec_next().is_ok() {}
    let result = exec.result().ok_or("interpreter produced no result")?;
    // Deliberately no panic catcher: upstream panics fail the job.
    Ok((result.success, exec.stats().max_nb_stack_items))
}

fn emit(
    out: &mut impl Write,
    metrics: &mut Metrics,
    code: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
    name: &str,
) -> Result<()> {
    let (success, stack) = execute(code, witness.to_vec())?;
    if success != expected {
        return Err(format!("{name}: expected {expected}, got {success}").into());
    }
    metrics.vectors += 1;
    metrics.expected_rejections += usize::from(!expected);
    metrics.max_script_bytes = metrics.max_script_bytes.max(code.len());
    metrics.max_stack_items = metrics.max_stack_items.max(stack);
    metrics.max_witness_items = metrics.max_witness_items.max(witness.len());
    metrics.max_witness_payload_bytes = metrics
        .max_witness_payload_bytes
        .max(witness.iter().map(Vec::len).sum());
    serde_json::to_writer(
        &mut *out,
        &Vector {
            name,
            script_hex: hex::encode(code.as_bytes()),
            witness_hex: witness.iter().map(hex::encode).collect(),
            expected_success: expected,
        },
    )?;
    out.write_all(b"\n")?;
    Ok(())
}

fn identity_tests(
    template: &Template,
    keys: &[PublicKey],
    expected: [u8; 32],
    key_id: [u8; 32],
) -> Result<usize> {
    let mut variants = Vec::new();
    let mut t = template.clone();
    t.context = "01".repeat(32);
    variants.push(t);
    let mut t = template.clone();
    t.program_sha256 = "02".repeat(32);
    variants.push(t);
    let mut t = template.clone();
    t.field_role = "vesta_scalar".into();
    variants.push(t);
    let mut t = template.clone();
    t.operation_id = "wrong-operation".into();
    variants.push(t);
    let mut t = template.clone();
    t.ordinal += 1;
    variants.push(t);
    let mut t = template.clone();
    t.wires.swap(0, 1);
    variants.push(t);
    let mut t = template.clone();
    t.body_hex = "51".into();
    variants.push(t);
    let mut t = template.clone();
    t.bounds[18] = 5;
    variants.push(t);
    let mut count = 0;
    for other in variants {
        if AuthenticatedLeaf::new(other, keys.to_vec(), expected, key_id).is_ok() {
            return Err("identity substitution accepted".into());
        }
        count += 1;
    }
    let mut wrong_keys = keys.to_vec();
    wrong_keys.swap(0, 1);
    if AuthenticatedLeaf::new(template.clone(), wrong_keys, expected, key_id).is_ok() {
        return Err("key slot substitution accepted".into());
    }
    let mut duplicate = keys.to_vec();
    duplicate[1] = duplicate[0];
    if AuthenticatedLeaf::new(template.clone(), duplicate, expected, key_id).is_ok() {
        return Err("one-time key reused across wires".into());
    }
    let mut wrong_id = key_id;
    wrong_id[0] ^= 1;
    if AuthenticatedLeaf::new(template.clone(), keys.to_vec(), expected, wrong_id).is_ok() {
        return Err("wrong verifier key commitment accepted".into());
    }
    Ok(count + 3)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: wots INPUTS_JSON OUTPUT_JSONL".into());
    }
    if fs::metadata(&args[1])?.len() > 2 * 1024 * 1024 {
        return Err("input fixtures exceed 2 MiB".into());
    }
    let cases: Vec<Case> = serde_json::from_slice(&fs::read(&args[1])?)?;
    if cases.is_empty() || cases.len() > 128 {
        return Err("fixture case bound".into());
    }
    let start = Instant::now();
    let mut metrics = Metrics::default();
    let mut out = BufWriter::new(fs::File::create(&args[2])?);
    let mut names = HashSet::new();
    let mut native_checks = 0;
    let mut ledger = Vec::new();
    for case in &cases {
        if case.name.len() > 192 || !names.insert(case.name.clone()) || case.words.len() != 28 {
            return Err("duplicate, oversize or malformed case".into());
        }
        // Fresh test-only keys per case and wire, independent of the word value.
        // Each key is used to sign precisely one message. Never use these keys live.
        let secrets: Vec<Vec<u8>> = case
            .template
            .wires
            .iter()
            .map(|wire| {
                let mut data = b"BITVM2-NOVA/TEST-ONLY-WOTS-KEY/v1\0".to_vec();
                data.extend_from_slice(case.name.as_bytes());
                data.push(0);
                data.extend_from_slice(wire.as_bytes());
                sha256::Hash::hash(&data).to_byte_array().to_vec()
            })
            .collect();
        let keys: Vec<PublicKey> = secrets.iter().map(Wots4::generate_public_key).collect();
        let expected = id32(&case.expected_template_id)?;
        let key_id = case.template.key_identity(&keys)?;
        let leaf = AuthenticatedLeaf::new(case.template.clone(), keys.clone(), expected, key_id)?;
        let codes = [leaf.script(false)?, leaf.script(true)?];
        let mut witness = Vec::new();
        for (secret, word) in secrets.iter().zip(&case.words) {
            witness
                .extend(Wots4::compact_sign_to_raw_witness(secret, &word.to_le_bytes()).to_vec());
        }
        if codes[0] != leaf.script(false)? || codes[1] != leaf.script(true)? {
            return Err("signing changed the verifier script".into());
        }
        for disprove in [false, true] {
            emit(
                &mut out,
                &mut metrics,
                &codes[usize::from(disprove)],
                &witness,
                case.expected_correct != disprove,
                &format!("{}/honest-opening/{disprove}", case.name),
            )?;
        }
        if case.name.ends_with("/zero") {
            native_checks += identity_tests(&case.template, &keys, expected, key_id)?;
            ledger.push(serde_json::json!({"field_role":case.template.field_role,
                "template_id":case.expected_template_id,"key_commitment":hex::encode(key_id),
                "correctness_script_bytes":codes[0].len(),"disproof_script_bytes":codes[1].len(),
                "initial_witness_items":witness.len(),"initial_witness_payload_bytes":witness.iter().map(Vec::len).sum::<usize>()}));
            for disprove in [false, true] {
                let code = &codes[usize::from(disprove)];
                let bad_lengths = [
                    vec![],
                    witness[..witness.len() - 1].to_vec(),
                    [vec![vec![]], witness.clone()].concat(),
                    [witness.clone(), vec![vec![]]].concat(),
                ];
                for (i, bad) in bad_lengths.iter().enumerate() {
                    emit(
                        &mut out,
                        &mut metrics,
                        code,
                        bad,
                        false,
                        &format!("{}/bad-length/{i}/{disprove}", case.name),
                    )?;
                }
                // Corrupt every signature element, including every checksum chain.
                for i in 0..witness.len() {
                    let mut bad = witness.clone();
                    bad[i][0] ^= 1;
                    emit(
                        &mut out,
                        &mut metrics,
                        code,
                        &bad,
                        false,
                        &format!("{}/forgery/{i}/{disprove}", case.name),
                    )?;
                }
                for i in [0, 9, 10, 179, 180, 279] {
                    for len in [0, 19, 21] {
                        let mut bad = witness.clone();
                        bad[i] = vec![0; len];
                        emit(
                            &mut out,
                            &mut metrics,
                            code,
                            &bad,
                            false,
                            &format!("{}/signature-size/{i}/{len}/{disprove}", case.name),
                        )?;
                    }
                }
                let mut swapped = witness.clone();
                for j in 0..10 {
                    swapped.swap(j, j + 10);
                }
                emit(
                    &mut out,
                    &mut metrics,
                    code,
                    &swapped,
                    false,
                    &format!("{}/swapped-wires/{disprove}", case.name),
                )?;
            }
        }
        if case.name.contains("invalid-bit") || case.name.contains("oversize-word/") {
            // An authenticated malformed value must never mask another bad signature.
            let mut bad = witness.clone();
            bad[0][0] ^= 1;
            for disprove in [false, true] {
                emit(
                    &mut out,
                    &mut metrics,
                    &codes[usize::from(disprove)],
                    &bad,
                    false,
                    &format!("{}/malformed-and-forged/{disprove}", case.name),
                )?;
            }
        }
    }
    out.flush()?;
    if fs::metadata(&args[2])?.len() > 256 * 1024 * 1024 {
        return Err("output fixture exceeds 256 MiB".into());
    }
    println!(
        "{}",
        serde_json::json!({"scope":"single-WOTS4-authenticated-mul-bit-leaf",
        "passed":true,"cases":cases.len(),"metrics":metrics,"native_identity_rejections":native_checks,
        "ledger":ledger,"wall_seconds":start.elapsed().as_secs_f64(),"test_keys_only":true,
        "initial_witness_stack":true,"stack_limit_enabled":true,"op_cat_enabled":false,
        "upstream_bitvm":"c620dbfaacebdf778e765a6681985350389973b1",
        "upstream_scriptexec":"ba96bc2bd76774c9d1b011461cb79d983c2c43a1",
        "complete_nova_verifier":false,"complete_assertion_protocol":false,"transactions_broadcast":0})
    );
    Ok(())
}
