//! Bounded research-fixture executor. No panic catcher or transaction sender.
use crate::wots::Result;
use bitcoin::{hashes::Hash, script::Instruction, taproot::TapLeafHash, ScriptBuf, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, Experimental, Options, TxTemplate};
use serde::Serialize;
use std::io::Write;

#[derive(Default, Serialize)]
pub struct Metrics {
    pub vectors: usize,
    pub expected_rejections: usize,
    pub max_script_bytes: usize,
    pub max_witness_items: usize,
    pub max_witness_payload_bytes: usize,
    pub max_stack_items: usize,
}

pub fn validate(code: &ScriptBuf) -> Result<()> {
    if code.len() > 100_000 {
        return Err("script size bound".into());
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
    Ok(())
}

pub fn execute(code: &ScriptBuf, witness: Vec<Vec<u8>>) -> Result<(bool, usize)> {
    validate(code)?;
    if witness.len() > 1000 || witness.iter().any(|w| w.len() > 520) {
        return Err("initial witness bounds".into());
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
    Ok((result.success, exec.stats().max_nb_stack_items))
}

pub fn emit(
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
        &serde_json::json!({"name":name,"script_hex":hex::encode(code.as_bytes()),
        "witness_hex":witness.iter().map(hex::encode).collect::<Vec<_>>(),"expected_success":expected}),
    )?;
    out.write_all(b"\n")?;
    Ok(())
}
