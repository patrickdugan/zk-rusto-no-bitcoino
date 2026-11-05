//! Fixed-claim research fixture checks, with real initial-stack witnesses.
//! No network calls, transactions, proof generation, or production bridge API.
use bitcoin::{hashes::Hash, script::Instruction, taproot::TapLeafHash, ScriptBuf, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, Experimental, Options, TxTemplate};
use ff::{Field, PrimeField};
use halo2curves::{group::Curve, pasta::{PallasAffine, VestaAffine}, CurveAffine};
use serde::Deserialize;
use std::{error::Error, fs, io::{BufRead, BufReader, Read}, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Point { infinity: u8, x_le: String, y_le: String }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CurveVector { name: String, curve: String, left: Point, right: Point, result: Point, expected_success: bool }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptVector { name: String, script_hex: String, witness_hex: Vec<String>, expected_success: bool }

fn field<F: PrimeField>(s: &str) -> Result<F> {
    if s.len() != 64 { return Err("field encoding must be exactly 32 bytes".into()); }
    let bytes = hex::decode(s)?;
    let mut repr = F::Repr::default();
    if repr.as_ref().len() != 32 { return Err("unexpected field representation".into()); }
    repr.as_mut().copy_from_slice(&bytes);
    Option::<F>::from(F::from_repr(repr)).ok_or_else(|| "noncanonical field".into())
}

fn point<A: CurveAffine>(p: &Point) -> Result<A> {
    let x = field::<A::Base>(&p.x_le)?;
    let y = field::<A::Base>(&p.y_le)?;
    match p.infinity {
        1 if x == A::Base::ZERO && y == A::Base::ZERO => Ok(A::identity()),
        0 => Option::<A>::from(A::from_xy(x,y)).ok_or_else(|| "off-curve point".into()),
        _ => Err("invalid infinity encoding".into()),
    }
}

fn curve_valid<A: CurveAffine>(v: &CurveVector) -> bool {
    match (point::<A>(&v.left), point::<A>(&v.right), point::<A>(&v.result)) {
        (Ok(a),Ok(b),Ok(c)) => (a.to_curve()+b.to_curve()).to_affine() == c,
        _ => false,
    }
}

fn curves(path: &str) -> Result<()> {
    if fs::metadata(path)?.len() > 2*1024*1024 { return Err("curve fixtures exceed 2 MiB".into()); }
    let vectors: Vec<CurveVector> = serde_json::from_slice(&fs::read(path)?)?;
    if vectors.is_empty() || vectors.len() > 1024 { return Err("curve vector count out of bounds".into()); }
    let mut rejected = 0;
    for v in &vectors {
        let actual = match v.curve.as_str() {
            "pallas" => curve_valid::<PallasAffine>(v),
            "vesta" => curve_valid::<VestaAffine>(v),
            _ => return Err("unsupported curve".into()),
        };
        if actual != v.expected_success { return Err(format!("halo2curves mismatch: {}",v.name).into()); }
        if !actual { rejected += 1; }
    }
    println!("{}",serde_json::json!({"oracle":"halo2curves-0.9.0","vectors":vectors.len(),
        "expected_rejections":rejected,"passed":true}));
    Ok(())
}

fn scripts(path: &str) -> Result<()> {
    if fs::metadata(path)?.len() > 256*1024*1024 { return Err("Script fixtures exceed 256 MiB".into()); }
    let mut reader = BufReader::new(fs::File::open(path)?);
    let (mut count,mut rejected,mut max_stack,mut max_script,mut max_witness)=(0,0,0,0,0);
    let start=Instant::now();
    loop {
        let mut line=Vec::new();
        let n=reader.by_ref().take(256*1024+1).read_until(b'\n',&mut line)?;
        if n==0 { break; }
        if n>256*1024 { return Err("JSONL record exceeds 256 KiB".into()); }
        count+=1;
        if count>20_000 { return Err("Script vector count exceeds 20,000".into()); }
        let v: ScriptVector=serde_json::from_slice(&line)?;
        let code=hex::decode(&v.script_hex)?;
        if code.len()>100_000 { return Err("primitive Script exceeds 100,000 bytes".into()); }
        let witness: Vec<Vec<u8>>=v.witness_hex.iter().map(hex::decode).collect::<std::result::Result<_,_>>()?;
        if witness.len()>1000 || witness.iter().any(|w| w.len()>520) { return Err("initial witness bound".into()); }
        let witness_bytes: usize=witness.iter().map(Vec::len).sum();
        max_witness=max_witness.max(witness_bytes);
        max_script=max_script.max(code.len());
        let script=ScriptBuf::from_bytes(code);
        // Independent allowlist: OP_SUCCESS and OP_CAT cannot slip through a fixture.
        for ins in script.instructions_minimal() {
            match ins? {
                Instruction::PushBytes(_) => {},
                Instruction::Op(op) => {
                    let op=op.to_u8();
                    if !(op==0x4f || (0x51..=0x60).contains(&op) ||
                         [0x63,0x67,0x68,0x69,0x6b,0x6c,0x74,0x75,0x79,0x87,0x88,0x91,
                          0x93,0x94,0x9a,0x9b,0x9f,0xa2,0xa5,0xa8].contains(&op)) {
                        return Err(format!("unsupported opcode {op:#x}").into());
                    }
                }
            }
        }
        let options=Options { require_minimal:true,verify_cltv:true,verify_csv:true,
            verify_minimal_if:true,enforce_stack_limit:true,experimental:Experimental { op_cat:false } };
        let template=TxTemplate {
            tx:Transaction { version:bitcoin::transaction::Version::TWO,
                lock_time:bitcoin::absolute::LockTime::ZERO,input:vec![],output:vec![] },
            prevouts:vec![],input_idx:0,taproot_annex_scriptleaf:Some((TapLeafHash::all_zeros(),None)) };
        let mut exec=Exec::new(ExecCtx::Tapscript,options,template,script,witness)
            .map_err(|e| format!("interpreter initialization: {e:?}"))?;
        while exec.exec_next().is_ok() {}
        let result=exec.result().ok_or("interpreter produced no result")?;
        if result.success!=v.expected_success {
            return Err(format!("{}: expected {}, got {:?}",v.name,v.expected_success,result).into());
        }
        if !result.success { rejected+=1; }
        max_stack=max_stack.max(exec.stats().max_nb_stack_items);
    }
    if count==0 { return Err("empty Script fixture".into()); }
    println!("{}",serde_json::json!({"oracle":"BitVM-rust-bitcoin-scriptexec-ba96bc2b",
        "vectors":count,"expected_rejections":rejected,"passed":true,"max_stack_items":max_stack,
        "max_script_bytes":max_script,"max_witness_payload_bytes":max_witness,
        "wall_seconds":start.elapsed().as_secs_f64(),"initial_witness_stack":true,
        "stack_limit_enabled":true,"op_cat_enabled":false,
        "opcode_count":null,"opcode_count_note":"upstream Tapscript counter is not populated",
        "bitcoin_core_regtest_executed":false,"transactions_broadcast":0}));
    Ok(())
}

fn main() -> Result<()> {
    let args:Vec<String>=std::env::args().collect();
    if args.len()!=3 { return Err("usage: m2-oracle --curves FILE | --scripts FILE".into()); }
    match args[1].as_str() { "--curves"=>curves(&args[2]),"--scripts"=>scripts(&args[2]),
        _=>Err("unsupported mode".into()) }
}
