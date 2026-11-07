//! m13-verify verify WRAP.bin EXPECT.json       (transcript v1, M13's final proof)
//! m13-verify verify-v2 WRAP.bin EXPECT.json    (transcript v2, fixed-cost challenges)
//!     The complete final verifier, run once on one thread: wall time,
//!     BLAKE3 compressions per role and (with the `opcount` feature and
//!     patched p3-koala-bear) every KoalaBear operation.
//!     M13_TRANSCRIPT_TRACE=PATH writes every transcript byte observed or
//!     sampled, in order (`ctx::trace_take_runs` format).
//! m13-verify dump-zerocheck-v2 WRAP.bin OUT.json
//!     The v2 proof's zerocheck sumcheck as JSON (M14 test data).
use std::{collections::BTreeMap, time::Instant};

use anyhow::{bail, ensure, Result};
use m13_verify::{ctx, opcount, verify_final, Blake3KoalaBear, Blake3KoalaBearV2, FinalLayer, FinalStatement};
use serde::{de::DeserializeOwned, Serialize};
use sp1_hypercube::{SP1PcsProof, SP1WrapProof, ShardProof};

fn main() -> Result<()> {
    // One rayon thread: a parallel reduction adds one partial sum per extra
    // thread, so counts taken with more threads vary with the thread count
    // and between runs. Single-threaded counts are deterministic and are the
    // work of the sequential verifier, which is what a circuit evaluates.
    std::env::set_var("RAYON_NUM_THREADS", "1");
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() == 4, "usage: m13-verify verify|verify-v2 WRAP.bin EXPECT.json");
    match a[1].as_str() {
        "verify" => run::<Blake3KoalaBear>(&a[2], &a[3]),
        "verify-v2" => run::<Blake3KoalaBearV2>(&a[2], &a[3]),
        "dump-zerocheck-v2" => {
            // The proof's zerocheck sumcheck (claimed sum, round polynomials, point, evaluation).
            let wrap: m13_verify::Blake3WrapProofV2 = bincode::deserialize(&std::fs::read(&a[2])?)?;
            std::fs::write(&a[3], serde_json::to_string(&wrap.proof.zerocheck_proof)? + "\n")?;
            Ok(())
        }
        _ => bail!("usage: m13-verify verify|verify-v2 WRAP.bin EXPECT.json | dump-zerocheck-v2 WRAP.bin OUT.json"),
    }
}

fn run<GC: FinalLayer>(wrap_path: &str, expect_path: &str) -> Result<()>
where
    SP1WrapProof<GC, SP1PcsProof<GC>>: DeserializeOwned,
    ShardProof<GC, SP1PcsProof<GC>>: Serialize,
{
    let bytes = std::fs::read(wrap_path)?;
    let wrap: SP1WrapProof<GC, SP1PcsProof<GC>> = bincode::deserialize(&bytes)?;
    let expect: FinalStatement = serde_json::from_slice(&std::fs::read(expect_path)?)?;
    let proof_bytes = bincode::serialize(&wrap.proof)?.len();
    let trace_path = std::env::var("M13_TRANSCRIPT_TRACE").ok();
    if trace_path.is_some() {
        ctx::trace_start();
    }
    ctx::reset_counters();
    opcount::reset();
    let t = Instant::now();
    let got = match verify_final(&wrap, &expect) {
        Ok(s) => s,
        Err(e) => bail!("refused: {e:#}"),
    };
    let secs = t.elapsed().as_secs_f64();
    if let Some(p) = trace_path {
        std::fs::write(&p, ctx::trace_take_runs())?;
    }
    let ops = opcount::snapshot();
    let counts = ctx::read_counters();
    let by_role: BTreeMap<_, _> = ctx::ROLE_NAMES.iter().zip(counts.iter()).map(|(k, v)| (*k, *v)).collect();
    let total: u64 = counts.iter().map(|c| c.compressions).sum();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "verified", "seconds": secs, "statement": got,
            "wrap_file_bytes": bytes.len(), "wrap_proof_bytes": proof_bytes,
            "public_values_len": wrap.proof.public_values.len(),
            "blake3": by_role, "blake3_compressions_total": total,
            "koalabear_ops": ops,
        }))?
    );
    Ok(())
}
