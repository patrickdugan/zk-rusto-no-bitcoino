//! groth16-gym spv [--out DIR]        SPV payment circuit on the mainnet fixture
//! groth16-gym headers N [--out DIR]  N-header chain circuit ending at 959,994
//!
//! One configuration per process, so the reported peak RSS is that run's.
//! Prints one JSON line. Setup uses a seeded RNG: the toxic waste is known
//! and the keys are for measurement only, never for anything real.
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use groth16_gym::{chain_from_txt, spv_from_hex};
use std::time::Instant;

const TX_HEX: &str = include_str!("../fixtures/fd2fdd44.tx.hex");
const MERKLEBLOCK_HEX: &str = include_str!("../fixtures/fd2fdd44.merkleblock.hex");
const HEADERS_TXT: &str = include_str!("../fixtures/headers_959617_959994.txt");

fn peak_rss_mb() -> f64 {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let kb = s
            .lines()
            .find(|l| l.starts_with("VmHWM:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        return kb / 1024.0;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
        return if ok != 0 {
            c.PeakWorkingSetSize as f64 / 1_048_576.0
        } else {
            0.0
        };
    }
    #[allow(unreachable_code)]
    0.0
}

fn count_constraints<C: ConstraintSynthesizer<Fr>>(c: C) -> (usize, usize) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    c.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(
        cs.is_satisfied().unwrap(),
        "fixture witness does not satisfy the circuit"
    );
    (cs.num_constraints(), cs.num_instance_variables() - 1)
}

fn run<C: ConstraintSynthesizer<Fr> + Clone>(
    name: &str,
    param: usize,
    c: C,
    inputs: Vec<Fr>,
    out: Option<&str>,
) {
    let (constraints, public_inputs) = count_constraints(c.clone());
    let after_count = peak_rss_mb();
    let mut rng = StdRng::seed_from_u64(0x0067_796d);
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c.clone(), &mut rng).unwrap();
    let setup_s = t.elapsed().as_secs_f64();
    let after_setup = peak_rss_mb();
    let t = Instant::now();
    let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
    let prove_s = t.elapsed().as_secs_f64();
    let after_prove = peak_rss_mb();
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
    let t = Instant::now();
    let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    // Check every public-input field against the same proof and verifying
    // key, including both limbs of each byte-array commitment. Setup and
    // proving are performed only once.
    let rejects_wrong_input = (0..inputs.len()).all(|i| {
        let mut wrong = inputs.clone();
        wrong[i] += Fr::from(1u64);
        !Groth16::<Bn254>::verify_with_processed_vk(&pvk, &wrong, &proof).unwrap()
    });
    let size = |x: &dyn Fn(&mut Vec<u8>)| {
        let mut v = Vec::new();
        x(&mut v);
        v.len()
    };
    let proof_bytes = size(&|v| proof.serialize_compressed(v).unwrap());
    let vk_bytes = size(&|v| vk.serialize_compressed(v).unwrap());
    let pk_bytes = size(&|v| pk.serialize_compressed(v).unwrap());
    if let Some(dir) = out {
        std::fs::create_dir_all(dir).unwrap();
        let w = |n: &str, f: &dyn Fn(&mut Vec<u8>)| {
            let mut v = Vec::new();
            f(&mut v);
            std::fs::write(format!("{dir}/{n}"), v).unwrap();
        };
        w("proof.bin", &|v| proof.serialize_compressed(v).unwrap());
        w("vk.bin", &|v| vk.serialize_compressed(v).unwrap());
        w("public_inputs.bin", &|v| {
            inputs.serialize_compressed(v).unwrap()
        });
    }
    println!(
        "{{\"circuit\":\"{name}\",\"param\":{param},\"constraints\":{constraints},\"public_inputs\":{public_inputs},\
\"setup_s\":{setup_s:.2},\"prove_s\":{prove_s:.2},\"verify_ms\":{verify_ms:.1},\"proof_bytes\":{proof_bytes},\
\"vk_bytes\":{vk_bytes},\"pk_mb\":{:.1},\"peak_rss_mb_after_count\":{after_count:.0},\
\"peak_rss_mb_after_setup\":{after_setup:.0},\"peak_rss_mb\":{after_prove:.0},\"threads\":{},\
\"verified\":{ok},\"rejects_wrong_input\":{rejects_wrong_input}}}",
        pk_bytes as f64 / 1_048_576.0,
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    );
    assert!(ok && rejects_wrong_input);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);
    match args.get(1).map(String::as_str) {
        Some("spv") => {
            let c = spv_from_hex(TX_HEX, MERKLEBLOCK_HEX, 0).expect("SPV witness");
            let inputs = c.public.inputs();
            run("spv_payment", c.branch.len(), c, inputs, out);
        }
        Some("headers") => {
            let n: usize = args.get(2).expect("headers N").parse().expect("N");
            let c = chain_from_txt(HEADERS_TXT, 959_994, n).expect("header witness");
            let inputs = c.public.inputs();
            run("header_chain", n, c, inputs, out);
        }
        _ => {
            eprintln!("usage: groth16-gym spv [--out DIR] | groth16-gym headers N [--out DIR]");
            std::process::exit(2);
        }
    }
}
