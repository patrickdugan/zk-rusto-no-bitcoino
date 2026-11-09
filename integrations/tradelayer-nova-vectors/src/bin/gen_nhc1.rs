//! Vector 7: NHC1 header-chain circuit under the ppsnark CompressedSNARK.
use ff::PrimeField;
use halo2curves::pasta::Fq;
use nova_vectors::nhc1::native::{Header, State};
use nova_vectors::nhc1::HeaderStep;
use nova_vectors::runner::*;
use num_bigint::BigUint;
use std::time::Instant;

/// `NHC1_FIXTURES`: the `fixtures` directory of rust-bitcoin-zk-adapter's
/// `integrations/nova-header-chain` (SP1 checkpoint and header files).
fn src_dir() -> std::path::PathBuf {
    std::env::var("NHC1_FIXTURES")
        .expect("set NHC1_FIXTURES to integrations/nova-header-chain/fixtures of rust-bitcoin-zk-adapter")
        .into()
}

fn sp1_checkpoint(b: &[u8]) -> State {
    assert!(b.len() == 128 && b[80] == 11, "not an SP1 chain start state");
    let u = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let mut ts = [0u32; 11];
    for (i, t) in ts.iter_mut().enumerate() {
        *t = u(81 + 4 * i);
    }
    assert_eq!(ts[10], u(72));
    State {
        height: u(0),
        prev: b[4..36].try_into().unwrap(),
        chainwork: BigUint::from_bytes_le(&b[36..68]),
        epoch_bits: u(68),
        epoch_start: u(76),
        ts,
    }
}

fn load_headers_txt(path: &std::path::Path) -> std::collections::BTreeMap<u32, Header> {
    let mut hs = std::collections::BTreeMap::new();
    for line in std::fs::read_to_string(path).unwrap().lines().filter(|l| !l.trim().is_empty()) {
        let mut it = line.split_whitespace();
        let h: u32 = it.next().unwrap().parse().unwrap();
        let header: Header = hex::decode(it.next().unwrap()).unwrap().try_into().unwrap();
        hs.insert(h, header);
    }
    hs
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let start: u32 = args.get(1).map(|v| v.parse().unwrap()).unwrap_or(959984);
    let k: u32 = args.get(2).map(|v| v.parse().unwrap()).unwrap_or(10);
    let steps: u32 = args.get(3).map(|v| v.parse().unwrap()).unwrap_or(1);
    let t0 = Instant::now();
    spawn_watchdog(16, 45 * 60, t0);
    let hs = load_headers_txt(&src_dir().join("headers_958987_959994.txt"));
    let mut cp = sp1_checkpoint(&std::fs::read(src_dir().join("checkpoint_958986.state")).unwrap());
    while cp.height < start {
        cp = cp.apply(&hs[&(cp.height + 1)]).expect("headers before start are valid");
    }
    let mut state = cp.clone();
    let mut circuits = Vec::new();
    for s in 0..steps {
        let headers: Vec<Header> = (0..k).map(|i| hs[&(start + 1 + s * k + i)]).collect();
        for h in headers.iter() {
            state = state.apply(h).expect("native check");
        }
        circuits.push(HeaderStep { headers });
    }
    let z0: Vec<Fq> = cp.to_z::<Fq>();
    let zn: Vec<Fq> = state.to_z::<Fq>();
    let _ = Fq::NUM_BITS;
    let o = Opts {
        name: format!("nhc1_ppsnark_k{k}x{steps}"),
        circuit_desc: format!(
            "NHC1 header-chain step circuit (nova-header-chain src/lib.rs copied verbatim), arity 17, {steps} step(s) x {k} mainnet headers, checkpoint height {start} (from fixtures checkpoint_958986.state + headers_958987_959994.txt)"
        ),
        write_full_vk: false,
        watchdog: true,
    };
    run_proof(&o, &circuits, &z0, Some(zn));
}
