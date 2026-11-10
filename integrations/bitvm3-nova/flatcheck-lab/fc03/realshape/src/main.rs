//! Rebuild the testnet4 k = 1 verifier key from the circuit shape (as M12's tests do), check it
//! against the M12 pin, and print the dimensions and per-row non-zero counts of both R1CS shapes.
//! These sizes parameterise the FC03 fixed circuits for the real Nova proof.
use nova_bitvm3_m12::{mirror, nova_io, pins};
use nova_header_chain::native::Network;
use sha2::{Digest, Sha256};

fn stats<E: nova_snark::traits::Engine>(s: &mirror::Shape<E>) -> serde_json::Value {
    let row_nnz = |m: &nova_snark::r1cs::SparseMatrix<E::Scalar>| -> Vec<usize> { (0..s.num_cons).map(|r| m.indptr[r + 1] - m.indptr[r]).collect() };
    let (a, b, c) = (row_nnz(&s.A), row_nnz(&s.B), row_nnz(&s.C));
    let hist = |v: &[usize]| {
        let mut h = std::collections::BTreeMap::new();
        for &x in v {
            let bucket = if x <= 4 { x } else { x.next_power_of_two() };
            *h.entry(bucket).or_insert(0usize) += 1;
        }
        h
    };
    let tot: Vec<usize> = (0..s.num_cons).map(|r| a[r] + b[r] + c[r]).collect();
    let mut sorted = tot.clone();
    sorted.sort_unstable();
    serde_json::json!({
        "num_cons": s.num_cons, "num_vars": s.num_vars, "num_io": s.num_io,
        "nnz": {"A": s.A.data.len(), "B": s.B.data.len(), "C": s.C.data.len()},
        "max_per_row": {"A": a.iter().max(), "B": b.iter().max(), "C": c.iter().max()},
        "row_total_nnz": {"max": sorted.last(), "p50": sorted[sorted.len() / 2], "p99": sorted[sorted.len() * 99 / 100], "p999": sorted[sorted.len() * 999 / 1000]},
        "hist_A": hist(&a), "hist_B": hist(&b), "hist_C": hist(&c),
    })
}

fn main() {
    let t = std::time::Instant::now();
    let vk = nova_io::vk_export(Network::Testnet4, 1);
    let d = hex::encode(Sha256::digest(&vk));
    pins::check(Network::Testnet4, 1, &d).expect("vk is the M12 pin");
    let v: mirror::CompressedVk = mirror::decode_exact(&vk).expect("vk mirror");
    let out = serde_json::json!({
        "network": "testnet4", "k": 1, "vk_sha256": d, "vk_bytes": vk.len(),
        "primary": stats(&v.vk_primary.S), "secondary": stats(&v.vk_secondary.S),
        "seconds": t.elapsed().as_secs_f64(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
