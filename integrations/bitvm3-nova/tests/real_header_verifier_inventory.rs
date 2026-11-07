//! Exact verifier-workload inventory of a real Bitcoin-header Nova verifier
//! key (Nova 0.76.0 CompressedSNARK, non-preprocessing Spartan with IPA on
//! both Pallas and Vesta engines), read from the key bytes themselves.
//!
//! The private wrappers (`nova::VerifierKey`, `spartan::snark::VerifierKey`,
//! `ipa_pc::VerifierKey`, `R1CSShape`) are mirrored field for field, in serde
//! order; every inner type is Nova's own public type, so decoding uses Nova's
//! serde for Poseidon constants, Pedersen keys, curve points and matrices.
//! Fields marked `#[serde(skip)]` upstream are not serialized and are omitted.
//!
//! Operation counts follow the installed 0.76.0 `verify` code paths:
//! - `spartan/snark.rs` `multi_evaluate`: equality tables T_x (2^|r_x|) and
//!   T_y (2^|r_y|) via `EqPolynomial::evals_from_points`, then
//!   `T_x[row] * T_y[col] * val` for every nonzero of A, B and C;
//! - `provider/ipa_pc.rs` `InnerProductArgument::verify`: an n-entry scalar
//!   vector `s` (one multiplication per entry after s[0]) committed against n
//!   generators, n = 2^|L_vec| = the batched W/E opening length.
//! These are native operation counts, not garbled gate counts.
//!
//!   NOVA_REAL_VK=key.vk [NOVA_INVENTORY_OUT=inventory.json] \
//!   cargo test --release --features native-reference --test real_header_verifier_inventory -- --nocapture
#![cfg(feature = "native-reference")]
#![allow(non_snake_case)]

use ff::PrimeField;
use nova_snark::{
    provider::{PallasEngine, VestaEngine, pedersen::CommitmentKey, traits::DlogGroup},
    r1cs::SparseMatrix,
    traits::{Engine, ROConstants, commitment::CommitmentEngineTrait},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

type E1 = PallasEngine;
type E2 = VestaEngine;

#[derive(Deserialize)]
#[serde(bound = "")]
struct IpaVk<E: Engine>
where
    E::GE: DlogGroup,
{
    ck_v: CommitmentKey<E>,
    ck_s: CommitmentKey<E>,
}

#[derive(Deserialize)]
#[serde(bound = "")]
struct Shape<E: Engine> {
    num_cons: usize,
    num_vars: usize,
    num_io: usize,
    A: SparseMatrix<E::Scalar>,
    B: SparseMatrix<E::Scalar>,
    C: SparseMatrix<E::Scalar>,
}

#[derive(Deserialize)]
#[serde(bound = "")]
struct SpartanVk<E: Engine>
where
    E::GE: DlogGroup,
{
    vk_ee: IpaVk<E>,
    S: Shape<E>,
}

#[derive(Deserialize)]
#[serde(bound = "")]
struct CompressedVk {
    F_arity: usize,
    _ro_consts_primary: ROConstants<E1>,
    _ro_consts_secondary: ROConstants<E2>,
    pp_digest: <E1 as Engine>::Scalar,
    vk_primary: SpartanVk<E1>,
    vk_secondary: SpartanVk<E2>,
    _dk_primary: <<E1 as Engine>::CE as CommitmentEngineTrait<E1>>::DerandKey,
    _dk_secondary: <<E2 as Engine>::CE as CommitmentEngineTrait<E2>>::DerandKey,
}

fn pow2(n: usize) -> usize {
    n.next_power_of_two()
}

fn engine<E: Engine>(name: &str, vk: &SpartanVk<E>) -> serde_json::Value
where
    E::GE: DlogGroup,
{
    let s = &vk.S;
    let nnz = [s.A.data.len(), s.B.data.len(), s.C.data.len()];
    for (m, n) in [(&s.A, nnz[0]), (&s.B, nnz[1]), (&s.C, nnz[2])] {
        assert_eq!(m.indices.len(), n);
        assert_eq!(m.indptr.len(), s.num_cons + 1, "row pointer length");
    }
    let nnz_total: usize = nnz.iter().sum();
    // Spartan pads the constraint count and the witness length to powers of two;
    // Z = (W, u, X) spans 2 * padded num_vars columns.
    let rows = pow2(s.num_cons);
    let vars = pow2(s.num_vars);
    let cols = 2 * vars;
    // Batched W/E opening: W over r_y[1..] (length vars), E over r_x (length rows),
    // zero-padded to the larger; the IPA runs on that length.
    let n_ipa = rows.max(vars);
    let eq_table_muls = rows + cols;
    let matrix_muls = 2 * nnz_total;
    serde_json::json!({
        "engine": name,
        "num_cons": s.num_cons, "num_vars": s.num_vars, "num_io": s.num_io,
        "padded_rows": rows, "padded_vars": vars, "z_columns": cols,
        "nnz": {"A": nnz[0], "B": nnz[1], "C": nnz[2], "total": nnz_total},
        "ipa_ck_v_generators": vk.vk_ee.ck_v.generators().len(),
        "ipa_ck_s_generators": vk.vk_ee.ck_s.generators().len(),
        "ipa_opening_length_n": n_ipa,
        "ipa_rounds": n_ipa.trailing_zeros(),
        "verify_ops": {
            "matrix_eval_field_muls": matrix_muls + eq_table_muls,
            "matrix_eval_breakdown": {"per_nonzero": matrix_muls, "eq_tables": eq_table_muls},
            "ipa_s_vector_field_muls": n_ipa - 1,
            "ipa_msm_terms": n_ipa,
        }
    })
}

#[test]
fn real_header_verifier_key_inventory() {
    let Ok(vk_path) = std::env::var("NOVA_REAL_VK") else {
        eprintln!("skipped: NOVA_REAL_VK unset");
        return;
    };
    let bytes = std::fs::read(&vk_path).unwrap();
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    let t = std::time::Instant::now();
    // The header prover writes keys with bincode 1.x's legacy encoding (fixed-width
    // integers). Rejecting trailing bytes proves the mirror consumed the key exactly.
    use bincode::Options;
    let vk: CompressedVk = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&bytes)
        .expect("verifier key decodes with the mirrored layout, with no bytes left over");
    let p = engine(
        "primary (Pallas scalar field, Pallas curve commitments)",
        &vk.vk_primary,
    );
    let s = engine(
        "secondary (Vesta scalar field, Vesta curve commitments)",
        &vk.vk_secondary,
    );
    let total_muls = p["verify_ops"]["matrix_eval_field_muls"].as_u64().unwrap()
        + s["verify_ops"]["matrix_eval_field_muls"].as_u64().unwrap()
        + p["verify_ops"]["ipa_s_vector_field_muls"].as_u64().unwrap()
        + s["verify_ops"]["ipa_s_vector_field_muls"].as_u64().unwrap();
    let total_msm = p["verify_ops"]["ipa_msm_terms"].as_u64().unwrap()
        + s["verify_ops"]["ipa_msm_terms"].as_u64().unwrap();
    let out = serde_json::json!({
        "schema": "nova-bitvm3-verifier-inventory/v1",
        "nova": "nova-snark 0.76.0 CompressedSNARK, spartan::snark::RelaxedR1CSSNARK + ipa_pc on both engines",
        "verifier_key_path": vk_path, "verifier_key_bytes": bytes.len(), "verifier_key_sha256": digest,
        "F_arity": vk.F_arity,
        "pp_digest_le_hex": vk.pp_digest.to_repr().as_ref().iter().map(|x| format!("{x:02x}")).collect::<String>(),
        "decode_seconds": t.elapsed().as_secs_f64(),
        "engines": [p, s],
        "linear_verifier_work": {
            "field_muls_in_matrix_eval_and_ipa_scalars": total_muls,
            "msm_terms_total": total_msm,
            "not_counted": ["NIFS Poseidon RO hashes and fold scalar multiplications",
                             "sumcheck rounds (logarithmic)", "Keccak transcript (logarithmic)",
                             "IPA L/R folding (2 log n points)"]
        }
    });
    let text = serde_json::to_string_pretty(&out).unwrap();
    println!("{text}");
    if let Ok(o) = std::env::var("NOVA_INVENTORY_OUT") {
        std::fs::write(o, text).unwrap();
    }
}
