//! Native check of real Bitcoin-header Nova proofs inside the BitVM3 lab
//! crate: decode an NHC1/NHT4 bundle and its verifier key with this crate's
//! pinned nova-snark 0.76.0, then verify. The header circuit is not linked:
//! `Arity17` only fixes the arity; the verifier key carries the circuit.
//! This is the native baseline M11's garbled path must match; it runs no
//! garbled verification.
//!
//! Fixtures and the key digest: fixtures/bitcoin-header/README.md.
//!
//!   NOVA_REAL_BUNDLES="fixtures/bitcoin-header/k20-testnet4-0-40.nht4;fixtures/bitcoin-header/k20-testnet4-40-80.nht4" \
//!   NOVA_REAL_VK=key.vk cargo test --release --features native-reference --test real_header_proof_native -- --nocapture
#![cfg(feature = "native-reference")]

use ff::PrimeField;
use nova_snark::{
    frontend::{ConstraintSystem, SynthesisError, num::AllocatedNum},
    nova::{CompressedSNARK, VerifierKey},
    provider::{PallasEngine, VestaEngine, ipa_pc},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{Engine, circuit::StepCircuit},
};
use sha2::{Digest, Sha256};

type E1 = PallasEngine;
type E2 = VestaEngine;
type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;

#[derive(Clone, Debug)]
struct Arity17;
impl StepCircuit<F> for Arity17 {
    fn arity(&self) -> usize {
        17
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        _: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        Ok(z.to_vec())
    }
}

const MAX_BUNDLE: usize = 1 << 20;

/// magic | steps u32 | k u32 | z0 (17 x 32) | proof
fn split(b: &[u8]) -> (&'static str, usize, usize, Vec<F>, &[u8]) {
    assert!(
        b.len() <= MAX_BUNDLE && b.len() > 12 + 17 * 32,
        "bundle size"
    );
    let net = match &b[..4] {
        b"NHC1" => "mainnet",
        b"NHT4" => "testnet4",
        _ => panic!("not an NHC1/NHT4 bundle"),
    };
    let steps = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    let k = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    let z0 = b[12..12 + 17 * 32]
        .chunks(32)
        .map(|c| {
            let mut r = <F as PrimeField>::Repr::default();
            r.as_mut().copy_from_slice(c);
            Option::<F>::from(F::from_repr(r)).expect("canonical z0")
        })
        .collect();
    (net, steps, k, z0, &b[12 + 17 * 32..])
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

#[test]
fn real_header_bundles_verify_natively_and_mutations_are_rejected() {
    let (Ok(paths), Ok(vk_path)) = (
        std::env::var("NOVA_REAL_BUNDLES"),
        std::env::var("NOVA_REAL_VK"),
    ) else {
        eprintln!("skipped: NOVA_REAL_BUNDLES / NOVA_REAL_VK unset");
        return;
    };
    let t = std::time::Instant::now();
    let vk_bytes = std::fs::read(&vk_path).unwrap();
    let vk: VerifierKey<E1, E2, Arity17, S1, S2> =
        bincode::deserialize(&vk_bytes).expect("vk decodes");
    eprintln!(
        "vk {} bytes sha256 {} decoded in {:.1}s",
        vk_bytes.len(),
        sha(&vk_bytes),
        t.elapsed().as_secs_f64()
    );
    drop(vk_bytes);

    for p in paths.split(';') {
        let b = std::fs::read(p).unwrap();
        let (net, steps, k, z0, proof) = split(&b);
        let snark: CompressedSNARK<E1, E2, Arity17, S1, S2> =
            bincode::deserialize(proof).expect("proof decodes");
        let t = std::time::Instant::now();
        let zn = snark.verify(&vk, steps, &z0).expect("real proof verifies");
        eprintln!(
            "{p}: {net} k={k} steps={steps} proof {} bytes sha256 {} verified in {:.2}s; end height {:?}",
            proof.len(),
            sha(proof),
            t.elapsed().as_secs_f64(),
            zn[0]
        );

        // The verdict must flip for each kind of change.
        assert!(
            snark.verify(&vk, steps + 1, &z0).is_err(),
            "wrong step count"
        );
        let mut z = z0.clone();
        z[3] += F::from(1u64);
        assert!(
            snark.verify(&vk, steps, &z).is_err(),
            "altered checkpoint chainwork"
        );
        let mut z = z0.clone();
        z[1] += F::from(1u64);
        assert!(
            snark.verify(&vk, steps, &z).is_err(),
            "altered checkpoint hash"
        );
        for at in [8usize, proof.len() / 4, proof.len() / 2, proof.len() - 40] {
            let mut bad = proof.to_vec();
            bad[at] ^= 1;
            let ok = bincode::deserialize::<CompressedSNARK<E1, E2, Arity17, S1, S2>>(&bad)
                .ok()
                .map(|s| s.verify(&vk, steps, &z0).is_ok())
                .unwrap_or(false);
            assert!(!ok, "proof byte {at} flipped and still verified");
        }
        assert!(
            bincode::deserialize::<CompressedSNARK<E1, E2, Arity17, S1, S2>>(
                &proof[..proof.len() - 1]
            )
            .is_err(),
            "truncated proof decoded"
        );
    }
}
