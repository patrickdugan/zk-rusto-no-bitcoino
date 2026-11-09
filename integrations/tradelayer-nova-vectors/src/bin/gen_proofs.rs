//! Vector 6: full ppsnark CompressedSNARK proofs for z' = z^3 + z + 5 (3 and 7 steps).
use halo2curves::pasta::Fq;
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;
use nova_vectors::runner::*;
use std::marker::PhantomData;

#[derive(Clone, Debug, Default)]
struct CubicCircuit<F: ff::PrimeField> {
    _p: PhantomData<F>,
}

impl<F: ff::PrimeField> StepCircuit<F> for CubicCircuit<F> {
    fn arity(&self) -> usize {
        1
    }
    fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let x = &z[0];
        let x_sq = x.square(cs.namespace(|| "x_sq"))?;
        let x_cu = x_sq.mul(cs.namespace(|| "x_cu"), x)?;
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(x_cu.get_value().unwrap() + x.get_value().unwrap() + F::from(5u64)))?;
        cs.enforce(
            || "y = x^3 + x + 5",
            |lc| lc + x_cu.get_variable() + x.get_variable() + CS::one() + CS::one() + CS::one() + CS::one() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + y.get_variable(),
        );
        Ok(vec![y])
    }
}

fn main() {
    let which: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let which = if which.is_empty() { vec![3, 7] } else { which };
    for steps in which {
        let z0 = match std::env::var("NOVA_CUBIC_Z0") {
            // 64 hex chars: the 32-byte little-endian canonical encoding of z0.
            Ok(hex) => {
                let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
                let mut repr = <Fq as ff::PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&bytes);
                Option::<Fq>::from(<Fq as ff::PrimeField>::from_repr(repr)).expect("canonical z0")
            }
            Err(_) => Fq::from(if steps == 3 { 2u64 } else { 7u64 }),
        };
        let mut z = z0;
        for _ in 0..steps {
            z = z * z * z + z + Fq::from(5u64);
        }
        let c = CubicCircuit::<Fq>::default();
        let circuits = vec![c; steps];
        let o = Opts {
            name: std::env::var("NOVA_CUBIC_NAME").unwrap_or_else(|_| format!("cubic_{steps}steps")),
            circuit_desc: "arity 1, z' = z^3 + z + 5 over the Pallas scalar field Fq (nova's CubicCircuit test circuit, written with nova_snark::frontend)".into(),
            write_full_vk: std::env::var("NOVA_VEC_FULL_VK").is_ok(),
            watchdog: false,
        };
        let _ = o.watchdog;
        run_proof(&o, &circuits, &[z0], Some(vec![z]));
    }
}
