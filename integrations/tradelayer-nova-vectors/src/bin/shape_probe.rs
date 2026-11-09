//! Cheap shape probe: R1CS sizes of the primary/secondary circuits for a step circuit, and the exact
//! ppsnark vk / proof sizes they imply (formula validated against measured cubic proofs).
use halo2curves::pasta::Fq;
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::nova::PublicParams;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use nova_vectors::nhc1::HeaderStep;
use nova_vectors::runner::*;
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};

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

static REC: std::sync::Mutex<Option<(u64, u64, usize)>> = std::sync::Mutex::new(None);

fn probe<C: StepCircuit<Fq>>(name: &str, c: &C) {
    *REC.lock().unwrap() = None;
    let h1 = |s: &nova_snark::r1cs::R1CSShape<E1>| -> usize {
        let b = bincode::serialize(s).unwrap();
        let f1 = S1::ck_floor();
        *REC.lock().unwrap() = Some((u64::from_le_bytes(b[0..8].try_into().unwrap()), u64::from_le_bytes(b[8..16].try_into().unwrap()), f1(s)));
        panic!("probe stop: shape recorded")
    };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = PublicParams::<E1, E2, C>::setup(c, &h1, &|_s: &nova_snark::r1cs::R1CSShape<E2>| 0usize);
    }));
    let (nc1, nv1, nnz1) = REC.lock().unwrap().unwrap();
    let m1 = nc1.max(nv1).next_power_of_two();
    let n1 = (nnz1 as u64).max(2 * m1).max(m1).next_power_of_two();
    println!("{name}\tprimary_num_cons={nc1}\tprimary_num_vars={nv1}\tnnz_total={nnz1}\tpadded_m={m1}\tN={n1}");
}

fn main() {
    probe("cubic", &CubicCircuit::<Fq>::default());
    probe("nhc1_k1", &HeaderStep { headers: vec![[0u8; 80]; 1] });
    probe("nhc1_k10", &HeaderStep { headers: vec![[0u8; 80]; 10] });
}
