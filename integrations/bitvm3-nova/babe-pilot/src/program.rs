//! The locally refutable relation carried by a cut-and-choose session.
//!
//! Callers independently select and pin this program before accepting Commit1.
//! A program emits one bit: an authenticated violation of the committed claim.

use anyhow::{ensure, Result};
use garbled_snark_verifier::CircuitContext;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    dispute_circuit::{
        eval_indexed_dispute_circuit, IndexedDisputeSpec, PILOT_INPUT_BITS, PILOT_PRIME,
    },
    gates::W,
    trace::{eval_trace_dispute_circuit, TraceDisputeSpec},
};

pub trait DisputeProgram: Clone + std::fmt::Debug + Eq + Serialize + DeserializeOwned {
    fn circuit_id(&self) -> [u8; 32];
    fn input_bits(&self) -> usize;
    fn validate(&self) -> Result<()>;
    fn eval<C: CircuitContext>(&self, c: &mut C, input: &[W]) -> Vec<W>;
}

impl DisputeProgram for IndexedDisputeSpec {
    fn circuit_id(&self) -> [u8; 32] {
        self.circuit_id
    }
    fn input_bits(&self) -> usize {
        PILOT_INPUT_BITS
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.generators.iter().all(|&g| u64::from(g) < PILOT_PRIME),
            "non-canonical fixed generator"
        );
        let mut expected = self.clone();
        expected.recompute_circuit_id();
        ensure!(
            self.circuit_id == expected.circuit_id,
            "non-canonical circuit identity"
        );
        Ok(())
    }
    fn eval<C: CircuitContext>(&self, c: &mut C, input: &[W]) -> Vec<W> {
        eval_indexed_dispute_circuit(c, self, input)
    }
}

impl DisputeProgram for TraceDisputeSpec {
    fn circuit_id(&self) -> [u8; 32] {
        self.circuit_id()
    }
    fn input_bits(&self) -> usize {
        self.input_bits()
    }
    fn validate(&self) -> Result<()> {
        self.validate()
    }
    fn eval<C: CircuitContext>(&self, c: &mut C, input: &[W]) -> Vec<W> {
        eval_trace_dispute_circuit(c, self, input)
    }
}
