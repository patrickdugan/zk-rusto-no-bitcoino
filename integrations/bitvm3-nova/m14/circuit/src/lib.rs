//! M14: the garbled final verifier, built from field arithmetic up.
//!
//! Wires are little-endian bit vectors. XOR and NOT are free; AND-class gates are counted
//! (one ciphertext each). Gadgets built from constants fold to constants and cost nothing.
pub mod ext;
pub mod field;
pub mod hash;
pub mod multilinear;
pub mod sample;
pub mod sumcheck;

pub use m12_gates::W;
