//! M13 prover side: SP1 6.9.0's shrink step, then SP1's wrap program proved
//! with BLAKE3. The verifier side is the `m13-verify` crate.
pub mod pipeline;

pub use m13_verify::ctx;
