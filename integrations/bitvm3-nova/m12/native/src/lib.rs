//! M12: final-proof feasibility for the Nova Bitcoin-header proofs.
//!
//! - [`bundle`]: the NHT4/NHC1 bundle format and the public statement a
//!   wrapper must bind (network, fold width, steps, z0, zn, key and proof
//!   digests), with a fixed 1,164-byte encoding shared with the SP1 guest.
//! - [`pins`]: pinned verifier-key digests per (network, k).
//! - [`nova_io`]: Nova 0.76.0 types, the genesis-anchored small prover and
//!   the statement-bound native verifier.
//! - [`mirror`]: serde mirrors that read the verifier key (shape, commitment
//!   key) and a RecursiveSNARK (the folded witness) from their bincode bytes.
//! - [`pcs`]: a transparent hash-based multilinear commitment (Reed-Solomon
//!   rows, SHA-256 Merkle columns, Ligero-style checks) over Nova's primary
//!   scalar field.
//! - [`decider_b`]: architecture B's relation: relaxed R1CS satisfaction of
//!   the folded instance plus binding of the hash-committed witness to Nova's
//!   Pedersen commitments.
#![allow(non_snake_case)]

pub mod bundle;
pub mod decider_b;
pub mod mirror;
pub mod nova_io;
pub mod pcs;
pub mod pins;
