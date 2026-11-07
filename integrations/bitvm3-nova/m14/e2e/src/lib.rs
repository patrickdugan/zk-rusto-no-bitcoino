//! M14 end to end: the complete final verifier of the M13 BLAKE3 wrap layer (transcript v2) as a
//! garbled circuit, built from `m14-circuit` gadgets and checked stage by stage against SP1's own
//! verifier on real proofs.
pub mod native;
pub mod full;
pub mod pcs;
pub mod verifier;
