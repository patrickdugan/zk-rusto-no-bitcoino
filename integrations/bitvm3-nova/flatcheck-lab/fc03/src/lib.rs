//! FlatCheck FC03: authenticated refutations of a Nova relaxed-R1CS instance.
//!
//! - [`protocol`]: `TrustedConfig`, `FlatCheckClaim`, `FlatCheckChallenge`, `FlatCheckResponse`;
//! - [`checker`]: the native adjudicator (the oracle for the circuits and the Python reference);
//! - [`binding`]: the Pedersen binding as a double-and-add trace of local steps;
//! - [`fixture`]: the four-row relation folded by Nova 0.76's NIFS on both Pasta engines;
//! - [`flatmerkle`], [`merkle`]: the two commitment schemes compared;
//! - [`circuit`]: the garbled row-check and binding-step circuits.
#![allow(non_snake_case)]

pub mod bench;
pub mod binding;
pub mod cases;
pub mod checker;
pub mod circuit;
pub mod enc;
pub mod field;
pub mod fixture;
pub mod flatmerkle;
pub mod hexser;
pub mod merkle;
pub mod protocol;
pub mod regtest;
pub mod sha;
pub mod shape;
