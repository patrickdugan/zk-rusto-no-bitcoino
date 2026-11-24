//! Canonical statement pins shared by native verification and the M14 circuit.
//!
//! JSON retains the existing hex-string format. Each external statement is checked before it
//! becomes a [`ValidatedFinalStatement`], whose fixed-size fields cannot be mutated. In
//! particular, short or empty digests can never reduce the number of circuit equality checks.
#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};

/// SP1 6.9.0's KoalaBear modulus. Field digests encode eight canonical LE u32 limbs.
pub const KOALABEAR_MODULUS: u32 = 0x7f00_0001;

/// The existing JSON wire representation. Public fields remain available for existing callers;
/// every verifier must call [`Self::validate`] because callers can construct or edit this value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "UncheckedFinalStatement")]
pub struct FinalStatement {
    pub wrap_vk_sha256: String,
    pub program_vk_digest: String,
    pub committed_values_sha256: String,
    pub exit_code: u32,
    pub is_complete: u32,
    pub recursion_vk_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedFinalStatement {
    wrap_vk_sha256: String,
    program_vk_digest: String,
    committed_values_sha256: String,
    exit_code: u32,
    is_complete: u32,
    recursion_vk_root: String,
}

impl TryFrom<UncheckedFinalStatement> for FinalStatement {
    type Error = StatementError;

    fn try_from(value: UncheckedFinalStatement) -> Result<Self, Self::Error> {
        let value = Self {
            wrap_vk_sha256: value.wrap_vk_sha256,
            program_vk_digest: value.program_vk_digest,
            committed_values_sha256: value.committed_values_sha256,
            exit_code: value.exit_code,
            is_complete: value.is_complete,
            recursion_vk_root: value.recursion_vk_root,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Immutable validated pins. Construction is possible only through [`FinalStatement::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFinalStatement {
    wrap_vk_sha256: [u8; 32],
    program_vk_digest: [u32; 8],
    committed_values_sha256: [u8; 32],
    recursion_vk_root: [u32; 8],
}

impl ValidatedFinalStatement {
    pub fn wrap_vk_sha256(&self) -> &[u8; 32] {
        &self.wrap_vk_sha256
    }

    pub fn program_vk_digest(&self) -> &[u32; 8] {
        &self.program_vk_digest
    }

    pub fn committed_values_sha256(&self) -> &[u8; 32] {
        &self.committed_values_sha256
    }

    pub fn recursion_vk_root(&self) -> &[u32; 8] {
        &self.recursion_vk_root
    }
}

impl FinalStatement {
    /// Require every hash to be exactly 32 bytes, every field digest to contain exactly eight
    /// canonical KoalaBear limbs, and the accepted execution status to be exit 0 / complete 1.
    pub fn validate(&self) -> Result<ValidatedFinalStatement, StatementError> {
        let pins = ValidatedFinalStatement {
            wrap_vk_sha256: hex32("wrap_vk_sha256", &self.wrap_vk_sha256)?,
            program_vk_digest: field_digest("program_vk_digest", &self.program_vk_digest)?,
            committed_values_sha256: hex32("committed_values_sha256", &self.committed_values_sha256)?,
            recursion_vk_root: field_digest("recursion_vk_root", &self.recursion_vk_root)?,
        };
        for (field, got, expected) in [("exit_code", self.exit_code, 0), ("is_complete", self.is_complete, 1)] {
            if got != expected {
                return Err(StatementError {
                    field,
                    kind: ErrorKind::Status { expected, got },
                });
            }
        }
        Ok(pins)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementError {
    field: &'static str,
    kind: ErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrorKind {
    Length { got: usize },
    Hex { at: usize },
    NonCanonicalLimb { index: usize, value: u32 },
    Status { expected: u32, got: u32 },
}

impl fmt::Display for StatementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: ", self.field)?;
        match self.kind {
            ErrorKind::Length { got } => write!(f, "expected exactly 64 hex bytes, got {got}"),
            ErrorKind::Hex { at } => write!(f, "non-hex byte at offset {at}"),
            ErrorKind::NonCanonicalLimb { index, value } => {
                write!(f, "limb {index} is {value}, expected less than {KOALABEAR_MODULUS}")
            }
            ErrorKind::Status { expected, got } => write!(f, "expected {expected}, got {got}"),
        }
    }
}

impl std::error::Error for StatementError {}

fn hex32(field: &'static str, value: &str) -> Result<[u8; 32], StatementError> {
    let input = value.as_bytes();
    if input.len() != 64 {
        return Err(StatementError {
            field,
            kind: ErrorKind::Length { got: input.len() },
        });
    }
    let nibble = |byte: u8, at: usize| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(StatementError {
            field,
            kind: ErrorKind::Hex { at },
        }),
    };
    let mut out = [0; 32];
    for (i, pair) in input.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0], 2 * i)? << 4) | nibble(pair[1], 2 * i + 1)?;
    }
    Ok(out)
}

fn field_digest(field: &'static str, value: &str) -> Result<[u32; 8], StatementError> {
    let bytes = hex32(field, value)?;
    let mut limbs = [0; 8];
    for (index, bytes) in bytes.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(bytes.try_into().expect("fixed four-byte chunk"));
        if value >= KOALABEAR_MODULUS {
            return Err(StatementError {
                field,
                kind: ErrorKind::NonCanonicalLimb { index, value },
            });
        }
        limbs[index] = value;
    }
    Ok(limbs)
}
