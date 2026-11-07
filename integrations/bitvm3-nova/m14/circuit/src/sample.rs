//! Challenge sampling with a fixed amount of work per challenge (transcript v2).
//!
//! SP1's `SerializingChallenger32` samples a base-field element by rejection: take 4 transcript
//! bytes, keep 31 bits, retry while the value is >= p (probability (2^24 - 1) / 2^31 per try). The
//! number of transcript bytes a challenge consumes then depends on the transcript, which shifts
//! every later byte position: a circuit would need a variable-offset byte selector for every
//! subsequent challenge.
//!
//! v2 takes 8 transcript bytes per base-field element and reduces the little-endian u64 mod p.
//! Every challenge consumes a fixed number of bytes and costs one `reduce_wide`. The distribution
//! is not uniform, but no residue has probability above ceil(2^64 / p) / 2^64 <= (1 + p / 2^64) / p,
//! so the probability of any set of challenges is at most (1 + 2^-33) times its uniform
//! probability: each Fiat-Shamir soundness term grows by that factor.
//!
//! Query indices (`sample_bits`) are unchanged: 4 bytes masked to `bits` low bits, uniform.
use garbled_snark_verifier::CircuitContext;
use m12_gates::W;

use crate::{
    ext::Ext,
    field::{self as f, Fe, P},
};

/// v2 base-field challenge from 8 transcript bytes (64 bit wires, byte 0 bit 0 first).
pub fn base_from_le64<C: CircuitContext>(c: &mut C, bits: &[W]) -> Fe {
    assert_eq!(bits.len(), 64);
    f::reduce_wide(c, bits)
}

/// v2 extension challenge: four base challenges from 32 consecutive bytes, coefficient 0 first.
pub fn ext_from_le256<C: CircuitContext>(c: &mut C, bits: &[W]) -> Ext {
    assert_eq!(bits.len(), 256);
    Ext(std::array::from_fn(|i| base_from_le64(c, &bits[64 * i..64 * i + 64])))
}

/// `sample_bits(n)`: the low n bits of a little-endian u32 from 4 transcript bytes. Wiring only.
pub fn bits_from_le32(bits: &[W], n: usize) -> Vec<W> {
    assert_eq!(bits.len(), 32);
    assert!(n <= 31);
    bits[..n].to_vec()
}

pub fn base_from_le64_native(b: [u8; 8]) -> u32 {
    (u64::from_le_bytes(b) % P as u64) as u32
}

/// SP1 v1 sampling from a byte stream: (value, 4-byte words consumed).
pub fn base_v1_native(stream: &mut impl Iterator<Item = [u8; 4]>) -> (u32, usize) {
    let mut tries = 0;
    loop {
        let v = u32::from_le_bytes(stream.next().expect("stream ended")) & 0x7fff_ffff;
        tries += 1;
        if v < P {
            return (v, tries);
        }
    }
}
