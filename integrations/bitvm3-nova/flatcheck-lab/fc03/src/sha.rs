//! SHA-256 through the raw compression function, with a per-thread count of compression calls.
//! Both commitment schemes hash through this module, so their counts are directly comparable.
use std::cell::Cell;

pub const IV: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52,
    0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
];

thread_local! {
    static COMPRESSIONS: Cell<u64> = const { Cell::new(0) };
}

/// Compression calls made on this thread so far.
pub fn compressions() -> u64 {
    COMPRESSIONS.with(|c| c.get())
}

/// Run `f` and return its result with the number of compression calls it made.
pub fn counted<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = compressions();
    let out = f();
    (out, compressions() - before)
}

/// One SHA-256 compression with a caller-supplied chaining state (big-endian words).
pub fn compress(state: &[u8; 32], block: &[u8; 64]) -> [u8; 32] {
    COMPRESSIONS.with(|c| c.set(c.get() + 1));
    let mut h = [0u32; 8];
    for (i, w) in h.iter_mut().enumerate() {
        *w = u32::from_be_bytes(state[4 * i..4 * i + 4].try_into().unwrap());
    }
    let blk: sha2::digest::generic_array::GenericArray<u8, sha2::digest::consts::U64> = (*block).into();
    sha2::compress256(&mut h, &[blk]);
    let mut out = [0u8; 32];
    for (i, w) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// Standard SHA-256 finalization of a chaining state after `byte_length` message bytes, all of
/// which have already been absorbed in whole blocks.
pub fn finalize(state: &[u8; 32], byte_length: usize) -> [u8; 32] {
    assert_eq!(byte_length % 64, 0, "finalize expects whole blocks");
    let mut pad = [0u8; 64];
    pad[0] = 0x80;
    pad[56..].copy_from_slice(&((byte_length as u64) * 8).to_be_bytes());
    compress(state, &pad)
}

/// Standard SHA-256 of a message, counted.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
    let mut st = IV;
    for blk in padded.chunks(64) {
        st = compress(&st, blk.try_into().unwrap());
    }
    st
}

/// Number of compressions SHA-256 needs for a message of `len` bytes.
pub fn blocks_for(len: usize) -> usize {
    (len + 9).div_ceil(64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn matches_sha2_crate() {
        for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 200, 1000] {
            let m: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let (d, n) = counted(|| sha256(&m));
            assert_eq!(d.as_slice(), Sha256::digest(&m).as_slice());
            assert_eq!(n as usize, blocks_for(len));
        }
    }
}
