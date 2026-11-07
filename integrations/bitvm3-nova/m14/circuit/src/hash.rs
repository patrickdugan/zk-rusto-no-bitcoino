//! BLAKE3 over a fixed number of bytes, the Fiat-Shamir byte transcript and Merkle paths, as used by
//! M13's `Blake3KoalaBear` (nova-bitvm3/m13/verify/src/ctx.rs).
//!
//! Bytes are 8 wires each, bit 0 first; a byte string is the concatenation, so a 32-bit
//! little-endian word is 32 consecutive wires. The shape (lengths, flags, counters, tree) is fixed
//! when the circuit is built; only the byte values are wires.
use garbled_snark_verifier::{CircuitContext, circuit::FALSE_WIRE};
use m12_gates::{self as g, B3_IV, W};

use crate::field::{self as f, Fe};

/// M13's transcript domain (rejection sampling, `Blake3KoalaBear`).
pub const DOMAIN_V1: &[u8] = b"garbled-snark-verifier/nova-bitvm3/m13/blake3-koalabear/v1";
/// Transcript v2 (fixed-cost sampling, see `sample`): a different domain, so v1 and v2 transcripts
/// never coincide.
pub const DOMAIN_V2: &[u8] = b"garbled-snark-verifier/nova-bitvm3/m14/blake3-koalabear/v2";

pub const CHUNK_START: u32 = 1;
pub const CHUNK_END: u32 = 2;
pub const PARENT: u32 = 4;
pub const ROOT: u32 = 8;
pub const CHUNK_LEN: usize = 1024;
pub const BLOCK_LEN: usize = 64;

/// A 32-byte digest as 256 wires.
pub type Digest = Vec<W>;

fn iv_words() -> Vec<W> {
    B3_IV.iter().flat_map(|w| g::const32(*w)).collect()
}

/// One compression: cv (256 wires) and a block of `block_len` bytes (zero-padded to 64).
fn compress<C: CircuitContext>(c: &mut C, cv: &[W], block: &[W], counter: u64, flags: u32) -> Vec<W> {
    assert_eq!(cv.len(), 256);
    assert!(block.len() <= 512 && block.len() % 8 == 0);
    let mut inp = cv.to_vec();
    inp.extend_from_slice(block);
    inp.resize(256 + 512, FALSE_WIRE);
    let out = g::blake3_compress(c, &inp, counter, (block.len() / 8) as u32, flags);
    out[..256].to_vec()
}

/// Chaining value of chunk `index` (`root` when it is the only chunk).
fn chunk_cv<C: CircuitContext>(c: &mut C, bytes: &[W], index: u64, root: bool) -> Vec<W> {
    let blocks: Vec<&[W]> = if bytes.is_empty() { vec![&bytes[..0]] } else { bytes.chunks(BLOCK_LEN * 8).collect() };
    let mut cv = iv_words();
    let n = blocks.len();
    for (i, blk) in blocks.into_iter().enumerate() {
        let mut flags = 0;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i + 1 == n {
            flags |= CHUNK_END;
            if root {
                flags |= ROOT;
            }
        }
        cv = compress(c, &cv, blk, index, flags);
    }
    cv
}

/// Subtree over chunks [first, first + n): the left subtree takes the largest power of two
/// chunk count that leaves at least one chunk on the right.
fn subtree<C: CircuitContext>(c: &mut C, bytes: &[W], first: usize, n: usize, root: bool) -> Vec<W> {
    if n == 1 {
        let lo = first * CHUNK_LEN * 8;
        let hi = (lo + CHUNK_LEN * 8).min(bytes.len());
        return chunk_cv(c, &bytes[lo..hi], first as u64, root);
    }
    let left_n = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
    let l = subtree(c, bytes, first, left_n, false);
    let r = subtree(c, bytes, first + left_n, n - left_n, false);
    let mut block = l;
    block.extend(r);
    compress(c, &iv_words(), &block, 0, PARENT | if root { ROOT } else { 0 })
}

/// BLAKE3 (32-byte output) of `bytes.len() / 8` bytes.
pub fn blake3<C: CircuitContext>(c: &mut C, bytes: &[W]) -> Digest {
    assert_eq!(bytes.len() % 8, 0);
    let len = bytes.len() / 8;
    let chunks = len.div_ceil(CHUNK_LEN).max(1);
    subtree(c, bytes, 0, chunks, true)
}

/// Compression-function calls for `len` bytes (same formula as m13's `blake3_compressions`).
pub fn compressions(len: usize) -> u64 {
    if len == 0 {
        return 1;
    }
    let chunks = len.div_ceil(CHUNK_LEN);
    (0..chunks).map(|i| (len - i * CHUNK_LEN).min(CHUNK_LEN).div_ceil(BLOCK_LEN) as u64).sum::<u64>() + chunks as u64 - 1
}

/// 1 iff two digests are equal: 255 OR gates.
pub fn digest_eq<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> W {
    assert_eq!(a.len(), b.len());
    let d: Vec<W> = a.iter().zip(b).map(|(x, y)| g::xor(c, *x, *y)).collect();
    let nz = f::or_all(c, &d);
    g::not(c, nz)
}

// ------------------------------------------------------------------ transcript
/// `Blake3Transcript` (Plonky3 `HashChallenger<u8, BLAKE3, 32>` semantics): observing a byte
/// clears pending output and appends to the input; sampling with no pending output hashes the
/// whole input, keeps the digest as the next input and hands out its bytes last-first.
#[derive(Clone, Debug)]
pub struct Transcript {
    input: Vec<W>,
    output: Vec<Vec<W>>,
    /// Compression calls spent so far (fixed by the shape).
    pub compressions: u64,
    /// Every observed byte (8 wires each), in order: lets tests compare a stage's observations
    /// with a recorded native transcript. Wiring only.
    pub log: Vec<W>,
}

impl Transcript {
    /// Starts from constant bytes (the domain separator).
    pub fn new(initial: &[u8]) -> Self {
        Transcript {
            input: initial.iter().flat_map(|b| g::const_bits(*b as u128, 8)).collect(),
            output: Vec::new(),
            compressions: 0,
            log: Vec::new(),
        }
    }
    pub fn observe_bytes(&mut self, bytes: &[W]) {
        assert_eq!(bytes.len() % 8, 0);
        if !bytes.is_empty() {
            self.output.clear();
        }
        self.input.extend_from_slice(bytes);
        self.log.extend_from_slice(bytes);
    }
    /// `observe(F)`: 4 little-endian bytes of the canonical value.
    pub fn observe_fe(&mut self, x: &Fe) {
        self.observe_bytes(&x.le_bits32());
    }
    pub fn observe_digest(&mut self, d: &[W]) {
        self.observe_bytes(d);
    }
    fn flush<C: CircuitContext>(&mut self, c: &mut C) {
        let input = std::mem::take(&mut self.input);
        self.compressions += compressions(input.len() / 8);
        let out = blake3(c, &input);
        self.output = out.chunks(8).map(|b| b.to_vec()).collect();
        self.input = out;
    }
    pub fn sample_byte<C: CircuitContext>(&mut self, c: &mut C) -> Vec<W> {
        if self.output.is_empty() {
            self.flush(c);
        }
        self.output.pop().unwrap()
    }
    /// `sample_array::<N>()`: N bytes in sampling order, concatenated.
    pub fn sample_bytes<C: CircuitContext>(&mut self, c: &mut C, n: usize) -> Vec<W> {
        (0..n).flat_map(|_| self.sample_byte(c)).collect()
    }
}

// ------------------------------------------------------------------ Merkle
/// Leaf: BLAKE3 of the row, each element as 4 little-endian bytes.
pub fn leaf_hash<C: CircuitContext>(c: &mut C, row: &[Fe]) -> Digest {
    let bytes: Vec<W> = row.iter().flat_map(|x| x.le_bits32()).collect();
    blake3(c, &bytes)
}

/// Node: BLAKE3 of left || right (64 bytes, one compression).
pub fn node<C: CircuitContext>(c: &mut C, l: &[W], r: &[W]) -> Digest {
    let mut b = l.to_vec();
    b.extend_from_slice(r);
    blake3(c, &b)
}

/// Root from a leaf digest, its index bits (bit i = 1: the current node is the right child at
/// height i) and the siblings bottom-up. Per level: 256 selects and one compression.
pub fn path_root<C: CircuitContext>(c: &mut C, leaf: &[W], index: &[W], siblings: &[Digest]) -> Digest {
    assert_eq!(index.len(), siblings.len());
    let mut cur = leaf.to_vec();
    for (bit, sib) in index.iter().zip(siblings) {
        let l: Vec<W> = (0..256).map(|i| g::mux(c, *bit, cur[i], sib[i])).collect();
        // r = cur ^ sib ^ l: the other operand, free
        let r: Vec<W> = (0..256)
            .map(|i| {
                let t = g::xor(c, cur[i], sib[i]);
                g::xor(c, t, l[i])
            })
            .collect();
        cur = node(c, &l, &r);
    }
    cur
}
