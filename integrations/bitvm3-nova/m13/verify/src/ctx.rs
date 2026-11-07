//! `Blake3KoalaBear`: SP1 6.9.0's proof configuration (`IopCtx`) with every
//! hash replaced by BLAKE3.
//!
//! The field (KoalaBear), its degree-4 extension, the AIRs, the jagged PCS,
//! BaseFold and the zerocheck/LogUp-GKR protocols are SP1's unchanged. Only
//! the three places a hash appears change:
//!
//! - Merkle leaves: [`LeafHasher`] (each field element as 4 little-endian
//!   bytes, the row hashed with BLAKE3);
//! - Merkle nodes: BLAKE3 of the 64-byte concatenation of the two children;
//! - Fiat-Shamir: `SerializingChallenger32<Blake3Transcript>` (Plonky3 `HashChallenger` semantics),
//!   which hashes everything observed since the last squeeze together with the
//!   previous output, and samples field elements by rejection from 31-bit
//!   words (KoalaBear has p = 2^31 - 2^24 + 1).
//!
//! The digest is `Hash<KoalaBear, u8, 32>`, 32 bytes.
//!
//! Each role has its own counter of BLAKE3 compression-function calls, so a
//! verifier run reports exactly how many compressions a garbled verifier of
//! the same proof has to evaluate.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use slop_challenger::{
    CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx, SerializingChallenger32,
};
use slop_algebra::{AbstractField, PrimeField32, PrimeField64};
use slop_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
use sp1_primitives::{SP1ExtensionField, SP1Field};

/// Domain separation for the transcript: the challenger starts from these bytes.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"garbled-snark-verifier/nova-bitvm3/m13/blake3-koalabear/v1";

pub const ROLE_LEAF: usize = 0;
pub const ROLE_NODE: usize = 1;
pub const ROLE_TRANSCRIPT: usize = 2;
pub const ROLE_NAMES: [&str; 3] = ["merkle_leaf", "merkle_node", "transcript"];

/// Per role: hash calls, compression-function calls, bytes hashed.
pub static CALLS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
pub static COMPRESSIONS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
pub static BYTES: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Number of BLAKE3 compression-function calls for one hash of `len` bytes:
/// 1024-byte chunks of 64-byte blocks (at least one block per chunk), plus
/// one parent compression per internal node of the chunk tree.
pub fn blake3_compressions(len: usize) -> u64 {
    if len == 0 {
        return 1;
    }
    let chunks = len.div_ceil(1024);
    let mut blocks = 0u64;
    for c in 0..chunks {
        let l = (len - c * 1024).min(1024);
        blocks += l.div_ceil(64).max(1) as u64;
    }
    blocks + (chunks as u64 - 1)
}

pub fn reset_counters() {
    for r in 0..3 {
        CALLS[r].store(0, Ordering::SeqCst);
        COMPRESSIONS[r].store(0, Ordering::SeqCst);
        BYTES[r].store(0, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashCounts {
    pub calls: u64,
    pub compressions: u64,
    pub bytes: u64,
}

pub fn read_counters() -> [HashCounts; 3] {
    std::array::from_fn(|r| HashCounts {
        calls: CALLS[r].load(Ordering::SeqCst),
        compressions: COMPRESSIONS[r].load(Ordering::SeqCst),
        bytes: BYTES[r].load(Ordering::SeqCst),
    })
}

/// BLAKE3 over bytes, counted under role `ROLE`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Blake3<const ROLE: usize>;

impl<const ROLE: usize> CryptographicHasher<u8, [u8; 32]> for Blake3<ROLE> {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let bytes: Vec<u8> = input.into_iter().collect();
        CALLS[ROLE].fetch_add(1, Ordering::Relaxed);
        COMPRESSIONS[ROLE].fetch_add(blake3_compressions(bytes.len()), Ordering::Relaxed);
        BYTES[ROLE].fetch_add(bytes.len() as u64, Ordering::Relaxed);
        *blake3::hash(&bytes).as_bytes()
    }
}

pub type Digest = Hash<SP1Field, u8, 32>;

/// Merkle leaf hash: each KoalaBear element as its canonical 4-byte
/// little-endian encoding, the row hashed with BLAKE3. Implemented for both
/// digest spellings the SP1 Merkle prover asks for (`[u8; 32]` and `Digest`).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafHasher;

impl CryptographicHasher<SP1Field, [u8; 32]> for LeafHasher {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = SP1Field>,
    {
        Blake3::<ROLE_LEAF>.hash_iter(input.into_iter().flat_map(|x| x.as_canonical_u32().to_le_bytes()))
    }
}

impl CryptographicHasher<SP1Field, Digest> for LeafHasher {
    fn hash_iter<I>(&self, input: I) -> Digest
    where
        I: IntoIterator<Item = SP1Field>,
    {
        let out: [u8; 32] = CryptographicHasher::<SP1Field, [u8; 32]>::hash_iter(self, input);
        out.into()
    }
}

/// Merkle node hash: BLAKE3 of left || right (64 bytes, one compression).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCompressor;

impl PseudoCompressionFunction<[u8; 32], 2> for NodeCompressor {
    fn compress(&self, input: [[u8; 32]; 2]) -> [u8; 32] {
        Blake3::<ROLE_NODE>.hash_iter(input[0].into_iter().chain(input[1]))
    }
}

impl PseudoCompressionFunction<Digest, 2> for NodeCompressor {
    fn compress(&self, input: [Digest; 2]) -> Digest {
        let [l, r] = input;
        let l: [u8; 32] = l.into();
        let r: [u8; 32] = r.into();
        PseudoCompressionFunction::<[u8; 32], 2>::compress(self, [l, r]).into()
    }
}

/// Byte transcript with the semantics of Plonky3's `HashChallenger<u8, H, 32>`
/// (observing clears pending output; a squeeze hashes everything observed
/// since the last squeeze, keeps the 32-byte output as the start of the next
/// input, and hands output bytes out last-first), with serde so proofs that
/// carry the configuration type serialize.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Blake3Transcript {
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
}

impl Blake3Transcript {
    pub fn new(initial_state: Vec<u8>) -> Self {
        Self { input_buffer: initial_state, output_buffer: Vec::new() }
    }

    fn flush(&mut self) {
        let inputs: Vec<u8> = self.input_buffer.drain(..).collect();
        let output = Blake3::<ROLE_TRANSCRIPT>.hash_iter(inputs);
        self.output_buffer = output.to_vec();
        self.input_buffer.extend(output);
    }
}

impl CanObserve<u8> for Blake3Transcript {
    fn observe(&mut self, value: u8) {
        trace_byte(false, value);
        self.output_buffer.clear();
        self.input_buffer.push(value);
    }
}

impl CanSample<u8> for Blake3Transcript {
    fn sample(&mut self) -> u8 {
        if self.output_buffer.is_empty() {
            self.flush();
        }
        let b = self.output_buffer.pop().expect("output buffer is non-empty after a flush");
        trace_byte(true, b);
        b
    }
}

/// Transcript trace: every byte observed (false) or sampled (true), in order, across all
/// `Blake3Transcript`s of the process. Off unless [`trace_start`] was called; M14 replays it
/// through the circuit transcript.
static TRACE: std::sync::Mutex<Option<Vec<(bool, u8)>>> = std::sync::Mutex::new(None);

fn trace_byte(sampled: bool, b: u8) {
    if let Some(t) = TRACE.lock().unwrap().as_mut() {
        t.push((sampled, b));
    }
}

pub fn trace_start() {
    *TRACE.lock().unwrap() = Some(Vec::new());
}

/// The recorded trace as runs: `kind` byte (0 observe, 1 sample), u32 LE length, the bytes.
pub fn trace_take_runs() -> Vec<u8> {
    let events = TRACE.lock().unwrap().take().unwrap_or_default();
    let mut out = Vec::new();
    let mut i = 0;
    while i < events.len() {
        let kind = events[i].0;
        let j = events[i..].iter().position(|e| e.0 != kind).map_or(events.len(), |k| i + k);
        out.push(kind as u8);
        out.extend(((j - i) as u32).to_le_bytes());
        out.extend(events[i..j].iter().map(|e| e.1));
        i = j;
    }
    out
}

pub type Blake3Challenger = SerializingChallenger32<SP1Field, Blake3Transcript>;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Blake3KoalaBear;

impl IopCtx for Blake3KoalaBear {
    type F = SP1Field;
    type EF = SP1ExtensionField;
    type Digest = Digest;
    type Challenger = Blake3Challenger;
    type Hasher = LeafHasher;
    type Compressor = NodeCompressor;

    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor) {
        (LeafHasher, NodeCompressor)
    }

    fn default_challenger() -> Self::Challenger {
        SerializingChallenger32::new(Blake3Transcript::new(TRANSCRIPT_DOMAIN.to_vec()))
    }
}

/// Transcript v2 domain (M14): fixed-cost challenge sampling over the same byte transcript.
pub const TRANSCRIPT_DOMAIN_V2: &[u8] = b"garbled-snark-verifier/nova-bitvm3/m14/blake3-koalabear/v2";

/// Fiat-Shamir challenger v2. Observing is as in [`Blake3Challenger`] (canonical 4-byte
/// little-endian field elements, digest bytes). Sampling does a fixed amount of work:
/// - a field element takes 8 bytes, read as a little-endian u64 and reduced mod p (no residue
///   has probability above (1 + p/2^64)/p, so any event's probability grows by at most a factor
///   1 + 2^-33 over uniform);
/// - `sample_bits(n)` takes 4 bytes, little-endian, masked to n bits (as v1).
///
/// v1 rejection-samples 31-bit words, so the number of bytes a challenge consumes depends on
/// the transcript and a circuit verifier has no fixed shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blake3ChallengerV2 {
    inner: Blake3Transcript,
}

impl Default for Blake3ChallengerV2 {
    fn default() -> Self {
        Self { inner: Blake3Transcript::new(TRANSCRIPT_DOMAIN_V2.to_vec()) }
    }
}

impl CanObserve<SP1Field> for Blake3ChallengerV2 {
    fn observe(&mut self, value: SP1Field) {
        self.inner.observe_slice(&value.as_canonical_u32().to_le_bytes());
    }
}

impl<const N: usize> CanObserve<Hash<SP1Field, u8, N>> for Blake3ChallengerV2 {
    fn observe(&mut self, values: Hash<SP1Field, u8, N>) {
        for v in values {
            self.inner.observe(v);
        }
    }
}

/// v2 base-field challenge from 8 transcript bytes.
pub fn sample_base_v2(bytes: [u8; 8]) -> SP1Field {
    SP1Field::from_canonical_u32((u64::from_le_bytes(bytes) % SP1Field::ORDER_U64) as u32)
}

impl CanSample<SP1Field> for Blake3ChallengerV2 {
    fn sample(&mut self) -> SP1Field {
        sample_base_v2(self.inner.sample_array::<8>())
    }
}

impl CanSampleBits<usize> for Blake3ChallengerV2 {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < 32, "sample_bits({bits})");
        let r = u32::from_le_bytes(self.inner.sample_array::<4>()) as usize;
        r & ((1usize << bits) - 1)
    }
}

impl GrindingChallenger for Blake3ChallengerV2 {
    type Witness = SP1Field;

    fn grind(&mut self, bits: usize) -> SP1Field {
        let witness = (0..SP1Field::ORDER_U64)
            .map(SP1Field::from_canonical_u64)
            .find(|w| self.clone().check_witness(bits, *w))
            .expect("no proof-of-work witness");
        assert!(self.check_witness(bits, witness));
        witness
    }
}

impl FieldChallenger<SP1Field> for Blake3ChallengerV2 {}

/// [`Blake3KoalaBear`] with challenger v2.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Blake3KoalaBearV2;

impl IopCtx for Blake3KoalaBearV2 {
    type F = SP1Field;
    type EF = SP1ExtensionField;
    type Digest = Digest;
    type Challenger = Blake3ChallengerV2;
    type Hasher = LeafHasher;
    type Compressor = NodeCompressor;

    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor) {
        (LeafHasher, NodeCompressor)
    }

    fn default_challenger() -> Self::Challenger {
        Blake3ChallengerV2::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_sampling_consumes_fixed_bytes() {
        // Two challengers over the same transcript: v2 field samples always take 8 bytes.
        let mut a = Blake3ChallengerV2::default();
        let mut raw = Blake3Transcript::new(TRANSCRIPT_DOMAIN_V2.to_vec());
        for i in 0..1000u32 {
            let x = SP1Field::from_canonical_u32(i * 7919 % 0x7f00_0001);
            a.observe(x);
            raw.observe_slice(&x.as_canonical_u32().to_le_bytes());
            let s: SP1Field = a.sample();
            assert_eq!(s, sample_base_v2(raw.sample_array::<8>()));
            let b = a.sample_bits(20);
            assert_eq!(b, (u32::from_le_bytes(raw.sample_array::<4>()) as usize) & ((1 << 20) - 1));
        }
    }

    #[test]
    fn v2_grinding_witness_checks() {
        let mut a = Blake3ChallengerV2::default();
        a.observe(SP1Field::from_canonical_u32(5));
        let w = a.clone().grind(8);
        assert!(a.check_witness(8, w));
    }

    #[test]
    fn compression_count_matches_blake3_structure() {
        assert_eq!(blake3_compressions(0), 1);
        assert_eq!(blake3_compressions(64), 1);
        assert_eq!(blake3_compressions(65), 2);
        assert_eq!(blake3_compressions(1024), 16);
        assert_eq!(blake3_compressions(1025), 18); // 16 + 1 blocks, 1 parent
        assert_eq!(blake3_compressions(4096), 4 * 16 + 3);
    }
}
