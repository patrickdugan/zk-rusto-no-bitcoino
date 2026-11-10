//! Boolean circuits for FC03 local checks, built on the pinned garbled-snark-verifier
//! (rev 8fa7efe) gate context and the M12 SHA-256 compression gadget.
//!
//! Wires: byte strings are 8 wires per byte, least-significant bit first. SHA-256 states and
//! blocks are in "word form": 32-bit big-endian words, each as 32 wires LSB first (the M12
//! gadget's convention). XOR/NOT are free; every AND is one ciphertext.
pub mod field;
pub mod inputs;
pub mod row;
pub mod run;
pub mod step;

use garbled_snark_verifier::{
    circuit::{FALSE_WIRE, TRUE_WIRE},
    gadgets::bigint::{self, BigIntWires},
    CircuitContext, WireId,
};
use m12_gates as g;
use num_bigint::BigUint;

pub type W = WireId;

pub fn const_bit(b: bool) -> W {
    if b {
        TRUE_WIRE
    } else {
        FALSE_WIRE
    }
}

pub fn const_bytes(bs: &[u8]) -> Vec<W> {
    bs.iter().flat_map(|&b| (0..8).map(move |i| const_bit((b >> i) & 1 == 1))).collect()
}

pub fn or<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    let (na, nb) = (g::not(c, a), g::not(c, b));
    let t = g::and(c, na, nb);
    g::not(c, t)
}

pub fn and_all<C: CircuitContext>(c: &mut C, ws: &[W]) -> W {
    let mut v: Vec<W> = ws.to_vec();
    if v.is_empty() {
        return TRUE_WIRE;
    }
    while v.len() > 1 {
        let mut n = Vec::with_capacity(v.len().div_ceil(2));
        for ch in v.chunks(2) {
            n.push(if ch.len() == 2 { g::and(c, ch[0], ch[1]) } else { ch[0] });
        }
        v = n;
    }
    v[0]
}

pub fn eq_bits<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> W {
    assert_eq!(a.len(), b.len());
    let x: Vec<W> = a.iter().zip(b).map(|(&x, &y)| {
        let d = g::xor(c, x, y);
        g::not(c, d)
    }).collect();
    and_all(c, &x)
}

pub fn eq_const_bytes<C: CircuitContext>(c: &mut C, a: &[W], bs: &[u8]) -> W {
    let k = const_bytes(bs);
    eq_bits(c, a, &k)
}

pub fn is_zero<C: CircuitContext>(c: &mut C, a: &[W]) -> W {
    let n: Vec<W> = a.iter().map(|&x| g::not(c, x)).collect();
    and_all(c, &n)
}

/// sel = 0 -> a, sel = 1 -> b.
pub fn select<C: CircuitContext>(c: &mut C, sel: W, a: &[W], b: &[W]) -> Vec<W> {
    a.iter().zip(b).map(|(&x, &y)| g::mux(c, sel, x, y)).collect()
}

pub fn mask<C: CircuitContext>(c: &mut C, s: W, a: &[W]) -> Vec<W> {
    a.iter().map(|&x| g::and(c, s, x)).collect()
}

pub fn xor_vec<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
    a.iter().zip(b).map(|(&x, &y)| g::xor(c, x, y)).collect()
}

/// A big-endian u32 given as 4 byte groups -> 32 value bits, LSB first.
pub fn be32_bits(bytes: &[W]) -> Vec<W> {
    assert_eq!(bytes.len(), 32);
    (0..32).map(|i| bytes[8 * (3 - i / 8) + i % 8]).collect()
}

/// a < k for LSB-first bits a.
pub fn lt_const<C: CircuitContext>(c: &mut C, a: &[W], k: &BigUint) -> W {
    if k.bits() as usize > a.len() {
        // every value of a is below k
        return TRUE_WIRE;
    }
    bigint::less_than_constant(c, &BigIntWires::from_bits(a.iter().copied()), k)
}

pub fn eq_const_u<C: CircuitContext>(c: &mut C, a: &[W], k: u64) -> W {
    if k >> a.len().min(63) != 0 && a.len() < 64 {
        return FALSE_WIRE;
    }
    let kb: Vec<W> = (0..a.len()).map(|i| const_bit(i < 64 && (k >> i) & 1 == 1)).collect();
    eq_bits(c, a, &kb)
}

// ------------------------------------------------------------------ SHA-256 in word form

/// Byte wires (4k bytes) -> word form.
pub fn words_of_bytes(b: &[W]) -> Vec<W> {
    assert_eq!(b.len() % 32, 0);
    let mut out = Vec::with_capacity(b.len());
    for w in b.chunks(32) {
        out.extend(be32_bits(w));
    }
    out
}

/// Word form -> byte wires (inverse of `words_of_bytes`).
pub fn bytes_of_words(w: &[W]) -> Vec<W> {
    let mut out = vec![FALSE_WIRE; w.len()];
    for (k, word) in w.chunks(32).enumerate() {
        for i in 0..32 {
            out[32 * k + 8 * (3 - i / 8) + i % 8] = word[i];
        }
    }
    out
}

pub fn iv_words() -> Vec<W> {
    words_of_bytes(&const_bytes(&crate::sha::IV))
}

pub fn compress<C: CircuitContext>(c: &mut C, state: &[W], block: &[W]) -> Vec<W> {
    assert_eq!((state.len(), block.len()), (256, 512));
    let mut inp = state.to_vec();
    inp.extend_from_slice(block);
    g::sha256_compress(c, &inp)
}

/// Standard SHA-256 of a fixed-length byte-wire message; digest in word form.
pub fn sha256<C: CircuitContext>(c: &mut C, msg: &[W]) -> Vec<W> {
    assert_eq!(msg.len() % 8, 0);
    let len = msg.len() / 8;
    let mut padded = msg.to_vec();
    padded.extend(const_bytes(&[0x80]));
    while (padded.len() / 8) % 64 != 56 {
        padded.extend(const_bytes(&[0]));
    }
    padded.extend(const_bytes(&((len as u64) * 8).to_be_bytes()));
    let mut st = iv_words();
    for blk in padded.chunks(512) {
        st = compress(c, &st, &words_of_bytes(blk));
    }
    st
}

/// The FlatMerkle MID block for a checkpoint (word form).
pub fn mid_block(ck: &[W]) -> Vec<W> {
    let mut b = ck.to_vec();
    let mut tail = [0u8; 32];
    tail[0] = 0x80;
    b.extend(words_of_bytes(&const_bytes(&tail)));
    b
}

/// FlatMerkle opening as circuit wires: index (32 bits LSB first), the pair (byte form), the
/// revealed states in level order (top level first, word form).
pub struct OpenW {
    pub index: Vec<W>,
    pub pair: [Vec<W>; 2],
    pub reveals: Vec<Vec<W>>,
}

/// Lerner FlatMerkle verification with data-dependent directions from `idx` (LSB first).
/// Returns 1 iff the opening's index equals idx, the pair holds `item` at idx, and the
/// recomputed stream digest equals `root` (word form).
pub fn flat_verify<C: CircuitContext>(c: &mut C, n: usize, root: &[W], idx: &[W], item: &[W], op: &OpenW) -> W {
    let m = crate::flatmerkle::level(n).expect("power of two >= 4");
    assert_eq!(op.reveals.len(), m - 1);
    let d = |l: usize| idx[l];
    let s = |l: usize| &op.reveals[m - 1 - l];
    let sel = select(c, d(0), &op.pair[0], &op.pair[1]);
    let ok_item = eq_bits(c, &sel, item);
    let ok_index = eq_bits(c, &op.index, &idx[..32]);
    // Down: checkpoints C[l] of the node split at bit l, for l = m-2 .. 0.
    let mut ck = vec![Vec::new(); m - 1];
    ck[m - 2] = select(c, d(m - 1), &iv_words(), s(m - 1));
    for l in (1..m - 1).rev() {
        ck[l - 1] = select(c, d(l), &ck[l], s(l));
    }
    // Up.
    let p0 = words_of_bytes(&op.pair[0]);
    let p1 = words_of_bytes(&op.pair[1]);
    let x = compress(c, &ck[0], &p0);
    let x = compress(c, &x, &p1);
    let mut e = compress(c, &x, &mid_block(&ck[0]));
    for l in 1..m - 1 {
        let right = if d(l) == TRUE_WIRE {
            e.clone()
        } else {
            let alt = compress(c, s(l), &mid_block(&e));
            select(c, d(l), &alt, &e)
        };
        e = compress(c, &right, &mid_block(&ck[l]));
    }
    let state = if d(m - 1) == TRUE_WIRE {
        e
    } else {
        let alt = compress(c, s(m - 1), &mid_block(&e));
        select(c, d(m - 1), &alt, &e)
    };
    let mut pad = [0u8; 64];
    pad[0] = 0x80;
    pad[56..].copy_from_slice(&((crate::flatmerkle::stream_blocks(n) as u64) * 64 * 8).to_be_bytes());
    let dig = compress(c, &state, &words_of_bytes(&const_bytes(&pad)));
    let ok_root = eq_bits(c, &dig, root);
    and_all(c, &[ok_item, ok_index, ok_root])
}

/// A circuit-side `Enc` (enc.rs): constant framing around wire values; `bytes()` is the exact
/// message `Enc::bytes` produces for the same values.
pub struct CEnc(Vec<W>);

impl CEnc {
    fn frame_const(&mut self, b: &[u8]) {
        self.0.extend(const_bytes(&(b.len() as u32).to_be_bytes()));
        self.0.extend(const_bytes(b));
    }
    pub fn new(kind: &str) -> CEnc {
        let mut e = CEnc(Vec::new());
        e.frame_const(crate::enc::PROTOCOL);
        e.frame_const(kind.as_bytes());
        e
    }
    pub fn field(&mut self, tag: &str, v: &[W]) -> &mut Self {
        assert_eq!(v.len() % 8, 0);
        self.frame_const(tag.as_bytes());
        self.0.extend(const_bytes(&((v.len() / 8) as u32).to_be_bytes()));
        self.0.extend_from_slice(v);
        self
    }
    pub fn bytes(&self) -> &[W] {
        &self.0
    }
}

/// Cursor over the circuit's input wires; consumption order mirrors `inputs::Layout`.
pub struct Cur<'a> {
    pub w: &'a [W],
    pub pos: usize,
}

impl<'a> Cur<'a> {
    pub fn new(w: &'a [W]) -> Self {
        Cur { w, pos: 0 }
    }
    pub fn bytes(&mut self, n: usize) -> Vec<W> {
        let v = self.w[self.pos..self.pos + 8 * n].to_vec();
        self.pos += 8 * n;
        v
    }
    pub fn opening(&mut self, n_leaves: usize) -> OpenW {
        let m = crate::flatmerkle::level(n_leaves).unwrap();
        let index = be32_bits(&self.bytes(4));
        let pair = [self.bytes(64), self.bytes(64)];
        let reveals = (0..m - 1).map(|_| words_of_bytes(&self.bytes(32))).collect();
        OpenW { index, pair, reveals }
    }
    pub fn done(&self) {
        assert_eq!(self.pos, self.w.len(), "input layout fully consumed");
    }
}

/// Parsed wires of a value item `"FC03" || fid || tag || 00 00 || index || payload || 0^20`.
pub struct ItemW {
    pub ok_fixed: W,
    pub index: Vec<W>,
    pub payload: Vec<W>,
}

pub fn parse_item<C: CircuitContext>(c: &mut C, it: &[W], fid: u8, tag: u8) -> ItemW {
    let head = eq_const_bytes(c, &it[..64], &[b'F', b'C', b'0', b'3', fid, tag, 0, 0]);
    let tail = is_zero(c, &it[44 * 8..]);
    ItemW { ok_fixed: g::and(c, head, tail), index: be32_bits(&it[64..96]), payload: it[96..352].to_vec() }
}

/// The record item for a hashed record: `item(fid, tag, index, digest)` from wires.
pub fn record_item(fid: u8, tag: u8, index_be: &[W], digest_words: &[W]) -> Vec<W> {
    let mut it = const_bytes(&[b'F', b'C', b'0', b'3', fid, tag, 0, 0]);
    it.extend_from_slice(index_be);
    it.extend(bytes_of_words(digest_words));
    it.extend(const_bytes(&[0u8; 20]));
    it
}

/// 32 LSB-first value bits -> big-endian byte wires.
pub fn be32_bytes(bits: &[W]) -> Vec<W> {
    let mut out = vec![FALSE_WIRE; 32];
    for i in 0..32 {
        out[8 * (3 - i / 8) + i % 8] = bits[i];
    }
    out
}

/// a + 1 over 32 bits.
pub fn inc32<C: CircuitContext>(c: &mut C, a: &[W]) -> Vec<W> {
    g::add(c, a, &g::const_bits(1, 32), 32)
}
