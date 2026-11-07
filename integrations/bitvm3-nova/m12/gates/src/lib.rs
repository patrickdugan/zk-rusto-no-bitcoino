//! M12: non-free gate costs of STARK/FRI verifier primitives.
//! Words are little-endian bit vectors. XOR/NOT are free; AND/OR-class gates are priced.
//! Constants (TRUE_WIRE/FALSE_WIRE) are folded so they never cost an AND gate.
use garbled_snark_verifier::{
    CircuitContext, Gate, WireId,
    circuit::{FALSE_WIRE, TRUE_WIRE},
    gadgets::bigint::{BigIntWires, mul, mul_naive},
};

pub type W = WireId;

pub fn xor<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    if a == FALSE_WIRE { return b; }
    if b == FALSE_WIRE { return a; }
    if a == b { return FALSE_WIRE; }
    let o = c.issue_wire();
    c.add_gate(Gate::xor(a, b, o));
    o
}
pub fn not<C: CircuitContext>(c: &mut C, a: W) -> W {
    if a == FALSE_WIRE { return TRUE_WIRE; }
    if a == TRUE_WIRE { return FALSE_WIRE; }
    xor(c, a, TRUE_WIRE)
}
pub fn and<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    if a == FALSE_WIRE || b == FALSE_WIRE { return FALSE_WIRE; }
    if a == TRUE_WIRE { return b; }
    if b == TRUE_WIRE { return a; }
    let o = c.issue_wire();
    c.add_gate(Gate::and(a, b, o));
    o
}
/// sel=0 -> a, sel=1 -> b. One AND.
pub fn mux<C: CircuitContext>(c: &mut C, sel: W, a: W, b: W) -> W {
    let d = xor(c, a, b);
    let t = and(c, sel, d);
    xor(c, a, t)
}
pub fn const_bits(v: u128, w: usize) -> Vec<W> {
    (0..w).map(|i| if (v >> i) & 1 == 1 { TRUE_WIRE } else { FALSE_WIRE }).collect()
}
fn bit(a: &[W], i: usize) -> W { a.get(i).copied().unwrap_or(FALSE_WIRE) }

/// a + b + cin over `w` bits; returns (sum[w], carry_out). One AND per bit (none when folded away).
pub fn add_c<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], cin: W, w: usize, want_carry: bool) -> (Vec<W>, W) {
    let mut carry = cin;
    let mut out = Vec::with_capacity(w);
    for i in 0..w {
        let (x, y) = (bit(a, i), bit(b, i));
        let last = i + 1 == w && !want_carry;
        if carry == FALSE_WIRE {
            out.push(xor(c, x, y));
            if !last { carry = and(c, x, y); }
        } else {
            let t1 = xor(c, x, carry);
            let t2 = xor(c, y, carry);
            out.push(xor(c, x, t2));
            if !last {
                let t = and(c, t1, t2);
                carry = xor(c, carry, t);
            }
        }
    }
    (out, carry)
}
/// a + b mod 2^w.
pub fn add<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], w: usize) -> Vec<W> {
    add_c(c, a, b, FALSE_WIRE, w, false).0
}
/// (a - b mod 2^w, 1 iff a >= b).
pub fn sub<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], w: usize) -> (Vec<W>, W) {
    let nb: Vec<W> = (0..w).map(|i| not(c, bit(b, i))).collect();
    let a: Vec<W> = (0..w).map(|i| bit(a, i)).collect();
    add_c(c, &a, &nb, TRUE_WIRE, w, true)
}
/// Subtract constant k from r (w bits) if r >= k.
pub fn cond_sub_const<C: CircuitContext>(c: &mut C, r: &[W], k: u128, w: usize) -> Vec<W> {
    let kb = const_bits(k, w);
    let (s, ge) = sub(c, r, &kb, w);
    (0..w).map(|i| mux(c, ge, bit(r, i), s[i])).collect()
}

// ---------------------------------------------------------------- 32-bit words
pub fn rotr(x: &[W], n: usize) -> Vec<W> { (0..32).map(|i| x[(i + n) % 32]).collect() }
pub fn shr(x: &[W], n: usize) -> Vec<W> { (0..32).map(|i| if i + n < 32 { x[i + n] } else { FALSE_WIRE }).collect() }
pub fn xor_w<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
    a.iter().zip(b).map(|(&x, &y)| xor(c, x, y)).collect()
}
pub fn add32<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> Vec<W> { add(c, a, b, 32) }
pub fn const32(v: u32) -> Vec<W> { const_bits(v as u128, 32) }

// ---------------------------------------------------------------- SHA-256
pub const SHA_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Input: 8 chaining words then 16 block words (32 bits each, LE bit order within a word; word values
/// as in FIPS 180-4). Output: 8 words, the new chaining value (input state + compressed state).
pub fn sha256_compress<C: CircuitContext>(c: &mut C, inp: &[W]) -> Vec<W> {
    assert_eq!(inp.len(), 24 * 32);
    let word = |i: usize| inp[32 * i..32 * i + 32].to_vec();
    let cv: Vec<Vec<W>> = (0..8).map(word).collect();
    let mut w: Vec<Vec<W>> = (8..24).map(word).collect();
    for t in 16..64 {
        let (x15, x2) = (w[t - 15].clone(), w[t - 2].clone());
        let s0 = { let a = xor_w(c, &rotr(&x15, 7), &rotr(&x15, 18)); xor_w(c, &a, &shr(&x15, 3)) };
        let s1 = { let a = xor_w(c, &rotr(&x2, 17), &rotr(&x2, 19)); xor_w(c, &a, &shr(&x2, 10)) };
        let a = add32(c, &s1, &w[t - 7]);
        let b = add32(c, &s0, &w[t - 16]);
        let n = add32(c, &a, &b);
        w.push(n);
    }
    let mut v = cv.clone();
    for t in 0..64 {
        let (a, b, cc, d, e, f, g, h) = (
            v[0].clone(), v[1].clone(), v[2].clone(), v[3].clone(),
            v[4].clone(), v[5].clone(), v[6].clone(), v[7].clone(),
        );
        let s1 = { let x = xor_w(c, &rotr(&e, 6), &rotr(&e, 11)); xor_w(c, &x, &rotr(&e, 25)) };
        // Ch = g ^ (e & (f ^ g))
        let fg = xor_w(c, &f, &g);
        let ch: Vec<W> = (0..32).map(|i| { let t = and(c, e[i], fg[i]); xor(c, g[i], t) }).collect();
        let s0 = { let x = xor_w(c, &rotr(&a, 2), &rotr(&a, 13)); xor_w(c, &x, &rotr(&a, 22)) };
        // Maj = a ^ ((a ^ b) & (a ^ c))
        let ab = xor_w(c, &a, &b);
        let ac = xor_w(c, &a, &cc);
        let maj: Vec<W> = (0..32).map(|i| { let t = and(c, ab[i], ac[i]); xor(c, a[i], t) }).collect();
        let t1 = add32(c, &h, &s1);
        let t1 = add32(c, &t1, &ch);
        let t1 = add32(c, &t1, &const32(SHA_K[t]));
        let t1 = add32(c, &t1, &w[t]);
        let t2 = add32(c, &s0, &maj);
        let ne = add32(c, &d, &t1);
        let na = add32(c, &t1, &t2);
        v = vec![na, a, b, cc, ne, e, f, g];
    }
    (0..8).flat_map(|i| add32(c, &cv[i], &v[i])).collect()
}

// ---------------------------------------------------------------- BLAKE3
pub const B3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
pub const B3_PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[allow(clippy::too_many_arguments)]
fn b3_g<C: CircuitContext>(c: &mut C, v: &mut [Vec<W>], a: usize, b: usize, cc: usize, d: usize, mx: &[W], my: &[W]) {
    let t = add32(c, &v[a], &v[b]);
    v[a] = add32(c, &t, mx);
    let t = xor_w(c, &v[d], &v[a]);
    v[d] = rotr(&t, 16);
    v[cc] = add32(c, &v[cc], &v[d]);
    let t = xor_w(c, &v[b], &v[cc]);
    v[b] = rotr(&t, 12);
    let t = add32(c, &v[a], &v[b]);
    v[a] = add32(c, &t, my);
    let t = xor_w(c, &v[d], &v[a]);
    v[d] = rotr(&t, 8);
    v[cc] = add32(c, &v[cc], &v[d]);
    let t = xor_w(c, &v[b], &v[cc]);
    v[b] = rotr(&t, 7);
}

/// Input: 8 chaining-value words then 16 message words. counter, block_len and flags are circuit
/// constants. Output: all 16 compression words (words 0..8 are the root hash when ROOT is set).
pub fn blake3_compress<C: CircuitContext>(c: &mut C, inp: &[W], counter: u64, block_len: u32, flags: u32) -> Vec<W> {
    assert_eq!(inp.len(), 24 * 32);
    let cv: Vec<Vec<W>> = (0..8).map(|i| inp[32 * i..32 * i + 32].to_vec()).collect();
    let mut m: Vec<Vec<W>> = (8..24).map(|i| inp[32 * i..32 * i + 32].to_vec()).collect();
    let mut v: Vec<Vec<W>> = cv.clone();
    for iv in &B3_IV[..4] { v.push(const32(*iv)); }
    v.push(const32(counter as u32));
    v.push(const32((counter >> 32) as u32));
    v.push(const32(block_len));
    v.push(const32(flags));
    for round in 0..7 {
        b3_g(c, &mut v, 0, 4, 8, 12, &m[0], &m[1]);
        b3_g(c, &mut v, 1, 5, 9, 13, &m[2], &m[3]);
        b3_g(c, &mut v, 2, 6, 10, 14, &m[4], &m[5]);
        b3_g(c, &mut v, 3, 7, 11, 15, &m[6], &m[7]);
        b3_g(c, &mut v, 0, 5, 10, 15, &m[8], &m[9]);
        b3_g(c, &mut v, 1, 6, 11, 12, &m[10], &m[11]);
        b3_g(c, &mut v, 2, 7, 8, 13, &m[12], &m[13]);
        b3_g(c, &mut v, 3, 4, 9, 14, &m[14], &m[15]);
        if round < 6 { m = (0..16).map(|i| m[B3_PERM[i]].clone()).collect(); }
    }
    let mut out = Vec::new();
    for i in 0..8 { out.extend(xor_w(c, &v[i], &v[i + 8])); }
    for i in 0..8 { out.extend(xor_w(c, &v[i + 8], &cv[i])); }
    out
}

// ---------------------------------------------------------------- prime fields
#[derive(Clone, Copy, Debug)]
pub struct Field { pub p: u64, pub k: usize, pub w_ext: u64 }
/// p = 2^31 - 2^24 + 1, extension X^4 - 3.
pub const KOALA: Field = Field { p: (1 << 31) - (1 << 24) + 1, k: 24, w_ext: 3 };
/// p = 2^31 - 2^27 + 1, extension X^4 - 11.
pub const BABY: Field = Field { p: (1 << 31) - (1 << 27) + 1, k: 27, w_ext: 11 };

impl Field {
    /// Barrett constant floor(2^62 / p).
    pub fn mu(&self) -> u64 { ((1u128 << 62) / self.p as u128) as u64 }

    /// Native model of the circuit algorithm: (result, number of correction subtractions taken).
    pub fn barrett_native(&self, x: u128) -> (u64, u32) {
        let q = ((x >> 30) * self.mu() as u128) >> 32;
        let mut r = x - q * self.p as u128;
        let mut n = 0;
        for j in (0..2).rev() {
            let k = (self.p as u128) << j;
            if r >= k { r -= k; n += 1; }
        }
        (r as u64, n)
    }

    /// 62-bit product -> canonical 31-bit residue. Barrett with q_est in [q-2, q], then two
    /// conditional subtractions (2p, p). Constant-multiplier adds fold against zero bits.
    pub fn reduce62<C: CircuitContext>(&self, c: &mut C, x: &[W]) -> Vec<W> {
        assert_eq!(x.len(), 62);
        let xh = &x[30..62]; // 32 bits
        let mu = self.mu() as u128;
        let mut acc: Vec<W> = vec![FALSE_WIRE; 64];
        for i in 0..32 {
            if (mu >> i) & 1 == 1 {
                let slice = acc[i..i + 32].to_vec();
                let (s, cy) = add_c(c, &slice, xh, FALSE_WIRE, 32, true);
                acc[i..i + 32].copy_from_slice(&s);
                acc[i + 32] = cy;
            }
        }
        let q = acc[32..63].to_vec(); // 31 bits
        // r = x - q*p mod 2^34 with p = 2^31 - 2^k + 1:  r = x + (q<<k) - (q<<31) - q
        let qk: Vec<W> = (0..34).map(|i| if i >= self.k && i - self.k < 31 { q[i - self.k] } else { FALSE_WIRE }).collect();
        let t1 = add(c, &x[..34], &qk, 34);
        let (hi, _) = sub(c, &t1[31..34], &q[..3], 3);
        let mut t2 = t1[..31].to_vec();
        t2.extend(hi);
        let (t3, _) = sub(c, &t2, &q, 34);
        let r = t3[..33].to_vec();
        let r = cond_sub_const(c, &r, (self.p as u128) << 1, 33);
        let r = cond_sub_const(c, &r, self.p as u128, 33);
        r[..31].to_vec()
    }

    pub fn mul31<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
        let aw = BigIntWires::from_bits(a.iter().copied());
        let bw = BigIntWires::from_bits(b.iter().copied());
        mul(c, &aw, &bw).bits[..62].to_vec()
    }
    pub fn mul31_naive<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
        let aw = BigIntWires::from_bits(a.iter().copied());
        let bw = BigIntWires::from_bits(b.iter().copied());
        mul_naive(c, &aw, &bw).bits[..62].to_vec()
    }
    pub fn mul_mod<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
        let x = self.mul31(c, a, b);
        self.reduce62(c, &x)
    }
    pub fn add_mod<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
        let s = add(c, a, b, 32);
        cond_sub_const(c, &s, self.p as u128, 32)[..31].to_vec()
    }
    /// m*a mod p for a small constant m: shift-and-add, then binary conditional subtraction of p<<j.
    pub fn mul_small<C: CircuitContext>(&self, c: &mut C, a: &[W], m: u64) -> Vec<W> {
        let nb = 64 - m.leading_zeros() as usize;
        let w = 31 + nb;
        let mut acc: Option<Vec<W>> = None;
        for i in 0..nb {
            if (m >> i) & 1 == 1 {
                let sh: Vec<W> = (0..w).map(|j| if j >= i && j - i < 31 { a[j - i] } else { FALSE_WIRE }).collect();
                acc = Some(match acc { None => sh, Some(x) => add(c, &x, &sh, w) });
            }
        }
        let mut r = acc.unwrap();
        let top = (64 - (m - 1).leading_zeros()) as usize; // ceil(log2 m); s <= m(p-1) < 2^top * p
        for j in (0..top).rev() {
            r = cond_sub_const(c, &r, (self.p as u128) << j, w);
        }
        r[..31].to_vec()
    }

    /// Schoolbook product in F[X]/(X^4 - W): 16 mul_mod, 12 add_mod, 3 mul_small(W).
    pub fn ext4_mul<C: CircuitContext>(&self, c: &mut C, a: &[Vec<W>], b: &[Vec<W>]) -> Vec<Vec<W>> {
        let mut prod: Vec<Vec<Vec<W>>> = Vec::new();
        for j in 0..4 {
            let mut row = Vec::new();
            for l in 0..4 { row.push(self.mul_mod(c, &a[j], &b[l])); }
            prod.push(row);
        }
        let mut out = Vec::new();
        for i in 0..4 {
            let mut direct: Option<Vec<W>> = None;
            let mut wrapped: Option<Vec<W>> = None;
            for j in 0..4 {
                for l in 0..4 {
                    let t = prod[j][l].clone();
                    if j + l == i {
                        direct = Some(match direct { None => t, Some(x) => self.add_mod(c, &x, &t) });
                    } else if j + l == i + 4 {
                        wrapped = Some(match wrapped { None => t, Some(x) => self.add_mod(c, &x, &t) });
                    }
                }
            }
            let d = direct.unwrap();
            out.push(match wrapped {
                None => d,
                Some(wv) => {
                    let wm = self.mul_small(c, &wv, self.w_ext);
                    self.add_mod(c, &d, &wm)
                }
            });
        }
        out
    }
}
