//! Compact Boolean gate primitives (Free-XOR folding + SHA-256 + bounded/255-bit modular gadgets).

use garbled_snark_verifier::{
    circuit::{FALSE_WIRE, TRUE_WIRE},
    CircuitContext, Gate, WireId,
};

pub type W = WireId;

pub fn xor<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    if a == FALSE_WIRE {
        return b;
    }
    if b == FALSE_WIRE {
        return a;
    }
    if a == b {
        return FALSE_WIRE;
    }
    let o = c.issue_wire();
    c.add_gate(Gate::xor(a, b, o));
    o
}

pub fn not<C: CircuitContext>(c: &mut C, a: W) -> W {
    if a == FALSE_WIRE {
        return TRUE_WIRE;
    }
    if a == TRUE_WIRE {
        return FALSE_WIRE;
    }
    xor(c, a, TRUE_WIRE)
}

pub fn and<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    if a == FALSE_WIRE || b == FALSE_WIRE {
        return FALSE_WIRE;
    }
    if a == TRUE_WIRE {
        return b;
    }
    if b == TRUE_WIRE {
        return a;
    }
    if a == b {
        return a;
    }
    let o = c.issue_wire();
    c.add_gate(Gate::and(a, b, o));
    o
}

pub fn or<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    let na = not(c, a);
    let nb = not(c, b);
    let both_false = and(c, na, nb);
    not(c, both_false)
}

/// Returns `a` when `sel == 0` and `b` when `sel == 1` (1 non-free gate).
pub fn mux<C: CircuitContext>(c: &mut C, sel: W, a: W, b: W) -> W {
    let d = xor(c, a, b);
    let t = and(c, sel, d);
    xor(c, a, t)
}

pub fn mux_vec<C: CircuitContext>(c: &mut C, sel: W, a: &[W], b: &[W]) -> Vec<W> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(&x, &y)| mux(c, sel, x, y)).collect()
}

pub fn eq_bit<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    let diff = xor(c, a, b);
    not(c, diff)
}

pub fn eq_vec<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> W {
    assert_eq!(a.len(), b.len());
    let mut acc = TRUE_WIRE;
    for (&x, &y) in a.iter().zip(b) {
        let eq = eq_bit(c, x, y);
        acc = and(c, acc, eq);
    }
    acc
}

pub fn all_true<C: CircuitContext>(c: &mut C, xs: &[W]) -> W {
    let mut acc = TRUE_WIRE;
    for &x in xs {
        acc = and(c, acc, x);
    }
    acc
}

pub fn const_bits_le(val: u128, width: usize) -> Vec<W> {
    (0..width)
        .map(|i| {
            if i < 128 && ((val >> i) & 1 == 1) {
                TRUE_WIRE
            } else {
                FALSE_WIRE
            }
        })
        .collect()
}

pub fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .collect()
}

pub fn const_bytes_le(bytes: &[u8]) -> Vec<W> {
    bytes_to_bits_le(bytes)
        .into_iter()
        .map(|b| if b { TRUE_WIRE } else { FALSE_WIRE })
        .collect()
}

pub fn add_carry<C: CircuitContext>(
    c: &mut C,
    a: &[W],
    b: &[W],
    cin: W,
    width: usize,
    want_carry: bool,
) -> (Vec<W>, W) {
    let mut carry = cin;
    let mut out = Vec::with_capacity(width);
    for i in 0..width {
        let x = a.get(i).copied().unwrap_or(FALSE_WIRE);
        let y = b.get(i).copied().unwrap_or(FALSE_WIRE);
        let last = i + 1 == width && !want_carry;
        if carry == FALSE_WIRE {
            out.push(xor(c, x, y));
            if !last {
                carry = and(c, x, y);
            }
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

pub fn add<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], width: usize) -> Vec<W> {
    add_carry(c, a, b, FALSE_WIRE, width, false).0
}

/// Returns `(a - b mod 2^width, ge)` where `ge == 1` iff `a >= b`.
pub fn sub<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], width: usize) -> (Vec<W>, W) {
    let nb: Vec<W> = (0..width)
        .map(|i| not(c, b.get(i).copied().unwrap_or(FALSE_WIRE)))
        .collect();
    let aw: Vec<W> = (0..width)
        .map(|i| a.get(i).copied().unwrap_or(FALSE_WIRE))
        .collect();
    add_carry(c, &aw, &nb, TRUE_WIRE, width, true)
}

/// Schoolbook unsigned multiplication producing `2 * width` bits.
pub fn mul_unsigned<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
    let n = a.len();
    assert_eq!(n, b.len());
    let mut acc = vec![FALSE_WIRE; 2 * n];
    for (i, &bi) in b.iter().enumerate() {
        let partial: Vec<W> = a.iter().map(|&aj| and(c, aj, bi)).collect();
        let mut shifted = vec![FALSE_WIRE; 2 * n];
        shifted[i..i + n].copy_from_slice(&partial);
        acc = add(c, &acc, &shifted, 2 * n);
    }
    acc
}

/// Modular addition `(a + b) mod p` assuming `a < p` and `b < p`.
pub fn add_mod<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], p_bits: &[W]) -> Vec<W> {
    let n = p_bits.len();
    let (sum, carry) = add_carry(c, a, b, FALSE_WIRE, n, true);
    let mut sum_ext = sum.clone();
    sum_ext.push(carry);
    let mut p_ext = p_bits.to_vec();
    p_ext.push(FALSE_WIRE);
    let (reduced, ge) = sub(c, &sum_ext, &p_ext, n + 1);
    mux_vec(c, ge, &sum, &reduced[..n])
}

/// Modular subtraction `(a - b) mod p` assuming `a < p` and `b < p`.
pub fn sub_mod<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], p_bits: &[W]) -> Vec<W> {
    let n = p_bits.len();
    let (diff, ge) = sub(c, a, b, n);
    let wrapped = add(c, &diff, p_bits, n);
    mux_vec(c, ge, &wrapped, &diff)
}

/// Witness-assisted modular multiplication: checks `q < p`, `r < p`? No: checks `a * b == q * p + r`
/// over exact `2 * n + 1` integer bits AND `r < p`!
/// Notice: for `n`-bit prime `p`, checking `a * b = q * p + r` as exact `2 * n`-bit integers (with no overflow)
/// and `r < p` reduces `n`-bit modular multiplication to 2 unsigned multiplications without division!
pub fn check_mul_mod_witness<C: CircuitContext>(
    c: &mut C,
    a: &[W],
    b: &[W],
    q: &[W],
    r: &[W],
    p_bits: &[W],
) -> W {
    let n = p_bits.len();
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);
    assert_eq!(q.len(), n);
    assert_eq!(r.len(), n);

    let (_, ge_r_p) = sub(c, r, p_bits, n);
    let r_canonical = not(c, ge_r_p);

    let lhs = mul_unsigned(c, a, b);
    let qp = mul_unsigned(c, q, p_bits);
    let mut r_ext = vec![FALSE_WIRE; 2 * n];
    r_ext[..n].copy_from_slice(r);
    let (rhs, carry) = add_carry(c, &qp, &r_ext, FALSE_WIRE, 2 * n, true);
    let no_overflow = not(c, carry);
    let eq = eq_vec(c, &lhs, &rhs);
    let ok1 = and(c, r_canonical, no_overflow);
    and(c, ok1, eq)
}

// ---------------------------------------------------------------- SHA-256 compression
const SHA_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn rotr32(x: &[W], n: usize) -> Vec<W> {
    (0..32).map(|i| x[(i + n) % 32]).collect()
}

fn shr32(x: &[W], n: usize) -> Vec<W> {
    (0..32)
        .map(|i| if i + n < 32 { x[i + n] } else { FALSE_WIRE })
        .collect()
}

fn xor32<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
    a.iter().zip(b).map(|(&x, &y)| xor(c, x, y)).collect()
}

fn ch32<C: CircuitContext>(c: &mut C, x: &[W], y: &[W], z: &[W]) -> Vec<W> {
    (0..32).map(|i| mux(c, x[i], z[i], y[i])).collect()
}

fn maj32<C: CircuitContext>(c: &mut C, x: &[W], y: &[W], z: &[W]) -> Vec<W> {
    (0..32)
        .map(|i| {
            let xy = xor(c, x[i], y[i]);
            let xz = xor(c, x[i], z[i]);
            let t = and(c, xy, xz);
            xor(c, x[i], t)
        })
        .collect()
}

/// FIPS 180-4 SHA-256 compression on 8 chaining words + 16 message words (each 32-bit LE bit order).
pub fn sha256_compress_words<C: CircuitContext>(
    c: &mut C,
    cv: &[Vec<W>; 8],
    msg_words: &[Vec<W>; 16],
) -> [Vec<W>; 8] {
    let mut w: Vec<Vec<W>> = msg_words.to_vec();
    for t in 16..64 {
        let s0 = {
            let a = xor32(c, &rotr32(&w[t - 15], 7), &rotr32(&w[t - 15], 18));
            xor32(c, &a, &shr32(&w[t - 15], 3))
        };
        let s1 = {
            let a = xor32(c, &rotr32(&w[t - 2], 17), &rotr32(&w[t - 2], 19));
            xor32(c, &a, &shr32(&w[t - 2], 10))
        };
        let a = add(c, &s1, &w[t - 7], 32);
        let b = add(c, &s0, &w[t - 16], 32);
        w.push(add(c, &a, &b, 32));
    }
    let mut v = cv.clone();
    for t in 0..64 {
        let s1 = {
            let a = xor32(c, &rotr32(&v[4], 6), &rotr32(&v[4], 11));
            xor32(c, &a, &rotr32(&v[4], 25))
        };
        let ch = ch32(c, &v[4], &v[5], &v[6]);
        let kw = const_bits_le(SHA_K[t] as u128, 32);
        let t1 = {
            let a = add(c, &v[7], &s1, 32);
            let b = add(c, &ch, &kw, 32);
            let d = add(c, &a, &b, 32);
            add(c, &d, &w[t], 32)
        };
        let s0 = {
            let a = xor32(c, &rotr32(&v[0], 2), &rotr32(&v[0], 13));
            xor32(c, &a, &rotr32(&v[0], 22))
        };
        let maj = maj32(c, &v[0], &v[1], &v[2]);
        let t2 = add(c, &s0, &maj, 32);
        v[7] = v[6].clone();
        v[6] = v[5].clone();
        v[5] = v[4].clone();
        v[4] = add(c, &v[3], &t1, 32);
        v[3] = v[2].clone();
        v[2] = v[1].clone();
        v[1] = v[0].clone();
        v[0] = add(c, &t1, &t2, 32);
    }
    std::array::from_fn(|i| add(c, &cv[i], &v[i], 32))
}

/// Converts a byte slice (`len` bytes, each 8 bits LE) into SHA-256 big-endian 32-bit words (each 32 bits LE).
fn bytes_bits_to_sha_words(byte_bits: &[W]) -> Vec<Vec<W>> {
    assert_eq!(byte_bits.len() % 32, 0);
    byte_bits
        .chunks_exact(32)
        .map(|four_bytes| {
            // Word value is `(b0 << 24) | (b1 << 16) | (b2 << 8) | b3`, so LE bits are `[b3, b2, b1, b0]`.
            let mut word = Vec::with_capacity(32);
            word.extend_from_slice(&four_bytes[24..32]);
            word.extend_from_slice(&four_bytes[16..24]);
            word.extend_from_slice(&four_bytes[8..16]);
            word.extend_from_slice(&four_bytes[0..8]);
            word
        })
        .collect()
}

fn sha_words_to_bytes_bits(words: &[Vec<W>; 8]) -> Vec<W> {
    let mut out = Vec::with_capacity(256);
    for w in words {
        out.extend_from_slice(&w[24..32]);
        out.extend_from_slice(&w[16..24]);
        out.extend_from_slice(&w[8..16]);
        out.extend_from_slice(&w[0..8]);
    }
    out
}

/// Hashes an exact `N`-byte message (`8 * N` bits, each byte 8 bits LE) using FIPS 180-4 SHA-256.
pub fn sha256_bytes<C: CircuitContext>(c: &mut C, msg_bits: &[W]) -> Vec<W> {
    assert_eq!(msg_bits.len() % 8, 0);
    let byte_len = msg_bits.len() / 8;
    let bit_len = (byte_len as u64) * 8;
    let mut padded = msg_bits.to_vec();
    padded.extend_from_slice(&const_bytes_le(&[0x80]));
    while (padded.len() / 8) % 64 != 56 {
        padded.extend_from_slice(&const_bytes_le(&[0x00]));
    }
    padded.extend_from_slice(&const_bytes_le(&bit_len.to_be_bytes()));

    let mut cv: [Vec<W>; 8] = std::array::from_fn(|i| const_bits_le(SHA_IV[i] as u128, 32));
    for block in padded.chunks_exact(512) {
        let words_vec = bytes_bits_to_sha_words(block);
        let words: [Vec<W>; 16] = words_vec.try_into().unwrap();
        cv = sha256_compress_words(c, &cv, &words);
    }
    sha_words_to_bytes_bits(&cv)
}
