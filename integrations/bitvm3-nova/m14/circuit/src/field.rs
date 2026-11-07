//! KoalaBear, p = 2^31 - 2^24 + 1. An element is 31 little-endian bit wires. Every gadget returns a
//! canonical element (< p) when its inputs are canonical; `is_canonical` checks circuit inputs.
//!
//! Multiplications by an operand whose wires are all constants take the constant path
//! (`mul_const`), so the gate count of a circuit reflects which operands are compile-time constants.
use garbled_snark_verifier::{
    CircuitContext,
    circuit::{FALSE_WIRE, TRUE_WIRE},
};
use m12_gates::{self as g, KOALA, W};

pub const P: u32 = 0x7f00_0001;
pub const BITS: usize = 31;

#[derive(Clone, Debug)]
pub struct Fe(pub Vec<W>);

impl Fe {
    pub fn constant(v: u32) -> Fe {
        assert!(v < P, "constant {v} is not canonical");
        Fe(g::const_bits(v as u128, BITS))
    }
    pub fn zero() -> Fe {
        Fe::constant(0)
    }
    pub fn one() -> Fe {
        Fe::constant(1)
    }
    pub fn from_wires(w: &[W]) -> Fe {
        assert_eq!(w.len(), BITS);
        Fe(w.to_vec())
    }
    /// The value, when every wire is a constant.
    pub fn as_constant(&self) -> Option<u32> {
        let mut v = 0u32;
        for (i, &w) in self.0.iter().enumerate() {
            if w == TRUE_WIRE {
                v |= 1 << i;
            } else if w != FALSE_WIRE {
                return None;
            }
        }
        Some(v)
    }
    /// `as_canonical_u32().to_le_bytes()` as 32 bit wires (byte 0 bit 0 first). Wiring only.
    pub fn le_bits32(&self) -> Vec<W> {
        let mut v = self.0.clone();
        v.push(FALSE_WIRE);
        v
    }
}

// ------------------------------------------------------------------ native helpers
pub const fn mulp(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P as u64) as u32
}
pub const fn addp(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) % P as u64) as u32
}
pub const fn subp(a: u32, b: u32) -> u32 {
    ((a as u64 + P as u64 - b as u64) % P as u64) as u32
}
pub const fn powp(a: u32, mut e: u64) -> u32 {
    let (mut base, mut acc) = (a, 1u32);
    while e > 0 {
        if e & 1 == 1 {
            acc = mulp(acc, base);
        }
        base = mulp(base, base);
        e >>= 1;
    }
    acc
}

// ------------------------------------------------------------------ boolean helpers
pub fn or<C: CircuitContext>(c: &mut C, a: W, b: W) -> W {
    let na = g::not(c, a);
    let nb = g::not(c, b);
    let t = g::and(c, na, nb);
    g::not(c, t)
}
/// OR of all wires (FALSE for none): one gate per non-constant input beyond the first.
pub fn or_all<C: CircuitContext>(c: &mut C, ws: &[W]) -> W {
    let mut layer: Vec<W> = ws.to_vec();
    if layer.is_empty() {
        return FALSE_WIRE;
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            next.push(if pair.len() == 2 && pair[0] != pair[1] { or(c, pair[0], pair[1]) } else { pair[0] });
        }
        layer = next;
    }
    layer[0]
}
pub fn and_all<C: CircuitContext>(c: &mut C, ws: &[W]) -> W {
    let mut layer: Vec<W> = ws.to_vec();
    if layer.is_empty() {
        return TRUE_WIRE;
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            next.push(if pair.len() == 2 && pair[0] != pair[1] { g::and(c, pair[0], pair[1]) } else { pair[0] });
        }
        layer = next;
    }
    layer[0]
}

// ------------------------------------------------------------------ gadgets
/// 1 iff the 31-bit input is < p. x >= p iff bits 24..31 are all set and bits 0..24 are not all
/// zero (p = 0x7f000001).
pub fn is_canonical<C: CircuitContext>(c: &mut C, x: &[W]) -> W {
    assert_eq!(x.len(), BITS);
    let top = and_all(c, &x[24..31]);
    let low = or_all(c, &x[..24]);
    let ge = g::and(c, top, low);
    g::not(c, ge)
}

/// a + b. Adding an element to itself is `double`: the ripple adder on two identical operands
/// would build AND gates whose two inputs are one wire.
pub fn add<C: CircuitContext>(c: &mut C, a: &Fe, b: &Fe) -> Fe {
    if a.0 == b.0 {
        return double(c, a);
    }
    // Adding constant 0 is the identity. The reduction of 0 + b would also build an AND of a
    // carry and its own negation (ExecuteMode counts it, the garbler emits no ciphertext for it).
    if a.as_constant() == Some(0) {
        return b.clone();
    }
    if b.as_constant() == Some(0) {
        return a.clone();
    }
    Fe(KOALA.add_mod(c, &a.0, &b.0))
}

/// a - b: the 31-bit difference, plus p when it borrowed.
pub fn sub<C: CircuitContext>(c: &mut C, a: &Fe, b: &Fe) -> Fe {
    if a.0 == b.0 {
        return Fe::zero();
    }
    let (d, ge) = g::sub(c, &a.0, &b.0, BITS);
    let dp = g::add(c, &d, &g::const_bits(P as u128, BITS), BITS);
    Fe((0..BITS).map(|i| g::mux(c, ge, dp[i], d[i])).collect())
}

pub fn neg<C: CircuitContext>(c: &mut C, a: &Fe) -> Fe {
    sub(c, &Fe::zero(), a)
}

pub fn double<C: CircuitContext>(c: &mut C, a: &Fe) -> Fe {
    let s: Vec<W> = std::iter::once(FALSE_WIRE).chain(a.0.iter().copied()).collect();
    Fe(g::cond_sub_const(c, &s, P as u128, 32)[..BITS].to_vec())
}

/// a / 2: a >> 1, plus (p + 1) / 2 when a is odd. No reduction: the sum is (a + p) / 2 < p.
pub fn halve<C: CircuitContext>(c: &mut C, a: &Fe) -> Fe {
    let shr: Vec<W> = (1..BITS).map(|i| a.0[i]).chain(std::iter::once(FALSE_WIRE)).collect();
    let half = (P + 1) / 2;
    let add_bits: Vec<W> = (0..BITS).map(|i| if (half >> i) & 1 == 1 { a.0[0] } else { FALSE_WIRE }).collect();
    Fe(g::add(c, &shr, &add_bits, BITS))
}

/// a * b as an unreduced 62-bit integer; a constant operand takes the shift-and-add path.
pub fn mul_raw<C: CircuitContext>(c: &mut C, a: &Fe, b: &Fe) -> Vec<W> {
    match (a.as_constant(), b.as_constant()) {
        (Some(x), Some(y)) => g::const_bits(x as u128 * y as u128, 62),
        (Some(k), None) => raw_const(c, &b.0, k),
        (None, Some(k)) => raw_const(c, &a.0, k),
        (None, None) => KOALA.mul31(c, &a.0, &b.0),
    }
}

fn raw_const<C: CircuitContext>(c: &mut C, a: &[W], k: u32) -> Vec<W> {
    let mut acc: Option<Vec<W>> = None;
    for i in 0..BITS {
        if (k >> i) & 1 == 1 {
            let sh: Vec<W> = (0..62).map(|j| if j >= i && j - i < BITS { a[j - i] } else { FALSE_WIRE }).collect();
            acc = Some(match acc {
                None => sh,
                Some(x) => g::add(c, &x, &sh, 62),
            });
        }
    }
    acc.unwrap_or_else(|| vec![FALSE_WIRE; 62])
}

/// Canonical residue of a 62-bit integer below p^2 (Barrett, M12's measured reduction).
pub fn reduce62<C: CircuitContext>(c: &mut C, x: &[W]) -> Fe {
    assert_eq!(x.len(), 62);
    Fe(KOALA.reduce62(c, x))
}

/// Canonical residue of an integer of up to 69 bits. M12's Barrett reduction (`reduce62`) is exact
/// only below p^2 (about 2^61.98), so the low 61 bits go through it and the high bits select the
/// constant hi * 2^61 mod p (a function of at most 8 bits, built from its algebraic normal form:
/// one AND per monomial of degree >= 2), then one modular addition.
pub fn reduce_wide<C: CircuitContext>(c: &mut C, x: &[W]) -> Fe {
    assert!(x.len() <= 69);
    let mut lo: Vec<W> = x.iter().take(61).copied().collect();
    lo.resize(62, FALSE_WIRE);
    let r = reduce62(c, &lo);
    if x.len() <= 61 {
        return r;
    }
    let hi = &x[61..];
    let k = hi.len();
    let two61 = powp(2, 61);
    let table: Vec<u32> = (0..(1u32 << k)).map(|h| mulp(h % P, two61)).collect();
    let sel = const_table(c, hi, &table);
    add(c, &r, &sel)
}

/// Wires of table[index] for a k-bit wire index and a table of 2^k canonical constants.
/// Per output bit, the ANF coefficients come from the Moebius transform of that bit's truth table;
/// each monomial over >= 2 index bits is one AND, shared by all output bits.
pub fn const_table<C: CircuitContext>(c: &mut C, idx: &[W], table: &[u32]) -> Fe {
    let k = idx.len();
    assert_eq!(table.len(), 1 << k);
    // monomial wires: mono[m] = AND of idx bits in mask m (mono[0] = TRUE)
    let mut mono: Vec<Option<W>> = vec![None; 1 << k];
    mono[0] = Some(TRUE_WIRE);
    let mut out = Vec::with_capacity(BITS);
    for bit in 0..BITS {
        let mut anf: Vec<u8> = table.iter().map(|v| ((v >> bit) & 1) as u8).collect();
        for i in 0..k {
            for m in 0..(1usize << k) {
                if m & (1 << i) != 0 {
                    anf[m] ^= anf[m ^ (1 << i)];
                }
            }
        }
        let mut acc = FALSE_WIRE;
        for m in 0..(1usize << k) {
            if anf[m] == 1 {
                let w = monomial(c, idx, &mut mono, m);
                acc = g::xor(c, acc, w);
            }
        }
        out.push(acc);
    }
    Fe(out)
}

fn monomial<C: CircuitContext>(c: &mut C, idx: &[W], mono: &mut [Option<W>], m: usize) -> W {
    if let Some(w) = mono[m] {
        return w;
    }
    let low = m.trailing_zeros() as usize;
    let rest = m & (m - 1);
    let w = if rest == 0 {
        idx[low]
    } else {
        let r = monomial(c, idx, mono, rest);
        g::and(c, r, idx[low])
    };
    mono[m] = Some(w);
    w
}

pub fn mul<C: CircuitContext>(c: &mut C, a: &Fe, b: &Fe) -> Fe {
    match (a.as_constant(), b.as_constant()) {
        (Some(x), Some(y)) => Fe::constant(mulp(x, y)),
        (Some(k), None) => mul_const(c, b, k),
        (None, Some(k)) => mul_const(c, a, k),
        (None, None) => Fe(KOALA.mul_mod(c, &a.0, &b.0)),
    }
}

pub fn square<C: CircuitContext>(c: &mut C, a: &Fe) -> Fe {
    mul(c, a, a)
}

/// k * a for a compile-time constant k: small constants (or p minus a small constant) by
/// shift-and-add with conditional subtractions; others by shift-and-add of k or p - k (fewer set
/// bits), Barrett reduction and, for p - k, a negation.
pub fn mul_const<C: CircuitContext>(c: &mut C, a: &Fe, k: u32) -> Fe {
    assert!(k < P);
    if let Some(v) = a.as_constant() {
        return Fe::constant(mulp(v, k));
    }
    match k {
        0 => return Fe::zero(),
        1 => return a.clone(),
        _ => {}
    }
    let nk = P - k;
    if nk == 1 {
        return neg(c, a);
    }
    if k < 256 {
        return Fe(KOALA.mul_small(c, &a.0, k as u64));
    }
    if nk < 256 {
        let t = Fe(KOALA.mul_small(c, &a.0, nk as u64));
        return neg(c, &t);
    }
    let (m, negate) = if nk.count_ones() < k.count_ones() { (nk, true) } else { (k, false) };
    let raw = raw_const(c, &a.0, m);
    let r = reduce62(c, &raw);
    if negate { neg(c, &r) } else { r }
}

pub fn is_zero<C: CircuitContext>(c: &mut C, a: &Fe) -> W {
    let nz = or_all(c, &a.0);
    g::not(c, nz)
}

pub fn eq<C: CircuitContext>(c: &mut C, a: &Fe, b: &Fe) -> W {
    let d: Vec<W> = (0..BITS).map(|i| g::xor(c, a.0[i], b.0[i])).collect();
    let nz = or_all(c, &d);
    g::not(c, nz)
}

/// s = 0 -> a, s = 1 -> b.
pub fn select<C: CircuitContext>(c: &mut C, s: W, a: &Fe, b: &Fe) -> Fe {
    Fe((0..BITS).map(|i| g::mux(c, s, a.0[i], b.0[i])).collect())
}

pub fn exp_power_of_2<C: CircuitContext>(c: &mut C, a: &Fe, n: usize) -> Fe {
    let mut r = a.clone();
    for _ in 0..n {
        r = square(c, &r);
    }
    r
}

/// a^e for a constant exponent, left-to-right square-and-multiply.
pub fn exp_const<C: CircuitContext>(c: &mut C, a: &Fe, e: u64) -> Fe {
    if e == 0 {
        return Fe::one();
    }
    let top = 63 - e.leading_zeros() as usize;
    let mut r = a.clone();
    for i in (0..top).rev() {
        r = square(c, &r);
        if (e >> i) & 1 == 1 {
            r = mul(c, &r, a);
        }
    }
    r
}

/// a^(p-2) with SP1's KoalaBear addition chain (29 squarings, 7 multiplications); 0 for a = 0.
/// The native `try_inverse` returns None for 0: callers that must reject 0 test `is_zero`.
pub fn inv<C: CircuitContext>(c: &mut C, a: &Fe) -> Fe {
    let p1 = a.clone();
    let p10 = square(c, &p1);
    let p11 = mul(c, &p10, &p1);
    let p1100 = exp_power_of_2(c, &p11, 2);
    let p1111 = mul(c, &p1100, &p11);
    let p110000 = exp_power_of_2(c, &p1100, 2);
    let p111111 = mul(c, &p110000, &p1111);
    let p1111110000 = exp_power_of_2(c, &p111111, 4);
    let p1111111111 = mul(c, &p1111110000, &p1111);
    let p11111101111 = mul(c, &p1111111111, &p1111110000);
    let p111111011110000000000 = exp_power_of_2(c, &p11111101111, 10);
    let p111111011111111111111 = mul(c, &p111111011110000000000, &p1111111111);
    let p1111110111111111111110000000000 = exp_power_of_2(c, &p111111011111111111111, 10);
    mul(c, &p1111110111111111111110000000000, &p1111111111)
}

/// base^idx for a constant base and an index given as little-endian bit wires: per index bit, a
/// constant multiplication by base^(2^i) and a select. Bit 0 selects between the constants 1 and base.
pub fn pow_const_base<C: CircuitContext>(c: &mut C, base: u32, idx: &[W]) -> Fe {
    if idx.is_empty() {
        return Fe::one();
    }
    let mut acc = select(c, idx[0], &Fe::one(), &Fe::constant(base));
    let mut gi = base;
    for &bit in &idx[1..] {
        gi = mulp(gi, gi);
        let m = mul_const(c, &acc, gi);
        acc = select(c, bit, &acc, &m);
    }
    acc
}
