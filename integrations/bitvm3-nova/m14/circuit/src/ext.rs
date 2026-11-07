//! Degree-4 extension F[X]/(X^4 - 3): SP1's `BinomialExtensionField<KoalaBear, 4>`.
//!
//! Products are reduced lazily: the 62-bit integer products of a coefficient are summed (with the
//! wrapped terms times 3) and reduced once, instead of reducing each of the 16 products.
use garbled_snark_verifier::CircuitContext;
use m12_gates::{self as g, W};

use crate::field::{self as f, Fe, P};

pub const W_EXT: u32 = 3;
/// W^((p - 1) / 4); X^p = DTH_ROOT * X.
pub const DTH_ROOT: u32 = f::powp(W_EXT, ((P - 1) / 4) as u64);

#[derive(Clone, Debug)]
pub struct Ext(pub [Fe; 4]);

impl Ext {
    pub fn constant(v: [u32; 4]) -> Ext {
        Ext(v.map(Fe::constant))
    }
    pub fn zero() -> Ext {
        Ext::constant([0; 4])
    }
    pub fn one() -> Ext {
        Ext::constant([1, 0, 0, 0])
    }
    pub fn from_base(a: &Fe) -> Ext {
        Ext([a.clone(), Fe::zero(), Fe::zero(), Fe::zero()])
    }
    pub fn as_constant(&self) -> Option<[u32; 4]> {
        let v: Vec<u32> = self.0.iter().map(|x| x.as_constant()).collect::<Option<_>>()?;
        Some([v[0], v[1], v[2], v[3]])
    }
    /// Coefficients in `as_base_slice` order, each as 4 little-endian bytes. Wiring only.
    pub fn le_bits(&self) -> Vec<W> {
        self.0.iter().flat_map(|x| x.le_bits32()).collect()
    }
}

// ------------------------------------------------------------------ native helpers
pub fn mul_native(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    let mut out = [0u32; 4];
    for j in 0..4 {
        for l in 0..4 {
            let t = f::mulp(a[j], b[l]);
            if j + l < 4 {
                out[j + l] = f::addp(out[j + l], t);
            } else {
                out[j + l - 4] = f::addp(out[j + l - 4], f::mulp(W_EXT, t));
            }
        }
    }
    out
}

// ------------------------------------------------------------------ gadgets
pub fn add<C: CircuitContext>(c: &mut C, a: &Ext, b: &Ext) -> Ext {
    Ext(std::array::from_fn(|i| f::add(c, &a.0[i], &b.0[i])))
}
pub fn sub<C: CircuitContext>(c: &mut C, a: &Ext, b: &Ext) -> Ext {
    Ext(std::array::from_fn(|i| f::sub(c, &a.0[i], &b.0[i])))
}
pub fn neg<C: CircuitContext>(c: &mut C, a: &Ext) -> Ext {
    Ext(std::array::from_fn(|i| f::neg(c, &a.0[i])))
}
pub fn mul_base<C: CircuitContext>(c: &mut C, a: &Ext, b: &Fe) -> Ext {
    Ext(std::array::from_fn(|i| f::mul(c, &a.0[i], b)))
}
pub fn add_base<C: CircuitContext>(c: &mut C, a: &Ext, b: &Fe) -> Ext {
    let mut r = a.clone();
    r.0[0] = f::add(c, &a.0[0], b);
    r
}

/// a + b with the carry kept: width max(|a|, |b|) + 1.
fn add_grow<C: CircuitContext>(c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
    let w = a.len().max(b.len());
    let (mut s, cy) = g::add_c(c, a, b, garbled_snark_verifier::circuit::FALSE_WIRE, w, true);
    s.push(cy);
    s
}

fn sum_grow<C: CircuitContext>(c: &mut C, terms: Vec<Vec<W>>) -> Option<Vec<W>> {
    let mut layer = terms;
    if layer.is_empty() {
        return None;
    }
    while layer.len() > 1 {
        let mut next = Vec::new();
        let mut it = layer.into_iter();
        while let Some(a) = it.next() {
            match it.next() {
                Some(b) => next.push(add_grow(c, &a, &b)),
                None => next.push(a),
            }
        }
        layer = next;
    }
    layer.pop()
}

/// Coefficient i of the product from unreduced products `raw[j][l]` (present for the pairs given):
/// sum(j+l=i) + 3 * sum(j+l=i+4), reduced once.
fn combine<C: CircuitContext>(c: &mut C, direct: Vec<Vec<W>>, wrapped: Vec<Vec<W>>) -> Fe {
    let d = sum_grow(c, direct);
    let w = sum_grow(c, wrapped);
    let total = match (d, w) {
        (None, None) => return Fe::zero(),
        (Some(d), None) => d,
        (d, Some(w)) => {
            // 3w = w + (w << 1)
            let w2: Vec<W> = std::iter::once(garbled_snark_verifier::circuit::FALSE_WIRE).chain(w.iter().copied()).collect();
            let w3 = add_grow(c, &w, &w2);
            match d {
                Some(d) => add_grow(c, &d, &w3),
                None => w3,
            }
        }
    };
    f::reduce_wide(c, &total)
}

pub fn mul<C: CircuitContext>(c: &mut C, a: &Ext, b: &Ext) -> Ext {
    if let (Some(x), Some(y)) = (a.as_constant(), b.as_constant()) {
        return Ext::constant(mul_native(x, y));
    }
    if let Some(k) = b.as_constant().or(a.as_constant()) {
        let v = if b.as_constant().is_some() { a } else { b };
        return mul_const(c, v, k);
    }
    let raw: Vec<Vec<Vec<W>>> = (0..4).map(|j| (0..4).map(|l| f::mul_raw(c, &a.0[j], &b.0[l])).collect()).collect();
    Ext(std::array::from_fn(|i| {
        let direct = (0..4).filter(|&j| i >= j).map(|j| raw[j][i - j].clone()).collect();
        let wrapped = (0..4).filter(|&j| i + 4 >= j && i + 4 - j < 4).map(|j| raw[j][i + 4 - j].clone()).collect();
        combine(c, direct, wrapped)
    }))
}

/// a * k for a constant k: each coefficient product by constant shift-and-add, lazily reduced.
pub fn mul_const<C: CircuitContext>(c: &mut C, a: &Ext, k: [u32; 4]) -> Ext {
    if k == [1, 0, 0, 0] {
        return a.clone();
    }
    if k[1..] == [0, 0, 0] {
        return Ext(std::array::from_fn(|i| f::mul_const(c, &a.0[i], k[0])));
    }
    let kf = Ext::constant(k);
    let raw: Vec<Vec<Option<Vec<W>>>> = (0..4)
        .map(|j| (0..4).map(|l| if k[l] == 0 { None } else { Some(f::mul_raw(c, &a.0[j], &kf.0[l])) }).collect())
        .collect();
    Ext(std::array::from_fn(|i| {
        let direct = (0..4).filter(|&j| i >= j).filter_map(|j| raw[j][i - j].clone()).collect();
        let wrapped = (0..4).filter(|&j| i + 4 >= j && i + 4 - j < 4).filter_map(|j| raw[j][i + 4 - j].clone()).collect();
        combine(c, direct, wrapped)
    }))
}

/// Square with the 6 cross products computed once and doubled by a shift: 10 integer products.
pub fn square<C: CircuitContext>(c: &mut C, a: &Ext) -> Ext {
    if let Some(x) = a.as_constant() {
        return Ext::constant(mul_native(x, x));
    }
    let mut raw: Vec<Vec<Option<Vec<W>>>> = vec![vec![None; 4]; 4];
    for j in 0..4 {
        for l in j..4 {
            let p = f::mul_raw(c, &a.0[j], &a.0[l]);
            raw[j][l] = Some(if j == l {
                p
            } else {
                std::iter::once(garbled_snark_verifier::circuit::FALSE_WIRE).chain(p).collect()
            });
        }
    }
    let term = |j: usize, l: usize| raw[j.min(l)][j.max(l)].clone().unwrap();
    Ext(std::array::from_fn(|i| {
        let direct: Vec<Vec<W>> = (0..4).filter(|&j| i >= j && j <= i - j).map(|j| term(j, i - j)).collect();
        let wrapped: Vec<Vec<W>> =
            (0..4).filter(|&j| i + 4 >= j && i + 4 - j < 4 && j <= i + 4 - j).map(|j| term(j, i + 4 - j)).collect();
        combine(c, direct, wrapped)
    }))
}

/// phi^k(a): coefficient i times DTH_ROOT^(k i).
pub fn frobenius_k<C: CircuitContext>(c: &mut C, a: &Ext, k: usize) -> Ext {
    let z = f::powp(DTH_ROOT, (k % 4) as u64);
    let mut zi = 1u32;
    Ext(std::array::from_fn(|i| {
        let r = f::mul_const(c, &a.0[i], zi);
        zi = f::mulp(zi, z);
        r
    }))
}

/// a^-1 as in p3's `frobenius_inv`: f = a^(p + p^2 + p^3), g = a * f in the base field,
/// result f * g^-1. 0 for a = 0 (the native inverse returns None; callers test `is_zero`).
pub fn inv<C: CircuitContext>(c: &mut C, a: &Ext) -> Ext {
    let mut fr = Ext::one();
    for _ in 1..4 {
        let t = mul(c, &fr, a);
        fr = frobenius_k(c, &t, 1);
    }
    // g = (a1 b3 + a2 b2 + a3 b1) * W + a0 b0, reduced once
    let wrapped: Vec<Vec<W>> = (1..4).map(|i| f::mul_raw(c, &a.0[i], &fr.0[4 - i])).collect();
    let direct = vec![f::mul_raw(c, &a.0[0], &fr.0[0])];
    let gv = combine(c, direct, wrapped);
    let gi = f::inv(c, &gv);
    mul_base(c, &fr, &gi)
}

pub fn is_zero<C: CircuitContext>(c: &mut C, a: &Ext) -> W {
    let all: Vec<W> = a.0.iter().flat_map(|x| x.0.iter().copied()).collect();
    let nz = f::or_all(c, &all);
    g::not(c, nz)
}

pub fn eq<C: CircuitContext>(c: &mut C, a: &Ext, b: &Ext) -> W {
    let d: Vec<W> =
        (0..4).flat_map(|i| (0..f::BITS).map(move |j| (i, j))).map(|(i, j)| g::xor(c, a.0[i].0[j], b.0[i].0[j])).collect();
    let nz = f::or_all(c, &d);
    g::not(c, nz)
}

/// s = 0 -> a, s = 1 -> b.
pub fn select<C: CircuitContext>(c: &mut C, s: W, a: &Ext, b: &Ext) -> Ext {
    Ext(std::array::from_fn(|i| f::select(c, s, &a.0[i], &b.0[i])))
}

pub fn exp_power_of_2<C: CircuitContext>(c: &mut C, a: &Ext, n: usize) -> Ext {
    let mut r = a.clone();
    for _ in 0..n {
        r = square(c, &r);
    }
    r
}
