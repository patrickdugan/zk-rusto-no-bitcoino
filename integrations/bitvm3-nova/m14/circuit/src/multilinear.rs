//! Multilinear helpers with `slop_multilinear`'s conventions: a point's first coordinate is the
//! most significant bit of a table index (`partial_lagrange` builds [v(1 - x), v x] per coordinate,
//! first coordinate outermost).
use garbled_snark_verifier::CircuitContext;
use m12_gates::{self as g, W};

use crate::ext::{self, Ext};

/// `partial_lagrange(point)`: the 2^n eq weights.
pub fn partial_lagrange<C: CircuitContext>(c: &mut C, point: &[Ext]) -> Vec<Ext> {
    let mut v = vec![Ext::one()];
    for x in point {
        let mut next = Vec::with_capacity(v.len() * 2);
        for val in &v {
            let p = ext::mul(c, val, x);
            next.push(ext::sub(c, val, &p));
            next.push(p);
        }
        v = next;
    }
    v
}

/// `Mle::blocking_eval_at`: the table's multilinear extension at `point`, by folding one
/// coordinate at a time (first coordinate = top half / bottom half).
pub fn mle_eval<C: CircuitContext>(c: &mut C, table: &[Ext], point: &[Ext]) -> Ext {
    assert_eq!(table.len(), 1 << point.len());
    let mut v = table.to_vec();
    for x in point {
        let h = v.len() / 2;
        v = (0..h)
            .map(|i| {
                let d = ext::sub(c, &v[h + i], &v[i]);
                let t = ext::mul(c, x, &d);
                ext::add(c, &v[i], &t)
            })
            .collect();
    }
    v.pop().unwrap()
}

/// `Mle::full_lagrange_eval`: prod (2 x y + 1 - x - y).
pub fn full_lagrange_eval<C: CircuitContext>(c: &mut C, p1: &[Ext], p2: &[Ext]) -> Ext {
    assert_eq!(p1.len(), p2.len());
    let mut acc = Ext::one();
    for (x, y) in p1.iter().zip(p2) {
        let xy = ext::mul(c, x, y);
        let two_xy = ext::add(c, &xy, &xy);
        let s = ext::add(c, x, y);
        let one_minus = ext::sub(c, &Ext::one(), &s);
        let term = ext::add(c, &two_xy, &one_minus);
        acc = ext::mul(c, &acc, &term);
    }
    acc
}

/// `full_geq(threshold, point)` for a constant 0/1 threshold, folded from the last coordinate:
/// acc <- ((1 - y)(1 - x) + y x) acc + y (1 - x).
pub fn full_geq<C: CircuitContext>(c: &mut C, threshold: &[u32], point: &[Ext]) -> Ext {
    assert_eq!(threshold.len(), point.len());
    let mut acc = Ext::one();
    for (&x, y) in threshold.iter().zip(point).rev() {
        acc = match x {
            0 => {
                let one_minus_y = ext::sub(c, &Ext::one(), y);
                let t = ext::mul(c, &one_minus_y, &acc);
                ext::add(c, &t, y)
            }
            1 => ext::mul(c, y, &acc),
            _ => panic!("threshold bit {x}"),
        };
    }
    acc
}

/// sum n_i / d_i as one fraction (N, D), combining pairs: (a/b + c/d) = (a d + c b) / (b d).
pub fn sum_fractions<C: CircuitContext>(c: &mut C, nums: &[Ext], dens: &[Ext]) -> (Ext, Ext) {
    assert_eq!(nums.len(), dens.len());
    let mut layer: Vec<(Ext, Ext)> = nums.iter().cloned().zip(dens.iter().cloned()).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut it = layer.into_iter();
        while let Some((a, b)) = it.next() {
            match it.next() {
                Some((cn, d)) => {
                    let ad = ext::mul(c, &a, &d);
                    let cb = ext::mul(c, &cn, &b);
                    let n = ext::add(c, &ad, &cb);
                    let bd = ext::mul(c, &b, &d);
                    next.push((n, bd));
                }
                None => next.push((a, b)),
            }
        }
        layer = next;
    }
    layer.pop().unwrap()
}

/// 1 iff no element is zero.
pub fn all_nonzero<C: CircuitContext>(c: &mut C, xs: &[Ext]) -> W {
    let nz: Vec<W> = xs
        .iter()
        .map(|x| {
            let z = ext::is_zero(c, x);
            g::not(c, z)
        })
        .collect();
    crate::field::and_all(c, &nz)
}
