//! Pasta prime-field arithmetic in Boolean gates: Montgomery multiplication with R = 2^255,
//! following garbled-snark-verifier's `Fp254Impl::montgomery_reduce` (rev 8fa7efe) with the
//! width raised from 254 to 255 bits, since both Pasta moduli exceed 2^254.
use super::{const_bit, eq_bits, is_zero, lt_const, W};
use garbled_snark_verifier::{
    gadgets::bigint::{self, BigIntWires},
    CircuitContext,
};
use m12_gates as g;
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub const N: usize = 255;

#[derive(Clone, Debug)]
pub struct PField {
    pub p: BigUint,
    pub minv: BigUint,
    pub r: BigUint,
    pub r2: BigUint,
    pub rinv: BigUint,
}

fn modinv(a: &BigUint, m: &BigUint) -> BigUint {
    // m prime or a power of two with a odd: extended Euclid over signed values.
    use num_bigint::BigInt;
    let (mut t, mut nt) = (BigInt::zero(), BigInt::one());
    let (mut r, mut nr) = (BigInt::from(m.clone()), BigInt::from(a.clone() % m));
    while !nr.is_zero() {
        let q = &r / &nr;
        (t, nt) = (nt.clone(), t - &q * &nt);
        (r, nr) = (nr.clone(), r - &q * &nr);
    }
    assert!(r.is_one(), "not invertible");
    let mm = BigInt::from(m.clone());
    (((t % &mm) + &mm) % &mm).to_biguint().unwrap()
}

impl PField {
    pub fn new(p: BigUint) -> Self {
        assert!(p.bits() as usize == N, "Pasta moduli are 255-bit");
        let r = BigUint::one() << N;
        let minv = modinv(&p, &r);
        let rinv = modinv(&(&r % &p), &p);
        PField { r2: (&r * &r) % &p, r: &r % &p, rinv, minv, p }
    }

    pub fn const_wires(&self, v: &BigUint) -> Vec<W> {
        (0..N).map(|i| const_bit(v.bit(i as u64))).collect()
    }

    /// x (2N bits) -> x R^{-1} mod p, for x < p R.
    fn reduce<C: CircuitContext>(&self, c: &mut C, x: BigIntWires) -> Vec<W> {
        assert_eq!(x.len(), 2 * N);
        let (x_low, x_high) = x.split_at(N);
        let q = bigint::mul_by_constant_modulo_power_two(c, &x_low, &self.minv, N);
        // q p is divisible-complement of x mod R; take its high half.
        let neg_q_p = bigint::mul_by_constant(c, &q, &self.p).split_at(N).1.truncate(N);
        let bound = bigint::greater_than(c, &neg_q_p, &x_high);
        let pw = BigIntWires::new_constant(N, &self.p).unwrap();
        let corr = bigint::self_or_zero(c, &pw, bound);
        let new_sub = bigint::sub_without_borrow(c, &neg_q_p, &corr);
        bigint::sub_without_borrow(c, &x_high, &new_sub).bits
    }

    /// Montgomery product a b R^{-1} mod p.
    pub fn mul<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
        let x = bigint::mul(c, &BigIntWires::from_bits(a[..N].iter().copied()), &BigIntWires::from_bits(b[..N].iter().copied()));
        self.reduce(c, x)
    }

    /// a k R^{-1} mod p for a constant k.
    pub fn mul_const<C: CircuitContext>(&self, c: &mut C, a: &[W], k: &BigUint) -> Vec<W> {
        if k.is_zero() {
            return vec![const_bit(false); N];
        }
        let x = bigint::mul_by_constant(c, &BigIntWires::from_bits(a[..N].iter().copied()), k);
        self.reduce(c, x)
    }

    /// (a + b) mod p for a, b < p.
    pub fn add<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
        let (s, carry) = g::add_c(c, &a[..N], &b[..N], const_bit(false), N, true);
        let mut s = s;
        s.push(carry);
        let pw: Vec<W> = (0..=N).map(|i| const_bit(self.p.bit(i as u64))).collect();
        let (d, ge) = g::sub(c, &s, &pw, N + 1);
        (0..N).map(|i| g::mux(c, ge, s[i], d[i])).collect()
    }

    /// (a - b) mod p for a, b < p.
    pub fn sub<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> Vec<W> {
        let (d, ge) = g::sub(c, &a[..N], &b[..N], N);
        let pw = self.const_wires(&self.p);
        let dp = g::add(c, &d, &pw, N);
        (0..N).map(|i| g::mux(c, ge, dp[i], d[i])).collect()
    }

    /// v < p for a 256-bit little-endian value.
    pub fn canonical<C: CircuitContext>(&self, c: &mut C, v: &[W]) -> W {
        lt_const(c, v, &self.p)
    }

    pub fn eq<C: CircuitContext>(&self, c: &mut C, a: &[W], b: &[W]) -> W {
        eq_bits(c, &a[..N], &b[..N])
    }

    pub fn is_zero<C: CircuitContext>(&self, c: &mut C, a: &[W]) -> W {
        is_zero(c, &a[..N])
    }

    /// Standard -> Montgomery form (a R mod p).
    pub fn to_mont<C: CircuitContext>(&self, c: &mut C, a: &[W]) -> Vec<W> {
        self.mul_const(c, a, &self.r2.clone())
    }

    /// Constant k in Montgomery form.
    pub fn mont_const(&self, k: u64) -> Vec<W> {
        self.const_wires(&((BigUint::from(k) * &self.r) % &self.p))
    }
}
