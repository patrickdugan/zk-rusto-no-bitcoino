//! PRAXIS-03: bounded centered target-group search and post-Comb recovery.
//! Source: arXiv:2611.28552v1, Fig. 10 lines 8-11, section 5.2.
//! No ciphertext generation, QAP, ties, MSIS, witness encryption, or security claim.
use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::{Pairing, PairingOutput}, PrimeGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Instant};

pub(crate) type GT = PairingOutput<Bn254>;

fn scalar(n: i128) -> Fr {
    let x = Fr::from_le_bytes_mod_order(&n.unsigned_abs().to_le_bytes());
    if n < 0 { -x } else { x }
}

// GT uses additive notation; negation is inversion in the order-q subgroup.
// In BN254 Fq12=Fq6[w], inversion of a GT element is its Fq6 conjugate.
// c0 is shared by the sign class {P,-P}. Hashes are filters, never evidence.
fn fingerprint(p: &GT, bits: u32) -> u64 {
    let mut bytes = Vec::with_capacity(192);
    p.0.c0.serialize_compressed(&mut bytes).expect("memory writer");
    let hash = Sha256::digest(&bytes);
    let n = u64::from_le_bytes(hash[..8].try_into().unwrap());
    if bits == 0 { 0 } else { n >> (64 - bits) }
}

#[derive(Default, Debug)]
pub(crate) struct Counts { pub(crate) babies: u64, pub(crate) giants: u64, pub(crate) exact_checks: u64 }

// Uses full subgroup equality on BOTH signs of every matching baby index.
// The caller chooses a finite giant-step budget; exhaustion is explicit.
// The paper's actual bound is wider than i64: use i128 throughout.
fn search(base: GT, target: GT, bound: i128, m: usize, max_giants: u64,
          bits: u32) -> Result<(Option<i128>, Counts), &'static str> {
    if !(0..=(1i128 << 100)).contains(&bound)
        || !(1..=(1usize << 20)).contains(&m) || max_giants == 0
        || max_giants > (1u64 << 32) || bits > 64 {
        return Err("invalid or unbounded search parameters");
    }
    let mut counts = Counts::default();
    if base.is_zero() {
        return Ok((if target.is_zero() { Some(0) } else { None }, counts));
    }
    let mut table: HashMap<u64, Vec<usize>> = HashMap::with_capacity(m);
    let mut baby = GT::zero();
    for b in 0..m {
        table.entry(fingerprint(&baby, bits)).or_default().push(b);
        baby += base;
        counts.babies += 1;
    }
    let stride = 2 * m as i128 - 1;
    let jump = base * scalar(stride);
    let max_j = (bound + stride - 1) / stride;
    let mut positive = target;
    let mut negative = target;
    for j in 0..=max_j {
        for sign in [1i128, -1] {
            if j == 0 && sign < 0 { continue; }
            if counts.giants >= max_giants { return Ok((None, counts)); }
            counts.giants += 1;
            let g = if sign > 0 { positive } else { negative };
            if let Some(indices) = table.get(&fingerprint(&g, bits)) {
                for &b in indices {
                    let p = base * scalar(b as i128);
                    for s in [1i128, -1] {
                        if b == 0 && s < 0 { continue; }
                        let t = sign * j * stride + s * b as i128;
                        if t.abs() > bound { continue; }
                        counts.exact_checks += 1;
                        if g == if s > 0 { p } else { -p } {
                            // Redundant verification of the returned exponent.
                            if base * scalar(t) == target {
                                return Ok((Some(t), counts));
                            }
                        }
                    }
                }
            }
        }
        positive -= jump;
        negative += jump;
    }
    Ok((None, counts))
}

// Figure 10 after Comb, xi_key is the public witness-dependent weight.
// Reject zero weight. Identity search base is permitted by the paper.
// These group inputs are synthetic test fixtures, never attacker-controlled
// deserialization. This is a correctness kernel, not ciphertext validation.
pub(crate) fn recover(lambda: GT, psi: GT, lambda_alpha: GT, psi_alpha: GT,
           key_alpha: GT, xi: Fr, center: i128, bound: i128,
           m: usize, max_giants: u64, bits: u32)
           -> Result<(Option<GT>, Counts), &'static str> {
    let inv = xi.inverse().ok_or("zero key weight")?;
    let target = lambda_alpha - key_alpha * xi - psi_alpha * scalar(center);
    let (t, counts) = search(psi_alpha, target, bound, m, max_giants, bits)?;
    let key = t.map(|t| (lambda - psi * (scalar(center) + scalar(t))) * inv);
    Ok((key, counts))
}

fn generator() -> GT {
    Bn254::pairing(G1Projective::generator(), G2Projective::generator())
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let m = args.get(1).map(|s| s.parse::<usize>().unwrap()).unwrap_or(1024);
    let distance = args.get(2).map(|s| s.parse::<i128>().unwrap()).unwrap_or(-123456);
    assert!((-1_000_000_000..=1_000_000_000).contains(&distance));
    let base = generator() * Fr::from(17u64);
    let target = base * scalar(distance);
    let now = Instant::now();
    let (answer, c) = search(base, target, distance.abs()+100, m, 1_000_000, 64).unwrap();
    assert_eq!(answer, Some(distance));
    println!("{{\"kernel\":\"praxis_centered_gt_reference\",\"m\":{m},\"distance\":{distance},\"baby_steps\":{},\"giant_steps\":{},\"exact_checks\":{},\"seconds\":{:.9},\"correct\":true}}",
             c.babies, c.giants, c.exact_checks, now.elapsed().as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signs_and_window_boundaries() {
        let p = generator() * Fr::from(23u64);
        for m in [1, 4, 17] {
            for t in [-64, -34, -33, -17, -16, -1, 0, 1, 16, 17, 33, 34, 64] {
                assert_eq!(search(p, p*scalar(t), 64, m, 200, 64).unwrap().0, Some(t));
            }
        }
    }
    #[test]
    fn collisions_cannot_create_false_matches() {
        let p = generator();
        assert_eq!(fingerprint(&p,64), fingerprint(&(-p),64));
        let (t,c) = search(p,p*scalar(-39),64,8,20,0).unwrap();
        assert_eq!(t,Some(-39));
        assert!(c.exact_checks > 1);
        assert_eq!(search(p,p*scalar(65),64,8,20,0).unwrap().0,None);
    }
    #[test]
    fn exhaustion_identity_and_validation() {
        let p = generator();
        assert_eq!(search(p,p*scalar(100),100,4,1,64).unwrap().0,None);
        assert_eq!(search(GT::zero(),GT::zero(),10,4,1,64).unwrap().0,Some(0));
        assert_eq!(search(GT::zero(),p,10,4,1,64).unwrap().0,None);
        assert!(search(p,p,1,0,1,64).is_err());
        assert!(search(p,p,-1,4,1,64).is_err());
        assert!(search(p,p,1,4,1,65).is_err());
    }
    #[test]
    fn figure10_recovery() {
        let g = generator();
        let k = g * scalar(91);
        let alpha = scalar(13);
        let xi = scalar(19);
        // Large center tests the scalar path beyond i64 without a huge search.
        let center = (1i128 << 68) + 7;
        for (delta, psi) in [(-35,g*scalar(7)),(35,g*scalar(7)),(0,GT::zero())] {
            let lambda = k * xi + psi * (scalar(center)+scalar(delta));
            let got = recover(lambda,psi,lambda*alpha,psi*alpha,k*alpha,xi,center,
                              64,8,20,64).unwrap().0;
            assert_eq!(got,Some(k));
        }
        assert!(recover(g,g,g,g,g,Fr::zero(),0,1,4,1,64).is_err());
    }
}
