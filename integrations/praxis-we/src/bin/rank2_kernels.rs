//! PRAXIS-02 independent BN254 kernel probes, not witness encryption.
//! PairingOutput is written additively by arkworks: + means GT multiplication.
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::{Pairing, PairingOutput}, CurveGroup, PrimeGroup};
use ark_ff::{Field, Zero};
use ark_serialize::CanonicalSerialize;
use std::{hint::black_box, time::Instant};

type L = [G1Projective; 2];
type R = [G2Projective; 2];
type GT = PairingOutput<Bn254>;

fn fixture(n: usize, m: usize) -> (Vec<L>, Vec<R>, Vec<Fr>, Vec<Fr>) {
    // Public deterministic coefficients; never use as cryptographic randomness.
    let u = (0..n).map(|i| {
        let i = i as u64;
        [G1Projective::generator() * Fr::from(3*i+2),
         G1Projective::generator() * Fr::from(i*i+5)]
    }).collect();
    let v = (0..m).map(|j| {
        let j = j as u64;
        [G2Projective::generator() * Fr::from(7*j+3),
         G2Projective::generator() * Fr::from(j*j+11)]
    }).collect();
    let a = (0..n).map(|i| Fr::from(i as u64 + 1)).collect();
    let b = (0..m).map(|j| -Fr::from(j as u64 + 2)).collect();
    (u,v,a,b)
}
fn weight(u: &[L], v: &[R], a: &[Fr], b: &[Fr]) -> (Vec<L>, Vec<R>) {
    assert_eq!(u.len(), a.len());
    assert_eq!(v.len(), b.len());
    (u.iter().zip(a).map(|(p,s)| [p[0]*s,p[1]*s]).collect(),
     v.iter().zip(b).map(|(p,s)| [p[0]*s,p[1]*s]).collect())
}
fn two(p: &L, q: &R) -> GT {
    Bn254::multi_pairing(p.map(|x| x.into_affine()), q.map(|x| x.into_affine()))
}
fn dense(u: &[L], v: &[R]) -> GT {
    let mut z = GT::zero();
    for p in u { for q in v { z += two(p,q); } }
    z
}
fn contracted(u: &[L], v: &[R]) -> GT {
    let mut p = [G1Projective::zero(); 2];
    let mut q = [G2Projective::zero(); 2];
    for x in u { p[0] += x[0]; p[1] += x[1]; }
    for x in v { q[0] += x[0]; q[1] += x[1]; }
    two(&p,&q)
}

fn probe(n: usize, m: usize) {
    let (u,v,a,b) = fixture(n,m);
    let start = Instant::now();
    let (u,v) = weight(&u,&v,&a,&b);
    let weight_ms = start.elapsed().as_secs_f64()*1e3;
    let start = Instant::now();
    let d = black_box(dense(black_box(&u),black_box(&v)));
    let dense_ms = start.elapsed().as_secs_f64()*1e3;
    let start = Instant::now();
    let c = black_box(contracted(black_box(&u),black_box(&v)));
    let contracted_ms = start.elapsed().as_secs_f64()*1e3;
    assert_eq!(d,c);
    let mut encoded = Vec::new();
    for p in &u { for x in p { x.into_affine().serialize_compressed(&mut encoded).unwrap(); } }
    for p in &v { for x in p { x.into_affine().serialize_compressed(&mut encoded).unwrap(); } }
    let gt_bytes = d.compressed_size();
    println!("{{\"kernel\":\"separable_rank2_contraction\",\"n\":{n},\"m\":{m},\"dense_pair_terms\":{},\"contracted_pair_terms\":2,\"factor_bytes\":{},\"dense_gt_bytes\":{},\"weight_ms\":{weight_ms:.6},\"dense_ms\":{dense_ms:.6},\"contracted_ms\":{contracted_ms:.6},\"equal\":true}}", 2*n*m, encoded.len(), n*m*gt_bytes);
}

// Eight independent streams reduce artificial dependency serialization.
// Fq2 rate is extension-field products/s, not Fq products/s.
fn mul_probe<F: Field>(name: &str, mut lanes: [F;8], multipliers: [F;8], rounds: usize) {
    let t = Instant::now();
    for _ in 0..rounds {
        for i in 0..8 { lanes[i] *= black_box(multipliers[i]); }
        black_box(&lanes);
    }
    let seconds = t.elapsed().as_secs_f64();
    black_box(lanes);
    let ops = rounds*8;
    println!("{{\"kernel\":\"{name}\",\"operations\":{ops},\"seconds\":{seconds:.9},\"operations_per_second\":{:.3}}}", ops as f64/seconds);
}
fn main() {
    let rounds = std::env::args().nth(1).map(|s| s.parse::<usize>().expect("rounds")).unwrap_or(100_000);
    assert!((1..=10_000_000).contains(&rounds));
    mul_probe("fq_mul", std::array::from_fn(|i| Fq::from(i as u64+2)),
              std::array::from_fn(|i| Fq::from(i as u64+13)), rounds);
    mul_probe("fq2_mul", std::array::from_fn(|i| Fq2::new(Fq::from(i as u64+2),Fq::from(3u64))),
              std::array::from_fn(|i| Fq2::new(Fq::from(i as u64+13),Fq::from(7u64))), rounds);
    for (n,m) in [(2,3),(4,4),(8,8),(16,16)] { probe(n,m); }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rectangular_weighted_and_zero() {
        let (u,v,a,b) = fixture(3,5);
        let (wu,wv) = weight(&u,&v,&a,&b);
        let base = dense(&wu,&wv);
        assert_eq!(base,contracted(&wu,&wv));
        assert!(!base.is_zero());
        let (zu,zv) = weight(&u,&v,&vec![Fr::zero();3],&b);
        assert!(contracted(&zu,&zv).is_zero());
        let mut modified = wu.clone();
        modified[0][0] += G1Projective::generator();
        assert_ne!(base,contracted(&modified,&wv));
        assert_eq!(dense(&modified,&wv),contracted(&modified,&wv));
    }
    #[test]
    fn agrees_with_clear_scalar_formula() {
        let (u,v,a,b) = fixture(3,5);
        let (wu,wv) = weight(&u,&v,&a,&b);
        let mut scalar = Fr::zero();
        for i in 0..3u64 {
            for j in 0..5u64 {
                let x = Fr::from((3*i+2)*(7*j+3)+(i*i+5)*(j*j+11));
                scalar += a[i as usize]*b[j as usize]*x;
            }
        }
        let generator = Bn254::pairing(G1Projective::generator(),G2Projective::generator());
        assert_eq!(contracted(&wu,&wv),generator*scalar);
    }
}
