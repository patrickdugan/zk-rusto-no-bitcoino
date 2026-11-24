//! PRAXIS-07: optimized sign-class fingerprint recurrence and packed search.
//! Six Fq multiplications per step from the reciprocal degree-12 Frobenius
//! characteristic polynomial. Deterministic test weights, not a security claim.
use ark_bn254::{Bn254, Fq, Fq2, Fq6, Fq12, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::{Pairing,PairingOutput}, PrimeGroup};
use ark_ff::{Field,PrimeField,One,Zero};
use std::time::Instant;
type GT=PairingOutput<Bn254>;
fn scalar(x:i128)->Fr {
    let s=Fr::from_le_bytes_mod_order(&x.unsigned_abs().to_le_bytes());
    if x<0{-s}else{s}
}
fn base_field(x:Fq12)->Fq {
    let v=x.c0.c0.c0;
    assert_eq!(x,Fq12::new(Fq6::new(Fq2::new(v,Fq::zero()),Fq2::zero(),Fq2::zero()),Fq6::zero()));
    v
}
fn coefficients(step:GT)->[Fq;6] {
    // Product (X - step^(p^j)), j=0..11. The coefficients lie in Fq;
    // roots occur in inverse pairs since step^(p^6) = step^-1.
    let mut p=vec![Fq12::one()];
    for j in 0..12 {
        let mut root=step.0;root.frobenius_map_in_place(j);
        let mut a=vec![Fq12::zero();p.len()+1];
        for (i,c) in p.iter().enumerate(){a[i]-=*c*root;a[i+1]+=c}
        p=a;
    }
    let c:Vec<Fq>=p.into_iter().map(base_field).collect();
    assert_eq!(c[0],Fq::one());assert_eq!(c[12],Fq::one());
    for i in 1..6{assert_eq!(c[i],c[12-i]);}
    std::array::from_fn(|i|c[i+1])
}
fn project(p:GT)->Fq {
    let a=p.0.c0;
    // Arbitrary fixed coefficients for differential tests only.
    let coords=[a.c0.c0,a.c0.c1,a.c1.c0,a.c1.c1,a.c2.c0,a.c2.c1];
    coords.into_iter().zip([3u64,5,7,11,13,17]).fold(Fq::zero(),|s,(a,b)|s+a*Fq::from(b))
}
struct Rec {coeff:[Fq;6],ring:[Fq;12],head:usize}
impl Rec {
    fn new(start:GT,step:GT,coeff:[Fq;6])->Self{
        let mut p=start;
        let ring=std::array::from_fn(|_|{let a=project(p);p+=step;a});
        Self{coeff,ring,head:0}
    }
    fn next(&mut self)->Fq {
        let h=self.head;let old=self.ring[h];
        let mut v=-old;
        for i in 1..6 {
            v-=self.coeff[i-1]*(self.ring[(h+i)%12]+self.ring[(h+12-i)%12]);
        }
        v-=self.coeff[5]*self.ring[(h+6)%12];
        self.ring[h]=v;self.head=(h+1)%12;old
    }
}
fn fp(s:Fq,bits:u32)->u64 {
    if bits==0{return 0}
    s.into_bigint().as_ref()[0] & (u64::MAX>>(64-bits))
}
fn record(f:u64,i:u32)->[u8;12] {
    let mut a=[0;12];a[..8].copy_from_slice(&f.to_be_bytes());a[8..].copy_from_slice(&i.to_be_bytes());a
}
fn read_index(a:&[u8;12])->u32 {u32::from_be_bytes(a[8..].try_into().unwrap())}
#[derive(Debug)]
struct Receipt {babies:usize,giants:u64,checks:u64}
fn search(base:GT,target:GT,bound:i128,m:usize,max_giants:u64,bits:u32)
 -> Result<(Option<i128>,Receipt),&'static str>{
    if bound<0||bound>(1i128<<100)||m==0||m>(1<<22)||max_giants==0||max_giants>(1<<32)||bits>64{return Err("invalid parameters")}
    let mut r=Receipt{babies:0,giants:0,checks:0};
    if base.is_zero(){return Ok((target.is_zero().then_some(0),r))}
    let mut baby=Rec::new(GT::zero(),base,coefficients(base));
    let mut table:Vec<[u8;12]>=(0..m).map(|i|record(fp(baby.next(),bits),i as u32)).collect();
    table.sort_unstable();r.babies=m;
    let stride=2*m as i128-1;
    let jump=base*scalar(stride);let coeff=coefficients(jump);
    let mut pos=Rec::new(target,-jump,coeff);
    let mut neg=Rec::new(target,jump,coeff);
    for j in 0..=(bound+stride-1)/stride {
        for sign in [1i128,-1] {
            // Both streams advance at j=0 even though j=0 is searched only once.
            let s=if sign>0{pos.next()}else{neg.next()};
            if j==0&&sign<0{continue}
            if r.giants>=max_giants{return Ok((None,r))}
            r.giants+=1;
            let fingerprint=fp(s,bits);
            let lo=table.partition_point(|x|x[..8]<fingerprint.to_be_bytes()[..]);
            let hi=table.partition_point(|x|x[..8]<=fingerprint.to_be_bytes()[..]);
            for row in &table[lo..hi] {
                let b=i128::from(read_index(row));
                for bs in [1i128,-1] {
                    if b==0&&bs<0{continue}
                    let t=sign*j*stride+bs*b;
                    if t.abs()>bound{continue}
                    r.checks+=1;
                    if base*scalar(t)==target{return Ok((Some(t),r))}
                }
            }
        }
    }
    Ok((None,r))
}
fn generator()->GT{Bn254::pairing(G1Projective::generator(),G2Projective::generator())}
fn main(){
    let m=std::env::args().nth(1).map(|s|s.parse::<usize>().unwrap()).unwrap_or(65536);
    assert!((1..=1<<20).contains(&m));let g=generator();let target=g*scalar(-12345678);
    let t=Instant::now();let (got,r)=search(g,target,12345678,m,1_000_000,64).unwrap();
    assert_eq!(got,Some(-12345678));
    println!("{{\"kernel\":\"packed_reciprocal_search\",\"babies\":{},\"giants\":{},\"exact_checks\":{},\"packed_bytes\":{},\"seconds\":{:.6},\"correct\":true}}",r.babies,r.giants,r.checks,12*r.babies,t.elapsed().as_secs_f64());
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn reciprocal_recurrence(){
        let g=generator();
        for step in [g,g*scalar(19),-g,GT::zero()] {
            let c=coefficients(step);assert_eq!(c,coefficients(-step));
            let mut x=g*scalar(41);let mut r=Rec::new(x,step,c);
            for _ in 0..128{assert_eq!(project(x),r.next());assert_eq!(project(x),project(-x));x+=step;}
        }
    }
    #[test] fn packed_search_collision_and_bounds(){
        let g=generator();for d in [-64,-17,-1,0,1,17,64]{
            assert_eq!(search(g,g*scalar(d),64,8,128,64).unwrap().0,Some(d));
        }
        assert_eq!(search(g,g*scalar(-39),64,8,128,0).unwrap().0,Some(-39));
        assert_eq!(search(g,g*scalar(65),64,8,128,0).unwrap().0,None);
        assert_eq!(search(g,g*scalar(64),64,8,1,64).unwrap().0,None);
        assert_eq!(search(GT::zero(),GT::zero(),64,8,1,64).unwrap().0,Some(0));
    }
}
