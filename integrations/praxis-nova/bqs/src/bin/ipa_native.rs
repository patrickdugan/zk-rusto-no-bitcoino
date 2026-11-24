//! Native Nova 0.76 IPA fixture and independent verifier-equation replay.
//! No BQS verifier completion claim. Both Pasta curves, no proof wrapper.
use ff::{Field,PrimeField};
use nova_snark::{
    provider::{PallasEngine,VestaEngine,ipa_pc::EvaluationEngine,traits::DlogGroupExt,
        pedersen::{CommitmentEngine,Commitment}},
    traits::{Engine,TranscriptEngineTrait,TranscriptReprTrait,Group,
        commitment::{CommitmentEngineTrait,CommitmentTrait},
        evaluation::EvaluationEngineTrait},
};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use std::path::Path;

#[derive(Clone,Serialize,Deserialize)]
#[serde(bound="")]
struct Opening<E:Engine<CE=CommitmentEngine<E>>>
where E::GE:DlogGroupExt{
    l_vec:Vec<Commitment<E>>,r_vec:Vec<Commitment<E>>,a_hat:E::Scalar,
}
struct Raw(Vec<u8>);
impl<G:Group> TranscriptReprTrait<G> for Raw {
    fn to_transcript_bytes(&self)->Vec<u8>{self.0.clone()}
}
type EE<E>=EvaluationEngine<E>;
type Arg<E>=<EE<E> as EvaluationEngineTrait<E>>::EvaluationArgument;
fn scalar<F:PrimeField>(v:F)->String{hex::encode(v.to_repr().as_ref())}
fn point<E:Engine<CE=CommitmentEngine<E>>>(c:Commitment<E>)->Value where E::GE:DlogGroupExt{
    let(x,y,i)=c.to_coordinates();
    let b=c.to_transcript_bytes();assert_eq!(b.len(),65);
    assert_eq!(&b[..32],x.to_repr().as_ref());
    assert_eq!(&b[32..64],y.to_repr().as_ref());assert_eq!(b[64],u8::from(i));
    if i{assert_eq!(x,E::Base::ZERO);assert_eq!(y,E::Base::ZERO);}
    json!({"x":scalar(x),"y":scalar(y),"infinity":i,"encoding":hex::encode(b)})
}
fn prefix<E:Engine<CE=CommitmentEngine<E>>>(c:&Commitment<E>,x:&[E::Scalar],y:E::Scalar)->E::TE
where E::GE:DlogGroupExt {
    // IPA relies on the preceding protocol to bind the evaluation point.
    let mut t=E::TE::new(b"pns-ipa-native-v1");
    t.absorb(b"context",&E::Scalar::from(19u64));t.absorb(b"comm",c);
    t.absorb(b"point",&Raw(x.iter().flat_map(|v|v.to_repr().as_ref().to_vec()).collect()));
    t.absorb(b"eval",&y);t
}
fn basis<F:PrimeField>(x:&[F])->Vec<F>{
    (0..1usize<<x.len()).map(|j|x.iter().enumerate().fold(F::ONE,|v,(i,a)|
        v*if (j>>(x.len()-1-i))&1==1{*a}else{F::ONE-*a})).collect()
}
fn dot<F:PrimeField>(a:&[F],b:&[F])->F{
    assert_eq!(a.len(),b.len());a.iter().zip(b).fold(F::ZERO,|s,(x,y)|s+*x**y)
}
fn native<E:Engine<CE=CommitmentEngine<E>>>(ell:usize,variant:usize,curve:&str)->Value
where E::GE:DlogGroupExt {
    let n=1usize<<ell;
    let ck=E::CE::setup(b"pns-ipa-commitment-key-v1",n).unwrap();
    let hck=E::CE::setup(b"ipa",1).unwrap();
    let (pk,vk)=EE::<E>::setup(&ck).unwrap();
    let a:Vec<_>=(0..n).map(|i|E::Scalar::from(((i+1)*(i+5)+7*variant)as u64)).collect();
    let x:Vec<_>=(0..ell).map(|i|if variant==1&&i==0{-E::Scalar::ONE}else{E::Scalar::from((i+2+variant)as u64)}).collect();
    let b=basis(&x);let y=dot(&a,&b);
    let c=E::CE::commit(&ck,&a,&E::Scalar::ZERO);
    let h=E::CE::commit(&hck,&[E::Scalar::ONE],&E::Scalar::ZERO);
    let mut t=prefix::<E>(&c,&x,y);
    let proof=EE::<E>::prove(&ck,&pk,&mut t,&c,&a,&x,&y).unwrap();
    let native_suffix=t.squeeze(b"after").unwrap();
    let mut t=prefix::<E>(&c,&x,y);
    EE::<E>::verify(&vk,&mut t,&c,&x,&y,&proof).unwrap();
    assert_eq!(t.squeeze(b"after").unwrap(),native_suffix);

    // Private IPA fields: use a strict bincode layout mirror as transport only.
    // Verify bytewise roundtrip and native acceptance after reconstructing it.
    let pb=bincode::serialize(&proof).unwrap();
    let v:Opening<E>=bincode::deserialize(&pb).unwrap();
    assert_eq!(bincode::serialize(&v).unwrap(),pb);
    assert_eq!(v.l_vec.len(),ell);assert_eq!(v.r_vec.len(),ell);
    let again:Arg<E>=bincode::deserialize(&bincode::serialize(&v).unwrap()).unwrap();
    EE::<E>::verify(&vk,&mut prefix::<E>(&c,&x,y),&c,&x,&y,&again).unwrap();

    // Exact Nova IPA transcript, reconstructed independently from typed bytes.
    let mut tr=prefix::<E>(&c,&x,y);
    tr.dom_sep(b"IPA");let mut u=c.to_transcript_bytes();u.extend(y.to_repr().as_ref());
    tr.absorb(b"U",&Raw(u));let rho=tr.squeeze(b"r").unwrap();
    let mut r=vec![];let mut inv=vec![];
    for i in 0..ell {
        tr.absorb(b"L",&v.l_vec[i]);tr.absorb(b"R",&v.r_vec[i]);
        let z=tr.squeeze(b"r").unwrap();
        r.push(z);inv.push(Option::<E::Scalar>::from(z.invert()).unwrap());
    }
    assert_eq!(tr.squeeze(b"after").unwrap(),native_suffix);
    let s:Vec<_>=(0..n).map(|j|r.iter().zip(&inv).enumerate().fold(E::Scalar::ONE,|v,(i,(a,b))|
        v*if(j>>(ell-1-i))&1==1{*a}else{*b})).collect();
    let mut recurrence=vec![E::Scalar::ZERO;n];
    recurrence[0]=inv.iter().fold(E::Scalar::ONE,|a,b|a**b);
    for j in 1..n {
        let h=j.ilog2() as usize;recurrence[j]=recurrence[j-(1<<h)]*r[ell-1-h].square();
    }
    assert_eq!(s,recurrence);
    let bhat=dot(&b,&s);
    let fact=x.iter().zip(r.iter().zip(&inv)).fold(E::Scalar::ONE,|v,(x,(r,ri))|
        v*((E::Scalar::ONE-*x)**ri+*x**r));
    assert_eq!(fact,bhat);
    // Fused MSM form of Nova's final equation. Avoid a second variable-base
    // multiplication of the folded key; multiply the scalar weights instead.
    let left=(0..ell).fold(c+h*(rho*y),|z,i|
        z+v.l_vec[i]*r[i].square()+v.r_vec[i]*inv[i].square());
    let rhs=E::CE::commit(&ck,&s.iter().map(|s|*s*v.a_hat).collect::<Vec<_>>(),&E::Scalar::ZERO)
        +h*(rho*v.a_hat*bhat);
    assert_eq!(left,rhs);

    let reject=|q:&Arg<E>,c2:Commitment<E>,x2:&[E::Scalar],y2:E::Scalar|{
        EE::<E>::verify(&vk,&mut prefix::<E>(&c2,x2,y2),&c2,x2,&y2,q).is_err()
    };
    assert!(reject(&proof,c,&x,y+E::Scalar::ONE));
    let mut xx=x.clone();xx[0]+=E::Scalar::ONE;assert!(reject(&proof,c,&xx,y));
    assert!(reject(&proof,c+h,&x,y));
    let decode=|v:&Opening<E>|->Arg<E>{bincode::deserialize(&bincode::serialize(v).unwrap()).unwrap()};
    let mut bad=v.clone();bad.a_hat+=E::Scalar::ONE;assert!(reject(&decode(&bad),c,&x,y));
    let mut bad=v.clone();bad.l_vec[0]=bad.l_vec[0]+h;assert!(reject(&decode(&bad),c,&x,y));
    let mut bad=v.clone();bad.r_vec[0]=bad.r_vec[0]+h;assert!(reject(&decode(&bad),c,&x,y));
    let mut bad=v.clone();bad.r_vec.pop();assert!(reject(&decode(&bad),c,&x,y));
    let mut reset=E::TE::new(b"pns-ipa-native-v1");assert!(EE::<E>::verify(&vk,&mut reset,&c,&x,&y,&proof).is_err());

    let generators:Vec<_>=(0..n).map(|j|{let mut v=vec![E::Scalar::ZERO;n];v[j]=E::Scalar::ONE;
        point::<E>(E::CE::commit(&ck,&v,&E::Scalar::ZERO))}).collect();
    json!({"curve":curve,"rounds":ell,"n":n,"variant":variant,
        "commitment":point::<E>(c),"h":point::<E>(h),"generators":generators,
        "point":x.iter().map(|x|scalar(*x)).collect::<Vec<_>>(),"evaluation":scalar(y),
        "l":v.l_vec.iter().map(|v|point::<E>(*v)).collect::<Vec<_>>(),
        "r":v.r_vec.iter().map(|v|point::<E>(*v)).collect::<Vec<_>>(),
        "a_hat":scalar(v.a_hat),"rho":scalar(rho),"challenges":r.iter().map(|x|scalar(*x)).collect::<Vec<_>>(),
        "inverses":inv.iter().map(|x|scalar(*x)).collect::<Vec<_>>(),
        "s":s.iter().map(|x|scalar(*x)).collect::<Vec<_>>(),"b_hat":scalar(bhat),
        "suffix":scalar(native_suffix),"native_proof_bytes":pb.len(),
        "native_verified":true,"fused_equation_verified":true,"negative_controls":8})
}
fn main(){
    let mut fixtures=vec![];
    for ell in [1,2,3]{for variant in 0..2{
        fixtures.push(native::<PallasEngine>(ell,variant,"Pallas"));
        fixtures.push(native::<VestaEngine>(ell,variant,"Vesta"));
    }}
    let report=json!({"scope":"Native Nova IPA openings and independent group equation; not a full Nova verifier",
        "fixtures":fixtures});
    let data=serde_json::to_vec_pretty(&report).unwrap();
    if let Some(p)=std::env::args().nth(1){std::fs::write(Path::new(&p),data).unwrap();}
    else{println!("{}",String::from_utf8(data).unwrap());}
}
