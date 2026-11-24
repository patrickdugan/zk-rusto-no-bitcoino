//! Exact unoptimized BQS sizes of actual pinned Nova verifier kernels.
use ff::{Field,PrimeField};
use garbled_snark_verifier::nova::{self,PastaField,Word,sumcheck,transcript::Transcript};
use nova_snark::{provider::{PallasEngine,VestaEngine},spartan::{sumcheck::SumcheckProof,polys::univariate::UniPoly},traits::{Engine,TranscriptEngineTrait,TranscriptReprTrait}};
use praxis_nova_bqs::Compiler;
use std::{path::Path,time::Instant};

fn round<E:Engine>(field:PastaField,degree:usize,out:Option<&Path>){
    let p=vec![-E::Scalar::ONE,E::Scalar::from(3),E::Scalar::from(2)];
    let mut p=p;if degree==3{p.push(E::Scalar::from(4));}
    let poly=UniPoly::<E::Scalar>::from_coeffs(p.clone()).unwrap();
    let claim=poly.eval_at_zero()+poly.eval_at_one();
    let mut transcript=E::TE::new(b"nova-bitvm3-m6");
    let proof=SumcheckProof::<E>::new(vec![poly.compress()]);
    let (next,_)=proof.verify(claim,1,degree,&mut transcript).unwrap();
    let repr=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&poly);
    let mut expected=p[0].to_repr().as_ref().to_vec();
    for v in &p[2..]{expected.extend_from_slice(v.to_repr().as_ref());}
    assert_eq!(repr,expected);
    let t=Instant::now();let mut c=Compiler::new();
    let old=c.word(claim.to_repr().as_ref());
    let coeffs:Vec<Word>=repr.chunks_exact(32).map(|x|c.word(x)).collect();
    let last=c.word(next.to_repr().as_ref());
    let mut tr=Transcript::new(&mut c,field,b"nova-bitvm3-m6");
    let ok=sumcheck::check_round(&mut c,&mut tr,&old,&coeffs,&last);c.accept(ok);c.seal();
    // The initial claim and expected final polynomial evaluation are fixed
    // for this fixture. In a real chain these are computed wires.
    for (i,w) in old.iter().chain(&last).enumerate(){
        let bytes=if i<256{claim.to_repr()}else{next.to_repr()};
        c.pin(*w,bytes.as_ref()[(i%256)/8]>>(i%8)&1!=0);
    }
    assert!(c.check(&c.assignment),"native sumcheck must satisfy BQS");
    let input:Vec<_>=c.inputs().iter().map(|i|c.assignment[*i as usize]).collect();
    assert_eq!(c.evaluate(&input),c.assignment,"polynomial evaluator must match native gate assignment");
    let mut bad=input.clone();let i=bad.len()-256;bad[i]^=1;
    assert!(!c.check(&c.evaluate(&bad)),"wrong next");
    let mut bad=input.clone();bad[256]^=1;
    assert!(!c.check(&c.evaluate(&bad)),"mutated compressed coefficient");
    let mut bad=c.assignment.clone();let z=c.rows[c.rows.len()/2].z as usize;bad[z]^=1;
    assert!(!c.check(&bad),"inconsistent intermediate");
    let mut bad=c.assignment.clone();bad[0]=0;assert!(!c.check(&bad));
    let mut bad=c.assignment.clone();bad[c.inputs()[0] as usize]=2;assert!(!c.check(&bad));
    let mut stats=c.stats();stats["kind"]="sumcheck_round".into();stats["field"]=format!("{field:?}").into();
    stats["degree"]=degree.into();stats["native_round_verified"]=true.into();
    stats["negative_controls"]=5.into();stats["elapsed_seconds"]=t.elapsed().as_secs_f64().into();
    if let Some(out)=out{c.export(out.join(format!("{field:?}-degree{degree}"))).unwrap();}
    println!("{stats}");
}
fn arithmetic<E:Engine>(field:PastaField,mul:bool){
    let a=-E::Scalar::ONE;let b=E::Scalar::from(123456789u64);
    let z=if mul{a*b}else{a+b};let t=Instant::now();let mut c=Compiler::new();
    let a=c.word(a.to_repr().as_ref());let b=c.word(b.to_repr().as_ref());let z=c.word(z.to_repr().as_ref());
    let ok=if mul{nova::check_mul(&mut c,field,&a,&b,&z)}else{nova::check_add(&mut c,field,&a,&b,&z)};
    c.accept(ok);assert!(c.check(&c.assignment));
    let mut inp:Vec<_>=c.inputs().iter().map(|i|c.assignment[*i as usize]).collect();
    inp[512]^=1;assert!(!c.check(&c.evaluate(&inp)));
    // all-one 256-bit operand is larger than either Pasta modulus
    inp[..256].fill(1);assert!(!c.check(&c.evaluate(&inp)));
    let mut stats=c.stats();stats["kind"]=(if mul{"pasta_mul"}else{"pasta_add"}).into();
    stats["field"]=format!("{field:?}").into();stats["native_arithmetic_verified"]=true.into();
    stats["negative_controls"]=2.into();stats["elapsed_seconds"]=t.elapsed().as_secs_f64().into();
    println!("{stats}");
}
fn main(){
    let args:Vec<_>=std::env::args().collect();assert!(args.len()<=2,"optional export dir");
    let out=args.get(1).map(Path::new);
    arithmetic::<PallasEngine>(PastaField::VestaBase,false);
    arithmetic::<VestaEngine>(PastaField::PallasBase,false);
    arithmetic::<PallasEngine>(PastaField::VestaBase,true);
    arithmetic::<VestaEngine>(PastaField::PallasBase,true);
    for degree in [2,3]{
        round::<PallasEngine>(PastaField::VestaBase,degree,out);
        round::<VestaEngine>(PastaField::PallasBase,degree,out);
    }
}
