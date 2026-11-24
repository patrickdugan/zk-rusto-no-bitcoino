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
    // Exact source-level count for expanded gates at the pinned fork revision.
    let pop:usize=field.modulus_le().iter().map(|x|x.count_ones() as usize).sum();
    let canonical=768+pop;let add=2816+pop;let dbl=1536+pop;let select=1792;
    let admit=3*canonical+2;
    let static_count=if mul{admit+dbl+add+select+127*(2*dbl+select+add)+768+1}
        else{admit+add+768+1};
    assert_eq!(c.rows.len(),static_count,"source-level count disagrees with expanded graph");
    let mut stats=c.stats();stats["static_source_gate_count"]=static_count.into();
    stats["kind"]=(if mul{"pasta_mul"}else{"pasta_add"}).into();
    stats["field"]=format!("{field:?}").into();stats["native_arithmetic_verified"]=true.into();
    stats["negative_controls"]=2.into();stats["elapsed_seconds"]=t.elapsed().as_secs_f64().into();
    println!("{stats}");
}

// Two rounds with shared transcript, using the M7 fixture schedule.
// A second fixture resets the transcript before round 2; all its arithmetic
// is internally valid for that reset transcript, but must fail this relation.
fn chain_fixture<E:Engine>(reset:bool)->(Vec<Vec<u8>>,E::Scalar,E::Scalar){
    let context=E::Scalar::from(7u64);let initial=E::Scalar::from(19u64);
    let prefix=||{let mut t=E::TE::new(b"nova-chain-fixture");t.absorb(b"context",&context);t};
    let mut t=prefix();let mut value=initial;let mut polys=vec![];
    let mut tape=vec![context.to_repr().as_ref().to_vec(),initial.to_repr().as_ref().to_vec()];
    for i in 0..2{
        if reset&&i>0{t=prefix();}
        let a0=if i==0{-E::Scalar::ONE}else{E::Scalar::from(4u64)};
        let a2=E::Scalar::from((i*13+11) as u64);
        let p=UniPoly::from_coeffs(vec![a0,value-a0-a0-a2,a2]).unwrap();
        let bytes=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&p);
        assert_eq!(bytes.len(),64);
        tape.extend(bytes.chunks_exact(32).map(|b|b.to_vec()));
        t.absorb(b"p",&p);let r=t.squeeze(b"c").unwrap();value=p.evaluate(&r);
        polys.push(p.compress());
    }
    let suffix=t.squeeze(b"after").unwrap();
    if !reset{
        let mut t=prefix();let (actual,rs)=SumcheckProof::<E>::new(polys).verify(initial,2,2,&mut t).unwrap();
        assert_eq!(actual,value);assert_eq!(rs.len(),2);assert_eq!(t.squeeze(b"after").unwrap(),suffix);
    }
    tape.push(value.to_repr().as_ref().to_vec());tape.push(suffix.to_repr().as_ref().to_vec());
    (tape,value,suffix)
}
fn chain_probe<E:Engine>(field:PastaField){
    use garbled_snark_verifier::{CircuitContext,Gate};
    let (tape,_,_)=chain_fixture::<E>(false);let t=Instant::now();let mut c=Compiler::new();
    let w:Vec<Word>=tape.iter().map(|b|c.word(b)).collect();
    let mut tr=Transcript::new(&mut c,field,b"nova-chain-fixture");
    tr.absorb_scalar(&mut c,b"context",&w[0]);
    let polynomials=vec![vec![w[2],w[3]],vec![w[4],w[5]]];
    let reduction=sumcheck::chain::reduce(&mut c,&mut tr,&w[1],&polynomials,2,2);
    let valid=reduction.check_final(&mut c,&w[6]);
    let suffix=tr.squeeze(&mut c,b"after").check(&mut c,&w[7]);
    let ok=c.issue_wire();c.add_gate(Gate::and(valid,suffix,ok));c.accept(ok);c.seal();
    for (i,word) in w[..2].iter().enumerate(){for(j,v)in word.iter().enumerate(){c.pin(*v,(tape[i][j/8]>>(j%8))&1!=0);}}
    assert!(c.check(&c.assignment));
    let (reset,_,_)=chain_fixture::<E>(true);
    let bits=|tape:&[Vec<u8>]|tape.iter().flat_map(|w|w.iter().flat_map(|b|(0..8).map(move|i|(b>>i)&1))).collect::<Vec<_>>();
    // The final claim and suffix are not pinned to the original assignment
    // in this component test; rejection depends on the constrained transcript.
    assert!(!c.check(&c.evaluate(&bits(&reset))),"reset transcript admitted");
    let mut bad=bits(&tape);bad[7*256]^=1;
    assert!(!c.check(&c.evaluate(&bad)),"altered suffix admitted");
    let mut stats=c.stats();stats["kind"]="sumcheck_chain".into();stats["field"]=format!("{field:?}").into();
    stats["rounds"]=2.into();stats["degree"]=2.into();stats["native_round_verified"]=true.into();
    stats["negative_controls"]=2.into();stats["elapsed_seconds"]=t.elapsed().as_secs_f64().into();println!("{stats}");
}

fn main(){
    let args:Vec<_>=std::env::args().collect();assert!(args.len()<=2,"optional export dir");
    let out=args.get(1).map(Path::new);
    arithmetic::<PallasEngine>(PastaField::VestaBase,false);
    arithmetic::<VestaEngine>(PastaField::PallasBase,false);
    arithmetic::<PallasEngine>(PastaField::VestaBase,true);
    arithmetic::<VestaEngine>(PastaField::PallasBase,true);
    chain_probe::<PallasEngine>(PastaField::VestaBase);
    for degree in [2,3]{
        round::<PallasEngine>(PastaField::VestaBase,degree,out);
        round::<VestaEngine>(PastaField::PallasBase,degree,out);
    }
}
