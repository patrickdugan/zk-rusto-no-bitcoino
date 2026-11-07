#![cfg(feature = "native-reference")]
//! M9 -> M10 integration with native outer, inner and batch sumcheck proofs.
//! The fixture isolates scalar algebra; original commitments and IPA are pending.
use ff::{Field, PrimeField};
use garbled_snark_verifier::{
    CircuitContext, Gate, WireId,
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult},
    nova::{PastaField, Word, transcript::Transcript,
        sumcheck::{batch::{self, BatchProof}, r1cs::{AlgebraProof, MatrixEntry, R1csShape, verify_algebra}}},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    spartan::{sumcheck::SumcheckProof, polys::{multilinear::MultilinearPolynomial, univariate::UniPoly}},
    traits::{Engine, TranscriptEngineTrait, TranscriptReprTrait},
};
const WORDS:usize=28;
const MATRICES:[&[(usize,usize,i64)];3]=[
    &[(0,0,1),(1,1,2),(2,4,3),(3,5,-1),(0,7,1)],
    &[(0,2,1),(1,3,1),(2,0,2),(3,4,1),(2,6,2)],
    &[(0,5,1),(1,4,1),(2,2,1),(3,1,3),(3,7,-1)],
];
fn signed<F:PrimeField>(v:i64)->F{let x=F::from(v.unsigned_abs());if v<0{-x}else{x}}
fn repr<F:PrimeField>(v:F)->Vec<u8>{v.to_repr().as_ref().to_vec()}
fn append<F:PrimeField>(raw:&mut Vec<u8>,v:F){raw.extend(repr(v));}
fn entries<F:PrimeField>()->[Vec<MatrixEntry>;3]{
    std::array::from_fn(|k|MATRICES[k].iter().map(|&(row,column,v)|MatrixEntry{
        row,column,coefficient:repr(signed::<F>(v)).try_into().unwrap()}).collect())
}
fn shape(field:PastaField)->R1csShape{
    let m=match field{PastaField::VestaBase=>entries::<<PallasEngine as Engine>::Scalar>(),
        PastaField::PallasBase=>entries::<<VestaEngine as Engine>::Scalar>()};
    R1csShape::new(field,2,2,1,m).unwrap()
}
fn word(w:&[WireId],i:usize)->Word{w[256*i..256*(i+1)].try_into().unwrap()}
fn build<C:CircuitContext>(c:&mut C,field:PastaField,w:&[WireId])->WireId{
    assert_eq!(w.len(),WORDS*256);let u=word(w,0);let x=word(w,1);
    let mut t=Transcript::new(c,field,b"nova-batch-r1cs-fixture");
    t.absorb_scalar(c,b"u_fixture",&u);t.absorb_scalar_slice(c,b"X_fixture",&[x]);
    let proof=AlgebraProof{
        outer_rounds:(0..2).map(|i|(0..3).map(|j|word(w,2+3*i+j)).collect()).collect(),
        outer_claims:std::array::from_fn(|i|word(w,8+i)),
        inner_rounds:(0..3).map(|i|(0..2).map(|j|word(w,12+2*i+j)).collect()).collect(),
        eval_w:word(w,18),
    };
    let algebra=verify_algebra(c,&mut t,&shape(field),&u,&[x],&proof);
    let batch_proof=BatchProof{
        rounds:(0..2).map(|i|(0..2).map(|j|word(w,19+2*i+j)).collect()).collect(),
        evaluations:[word(w,23),word(w,24)],
    };
    let opening=batch::from_algebra(c,&mut t,&algebra,&batch_proof);
    let outputs=opening.check_outputs(c,&word(w,25),&word(w,26));
    let suffix=t.squeeze(c,b"after").check(c,&word(w,27));
    let ok=c.issue_wire();c.add_gate(Gate::and(outputs,suffix,ok));ok
}
struct Plain(Vec<bool>);
impl CircuitInput for Plain{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0.len()).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl EncodeInput<ExecuteMode> for Plain{
    fn encode(&self,w:&Self::WireRepr,m:&mut ExecuteMode){for(id,b)in w.iter().zip(&self.0){m.feed_wire(*id,*b);}}
}
fn execute(field:PastaField,raw:&[u8])->bool{
    let bits=raw.iter().flat_map(|b|(0..8).map(move|i|(b>>i)&1==1)).collect();
    let result:StreamingResult<ExecuteMode,_,bool>=CircuitBuilder::streaming_execute(
        Plain(bits),65536,|c,w|build(c,field,w));result.output_value
}
fn basis<F:PrimeField>(index:usize,p:&[F])->F{
    p.iter().enumerate().fold(F::ONE,|v,(j,r)|v*if(index>>(p.len()-1-j))&1==1{*r}else{F::ONE-r})
}
fn mle<F:PrimeField>(table:&[F],p:&[F])->F{
    assert_eq!(table.len(),1usize<<p.len());
    table.iter().enumerate().fold(F::ZERO,|s,(i,v)|s+*v*basis(i,p))
}
fn eq<F:PrimeField>(a:&[F],b:&[F])->F{
    a.iter().zip(b).fold(F::ONE,|v,(x,y)|v*(*x**y+(F::ONE-x)*(F::ONE-y)))
}
fn prefix<E:Engine>(u:E::Scalar,x:E::Scalar)->E::TE{
    let mut t=E::TE::new(b"nova-batch-r1cs-fixture");t.absorb(b"u_fixture",&u);
    t.absorb(b"X_fixture",&[x].as_slice());t
}
fn tape<E:Engine>(p:&SumcheckProof<E>,degree:usize)->Vec<u8>{
    let mut out=Vec::new();for poly in p.compressed_polys(){
        let expanded=poly.decompress(&E::Scalar::ZERO);
        let bytes=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&expanded);
        assert_eq!(bytes.len(),degree*32);out.extend(bytes);
    }out
}
fn fixture<E:Engine>(bad_padding:bool)->Vec<u8>{
    let u=E::Scalar::from(7u64);let x=E::Scalar::from(11u64);
    let mut z=vec![E::Scalar::from(2u64),E::Scalar::from(5u64),E::Scalar::from(9u64),
        -E::Scalar::ONE,u,x,E::Scalar::ZERO,E::Scalar::ZERO];
    if bad_padding{z[6]=E::Scalar::ONE;}
    let rows:Vec<Vec<E::Scalar>>=MATRICES.iter().map(|m|(0..4).map(|i|
        m.iter().filter(|&&(row,_,_)|row==i).fold(E::Scalar::ZERO,|s,&(_,col,v)|s+signed::<E::Scalar>(v)*z[col])
    ).collect()).collect();
    let error:Vec<_>=(0..4).map(|i|rows[0][i]*rows[1][i]-u*rows[2][i]).collect();
    let combined:Vec<_>=(0..4).map(|i|u*rows[2][i]+error[i]).collect();
    let mut t=prefix::<E>(u,x);let mut verifier=prefix::<E>(u,x);
    let tau:Vec<_>=(0..2).map(|_|{let r=t.squeeze(b"t").unwrap();assert_eq!(r,verifier.squeeze(b"t").unwrap());r}).collect();
    let mut a=MultilinearPolynomial::new(rows[0].clone());
    let mut b=MultilinearPolynomial::new(rows[1].clone());
    let mut d=MultilinearPolynomial::new(combined);
    let (outer,rx,_)=SumcheckProof::<E>::prove_cubic_with_three_inputs(
        &E::Scalar::ZERO,tau.clone(),&mut a,&mut b,&mut d,&mut t).unwrap();
    let claims=[mle(&rows[0],&rx),mle(&rows[1],&rx),mle(&rows[2],&rx),mle(&error,&rx)];
    let (outer_final,native_rx)=outer.verify(E::Scalar::ZERO,2,3,&mut verifier).unwrap();
    assert_eq!(native_rx,rx);
    assert_eq!(outer_final,eq(&tau,&rx)*(claims[0]*claims[1]-u*claims[2]-claims[3]));
    t.absorb(b"claims_outer",&claims.as_slice());verifier.absorb(b"claims_outer",&claims.as_slice());
    let mixing=t.squeeze(b"r").unwrap();assert_eq!(mixing,verifier.squeeze(b"r").unwrap());
    let initial=claims[0]+mixing*claims[1]+mixing*mixing*claims[2];
    let mut columns=vec![E::Scalar::ZERO;8];let weights=[E::Scalar::ONE,mixing,mixing*mixing];
    for(k,m)in MATRICES.iter().enumerate(){for&(row,col,v)in *m{columns[col]+=weights[k]*signed::<E::Scalar>(v)*basis(row,&rx);}}
    let mut lhs=MultilinearPolynomial::new(columns.clone());let mut rhs=MultilinearPolynomial::new(z.clone());
    let (inner,ry,_)=SumcheckProof::<E>::prove_quad_prod(&initial,3,&mut lhs,&mut rhs,&mut t).unwrap();
    let (inner_final,native_ry)=inner.verify(initial,3,2,&mut verifier).unwrap();
    assert_eq!(ry,native_ry);assert_eq!(inner_final,mle(&columns,&ry)*mle(&z,&ry));
    let eval_w=mle(&z[..4],&ry[1..]);
    t.absorb(b"w",&[eval_w].as_slice());verifier.absorb(b"w",&[eval_w].as_slice());

    let rho=t.squeeze(b"r").unwrap();assert_eq!(rho,verifier.squeeze(b"r").unwrap());
    let batch_claims=[eval_w,claims[3]];let sizes=[2usize,2usize];let weights=[E::Scalar::ONE,rho];
    let points=vec![ry[1..].to_vec(),rx.clone()];
    let polys=vec![MultilinearPolynomial::new(z[..4].to_vec()),MultilinearPolynomial::new(error.clone())];
    let (batch,r,left)=SumcheckProof::<E>::prove_batch_eval(
        &batch_claims,&sizes,polys,points.clone(),&weights,&mut t).unwrap();
    let (end,native_r)=batch.verify_batch(&batch_claims,&sizes,&weights,2,&mut verifier).unwrap();
    assert_eq!(native_r,r);assert_eq!(end,left[0]*eq(&points[0],&r)+rho*left[1]*eq(&points[1],&r));
    t.absorb(b"l",&left.as_slice());verifier.absorb(b"l",&left.as_slice());
    let gamma=t.squeeze(b"c").unwrap();assert_eq!(gamma,verifier.squeeze(b"c").unwrap());
    let joint=left[0]+gamma*left[1];
    let joint_table:Vec<_>=(0..4).map(|i|z[i]+gamma*error[i]).collect();assert_eq!(joint,mle(&joint_table,&r));
    let after=t.squeeze(b"after").unwrap();assert_eq!(after,verifier.squeeze(b"after").unwrap());
    let mut raw=repr(u);append(&mut raw,x);raw.extend(tape::<E>(&outer,3));
    for claim in claims{append(&mut raw,claim);}
    raw.extend(tape::<E>(&inner,2));append(&mut raw,eval_w);raw.extend(tape::<E>(&batch,2));
    for v in left{append(&mut raw,v);}
    for v in [joint,gamma,after]{append(&mut raw,v);}
    assert_eq!(raw.len(),WORDS*32);raw
}
fn input(field:PastaField,bad_padding:bool)->Vec<u8>{match field{
    PastaField::VestaBase=>fixture::<PallasEngine>(bad_padding),
    PastaField::PallasBase=>fixture::<VestaEngine>(bad_padding),
}}
#[test]
fn r1cs_to_batch_uses_same_transcript_and_preserves_prior_failure(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        assert!(execute(field,&input(field,false)));
        // All three native sumcheck proofs still verify for the altered layout.
        // Rejection must propagate from M9's fixed-assignment terminal equation.
        assert!(!execute(field,&input(field,true)),"earlier algebra rejection lost");
    }
}
#[test]
fn integrated_pending_opening_binds_exported_scalars(){
    let field=PastaField::VestaBase;let good=input(field,false);
    for index in [25,26,27]{let mut bad=good.clone();bad[32*index]^=1;assert!(!execute(field,&bad));}
}
