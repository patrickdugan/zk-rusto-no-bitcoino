#![cfg(feature = "native-reference")]
//! M9 native sumcheck differential tests. Full commitment openings are pending.
use ff::{Field, PrimeField};
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire, GarbledWire,
    Gate, GateHasher, S, WireId,
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode,
        CiphertextHandler, GarbleMode, EvaluateMode, FileSource, StreamingResult},
    nova::{PastaField, Word, transcript::Transcript,
        sumcheck::r1cs::{AlgebraProof, R1csShape, MatrixEntry, verify_algebra}},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    spartan::{sumcheck::SumcheckProof, polys::{multilinear::MultilinearPolynomial, univariate::UniPoly}},
    traits::{Engine, Group, TranscriptEngineTrait, TranscriptReprTrait},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::io::{BufWriter, Write};
const CAP: usize = 65536;
const WORDS: usize = 20;
const MATRICES: [&[(usize,usize,i64)];3] = [
    &[(0,0,1),(1,1,2),(2,4,3),(3,5,-1),(0,7,1)],
    &[(0,2,1),(1,3,1),(2,0,2),(3,4,1),(2,6,2)],
    &[(0,5,1),(1,4,1),(2,2,1),(3,1,3),(3,7,-1)],
];
fn signed<F:PrimeField>(v:i64)->F { let x=F::from(v.unsigned_abs());if v<0{-x}else{x} }
fn repr<F:PrimeField>(v:F)->Vec<u8>{v.to_repr().as_ref().to_vec()}
fn append<F:PrimeField>(b:&mut Vec<u8>,v:F){b.extend(repr(v));}
fn entries<F:PrimeField>()->[Vec<MatrixEntry>;3]{
    std::array::from_fn(|k|MATRICES[k].iter().map(|&(row,column,value)|MatrixEntry{
        row,column,coefficient:repr(signed::<F>(value)).try_into().unwrap()
    }).collect())
}
fn shape(field:PastaField,changed:bool)->R1csShape{
    let mut matrices=match field{
        PastaField::VestaBase=>entries::<<PallasEngine as Engine>::Scalar>(),
        PastaField::PallasBase=>entries::<<VestaEngine as Engine>::Scalar>(),
    };
    if changed {matrices[0][0].coefficient[0]=2;}
    R1csShape::new(field,2,2,1,matrices).unwrap()
}
fn bits(raw:&[u8])->Vec<bool>{raw.iter().flat_map(|b|(0..8).map(move|i|(b>>i)&1==1)).collect()}
fn word(w:&[WireId],i:usize)->Word{w[i*256..(i+1)*256].try_into().unwrap()}
fn conjunction<C:CircuitContext>(c:&mut C,a:WireId,b:WireId)->WireId{
    let out=c.issue_wire();c.add_gate(Gate::and(a,b,out));out
}
fn build<C:CircuitContext>(c:&mut C,field:PastaField,changed:bool,w:&[WireId])->WireId{
    assert_eq!(w.len(),WORDS*256);
    let u=word(w,0);let public=word(w,1);
    let proof=AlgebraProof{
        outer_rounds:(0..2).map(|i|(0..3).map(|j|word(w,2+3*i+j)).collect()).collect(),
        outer_claims:std::array::from_fn(|i|word(w,8+i)),
        inner_rounds:(0..3).map(|i|(0..2).map(|j|word(w,12+2*i+j)).collect()).collect(),
        eval_w:word(w,18),
    };
    let mut transcript=Transcript::new(c,field,b"nova-r1cs-fixture");
    transcript.absorb_scalar(c,b"u_fixture",&u);
    transcript.absorb_scalar_slice(c,b"X_fixture",&[public]);
    let result=verify_algebra(c,&mut transcript,&shape(field,changed),&u,&[public],&proof);
    assert_eq!(result.error_point().len(),2);
    assert_eq!(result.witness_point().len(),2);
    let next=transcript.squeeze(c,b"after").check(c,&word(w,19));
    conjunction(c,result.validity(),next)
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
fn execute(field:PastaField,changed:bool,raw:&[u8])->bool{
    let run:StreamingResult<ExecuteMode,_,bool>=CircuitBuilder::streaming_execute(
        Plain(bits(raw)),CAP,|c,w|build(c,field,changed,w));run.output_value
}
fn prefix<E:Engine>(u:E::Scalar,x:E::Scalar)->E::TE{
    let mut t=E::TE::new(b"nova-r1cs-fixture");t.absorb(b"u_fixture",&u);
    t.absorb(b"X_fixture",&[x].as_slice());t
}
fn basis<F:PrimeField>(index:usize,p:&[F])->F{
    p.iter().enumerate().fold(F::ONE,|v,(j,r)|v*if(index>>(p.len()-1-j))&1==1{*r}else{F::ONE-r})
}
fn mle<F:PrimeField>(table:&[F],p:&[F])->F{
    assert_eq!(table.len(),1usize<<p.len());table.iter().enumerate().fold(F::ZERO,|sum,(i,v)|sum+*v*basis(i,p))
}
fn tape<E:Engine>(proof:&SumcheckProof<E>,degree:usize)->Vec<u8>{
    let mut raw=Vec::new();
    for p in proof.compressed_polys(){
        let poly=p.decompress(&E::Scalar::ZERO);
        let b=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&poly);
        assert_eq!(b.len(),degree*32);raw.extend(b);
    }raw
}
// Malicious layouts still produce internally consistent native sumchecks.
fn fixture<E:Engine>(layout:u8)->Vec<u8>{
    let u=E::Scalar::from(7u64);let x=E::Scalar::from(11u64);
    let mut z=vec![E::Scalar::from(2u64),E::Scalar::from(5u64),E::Scalar::from(9u64),
        -E::Scalar::ONE,u,x,E::Scalar::ZERO,E::Scalar::ZERO];
    if layout==1{z[6]=E::Scalar::ONE;}
    if layout==2{z.rotate_left(4);}
    let rows:Vec<Vec<E::Scalar>>=MATRICES.iter().map(|matrix|(0..4).map(|i|
        matrix.iter().filter(|&&(row,_,_)|row==i).fold(E::Scalar::ZERO,|sum,&(_,col,v)|sum+signed::<E::Scalar>(v)*z[col])
    ).collect()).collect();
    let error:Vec<_>=(0..4).map(|i|rows[0][i]*rows[1][i]-u*rows[2][i]).collect();
    let combined:Vec<_>=(0..4).map(|i|u*rows[2][i]+error[i]).collect();
    let mut t=prefix::<E>(u,x);
    let tau:Vec<_>=(0..2).map(|_|t.squeeze(b"t").unwrap()).collect();
    let mut a=MultilinearPolynomial::new(rows[0].clone());
    let mut b=MultilinearPolynomial::new(rows[1].clone());
    let mut d=MultilinearPolynomial::new(combined);
    let (outer,rx,_)=SumcheckProof::<E>::prove_cubic_with_three_inputs(
        &E::Scalar::ZERO,tau.clone(),&mut a,&mut b,&mut d,&mut t).unwrap();
    let claims=[mle(&rows[0],&rx),mle(&rows[1],&rx),mle(&rows[2],&rx),mle(&error,&rx)];
    let mut verifier=prefix::<E>(u,x);
    for expected in tau{assert_eq!(verifier.squeeze(b"t").unwrap(),expected);}
    let (_,native_rx)=outer.verify(E::Scalar::ZERO,2,3,&mut verifier).unwrap();
    assert_eq!(native_rx,rx);
    t.absorb(b"claims_outer",&claims.as_slice());
    verifier.absorb(b"claims_outer",&claims.as_slice());
    let mixing=t.squeeze(b"r").unwrap();assert_eq!(verifier.squeeze(b"r").unwrap(),mixing);
    let initial=claims[0]+mixing*claims[1]+mixing*mixing*claims[2];
    let mut matrix_columns=vec![E::Scalar::ZERO;8];
    let weights=[E::Scalar::ONE,mixing,mixing*mixing];
    for (k,matrix) in MATRICES.iter().enumerate(){for &(row,col,v) in *matrix{
        matrix_columns[col]+=weights[k]*signed::<E::Scalar>(v)*basis(row,&rx);
    }}
    assert_eq!(initial,matrix_columns.iter().zip(&z).fold(E::Scalar::ZERO,|s,(a,b)|s+*a**b));
    let mut lhs=MultilinearPolynomial::new(matrix_columns.clone());
    let mut rhs=MultilinearPolynomial::new(z.clone());
    let (inner,ry,_)=SumcheckProof::<E>::prove_quad_prod(&initial,3,&mut lhs,&mut rhs,&mut t).unwrap();
    let (inner_final,native_ry)=inner.verify(initial,3,2,&mut verifier).unwrap();
    assert_eq!(native_ry,ry);assert_eq!(inner_final,mle(&matrix_columns,&ry)*mle(&z,&ry));
    let eval_w=mle(&z[..4],&ry[1..]);
    t.absorb(b"w",&[eval_w].as_slice());verifier.absorb(b"w",&[eval_w].as_slice());
    let after=t.squeeze(b"after").unwrap();assert_eq!(after,verifier.squeeze(b"after").unwrap());
    let mut raw=repr(u);append(&mut raw,x);raw.extend(tape::<E>(&outer,3));
    for claim in claims{append(&mut raw,claim);}
    raw.extend(tape::<E>(&inner,2));append(&mut raw,eval_w);append(&mut raw,after);
    assert_eq!(raw.len(),WORDS*32);raw
}
fn input(field:PastaField,layout:u8)->Vec<u8>{match field{
    PastaField::VestaBase=>fixture::<PallasEngine>(layout),
    PastaField::PallasBase=>fixture::<VestaEngine>(layout),
}}
struct Raw(Vec<u8>);
impl<G:Group> TranscriptReprTrait<G> for Raw{fn to_transcript_bytes(&self)->Vec<u8>{self.0.clone()}}
// Raw absorption deliberately preserves malformed encodings. The following
// challenge can match every raw byte while circuit admission still rejects.
fn recompute_suffix<E:Engine>(raw:&mut [u8]){
    let mut t=E::TE::new(b"nova-r1cs-fixture");
    t.absorb(b"u_fixture",&Raw(raw[..32].to_vec()));
    t.absorb(b"X_fixture",&Raw(raw[32..64].to_vec()));
    for _ in 0..2{let _=t.squeeze(b"t").unwrap();}
    for i in 0..2{t.absorb(b"p",&Raw(raw[64+96*i..160+96*i].to_vec()));let _=t.squeeze(b"c").unwrap();}
    t.absorb(b"claims_outer",&Raw(raw[256..384].to_vec()));let _=t.squeeze(b"r").unwrap();
    for i in 0..3{t.absorb(b"p",&Raw(raw[384+64*i..448+64*i].to_vec()));let _=t.squeeze(b"c").unwrap();}
    t.absorb(b"w",&Raw(raw[576..608].to_vec()));
    raw[608..640].copy_from_slice(&repr(t.squeeze(b"after").unwrap()));
}
#[test]
fn native_outer_and_inner_proofs_match_fixed_matrix_algebra(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let good=input(field,0);assert!(execute(field,false,&good));
        assert!(!execute(field,true,&good),"changed verifier matrix must reject");
    }
}
#[test]
fn invalid_assignment_padding_and_half_order_reject(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        for layout in [1,2]{assert!(!execute(field,false,&input(field,layout)),"layout {layout}");}
    }
}
#[test]
fn changed_eval_w_rejects_with_recomputed_transcript_suffix(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let mut bad=input(field,0);bad[576]^=1;
        match field{PastaField::PallasBase=>recompute_suffix::<VestaEngine>(&mut bad),
            PastaField::VestaBase=>recompute_suffix::<PallasEngine>(&mut bad)}
        assert!(!execute(field,false,&bad));
    }
}
#[test]
fn noncanonical_public_input_and_late_inner_coefficient_reject(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let raw=input(field,0);
        let prime:Vec<u8>=field.modulus_le().iter().flat_map(|x|x.to_le_bytes()).collect();
        for offset in [32,544,576]{
            let mut bad=raw.clone();bad[offset..offset+32].copy_from_slice(&prime);
            match field{PastaField::PallasBase=>recompute_suffix::<VestaEngine>(&mut bad),
                PastaField::VestaBase=>recompute_suffix::<PallasEngine>(&mut bad)}
            assert!(!execute(field,false,&bad));
        }
    }
}
#[test]
fn verifier_shape_rejects_bad_dimensions_indices_and_coefficients(){
    let f=PastaField::VestaBase;let m=entries::<<PallasEngine as Engine>::Scalar>();
    assert!(R1csShape::new(f,0,2,1,m.clone()).is_err());
    assert!(R1csShape::new(f,2,usize::MAX,1,m.clone()).is_err());
    assert!(R1csShape::new(f,2,2,4,m.clone()).is_err());
    for (row,col) in [(4,0),(0,8)]{let mut bad=m.clone();bad[0][0].row=row;bad[0][0].column=col;
        assert!(R1csShape::new(f,2,2,1,bad).is_err());}
    let mut bad=m.clone();bad[0][0].coefficient=f.modulus_le().iter().flat_map(|x|x.to_le_bytes())
        .collect::<Vec<_>>().try_into().unwrap();
    assert!(R1csShape::new(f,2,2,1,bad).is_err());
    assert!(R1csShape::new(f,2,2,0,[vec![],vec![],vec![]]).is_ok());
}
struct GarbleInput;
impl CircuitInput for GarbleInput{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..WORDS*256).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<H:GateHasher,T:CiphertextHandler> EncodeInput<GarbleMode<H,T>> for GarbleInput{
    fn encode(&self,w:&Self::WireRepr,m:&mut GarbleMode<H,T>){for id in w{let v=m.issue_garbled_wire();m.feed_wire(*id,v);}}
}
struct EvalInput(Vec<EvaluatedWire>);
impl CircuitInput for EvalInput{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0.len()).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<M:CircuitMode<WireValue=EvaluatedWire>> EncodeInput<M> for EvalInput{
    fn encode(&self,w:&Self::WireRepr,m:&mut M){assert_eq!(w.len(),self.0.len());for(id,v)in w.iter().zip(&self.0){m.feed_wire(*id,v.clone());}}
}
struct Sink{writer:BufWriter<std::fs::File>,hash:Blake3AccumulatingHash,count:u64}
impl CiphertextHandler for Sink{
    type Result=([u8;32],u64);
    fn handle(&mut self,ct:S){self.writer.write_all(&ct.to_bytes()).unwrap();self.hash.update(ct);self.count+=1;}
    fn finalize(mut self)->Self::Result{self.writer.flush().unwrap();(self.hash.finalize(),self.count)}
}
struct Cleanup(std::path::PathBuf);
impl Drop for Cleanup{fn drop(&mut self){let _=std::fs::remove_file(&self.0);}}
#[test]
fn streamed_r1cs_algebra_accepts_native_and_rejects_padding(){
    let f=PastaField::VestaBase;let seed=6009u64;
    let mut rng=ChaChaRng::seed_from_u64(seed);let hasher=AesCcrGateHasher::from_rng(&mut rng);
    let path=Cleanup(std::env::temp_dir().join(format!("nova-m9-{}-{seed}.ct",std::process::id())));
    let file=std::fs::OpenOptions::new().create_new(true).write(true).open(&path.0).unwrap();
    let sink=Sink{writer:BufWriter::with_capacity(65536,file),hash:Blake3AccumulatingHash::default(),count:0};
    let g:StreamingResult<GarbleMode<AesCcrGateHasher,Sink>,_,GarbledWire>=
        CircuitBuilder::streaming_garbling(GarbleInput,CAP,seed,sink,|c,w|build(c,f,false,w));
    let(digest,count)=g.ciphertext_handler_result;let bytes=std::fs::metadata(&path.0).unwrap().len();
    assert_eq!(bytes,count*16);eprintln!("M9 outer_inner_r1cs nonfree={count} ciphertext_bytes={bytes} gates={}",g.gate_count);
    for(layout,expected)in[(0,true),(1,false)]{
        let values=bits(&input(f,layout));
        let inputs=EvalInput(g.input_wire_values.iter().zip(values).map(|(w,b)|EvaluatedWire::new_from_garbled(w,b)).collect());
        let e:StreamingResult<EvaluateMode<AesCcrGateHasher,FileSource>,_,EvaluatedWire>=
            CircuitBuilder::streaming_evaluation(inputs,CAP,g.true_wire_constant.label1.to_u128(),
                g.false_wire_constant.label0.to_u128(),hasher.clone(),FileSource::from_path(&path.0).unwrap(),
                |c,w|build(c,f,false,w));
        assert_eq!(e.output_value.active_label,g.output_value.select(expected));
        assert_eq!(e.ciphertext_handler_result,digest);
    }
}
