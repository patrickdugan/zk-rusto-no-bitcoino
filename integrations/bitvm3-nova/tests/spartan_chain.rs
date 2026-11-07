#![cfg(feature = "native-reference")]
//! Native Nova differential tests for chain continuity and outer algebra.
use ff::{Field, PrimeField};
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire, GarbledWire,
    Gate, GateHasher, S, WireId,
    circuit::{CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput,
        EvaluateMode, ExecuteMode, FileSource, GarbleMode, StreamingResult},
    nova::{PastaField, Word, sumcheck::chain, transcript::Transcript},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    spartan::{polys::univariate::UniPoly, sumcheck::SumcheckProof},
    traits::{Engine, Group, TranscriptEngineTrait, TranscriptReprTrait},
};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::io::{BufWriter, Write};

const CAP: usize = 65536;
#[derive(Clone, Copy, Debug)]
enum Kind { Chain(PastaField,usize,usize), Outer(PastaField,usize) }
impl Kind {
    fn words(self)->usize {match self {Self::Chain(_,n,d)=>n*d+4,Self::Outer(_,n)=>3*n+9}}
    fn field(self)->PastaField {match self {Self::Chain(f,_,_)|Self::Outer(f,_)=>f}}
}
fn bits(raw:&[u8])->Vec<bool>{raw.iter().flat_map(|b|(0..8).map(move|i|(b>>i)&1==1)).collect()}
fn conjunction<C:CircuitContext>(c:&mut C,a:WireId,b:WireId)->WireId{
    let w=c.issue_wire();c.add_gate(Gate::and(a,b,w));w
}
fn word(w:&[WireId],i:usize)->Word{w[i*256..(i+1)*256].try_into().unwrap()}
fn build<C:CircuitContext>(c:&mut C,kind:Kind,w:&[WireId])->WireId{
    assert_eq!(w.len(),kind.words()*256);
    let mut t=Transcript::new(c,kind.field(),b"nova-chain-fixture");
    t.absorb_scalar(c,b"context",&word(w,0));
    let (rounds,degree)=match kind{Kind::Chain(_,n,d)=>(n,d),Kind::Outer(_,n)=>(n,3)};
    let polys:Vec<Vec<Word>>=(0..rounds).map(|i|(0..degree)
        .map(|j|word(w,2+i*degree+j)).collect()).collect();
    let outputs=2+rounds*degree;
    match kind{
        Kind::Chain(_,n,d)=>{
            let reduction=chain::reduce(c,&mut t,&word(w,1),&polys,n,d);
            let valid=reduction.check_final(c,&word(w,outputs));
            let suffix=t.squeeze(c,b"after").check(c,&word(w,outputs+1));
            conjunction(c,valid,suffix)
        }
        Kind::Outer(_,n)=>{
            let u=word(w,1);
            // The fixture binds u before calling the production algebraic phase.
            t.absorb_scalar(c,b"u_fixture",&u);
            let claims=std::array::from_fn(|i|word(w,outputs+i));
            let result=chain::outer_phase(c,&mut t,&polys,n,&u,&claims);
            let valid=result.check_transition(c,&word(w,outputs+4),&word(w,outputs+5));
            let suffix=t.squeeze(c,b"after").check(c,&word(w,outputs+6));
            conjunction(c,valid,suffix)
        }
    }
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
fn execute(kind:Kind,raw:&[u8])->bool{
    let run:StreamingResult<ExecuteMode,_,bool>=CircuitBuilder::streaming_execute(
        Plain(bits(raw)),CAP,|c,w|build(c,kind,w));run.output_value
}
fn repr<F:PrimeField>(x:F)->Vec<u8>{x.to_repr().as_ref().to_vec()}
fn append<F:PrimeField>(raw:&mut Vec<u8>,x:F){raw.extend(repr(x));}
fn scalar<F:PrimeField>(raw:&[u8])->F{
    let mut r=F::Repr::default();r.as_mut().copy_from_slice(raw);
    Option::<F>::from(F::from_repr(r)).unwrap()
}
fn prime<F:PrimeField>()->BigUint{BigUint::parse_bytes(F::MODULUS.trim_start_matches("0x").as_bytes(),16).unwrap()}
fn reduced<F:PrimeField>(raw:&[u8])->F{
    let mut v=(BigUint::from_bytes_le(raw)%prime::<F>()).to_bytes_le();v.resize(32,0);scalar::<F>(&v)
}
struct Raw(Vec<u8>);
impl<G:Group> TranscriptReprTrait<G> for Raw{fn to_transcript_bytes(&self)->Vec<u8>{self.0.clone()}}
fn prefix<E:Engine>(context:E::Scalar)->E::TE{
    let mut t=E::TE::new(b"nova-chain-fixture");t.absorb(b"context",&context);t
}
fn chain_fixture<E:Engine>(n:usize,d:usize,reset:bool)->Vec<u8>{
    let context=E::Scalar::from(7u64);let initial=E::Scalar::from(19u64);
    let mut t=prefix::<E>(context);let mut value=initial;let mut proofs=Vec::new();
    let mut raw=repr(context);append(&mut raw,initial);
    for i in 0..n{
        if reset && i>0{t=prefix::<E>(context);}
        let a0=if i%2==0{-E::Scalar::ONE}else{E::Scalar::from((i+3)as u64)};
        let mut coefficients=vec![a0,E::Scalar::ZERO];
        for j in 2..=d{coefficients.push(E::Scalar::from((i*13+j*5+1)as u64));}
        let mut linear=value-a0-a0;
        for a in &coefficients[2..]{linear-=a;}
        coefficients[1]=linear;
        let poly=UniPoly::from_coeffs(coefficients).unwrap();
        let bytes=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&poly);
        assert_eq!(bytes.len(),d*32);raw.extend(bytes);
        t.absorb(b"p",&poly);let r=t.squeeze(b"c").unwrap();value=poly.evaluate(&r);
        proofs.push(poly.compress());
    }
    if !reset{
        let mut verifier=prefix::<E>(context);
        let (end,rs)=SumcheckProof::<E>::new(proofs).verify(initial,n,d,&mut verifier).unwrap();
        assert_eq!(end,value);assert_eq!(rs.len(),n);
        assert_eq!(verifier.squeeze(b"after").unwrap(),t.squeeze(b"after").unwrap());
        // Recreate the expected continuation from the raw tape below.
    }
    append(&mut raw,value);
    // Replaying raw bytes also gives canonical fixtures an independent Horner path.
    let mut placeholder=raw.clone();placeholder.extend([0u8;32]);
    replay_chain::<E>(n,d,&mut placeholder,reset);
    assert_eq!(&placeholder[placeholder.len()-64..placeholder.len()-32],repr(value));
    placeholder
}
fn replay_chain<E:Engine>(n:usize,d:usize,raw:&mut [u8],reset:bool){
    let context=scalar::<E::Scalar>(&raw[..32]);let mut t=prefix::<E>(context);
    let mut value=reduced::<E::Scalar>(&raw[32..64]);
    for i in 0..n{
        if reset&&i>0{t=prefix::<E>(context);}
        let start=64+i*d*32;let bytes=&raw[start..start+d*32];
        let c:Vec<_>=bytes.chunks_exact(32).map(reduced::<E::Scalar>).collect();
        let mut linear=value-c[0]-c[0];for a in &c[1..]{linear-=a;}
        t.absorb(b"p",&Raw(bytes.to_vec()));let r=t.squeeze(b"c").unwrap();
        let mut full=vec![c[0],linear];full.extend_from_slice(&c[1..]);
        value=*full.last().unwrap();for a in full[..full.len()-1].iter().rev(){value=value*r+a;}
    }
    let offset=64+n*d*32;raw[offset..offset+32].copy_from_slice(&repr(value));
    raw[offset+32..offset+64].copy_from_slice(&repr(t.squeeze(b"after").unwrap()));
}
fn fixture(kind:Kind,reset:bool)->Vec<u8>{match kind{
    Kind::Chain(PastaField::PallasBase,n,d)=>chain_fixture::<VestaEngine>(n,d,reset),
    Kind::Chain(PastaField::VestaBase,n,d)=>chain_fixture::<PallasEngine>(n,d,reset),
    Kind::Outer(PastaField::PallasBase,n)=>outer_fixture::<VestaEngine>(n),
    Kind::Outer(PastaField::VestaBase,n)=>outer_fixture::<PallasEngine>(n),
}}
fn eq<F:PrimeField>(a:&[F],b:&[F])->F{
    a.iter().zip(b).fold(F::ONE,|v,(x,y)|v*(*x**y+(F::ONE-x)*(F::ONE-y)))
}
fn multilinear<F:PrimeField>(table:&[F],point:&[F])->F{
    assert_eq!(table.len(),1usize<<point.len());
    table.iter().enumerate().fold(F::ZERO,|sum,(i,value)|{
        let weight=point.iter().enumerate().fold(F::ONE,|w,(j,r)|
            w*if(i>>(point.len()-1-j))&1==1{*r}else{F::ONE-r});
        sum+*value*weight
    })
}
fn outer_fixture<E:Engine>(n:usize)->Vec<u8>{
    let context=E::Scalar::from(11u64);let u=E::Scalar::from(7u64);
    let mut t=prefix::<E>(context);t.absorb(b"u_fixture",&u);
    let tau:Vec<_>=(0..n).map(|_|t.squeeze(b"t").unwrap()).collect();
    let a:Vec<_>=(0..1usize<<n).map(|i|E::Scalar::from((3*i+2)as u64)).collect();
    let b:Vec<_>=(0..1usize<<n).map(|i|E::Scalar::from((i*i+5)as u64)).collect();
    let c:Vec<_>=(0..1usize<<n).map(|i|E::Scalar::from((i*7+4)as u64)).collect();
    let error:Vec<_>=a.iter().zip(&b).zip(&c).map(|((a,b),c)|*a**b-u*c).collect();
    let evaluate=|point:&[E::Scalar]|eq(&tau,point)*(
        multilinear(&a,point)*multilinear(&b,point)-u*multilinear(&c,point)-multilinear(&error,point));
    let mut raw=repr(context);append(&mut raw,u);
    let mut prefix_point=Vec::new();let mut value=E::Scalar::ZERO;let mut proofs=Vec::new();
    for round in 0..n{
        let evals:Vec<_>=(0..4u64).map(|x|{
            (0..1usize<<(n-round-1)).fold(E::Scalar::ZERO,|sum,suffix|{
                let mut p=prefix_point.clone();p.push(E::Scalar::from(x));
                for j in (0..n-round-1).rev(){p.push(E::Scalar::from(((suffix>>j)&1)as u64));}
                sum+evaluate(&p)
            })
        }).collect();
        assert_eq!(evals[0]+evals[1],value);
        let poly=UniPoly::from_evals(&evals);
        let encoded=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&poly);
        assert_eq!(encoded.len(),96);raw.extend(encoded);
        t.absorb(b"p",&poly);let challenge=t.squeeze(b"c").unwrap();
        value=poly.evaluate(&challenge);prefix_point.push(challenge);proofs.push(poly.compress());
    }
    let mut verifier=prefix::<E>(context);verifier.absorb(b"u_fixture",&u);
    for expected in &tau{assert_eq!(verifier.squeeze(b"t").unwrap(),*expected);}
    let (verified,rx)=SumcheckProof::<E>::new(proofs).verify(E::Scalar::ZERO,n,3,&mut verifier).unwrap();
    assert_eq!(verified,value);assert_eq!(rx,prefix_point);assert_eq!(value,evaluate(&rx));
    let claims=[multilinear(&a,&rx),multilinear(&b,&rx),multilinear(&c,&rx),multilinear(&error,&rx)];
    for v in claims{append(&mut raw,v);}
    t.absorb(b"claims_outer",&claims.as_slice());let r=t.squeeze(b"r").unwrap();
    append(&mut raw,claims[0]+r*claims[1]+r*r*claims[2]);append(&mut raw,r);
    append(&mut raw,t.squeeze(b"after").unwrap());raw
}
// Recompute the transcript suffix after changing a claimed final evaluation.
// Acceptance must still fail at the outer polynomial equation.
fn replay_outer_suffix<E:Engine>(n:usize,raw:&mut [u8]){
    let context=scalar::<E::Scalar>(&raw[..32]);let u=scalar::<E::Scalar>(&raw[32..64]);
    let mut t=prefix::<E>(context);t.absorb(b"u_fixture",&u);
    for _ in 0..n{let _=t.squeeze(b"t").unwrap();}
    for i in 0..n{let s=64+96*i;t.absorb(b"p",&Raw(raw[s..s+96].to_vec()));let _=t.squeeze(b"c").unwrap();}
    let offset=64+96*n;
    let claims:Vec<_>=raw[offset..offset+128].chunks_exact(32).map(scalar::<E::Scalar>).collect();
    t.absorb(b"claims_outer",&claims.as_slice());let r=t.squeeze(b"r").unwrap();
    let inner=claims[0]+r*claims[1]+r*r*claims[2];let after=t.squeeze(b"after").unwrap();
    for (i,v) in [inner,r,after].iter().enumerate(){raw[offset+128+i*32..offset+160+i*32].copy_from_slice(&repr(*v));}
}
#[test]
fn multi_round_native_matches_and_preserves_transcript(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        for (n,d) in [(1,2),(2,2),(3,3),(4,3)]{
            let kind=Kind::Chain(field,n,d);let good=fixture(kind,false);
            assert!(execute(kind,&good),"{kind:?}");
            for index in [0,32,64,64+(n-1)*d*32,good.len()-64,good.len()-32]{
                let mut bad=good.clone();bad[index]^=1;assert!(!execute(kind,&bad),"mutation {kind:?} at {index}");
            }
        }
    }
}
#[test]
fn resets_reordering_and_recomputed_noncanonical_inputs_reject(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let kind=Kind::Chain(field,3,3);let good=fixture(kind,false);
        assert!(!execute(kind,&fixture(kind,true)),"reset transcript must reject");
        let mut reordered=good.clone();let first=good[64..160].to_vec();
        reordered[64..160].copy_from_slice(&good[160..256]);reordered[160..256].copy_from_slice(&first);
        assert!(!execute(kind,&reordered));
        let p=BigUint::from_bytes_le(&field.modulus_le().iter().flat_map(|v|v.to_le_bytes()).collect::<Vec<_>>());
        let mut modulus=p.to_bytes_le();modulus.resize(32,0);
        for offset in [32,64,160,256]{
            let mut raw=good.clone();raw[offset..offset+32].copy_from_slice(&modulus);
            match field{
                PastaField::PallasBase=>replay_chain::<VestaEngine>(3,3,&mut raw,false),
                PastaField::VestaBase=>replay_chain::<PallasEngine>(3,3,&mut raw,false),
            }
            assert!(!execute(kind,&raw),"matching raw hashes cannot admit noncanonical port {offset}");
        }
    }
}
#[test]
fn outer_terminal_equation_and_inner_transition_match_native(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        for n in [2,3]{let kind=Kind::Outer(field,n);let good=fixture(kind,false);
            assert!(execute(kind,&good),"{kind:?}");
            for offset in [0,32,64,64+96*n,good.len()-96,good.len()-64,good.len()-32]{
                let mut bad=good.clone();bad[offset]^=1;assert!(!execute(kind,&bad),"{kind:?} {offset}");
            }
        }
    }
}
#[test]
fn forged_evaluation_with_recomputed_inner_transition_still_rejects(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let kind=Kind::Outer(field,2);let good=fixture(kind,false);
        for port in 0..4{let mut bad=good.clone();let offset=64+192+32*port;
            // Replace each evaluation by canonical zero or one, ensuring a change.
            let zero=bad[offset..offset+32].iter().all(|b|*b==0);
            bad[offset..offset+32].fill(0);if zero{bad[offset]=1;}
            match field{
                PastaField::PallasBase=>replay_outer_suffix::<VestaEngine>(2,&mut bad),
                PastaField::VestaBase=>replay_outer_suffix::<PallasEngine>(2,&mut bad),
            }
            assert!(!execute(kind,&bad),"terminal evaluation port {port}");
        }
    }
}
#[test]
fn mismatched_round_count_is_a_shape_error(){
    let result=std::panic::catch_unwind(||{
        let _:StreamingResult<ExecuteMode,_,bool>=CircuitBuilder::streaming_execute(
            Plain(vec![false;256]),CAP,|c,w|{
                let mut t=Transcript::new(c,PastaField::PallasBase,b"shape");
                let initial:Word=w.as_slice().try_into().unwrap();
                chain::reduce(c,&mut t,&initial,&[],1,3).validity()
            });
    });assert!(result.is_err());
}
struct GarbleInput(usize);
impl CircuitInput for GarbleInput{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<H:GateHasher,T:CiphertextHandler> EncodeInput<GarbleMode<H,T>> for GarbleInput{
    fn encode(&self,w:&Self::WireRepr,m:&mut GarbleMode<H,T>){for id in w{let value=m.issue_garbled_wire();m.feed_wire(*id,value);}}
}
struct EvalInput(Vec<EvaluatedWire>);
impl CircuitInput for EvalInput{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0.len()).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<M:CircuitMode<WireValue=EvaluatedWire>> EncodeInput<M> for EvalInput{
    fn encode(&self,w:&Self::WireRepr,m:&mut M){for(id,v)in w.iter().zip(&self.0){m.feed_wire(*id,v.clone());}}
}
struct Sink{writer:BufWriter<std::fs::File>,hash:Blake3AccumulatingHash,count:u64}
impl CiphertextHandler for Sink{
    type Result=([u8;32],u64);
    fn handle(&mut self,s:S){self.writer.write_all(&s.to_bytes()).unwrap();self.hash.update(s);self.count+=1;}
    fn finalize(mut self)->Self::Result{self.writer.flush().unwrap();(self.hash.finalize(),self.count)}
}
struct Cleanup(std::path::PathBuf);
impl Drop for Cleanup{fn drop(&mut self){let _=std::fs::remove_file(&self.0);}}
#[test]
fn streamed_chain_and_outer_phase_accept_and_reject(){
    for (index,kind) in [Kind::Chain(PastaField::VestaBase,3,3),Kind::Outer(PastaField::PallasBase,2)].iter().copied().enumerate(){
        let seed=7008+index as u64;let mut rng=ChaChaRng::seed_from_u64(seed);
        let hasher=AesCcrGateHasher::from_rng(&mut rng);
        let path=Cleanup(std::env::temp_dir().join(format!("nova-m78-{}-{seed}.ct",std::process::id())));
        let file=std::fs::OpenOptions::new().create_new(true).write(true).open(&path.0).unwrap();
        let sink=Sink{writer:BufWriter::with_capacity(65536,file),hash:Blake3AccumulatingHash::default(),count:0};
        let g:StreamingResult<GarbleMode<AesCcrGateHasher,Sink>,_,GarbledWire>=
            CircuitBuilder::streaming_garbling(GarbleInput(kind.words()*256),CAP,seed,sink,|c,w|build(c,kind,w));
        let (digest,count)=g.ciphertext_handler_result;let bytes=std::fs::metadata(&path.0).unwrap().len();assert_eq!(bytes,count*16);
        eprintln!("M78 {kind:?} nonfree={count} ciphertext_bytes={bytes}");
        let good=fixture(kind,false);let mut bad=good.clone();bad[64]^=1;
        let mut bad_output=good.clone();*bad_output.last_mut().unwrap()^=1;
        for(raw,expected)in[(good,true),(bad,false),(bad_output,false)]{
            let input=EvalInput(g.input_wire_values.iter().zip(bits(&raw)).map(|(w,b)|EvaluatedWire::new_from_garbled(w,b)).collect());
            let e:StreamingResult<EvaluateMode<AesCcrGateHasher,FileSource>,_,EvaluatedWire>=
                CircuitBuilder::streaming_evaluation(input,CAP,g.true_wire_constant.label1.to_u128(),g.false_wire_constant.label0.to_u128(),
                    hasher.clone(),FileSource::from_path(&path.0).unwrap(),|c,w|build(c,kind,w));
            assert_eq!(e.output_value.active_label,g.output_value.select(expected));assert_eq!(e.ciphertext_handler_result,digest);
        }
    }
}
