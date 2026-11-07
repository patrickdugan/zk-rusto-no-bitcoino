#![cfg(feature = "native-reference")]
//! Native Nova batch-sumcheck proof comparison and zero-padding adversaries.
use ff::{Field, PrimeField};
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire,
    GarbledWire, Gate, GateHasher, S, WireId,
    circuit::{CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput,
        EvaluateMode, ExecuteMode, FileSource, GarbleMode, StreamingResult, FALSE_WIRE, TRUE_WIRE},
    nova::{PastaField, Word, transcript::Transcript,
        sumcheck::batch::{self, BatchProof, EvaluationClaim}},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    spartan::{sumcheck::SumcheckProof, polys::{multilinear::MultilinearPolynomial, univariate::UniPoly}},
    traits::{Engine, Group, TranscriptEngineTrait, TranscriptReprTrait},
};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::io::{BufWriter, Write};
const CAP: usize = 65536;

#[derive(Clone, Copy, Debug)]
struct Config { field: PastaField, sizes: [usize; 2] }
impl Config {
    fn rounds(self) -> usize { self.sizes[0].max(self.sizes[1]) }
    fn prefix_words(self) -> usize { 3 + self.sizes.iter().sum::<usize>() }
    fn left_offset(self) -> usize { self.prefix_words() + 2*self.rounds() }
    fn output_offset(self) -> usize { self.left_offset() + 2 }
    fn words(self) -> usize { self.output_offset() + 3 + self.rounds() }
}
fn bits(raw: &[u8]) -> Vec<bool> {
    raw.iter().flat_map(|b| (0..8).map(move |i| (b>>i)&1==1)).collect()
}
fn word(w: &[WireId], i: usize) -> Word { w[256*i..256*(i+1)].try_into().unwrap() }
fn and<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let w=c.issue_wire(); c.add_gate(Gate::and(a,b,w)); w
}
fn equal<C: CircuitContext>(c: &mut C, a: &Word, b: &Word) -> WireId {
    let mut ok=TRUE_WIRE;
    for i in 0..256 {
        let d=c.issue_wire(); c.add_gate(Gate::xor(a[i],b[i],d));
        let same=c.issue_wire(); c.add_gate(Gate::xor(d,TRUE_WIRE,same));
        ok=and(c,ok,same);
    }
    ok
}
fn build<C: CircuitContext>(c: &mut C, cfg: Config, prior: bool, w: &[WireId]) -> WireId {
    assert_eq!(w.len(), cfg.words()*256);
    let points: [Vec<Word>;2]=[
        (0..cfg.sizes[0]).map(|i|word(w,1+i)).collect(),
        (0..cfg.sizes[1]).map(|i|word(w,1+cfg.sizes[0]+i)).collect(),
    ];
    let evaluations=[word(w,cfg.prefix_words()-2),word(w,cfg.prefix_words()-1)];
    let mut t=Transcript::new(c,cfg.field,b"nova-batch-fixture");
    t.absorb_scalar(c,b"context",&word(w,0));
    t.absorb_scalar_slice(c,b"x0",&points[0]);
    t.absorb_scalar_slice(c,b"x1",&points[1]);
    t.absorb_scalar_slice(c,b"e",&evaluations);
    let proof=BatchProof {
        rounds:(0..cfg.rounds()).map(|i|(0..2)
            .map(|j|word(w,cfg.prefix_words()+2*i+j)).collect()).collect(),
        evaluations:std::array::from_fn(|i|word(w,cfg.left_offset()+i)),
    };
    let claims=std::array::from_fn(|i|EvaluationClaim{point:&points[i],value:&evaluations[i]});
    let result=batch::verify_pair(c,&mut t,claims,if prior{TRUE_WIRE}else{FALSE_WIRE},&proof);
    let out=cfg.output_offset();
    let mut ok=result.check_outputs(c,&word(w,out),&word(w,out+1));
    for (i,r) in result.point().iter().enumerate() {
        let matched=equal(c,r,&word(w,out+2+i)); ok=and(c,ok,matched);
    }
    let suffix=t.squeeze(c,b"after").check(c,&word(w,cfg.words()-1));
    and(c,ok,suffix)
}
struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0.len()).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self,w:&Self::WireRepr,m:&mut ExecuteMode){for(id,b)in w.iter().zip(&self.0){m.feed_wire(*id,*b);}}
}
fn execute(cfg:Config,prior:bool,raw:&[u8])->bool {
    let run:StreamingResult<ExecuteMode,_,bool>=CircuitBuilder::streaming_execute(
        Plain(bits(raw)),CAP,|c,w|build(c,cfg,prior,w));run.output_value
}
fn repr<F:PrimeField>(v:F)->Vec<u8>{v.to_repr().as_ref().to_vec()}
fn append<F:PrimeField>(out:&mut Vec<u8>,v:F){out.extend(repr(v));}
fn prime<F:PrimeField>()->BigUint{BigUint::parse_bytes(F::MODULUS.trim_start_matches("0x").as_bytes(),16).unwrap()}
fn reduced<F:PrimeField>(raw:&[u8])->F {
    let mut bytes=(BigUint::from_bytes_le(raw)%prime::<F>()).to_bytes_le();bytes.resize(32,0);
    let mut r=F::Repr::default();r.as_mut().copy_from_slice(&bytes);
    Option::<F>::from(F::from_repr(r)).unwrap()
}
fn mle<F:PrimeField>(table:&[F],point:&[F])->F {
    assert_eq!(table.len(),1usize<<point.len());
    table.iter().enumerate().fold(F::ZERO,|sum,(i,v)|{
        let basis=point.iter().enumerate().fold(F::ONE,|w,(j,r)|
            w*if(i>>(point.len()-1-j))&1==1{*r}else{F::ONE-r});
        sum+*v*basis
    })
}
fn eq<F:PrimeField>(a:&[F],b:&[F])->F {
    assert_eq!(a.len(),b.len());
    a.iter().zip(b).fold(F::ONE,|v,(x,y)|v*(*x**y+(F::ONE-x)*(F::ONE-y)))
}
struct Raw(Vec<u8>);
impl<G:Group> TranscriptReprTrait<G> for Raw {fn to_transcript_bytes(&self)->Vec<u8>{self.0.clone()}}
fn prefix<E:Engine>(points:&[Vec<E::Scalar>;2],evals:&[E::Scalar;2])->E::TE {
    let mut t=E::TE::new(b"nova-batch-fixture");
    t.absorb(b"context",&E::Scalar::from(17u64));
    t.absorb(b"x0",&points[0].as_slice());t.absorb(b"x1",&points[1].as_slice());
    t.absorb(b"e",&evals.as_slice());t
}
fn fixture<E:Engine>(cfg:Config,zero:bool)->Vec<u8> {
    let n=cfg.rounds();let sizes=cfg.sizes;
    let tables:[Vec<E::Scalar>;2]=std::array::from_fn(|k|(0..1usize<<sizes[k])
        .map(|i|if zero{E::Scalar::ZERO}else if i==0{-E::Scalar::ONE}
            else{E::Scalar::from((3*i*i+(k+5)*i+7)as u64)}).collect());
    let points:[Vec<E::Scalar>;2]=std::array::from_fn(|k|(0..sizes[k])
        .map(|j|E::Scalar::from((j*3+k+2)as u64)).collect());
    let values=std::array::from_fn(|i|mle(&tables[i],&points[i]));
    let mut t=prefix::<E>(&points,&values);
    let rho=t.squeeze(b"r").unwrap();let weights=[E::Scalar::ONE,rho];
    let polys=tables.iter().map(|v|MultilinearPolynomial::new(v.clone())).collect();
    let (proof,r,left)=SumcheckProof::<E>::prove_batch_eval(
        &values,&sizes,polys,points.to_vec(),&weights,&mut t).unwrap();
    let mut verifier=prefix::<E>(&points,&values);assert_eq!(verifier.squeeze(b"r").unwrap(),rho);
    let (end,native_r)=proof.verify_batch(&values,&sizes,&weights,2,&mut verifier).unwrap();
    assert_eq!(r,native_r);
    let expected=(0..2).fold(E::Scalar::ZERO,|s,i|s+weights[i]*left[i]*eq(&points[i],&r[n-sizes[i]..]));
    assert_eq!(end,expected);
    for i in 0..2{assert_eq!(left[i],mle(&tables[i],&r[n-sizes[i]..]));}
    t.absorb(b"l",&left.as_slice());verifier.absorb(b"l",&left.as_slice());
    let gamma=t.squeeze(b"c").unwrap();assert_eq!(verifier.squeeze(b"c").unwrap(),gamma);
    let padded:Vec<_>=(0..1usize<<n).map(|i|
        tables[0].get(i).copied().unwrap_or(E::Scalar::ZERO)+gamma*tables[1].get(i).copied().unwrap_or(E::Scalar::ZERO)).collect();
    let joint=mle(&padded,&r);
    let scaled=(0..2).fold(E::Scalar::ZERO,|s,i|{
        let l0=r[..n-sizes[i]].iter().fold(E::Scalar::ONE,|v,x|v*(E::Scalar::ONE-x));
        s+if i==0{left[i]*l0}else{gamma*left[i]*l0}
    });
    assert_eq!(joint,scaled);
    let mut raw=repr(E::Scalar::from(17u64));
    for p in &points{for x in p{append(&mut raw,*x);}}
    for v in values{append(&mut raw,v);}
    for p in proof.compressed_polys(){
        let poly=p.decompress(&E::Scalar::ZERO);
        let b=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&poly);
        assert_eq!(b.len(),64);raw.extend(b);
    }
    for l in left{append(&mut raw,l);}
    append(&mut raw,joint);append(&mut raw,gamma);
    for x in r{append(&mut raw,x);}
    let after=t.squeeze(b"after").unwrap();assert_eq!(after,verifier.squeeze(b"after").unwrap());
    append(&mut raw,after);assert_eq!(raw.len(),cfg.words()*32);raw
}
fn input(cfg:Config,zero:bool)->Vec<u8>{match cfg.field{
    PastaField::VestaBase=>fixture::<PallasEngine>(cfg,zero),
    PastaField::PallasBase=>fixture::<VestaEngine>(cfg,zero),
}}
// A raw-byte oracle recomputes every exported scalar after deliberate corruption.
// It returns whether the algebraic terminal equation holds after reducing all
// supplied words modulo p. Thus zero tapes isolate canonical-admission failures.
fn replay<E:Engine>(cfg:Config,raw:&mut [u8],drop_padding:bool)->bool {
    let n=cfg.rounds();let sizes=cfg.sizes;
    let get=|i:usize|reduced::<E::Scalar>(&raw[32*i..32*(i+1)]);
    let points:[Vec<_>;2]=[(0..sizes[0]).map(|i|get(1+i)).collect(),
        (0..sizes[1]).map(|i|get(1+sizes[0]+i)).collect()];
    let values=[get(cfg.prefix_words()-2),get(cfg.prefix_words()-1)];
    let left=[get(cfg.left_offset()),get(cfg.left_offset()+1)];
    let mut t=E::TE::new(b"nova-batch-fixture");
    t.absorb(b"context",&Raw(raw[..32].to_vec()));
    let split=32*(1+sizes[0]);let eval_start=32*(cfg.prefix_words()-2);
    t.absorb(b"x0",&Raw(raw[32..split].to_vec()));
    t.absorb(b"x1",&Raw(raw[split..eval_start].to_vec()));
    t.absorb(b"e",&Raw(raw[eval_start..eval_start+64].to_vec()));
    let rho=t.squeeze(b"r").unwrap();let weights=[E::Scalar::ONE,rho];
    let mut value=(0..2).fold(E::Scalar::ZERO,|s,i|
        s+weights[i]*E::Scalar::from(2u64).pow_vartime([(n-sizes[i])as u64])*values[i]);
    let mut point=Vec::new();
    for i in 0..n {
        let start=32*(cfg.prefix_words()+2*i);let bytes=&raw[start..start+64];
        let a0=reduced::<E::Scalar>(&bytes[..32]);let a2=reduced::<E::Scalar>(&bytes[32..]);
        let a1=value-a0-a0-a2;
        t.absorb(b"p",&Raw(bytes.to_vec()));let r=t.squeeze(b"c").unwrap();
        value=a0+r*(a1+r*a2);point.push(r);
    }
    let expected=(0..2).fold(E::Scalar::ZERO,|s,i|
        s+weights[i]*left[i]*eq(&points[i],&point[n-sizes[i]..]));
    let start=32*cfg.left_offset();t.absorb(b"l",&Raw(raw[start..start+64].to_vec()));
    let gamma=t.squeeze(b"c").unwrap();
    let joint=(0..2).fold(E::Scalar::ZERO,|s,i|{
        let l0=if drop_padding{E::Scalar::ONE}else{
            point[..n-sizes[i]].iter().fold(E::Scalar::ONE,|v,x|v*(E::Scalar::ONE-x))};
        s+if i==0{left[i]*l0}else{gamma*left[i]*l0}
    });
    let mut out=repr(joint);append(&mut out,gamma);for r in point{append(&mut out,r);}
    append(&mut out,t.squeeze(b"after").unwrap());
    raw[32*cfg.output_offset()..].copy_from_slice(&out);value==expected
}
fn replay_for(cfg:Config,raw:&mut [u8],drop_padding:bool)->bool{match cfg.field{
    PastaField::VestaBase=>replay::<PallasEngine>(cfg,raw,drop_padding),
    PastaField::PallasBase=>replay::<VestaEngine>(cfg,raw,drop_padding),
}}
#[test]
fn native_batch_proofs_match_equal_unequal_and_constant_sizes(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        for sizes in [[1,1],[1,2],[2,1],[2,2],[1,3],[3,1],[0,2],[2,0]]{
            let cfg=Config{field,sizes};let good=input(cfg,false);
            assert!(execute(cfg,true,&good),"{cfg:?}");
        }
    }
}
#[test]
fn forged_terminal_evaluations_fail_with_fresh_transcript_outputs(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let cfg=Config{field,sizes:[1,2]};let good=input(cfg,false);
        for index in [cfg.left_offset(),cfg.left_offset()+1]{
            let mut bad=good.clone();bad[32*index]^=1;
            assert!(!replay_for(cfg,&mut bad,false),"terminal must mismatch");
            assert!(!execute(cfg,true,&bad));
        }
        for index in [0,cfg.prefix_words(),cfg.prefix_words()+2]{
            let mut bad=good.clone();bad[32*index]^=1;assert!(!execute(cfg,true,&bad));
        }
    }
}
#[test]
fn scalar_aliases_reject_even_when_zero_tape_algebra_and_hashes_match(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let cfg=Config{field,sizes:[1,2]};let good=input(cfg,true);
        let p:Vec<u8>=field.modulus_le().iter().flat_map(|v|v.to_le_bytes()).collect();
        for index in [1,cfg.prefix_words()-2,cfg.prefix_words(),cfg.prefix_words()+3,cfg.left_offset()+1]{
            let mut bad=good.clone();bad[32*index..32*(index+1)].copy_from_slice(&p);
            assert!(replay_for(cfg,&mut bad,false),"zero tape still satisfies terminal");
            assert!(!execute(cfg,true,&bad),"admission port {index}");
        }
    }
}
#[test]
fn omitted_zero_padding_and_earlier_rejection_cannot_be_bypassed(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        for sizes in [[1,2],[2,1]]{
            let cfg=Config{field,sizes};let good=input(cfg,false);
            assert!(!execute(cfg,false,&good),"prior rejection must persist");
            let mut bad=good.clone();assert!(replay_for(cfg,&mut bad,true));
            assert_ne!(&good[32*cfg.output_offset()..32*(cfg.output_offset()+1)],
                &bad[32*cfg.output_offset()..32*(cfg.output_offset()+1)]);
            assert!(!execute(cfg,true,&bad),"missing L0 correction");
        }
    }
}
#[test]
fn malformed_verifier_owned_round_shapes_are_rejected(){
    for (sizes,rounds) in [([0,0],vec![]),([1,2],vec![vec![[FALSE_WIRE;256];2]]),
        ([1,1],vec![vec![[FALSE_WIRE;256];3]])]{
        let rejected=std::panic::catch_unwind(||{
            let _:StreamingResult<ExecuteMode,_,bool>=CircuitBuilder::streaming_execute(
                Plain(vec![false;256]),CAP,|c,w|{
                    let zero:Word=w[..256].try_into().unwrap();
                    let points=[vec![zero;sizes[0]],vec![zero;sizes[1]]];
                    let mut t=Transcript::new(c,PastaField::PallasBase,b"shape");
                    batch::verify_pair(c,&mut t,
                        [EvaluationClaim{point:&points[0],value:&zero},EvaluationClaim{point:&points[1],value:&zero}],
                        TRUE_WIRE,&BatchProof{rounds:rounds.clone(),evaluations:[zero;2]}).validity()
                });
        });assert!(rejected.is_err());
    }
}
struct GarbleInput(usize);
impl CircuitInput for GarbleInput{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0).map(|_|issue()).collect()}
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
fn streamed_batch_accepts_native_and_rejects_forged_opening_data(){
    for (field,sizes) in [(PastaField::VestaBase,[1,2]),(PastaField::PallasBase,[2,1])]{
        let cfg=Config{field,sizes};let seed=6010u64;
        let mut rng=ChaChaRng::seed_from_u64(seed);let hasher=AesCcrGateHasher::from_rng(&mut rng);
        let path=Cleanup(std::env::temp_dir().join(format!("nova-m10-{}-{field:?}.ct",std::process::id())));
        let file=std::fs::OpenOptions::new().create_new(true).write(true).open(&path.0).unwrap();
        let sink=Sink{writer:BufWriter::with_capacity(65536,file),hash:Blake3AccumulatingHash::default(),count:0};
        let g:StreamingResult<GarbleMode<AesCcrGateHasher,Sink>,_,GarbledWire>=CircuitBuilder::streaming_garbling(
            GarbleInput(cfg.words()*256),CAP,seed,sink,|c,w|build(c,cfg,true,w));
        let(digest,count)=g.ciphertext_handler_result;let bytes=std::fs::metadata(&path.0).unwrap().len();
        assert_eq!(bytes,count*16);eprintln!("M10 batch field={field:?} sizes={sizes:?} nonfree={count} ciphertext_bytes={bytes} gates={}",g.gate_count);
        let good=input(cfg,false);let mut forged=good.clone();forged[32*cfg.left_offset()]^=1;
        assert!(!replay_for(cfg,&mut forged,false));
        let mut padding=good.clone();assert!(replay_for(cfg,&mut padding,true));
        let mut alias=input(cfg,true);let p:Vec<u8>=field.modulus_le().iter().flat_map(|v|v.to_le_bytes()).collect();
        let s=32*cfg.prefix_words();alias[s..s+32].copy_from_slice(&p);assert!(replay_for(cfg,&mut alias,false));
        for(raw,accept)in [(good,true),(forged,false),(padding,false),(alias,false)]{
            let input=EvalInput(g.input_wire_values.iter().zip(bits(&raw)).map(|(w,b)|EvaluatedWire::new_from_garbled(w,b)).collect());
            let e:StreamingResult<EvaluateMode<AesCcrGateHasher,FileSource>,_,EvaluatedWire>=CircuitBuilder::streaming_evaluation(
                input,CAP,g.true_wire_constant.label1.to_u128(),g.false_wire_constant.label0.to_u128(),
                hasher.clone(),FileSource::from_path(&path.0).unwrap(),|c,w|build(c,cfg,true,w));
            assert_eq!(e.output_value.active_label,g.output_value.select(accept));assert_eq!(e.ciphertext_handler_result,digest);
        }
    }
}
