#![cfg(feature = "native-reference")]
//! One round of Nova 0.76 Spartan, verified by independent Boolean arithmetic.
use ff::{Field, PrimeField};
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire,
    GarbledWire, GateHasher, S, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput,
        EvaluateMode, ExecuteMode, FileSource, GarbleMode, StreamingResult,
    },
    nova::{PastaField, Word, sumcheck, transcript::Transcript},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    spartan::{sumcheck::SumcheckProof, polys::univariate::UniPoly},
    traits::{Engine, TranscriptEngineTrait, TranscriptReprTrait},
};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::io::{BufWriter, Write};

#[derive(Clone, Copy)]
struct Kind { field:PastaField, degree:usize }
impl Kind {fn width(self)->usize{(self.degree+2)*256}}
fn bits(raw:&[u8])->Vec<bool>{
    raw.iter().flat_map(|b|(0..8).map(move|i|(b>>i)&1==1)).collect()
}
struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr=Vec<WireId>;
    fn allocate(&self, mut issue:impl FnMut()->WireId)->Self::WireRepr{
        (0..self.0.len()).map(|_|issue()).collect()
    }
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl EncodeInput<ExecuteMode> for Plain{
    fn encode(&self,w:&Self::WireRepr,m:&mut ExecuteMode){
        for (id,v) in w.iter().zip(&self.0){m.feed_wire(*id,*v);}
    }
}
fn build<C:CircuitContext>(c:&mut C,kind:Kind,w:&[WireId])->WireId{
    assert_eq!(w.len(),kind.width());
    let claim:Word=w[..256].try_into().unwrap();
    let coeffs:Vec<Word>=(0..kind.degree).map(|i|{
        let j=(i+1)*256;w[j..j+256].try_into().unwrap()
    }).collect();
    let next:Word=w[w.len()-256..].try_into().unwrap();
    let mut transcript=Transcript::new(c,kind.field,b"nova-bitvm3-m6");
    sumcheck::check_round(c,&mut transcript,&claim,&coeffs,&next)
}
fn execute(kind:Kind,raw:&[u8])->bool{
    let r:StreamingResult<ExecuteMode,_,bool>=CircuitBuilder::streaming_execute(
        Plain(bits(raw)),65536,|c,w|build(c,kind,w));
    r.output_value
}
fn native<E:Engine>(degree:usize,high:bool)->Vec<u8>{
    let mut coefficients=vec![
        if high{-E::Scalar::ONE}else{E::Scalar::ONE},
        E::Scalar::from(3u64),E::Scalar::from(2u64)
    ];
    if degree==3 {coefficients.push(E::Scalar::from(4u64));}
    let poly=UniPoly::<E::Scalar>::from_coeffs(coefficients.clone()).unwrap();
    let claim=poly.eval_at_zero()+poly.eval_at_one();
    let mut transcript=E::TE::new(b"nova-bitvm3-m6");
    let proof=SumcheckProof::<E>::new(vec![poly.compress()]);
    let (next,challenge)=proof.verify(claim,1,degree,&mut transcript).unwrap();
    assert_eq!(challenge.len(),1);
    let native_bytes=<UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>
        ::to_transcript_bytes(&poly);
    let mut compressed=coefficients[0].to_repr().as_ref().to_vec();
    compressed.extend_from_slice(coefficients[2].to_repr().as_ref());
    if degree==3{compressed.extend_from_slice(coefficients[3].to_repr().as_ref());}
    assert_eq!(native_bytes,compressed);
    let mut input=claim.to_repr().as_ref().to_vec();
    input.extend_from_slice(&native_bytes);
    input.extend_from_slice(next.to_repr().as_ref());
    input
}
fn native_input(kind:Kind,high:bool)->Vec<u8>{
    match kind.field{
        PastaField::PallasBase=>native::<VestaEngine>(kind.degree,high),
        PastaField::VestaBase=>native::<PallasEngine>(kind.degree,high),
    }
}
fn modulus(f:PastaField)->BigUint{
    BigUint::from_bytes_le(&f.modulus_le().iter()
        .flat_map(|v|v.to_le_bytes()).collect::<Vec<_>>())
}
#[test]
fn native_quadratic_and_cubic_rounds_match_boolean(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        for degree in [2,3]{
            let kind=Kind{field,degree};
            for high in [false,true]{
                let raw=native_input(kind,high);
                assert_eq!(raw.len()*8,kind.width());
                assert!(execute(kind,&raw));
                for index in [0,32,raw.len()-32]{
                    let mut bad=raw.clone();
                    bad[index]^=1;
                    assert!(!execute(kind,&bad));
                }
            }
        }
    }
}
#[test]
fn every_field_port_requires_canonical_encoding(){
    for field in [PastaField::PallasBase,PastaField::VestaBase]{
        let kind=Kind{field,degree:3};
        let raw=native_input(kind,false);
        let mut p=modulus(field).to_bytes_le();p.resize(32,0);
        for offset in [0,32,64,96,128]{
            let mut bad=raw.clone();
            bad[offset..offset+32].copy_from_slice(&p);
            assert!(!execute(kind,&bad));
        }
    }
}

struct GarbleInput(usize);
impl CircuitInput for GarbleInput {
    type WireRepr=Vec<WireId>;
    fn allocate(&self, mut issue:impl FnMut()->WireId)->Self::WireRepr {
        (0..self.0).map(|_|issue()).collect()
    }
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<H:GateHasher,T:CiphertextHandler> EncodeInput<GarbleMode<H,T>> for GarbleInput {
    fn encode(&self,w:&Self::WireRepr,mode:&mut GarbleMode<H,T>) {
        for id in w {let v=mode.issue_garbled_wire();mode.feed_wire(*id,v);}
    }
}
struct EvalInput(Vec<EvaluatedWire>);
impl CircuitInput for EvalInput {
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr {
        (0..self.0.len()).map(|_|issue()).collect()
    }
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<M:CircuitMode<WireValue=EvaluatedWire>> EncodeInput<M> for EvalInput {
    fn encode(&self,w:&Self::WireRepr,mode:&mut M) {
        for (id,v) in w.iter().zip(&self.0){mode.feed_wire(*id,v.clone());}
    }
}
struct Sink {
    writer:BufWriter<std::fs::File>,
    hash:Blake3AccumulatingHash,
    count:u64,
}
impl CiphertextHandler for Sink {
    type Result=([u8;32],u64);
    fn handle(&mut self,ct:S) {
        self.writer.write_all(&ct.to_bytes()).unwrap();
        self.hash.update(ct);self.count+=1;
    }
    fn finalize(mut self)->Self::Result {
        self.writer.flush().unwrap();(self.hash.finalize(),self.count)
    }
}
struct Cleanup(std::path::PathBuf);
impl Drop for Cleanup {fn drop(&mut self){let _=std::fs::remove_file(&self.0);}}
#[test]
fn streamed_spartan_round_replays_native_and_rejects_mutations() {
    let kind=Kind{field:PastaField::VestaBase,degree:3};
    let seed=6006u64;
    let mut rng=ChaChaRng::seed_from_u64(seed);
    let hasher=AesCcrGateHasher::from_rng(&mut rng);
    let path=Cleanup(std::env::temp_dir().join(format!(
        "nova-m6-{}-{seed}.ct",std::process::id())));
    let file=std::fs::OpenOptions::new()
        .create_new(true).write(true).open(&path.0).unwrap();
    let sink=Sink{
        writer:BufWriter::with_capacity(65536,file),
        hash:Blake3AccumulatingHash::default(),count:0
    };
    let g:StreamingResult<GarbleMode<AesCcrGateHasher,Sink>,_,GarbledWire>=
        CircuitBuilder::streaming_garbling(GarbleInput(kind.width()),65536,seed,sink,
            |c,w|build(c,kind,w));
    let (digest,count)=g.ciphertext_handler_result;
    let bytes=std::fs::metadata(&path.0).unwrap().len();
    assert_eq!(bytes,count*16);
    eprintln!("M6 sumcheck cubic nonfree={count} ciphertext_bytes={bytes}");
    let good=native_input(kind,false);
    let mut changed_coeff=good.clone();changed_coeff[32]^=1;
    let mut changed_output=good.clone();*changed_output.last_mut().unwrap()^=1;
    for (raw,expected) in [(good,true),(changed_coeff,false),(changed_output,false)] {
        let input=EvalInput(g.input_wire_values.iter().zip(bits(&raw))
            .map(|(w,v)|EvaluatedWire::new_from_garbled(w,v)).collect());
        let result:StreamingResult<EvaluateMode<AesCcrGateHasher,FileSource>,_,EvaluatedWire>=
            CircuitBuilder::streaming_evaluation(input,65536,
                g.true_wire_constant.label1.to_u128(),
                g.false_wire_constant.label0.to_u128(),
                hasher.clone(),FileSource::from_path(&path.0).unwrap(),
                |c,w|build(c,kind,w));
        assert_eq!(result.output_value.active_label,g.output_value.select(expected));
        assert_eq!(result.ciphertext_handler_result,digest);
    }
}
