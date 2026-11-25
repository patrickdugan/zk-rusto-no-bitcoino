//! ZKL-NOVA-06: trusted fixed-matrix bridge into Nova 0.76.0.
//! Membership-only, two pinned public request batches. No theoremhood or ZK claim.
use ff::{Field, PrimeField};
use generic_array::typenum::U5;
use nova_snark::{
    frontend::{
        gadgets::poseidon::{IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength},
        num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
    },
    nova::{PublicParams, RecursiveSNARK},
    provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde::Deserialize;
use serde_json::json;
use std::{sync::{Arc, OnceLock}, time::Instant};

type F = <PallasEngine as Engine>::Scalar;
type E1 = PallasEngine;
type E2 = VestaEngine;
type S1 = RelaxedR1CSSNARK<E1, EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, EvaluationEngine<E2>>;
type Pp = PublicParams<E1, E2, MembershipStep>;
type Rs = RecursiveSNARK<E1, E2, MembershipStep>;

const D: usize = 4;
const K: usize = 5;
const N: usize = 11;
const Q: usize = K * 3;
const ARITY: usize = 3 + 2 * Q;
const MATRIX_ROWS: usize = 4470;
const MATRIX_WIRES: usize = 4368;
const STEP_ROWS: usize = MATRIX_ROWS + 1 + 2 + Q + ARITY;
const MODULUS: &str = "28948022309329048855892746252171976963363056481941647379679742748393362948097";
const ROOT: &str = "28444383152523492001806863032623493205850027174127485938082587742772458775681";
const VECTOR: &str = "3189450979416672123379718128033158450810174494458308961147039301746121343378";
const DOMAIN: u64 = 0x5a4b4c30352f4e4f;
const IDS0: [usize;4] = [0,1,10,1];
const IDS1: [usize;5] = [2,4,6,8,10];
const PUB: [usize;17] = [1,2,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27];

fn scalar(s: &str) -> F {
    assert!(!s.is_empty() && s.bytes().all(|x| x.is_ascii_digit()));
    assert!(s == "0" || !s.starts_with('0'), "noncanonical decimal scalar");
    assert!(s.len() < MODULUS.len() || (s.len() == MODULUS.len() && s < MODULUS), "scalar overflow");
    s.bytes().fold(F::ZERO, |a,b| a * F::from(10) + F::from((b-b'0') as u64))
}
fn native_hash(a: F,b: F) -> F {
    static C: OnceLock<PoseidonConstants<F,U5>> = OnceLock::new();
    let constants = C.get_or_init(|| Sponge::<F,U5>::api_constants(Strength::Standard));
    let mut sponge = Sponge::new_with_constants(constants,Simplex);
    let acc = &mut ();
    sponge.start(IOPattern(vec![SpongeOp::Absorb(3),SpongeOp::Squeeze(1)]),None,acc);
    SpongeAPI::absorb(&mut sponge,3,&[F::from(DOMAIN),a,b],acc);
    let out = SpongeAPI::squeeze(&mut sponge,1,acc);
    sponge.finish(acc).unwrap();
    out[0]
}
fn native_root() -> F {
    let mut layer:Vec<F>=(0..1usize<<D).map(|i| if i<N {F::from((i+1) as u64)} else {F::ZERO}).collect();
    for _ in 0..D { layer=layer.chunks_exact(2).map(|a|native_hash(a[0],a[1])).collect(); }
    layer[0]
}
fn request(ids:&[usize])->Vec<F>{
    (0..K).flat_map(|j|if let Some(&i)=ids.get(j) {[F::ONE,F::from(i as u64),F::from((i+1) as u64)]} else {[F::ZERO;3]}).collect()
}
type Term = (usize,F);
type Row = [Vec<Term>;3];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    constraints:usize,wires:usize,hashes:usize,hash_constraints:usize,non_hash:usize,nonzeros:usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema:String,
    #[serde(rename="D")] d:usize,
    #[serde(rename="K")] k:usize,
    n:usize,domain:String,hash_vector:String,root:String,
    public_ids:Vec<usize>,
    public_values:Vec<Vec<String>>,
    rows:Vec<[Vec<(usize,String)>;3]>,
    assignments:Vec<Vec<String>>,
    corrupt_wire:usize,summary:Summary,
}
#[derive(Clone)]
struct MembershipStep { matrix:Arc<Vec<Row>>, assignment:Arc<Vec<F>> }

impl StepCircuit<F> for MembershipStep {
    fn arity(&self)->usize { ARITY }
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
        assert_eq!(z.len(),ARITY);
        assert_eq!(self.assignment.len(),MATRIX_WIRES);
        let mut vars=Vec::with_capacity(MATRIX_WIRES);
        vars.push(CS::one());
        for i in 1..MATRIX_WIRES {
            let x=self.assignment[i];
            vars.push(cs.alloc(||format!("w{i}"),||Ok(x))?);
        }
        for (i,row) in self.matrix.iter().enumerate(){
            let lc=|j:usize| row[j].iter().fold(LinearCombination::zero(),|a,(id,v)|a+(*v,vars[*id]));
            let (a,b,c)=(lc(0),lc(1),lc(2));
            cs.enforce(||format!("matrix{i}"),|l|l+&a,|l|l+&b,|l|l+&c);
        }
        let ctr=z[2].get_variable();
        cs.enforce(||"counter bit",|l|l+ctr,|l|l+ctr-CS::one(),|l|l);
        for j in 0..2{
            cs.enforce(||format!("state bind {j}"),|l|l+vars[PUB[j]]-z[j].get_variable(),|l|l+CS::one(),|l|l);
        }
        for j in 0..Q {
            let a=z[3+j].get_variable();let b=z[3+Q+j].get_variable();let w=vars[PUB[2+j]];
            cs.enforce(||format!("request bind {j}"),|l|l+ctr,|l|l+b-a,|l|l+w-a);
        }
        let mut out=Vec::with_capacity(ARITY);
        for (i,v) in z.iter().enumerate(){
            let inc=if i==2 {F::ONE} else {F::ZERO};
            let a=AllocatedNum::alloc_infallible(cs.namespace(||format!("out{i}")),||v.get_value().unwrap_or(F::ZERO)+inc);
            cs.enforce(||format!("output bind {i}"),|l|l+v.get_variable()+(inc,CS::one())-a.get_variable(),|l|l+CS::one(),|l|l);
            out.push(a);
        }
        Ok(out)
    }
}

// Evaluates actual frontend constraints on independently supplied assignments.
// Same ConstraintSystem interface as the repository's M17 CheckCS.
struct CheckCS { inputs:Vec<F>,aux:Vec<F>,n:usize,failed:Option<usize> }
impl ConstraintSystem<F> for CheckCS {
    type Root=Self;
    fn new()->Self{Self{inputs:vec![F::ONE],aux:vec![],n:0,failed:None}}
    fn alloc<Fn_,A,AR>(&mut self,_a:A,f:Fn_)->Result<Variable,SynthesisError>
    where Fn_:FnOnce()->Result<F,SynthesisError>,A:FnOnce()->AR,AR:Into<String>{
        self.aux.push(f()?);Ok(Variable::new_unchecked(Index::Aux(self.aux.len()-1)))
    }
    fn alloc_input<Fn_,A,AR>(&mut self,_a:A,f:Fn_)->Result<Variable,SynthesisError>
    where Fn_:FnOnce()->Result<F,SynthesisError>,A:FnOnce()->AR,AR:Into<String>{
        self.inputs.push(f()?);Ok(Variable::new_unchecked(Index::Input(self.inputs.len()-1)))
    }
    fn enforce<A,AR,LA,LB,LC>(&mut self,_a:A,a:LA,b:LB,c:LC)
    where A:FnOnce()->AR,AR:Into<String>,LA:FnOnce(LinearCombination<F>)->LinearCombination<F>,LB:FnOnce(LinearCombination<F>)->LinearCombination<F>,LC:FnOnce(LinearCombination<F>)->LinearCombination<F>{
        let ev=|l:LinearCombination<F>|l.eval(&self.inputs,&self.aux);
        if ev(a(LinearCombination::zero()))*ev(b(LinearCombination::zero()))!=ev(c(LinearCombination::zero())) && self.failed.is_none(){self.failed=Some(self.n);}
        self.n+=1;
    }
    fn push_namespace<NR,Nm>(&mut self,_n:Nm) where NR:Into<String>,Nm:FnOnce()->NR{}
    fn pop_namespace(&mut self){}
    fn get_root(&mut self)->&mut Self{self}
}
fn checked_step(step:&MembershipStep,z:&[F])->(bool,Vec<F>,usize){
    let mut cs=CheckCS::new();
    let inp:Vec<_>=z.iter().enumerate().map(|(i,x)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*x)).collect();
    let out=step.synthesize(&mut cs,&inp).unwrap().iter().map(|x|x.get_value().unwrap()).collect();
    (cs.failed.is_none(),out,cs.n)
}

fn main(){
    // TRUST BOUNDARY: this matrix is a locally generated, verifier-owned build
    // artifact. Never accept a matrix supplied by a remote proof producer.
    let path=std::env::args().nth(1).expect("usage: zklean-nova-smoke trusted-generated-fixture.json");
    let raw=std::fs::read(path).unwrap();assert!(raw.len()<16<<20);
    let f:Fixture=serde_json::from_slice(&raw).unwrap();
    assert_eq!(f.schema,"zkl-nova-06/matrix-v1");assert_eq!((f.d,f.k,f.n),(D,K,N));
    assert_eq!(scalar(&f.domain),F::from(DOMAIN));assert_eq!(scalar(&f.hash_vector),scalar(VECTOR));
    assert_eq!(native_hash(F::from(19),F::from(42)),scalar(VECTOR),"native Poseidon vector");
    let root=native_root();assert_eq!(root,scalar(ROOT));assert_eq!(root,scalar(&f.root));
    assert_eq!(f.public_ids.as_slice(),&PUB);
    assert_eq!((f.summary.constraints,f.summary.wires,f.summary.hashes,f.summary.hash_constraints,f.summary.non_hash,f.summary.nonzeros),(MATRIX_ROWS,MATRIX_WIRES,12,3744,726,105209));
    assert_eq!(f.rows.len(),MATRIX_ROWS);
    let mut nnz=0;
    let matrix:Arc<Vec<Row>>=Arc::new(f.rows.into_iter().map(|r|r.map(|l|{
        let mut prev=None;
        l.into_iter().map(|(i,v)|{
            assert!(i<MATRIX_WIRES && prev.map_or(true,|j|j<i));
            prev=Some(i);let v=scalar(&v);assert_ne!(v,F::ZERO);nnz+=1;(i,v)
        }).collect()
    })).collect());
    assert_eq!(nnz,105209);
    let batches=[request(&IDS0),request(&IDS1),request(&[])];
    assert_eq!(f.assignments.len(),3);assert_eq!(f.public_values.len(),3);
    let steps:Vec<MembershipStep>=f.assignments.into_iter().zip(f.public_values).zip(batches.iter()).map(|((w,p),q)|{
        let w:Vec<_>=w.iter().map(|s|scalar(s)).collect();assert_eq!(w.len(),MATRIX_WIRES);assert_eq!(w[0],F::ONE);
        let expected:Vec<_>=[root,F::from(N as u64)].into_iter().chain(q.iter().copied()).collect();
        assert_eq!(p.iter().map(|s|scalar(s)).collect::<Vec<_>>(),expected);
        assert_eq!(PUB.iter().map(|&i|w[i]).collect::<Vec<_>>(),expected);
        MembershipStep{matrix:matrix.clone(),assignment:Arc::new(w)}
    }).collect();
    let mut z0=vec![root,F::from(N as u64),F::ZERO];
    z0.extend_from_slice(&batches[0]);z0.extend_from_slice(&batches[1]);
    let mut z1=z0.clone();z1[2]=F::ONE;let mut z2=z1.clone();z2[2]=F::from(2);
    assert_eq!(checked_step(&steps[0],&z0),(true,z1.clone(),STEP_ROWS));
    assert_eq!(checked_step(&steps[1],&z1),(true,z2.clone(),STEP_ROWS));
    let mut bad=steps[0].clone();
    assert!(f.corrupt_wire>27 && f.corrupt_wire<MATRIX_WIRES);
    Arc::make_mut(&mut bad.assignment)[f.corrupt_wire]+=F::ONE;
    let mut attacks=0;
    for (step,z) in [(&steps[2],&z0),(&steps[1],&z0),(&steps[0],&z1),(&steps[0],&z2),(&bad,&z0)]{
        assert!(!checked_step(step,z).0,"invalid step accepted");attacks+=1;
    }
    for i in [0,1,3,5]{
        let mut z=z0.clone();z[i]+=F::ONE;
        assert!(!checked_step(&steps[0],&z).0,"changed state accepted");attacks+=1;
    }
    eprintln!("native hash parity; {} step constraints; {} malformed steps rejected",STEP_ROWS,attacks);
    let t=Instant::now();
    let pp=Pp::setup(&steps[0],&*S1::ck_floor(),&*S2::ck_floor()).unwrap();
    let setup=t.elapsed().as_secs_f64();
    let (primary,secondary)=pp.num_constraints();
    let t=Instant::now();
    let mut rs=Rs::new(&pp,&steps[0],&z0).unwrap();
    let init=t.elapsed().as_secs_f64();let mut fold=vec![];
    for s in &steps[..2]{
        let t=Instant::now();rs.prove_step(&pp,s).unwrap();fold.push(t.elapsed().as_secs_f64());
    }
    let t=Instant::now();let zn=rs.verify(&pp,2,&z0).unwrap();
    let verify=t.elapsed().as_secs_f64();assert_eq!(zn,z2);
    let mut verifier_rejections=0;
    for i in [0,1,2,5,3+Q+2]{
        let mut z=z0.clone();z[i]+=F::ONE;
        assert!(rs.verify(&pp,2,&z).is_err(),"altered initial statement accepted");verifier_rejections+=1;
    }
    assert!(rs.verify(&pp,1,&z0).is_err(),"incorrect step count accepted");verifier_rejections+=1;
    let bytes=bincode::serialize(&rs).unwrap();
    let recovered:Rs=bincode::deserialize(&bytes).unwrap();
    assert_eq!(recovered.verify(&pp,2,&z0).unwrap(),z2);
    println!("{}",serde_json::to_string_pretty(&json!({
        "passed":true,"scope":"two pinned Merkle membership batches only; no theoremhood or zero-knowledge wrapper",
        "depth":D,"read_capacity":K,"state_arity":ARITY,"steps":2,"active_reads":9,
        "matrix_constraints":MATRIX_ROWS,"step_constraints":STEP_ROWS,"matrix_wires":MATRIX_WIRES,
        "nova_primary_constraints":primary,"nova_secondary_constraints":secondary,
        "native_poseidon_parity":true,"malformed_steps_rejected":attacks,"verifier_rejections":verifier_rejections,
        "setup_seconds":setup,"init_seconds":init,"fold_seconds":fold,"verify_seconds":verify,
        "recursive_proof_bytes_bincode":bytes.len(),"serialization_roundtrip":true
    })).unwrap());
}
