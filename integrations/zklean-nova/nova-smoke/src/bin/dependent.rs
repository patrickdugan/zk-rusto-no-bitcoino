//! ZKL-NOVA-11: fold the authenticated dependent-type row relation.
//! Trusted verifier-generated matrix; no claim of a hiding proof wrapper.
use ff::{Field,PrimeField};
use generic_array::typenum::U5;
use nova_snark::{
 frontend::{gadgets::poseidon::{IOPattern,PoseidonConstants,Simplex,Sponge,SpongeAPI,SpongeOp,SpongeTrait,Strength},
 num::AllocatedNum,ConstraintSystem,Index,LinearCombination,SynthesisError,Variable},
 nova::{PublicParams,RecursiveSNARK,CompressedSNARK},
 provider::{ipa_pc::EvaluationEngine,PallasEngine,VestaEngine},
 spartan::snark::RelaxedR1CSSNARK,traits::{circuit::StepCircuit,snark::RelaxedR1CSSNARKTrait,Engine},
};
use serde::Deserialize;
use serde_json::{json,Value};
use std::{sync::{Arc,OnceLock},time::Instant};
type F=<PallasEngine as Engine>::Scalar;
type E1=PallasEngine;
type E2=VestaEngine;
type S1=RelaxedR1CSSNARK<E1,EvaluationEngine<E1>>;
type S2=RelaxedR1CSSNARK<E2,EvaluationEngine<E2>>;
type Pp=PublicParams<E1,E2,DependentStep>;
type Rs=RecursiveSNARK<E1,E2,DependentStep>;
type Cs=CompressedSNARK<E1,E2,DependentStep,S1,S2>;
type Cvk=nova_snark::nova::VerifierKey<E1,E2,DependentStep,S1,S2>;
const D:usize=6;
const ARITY:usize=4;
const STEPS:usize=52;
const MATRIX_ROWS:usize=29906;
const MATRIX_WIRES:usize=29114;
const STEP_ROWS:usize=MATRIX_ROWS+2*ARITY;
const MODULUS:&str="28948022309329048855892746252171976963363056481941647379679742748393362948097";
const ROOT:&str="21126881501828034488680577522648234560215113972804824311247652989139188675329";
const GOAL:&str="25327786219354606581701440963272839582669484053242296055831016064365032228631";
const FINAL_ROOT:&str="22931348701074883580880961096199602307671849238854529278659453453117345000763";
const NODE_VECTOR:&str="14114214179916697404878619261192913361145130603274328369933284479456013695164";
const LEAF_VECTOR:&str="10002637170120463377809397913605476821031046123563835871351888133954241573199";
const NODE:u64=6506377860829105743;
const LEAF:u64=6506377860829105222;
const TERM:u64=6506377860829107200;
const PUB:[usize;8]=[2729,1,2730,2731,2732,2733,2734,2735];
fn scalar(s:&str)->F {
 assert!(!s.is_empty()&&s.bytes().all(|x|x.is_ascii_digit()));
 assert!(s=="0"||!s.starts_with('0'));
 assert!(s.len()<MODULUS.len()||(s.len()==MODULUS.len()&&s<MODULUS));
 s.bytes().fold(F::ZERO,|a,b|a*F::from(10)+F::from((b-b'0') as u64))
}
fn native_hash(domain:u64,args:&[F])->F {
 static C:OnceLock<PoseidonConstants<F,U5>>=OnceLock::new();
 let constants=C.get_or_init(||Sponge::<F,U5>::api_constants(Strength::Standard));
 let mut input=vec![F::from(domain)];input.extend_from_slice(args);
 assert!(input.len()<=5);
 let mut sponge=Sponge::new_with_constants(constants,Simplex);let acc=&mut ();
 sponge.start(IOPattern(vec![SpongeOp::Absorb(input.len() as u32),SpongeOp::Squeeze(1)]),None,acc);
 SpongeAPI::absorb(&mut sponge,input.len() as u32,&input,acc);
 let out=SpongeAPI::squeeze(&mut sponge,1,acc);sponge.finish(acc).unwrap();out[0]
}
fn genesis()->Vec<F>{
 let mut root=F::ZERO;
 for _ in 0..D{root=native_hash(NODE,&[root,root]);}
 let sort=native_hash(TERM+1,&[F::ONE,F::ZERO]);
 let b0=native_hash(TERM+2,&[F::ZERO,F::ZERO]);
 let b1=native_hash(TERM+2,&[F::ONE,F::ZERO]);
 let product=native_hash(TERM+4,&[b0,b1]);
 let goal=native_hash(TERM+4,&[sort,product]);
 assert_eq!(root,scalar(ROOT));assert_eq!(goal,scalar(GOAL));
 vec![root,F::ZERO,goal,F::ZERO]
}
fn admitted(z:&[F],steps:usize,goal:F)->bool{
 z.len()==ARITY&&steps>0&&steps<=(1<<D)&&z[1]==F::from(steps as u64)&&z[2]==goal&&z[3]==F::ONE
}
type Term=(usize,F);
type Row=[Vec<Term>;3];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture{schema:String,summary:Value,states:Vec<Vec<String>>,rows:Vec<[Vec<(usize,String)>;3]>}
#[derive(Clone)]
struct DependentStep {matrix:Arc<Vec<Row>>,assignment:Arc<Vec<F>>}
impl StepCircuit<F> for DependentStep {
 fn arity(&self)->usize{ARITY}
 fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
  assert_eq!(z.len(),ARITY);assert_eq!(self.assignment.len(),MATRIX_WIRES);
  let mut vars=Vec::with_capacity(MATRIX_WIRES);vars.push(CS::one());
  for i in 1..MATRIX_WIRES {let x=self.assignment[i];vars.push(cs.alloc(||format!("w{i}"),||Ok(x))?);}
  for (i,row) in self.matrix.iter().enumerate(){
   let lc=|j:usize|row[j].iter().fold(LinearCombination::zero(),|a,(id,v)|a+(*v,vars[*id]));
   let (a,b,c)=(lc(0),lc(1),lc(2));
   cs.enforce(||format!("matrix{i}"),|l|l+&a,|l|l+&b,|l|l+&c);
  }
  for i in 0..ARITY {cs.enforce(||format!("input{i}"),|l|l+vars[PUB[i]]-z[i].get_variable(),|l|l+CS::one(),|l|l);}
  let mut out=Vec::with_capacity(ARITY);
  for i in 0..ARITY{
   let w=PUB[ARITY+i];let a=AllocatedNum::alloc_infallible(cs.namespace(||format!("out{i}")),||self.assignment[w]);
   cs.enforce(||format!("output{i}"),|l|l+vars[w]-a.get_variable(),|l|l+CS::one(),|l|l);
   out.push(a);
  }
  Ok(out)
 }
}
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
fn checked_step(step:&DependentStep,z:&[F])->(bool,Vec<F>,usize){
    let mut cs=CheckCS::new();
    let inp:Vec<_>=z.iter().enumerate().map(|(i,x)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*x)).collect();
    let out=step.synthesize(&mut cs,&inp).unwrap().iter().map(|x|x.get_value().unwrap()).collect();
    (cs.failed.is_none(),out,cs.n)
}


fn endpoint(w:&[F],start:usize)->Vec<F>{PUB[start..start+ARITY].iter().map(|&i|w[i]).collect()}


fn state_hex(z:&[F])->Vec<String>{z.iter().map(|x|x.to_repr().as_ref().iter().map(|b|format!("{b:02x}")).collect::<String>()).collect()}
fn main(){
 let args:Vec<String>=std::env::args().collect();assert_eq!(args.len(),3,"usage: dependent fixture-dir output-dir");
 let dir=&args[1];let output=&args[2];std::fs::create_dir_all(output).unwrap();
 // The matrix is a trusted build artifact from the checked-in generator, never
 // an untrusted prover input. Production verifier pins an independent matrix/VK.
 let bytes=std::fs::read(format!("{dir}/matrix.json")).unwrap();assert!(bytes.len()<128<<20);
 let f:Fixture=serde_json::from_slice(&bytes).unwrap();drop(bytes);
 assert_eq!(f.schema,"zkl-nova-11/auth-v1");
 let q=&f.summary;assert_eq!(q["mode"],"full");
 for (k,v) in [("depth",D),("steps",STEPS),("matrices_checked",STEPS),("constraints",MATRIX_ROWS),("wires",MATRIX_WIRES),("nonzeros",718374),("hashes",84),("hash_constraints",26208)]{
  assert_eq!(q[k].as_u64().unwrap(),v as u64);
 }
 assert_eq!(q["state_ids"],json!(PUB));assert_eq!(q["goal"],json!(["P",["S",1],["P",["B",0],["B",1]]]));
 for (k,v) in [("node_domain",NODE),("leaf_domain",LEAF),("term_domain",TERM)]{assert_eq!(scalar(q[k].as_str().unwrap()),F::from(v));}
 assert_eq!(q["node_vector"],NODE_VECTOR);assert_eq!(q["leaf_vector"],LEAF_VECTOR);
 assert_eq!(native_hash(NODE,&[F::from(19),F::from(42)]),scalar(NODE_VECTOR));
 assert_eq!(native_hash(LEAF,&[F::from(123),F::from(456),F::from(789)]),scalar(LEAF_VECTOR));
 let z0=genesis();assert_eq!(q["goal_digest"],GOAL);
 let states:Vec<Vec<F>>=f.states.iter().map(|z|z.iter().map(|s|scalar(s)).collect()).collect();
 assert_eq!(states.len(),STEPS+1);assert_eq!(states[0],z0);assert_eq!(states[STEPS][0],scalar(FINAL_ROOT));
 assert_eq!(f.rows.len(),MATRIX_ROWS);
 let mut nnz=0;
 let matrix:Arc<Vec<Row>>=Arc::new(f.rows.into_iter().map(|r|r.map(|l|{
  let mut prev=None;l.into_iter().map(|(i,v)|{
   assert!(i<MATRIX_WIRES&&prev.map_or(true,|j|j<i));prev=Some(i);
   let v=scalar(&v);assert_ne!(v,F::ZERO);nnz+=1;(i,v)
  }).collect()
 })).collect());assert_eq!(nnz,718374);
 let mut steps=Vec::with_capacity(STEPS);
 for i in 0..STEPS{
  let raw=std::fs::read(format!("{dir}/step-{i}.json")).unwrap();assert!(raw.len()<4<<20);
  let w:Vec<String>=serde_json::from_slice(&raw).unwrap();
  let w:Vec<F>=w.iter().map(|s|scalar(s)).collect();assert_eq!(w.len(),MATRIX_WIRES);assert_eq!(w[0],F::ONE);
  let step=DependentStep{matrix:matrix.clone(),assignment:Arc::new(w)};
  assert_eq!(endpoint(&step.assignment,0),states[i]);assert_eq!(endpoint(&step.assignment,4),states[i+1]);
  assert_eq!(checked_step(&step,&states[i]),(true,states[i+1].clone(),STEP_ROWS));
  assert!(!admitted(&states[i],i,z0[2]));steps.push(step);
 }
 assert!(admitted(&states[STEPS],STEPS,z0[2]));
 let mut malformed=0;
 for i in 0..ARITY{
  let mut z=z0.clone();z[i]+=F::ONE;assert!(!checked_step(&steps[0],&z).0);malformed+=1;
 }
 assert!(!checked_step(&steps[STEPS-1],&states[STEPS]).0);malformed+=1;
 let mut bad=steps[STEPS-1].clone();
 Arc::make_mut(&mut bad.assignment)[PUB[4]]+=F::ONE;
 assert!(!checked_step(&bad,&states[STEPS-1]).0);malformed+=1;
 eprintln!("native goal/genesis/leaf parity and 52 assignment checks; {STEP_ROWS} explicit constraints");
 let t=Instant::now();let pp=Pp::setup(&steps[0],&*S1::ck_floor(),&*S2::ck_floor()).unwrap();
 let setup=t.elapsed().as_secs_f64();let(primary,secondary)=pp.num_constraints();
 let t=Instant::now();let mut rs=Rs::new(&pp,&steps[0],&z0).unwrap();let init=t.elapsed().as_secs_f64();
 let mut times=vec![];
 for(i,step)in steps.iter().enumerate(){
  let t=Instant::now();rs.prove_step(&pp,step).unwrap();times.push(t.elapsed().as_secs_f64());
  if i%8==0||i==STEPS-1{eprintln!("fold {}/{}: {:.3}s",i+1,STEPS,times[i]);}
  if i==STEPS-2{let end=rs.verify(&pp,i+1,&z0).unwrap();assert_eq!(end,states[i+1]);assert!(!admitted(&end,i+1,z0[2]));}
 }
 let t=Instant::now();let end=rs.verify(&pp,STEPS,&z0).unwrap();let verify=t.elapsed().as_secs_f64();
 assert_eq!(end,states[STEPS]);assert!(admitted(&end,STEPS,z0[2]));
 let recursive_bytes=bincode::serialized_size(&rs).unwrap();
 let mut rejected=0;
 for i in 0..ARITY{let mut z=z0.clone();z[i]+=F::ONE;assert!(rs.verify(&pp,STEPS,&z).is_err());rejected+=1;}
 for n in [STEPS-1,STEPS+1]{assert!(rs.verify(&pp,n,&z0).is_err());rejected+=1;}
 let t=Instant::now();let(pk,vk)=Cs::setup(&pp).unwrap();let compression_setup=t.elapsed().as_secs_f64();
 let t=Instant::now();let proof=Cs::prove(&pp,&pk,&rs).unwrap();let compression=t.elapsed().as_secs_f64();
 let t=Instant::now();let compressed_end=proof.verify(&vk,STEPS,&z0).unwrap();let compressed_verify=t.elapsed().as_secs_f64();
 assert_eq!(compressed_end,end);assert!(admitted(&compressed_end,STEPS,z0[2]));
 let proof_bytes=bincode::serialize(&proof).unwrap();let vk_bytes=bincode::serialize(&vk).unwrap();
 let restored:Cs=bincode::deserialize(&proof_bytes).unwrap();let restored_vk:Cvk=bincode::deserialize(&vk_bytes).unwrap();
 assert_eq!(restored.verify(&restored_vk,STEPS,&z0).unwrap(),end);
 let mut compressed_rejections=0;
 for i in 0..ARITY{let mut z=z0.clone();z[i]+=F::ONE;assert!(restored.verify(&restored_vk,STEPS,&z).is_err());compressed_rejections+=1;}
 for n in [STEPS-1,STEPS+1]{assert!(restored.verify(&restored_vk,n,&z0).is_err());compressed_rejections+=1;}
 std::fs::write(format!("{output}/dependent.compressed.bin"),&proof_bytes).unwrap();
 std::fs::write(format!("{output}/dependent.vk.bin"),&vk_bytes).unwrap();
 println!("{}",serde_json::to_string_pretty(&json!({
 "passed":true,"scope":"bounded dependent calculus of constructions; no Lean or hiding claim",
 "steps":STEPS,"step_constraints":STEP_ROWS,"primary_constraints":primary,"secondary_constraints":secondary,
 "malformed_steps_rejected":malformed,"unsealed_prefix_refused":true,"recursive_verifier_rejections":rejected,
 "compressed_verifier_rejections":compressed_rejections,"native_hash_goal_and_genesis_parity":true,
 "setup_seconds":setup,"init_seconds":init,"fold_seconds":times,"verify_seconds":verify,"recursive_bytes":recursive_bytes,
 "compression_setup_seconds":compression_setup,"compression_seconds":compression,"compressed_verify_seconds":compressed_verify,
 "compressed_bytes":proof_bytes.len(),"vk_bytes":vk_bytes.len(),"serialization_roundtrip":true,
 "initial_state_le_hex":state_hex(&z0),"terminal_state_le_hex":state_hex(&end)
 })).unwrap());
}
