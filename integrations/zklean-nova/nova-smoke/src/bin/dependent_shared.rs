//! ZKL-NOVA-13: shared-path depth-nine dependent theorem circuit.
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
const D:usize=9;
const ARITY:usize=4;

const MATRIX_ROWS:usize=36671;
const MATRIX_WIRES:usize=35736;
const STEP_ROWS:usize=MATRIX_ROWS+2*ARITY;
const MODULUS:&str="28948022309329048855892746252171976963363056481941647379679742748393362948097";
const ROOT:&str="13933911177787379986778340178665794420387159831411262822706660853453592611501";
const NODE_VECTOR:&str="14114214179916697404878619261192913361145130603274328369933284479456013695164";
const LEAF_VECTOR:&str="10002637170120463377809397913605476821031046123563835871351888133954241573199";
const NODE:u64=6506377860829105743;
const LEAF:u64=6506377860829105222;
const TERM:u64=6506377860829107200;
const PUB:[usize;8]=[2743,1,2744,2745,2746,2747,2748,2749];
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

const CASES:[(&str,usize,&str);4]=[
 ("polymorphic_identity",52,r#"["P",["S",1],["P",["B",0],["B",1]]]"#),
 ("dependent_application",340,r#"["P",["S",1],["P",["P",["B",0],["S",1]],["P",["P",["B",1],["A",["B",1],["B",0]]],["P",["B",2],["A",["B",2],["B",0]]]]]]"#),
 ("beta_conversion",276,r#"["P",["S",1],["P",["A",["L",["S",1],["B",0]],["B",0]],["B",1]]]"#),
 ("impredicative_predicate_identity",289,r#"["P",["S",1],["P",["P",["B",0],["S",0]],["P",["B",1],["P",["A",["B",1],["B",0]],["A",["B",2],["B",1]]]]]]"#)
];
fn goal_digest(ast:&Value)->F {
 let a=ast.as_array().expect("term AST");
 let tag=a[0].as_str().unwrap();
 let code=match tag{"S"=>1,"B"=>2,"F"=>3,"P"=>4,"L"=>5,"A"=>6,_=>panic!("unsupported term")};
 if code<=3 {assert_eq!(a.len(),2);native_hash(TERM+code,&[F::from(a[1].as_u64().unwrap()),F::ZERO])}
 else {assert_eq!(a.len(),3);native_hash(TERM+code,&[goal_digest(&a[1]),goal_digest(&a[2])])}
}
fn genesis(goal:F)->Vec<F>{
 let mut root=F::ZERO;for _ in 0..D{root=native_hash(NODE,&[root,root]);}
 assert_eq!(root,scalar(ROOT));vec![root,F::ZERO,goal,F::ZERO]
}
fn admitted(z:&[F],steps:usize,goal:F)->bool{
 z.len()==ARITY&&steps>0&&steps<=(1<<D)&&z[1]==F::from(steps as u64)&&z[2]==goal&&z[3]==F::ONE
}
type Term=(usize,F);
type Row=[Vec<Term>;3];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture{schema:String,summary:Value,rows:Vec<[Vec<(usize,String)>;3]>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case{info:Value,states:Vec<Vec<String>>}
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

fn read_step(dir:&str,name:&str,i:usize,matrix:&Arc<Vec<Row>>)->DependentStep{
 let raw=std::fs::read(format!("{dir}/{name}-{i}.bin")).unwrap();
 assert_eq!(raw.len(),MATRIX_WIRES*32);
 let w:Vec<F>=raw.chunks_exact(32).map(|x|{
  let mut r=<F as PrimeField>::Repr::default();r.as_mut().copy_from_slice(x);
  Option::<F>::from(F::from_repr(r)).expect("noncanonical scalar")
 }).collect();
 assert_eq!(w[0],F::ONE);
 DependentStep{matrix:matrix.clone(),assignment:Arc::new(w)}
}
fn main(){
 let args:Vec<String>=std::env::args().collect();assert_eq!(args.len(),3,"usage: dependent_shared fixture-dir output-dir");
 let dir=&args[1];let output=&args[2];std::fs::create_dir_all(output).unwrap();
 // Only a verifier-generated matrix is admitted; do not use an untrusted prover matrix.
 let bytes=std::fs::read(format!("{dir}/matrix.json")).unwrap();assert!(bytes.len()<128<<20);
 let f:Fixture=serde_json::from_slice(&bytes).unwrap();drop(bytes);
 assert_eq!(f.schema,"zkl-nova-13/shared-auth-v1");
 let q=&f.summary;
 for(k,v)in[("depth",D),("constraints",MATRIX_ROWS),("wires",MATRIX_WIRES),("nonzeros",897078),("hashes",95),("hash_constraints",29640)]{assert_eq!(q[k].as_u64().unwrap(),v as u64);}
 assert_eq!(q["state_ids"],json!(PUB));
 for(k,v)in[("node_domain",NODE),("leaf_domain",LEAF),("term_domain",TERM)]{assert_eq!(scalar(q[k].as_str().unwrap()),F::from(v));}
 assert_eq!(q["node_vector"],NODE_VECTOR);assert_eq!(q["leaf_vector"],LEAF_VECTOR);
 assert_eq!(native_hash(NODE,&[F::from(19),F::from(42)]),scalar(NODE_VECTOR));
 assert_eq!(native_hash(LEAF,&[F::from(123),F::from(456),F::from(789)]),scalar(LEAF_VECTOR));
 assert_eq!(f.rows.len(),MATRIX_ROWS);let mut nnz=0;
 let matrix:Arc<Vec<Row>>=Arc::new(f.rows.into_iter().map(|r|r.map(|l|{
  let mut prev=None;l.into_iter().map(|(i,v)|{
   assert!(i<MATRIX_WIRES&&prev.map_or(true,|j|j<i));prev=Some(i);
   let v=scalar(&v);assert_ne!(v,F::ZERO);nnz+=1;(i,v)
  }).collect()
 })).collect());assert_eq!(nnz,897078);
 let first=read_step(dir,CASES[0].0,0,&matrix);
 let t=Instant::now();let pp=Pp::setup(&first,&*S1::ck_floor(),&*S2::ck_floor()).unwrap();let setup=t.elapsed().as_secs_f64();
 let(primary,secondary)=pp.num_constraints();
 let t=Instant::now();let(pk,vk)=Cs::setup(&pp).unwrap();let compression_setup=t.elapsed().as_secs_f64();
 let vk_bytes=bincode::serialize(&vk).unwrap();let restored_vk:Cvk=bincode::deserialize(&vk_bytes).unwrap();
 std::fs::write(format!("{output}/shared.vk.bin"),&vk_bytes).unwrap();
 eprintln!("shared setup {setup:.3}s; primary {primary}; secondary {secondary}; VK {} bytes",vk_bytes.len());
 let mut results=vec![];let mut total=0;
 for(case_index,(name,steps,ast))in CASES.iter().copied().enumerate(){
  let goal_ast:Value=serde_json::from_str(ast).unwrap();let goal=goal_digest(&goal_ast);
  let z0=genesis(goal);
  let f:Case=serde_json::from_slice(&std::fs::read(format!("{dir}/{name}.json")).unwrap()).unwrap();
  assert_eq!(f.info["name"],name);assert_eq!(f.info["steps"].as_u64().unwrap(),steps as u64);
  assert_eq!(f.info["matrices_checked"].as_u64().unwrap(),steps as u64);
  assert_eq!(f.info["goal"],goal_ast);assert_eq!(scalar(f.info["goal_digest"].as_str().unwrap()),goal);
  let states:Vec<Vec<F>>=f.states.iter().map(|z|z.iter().map(|s|scalar(s)).collect()).collect();
  assert_eq!(states.len(),steps+1);assert_eq!(states[0],z0);assert!(admitted(&states[steps],steps,goal));
  let step0=read_step(dir,name,0,&matrix);
  let t=Instant::now();let mut rs=Rs::new(&pp,&step0,&z0).unwrap();let init=t.elapsed().as_secs_f64();
  let mut times=Vec::with_capacity(steps);let mut malformed=0;
  for i in 0..steps{
   let step=read_step(dir,name,i,&matrix);
   assert_eq!(endpoint(&step.assignment,0),states[i]);assert_eq!(endpoint(&step.assignment,4),states[i+1]);
   assert_eq!(checked_step(&step,&states[i]),(true,states[i+1].clone(),STEP_ROWS));
   assert!(!admitted(&states[i],i,goal));
   if i==steps-1 {
    let mut bad=step.clone();Arc::make_mut(&mut bad.assignment)[PUB[4]]+=F::ONE;
    assert!(!checked_step(&bad,&states[i]).0);malformed+=1;
    assert!(!checked_step(&step,&states[i+1]).0);malformed+=1;
   }
   let t=Instant::now();rs.prove_step(&pp,&step).unwrap();times.push(t.elapsed().as_secs_f64());
   if i%32==0||i==steps-1{eprintln!("{name}: fold {}/{}: {:.3}s",i+1,steps,times[i]);}
   if i==steps-2{let end=rs.verify(&pp,i+1,&z0).unwrap();assert_eq!(end,states[i+1]);assert!(!admitted(&end,i+1,goal));}
  }
  let t=Instant::now();let end=rs.verify(&pp,steps,&z0).unwrap();let verify=t.elapsed().as_secs_f64();
  assert_eq!(end,states[steps]);assert!(admitted(&end,steps,goal));
  let recursive_bytes=bincode::serialized_size(&rs).unwrap();
  let t=Instant::now();let proof=Cs::prove(&pp,&pk,&rs).unwrap();let compression=t.elapsed().as_secs_f64();
  let t=Instant::now();let compressed_end=proof.verify(&vk,steps,&z0).unwrap();let compressed_verify=t.elapsed().as_secs_f64();
  assert_eq!(compressed_end,end);assert!(admitted(&compressed_end,steps,goal));
  let proof_bytes=bincode::serialize(&proof).unwrap();let restored:Cs=bincode::deserialize(&proof_bytes).unwrap();
  assert_eq!(restored.verify(&restored_vk,steps,&z0).unwrap(),end);
  let mut recursive_rejections=0;let mut compressed_rejections=0;
  let other:Value=serde_json::from_str(CASES[(case_index+1)%CASES.len()].2).unwrap();let other=goal_digest(&other);assert_ne!(goal,other);
  for i in 0..ARITY{
   let mut z=z0.clone();if i==2{z[i]=other;}else{z[i]+=F::ONE;}
   assert!(rs.verify(&pp,steps,&z).is_err());recursive_rejections+=1;
   assert!(restored.verify(&restored_vk,steps,&z).is_err());compressed_rejections+=1;
  }
  for n in [steps-1,steps+1]{
   assert!(rs.verify(&pp,n,&z0).is_err());recursive_rejections+=1;
   assert!(restored.verify(&restored_vk,n,&z0).is_err());compressed_rejections+=1;
  }
  std::fs::write(format!("{output}/{name}.compressed.bin"),&proof_bytes).unwrap();
  let mean=times.iter().skip(1).sum::<f64>()/(steps-1) as f64;
  let receipt=json!({"name":name,"steps":steps,"goal":goal_ast,"initial_state_le_hex":state_hex(&z0),"terminal_state_le_hex":state_hex(&end),
   "passed":true,"unsealed_prefix_refused":true,"malformed_steps_rejected":malformed,
   "recursive_verifier_rejections":recursive_rejections,"compressed_verifier_rejections":compressed_rejections,
   "init_seconds":init,"fold_seconds":times,"mean_steady_fold_seconds":mean,"verify_seconds":verify,
   "recursive_bytes":recursive_bytes,"compression_seconds":compression,"compressed_verify_seconds":compressed_verify,
   "compressed_bytes":proof_bytes.len(),"serialization_roundtrip":true});
  std::fs::write(format!("{output}/{name}.receipt.json"),serde_json::to_string_pretty(&receipt).unwrap()+"\n").unwrap();
  total+=steps;results.push(receipt);
 }
 assert_eq!(total,957);
 println!("{}",serde_json::to_string_pretty(&json!({
 "passed":true,"scope":"four bounded dependent-calculus proofs with shared-path memory; no Lean or hiding claim",
 "depth":D,"steps":total,"proofs":results,"matrix_constraints":MATRIX_ROWS,"step_constraints":STEP_ROWS,
 "primary_constraints":primary,"secondary_constraints":secondary,"shared_vk":true,"vk_bytes":vk_bytes.len(),
 "setup_seconds":setup,"compression_setup_seconds":compression_setup,"native_hash_parity":true
 })).unwrap());
}
