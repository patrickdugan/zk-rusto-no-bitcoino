//! ZKL-NOVA-08: fixed-matrix recursive admission for a small implicational calculus.
//! The matrix is generated from verifier-owned source. No privacy or Lean compatibility claim.
use ff::{Field,PrimeField};
use generic_array::typenum::U5;
use nova_snark::{
 frontend::{gadgets::poseidon::{IOPattern,PoseidonConstants,Simplex,Sponge,SpongeAPI,SpongeOp,SpongeTrait,Strength},
 num::AllocatedNum,ConstraintSystem,Index,LinearCombination,SynthesisError,Variable},
 nova::{PublicParams,RecursiveSNARK,CompressedSNARK},provider::{ipa_pc::EvaluationEngine,PallasEngine,VestaEngine},
 spartan::snark::RelaxedR1CSSNARK,traits::{circuit::StepCircuit,snark::RelaxedR1CSSNARKTrait,Engine},
};
use serde::Deserialize;
use serde_json::json;
use std::{sync::{Arc,OnceLock},time::Instant};
type F=<PallasEngine as Engine>::Scalar;
type E1=PallasEngine;
type E2=VestaEngine;
type S1=RelaxedR1CSSNARK<E1,EvaluationEngine<E1>>;
type S2=RelaxedR1CSSNARK<E2,EvaluationEngine<E2>>;
type Pp=PublicParams<E1,E2,TheoremStep>;
type Rs=RecursiveSNARK<E1,E2,TheoremStep>;
const D:usize=4;
const ARITY:usize=5;
const STEPS:usize=12;
const MATRIX_ROWS:usize=11023;
const MATRIX_WIRES:usize=10947;
const STEP_ROWS:usize=MATRIX_ROWS+2*ARITY;
const MODULUS:&str="28948022309329048855892746252171976963363056481941647379679742748393362948097";
const GENESIS_ROOT:&str="8292702296760616536293423984468546471320845560884722282801420769833046234621";
const TERMINAL_ROOT:&str="1428547338094671197299858150693881127055436017647795909497136294511328706173";
const NODE_VECTOR:&str="3189450979416672123379718128033158450810174494458308961147039301746121343378";
const LEAF_VECTOR:&str="22482925955085351129646725282763735243085702619100849070227720007972990456435";
const NODE:u64=0x5a4b4c30352f4e4f;
const LEAF:u64=0x5a4b4c30372f4c46;
const PUB:[usize;10]=[1,2,3,4,5,6,7,8,9,10];
fn scalar(s:&str)->F {
 assert!(!s.is_empty()&&s.bytes().all(|x|x.is_ascii_digit()));
 assert!(s=="0"||!s.starts_with('0'));
 assert!(s.len()<MODULUS.len()||(s.len()==MODULUS.len()&&s<MODULUS));
 s.bytes().fold(F::ZERO,|a,b|a*F::from(10)+(F::from((b-b'0') as u64)))
}
fn native_hash(domain:u64,a:F,b:F)->F {
 static C:OnceLock<PoseidonConstants<F,U5>>=OnceLock::new();
 let constants=C.get_or_init(||Sponge::<F,U5>::api_constants(Strength::Standard));
 let mut sponge=Sponge::new_with_constants(constants,Simplex);let acc=&mut ();
 sponge.start(IOPattern(vec![SpongeOp::Absorb(3),SpongeOp::Squeeze(1)]),None,acc);
 SpongeAPI::absorb(&mut sponge,3,&[F::from(domain),a,b],acc);
 let out=SpongeAPI::squeeze(&mut sponge,1,acc);sponge.finish(acc).unwrap();out[0]
}
fn genesis()->Vec<F>{
 let rows:[[u64;5];4]=[[0,0,0,0,0],[1,0,0,0,0],[1,1,1,0,0],[2,0,0,0,0]];
 let mut layer=vec![F::ZERO;1<<D];
 for (i,r) in rows.iter().enumerate(){
  let v=r.iter().enumerate().fold((i as u64)<<20,|a,(j,x)|a+(*x<<(4*j)));
  layer[i]=native_hash(LEAF,F::from(v),F::from(i as u64+101));
 }
 assert_eq!(layer[0],scalar(LEAF_VECTOR));
 for _ in 0..D {layer=layer.chunks_exact(2).map(|x|native_hash(NODE,x[0],x[1])).collect();}
 assert_eq!(layer[0],scalar(GENESIS_ROOT));
 vec![layer[0],F::from(4),F::ONE,F::from(3),F::ZERO]
}
// Admission permits any correctly authenticated terminal root, not just the
// deterministic fixture root. The fixture root is a separate regression check.
fn admitted(z:&[F],steps:usize)->bool {
 z.len()==ARITY&&steps>0&&steps<=STEPS&&z[1]==F::from((4+steps) as u64)&&z[2]==F::ONE&&z[3]==F::from(3)&&z[4]==F::ONE
}
type Term=(usize,F);
type Row=[Vec<Term>;3];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Summary {constraints:usize,wires:usize,hashes:usize,hash_constraints:usize,nonzeros:usize}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {name:String,step:usize,assignment:Vec<String>,valid_relation:bool}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
 schema:String,#[serde(rename="D")] d:usize,goal:usize,empty:usize,node_domain:String,leaf_domain:String,
 node_vector:String,leaf_vector:String,public_ids:Vec<usize>,states:Vec<Vec<String>>,summary:Summary,
 rows:Vec<[Vec<(usize,String)>;3]>,assignments:Vec<Vec<String>>,controls:Vec<Control>,corrupt_wire:usize
}
#[derive(Clone)]
struct TheoremStep {matrix:Arc<Vec<Row>>,assignment:Arc<Vec<F>>}
impl StepCircuit<F> for TheoremStep {
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
fn checked_step(step:&TheoremStep,z:&[F])->(bool,Vec<F>,usize){
    let mut cs=CheckCS::new();
    let inp:Vec<_>=z.iter().enumerate().map(|(i,x)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*x)).collect();
    let out=step.synthesize(&mut cs,&inp).unwrap().iter().map(|x|x.get_value().unwrap()).collect();
    (cs.failed.is_none(),out,cs.n)
}


fn endpoint(w:&[F],start:usize)->Vec<F>{PUB[start..start+ARITY].iter().map(|&i|w[i]).collect()}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Variant { name:String,goal:usize,states:Vec<Vec<String>>,assignments:Vec<Vec<String>> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Variants { schema:String,public_ids:Vec<usize>,summary:Summary,variants:Vec<Variant>,atom_goal_rejected:bool }

type Cs=CompressedSNARK<E1,E2,TheoremStep,S1,S2>;
type Cvk=nova_snark::nova::VerifierKey<E1,E2,TheoremStep,S1,S2>;

fn state_le_hex(z:&[F])->Vec<String>{
 z.iter().map(|x|x.to_repr().as_ref().iter().map(|b|format!("{b:02x}")).collect::<String>()).collect()
}
fn admitted_for(z:&[F],steps:usize,goal:usize)->bool{
 (goal==1||goal==2)&&z.len()==ARITY&&steps>0&&steps<=STEPS&&
 z[1]==F::from((4+steps) as u64)&&z[2]==F::from(goal as u64)&&z[3]==F::from(3)&&z[4]==F::ONE
}
fn compression(pp:&Pp,long:&Rs,z0:&[F],zn:&[F],prefix_bytes:&[u8],matrix:Arc<Vec<Row>>,variants_path:&str,output:&str)->serde_json::Value{
 let raw=std::fs::read(variants_path).unwrap();assert!(raw.len()<16<<20);
 let f:Variants=serde_json::from_slice(&raw).unwrap();assert_eq!(f.schema,"zkl-nova-09/variants-v1");
 assert_eq!(f.public_ids.as_slice(),&PUB);assert!(f.atom_goal_rejected);
 assert_eq!((f.summary.constraints,f.summary.wires,f.summary.hashes,f.summary.hash_constraints,f.summary.nonzeros),(MATRIX_ROWS,MATRIX_WIRES,34,10608,285971));
 assert_eq!(f.variants.len(),2);
 std::fs::create_dir_all(output).unwrap();
 let t=Instant::now();let(pk,vk)=Cs::setup(pp).unwrap();let setup=t.elapsed().as_secs_f64();
 let vk_bytes=bincode::serialize(&vk).unwrap();
 let decoded_vk:Cvk=bincode::deserialize(&vk_bytes).unwrap();
 std::fs::write(format!("{output}/compressed_vk.bin"),&vk_bytes).unwrap();
 eprintln!("Spartan setup: {setup:.3}s, VK {} bytes",vk_bytes.len());
 let compress_one=|name:&str,rs:&Rs,initial:&[F],expected:&[F],steps:usize,goal:usize,accept:bool|{
  assert_eq!(admitted_for(expected,steps,goal),accept);
  let t=Instant::now();let proof=Cs::prove(pp,&pk,rs).unwrap();let prove=t.elapsed().as_secs_f64();
  let t=Instant::now();let end=proof.verify(&vk,steps,initial).unwrap();let verify=t.elapsed().as_secs_f64();
  assert_eq!(end.as_slice(),expected);assert_eq!(admitted_for(&end,steps,goal),accept);
  let bytes=bincode::serialize(&proof).unwrap();let decoded:Cs=bincode::deserialize(&bytes).unwrap();
  assert_eq!(decoded.verify(&decoded_vk,steps,initial).unwrap(),end);
  let mut rejections=0;
  for i in 0..ARITY {
   let mut z=initial.to_vec();
   // At the goal coordinate, substitute the other valid theorem statement.
   if i==2{z[i]=F::from(if goal==1{2}else{1});}else{z[i]+=F::ONE;}
   assert!(decoded.verify(&decoded_vk,steps,&z).is_err(),"changed initial statement accepted: {name}/{i}");
   rejections+=1;
  }
  for count in [steps-1,steps+1] {
   assert!(decoded.verify(&decoded_vk,count,initial).is_err(),"changed step count accepted");
   rejections+=1;
  }
  std::fs::write(format!("{output}/{name}.compressed.bin"),&bytes).unwrap();
  let recursive_bytes=bincode::serialized_size(rs).unwrap();
  eprintln!("{name}: {steps} steps, {} bytes, compress {prove:.3}s, verify {verify:.3}s, admitted {accept}",bytes.len());
  json!({"name":name,"goal":goal,"steps":steps,"cryptographic_verify":true,"admitted":accept,
   "initial_state_le_hex":state_le_hex(initial),"terminal_state_le_hex":state_le_hex(&end),
   "compression_seconds":prove,"verify_seconds":verify,"recursive_bytes_bincode":recursive_bytes,
   "compressed_bytes_bincode":bytes.len(),"compression_ratio":recursive_bytes as f64 / bytes.len() as f64,
   "verifier_rejections":rejections,"proof_and_vk_serialization_roundtrip":true})
 };
 let mut rows=vec![compress_one("long_identity",long,z0,zn,STEPS,1,true)];
 // A genuine cryptographically valid compressed prefix must still fail theorem admission.
 let prefix:Rs=bincode::deserialize(prefix_bytes).unwrap();
 let prefix_end=prefix.verify(pp,STEPS-1,z0).unwrap();
 assert!(!admitted_for(&prefix_end,STEPS-1,1));
 rows.push(compress_one("unsealed_prefix",&prefix,z0,&prefix_end,STEPS-1,1,false));
 for (j,v) in f.variants.into_iter().enumerate() {
  let goal=j+1;
  assert_eq!(v.goal,goal);assert_eq!(v.name,["short_identity","higher_identity"][j]);
  let states:Vec<Vec<F>>=v.states.iter().map(|z|z.iter().map(|s|scalar(s)).collect()).collect();
  assert_eq!(states.len(),5);assert_eq!(v.assignments.len(),4);
  let mut initial=genesis();initial[2]=F::from(goal as u64);assert_eq!(states[0],initial);
  let steps:Vec<TheoremStep>=v.assignments.into_iter().map(|w|{
   let w:Vec<_>=w.iter().map(|s|scalar(s)).collect();assert_eq!(w.len(),MATRIX_WIRES);assert_eq!(w[0],F::ONE);
   TheoremStep{matrix:matrix.clone(),assignment:Arc::new(w)}
  }).collect();
  for i in 0..4{
   assert_eq!(endpoint(&steps[i].assignment,0),states[i]);assert_eq!(endpoint(&steps[i].assignment,5),states[i+1]);
   assert_eq!(checked_step(&steps[i],&states[i]),(true,states[i+1].clone(),STEP_ROWS));
   assert!(!admitted_for(&states[i],i,goal));
  }
  let t=Instant::now();let mut rs=Rs::new(pp,&steps[0],&initial).unwrap();
  for step in &steps{rs.prove_step(pp,step).unwrap();}
  let fold=t.elapsed().as_secs_f64();
  let end=rs.verify(pp,4,&initial).unwrap();assert_eq!(end,states[4]);assert!(admitted_for(&end,4,goal));
  let mut row=compress_one(&v.name,&rs,&initial,&end,4,goal,true);
  row["variant_fold_including_init_seconds"]=json!(fold);rows.push(row);
 }
 json!({"passed":true,"scheme":"Nova 0.76 Spartan/IPA on Pallas/Vesta",
 "scope":"restricted implicational calculus; no privacy claim","compression_setup_seconds":setup,
 "compressed_vk_bytes_bincode":vk_bytes.len(),"shared_vk":true,"cases":rows,
 "admitted_theorem_proofs":3,"cryptographically_valid_unsealed_prefix_refused":1,
 "changed_statement_or_count_rejections":28})
}

fn main(){
 // Trust boundary: this file must come from the verifier's pinned generator,
 // never a remote prover. Matrix contents define the statement being proved.
 let args:Vec<String>=std::env::args().collect();
 assert!(args.len()==2||args.len()==4,"usage: theorem trusted-admission-fixture.json [variants.json output-dir]");
 let path=&args[1];
 let compress=args.len()==4;
 let raw=std::fs::read(path).unwrap();assert!(raw.len()<64<<20);
 let f:Fixture=serde_json::from_slice(&raw).unwrap();
 assert_eq!(f.schema,"zkl-nova-08/admission-matrix-v1");assert_eq!((f.d,f.goal,f.empty),(D,1,3));
 assert_eq!(scalar(&f.node_domain),F::from(NODE));assert_eq!(scalar(&f.leaf_domain),F::from(LEAF));
 assert_eq!(scalar(&f.node_vector),scalar(NODE_VECTOR));assert_eq!(scalar(&f.leaf_vector),scalar(LEAF_VECTOR));
 assert_eq!(native_hash(NODE,F::from(19),F::from(42)),scalar(NODE_VECTOR));
 let z0=genesis();
 assert_eq!(f.public_ids.as_slice(),&PUB);
 assert_eq!((f.summary.constraints,f.summary.wires,f.summary.hashes,f.summary.hash_constraints,f.summary.nonzeros),(MATRIX_ROWS,MATRIX_WIRES,34,10608,285971));
 assert_eq!(f.rows.len(),MATRIX_ROWS);let mut nnz=0;
 let matrix:Arc<Vec<Row>>=Arc::new(f.rows.into_iter().map(|r|r.map(|l|{
  let mut prev=None;l.into_iter().map(|(i,v)|{
   assert!(i<MATRIX_WIRES&&prev.map_or(true,|j|j<i));prev=Some(i);
   let v=scalar(&v);assert_ne!(v,F::ZERO);nnz+=1;(i,v)
  }).collect()
 })).collect());
 assert_eq!(nnz,285971);
 let states:Vec<Vec<F>>=f.states.iter().map(|z|z.iter().map(|s|scalar(s)).collect()).collect();
 assert_eq!(states.len(),STEPS+1);assert_eq!(states[0],z0);assert_eq!(states[STEPS][0],scalar(TERMINAL_ROOT));
 let parse=|w:Vec<String>|{
  let w:Vec<_>=w.iter().map(|s|scalar(s)).collect();assert_eq!(w.len(),MATRIX_WIRES);assert_eq!(w[0],F::ONE);
  TheoremStep{matrix:matrix.clone(),assignment:Arc::new(w)}
 };
 assert_eq!(f.assignments.len(),STEPS);let steps:Vec<_>=f.assignments.into_iter().map(&parse).collect();
 for i in 0..STEPS {
  assert_eq!(endpoint(&steps[i].assignment,0),states[i]);assert_eq!(endpoint(&steps[i].assignment,5),states[i+1]);
  assert_eq!(checked_step(&steps[i],&states[i]),(true,states[i+1].clone(),STEP_ROWS));
  assert!(!admitted(&states[i],i));
 }
 assert!(admitted(&states[STEPS],STEPS));
 let mut malformed=0;let mut admission_rejections=0;
 assert_eq!(f.controls.len(),3);
 for (i,control) in f.controls.into_iter().enumerate(){
  assert_eq!(control.name,["unsealed_terminal","wrong_goal","wrong_append_root"][i]);assert_eq!(control.step,STEPS-1);
  assert_eq!(control.valid_relation,i==0);
  let step=parse(control.assignment);let state=endpoint(&step.assignment,0);
  let (ok,out,rows)=checked_step(&step,&state);assert_eq!(rows,STEP_ROWS);assert_eq!(ok,control.valid_relation);
  if ok {assert!(!admitted(&out,STEPS));admission_rejections+=1;}else{malformed+=1;}
 }
 let mut bad=steps[0].clone();assert!(f.corrupt_wire>10&&f.corrupt_wire<MATRIX_WIRES);
 Arc::make_mut(&mut bad.assignment)[f.corrupt_wire]+=F::ONE;
 assert!(!checked_step(&bad,&z0).0);malformed+=1;
 for (step,state) in [(&steps[0],&states[1]),(&steps[1],&z0),(&steps[STEPS-1],&states[STEPS])]{
  assert!(!checked_step(step,state).0);malformed+=1;
 }
 for i in 0..ARITY{
  let mut z=z0.clone();z[i]+=F::ONE;assert!(!checked_step(&steps[0],&z).0);malformed+=1;
 }
 eprintln!("native hash/genesis parity; {STEP_ROWS} explicit constraints; {malformed} malformed assignments refused");
 let t=Instant::now();let pp=Pp::setup(&steps[0],&*S1::ck_floor(),&*S2::ck_floor()).unwrap();
 let setup=t.elapsed().as_secs_f64();let (primary,secondary)=pp.num_constraints();
 let t=Instant::now();let mut rs=Rs::new(&pp,&steps[0],&z0).unwrap();
 let init=t.elapsed().as_secs_f64();let mut times=vec![];let mut prefix_bytes=Vec::new();
 for (i,s) in steps.iter().enumerate(){
  let t=Instant::now();rs.prove_step(&pp,s).unwrap();times.push(t.elapsed().as_secs_f64());
  eprintln!("fold {}/{}: {:.3}s",i+1,STEPS,times[i]);
  if i==STEPS-2 {
   let prefix=rs.verify(&pp,i+1,&z0).unwrap();
   assert_eq!(prefix,states[i+1]);assert!(!admitted(&prefix,i+1));admission_rejections+=1;
   if compress {prefix_bytes=bincode::serialize(&rs).unwrap();}
  }
 }
 let t=Instant::now();let zn=rs.verify(&pp,STEPS,&z0).unwrap();let verify=t.elapsed().as_secs_f64();
 assert!(admitted(&zn,STEPS));assert_eq!(zn,states[STEPS]);
 let mut verifier_rejections=0;
 for i in 0..ARITY {
  let mut z=z0.clone();z[i]+=F::ONE;assert!(rs.verify(&pp,STEPS,&z).is_err());verifier_rejections+=1;
 }
 for count in [STEPS-1,STEPS+1]{assert!(rs.verify(&pp,count,&z0).is_err());verifier_rejections+=1;}
 let bytes=bincode::serialize(&rs).unwrap();let restored:Rs=bincode::deserialize(&bytes).unwrap();
 let end=restored.verify(&pp,STEPS,&z0).unwrap();assert!(admitted(&end,STEPS));assert_eq!(end,zn);
 let compression_receipt=if compress{Some(compression(&pp,&rs,&z0,&zn,&prefix_bytes,matrix.clone(),&args[2],&args[3]))}else{None};
 println!("{}",serde_json::to_string_pretty(&json!({
 "compression":compression_receipt,
 "passed":true,"scope":"recursive admission in restricted implicational logic; no hiding wrapper",
 "steps":STEPS,"state_arity":ARITY,"matrix_constraints":MATRIX_ROWS,"step_constraints":STEP_ROWS,
 "nova_primary_constraints":primary,"nova_secondary_constraints":secondary,
 "native_node_leaf_and_genesis_parity":true,"malformed_steps_rejected":malformed,"admission_rejections":admission_rejections,
 "verifier_rejections":verifier_rejections,"setup_seconds":setup,"init_seconds":init,"fold_seconds":times,
 "verify_seconds":verify,"recursive_proof_bytes_bincode":bytes.len(),"serialization_roundtrip":true
 })).unwrap());
}
