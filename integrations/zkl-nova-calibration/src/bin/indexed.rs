//! ZKL-15: authenticated affine-index dependent predicate derivations.
//! Narrow research fragment; not a general Lean kernel or a privacy claim.
use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{num::AllocatedNum, shape_cs::ShapeCS, test_cs::TestConstraintSystem,
               AllocatedBit, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc, poseidon::{PoseidonConstantsCircuit, PoseidonRO, PoseidonROCircuit},
               PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine,
             ROCircuitTrait, ROTrait, ROMode},
};
use serde_json::json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
use std::{collections::HashMap, error::Error, sync::OnceLock, time::Instant};

type E1 = PallasEngine;
type E2 = VestaEngine;
type F = <E1 as Engine>::Scalar;
type Num = AllocatedNum<F>;
type SE = SynthesisError;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type Proof = CompressedSNARK<E1,E2,RowStep,S1,S2>;
const RULE_DEPTH: usize = 2;
const ATOM_BITS: usize = 16;
const BINDER_BITS: usize = ATOM_BITS - 1;
// Separate namespaces for empty, row, rule, memory node, rule node.
const EMPTY: u64 = 101;
const ROW: u64 = 102;
const RULE: u64 = 103;
const MEM_NODE: u64 = 104;
const RULE_NODE: u64 = 105;

fn constants() -> &'static PoseidonConstantsCircuit<F> {
    static C: OnceLock<PoseidonConstantsCircuit<F>> = OnceLock::new();
    C.get_or_init(PoseidonConstantsCircuit::default)
}
fn hash(xs: &[F]) -> F {
    let mut ro = PoseidonRO::<F>::new_with_mode(constants().clone(), ROMode::Narrow);
    for x in xs { ro.absorb(*x); }
    ro.squeeze(F::NUM_BITS as usize, false)
}
fn f(x: u64) -> F { F::from(x) }
fn empty() -> F { hash(&[f(EMPTY)]) }
fn row(index: u64, atom: u64) -> F { hash(&[f(ROW), f(index), f(atom)]) }
fn node(tag: u64, l: F, r: F) -> F { hash(&[f(tag),l,r]) }

#[derive(Clone, Copy, Debug)]
struct Rule {
    // Packed base atom = 2 * index_offset + predicate_family (P=0, Q=1).
    head: u64,
    bound: bool,
    active: [bool;2],
    premises: [u64;2],
}
impl Rule {
    fn leaf(&self, rid: u64) -> F {
        hash(&[f(RULE), f(rid), f(self.head), f(self.bound as u64), f(self.active[0] as u64),
               f(self.premises[0]), f(self.active[1] as u64), f(self.premises[1])])
    }
    fn instantiate(&self, base: u64, n: u64) -> u64 { base + 2*n }
}
fn rules() -> [Rule;4] {
    [
        Rule { head: 6, bound: false, active: [false,false], premises: [0,0] }, // P(3)
        Rule { head: 3, bound: true, active: [true,false], premises: [0,0] }, // P(n) -> Q(n+1)
        Rule { head: 4, bound: true, active: [true,true], premises: [0,3] }, // P(n), Q(n+1) -> P(n+2)
        Rule { head: 65535, bound: true, active: [false,false], premises: [0,0] }, // overflow boundary fixture

    ]
}
// Sparse append-only witness builder. Never used by the verifier.
struct Tree {
    depth: usize,
    tag: u64,
    default: Vec<F>,
    nodes: HashMap<(usize,u64),F>,
}
impl Tree {
    fn new(depth: usize, tag: u64) -> Self {
        let mut default = vec![empty()];
        for i in 0..depth { default.push(node(tag,default[i],default[i])); }
        Self {depth,tag,default,nodes:HashMap::new()}
    }
    fn at(&self,l:usize,i:u64)->F {
        self.nodes.get(&(l,i)).copied().unwrap_or(self.default[l])
    }
    fn root(&self)->F { self.at(self.depth,0) }
    fn path(&self,mut i:u64)->Vec<F> {
        (0..self.depth).map(|l| { let s=self.at(l,i^1); i>>=1; s }).collect()
    }
    fn set(&mut self,mut i:u64,v:F) {
        self.nodes.insert((0,i),v);
        for l in 0..self.depth {
            i >>= 1;
            let v=node(self.tag,self.at(l,2*i),self.at(l,2*i+1));
            self.nodes.insert((l+1,i),v);
        }
    }
}
#[derive(Clone,Debug)]
struct RowStep {
    depth: usize,
    rule_depth: usize,
    slots: usize, // circuit shape parameter: maximum active premises
    cursor: u64,
    rid: u64,
    binder: u64,
    rule: Rule,
    rule_path: Vec<F>,
    refs: [u64;2],
    read_paths: [Vec<F>;2],
    append: Vec<F>,
}
fn alloc<CS:ConstraintSystem<F>>(cs:CS,v:F)->Result<Num,SE> {
    Num::alloc(cs,||Ok(v))
}
fn const_num<CS:ConstraintSystem<F>>(mut cs:CS,v:F)->Result<Num,SE> {
    let a=alloc(cs.namespace(||"allocate"),v)?;
    cs.enforce(||"constant",|lc|lc+a.get_variable()-(v,CS::one()),|lc|lc+CS::one(),|lc|lc);
    Ok(a)
}
fn eq<CS:ConstraintSystem<F>>(mut cs:CS,a:&Num,b:&Num) {
    cs.enforce(||"equal",|lc|lc+a.get_variable()-b.get_variable(),|lc|lc+CS::one(),|lc|lc);
}
fn gate_eq<CS:ConstraintSystem<F>>(mut cs:CS,g:&Num,a:&Num,b:&Num) {
    cs.enforce(||"gated equal",|lc|lc+g.get_variable(),|lc|lc+a.get_variable()-b.get_variable(),|lc|lc);
}
fn bool_num<CS:ConstraintSystem<F>>(mut cs:CS,v:bool)->Result<Num,SE> {
    let a=alloc(cs.namespace(||"allocate"),f(v as u64))?;
    cs.enforce(||"boolean",|lc|lc+a.get_variable(),|lc|lc+CS::one()-a.get_variable(),|lc|lc);
    Ok(a)
}
// Constrain x to a canonical w-bit unsigned integer; no modular aliasing at these widths.
fn range<CS:ConstraintSystem<F>>(mut cs:CS,x:&Num,v:u64,w:usize)->Result<Vec<AllocatedBit>,SE> {
    let bits: Vec<_>=(0..w).map(|i|AllocatedBit::alloc(
        cs.namespace(||format!("bit {i}")),Some(((v>>i)&1)==1))).collect::<Result<_,_>>()?;
    cs.enforce(||"bit reconstruction",|mut lc|{
        for (i,b) in bits.iter().enumerate(){lc=lc+(f(1u64<<i),b.get_variable());}
        lc-x.get_variable()
    },|lc|lc+CS::one(),|lc|lc);
    Ok(bits)
}
fn instantiate<CS:ConstraintSystem<F>>(mut cs:CS,base:&Num,base_value:u64,n:&Num,n_value:u64)->Result<Num,SE> {
    let v=base_value+2*n_value;
    let out=alloc(cs.namespace(||"instantiated atom"),f(v))?;
    cs.enforce(||"affine instantiation",|lc|lc+base.get_variable()+(f(2),n.get_variable())-out.get_variable(),|lc|lc+CS::one(),|lc|lc);
    range(cs.namespace(||"instantiated atom range"),&out,v,ATOM_BITS)?;
    Ok(out)
}
fn h<CS:ConstraintSystem<F>>(cs:CS,xs:&[Num])->Result<Num,SE> {
    let mut ro=PoseidonROCircuit::<F>::new_with_mode(constants().clone(),ROMode::Narrow);
    for x in xs {ro.absorb(x);}
    ro.squeeze_scalar(cs)
}
fn siblings<CS:ConstraintSystem<F>>(mut cs:CS,vs:&[F])->Result<Vec<Num>,SE> {
    vs.iter().enumerate().map(|(i,v)|alloc(cs.namespace(||format!("sibling {i}")),*v)).collect()
}
fn merkle<CS:ConstraintSystem<F>>(mut cs:CS,tag:&Num,mut x:Num,
                                  bits:&[AllocatedBit],siblings:&[Num])->Result<Num,SE> {
    assert_eq!(bits.len(),siblings.len());
    for (i,(bit,s)) in bits.iter().zip(siblings).enumerate() {
        let mut ns=cs.namespace(||format!("level {i}"));
        let l=Num::alloc(ns.namespace(||"left"),|| {
            if bit.get_value().ok_or(SE::AssignmentMissing)? {
                s.get_value().ok_or(SE::AssignmentMissing)
            } else {x.get_value().ok_or(SE::AssignmentMissing)}
        })?;
        // l = x + bit * (s - x)
        ns.enforce(||"order left",|lc|lc+bit.get_variable(),|lc|lc+s.get_variable()-x.get_variable(),
                   |lc|lc+l.get_variable()-x.get_variable());
        let r=Num::alloc(ns.namespace(||"right"),||Ok(
            x.get_value().ok_or(SE::AssignmentMissing)?+s.get_value().ok_or(SE::AssignmentMissing)?
            -l.get_value().ok_or(SE::AssignmentMissing)?))?;
        ns.enforce(||"order right",|lc|lc+l.get_variable()+r.get_variable()-x.get_variable()-s.get_variable(),
                   |lc|lc+CS::one(),|lc|lc);
        x=h(ns.namespace(||"parent"),&[tag.clone(),l,r])?;
    }
    Ok(x)
}

impl StepCircuit<F> for RowStep {
    // z = (rule table root, public goal, memory root, next free slot, last derived atom).
    fn arity(&self)->usize {5}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[Num])->Result<Vec<Num>,SE> {
        assert!((1..=12).contains(&self.depth) && self.slots<=2);
        assert_eq!(self.append.len(),self.depth);
        assert!((1..=5).contains(&self.rule_depth));
        assert_eq!(self.rule_path.len(),self.rule_depth);
        let zero=const_num(cs.namespace(||"zero"),F::ZERO)?;
        let row_tag=const_num(cs.namespace(||"row tag"),f(ROW))?;
        let rule_tag=const_num(cs.namespace(||"rule tag"),f(RULE))?;
        let mem_tag=const_num(cs.namespace(||"memory node tag"),f(MEM_NODE))?;
        let rule_node=const_num(cs.namespace(||"rule node tag"),f(RULE_NODE))?;
        let empty=const_num(cs.namespace(||"empty"),empty())?;
        let cur_bits=range(cs.namespace(||"cursor"),&z[3],self.cursor,self.depth)?;
        let rid=alloc(cs.namespace(||"rule index"),f(self.rid))?;
        let rid_bits=range(cs.namespace(||"rule index bits"),&rid,self.rid,self.rule_depth)?;
        let head_base=alloc(cs.namespace(||"head base"),f(self.rule.head))?;
        range(cs.namespace(||"head base bits"),&head_base,self.rule.head,ATOM_BITS)?;
        let bound=bool_num(cs.namespace(||"universal rule"),self.rule.bound)?;
        let binder=alloc(cs.namespace(||"binder"),f(self.binder))?;
        range(cs.namespace(||"binder bits"),&binder,self.binder,BINDER_BITS)?;
        cs.enforce(||"ground rule binder zero",|lc|lc+CS::one()-bound.get_variable(),
            |lc|lc+binder.get_variable(),|lc|lc);
        let head=instantiate(cs.namespace(||"head substitution"),&head_base,self.rule.head,&binder,self.binder)?;
        let mut active=Vec::new();
        let mut premise_base=Vec::new();
        let mut premise=Vec::new();
        for j in 0..2 {
            let mut ns=cs.namespace(||format!("premise {j}"));
            let a=bool_num(ns.namespace(||"active"),self.rule.active[j])?;
            let p=alloc(ns.namespace(||"atom"),f(self.rule.premises[j]))?;
            range(ns.namespace(||"atom bits"),&p,self.rule.premises[j],ATOM_BITS)?;
            // Inactive fields have a canonical zero encoding.
            ns.enforce(||"inactive atom zero",|lc|lc+CS::one()-a.get_variable(),
                       |lc|lc+p.get_variable(),|lc|lc);
            if j>=self.slots {eq(ns.namespace(||"outside shape arity"),&a,&zero);}
            premise.push(instantiate(ns.namespace(||"premise substitution"),&p,self.rule.premises[j],&binder,self.binder)?);
            active.push(a); premise_base.push(p);
        }
        cs.enforce(||"prefix active",|lc|lc+active[1].get_variable(),
                   |lc|lc+CS::one()-active[0].get_variable(),|lc|lc);
        let rule_leaf=h(cs.namespace(||"rule leaf"),&[
            rule_tag,rid,head_base,bound,active[0].clone(),premise_base[0].clone(),
            active[1].clone(),premise_base[1].clone()])?;
        let rule_sibs=siblings(cs.namespace(||"rule siblings"),&self.rule_path)?;
        let rule_root=merkle(cs.namespace(||"rule membership"),&rule_node,rule_leaf,&rid_bits,&rule_sibs)?;
        eq(cs.namespace(||"bind rule environment"),&rule_root,&z[0]);
        for j in 0..self.slots {
            assert_eq!(self.read_paths[j].len(),self.depth);
            let mut ns=cs.namespace(||format!("read {j}"));
            let reference=alloc(ns.namespace(||"index"),f(self.refs[j]))?;
            let bits=range(ns.namespace(||"index bits"),&reference,self.refs[j],self.depth)?;
            let gap=self.cursor.checked_sub(self.refs[j]).and_then(|x|x.checked_sub(1)).unwrap_or(0);
            let gap_num=alloc(ns.namespace(||"gap"),f(gap))?;
            range(ns.namespace(||"gap bits"),&gap_num,gap,self.depth)?;
            // active implies ref < cursor, checked as a bounded nonnegative difference.
            ns.enforce(||"strict backward reference",|lc|lc+active[j].get_variable(),
                       |lc|lc+z[3].get_variable()-reference.get_variable()-CS::one()-gap_num.get_variable(),|lc|lc);
            let leaf=h(ns.namespace(||"read leaf"),&[row_tag.clone(),reference,premise[j].clone()])?;
            let sib=siblings(ns.namespace(||"read siblings"),&self.read_paths[j])?;
            let root=merkle(ns.namespace(||"read membership"),&mem_tag,leaf,&bits,&sib)?;
            gate_eq(ns.namespace(||"bind read root"),&active[j],&root,&z[2]);
        }
        // The SAME allocated siblings and path bits authenticate old and new roots.
        let append=siblings(cs.namespace(||"append siblings"),&self.append)?;
        let old=merkle(cs.namespace(||"empty slot"),&mem_tag,empty,&cur_bits,&append)?;
        eq(cs.namespace(||"bind old root"),&old,&z[2]);
        let new_leaf=h(cs.namespace(||"new leaf"),&[row_tag,z[3].clone(),head.clone()])?;
        let new_root=merkle(cs.namespace(||"write slot"),&mem_tag,new_leaf,&cur_bits,&append)?;
        let next=Num::alloc(cs.namespace(||"next cursor"),||Ok(z[3].get_value().ok_or(SE::AssignmentMissing)?+F::ONE))?;
        cs.enforce(||"increment",|lc|lc+z[3].get_variable()+CS::one()-next.get_variable(),
                   |lc|lc+CS::one(),|lc|lc);
        Ok(vec![z[0].clone(),z[1].clone(),new_root,next,head])
    }
}

fn fixture(depth:usize,slots:usize)->(Vec<RowStep>,Vec<Vec<F>>) {
    let rs=rules();
    let mut env=Tree::new(RULE_DEPTH,RULE_NODE);
    for (i,r) in rs.iter().enumerate(){env.set(i as u64,r.leaf(i as u64));}
    let mut mem=Tree::new(depth,MEM_NODE);
    let goal=rs[slots].instantiate(rs[slots].head,if slots==0 {0} else {3});
    let mut states=vec![vec![env.root(),f(goal),mem.root(),F::ZERO,F::ZERO]];
    let mut steps=vec![];
    for rid in 0..=slots {
        let cursor=rid as u64;
        let binder=if rid==0 {0} else {3};
        let head=rs[rid].instantiate(rs[rid].head,binder);
        steps.push(RowStep {depth,rule_depth:RULE_DEPTH,slots,cursor,rid:cursor,binder,rule:rs[rid],
            rule_path:env.path(cursor),refs:[0,1],read_paths:[mem.path(0),mem.path(1)],
            append:mem.path(cursor)});
        mem.set(cursor,row(cursor,head));
        states.push(vec![env.root(),f(goal),mem.root(),f(cursor+1),f(head)]);
    }
    (steps,states)
}
fn check(c:&RowStep,z:&[F],expected:Option<&[F]>)->Result<(bool,usize),SE> {
    let mut cs=TestConstraintSystem::<F>::new();
    let inputs=z.iter().enumerate().map(|(i,v)|alloc(cs.namespace(||format!("input {i}")),*v))
        .collect::<Result<Vec<_>,_>>()?;
    let outputs=c.synthesize(&mut cs,&inputs)?;
    let matches=expected.map_or(true,|want|outputs.iter().map(|x|x.get_value().unwrap()).eq(want.iter().copied()));
    Ok((cs.which_is_unsatisfied().is_none() && matches,cs.num_constraints()))
}
fn shape(c:&RowStep)->Result<(usize,usize),SE> {
    let mut cs=ShapeCS::<E1>::new();
    let inputs=(0..5).map(|i|alloc(cs.namespace(||format!("input {i}")),F::ZERO))
        .collect::<Result<Vec<_>,_>>()?;
    c.synthesize(&mut cs,&inputs)?;
    Ok((cs.num_constraints(),cs.num_aux()))
}
fn terminal(z:&[F],z0:&[F],steps:usize)->bool {
    z.len()==5 && z0.len()==5 && steps>0 && z[0]==z0[0] && z[1]==z0[1]
        && z[3]==f(steps as u64) && z[4]==z0[1]
}
fn calibrate()->Result<(),Box<dyn Error>> {
    let mut reports=vec![];
    for depth in [4,8,12] {
        for slots in 0..=2 {
            let (steps,states)=fixture(depth,slots);
            let (constraints,aux)=shape(&steps[0])?;
            for (i,c) in steps.iter().enumerate() {
                let (ok,count)=check(c,&states[i],Some(&states[i+1]))?;
                assert!(ok && count==constraints);
                assert_eq!(shape(c)?,(constraints,aux));
            }
            reports.push(json!({"depth":depth,"max_arity":slots,"constraints":constraints,
                "aux_including_5_state_inputs":aux,"honest_transitions":steps.len(),
                "same_shape_across_active_arities":true}));
        }
    }
    let (cs,z)=fixture(4,2);
    let c=&cs[2];
    let mut bad=Vec::new();
    let mut x=c.clone(); x.rule.head=9; bad.push(x);
    let mut x=c.clone(); x.rule.active=[false,false]; bad.push(x);
    let mut x=c.clone(); x.rule.premises[1]=0; bad.push(x);
    let mut x=c.clone(); x.rid=3; bad.push(x);
    let mut x=c.clone(); x.rid=4; bad.push(x);
    let mut x=c.clone(); x.refs[0]=2; bad.push(x);
    let mut x=c.clone(); x.refs[0]=16; bad.push(x);
    let mut x=c.clone(); x.read_paths[1][0]+=F::ONE; bad.push(x);
    let mut x=c.clone(); x.append[0]+=F::ONE; bad.push(x);
    let mut x=c.clone(); x.rule_path[0]+=F::ONE; bad.push(x);
    let mut x=c.clone(); x.cursor=1; bad.push(x);
    let mut x=c.clone(); x.binder=4; bad.push(x);
    let mut x=c.clone(); x.binder=32768; bad.push(x);
    let mut x=c.clone(); x.rule.bound=false; bad.push(x);
    for x in &bad {assert!(!check(x,&z[2],None)?.0);}
    let mut ground=cs[0].clone(); ground.binder=1;
    assert!(!check(&ground,&z[0],None)?.0);
    // Coherent authenticated boundary rule: legitimate maximum atom at n=0,
    // but n=1 would overflow the packed integer range and must fail.
    let rs=rules();
    let mut env=Tree::new(RULE_DEPTH,RULE_NODE);
    for (i,r) in rs.iter().enumerate(){env.set(i as u64,r.leaf(i as u64));}
    let mut boundary=cs[0].clone(); boundary.rid=3; boundary.rule=rs[3]; boundary.rule_path=env.path(3);
    assert!(check(&boundary,&z[0],None)?.0);
    boundary.binder=1;
    assert!(!check(&boundary,&z[0],None)?.0);
    let mut wrong=z[2].clone();wrong[2]+=F::ONE;
    assert!(!check(c,&wrong,None)?.0);
    let mut wrong=z[2].clone();wrong[0]+=F::ONE;
    assert!(!check(c,&wrong,None)?.0);
    assert!(terminal(&z[3],&z[0],3));
    assert!(!terminal(&z[2],&z[0],2));
    let mut other=z[0].clone();other[1]=f(3);
    assert!(!terminal(&z[3],&other,3));
    println!("{}",json!({"scope":"affine_indexed_nova_frontend_r1cs_synthesis",
        "nova":"0.76.0","shape_measurements":reports,
        "constraint_attack_rejections":bad.len()+4,"host_terminal_negatives":2,
        "proof_generated":false}));
    Ok(())
}
fn fold(compress:bool)->Result<(),Box<dyn Error>> {
    let (steps,z)=fixture(4,2);
    let start=Instant::now();
    let pp=PublicParams::<E1,E2,RowStep>::setup(&steps[0],&*S1::ck_floor(),&*S2::ck_floor())?;
    let setup=start.elapsed().as_secs_f64();
    let start=Instant::now();
    let mut recursive=RecursiveSNARK::<E1,E2,RowStep>::new(&pp,&steps[0],&z[0])?;
    for c in &steps {recursive.prove_step(&pp,c)?;}
    let prove=start.elapsed().as_secs_f64();
    let start=Instant::now();
    let out=recursive.verify(&pp,steps.len(),&z[0])?;
    let verify=start.elapsed().as_secs_f64();
    assert_eq!(out,z[3]);assert!(terminal(&out,&z[0],steps.len()));
    assert!(recursive.verify(&pp,steps.len()+1,&z[0]).is_err());
    let mut wrong=z[0].clone();wrong[1]=f(3);
    assert!(recursive.verify(&pp,steps.len(),&wrong).is_err());
    let mut report=json!({"scope":"affine_indexed_nova_recursive_verifier","nova":"0.76.0",
        "depth":4,"steps":steps.len(),"setup_seconds":setup,"fold_seconds":prove,
        "verify_seconds":verify,"recursive_serialized_bytes":bincode::serialize(&recursive)?.len(),
        "augmented_constraints":pp.num_constraints(),"augmented_variables":pp.num_variables(),
        "wrong_initial_and_step_count_rejected":true,"expected_terminal_verified":true,
        "witness_privacy_claimed":false});
    if compress {
        let start=Instant::now();
        let (pk,vk)=Proof::setup(&pp)?;
        let p=Proof::prove(&pp,&pk,&recursive)?;
        let seconds=start.elapsed().as_secs_f64();
        let start=Instant::now();
        let out=p.verify(&vk,steps.len(),&z[0])?;
        let verification=start.elapsed().as_secs_f64();
        assert_eq!(out,z[3]);
        assert!(p.verify(&vk,steps.len()+1,&z[0]).is_err());
        assert!(p.verify(&vk,steps.len(),&wrong).is_err());
        report["compression"]=json!({"scheme":"Spartan/IPA","setup_plus_prove_seconds":seconds,
            "verify_seconds":verification,"proof_bytes":bincode::serialize(&p)?.len(),
            "verification_key_bytes":bincode::serialize(&vk)?.len()});
    }
    println!("{report}");Ok(())
}

const BATCH_RULE_DEPTH: usize = 5;
const BATCH_MEMORY_DEPTH: usize = 6;
const ATOM_MAX: u64 = 65535;
const BINDER_MAX: u64 = 32767;
const MAX_INPUT: u64 = 262144;

#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct WireRule { bound: bool, head: u64, premises: Vec<u64> }
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct WireStep { rule: usize, binder: u64, refs: Vec<usize> }
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct WireCase {
    root: String,
    arm: String,
    goal: u64,
    exact_rows: usize,
    environment_id: String,
    rules: Vec<WireRule>,
    steps: Vec<WireStep>,
}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBatch { schema: String, rule_depth: usize, memory_depth: usize, cases: Vec<WireCase> }
fn require(ok:bool,msg:&str)->Result<(),Box<dyn Error>> {
    if ok { Ok(()) } else { Err(msg.into()) }
}
fn digest(bytes:&[u8])->String { format!("{:x}",Sha256::digest(bytes)) }
fn env_id(c:&WireCase)->Result<String,Box<dyn Error>> {
    // JSON Value objects use sorted keys (serde_json's default map).
    Ok(digest(&serde_json::to_vec(&json!({"grammar":"zkl-affine-v1","goal":c.goal,"schemas":c.rules}))?))
}
fn wire_rule(r:&WireRule)->Result<Rule,Box<dyn Error>> {
    require(r.head<=ATOM_MAX && r.premises.len()<=2 &&
        r.premises.iter().all(|p|*p<=ATOM_MAX),"invalid rule")?;
    let mut p=[0;2];
    p[..r.premises.len()].copy_from_slice(&r.premises);
    Ok(Rule { head:r.head,bound:r.bound,active:[!r.premises.is_empty(),r.premises.len()==2],premises:p })
}
fn materialize(c:&WireCase)->Result<(Vec<RowStep>,Vec<Vec<F>>),Box<dyn Error>> {
    require(c.goal<=ATOM_MAX && !c.rules.is_empty() && c.rules.len()<=1<<BATCH_RULE_DEPTH &&
        !c.steps.is_empty() && c.steps.len()<=1<<BATCH_MEMORY_DEPTH,"capacity")?;
    require(c.exact_rows>0 && c.exact_rows<=c.steps.len(),"invalid reference cost")?;
    require(c.environment_id==env_id(c)?,"environment digest mismatch")?;
    let rs=c.rules.iter().map(wire_rule).collect::<Result<Vec<_>,_>>()?;
    let mut env=Tree::new(BATCH_RULE_DEPTH,RULE_NODE);
    for (i,r) in rs.iter().enumerate(){env.set(i as u64,r.leaf(i as u64));}
    let mut mem=Tree::new(BATCH_MEMORY_DEPTH,MEM_NODE);
    let mut states=vec![vec![env.root(),f(c.goal),mem.root(),F::ZERO,F::ZERO]];
    let mut steps=vec![];
    let mut atoms:Vec<u64>=vec![];
    for (i,w) in c.steps.iter().enumerate() {
        let r=*rs.get(w.rule).ok_or("unknown schema")?;
        require(w.binder<=BINDER_MAX && (r.bound || w.binder==0),"binder")?;
        let arity=c.rules[w.rule].premises.len();
        require(w.refs.len()==arity,"arity")?;
        let head=r.instantiate(r.head,w.binder);
        require(head<=ATOM_MAX,"head overflow")?;
        let mut refs=[0u64;2];
        for (j,&ridx) in w.refs.iter().enumerate() {
            let want=r.instantiate(r.premises[j],w.binder);
            require(want<=ATOM_MAX && ridx<i && atoms.get(ridx)==Some(&want),"premise")?;
            refs[j]=ridx as u64;
        }
        let cursor=i as u64;
        steps.push(RowStep {depth:BATCH_MEMORY_DEPTH,rule_depth:BATCH_RULE_DEPTH,slots:2,
            cursor,rid:w.rule as u64,binder:w.binder,rule:r,rule_path:env.path(w.rule as u64),
            refs,read_paths:[mem.path(refs[0]),mem.path(refs[1])],append:mem.path(cursor)});
        mem.set(cursor,row(cursor,head));
        atoms.push(head);
        states.push(vec![env.root(),f(c.goal),mem.root(),f(cursor+1),f(head)]);
    }
    require(atoms.last()==Some(&c.goal),"terminal goal")?;
    Ok((steps,states))
}
fn batch(input:&Path,out:&Path)->Result<(),Box<dyn Error>> {
    let mut bytes=Vec::new();
    fs::File::open(input)?.take(MAX_INPUT+1).read_to_end(&mut bytes)?;
    require(bytes.len() as u64<=MAX_INPUT,"input byte cap")?;
    let b:WireBatch=serde_json::from_slice(&bytes)?;
    require(b.schema=="zkl-affine-batch-v1" && b.rule_depth==BATCH_RULE_DEPTH &&
        b.memory_depth==BATCH_MEMORY_DEPTH && b.cases.len()==8,"batch contract")?;
    let roots=["same-93000","same-93001","shift-94000","shift-94001"];
    let mut prepared=Vec::new();
    for (pair,root) in b.cases.chunks_exact(2).zip(roots) {
        let a=&pair[0];let t=&pair[1];
        require(a.root==root && t.root==root && a.arm=="astar" && t.arm=="weighted_tree_shared" &&
            a.goal==t.goal && a.rules==t.rules && a.environment_id==t.environment_id &&
            a.exact_rows==t.exact_rows && a.steps.len()==a.exact_rows &&
            a.steps.len()<=t.steps.len(),"paired source contract")?;
        prepared.push(materialize(a)?);
        prepared.push(materialize(t)?);
    }
    // Check malformed transport independently of any Merkle witness construction.
    let mut invalid=b.cases[0].clone();invalid.environment_id="00".repeat(32);
    require(materialize(&invalid).is_err(),"environment mutation accepted")?;
    let mut invalid=b.cases[0].clone();invalid.steps[0].rule=32;
    require(materialize(&invalid).is_err(),"schema mutation accepted")?;
    let mut invalid=b.cases[0].clone();invalid.steps[0].binder=BINDER_MAX+1;
    require(materialize(&invalid).is_err(),"binder mutation accepted")?;
    let mut invalid=b.cases[0].clone();invalid.goal^=1;invalid.environment_id=env_id(&invalid)?;
    require(materialize(&invalid).is_err(),"coherent wrong goal accepted")?;
    let mut invalid=b.cases[0].clone();invalid.steps[0].refs=vec![0];
    require(materialize(&invalid).is_err(),"first-row reference accepted")?;
    fs::create_dir_all(out)?;
    let first=&prepared[0].0[0];
    let raw=shape(first)?;
    let start=Instant::now();
    let pp=PublicParams::<E1,E2,RowStep>::setup(first,&*S1::ck_floor(),&*S2::ck_floor())?;
    let pp_seconds=start.elapsed().as_secs_f64();
    let start=Instant::now();
    let (pk,vk)=Proof::setup(&pp)?;
    let compression_setup_seconds=start.elapsed().as_secs_f64();
    let vk_bytes=bincode::serialize(&vk)?;
    fs::write(out.join("vk.bin"),&vk_bytes)?;
    let mut reports=vec![];
    for (i,(c,(steps,states))) in b.cases.iter().zip(prepared.iter()).enumerate() {
        for (j,s) in steps.iter().enumerate(){
            require(shape(s)?==raw,"inconsistent fixed step shape")?;
            require(check(s,&states[j],Some(&states[j+1]))?.0,"constraint replay failed")?;
        }
        let mut forged=steps[0].clone();
        forged.rule_path[0]+=F::ONE;
        require(!check(&forged,&states[0],None)?.0,"forged rule path accepted")?;
        let start=Instant::now();
        let mut rec=RecursiveSNARK::<E1,E2,RowStep>::new(&pp,&steps[0],&states[0])?;
        for step in steps {rec.prove_step(&pp,step)?;}
        let fold_seconds=start.elapsed().as_secs_f64();
        let start=Instant::now();
        let result=rec.verify(&pp,steps.len(),&states[0])?;
        let recursive_verify_seconds=start.elapsed().as_secs_f64();
        require(result==*states.last().unwrap() && terminal(&result,&states[0],steps.len()),"recursive terminal")?;
        let start=Instant::now();
        let compressed=Proof::prove(&pp,&pk,&rec)?;
        let compression_prove_seconds=start.elapsed().as_secs_f64();
        let proof_bytes=bincode::serialize(&compressed)?;
        // Verify a deserialized proof, rather than relying on the in-memory object.
        let received:Proof=bincode::deserialize(&proof_bytes)?;
        let start=Instant::now();
        let result=received.verify(&vk,steps.len(),&states[0])?;
        let compressed_verify_seconds=start.elapsed().as_secs_f64();
        require(result==*states.last().unwrap() && terminal(&result,&states[0],steps.len()),"compressed terminal")?;
        require(received.verify(&vk,steps.len()+1,&states[0]).is_err(),"wrong count accepted")?;
        for k in [0,1,2] {
            let mut wrong=states[0].clone();wrong[k]+=F::ONE;
            require(received.verify(&vk,steps.len(),&wrong).is_err(),"wrong initial state accepted")?;
        }
        let filename=format!("proof-{i}.bin");
        fs::write(out.join(&filename),&proof_bytes)?;
        reports.push(json!({"root":c.root,"arm":c.arm,"environment_id":c.environment_id,
            "goal":c.goal,"rule_count":c.rules.len(),"steps":steps.len(),"exact_rows":c.exact_rows,
            "raw_step_constraint_sum":raw.0*steps.len(),"fold_seconds":fold_seconds,
            "recursive_verify_seconds":recursive_verify_seconds,
            "compression_prove_seconds":compression_prove_seconds,
            "compressed_verify_seconds":compressed_verify_seconds,"proof_bytes":proof_bytes.len(),
            "proof_sha256":digest(&proof_bytes),"proof_file":filename,
            "verified":true,"wrong_count_and_initial_rejected":true}));
    }
    let report=json!({"schema":"zkl-nova-batch-receipt-v1","nova":"0.76.0",
        "scope":"fixed-shape affine indexed rule derivation",
        "transport_sha256":digest(&bytes),"rule_depth":BATCH_RULE_DEPTH,"memory_depth":BATCH_MEMORY_DEPTH,
        "max_arity":2,"raw_step_constraints":raw.0,"raw_aux_including_state":raw.1,
        "augmented_constraints":pp.num_constraints(),"augmented_variables":pp.num_variables(),
        "pp_setup_seconds":pp_seconds,"compression_setup_seconds":compression_setup_seconds,
        "verification_key_bytes":vk_bytes.len(),"verification_key_sha256":digest(&vk_bytes),
        "transport_negatives":5,"constraint_negatives":reports.len(),"cases":reports,
        "witness_privacy_claimed":false});
    fs::write(out.join("receipt.json"),serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}

fn main()->Result<(),Box<dyn Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("--batch")=>{
            let input=std::env::args().nth(2).ok_or("missing batch input")?;
            let output=std::env::args().nth(3).ok_or("missing batch output")?;
            batch(Path::new(&input),Path::new(&output))
        },
        Some("--fold")=>fold(false),
        Some("--compress")=>fold(true),
        None|Some("--calibrate")=>calibrate(),
        _=>Err("use --calibrate, --fold or --compress".into()),
    }
}
