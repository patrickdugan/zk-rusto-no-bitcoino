//! ZKL-08: Poseidon-authenticated Horn-DAG step, using actual Nova 0.76.0.
//! Bounded research fixture; no general Lean kernel or privacy claim.
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
// Separate namespaces for empty, row, rule, memory node, rule node.
const EMPTY: u64 = 1;
const ROW: u64 = 2;
const RULE: u64 = 3;
const MEM_NODE: u64 = 4;
const RULE_NODE: u64 = 5;

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
    head: u64,
    active: [bool;2],
    premises: [u64;2],
}
impl Rule {
    fn leaf(&self, rid: u64) -> F {
        hash(&[f(RULE), f(rid), f(self.head), f(self.active[0] as u64),
               f(self.premises[0]), f(self.active[1] as u64), f(self.premises[1])])
    }
}
fn rules() -> [Rule;4] {
    [
        Rule { head: 0, active: [false,false], premises: [0,0] },
        Rule { head: 1, active: [true,false], premises: [0,0] },
        Rule { head: 2, active: [true,true], premises: [0,1] },
        Rule { head: 3, active: [false,false], premises: [0,0] },
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
    slots: usize, // circuit shape parameter: maximum active premises
    cursor: u64,
    rid: u64,
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
        assert_eq!(self.rule_path.len(),RULE_DEPTH);
        let zero=const_num(cs.namespace(||"zero"),F::ZERO)?;
        let row_tag=const_num(cs.namespace(||"row tag"),f(ROW))?;
        let rule_tag=const_num(cs.namespace(||"rule tag"),f(RULE))?;
        let mem_tag=const_num(cs.namespace(||"memory node tag"),f(MEM_NODE))?;
        let rule_node=const_num(cs.namespace(||"rule node tag"),f(RULE_NODE))?;
        let empty=const_num(cs.namespace(||"empty"),empty())?;
        let cur_bits=range(cs.namespace(||"cursor"),&z[3],self.cursor,self.depth)?;
        let rid=alloc(cs.namespace(||"rule index"),f(self.rid))?;
        let rid_bits=range(cs.namespace(||"rule index bits"),&rid,self.rid,RULE_DEPTH)?;
        let head=alloc(cs.namespace(||"head"),f(self.rule.head))?;
        range(cs.namespace(||"head bits"),&head,self.rule.head,ATOM_BITS)?;
        let mut active=Vec::new();
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
            active.push(a); premise.push(p);
        }
        cs.enforce(||"prefix active",|lc|lc+active[1].get_variable(),
                   |lc|lc+CS::one()-active[0].get_variable(),|lc|lc);
        let rule_leaf=h(cs.namespace(||"rule leaf"),&[
            rule_tag,rid,head.clone(),active[0].clone(),premise[0].clone(),
            active[1].clone(),premise[1].clone()])?;
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
    let goal=slots as u64;
    let mut states=vec![vec![env.root(),f(goal),mem.root(),F::ZERO,F::ZERO]];
    let mut steps=vec![];
    for rid in 0..=slots {
        let cursor=rid as u64;
        steps.push(RowStep {depth,slots,cursor,rid:cursor,rule:rs[rid],
            rule_path:env.path(cursor),refs:[0,1],read_paths:[mem.path(0),mem.path(1)],
            append:mem.path(cursor)});
        mem.set(cursor,row(cursor,rs[rid].head));
        states.push(vec![env.root(),f(goal),mem.root(),f(cursor+1),f(rs[rid].head)]);
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
    for x in &bad {assert!(!check(x,&z[2],None)?.0);}
    let mut wrong=z[2].clone();wrong[2]+=F::ONE;
    assert!(!check(c,&wrong,None)?.0);
    let mut wrong=z[2].clone();wrong[0]+=F::ONE;
    assert!(!check(c,&wrong,None)?.0);
    assert!(terminal(&z[3],&z[0],3));
    assert!(!terminal(&z[2],&z[0],2));
    let mut other=z[0].clone();other[1]=f(3);
    assert!(!terminal(&z[3],&other,3));
    println!("{}",json!({"scope":"actual_nova_frontend_r1cs_synthesis",
        "nova":"0.76.0","shape_measurements":reports,
        "constraint_attack_rejections":bad.len()+2,"host_terminal_negatives":2,
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
    let mut report=json!({"scope":"actual_nova_recursive_verifier","nova":"0.76.0",
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
fn main()->Result<(),Box<dyn Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("--fold")=>fold(false),
        Some("--compress")=>fold(true),
        None|Some("--calibrate")=>calibrate(),
        _=>Err("use --calibrate, --fold or --compress".into()),
    }
}
