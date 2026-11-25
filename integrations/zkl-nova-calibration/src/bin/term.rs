//! ZKL-15: public-arena de Bruijn substitution and beta-conversion.
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
use serde::Deserialize;
use std::{fs, io::Read};
use std::{collections::HashMap, error::Error, sync::OnceLock, time::Instant};

type E1 = PallasEngine;
type E2 = VestaEngine;
type F = <E1 as Engine>::Scalar;
type Num = AllocatedNum<F>;
type SE = SynthesisError;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type Proof = CompressedSNARK<E1,E2,TermStep,S1,S2>;
const DEPTH: usize = 6;
const WIDTH: usize = 16;
// Separate namespaces for empty, row, rule, memory node, rule node.
const EMPTY: u64 = 201;
const ROW: u64 = 202;
const TERM: u64 = 203;
const MEM_NODE: u64 = 204;
const TERM_NODE: u64 = 205;

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
fn node(tag: u64, l: F, r: F) -> F { hash(&[f(tag),l,r]) }

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


const ARITY:[usize;17]=[0,0,0,1,2,0,0,0,0,2,2,0,1,2,1,1,2];
fn kind(op:u64)->u64 {if op<5 {0} else if op<11 {1} else {2}}
#[derive(Clone,Debug,Deserialize)]
struct WireRow(u64,u64,u64,u64,u64,Vec<usize>);
impl WireRow {
    fn payload(&self)->[u64;5] {[kind(self.0),self.1,self.2,self.3,self.4]}
}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {name:String,terms:Vec<[u64;3]>,rows:Vec<WireRow>,goal:[u64;2]}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {schema:String,cases:Vec<Case>}
#[derive(Clone,Debug)]
struct TermOpening {id:u64,node:[u64;3],path:Vec<F>}
#[derive(Clone,Debug)]
struct RowOpening {id:u64,payload:[u64;5],path:Vec<F>}
#[derive(Clone,Debug)]
struct TermStep {
    cursor:u64, row:WireRow, term:[TermOpening;3], prev:[RowOpening;2], append:Vec<F>,
}
fn term_leaf(i:u64,t:[u64;3])->F {
    hash(&[f(TERM),f(i),f(t[0]),f(t[1]),f(t[2])])
}
fn row_leaf(i:u64,r:[u64;5])->F {
    hash(&[f(ROW),f(i),f(r[0]),f(r[1]),f(r[2]),f(r[3]),f(r[4])])
}
fn gate<CS:ConstraintSystem<F>>(mut cs:CS,g:&Num,c:i64,terms:&[(i64,&Num)]) {
    let field=|v:i64|if v<0 {-f(v.unsigned_abs())} else {f(v as u64)};
    cs.enforce(||"selected linear condition",|lc|lc+g.get_variable(),|mut lc|{
        lc=lc+(field(c),CS::one());
        for (coef,v) in terms {lc=lc+(field(*coef),v.get_variable());}
        lc
    },|lc|lc);
}
fn ref_match<CS:ConstraintSystem<F>>(mut cs:CS,g:&Num,got:&[Num],want:[&Num;5]){
    for i in 0..5 {gate_eq(cs.namespace(||format!("field {i}")),g,&got[i],want[i]);}
}
fn fixed_tag<CS:ConstraintSystem<F>>(mut cs:CS,t:&TermOpening,leaf_tag:&Num,node_tag:&Num,root:&Num)->Result<Vec<Num>,SE> {
    let id=alloc(cs.namespace(||"id"),f(t.id))?;
    let bits=range(cs.namespace(||"id bits"),&id,t.id,DEPTH)?;
    let mut vals=vec![id];
    for (j,v) in t.node.iter().enumerate(){vals.push(alloc(cs.namespace(||format!("value {j}")),f(*v))?);}
    let mut hargs=vec![leaf_tag.clone()];hargs.extend(vals.clone());
    let leaf=h(cs.namespace(||"leaf"),&hargs)?;
    let sib=siblings(cs.namespace(||"siblings"),&t.path)?;
    let got=merkle(cs.namespace(||"path"),node_tag,leaf,&bits,&sib)?;
    eq(cs.namespace(||"bind root"),&got,root);
    Ok(vals) // [id, tag, a, b]
}

impl StepCircuit<F> for TermStep {
    // z=(public arena root, goal left, goal right, proof log root, cursor, last kind,left,right).
    fn arity(&self)->usize {8}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[Num])->Result<Vec<Num>,SE> {
        let zero=const_num(cs.namespace(||"zero"),F::ZERO)?;
        let one=const_num(cs.namespace(||"one"),F::ONE)?;
        let two=const_num(cs.namespace(||"two"),f(2))?;
        let rt=const_num(cs.namespace(||"row tag"),f(ROW))?;
        let tt=const_num(cs.namespace(||"term tag"),f(TERM))?;
        let tn=const_num(cs.namespace(||"term node"),f(TERM_NODE))?;
        let mn=const_num(cs.namespace(||"memory node"),f(MEM_NODE))?;
        let empty=const_num(cs.namespace(||"empty"),empty())?;
        let cur=range(cs.namespace(||"cursor"),&z[4],self.cursor,DEPTH)?;
        let select=(0..17).map(|i|bool_num(cs.namespace(||format!("selector {i}")),self.row.0==i))
            .collect::<Result<Vec<_>,_>>()?;
        cs.enforce(||"one selected",|mut lc|{for s in &select {lc=lc+s.get_variable();}lc-CS::one()},|lc|lc+CS::one(),|lc|lc);
        let r=self.row.payload().iter().enumerate().map(|(i,v)|alloc(cs.namespace(||format!("row field {i}")),f(*v)))
            .collect::<Result<Vec<_>,_>>()?;
        cs.enforce(||"derive kind",|mut lc|{for (i,s) in select.iter().enumerate(){
            lc=lc+(f(kind(i as u64)),s.get_variable());
        }lc-r[0].get_variable()},|lc|lc+CS::one(),|lc|lc);
        range(cs.namespace(||"cutoff range"),&r[2],self.row.2,WIDTH)?;
        // The third opening is the replacement for substitution, the lambda function
        // for beta, or a dummy public term for the other rules. IDs are constrained below.
        let t=fixed_tag(cs.namespace(||"source"),&self.term[0],&tt,&tn,&z[0])?;
        let u=fixed_tag(cs.namespace(||"result"),&self.term[1],&tt,&tn,&z[0])?;
        let x=fixed_tag(cs.namespace(||"extra"),&self.term[2],&tt,&tn,&z[0])?;
        eq(cs.namespace(||"bind source"),&t[0],&r[1]);
        eq(cs.namespace(||"bind result"),&u[0],&r[4]);
        let kp=Num::alloc(cs.namespace(||"next cutoff"),||Ok(r[2].get_value().ok_or(SE::AssignmentMissing)?+F::ONE))?;
        cs.enforce(||"increment cutoff",|lc|lc+r[2].get_variable()+CS::one()-kp.get_variable(),|lc|lc+CS::one(),|lc|lc);
        let a=self.term[0].node[1];let k=self.row.2;
        let gap=match self.row.0 {0|5=>k.checked_sub(a).and_then(|v|v.checked_sub(1)).unwrap_or(0),
            1=>a.checked_sub(k).unwrap_or(0),7=>a.checked_sub(k).and_then(|v|v.checked_sub(1)).unwrap_or(0),_=>0};
        let gapnum=alloc(cs.namespace(||"gap"),f(gap))?;
        range(cs.namespace(||"gap bits"),&gapnum,gap,WIDTH)?;
        let mut prev=vec![];
        for j in 0..2 {
            let mut ns=cs.namespace(||format!("previous {j}"));
            let active=alloc(ns.namespace(||"active"),f((ARITY.get(self.row.0 as usize).copied().unwrap_or(0)>j) as u64))?;
            ns.enforce(||"derive active",|mut lc|{for (i,s) in select.iter().enumerate(){if ARITY[i]>j {lc=lc+s.get_variable();}}
                lc-active.get_variable()},|lc|lc+CS::one(),|lc|lc);
            let p=&self.prev[j];
            let id=alloc(ns.namespace(||"index"),f(p.id))?;
            let bits=range(ns.namespace(||"index bits"),&id,p.id,DEPTH)?;
            let gap=self.cursor.checked_sub(p.id).and_then(|v|v.checked_sub(1)).unwrap_or(0);
            let diff=alloc(ns.namespace(||"backward gap"),f(gap))?;
            range(ns.namespace(||"backward gap bits"),&diff,gap,DEPTH)?;
            gate(ns.namespace(||"strict backwards"),&active,-1,&[(1,&z[4]),(-1,&id),(-1,&diff)]);
            let payload=p.payload.iter().enumerate().map(|(i,v)|alloc(ns.namespace(||format!("payload {i}")),f(*v)))
                .collect::<Result<Vec<_>,_>>()?;
            let mut args=vec![rt.clone(),id];args.extend(payload.clone());
            let leaf=h(ns.namespace(||"leaf"),&args)?;
            let sib=siblings(ns.namespace(||"siblings"),&p.path)?;
            let root=merkle(ns.namespace(||"path"),&mn,leaf,&bits,&sib)?;
            gate_eq(ns.namespace(||"authenticate active predecessor"),&active,&root,&z[3]);
            prev.push(payload);
        }
        // All 17 cases are synthesized on every step. Branching below is on a fixed
        // loop index, never the private selector. Thus no witness-dependent shape.
        for op in 0..17 {
            let mut ns=cs.namespace(||format!("rule {op}"));
            let g=&select[op];
            let mut n=0;
            macro_rules! lin {($c:expr; $($coef:expr,$v:expr);+)=>{{
                n+=1;gate(ns.namespace(||format!("condition {n}")),g,$c,&[$(($coef,$v)),+]);
            }}}
            macro_rules! equal {($a:expr,$b:expr)=>{lin!(0;1,$a;-1,$b)}}
            macro_rules! tag {($a:expr,$v:expr)=>{lin!(-($v as i64);1,$a)}}
            macro_rules! prev {($i:expr,$kind:expr,$t:expr,$k:expr,$s:expr,$u:expr)=>{{
                n+=1;ref_match(ns.namespace(||format!("condition {n}")),g,&prev[$i],[$kind,$t,$k,$s,$u]);
            }}}
            if op<5 || op>=11 {equal!(&r[3],&zero);}
            if op>=11 {equal!(&r[2],&zero);}
            if (5..11).contains(&op) {equal!(&x[0],&r[3]);}
            match op {
                // Lift: below cutoff, at/above cutoff, inert constant, lambda, application.
                0=>{tag!(&t[1],0);equal!(&t[0],&u[0]);lin!(-1;1,&r[2];-1,&t[2];-1,&gapnum);}
                1=>{tag!(&t[1],0);tag!(&u[1],0);lin!(0;1,&t[2];-1,&r[2];-1,&gapnum);
                    lin!(-1;1,&u[2];-1,&t[2]);}
                2=>{tag!(&t[1],1);equal!(&t[0],&u[0]);}
                3=>{tag!(&t[1],2);tag!(&u[1],2);prev!(0,&zero,&t[2],&kp,&zero,&u[2]);}
                4=>{tag!(&t[1],3);tag!(&u[1],3);
                    prev!(0,&zero,&t[2],&r[2],&zero,&u[2]);prev!(1,&zero,&t[3],&r[2],&zero,&u[3]);}
                // Substitution with binder removal: below, equal, above, constant, lambda, app.
                5=>{tag!(&t[1],0);equal!(&t[0],&u[0]);lin!(-1;1,&r[2];-1,&t[2];-1,&gapnum);}
                6=>{tag!(&t[1],0);equal!(&t[2],&r[2]);equal!(&u[0],&r[3]);}
                7=>{tag!(&t[1],0);tag!(&u[1],0);lin!(-1;1,&t[2];-1,&r[2];-1,&gapnum);
                    lin!(-1;1,&t[2];-1,&u[2]);}
                8=>{tag!(&t[1],1);equal!(&t[0],&u[0]);}
                9=>{tag!(&t[1],2);tag!(&u[1],2);
                    prev!(0,&zero,&r[3],&zero,&zero,&prev[0][4]);
                    prev!(1,&one,&t[2],&kp,&prev[0][4],&u[2]);}
                10=>{tag!(&t[1],3);tag!(&u[1],3);
                    prev!(0,&one,&t[2],&r[2],&r[3],&u[2]);prev!(1,&one,&t[3],&r[2],&r[3],&u[3]);}
                // Conversion: reflexivity, symmetry, transitivity, beta, lambda/app congruence.
                11=>{equal!(&t[0],&u[0]);}
                12=>{prev!(0,&two,&u[0],&zero,&zero,&t[0]);}
                13=>{prev!(0,&two,&t[0],&zero,&zero,&prev[0][4]);
                     prev!(1,&two,&prev[0][4],&zero,&zero,&u[0]);}
                14=>{tag!(&t[1],3);equal!(&x[0],&t[2]);tag!(&x[1],2);
                     prev!(0,&one,&x[2],&zero,&t[3],&u[0]);}
                15=>{tag!(&t[1],2);tag!(&u[1],2);prev!(0,&two,&t[2],&zero,&zero,&u[2]);}
                16=>{tag!(&t[1],3);tag!(&u[1],3);
                     prev!(0,&two,&t[2],&zero,&zero,&u[2]);prev!(1,&two,&t[3],&zero,&zero,&u[3]);}
                _=>unreachable!()
            }
            let _=n;
        }
        let append=siblings(cs.namespace(||"append siblings"),&self.append)?;
        let old=merkle(cs.namespace(||"empty slot"),&mn,empty,&cur,&append)?;
        eq(cs.namespace(||"bind old proof root"),&old,&z[3]);
        let mut args=vec![rt,z[4].clone()];args.extend(r.clone());
        let leaf=h(cs.namespace(||"new row"),&args)?;
        let root=merkle(cs.namespace(||"write slot"),&mn,leaf,&cur,&append)?;
        let next=Num::alloc(cs.namespace(||"next cursor"),||Ok(z[4].get_value().ok_or(SE::AssignmentMissing)?+F::ONE))?;
        cs.enforce(||"increment cursor",|lc|lc+z[4].get_variable()+CS::one()-next.get_variable(),|lc|lc+CS::one(),|lc|lc);
        Ok(vec![z[0].clone(),z[1].clone(),z[2].clone(),root,next,r[0].clone(),r[1].clone(),r[4].clone()])
    }
}

fn require(ok:bool,msg:&str)->Result<(),Box<dyn Error>> {if ok {Ok(())} else {Err(msg.into())}}
fn prepare(c:&Case)->Result<(Vec<TermStep>,Vec<Vec<F>>),Box<dyn Error>>{
    require(!c.terms.is_empty() && c.terms.len()<=1<<DEPTH && !c.rows.is_empty() && c.rows.len()<=1<<DEPTH,"capacity")?;
    require(c.terms[0]==[1,0,0],"dummy term")?;
    require(c.goal.iter().all(|i|(*i as usize)<c.terms.len()),"goal ids")?;
    let mut seen=std::collections::HashSet::new();
    let mut arena=Tree::new(DEPTH,TERM_NODE);
    for (i,t) in c.terms.iter().enumerate(){
        let [tag,a,b]=*t;
        let valid=match tag {0|1=>a<=65535 && b==0,2=>(a as usize)<i && b==0,3=>(a as usize)<i && (b as usize)<i,_=>false};
        require(valid && seen.insert(*t),"public arena must be canonical and well formed")?;
        arena.set(i as u64,term_leaf(i as u64,*t));
    }
    let open=|id:u64|TermOpening{id,node:c.terms[id as usize],path:arena.path(id)};
    let mut mem=Tree::new(DEPTH,MEM_NODE);
    let mut states=vec![vec![arena.root(),f(c.goal[0]),f(c.goal[1]),mem.root(),F::ZERO,F::ZERO,F::ZERO,F::ZERO]];
    let mut steps=vec![];
    for (i,r) in c.rows.iter().enumerate(){
        require(r.0<17 && r.2<=65535 && [r.1,r.3,r.4].iter().all(|v|(*v as usize)<c.terms.len()),"row admission")?;
        require(r.5.len()==ARITY[r.0 as usize] && r.5.iter().all(|p|*p<i),"reference admission")?;
        let extra=if kind(r.0)==1 {r.3} else if r.0==14 {
            let t=c.terms[r.1 as usize];if t[0]==3 {t[1]}else{0}
        }else{0};
        let ref_open=|j:usize|{
            if let Some(p)=r.5.get(j) {RowOpening{id:*p as u64,payload:c.rows[*p].payload(),path:mem.path(*p as u64)}}
            else {RowOpening{id:0,payload:[0;5],path:mem.path(0)}}
        };
        steps.push(TermStep {cursor:i as u64,row:r.clone(),term:[open(r.1),open(r.4),open(extra)],
            prev:[ref_open(0),ref_open(1)],append:mem.path(i as u64)});
        mem.set(i as u64,row_leaf(i as u64,r.payload()));
        states.push(vec![arena.root(),f(c.goal[0]),f(c.goal[1]),mem.root(),f((i+1) as u64),f(kind(r.0)),f(r.1),f(r.4)]);
    }
    Ok((steps,states))
}
fn check(c:&TermStep,z:&[F],expected:Option<&[F]>)->Result<(bool,usize),SE> {
    let mut cs=TestConstraintSystem::<F>::new();
    let inputs=z.iter().enumerate().map(|(i,v)|alloc(cs.namespace(||format!("input {i}")),*v)).collect::<Result<Vec<_>,_>>()?;
    let outputs=c.synthesize(&mut cs,&inputs)?;
    let matches=expected.map_or(true,|want|outputs.iter().map(|x|x.get_value().unwrap()).eq(want.iter().copied()));
    Ok((cs.which_is_unsatisfied().is_none() && matches,cs.num_constraints()))
}
fn shape(c:&TermStep)->Result<(usize,usize),SE> {
    let mut cs=ShapeCS::<E1>::new();
    let inputs=(0..8).map(|i|alloc(cs.namespace(||format!("input {i}")),F::ZERO)).collect::<Result<Vec<_>,_>>()?;
    c.synthesize(&mut cs,&inputs)?;
    Ok((cs.num_constraints(),cs.num_aux()))
}
fn terminal(z:&[F],z0:&[F],n:usize)->bool{
    z.len()==8 && z0.len()==8 && n>0 && z[..3]==z0[..3] && z[4]==f(n as u64) &&
        z[5]==f(2) && z[6]==z0[1] && z[7]==z0[2]
}
fn main()->Result<(),Box<dyn Error>>{
    let input=std::env::args().nth(1).ok_or("fixture path required")?;
    let mode=std::env::args().nth(2).unwrap_or_else(||"--calibrate".into());
    require(mode=="--calibrate" || mode=="--compress","unknown mode")?;
    let mut bytes=vec![];fs::File::open(input)?.take(262145).read_to_end(&mut bytes)?;
    require(bytes.len()<=262144,"byte cap")?;
    let batch:Batch=serde_json::from_slice(&bytes)?;
    require(batch.schema=="zkl-term-v1" && batch.cases.len()==5,"fixture schema")?;
    let prepared=batch.cases.iter().map(prepare).collect::<Result<Vec<_>,_>>()?;
    let raw=shape(&prepared[0].0[0])?;
    let mut count=0;let mut covered=std::collections::BTreeSet::new();
    for (steps,z) in &prepared{
        for (i,step) in steps.iter().enumerate(){
            require(shape(step)?==raw && check(step,&z[i],Some(&z[i+1]))?.0,"honest step")?;
            covered.insert(step.row.0);count+=1;
        }
        require(terminal(z.last().unwrap(),&z[0],steps.len()),"terminal");
    }
    require(covered.len()==17,"missing rule coverage")?;
    let (steps,z)=&prepared[0];
    let mut attacks=0;
    // Capture fixture: reconstruct coherent authenticated public openings and preceding row
    // references for a WRONG result. All term IDs are legal; the rule is false.
    for (i,field,val) in [(0,4,1),(1,4,1),(2,4,1),(3,4,1),(3,3,1),(1,2,0)]{
        let mut bad=batch.cases[0].clone();
        let r=&mut bad.rows[i];
        match field{2=>r.2=val,3=>r.3=val,4=>r.4=val,_=>unreachable!()}
        let (bs,bz)=prepare(&bad)?;
        require(!check(&bs[i],&bz[i],None)?.0,"coherent mutated row accepted")?;
        attacks+=1;
    }
    let mut bad=steps[2].clone();bad.prev[0].path[0]+=F::ONE;
    require(!check(&bad,&z[2],None)?.0,"forged predecessor accepted")?;attacks+=1;
    let mut bad=steps[2].clone();bad.prev[0].id=2;
    require(!check(&bad,&z[2],None)?.0,"future predecessor accepted")?;attacks+=1;
    let mut bad=steps[2].clone();bad.term[0].path[0]+=F::ONE;
    require(!check(&bad,&z[2],None)?.0,"forged public term accepted")?;attacks+=1;
    let mut bad=steps[2].clone();bad.append[0]+=F::ONE;
    require(!check(&bad,&z[2],None)?.0,"forged append accepted")?;attacks+=1;
    let mut bad=steps[2].clone();bad.row.0=17;
    require(!check(&bad,&z[2],None)?.0,"unknown selector accepted")?;attacks+=1;
    require(!terminal(&z[2],&z[0],2),"early completion accepted")?;
    println!("{}",json!({"scope":"raw_de_bruijn_conversion_public_arena","raw_step_constraints":raw.0,
        "raw_aux_including_state":raw.1,"honest_steps":count,"covered_rules":covered.len(),
        "forged_steps_rejected":attacks,"host_terminal_negative":true}));
    if mode=="--compress"{
        let start=Instant::now();
        let pp=PublicParams::<E1,E2,TermStep>::setup(&steps[0],&*S1::ck_floor(),&*S2::ck_floor())?;
        let setup=start.elapsed().as_secs_f64();
        let start=Instant::now();let (pk,vk)=Proof::setup(&pp)?;
        let compression_setup=start.elapsed().as_secs_f64();
        let mut reports=vec![];
        for (case,(steps,z)) in batch.cases.iter().zip(prepared.iter()){
            let start=Instant::now();
            let mut rec=RecursiveSNARK::<E1,E2,TermStep>::new(&pp,&steps[0],&z[0])?;
            for s in steps{rec.prove_step(&pp,s)?;}
            let fold=start.elapsed().as_secs_f64();
            let expected=z.last().unwrap();
            require(rec.verify(&pp,steps.len(),&z[0])?==*expected,"recursive proof")?;
            let start=Instant::now();let p=Proof::prove(&pp,&pk,&rec)?;
            let prove=start.elapsed().as_secs_f64();
            let bytes=bincode::serialize(&p)?;let received:Proof=bincode::deserialize(&bytes)?;
            let start=Instant::now();let out=received.verify(&vk,steps.len(),&z[0])?;
            let verify=start.elapsed().as_secs_f64();
            require(out==*expected && terminal(&out,&z[0],steps.len()),"compressed terminal")?;
            require(received.verify(&vk,steps.len()+1,&z[0]).is_err(),"wrong count")?;
            for k in [0,1,2,3]{
                let mut wrong=z[0].clone();wrong[k]+=F::ONE;
                require(received.verify(&vk,steps.len(),&wrong).is_err(),"wrong initial state")?;
            }
            reports.push(json!({"name":case.name,"steps":steps.len(),"fold_seconds":fold,
                "compression_prove_seconds":prove,"compressed_verify_seconds":verify,
                "proof_bytes":bytes.len(),"verified":true}));
        }
        println!("{}",json!({"scope":"nova_raw_de_bruijn_conversion","nova":"0.76.0",
            "setup_seconds":setup,"compression_setup_seconds":compression_setup,"cases":reports,
            "augmented_constraints":pp.num_constraints(),"augmented_variables":pp.num_variables(),
            "verification_key_bytes":bincode::serialize(&vk)?.len(),"witness_privacy_claimed":false}));
    }
    Ok(())
}
