//! ZKL-RH-01: bulk typed replay of monomorphic imported Lean core declarations.
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
static PROFILE_DEPTH: OnceLock<usize> = OnceLock::new();
fn depth() -> usize { *PROFILE_DEPTH.get().expect("fixed public circuit profile") }
const WIDTH: usize = 16;
// Separate namespaces for empty, row, rule, memory node, rule node.
const EMPTY: u64 = 401;
const ROW: u64 = 402;
const TERM: u64 = 403;
const MEM_NODE: u64 = 404;
const TERM_NODE: u64 = 405;

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

#[derive(Deserialize)]
struct RuleSpec{kind:u64,arity:usize,conditions:Vec<(i64,Vec<(i64,usize)>)>}
fn specs()->&'static Vec<RuleSpec>{
    static SPEC:OnceLock<Vec<RuleSpec>>=OnceLock::new();
    SPEC.get_or_init(||{
        let s:Vec<RuleSpec>=serde_json::from_str(include_str!("../../bulk-rules.json")).expect("compiled fixed rule program");
        assert_eq!(s.len(),32);
        assert!(s.iter().all(|r|r.arity<=3&&r.kind<=5&&r.conditions.iter().all(|(_,c)|c.iter().all(|(_,i)|*i<54))));
        s
    })
}
#[derive(Clone,Debug,Deserialize)]
struct WireRow(u64,u64,u64,u64,u64,Vec<usize>,[u64;4]);
impl WireRow{
    fn payload(&self)->[u64;5]{
        [specs().get(self.0 as usize).map_or(0,|x|x.kind),self.1,self.2,self.3,self.4]
    }
}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct Case{name:String,arena:Vec<[u64;3]>,rows:Vec<WireRow>,goal:[u64;2]}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch{schema:String,cases:Vec<Case>}
#[derive(Clone,Debug)]
struct Opening{id:u64,node:[u64;3],path:Vec<F>}
#[derive(Clone,Debug)]
struct Prior{id:u64,payload:[u64;5],path:Vec<F>}
#[derive(Clone,Debug)]
struct TermStep{cursor:u64,row:WireRow,opens:[Opening;6],prev:[Prior;3],append:Vec<F>}
fn open_object<CS:ConstraintSystem<F>>(mut cs:CS,o:&Opening,tt:&Num,tn:&Num,root:&Num)->Result<Vec<Num>,SE>{
    let id=alloc(cs.namespace(||"id"),f(o.id))?;
    let bits=range(cs.namespace(||"id bits"),&id,o.id,depth())?;
    let mut vals=vec![id];
    for (j,v) in o.node.iter().enumerate(){vals.push(alloc(cs.namespace(||format!("value {j}")),f(*v))?);}
    let mut args=vec![tt.clone()];args.extend(vals.clone());
    let leaf=h(cs.namespace(||"leaf"),&args)?;
    let sib=siblings(cs.namespace(||"siblings"),&o.path)?;
    let got=merkle(cs.namespace(||"opening"),tn,leaf,&bits,&sib)?;
    eq(cs.namespace(||"bind public arena"),&got,root);
    let tags=(0..7).map(|i|bool_num(cs.namespace(||format!("tag flag {i}")),o.node[0]==i))
        .collect::<Result<Vec<_>,_>>()?;
    cs.enforce(||"one tag",|mut lc|{for a in &tags{lc=lc+a.get_variable();}lc-CS::one()},|lc|lc+CS::one(),|lc|lc);
    cs.enforce(||"tag encoding",|mut lc|{for(i,a)in tags.iter().enumerate(){lc=lc+(f(i as u64),a.get_variable());}lc-vals[1].get_variable()},|lc|lc+CS::one(),|lc|lc);
    let term=alloc(cs.namespace(||"term flag"),f((o.node[0]<5) as u64))?;
    cs.enforce(||"term tag class",|mut lc|{for a in &tags[..5]{lc=lc+a.get_variable();}lc-term.get_variable()},|lc|lc+CS::one(),|lc|lc);
    vals.push(term);Ok(vals)
}
impl StepCircuit<F> for TermStep{
    // Public arena root, goal term, goal type, proof root, cursor,
    // last kind, last context/source, last subject/cutoff, last result/type.
    fn arity(&self)->usize{9}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[Num])->Result<Vec<Num>,SE>{
        let tt=const_num(cs.namespace(||"object tag"),f(TERM))?;
        let tn=const_num(cs.namespace(||"object node tag"),f(TERM_NODE))?;
        let rt=const_num(cs.namespace(||"row tag"),f(ROW))?;
        let mn=const_num(cs.namespace(||"proof node tag"),f(MEM_NODE))?;
        let empty=const_num(cs.namespace(||"empty"),empty())?;
        let cur=range(cs.namespace(||"cursor"),&z[4],self.cursor,depth())?;
        let selected=(0..32).map(|i|bool_num(cs.namespace(||format!("select {i}")),self.row.0==i))
            .collect::<Result<Vec<_>,_>>()?;
        cs.enforce(||"one rule",|mut lc|{for a in &selected{lc=lc+a.get_variable();}lc-CS::one()},|lc|lc+CS::one(),|lc|lc);
        let r=self.row.payload().iter().enumerate().map(|(i,v)|alloc(cs.namespace(||format!("row field {i}")),f(*v)))
            .collect::<Result<Vec<_>,_>>()?;
        cs.enforce(||"row kind",|mut lc|{for(i,a)in selected.iter().enumerate(){lc=lc+(f(specs()[i].kind),a.get_variable());}lc-r[0].get_variable()},|lc|lc+CS::one(),|lc|lc);
        range(cs.namespace(||"cutoff or subject range"),&r[2],self.row.2,WIDTH)?;
        range(cs.namespace(||"lift distance or replacement range"),&r[3],self.row.3,WIDTH)?;
        let mut values=r.clone();
        for (j,o) in self.opens.iter().enumerate(){values.extend(open_object(cs.namespace(||format!("object {j}")),o,&tt,&tn,&z[0])?);}
        for j in 0..3{
            let mut ns=cs.namespace(||format!("prior {j}"));
            let active=alloc(ns.namespace(||"active"),f(specs().get(self.row.0 as usize).is_some_and(|r|r.arity>j) as u64))?;
            ns.enforce(||"derive active",|mut lc|{for(i,a)in selected.iter().enumerate(){if specs()[i].arity>j{lc=lc+a.get_variable();}}lc-active.get_variable()},|lc|lc+CS::one(),|lc|lc);
            let p=&self.prev[j];
            let id=alloc(ns.namespace(||"id"),f(p.id))?;
            let bits=range(ns.namespace(||"id bits"),&id,p.id,depth())?;
            let gap=self.cursor.checked_sub(p.id).and_then(|v|v.checked_sub(1)).unwrap_or(0);
            let diff=alloc(ns.namespace(||"gap"),f(gap))?;
            range(ns.namespace(||"gap bits"),&diff,gap,depth())?;
            gate(ns.namespace(||"strict backwards"),&active,-1,&[(1,&z[4]),(-1,&id),(-1,&diff)]);
            let payload=p.payload.iter().enumerate().map(|(i,v)|alloc(ns.namespace(||format!("field {i}")),f(*v)))
                .collect::<Result<Vec<_>,_>>()?;
            let mut args=vec![rt.clone(),id];args.extend(payload.clone());
            let leaf=h(ns.namespace(||"leaf"),&args)?;
            let sib=siblings(ns.namespace(||"siblings"),&p.path)?;
            let got=merkle(ns.namespace(||"opening"),&mn,leaf,&bits,&sib)?;
            gate_eq(ns.namespace(||"active prior root"),&active,&got,&z[3]);
            values.extend(payload);
        }
        let k=self.row.2;
        let kp=alloc(cs.namespace(||"k plus one"),f(k)+F::ONE)?;
        let bm=alloc(cs.namespace(||"k minus one"),f(k)-F::ONE)?;
        cs.enforce(||"plus one",|lc|lc+r[2].get_variable()+CS::one()-kp.get_variable(),|lc|lc+CS::one(),|lc|lc);
        cs.enforce(||"minus one",|lc|lc+r[2].get_variable()-CS::one()-bm.get_variable(),|lc|lc+CS::one(),|lc|lc);
        let index=self.opens[0].node[1];let u=self.opens[4].node[1];let v=self.opens[5].node[1];
        let gap=match self.row.0{
            0|6=>k.checked_sub(index).and_then(|x|x.checked_sub(1)).unwrap_or(0),
            1=>index.saturating_sub(k),8=>index.checked_sub(k).and_then(|x|x.checked_sub(1)).unwrap_or(0),
            27=>u.saturating_sub(v),28=>v.saturating_sub(u),_=>0};
        let gn=alloc(cs.namespace(||"comparison gap"),f(gap))?;
        range(cs.namespace(||"comparison bits"),&gn,gap,WIDTH)?;
        let vm=v.saturating_sub(1);
        let vn=alloc(cs.namespace(||"universe positive gap"),f(vm))?;
        range(cs.namespace(||"universe gap bits"),&vn,vm,WIDTH)?;
        values.extend([kp,bm,gn,vn]);assert_eq!(values.len(),54);
        // The program is included at compile time. Every branch is synthesized,
        // with the private one-hot selector gating its fixed linear equations.
        for (i,spec) in specs().iter().enumerate(){
            let mut ns=cs.namespace(||format!("rule {i}"));
            for (j,(c,coeff)) in spec.conditions.iter().enumerate(){
                let terms=coeff.iter().map(|(a,i)|(*a,&values[*i])).collect::<Vec<_>>();
                gate(ns.namespace(||format!("condition {j}")),&selected[i],*c,&terms);
            }
        }
        let sib=siblings(cs.namespace(||"append siblings"),&self.append)?;
        let before=merkle(cs.namespace(||"empty slot"),&mn,empty,&cur,&sib)?;
        eq(cs.namespace(||"bind old root"),&before,&z[3]);
        let mut args=vec![rt,z[4].clone()];args.extend(r.clone());
        let leaf=h(cs.namespace(||"new row"),&args)?;
        let after=merkle(cs.namespace(||"append"),&mn,leaf,&cur,&sib)?;
        let next=Num::alloc(cs.namespace(||"next"),||Ok(z[4].get_value().ok_or(SE::AssignmentMissing)?+F::ONE))?;
        cs.enforce(||"next cursor",|lc|lc+z[4].get_variable()+CS::one()-next.get_variable(),|lc|lc+CS::one(),|lc|lc);
        Ok(vec![z[0].clone(),z[1].clone(),z[2].clone(),after,next,r[0].clone(),r[1].clone(),r[2].clone(),r[4].clone()])
    }
}
fn require(ok:bool,msg:&str)->Result<(),Box<dyn Error>>{if ok{Ok(())}else{Err(msg.into())}}
// Only structural admission, no type inference, substitution, reduction or
// prevalidated rule table. This is part of reconstructing the public statement.
fn public_arena(c:&Case)->Result<Tree,Box<dyn Error>>{
    require(c.arena.len()>=2&&c.arena.len()<=1<<depth()&&c.arena[0]==[0,0,0]&&c.arena[1]==[5,0,0],"public arena bounds")?;
    let mut seen=std::collections::HashSet::new();
    let mut tree=Tree::new(depth(),TERM_NODE);
    for(i,&[tag,a,b])in c.arena.iter().enumerate(){
        require(seen.insert([tag,a,b]),"noncanonical arena")?;
        let valid=match tag{
            0=>a<=7&&b==0,1=>a<=65535&&b==0,
            2..=4=>a<i as u64&&b<i as u64&&c.arena[a as usize][0]<5&&c.arena[b as usize][0]<5,
            5=>i==1&&a==0&&b==0,
            6=>a<i as u64&&b<i as u64&&c.arena[a as usize][0]>=5&&c.arena[b as usize][0]<5,
            _=>false};
        require(valid,"public syntax")?;
        tree.set(i as u64,term_leaf(i as u64,[tag,a,b]));
    }
    require(c.goal.iter().all(|v|(*v as usize)<c.arena.len()&&c.arena[*v as usize][0]<5),"goal syntax")?;
    Ok(tree)
}
fn prepare(c:&Case)->Result<(Vec<TermStep>,Vec<Vec<F>>),Box<dyn Error>>{
    let arena=public_arena(c)?;
    require(!c.rows.is_empty()&&c.rows.len()<=1<<depth(),"proof capacity")?;
    let open=|id:u64|Opening{id,node:c.arena[id as usize],path:arena.path(id)};
    let mut mem=Tree::new(depth(),MEM_NODE);
    let mut states=vec![vec![arena.root(),f(c.goal[0]),f(c.goal[1]),mem.root(),F::ZERO,F::ZERO,F::ZERO,F::ZERO,F::ZERO]];
    let mut steps=vec![];
    for(i,r)in c.rows.iter().enumerate(){
        require(r.0<32&&r.2<=65535&&r.3<=65535&&[r.1,r.4].iter().chain(r.6.iter()).all(|v|(*v as usize)<c.arena.len()),"row structural bounds")?;
        require(r.5.len()==specs()[r.0 as usize].arity&&r.5.iter().all(|p|*p<i),"reference admission")?;
        let read=|j:usize|{if let Some(&p)=r.5.get(j){
            Prior{id:p as u64,payload:c.rows[p].payload(),path:mem.path(p as u64)}
        }else{Prior{id:0,payload:[0;5],path:mem.path(0)}}};
        steps.push(TermStep{cursor:i as u64,row:r.clone(),opens:[open(r.1),open(r.4),open(r.6[0]),open(r.6[1]),open(r.6[2]),open(r.6[3])],
            prev:[read(0),read(1),read(2)],append:mem.path(i as u64)});
        let p=r.payload();mem.set(i as u64,row_leaf(i as u64,p));
        states.push(vec![arena.root(),f(c.goal[0]),f(c.goal[1]),mem.root(),f((i+1)as u64),f(p[0]),f(p[1]),f(p[2]),f(p[4])]);
    }
    Ok((steps,states))
}
fn check(c:&TermStep,z:&[F],want:Option<&[F]>)->Result<(bool,usize),SE>{
    let mut cs=TestConstraintSystem::<F>::new();
    let ins=z.iter().enumerate().map(|(i,v)|alloc(cs.namespace(||format!("input {i}")),*v)).collect::<Result<Vec<_>,_>>()?;
    let out=c.synthesize(&mut cs,&ins)?;
    let matches=want.map_or(true,|w|out.iter().map(|x|x.get_value().unwrap()).eq(w.iter().copied()));
    Ok((cs.which_is_unsatisfied().is_none()&&matches,cs.num_constraints()))
}
fn shape(c:&TermStep)->Result<(usize,usize),SE>{
    let mut cs=ShapeCS::<E1>::new();
    let ins=(0..9).map(|i|alloc(cs.namespace(||format!("input {i}")),F::ZERO)).collect::<Result<Vec<_>,_>>()?;
    c.synthesize(&mut cs,&ins)?;Ok((cs.num_constraints(),cs.num_aux()))
}
fn terminal(z:&[F],z0:&[F],n:usize)->bool{
    z.len()==9&&z0.len()==9&&n>0&&z[..3]==z0[..3]&&z[4]==f(n as u64)&&z[5]==f(5)&&z[6]==f(1)&&z[7]==z0[1]&&z[8]==z0[2]
}
fn main()->Result<(),Box<dyn Error>>{
    let input=std::env::args().nth(1).ok_or("fixture path required")?;
    let mode=std::env::args().nth(2).unwrap_or_else(||"--calibrate".into());
    let d:usize=std::env::args().nth(3).unwrap_or_else(||"6".into()).parse()?;
    require(d==6||d==9,"supported profile")?;
    PROFILE_DEPTH.set(d).map_err(|_|"profile already set")?;
    require(mode=="--calibrate"||mode=="--compress","mode")?;
    let mut bytes=vec![];fs::File::open(input)?.take(262145).read_to_end(&mut bytes)?;
    require(bytes.len()<=262144,"byte cap")?;
    let b:Batch=serde_json::from_slice(&bytes)?;
    require(b.schema=="zkl-bulk-v1"&&b.cases.len()==6&&d==9,"registered import batch")?;
    let prepared=b.cases.iter().map(prepare).collect::<Result<Vec<_>,_>>()?;
    let raw=shape(&prepared[0].0[0])?;
    let mut covered=std::collections::BTreeSet::new();
    let mut rows=0;let mut wrong_refs=0;let mut attacked=std::collections::BTreeSet::new();
    for(c,(steps,z))in b.cases.iter().zip(prepared.iter()){
        for(i,s)in steps.iter().enumerate(){
            require(shape(s)?==raw&&check(s,&z[i],Some(&z[i+1]))?.0,"honest step")?;
            covered.insert(s.row.0);rows+=1;
            // A real earlier, correctly opened row with a different judgment.
            if !attacked.contains(&s.row.0) {
                for(j,&p)in c.rows[i].5.iter().enumerate(){
                    if let Some(q)=(0..i).find(|q|c.rows[*q].payload()!=c.rows[p].payload()){
                        let mut bad=c.clone();bad.rows[i].5[j]=q;
                        let(bs,bz)=prepare(&bad)?;
                        require(!check(&bs[i],&bz[i],None)?.0,"coherent wrong premise")?;
                        attacked.insert(s.row.0);wrong_refs+=1;break
                    }
                }
            }
        }
        require(terminal(z.last().unwrap(),&z[0],steps.len()),"terminal")?;
    }
    let (_c,(ss,_z))=(&b.cases[0],&prepared[0]);
    let expected=["zkl_import_id_0","zkl_import_id_1","zkl_import_Function_const_0","zkl_import_Function_const_1","zkl_import_Function_comp_0","zkl_import_Function_comp_1"];
    require(b.cases.iter().map(|c|c.name.as_str()).eq(expected),"registered root order")?;
    println!("{}",json!({"scope":"lean_core_import_bulk_public_syntax","depth":d,"raw_step_constraints":raw.0,
        "raw_aux_including_state":raw.1,"honest_rows":rows,"covered_rules":covered.len(),"coherent_wrong_premises":wrong_refs,
        "native_semantic_compiler":false,"kernel_profile":"ZKL-20"}));
    if mode=="--compress"{
        let start=Instant::now();let pp=PublicParams::<E1,E2,TermStep>::setup(&ss[0],&*S1::ck_floor(),&*S2::ck_floor())?;
        let setup=start.elapsed().as_secs_f64();let start=Instant::now();let(pk,vk)=Proof::setup(&pp)?;let compression_setup=start.elapsed().as_secs_f64();
        let mut reports=vec![];
        for(c,(steps,z))in b.cases.iter().zip(prepared.iter()){
            let start=Instant::now();let mut rec=RecursiveSNARK::<E1,E2,TermStep>::new(&pp,&steps[0],&z[0])?;
            for s in steps{rec.prove_step(&pp,s)?;}let fold=start.elapsed().as_secs_f64();
            let expected=z.last().unwrap();require(rec.verify(&pp,steps.len(),&z[0])?==*expected,"recursive proof")?;
            let start=Instant::now();let p=Proof::prove(&pp,&pk,&rec)?;let prove=start.elapsed().as_secs_f64();
            let bytes=bincode::serialize(&p)?;let p:Proof=bincode::deserialize(&bytes)?;
            let start=Instant::now();let out=p.verify(&vk,steps.len(),&z[0])?;let verify=start.elapsed().as_secs_f64();
            require(out==*expected&&terminal(&out,&z[0],steps.len()),"compressed terminal")?;
            require(p.verify(&vk,steps.len()+1,&z[0]).is_err(),"wrong count")?;
            for j in 0..4{let mut wrong=z[0].clone();wrong[j]+=F::ONE;require(p.verify(&vk,steps.len(),&wrong).is_err(),"wrong public state")?;}
            reports.push(json!({"name":c.name,"objects":c.arena.len(),"steps":steps.len(),"proof_bytes":bytes.len(),"fold_seconds":fold,
                "compression_prove_seconds":prove,"compressed_verify_seconds":verify,"verified":true}));
        }
        println!("{}",json!({"scope":"nova_lean_core_import_bulk_public_syntax","depth":d,"nova":"0.76.0","setup_seconds":setup,"compression_setup_seconds":compression_setup,
            "augmented_constraints":pp.num_constraints(),"augmented_variables":pp.num_variables(),"cases":reports,
            "verification_key_bytes":bincode::serialize(&vk)?.len(),"witness_privacy_claimed":false}));
    }
    Ok(())
}
