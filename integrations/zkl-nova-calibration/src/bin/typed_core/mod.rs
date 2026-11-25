//! ZKL-18: public-syntax dependent Pi core compiled to authenticated inferences.
//! Native semantic admission is part of the verifier TCB.
use super::*;
use std::collections::{BTreeMap,BTreeSet};

type R<T> = Result<T,Box<dyn Error>>;
type Judgment = [u64;4]; // [kind=0 WF or 1 typing, context, term, type]
const RULE_D:usize=6;
const MEM_D:usize=6;
const MAX_NODES:usize=256;
const MAX_TREE:usize=4096;
const MAX_HEIGHT:usize=64;
const MAX_LEVEL:u64=7;
const MAX_INDEX:u64=65535;

#[derive(Clone,Debug,PartialEq,Eq)]
enum Expr {
    Sort(u64), Var(u64),
    Pi(Box<Expr>,Box<Expr>), Lam(Box<Expr>,Box<Expr>), App(Box<Expr>,Box<Expr>),
}
use Expr::*;
fn pair(tag:u64,a:Expr,b:Expr)->Expr{
    match tag {2=>Pi(Box::new(a),Box::new(b)),3=>Lam(Box::new(a),Box::new(b)),4=>App(Box::new(a),Box::new(b)),_=>unreachable!()}
}
fn sort_level(t:&Expr)->R<u64>{
    if let Sort(u)=t {Ok(*u)}else{Err("expected sort".into())}
}
fn imax(u:u64,v:u64)->u64{if v==0{0}else{u.max(v)}}
fn metric(t:&Expr,depth:usize)->R<usize>{
    require(depth<=MAX_HEIGHT,"expression depth")?;
    let n=match t{
        Sort(u)=>{require(*u<=MAX_LEVEL,"universe bound")?;1},
        Var(i)=>{require(*i<=MAX_INDEX,"variable bound")?;1},
        Pi(a,b)|Lam(a,b)|App(a,b)=>1+metric(a,depth+1)?+metric(b,depth+1)?,
    };
    require(n<=MAX_TREE,"expanded expression bound")?;
    Ok(n)
}
struct Fuel(usize);
impl Fuel {
    fn charge(&mut self,n:usize,depth:usize)->R<()>{
        require(depth<=MAX_HEIGHT && n<=self.0,"operation fuel or depth")?;
        self.0-=n;Ok(())
    }
}
fn lift(t:&Expr,k:u64,delta:u64,gas:&mut Fuel,depth:usize)->R<Expr>{
    gas.charge(1,depth)?;
    Ok(match t{
        Sort(u)=>Sort(*u),
        Var(i)=>{let v=if *i>=k {i.checked_add(delta).ok_or("index overflow")?}else{*i};require(v<=MAX_INDEX,"lift bound")?;Var(v)},
        Pi(a,b)=>pair(2,lift(a,k,delta,gas,depth+1)?,lift(b,k+1,delta,gas,depth+1)?),
        Lam(a,b)=>pair(3,lift(a,k,delta,gas,depth+1)?,lift(b,k+1,delta,gas,depth+1)?),
        App(a,b)=>pair(4,lift(a,k,delta,gas,depth+1)?,lift(b,k,delta,gas,depth+1)?),
    })
}
// Independent depth-accumulator substitution: lift only at a replaced occurrence.
fn sub(t:&Expr,s:&Expr,k:u64,d:u64,gas:&mut Fuel,depth:usize)->R<Expr>{
    gas.charge(1,depth)?;
    Ok(match t{
        Sort(u)=>Sort(*u),
        Var(i)=>{let target=k+d;if *i==target{lift(s,0,d,gas,depth+1)?}else{Var(*i-u64::from(*i>target))}},
        Pi(a,b)=>pair(2,sub(a,s,k,d,gas,depth+1)?,sub(b,s,k,d+1,gas,depth+1)?),
        Lam(a,b)=>pair(3,sub(a,s,k,d,gas,depth+1)?,sub(b,s,k,d+1,gas,depth+1)?),
        App(a,b)=>pair(4,sub(a,s,k,d,gas,depth+1)?,sub(b,s,k,d,gas,depth+1)?),
    })
}
fn nf(t:&Expr,gas:&mut Fuel,depth:usize)->R<Expr>{
    gas.charge(1,depth)?;
    let v=match t{
        Sort(u)=>Sort(*u),Var(i)=>Var(*i),
        Pi(a,b)=>pair(2,nf(a,gas,depth+1)?,nf(b,gas,depth+1)?),
        Lam(a,b)=>pair(3,nf(a,gas,depth+1)?,nf(b,gas,depth+1)?),
        App(a,b)=>{
            let fun=nf(a,gas,depth+1)?;
            match fun {
                Lam(_,body)=>{
                    let reduced=sub(&body,b,0,0,gas,depth+1)?;
                    metric(&reduced,0)?;
                    nf(&reduced,gas,depth+1)?
                },
                fun=>pair(4,fun,nf(b,gas,depth+1)?),
            }
        }
    };
    metric(&v,0)?;
    Ok(v)
}

#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Case{
    name:String, terms:Vec<[u64;3]>, contexts:Vec<[u64;2]>,
    descriptors:Vec<[u64;7]>, steps:Vec<WireStepTyped>, goal:Judgment,
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct WireStepTyped{rule:usize,refs:Vec<usize>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch{schema:String,cases:Vec<Case>}
fn wf(c:u64)->Judgment{[0,c,0,0]}
fn ty(c:u64,t:u64,a:u64)->Judgment{[1,c,t,a]}
fn arena(c:&Case)->R<Vec<Expr>>{
    require(!c.terms.is_empty()&&c.terms.len()<=MAX_NODES,"term capacity")?;
    require(c.terms[0]==[0,0,0],"canonical first term")?;
    let mut terms:Vec<Expr>=vec![];let mut sizes:Vec<usize>=vec![];let mut heights:Vec<usize>=vec![];
    let mut seen=BTreeSet::new();
    for (i,&[tag,a,b]) in c.terms.iter().enumerate(){
        require(seen.insert([tag,a,b]),"duplicate public term")?;
        let (expr,n,d)=match tag{
            0|1=>{require(b==0,"noncanonical atom")?;
                (if tag==0{Sort(a)}else{Var(a)},1,1)},
            2..=4=>{
                require(a<i as u64&&b<i as u64,"cyclic or forward term")?;
                let (a,b)=(a as usize,b as usize);
                let n=1+sizes[a]+sizes[b];let d=1+heights[a].max(heights[b]);
                require(n<=MAX_TREE&&d<=MAX_HEIGHT,"expanded syntax cap")?;
                (pair(tag,terms[a].clone(),terms[b].clone()),n,d)
            }
            _=>return Err("unknown term tag".into()),
        };
        metric(&expr,0)?;terms.push(expr);sizes.push(n);heights.push(d);
    }
    require(!c.contexts.is_empty()&&c.contexts.len()<=MAX_NODES&&c.contexts[0]==[0,0],"empty context")?;
    let mut contexts=BTreeSet::new();
    for(i,&[parent,a])in c.contexts.iter().enumerate().skip(1){
        require(parent<i as u64&&a<c.terms.len() as u64&&contexts.insert([parent,a]),"context syntax")?;
    }
    Ok(terms)
}
fn expand(c:&Case,ts:&[Expr],d:[u64;7])->R<(Judgment,Vec<Judgment>)>{
    let [op,g,t,a,e,u,v]=d;
    let nt=ts.len() as u64;let nc=c.contexts.len() as u64;
    require(g<nc&&e<nc&&[t,a,u,v].iter().all(|x|*x<nt),"descriptor indices")?;
    let term=|i:u64|&ts[i as usize];
    let node=|i:u64|c.terms[i as usize];
    let ctx=|i:u64|c.contexts[i as usize];
    let mut gas=Fuel(100000);
    let out=ty(g,t,a);
    Ok(match op{
        0=>{require(d==[0;7],"empty WF rule")?;(wf(0),vec![])},
        1=>{
            require(g>0&&t==0&&a==0&&e==0&&v==0,"extend descriptor")?;
            sort_level(term(u))?;
            let [parent,binder]=ctx(g);
            (wf(g),vec![wf(parent),ty(parent,binder,u)])
        },
        2=>{
            require(e==0&&u==0&&v==0,"sort descriptor")?;
            let level=sort_level(term(t))?;
            require(*term(a)==Sort(level+1),"sort successor")?;
            (out,vec![wf(g)])
        },
        3=>{
            require(e==0&&u==0&&v==0,"variable descriptor")?;
            let Var(i)=term(t)else{return Err("expected variable".into())};
            require(*i<nc,"unbound variable")?;
            let mut cidx=g;
            for _ in 0..*i {require(cidx>0,"unbound variable")?;cidx=ctx(cidx)[0];}
            require(cidx>0,"unbound variable")?;
            let binder=ctx(cidx)[1];
            let lifted=lift(term(binder),0,*i+1,&mut gas,0)?;
            require(lifted==*term(a),"variable type shift")?;
            (out,vec![wf(g)])
        },
        4=>{
            let [tag,dom,body]=node(t);
            require(tag==2&&e>0&&ctx(e)==[g,dom],"Pi binder context")?;
            let s=imax(sort_level(term(u))?,sort_level(term(v))?);
            require(*term(a)==Sort(s),"Pi universe")?;
            (out,vec![ty(g,dom,u),ty(e,body,v)])
        },
        5=>{
            let [tag,dom,body]=node(t);let [ptag,pdom,cod]=node(a);
            require(tag==3&&ptag==2&&dom==pdom&&e>0&&ctx(e)==[g,dom]&&v==0,"lambda binder or type")?;
            sort_level(term(u))?;
            (out,vec![ty(g,a,u),ty(e,body,cod)])
        },
        6=>{
            let [tag,fun,arg]=node(t);let [ptag,dom,cod]=node(u);
            require(tag==4&&ptag==2&&e==0&&v==0,"dependent application")?;
            let result=sub(term(cod),term(arg),0,0,&mut gas,0)?;
            metric(&result,0)?;
            require(result==*term(a),"dependent application substitution")?;
            (out,vec![ty(g,fun,u),ty(g,arg,dom)])
        },
        7=>{
            require(e==0,"conversion descriptor")?;
            sort_level(term(v))?;
            require(nf(term(u),&mut gas,0)?==nf(term(a),&mut gas,0)?,"not beta convertible")?;
            (out,vec![ty(g,t,u),ty(g,a,v)])
        },
        _=>return Err("unknown typed rule".into()),
    })
}
struct Compiled{
    rules:Vec<Rule>,expanded:Vec<(Judgment,Vec<Judgment>)>,goal:u64,
    statement:String,statement_fields:[F;2],
}
fn digest_fields(bytes:&[u8])->[F;2]{
    let digest=Sha256::digest(bytes);
    let mut out=[F::ZERO;2];
    for (i,v) in out.iter_mut().enumerate(){
        for b in &digest[i*16..(i+1)*16]{*v=*v*f(256)+f(*b as u64);}
    }
    out
}
// Never reads witness steps: checks every public local inference first.
fn compile(c:&Case)->R<Compiled>{
    let ts=arena(c)?;
    require(!c.descriptors.is_empty()&&c.descriptors.len()<=1<<RULE_D,"rule capacity")?;
    require(c.goal[0]==1&&c.goal[1]==0&&c.goal[2]<ts.len() as u64&&c.goal[3]<ts.len() as u64,"closed typing goal")?;
    let mut expanded=vec![];let mut atoms=BTreeSet::new();
    for d in &c.descriptors{
        let (out,prem)=expand(c,&ts,*d)?;
        atoms.insert(out);atoms.extend(prem.iter().copied());expanded.push((out,prem));
    }
    require(atoms.len()<=65535,"judgment index capacity")?;
    let ids:BTreeMap<_,_>=atoms.into_iter().enumerate().map(|(i,j)|(j,i as u64)).collect();
    let goal=*ids.get(&c.goal).ok_or("missing goal judgment")?;
    let rules=expanded.iter().map(|(out,prem)|{
        let mut args=[0;2];
        for(i,j)in prem.iter().enumerate(){args[i]=ids[j];}
        Rule{head:ids[out],bound:false,active:[!prem.is_empty(),prem.len()==2],premises:args}
    }).collect();
    let public=serde_json::to_vec(&json!({"schema":"zkl-typed-public-v1","terms":c.terms,
        "contexts":c.contexts,"descriptors":c.descriptors,"goal":c.goal}))?;
    Ok(Compiled{rules,expanded,goal,statement:digest(&public),statement_fields:digest_fields(&public)})
}

#[derive(Clone,Debug)]
struct TypedStep{inner:RowStep}
impl StepCircuit<F> for TypedStep{
    fn arity(&self)->usize{7}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[Num])->Result<Vec<Num>,SE>{
        let mut result=self.inner.synthesize(cs,&z[..5])?;
        // Bind the public syntax even if distinct statements compile to isomorphic graphs.
        result.extend_from_slice(&z[5..7]);Ok(result)
    }
}
type TypedProof=CompressedSNARK<E1,E2,TypedStep,S1,S2>;

fn prepare(c:&Case,compiled:&Compiled)->R<(Vec<TypedStep>,Vec<Vec<F>>)>{
    require(!c.steps.is_empty()&&c.steps.len()<=1<<MEM_D,"proof capacity")?;
    let mut env=Tree::new(RULE_D,RULE_NODE);
    for(i,r)in compiled.rules.iter().enumerate(){env.set(i as u64,r.leaf(i as u64));}
    let mut mem=Tree::new(MEM_D,MEM_NODE);
    let mut z=vec![env.root(),f(compiled.goal),mem.root(),F::ZERO,F::ZERO];
    z.extend_from_slice(&compiled.statement_fields);
    let mut states=vec![z.clone()];let mut steps=vec![];
    for(i,w)in c.steps.iter().enumerate(){
        let r=*compiled.rules.get(w.rule).ok_or("unknown descriptor")?;
        let n=compiled.expanded[w.rule].1.len();
        require(w.refs.len()==n&&w.refs.iter().all(|j|*j<i),"premise reference admission")?;
        let mut refs=[0u64;2];for(j,p)in w.refs.iter().enumerate(){refs[j]=*p as u64;}
        // Does not check premise semantics: circuit must reject wrong authenticated prior fact.
        let cursor=i as u64;
        steps.push(TypedStep{inner:RowStep{depth:MEM_D,rule_depth:RULE_D,slots:2,cursor,
            rid:w.rule as u64,binder:0,rule:r,rule_path:env.path(w.rule as u64),refs,
            read_paths:[mem.path(refs[0]),mem.path(refs[1])],append:mem.path(cursor)}});
        mem.set(cursor,row(cursor,r.head));
        z[2]=mem.root();z[3]=f(cursor+1);z[4]=f(r.head);states.push(z.clone());
    }
    Ok((steps,states))
}
fn typed_shape(s:&TypedStep)->R<(usize,usize)>{
    let mut cs=ShapeCS::<E1>::new();
    let inputs=(0..7).map(|i|alloc(cs.namespace(||format!("input {i}")),F::ZERO)).collect::<Result<Vec<_>,_>>()?;
    s.synthesize(&mut cs,&inputs)?;
    Ok((cs.num_constraints(),cs.num_aux()))
}
fn typed_check(s:&TypedStep,z:&[F],expected:Option<&[F]>)->R<bool>{
    let mut cs=TestConstraintSystem::<F>::new();
    let inputs=z.iter().enumerate().map(|(i,v)|alloc(cs.namespace(||format!("input {i}")),*v)).collect::<Result<Vec<_>,_>>()?;
    let output=s.synthesize(&mut cs,&inputs)?;
    Ok(cs.which_is_unsatisfied().is_none()&&expected.map_or(true,|want|output.iter().map(|x|x.get_value().unwrap()).eq(want.iter().copied())))
}
fn final_check(out:&[F],initial:&[F],n:usize)->bool{
    out.len()==7&&initial.len()==7&&terminal(&out[..5],&initial[..5],n)&&out[5..7]==initial[5..7]
}
fn attack_compile(cases:&[Case])->R<usize>{
    let mut bad=vec![];
    let mut c=cases[0].clone();c.contexts[1][0]=1;bad.push(c);
    let mut c=cases[0].clone();let t=c.terms[0];c.terms.push(t);bad.push(c);
    let mut c=cases[0].clone();let d=c.descriptors.iter_mut().find(|d|d[0]==0).unwrap();d[1]=1;bad.push(c);
    for (ci,op,field)in [(0,3,3),(1,6,3),(0,4,3),(0,5,3),(3,7,3)]{
        let mut c=cases[ci].clone();let nt=c.terms.len() as u64;
        let d=c.descriptors.iter_mut().find(|d|d[0]==op).unwrap();
        if op==3||op==6||op==4{d[field]=(d[field]+1)%nt;}else{d[field]=0;}
        bad.push(c);
    }
    let mut c=cases[0].clone();
    let v=c.terms.iter().position(|t|t[0]==1).unwrap() as u64;
    c.descriptors.iter_mut().find(|d|d[0]==1).unwrap()[5]=v;bad.push(c);
    for c in &bad{require(compile(c).is_err(),"invalid public inference accepted")?;}
    Ok(bad.len())
}
pub(super) fn run(path:&Path)->R<()>{
    let mut bytes=vec![];fs::File::open(path)?.take(262145).read_to_end(&mut bytes)?;
    require(bytes.len()<=262144,"input byte cap")?;
    let batch:Batch=serde_json::from_slice(&bytes)?;
    require(batch.schema=="zkl-typed-public-v1"&&batch.cases.len()==5,"fixture batch")?;
    let mut prepared=vec![];let mut coverage=BTreeSet::new();
    let mut count=0;
    for c in &batch.cases{
        let compiled=compile(c)?;
        let (steps,states)=prepare(c,&compiled)?;
        for(i,s)in steps.iter().enumerate(){
            require(typed_check(s,&states[i],Some(&states[i+1]))?,"honest typed step")?;
            coverage.insert(c.descriptors[c.steps[i].rule][0]);count+=1;
        }
        require(final_check(states.last().unwrap(),&states[0],steps.len()),"typed terminal")?;
        prepared.push((compiled,steps,states));
    }
    require(coverage.len()==8,"missing typing rule coverage")?;
    let raw=typed_shape(&prepared[0].1[0])?;
    for(_,steps,_)in &prepared{for s in steps{require(typed_shape(s)?==raw,"witness-dependent shape")?;}}
    let semantic_attacks=attack_compile(&batch.cases)?;
    let (compiled,steps,z)=&prepared[0];
    let mut wrong=batch.cases[0].clone();wrong.steps[4].refs[0]=0;
    let (ws,wz)=prepare(&wrong,compiled)?;
    require(!typed_check(&ws[4],&wz[4],None)?,"coherent wrong premise")?;
    let mut bad=steps[4].clone();bad.inner.refs[0]=4;
    require(!typed_check(&bad,&z[4],None)?,"forward premise")?;
    let mut bad=steps[4].clone();bad.inner.rule.head^=1;
    require(!typed_check(&bad,&z[4],None)?,"changed rule conclusion")?;
    let mut bad=steps[4].clone();bad.inner.append[0]+=F::ONE;
    require(!typed_check(&bad,&z[4],None)?,"forged append")?;
    require(!final_check(&z[4],&z[0],4),"early terminal")?;
    println!("{}",json!({"scope":"compiled_public_dependent_pi","raw_step_constraints":raw.0,
        "raw_aux_including_state":raw.1,"honest_rows":count,"covered_rules":coverage.len(),
        "public_compiler_negatives":semantic_attacks,"constraint_negatives":4,
        "fixture_sha256":digest(&bytes),"native_compiler_in_tcb":true}));
    let first=&prepared[0].1[0];
    let start=Instant::now();
    let pp=PublicParams::<E1,E2,TypedStep>::setup(first,&*S1::ck_floor(),&*S2::ck_floor())?;
    let setup=start.elapsed().as_secs_f64();
    let start=Instant::now();let (pk,vk)=TypedProof::setup(&pp)?;
    let compression_setup=start.elapsed().as_secs_f64();
    let mut reports=vec![];
    for(c,(compiled,steps,z))in batch.cases.iter().zip(prepared.iter()){
        let start=Instant::now();
        let mut rec=RecursiveSNARK::<E1,E2,TypedStep>::new(&pp,&steps[0],&z[0])?;
        for s in steps{rec.prove_step(&pp,s)?;}
        let fold=start.elapsed().as_secs_f64();
        let expected=z.last().unwrap();
        require(rec.verify(&pp,steps.len(),&z[0])?==*expected,"recursive proof")?;
        let start=Instant::now();let p=TypedProof::prove(&pp,&pk,&rec)?;
        let prove=start.elapsed().as_secs_f64();
        let bytes=bincode::serialize(&p)?;let received:TypedProof=bincode::deserialize(&bytes)?;
        let start=Instant::now();let out=received.verify(&vk,steps.len(),&z[0])?;
        let verify=start.elapsed().as_secs_f64();
        require(out==*expected&&final_check(&out,&z[0],steps.len()),"compressed typed terminal")?;
        require(received.verify(&vk,steps.len()+1,&z[0]).is_err(),"wrong count")?;
        for k in [0,1,2,5,6]{
            let mut wrong=z[0].clone();wrong[k]+=F::ONE;
            require(received.verify(&vk,steps.len(),&wrong).is_err(),"wrong initial statement")?;
        }
        reports.push(json!({"name":c.name,"terms":c.terms.len(),"contexts":c.contexts.len(),
            "public_rules":c.descriptors.len(),"steps":steps.len(),"statement_sha256":compiled.statement,
            "fold_seconds":fold,"compression_prove_seconds":prove,"compressed_verify_seconds":verify,
            "proof_bytes":bytes.len(),"verified":true}));
    }
    println!("{}",json!({"scope":"nova_compiled_public_dependent_pi","nova":"0.76.0","setup_seconds":setup,
        "compression_setup_seconds":compression_setup,"cases":reports,"augmented_constraints":pp.num_constraints(),
        "augmented_variables":pp.num_variables(),"verification_key_bytes":bincode::serialize(&vk)?.len(),
        "native_compiler_in_tcb":true,"witness_privacy_claimed":false}));
    Ok(())
}
