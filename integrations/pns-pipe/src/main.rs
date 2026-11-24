//! PNS-PIPE-01 fixed-shape authenticated gate fault BQS.
//! A local fault for an independently fixed Boolean program, not a Nova verifier.
//! Public session and roots are circuit constants. All witness data are bits.
use garbled_snark_verifier::{CircuitContext,Gate,WireId,
    circuit::{ExecuteMode,FromWires,WiresObject,FALSE_WIRE,TRUE_WIRE},
    nova::{self,PastaField,transcript::keccak256}};
use praxis_nova_bqs::{Compiler,Row};
use sha3::{Digest,Keccak256};
use serde_json::{Value,json};
type H=[u8;32];
const ROW:u8=16;const TRACE:u8=32;
#[derive(Clone,Debug)]
struct Instance {session:H,row_root:H,trace_root:H,row_count:u64,slot_count:u64}
#[derive(Clone,Debug)]
struct Opening{page:H,path:Vec<H>}
#[derive(Clone,Debug)]
struct Witness{row_index:u64,row:H,row_path:Vec<H>,slots:[Opening;3]}
fn depth(n:u64)->usize{assert!(n>0);(64-(n-1).leading_zeros()) as usize}
fn pages(n:u64)->u64{n.div_ceil(256)}
fn hash(b:&[u8])->H{Keccak256::digest(b).into()}
fn leaf(t:u8,s:&H,v:&H)->H{let mut b=vec![t];b.extend(s);b.extend(v);hash(&b)}
fn node(t:u8,s:&H,a:&H,b:&H)->H{let mut v=vec![t+1];v.extend(s);v.extend(a);v.extend(b);hash(&v)}
fn record(a:u64,b:u64,z:u64,t:u8)->H{
    assert!(t<16);let mut r=[0;32];
    r[..8].copy_from_slice(&a.to_le_bytes());r[8..16].copy_from_slice(&b.to_le_bytes());
    r[16..24].copy_from_slice(&z.to_le_bytes());r[24]=t;r
}
fn slots(r:&H)->[u64;3]{std::array::from_fn(|i|u64::from_le_bytes(r[8*i..8*i+8].try_into().unwrap()))}
fn pin(i:u64,v:bool)->H{record(0,0,i,if v{15}else{0})}
fn truth(r:&H,a:u8,b:u8)->u8{(r[24]>>(2*a+b))&1}
fn shape(x:&Instance,w:&Witness)->bool{
    x.row_count>0&&x.slot_count>=2&&w.row_path.len()==depth(x.row_count)&&
    w.slots.iter().all(|p|p.path.len()==depth(pages(x.slot_count)))
}
fn opening(t:u8,s:&H,root:&H,v:&H,mut i:u64,n:u64,path:&[H])->bool{
    if i>=n||path.len()!=depth(n){return false}
    let mut h=leaf(t,s,v);
    for p in path{h=if i&1==0{node(t,s,&h,p)}else{node(t,s,p,&h)};i>>=1;}
    h==*root
}
fn native(x:&Instance,w:&Witness)->bool{
    if !shape(x,w)||w.row[24]>=16||w.row[25..].iter().any(|&x|x!=0)||
       !opening(ROW,&x.session,&x.row_root,&w.row,w.row_index,x.row_count,&w.row_path){return false}
    let mut b=[0;3];
    for (k,i) in slots(&w.row).into_iter().enumerate(){
        let p=&w.slots[k];
        if i>=x.slot_count||!opening(TRACE,&x.session,&x.trace_root,&p.page,i/256,pages(x.slot_count),&p.path){return false}
        b[k]=(p.page[(i%256/8) as usize]>>(i%8))&1;
    }
    truth(&w.row,b[0],b[1])!=b[2]
}
trait Backend:CircuitContext{fn private(&mut self,b:bool)->WireId;}
impl Backend for Compiler{fn private(&mut self,b:bool)->WireId{self.input(b)}}
/// Exact expanded gate count, without allocating the multimegabyte row stream.
struct Counter{next:usize,inputs:u64,gates:u64}
impl Counter{fn new()->Self{Self{next:2,inputs:0,gates:0}}}
impl CircuitContext for Counter{
    type Mode=ExecuteMode;
    fn issue_wire(&mut self)->WireId{let i=self.next;self.next+=1;WireId(i)}
    fn add_gate(&mut self,_:Gate){self.gates+=1;}
    fn with_named_child<I:WiresObject,O:FromWires>(&mut self,_key:[u8;8],inputs:I,f:impl Fn(&mut Self,&I)->O,arity:usize)->O{
        let out=f(self,&inputs);assert_eq!(out.to_wires_vec().len(),arity);out
    }
}
impl Backend for Counter{fn private(&mut self,_:bool)->WireId{self.inputs+=1;self.issue_wire()}}
fn bits(c:&mut impl Backend,raw:&[u8])->Vec<WireId>{
    raw.iter().flat_map(|b|(0..8).map(move|i|b>>i&1!=0)).map(|b|c.private(b)).collect()
}
fn constant(raw:&[u8])->Vec<WireId>{
    raw.iter().flat_map(|b|(0..8).map(move|i|if b>>i&1!=0{TRUE_WIRE}else{FALSE_WIRE})).collect()
}
fn and<C:CircuitContext>(c:&mut C,a:WireId,b:WireId)->WireId{let z=c.issue_wire();c.add_gate(Gate::and(a,b,z));z}
fn or<C:CircuitContext>(c:&mut C,a:WireId,b:WireId)->WireId{let z=c.issue_wire();c.add_gate(Gate::or(a,b,z));z}
fn xor<C:CircuitContext>(c:&mut C,a:WireId,b:WireId)->WireId{let z=c.issue_wire();c.add_gate(Gate::xor(a,b,z));z}
fn not<C:CircuitContext>(c:&mut C,a:WireId)->WireId{xor(c,a,TRUE_WIRE)}
fn mux<C:CircuitContext>(c:&mut C,s:WireId,a:WireId,b:WireId)->WireId{
    let d=xor(c,a,b);let q=and(c,s,d);xor(c,a,q)
}
fn all<C:CircuitContext>(c:&mut C,v:&[WireId])->WireId{v.iter().fold(TRUE_WIRE,|p,&q|and(c,p,q))}
fn less<C:CircuitContext>(c:&mut C,v:&[WireId],bound:u64)->WireId{
    assert_eq!(v.len(),64);let mut b=FALSE_WIRE;
    for (i,&x) in v.iter().enumerate(){let n=not(c,x);b=if (bound>>i)&1==1{or(c,n,b)}else{and(c,n,b)}}
    b
}
fn select<C:CircuitContext>(c:&mut C,mut table:Vec<WireId>,bits:&[WireId])->WireId{
    assert_eq!(table.len(),1usize<<bits.len());
    for &b in bits{table=table.chunks_exact(2).map(|v|mux(c,b,v[0],v[1])).collect();}
    table[0]
}
fn equal<C:CircuitContext>(c:&mut C,a:&[WireId],b:&[WireId])->WireId{
    assert_eq!(a.len(),b.len());let mut ok=TRUE_WIRE;
    for (&x,&y) in a.iter().zip(b){let d=xor(c,x,y);let n=not(c,d);ok=and(c,ok,n);}ok
}
fn hash_wire<C:CircuitContext>(c:&mut C,tag:u8,s:&H,a:&[WireId],b:&[WireId])->Vec<WireId>{
    let mut v=constant(&[tag]);v.extend(constant(s));v.extend(a);v.extend(b);
    // Leaf (65 bytes) and internal node (97 bytes) each fit one Keccak rate block.
    assert!(v.len()==65*8||v.len()==97*8);
    keccak256(c,&v).to_vec()
}
fn merkle<C:Backend>(c:&mut C,tag:u8,session:&H,root:&H,data:&[WireId],idx:&[WireId],path:&[H])->WireId{
    assert!(idx.len()>=path.len());
    let mut h=hash_wire(c,tag,session,data,&[]);
    for (j,p) in path.iter().enumerate(){
        let sibling=bits(c,p);let mut l=Vec::with_capacity(256);let mut r=Vec::with_capacity(256);
        for i in 0..256{
            let d=xor(c,h[i],sibling[i]);let t=and(c,idx[j],d);
            l.push(xor(c,h[i],t));r.push(xor(c,sibling[i],t));
        }
        h=hash_wire(c,tag+1,session,&l,&r);
    }
    equal(c,&h,&constant(root))
}
fn relation<C:Backend>(c:&mut C,x:&Instance,w:&Witness)->WireId{
    assert!(shape(x,w),"noncanonical witness framing");
    let ix=bits(c,&w.row_index.to_le_bytes());let r=bits(c,&w.row);
    let mut conditions=vec![less(c,&ix,x.row_count),merkle(c,ROW,&x.session,&x.row_root,&r,&ix,&w.row_path)];
    // Truth table occupies exactly four bits; all 60 reserved bits must be zero.
    for &b in &r[196..256]{conditions.push(not(c,b));}
    let mut v=vec![];
    for k in 0..3{
        let i=&r[k*64..(k+1)*64];
        conditions.push(less(c,i,x.slot_count));
        let p=&w.slots[k];let page=bits(c,&p.page);
        conditions.push(merkle(c,TRACE,&x.session,&x.trace_root,&page,&i[8..],&p.path));
        v.push(select(c,page,&i[..8]));
    }
    let want=select(c,r[192..196].to_vec(),&[v[1],v[0]]);
    conditions.push(xor(c,want,v[2]));all(c,&conditions)
}
fn eval(x:&Instance,w:&Witness,expected:bool)->Value{
    assert_eq!(native(x,w),expected,"independent native relation");
    let mut c=Compiler::new();let z=relation(&mut c,x,w);c.accept(z);
    assert_eq!(c.check(&c.assignment),expected,"BQS relation");c.seal();
    let stats=c.stats();let mut counter=Counter::new();relation(&mut counter,x,w);
    assert_eq!(counter.gates,c.rows.len() as u64);assert_eq!(counter.inputs,c.inputs().len() as u64);
    json!({"accepted":expected,"stats":stats,"hash_permutations":4+depth(x.row_count)+3*depth(pages(x.slot_count))})
}
fn h(v:&Value)->H{hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()}
fn hp(v:&Value)->Vec<H>{v.as_array().unwrap().iter().map(h).collect()}
fn parse(v:&Value)->(Instance,Witness,bool){
    let x=&v["instance"];let w=&v["witness"];
    let inst=Instance{session:h(&x["session"]),row_root:h(&x["row_root"]),trace_root:h(&x["trace_root"]),
        row_count:x["row_count"].as_u64().unwrap(),slot_count:x["slot_count"].as_u64().unwrap()};
    let wit=Witness{row_index:w["row_index"].as_u64().unwrap(),row:h(&w["row"]),row_path:hp(&w["row_path"]),
        slots:std::array::from_fn(|i|Opening{page:h(&w["slots"][i]["page"]),path:hp(&w["slots"][i]["path"])})};
    (inst,wit,v["expected_fraud"].as_bool().unwrap())
}
struct Tree{layers:Vec<Vec<H>>}
impl Tree{
    fn new(tag:u8,s:&H,v:&[H])->Self{
        let mut l=v.iter().map(|x|leaf(tag,s,x)).collect::<Vec<_>>();
        l.resize(l.len().next_power_of_two(),leaf(tag,s,&[0;32]));let mut layers=vec![l];
        while layers.last().unwrap().len()>1{let p=layers.last().unwrap().chunks_exact(2).map(|v|node(tag,s,&v[0],&v[1])).collect();layers.push(p);}
        Self{layers}
    }
    fn root(&self)->H{self.layers.last().unwrap()[0]}
    fn path(&self,mut i:usize)->Vec<H>{
        let mut p=vec![];for l in &self.layers[..self.layers.len()-1]{p.push(l[i^1]);i>>=1;}p
    }
}
fn compile_row(r:&Row)->H{
    let mut t=0u8;for a in 0..=1i16{for b in 0..=1i16{
        let v=r.d as i16+r.l as i16*a+r.r as i16*b+r.m as i16*a*b;
        assert!((0..=1).contains(&v));t|=(v as u8)<<(2*a+b);
    }}
    record(r.a as u64,r.b as u64,r.z as u64,t)
}
fn row_pass(r:&H,w:&[u8])->bool{let [a,b,z]=slots(r).map(|x|x as usize);w[z]==truth(r,w[a],w[b])}
fn make_witness(s:H,rows:&[H],w:&[u8],i:usize)->(Instance,Witness){
    assert!(w.iter().all(|&x|x<=1));
    let p=w.chunks(256).map(|b|{let mut v=[0;32];for (i,&x) in b.iter().enumerate(){v[i/8]|=x<<(i%8)}v}).collect::<Vec<_>>();
    let rt=Tree::new(ROW,&s,rows);let vt=Tree::new(TRACE,&s,&p);
    let x=Instance{session:s,row_root:rt.root(),trace_root:vt.root(),row_count:rows.len() as u64,slot_count:w.len() as u64};
    let w=Witness{row_index:i as u64,row:rows[i],row_path:rt.path(i),
        slots:slots(&rows[i]).map(|j|{let k=(j/256) as usize;Opening{page:p[k],path:vt.path(k)}})};
    (x,w)
}
fn nova_kernel()->Value{
    // Actual pinned BitVM3 Nova Pasta addition gate graph, a component only.
    // Inputs are independently fixed to (p-1)+1=0, with final accept pinned.
    let f=PastaField::VestaBase;let mut p=f.modulus_le();p[0]-=1;
    let a:Vec<u8>=p.iter().flat_map(|x|x.to_le_bytes()).collect();
    let mut b=[0;32];b[0]=1;let z=[0;32];let mut c=Compiler::new();
    let wa=c.word(&a);let wb=c.word(&b);let wz=c.word(&z);
    let ok=nova::check_add(&mut c,f,&wa,&wb,&wz);c.accept(ok);c.seal();assert!(c.check(&c.assignment));
    let mut rows=vec![pin(0,true),pin(1,false)];
    rows.extend(c.inputs().iter().map(|&i|pin(i as u64,c.assignment[i as usize]==1)));
    rows.extend(c.rows.iter().map(compile_row));rows.extend(c.pins.iter().map(compile_row));
    assert!(rows.iter().all(|r|row_pass(r,&c.assignment)));
    let s=hash(b"PNS-PIPE TEST: pinned Pasta add");let mut bad=c.assignment.clone();
    let gate=&c.rows[c.rows.len()/2];bad[gate.z as usize]^=1;
    let i=rows.iter().position(|r|!row_pass(r,&bad)).unwrap();
    let (x,w)=make_witness(s,&rows,&bad,i);let valid=eval(&x,&w,true);
    let (honest_x,honest_w)=make_witness(s,&rows,&c.assignment,i);
    assert!(!native(&honest_x,&honest_w));assert!(!native(&honest_x,&w));
    json!({"scope":"actual Nova Pasta addition component only","underlying_slots":c.assignment.len(),
        "underlying_gate_rows":c.rows.len(),"instance_rows_including_pins":rows.len(),
        "localized_bad_gate":i,"fault_bqs":valid})
}
fn cost(rows:u64,slots:u64)->Value{
    let d=depth(rows);let t=depth(pages(slots));let zero=[0;32];
    let x=Instance{session:zero,row_root:zero,trace_root:zero,row_count:rows,slot_count:slots};
    let w=Witness{row_index:0,row:zero,row_path:vec![zero;d],slots:std::array::from_fn(|_|Opening{page:zero,path:vec![zero;t]})};
    let mut c=Counter::new();relation(&mut c,&x,&w);
    assert_eq!(c.next as u64,c.inputs+c.gates+2);
    json!({"scenario_rows":rows,"scenario_slots":slots,"row_depth":d,"page_depth":t,
        "hash_permutations":4+d+3*t,"witness_bytes":c.inputs/8,
        "boolean_unknowns":c.next-1,"bqs_equations_excluding_implicit_bitness":c.gates+2,
        "gate_rows":c.gates,"max_products_per_equation":1})
}
fn main(){
    let f:Value=serde_json::from_str(include_str!("../fixtures/cross-page.json")).unwrap();
    let mut reports=vec![];
    for v in f["cases"].as_array().unwrap(){
        let(x,w,expected)=parse(v);let a=eval(&x,&w,expected);
        if expected{
            let mut bad=w.clone();bad.slots.swap(0,1);
            let b=eval(&x,&bad,false);
            assert_eq!(a["stats"]["shape_sha256"],b["stats"]["shape_sha256"]);
            let mut bad=w.clone();bad.row_index=x.row_count;
            let b=eval(&x,&bad,false);
            assert_eq!(a["stats"]["shape_sha256"],b["stats"]["shape_sha256"]);
        }
        reports.push(a);
    }
    let kernel=nova_kernel();
    let costs=[cost(3,520),cost(1<<20,1<<20),cost(1<<33,1<<33)];
    println!("{}",json!({"fixture_results":reports,"native_kernel":kernel,"costs":costs,
        "scope":"Boolean committed trace, exact local relation shape; large sizes are illustrative, not full Nova estimates"}));
}
