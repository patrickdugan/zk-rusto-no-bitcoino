//! PNS-04E: raw transcript compiler for a real Nova IPA opening. Exposes typed
//! BQS slot IDs to the limb/group backend, not an unchecked digest/challenge.
use garbled_snark_verifier::WireId;
use praxis_nova_bqs::Compiler;
use serde_json::{Value,json};
use std::{path::Path,time::Instant};


// Mirror of the pinned Nova 0.76 non-EVM transcript schedule, using the
// existing Keccak gate kernel. Export raw 512-bit state rather than reducing
// it in Boolean long division. The suffix must constrain integer reduction.
use garbled_snark_verifier::{circuit::{FALSE_WIRE,TRUE_WIRE},nova::transcript::keccak256};
fn constant(raw:&[u8])->Vec<WireId>{
    raw.iter().flat_map(|b|(0..8).map(move|i|if b>>i&1!=0{TRUE_WIRE}else{FALSE_WIRE})).collect()
}
fn pair(c:&mut Compiler,input:&[WireId])->Vec<WireId>{
    let mut out=vec![];
    for suffix in [0u8,1]{
        let mut msg=input.to_vec();msg.extend(constant(&[suffix]));
        out.extend(keccak256(c,&msg));
    }
    assert_eq!(out.len(),512);out
}
struct RawTranscript{state:Vec<WireId>,pending:Vec<WireId>,round:u64}
impl RawTranscript{
    fn new(c:&mut Compiler,label:&[u8])->Self{
        let mut input=constant(b"NoTR");input.extend(constant(label));
        Self{state:pair(c,&input),pending:vec![],round:0}
    }
    fn absorb_bytes(&mut self,label:&[u8],repr:&[WireId]){
        self.pending.extend(constant(label));self.pending.extend_from_slice(repr);
    }
    fn dom_sep(&mut self,label:&[u8]){self.pending.extend(constant(b"NoDS"));self.pending.extend(constant(label));}
    fn squeeze(&mut self,c:&mut Compiler,label:&[u8])->Vec<WireId>{
        self.pending.extend(constant(b"NoDS"));self.pending.extend(constant(&self.round.to_le_bytes()));
        self.pending.extend_from_slice(&self.state);self.pending.extend(constant(label));
        self.state=pair(c,&self.pending);self.pending.clear();self.round=self.round.checked_add(1).unwrap();
        self.state.clone()
    }
}

fn bytes(v:&Value)->Vec<u8>{hex::decode(v.as_str().expect("fixture hex")).unwrap()}
fn allocate(c:&mut Compiler,raw:&[u8])->Vec<WireId>{
    raw.iter().flat_map(|b|(0..8).map(move|i|b>>i&1!=0)).map(|b|c.input(b)).collect()
}
fn slots(w:&[WireId])->Vec<u32>{
    w.iter().map(|w|u32::try_from(match w.0{0=>1,1=>0,n=>n}).unwrap()).collect()
}
fn pin(c:&mut Compiler,w:&[WireId],raw:&[u8]){
    assert_eq!(w.len(),8*raw.len());
    for(i,w)in w.iter().enumerate(){c.pin(*w,raw[i/8]>>(i%8)&1!=0);}
}
fn actual(c:&Compiler,w:&[WireId])->Vec<u8>{
    assert_eq!(w.len()%8,0);
    slots(w).chunks_exact(8).map(|bits|bits.iter().enumerate().fold(0u8,|a,(i,w)|a|(c.assignment[*w as usize]<<i))).collect()
}
fn run(f:&Value,dir:&Path){
    let curve=f["curve"].as_str().unwrap();
    assert!(curve=="Pallas"||curve=="Vesta");
    let ell=f["rounds"].as_u64().unwrap() as usize;assert!((1..=3).contains(&ell));
    let t=Instant::now();let mut c=Compiler::new();
    let mut ctx=[0u8;32];ctx[0]=19;
    let context=allocate(&mut c,&ctx);pin(&mut c,&context,&ctx);
    let cb=bytes(&f["commitment"]["encoding"]);assert_eq!(cb.len(),65);
    let comm=allocate(&mut c,&cb);pin(&mut c,&comm,&cb);
    let xb:Vec<_>=f["point"].as_array().unwrap().iter().flat_map(bytes).collect();
    assert_eq!(xb.len(),ell*32);
    let x=allocate(&mut c,&xb);pin(&mut c,&x,&xb);
    let yb=bytes(&f["evaluation"]);assert_eq!(yb.len(),32);
    let y=allocate(&mut c,&yb);pin(&mut c,&y,&yb);
    let mut tr=RawTranscript::new(&mut c,b"pns-ipa-native-v1");
    tr.absorb_bytes(b"context",&context);
    tr.absorb_bytes(b"comm",&comm);
    tr.absorb_bytes(b"point",&x);
    tr.absorb_bytes(b"eval",&y);
    tr.dom_sep(b"IPA");
    let u=comm.iter().chain(&y).copied().collect::<Vec<_>>();
    tr.absorb_bytes(b"U",&u);
    let rho=tr.squeeze(&mut c,b"r");
    assert_eq!(rho.len(),512);
    let mut l_slots=vec![];let mut r_slots=vec![];let mut challenges=vec![];
    for i in 0..ell{
        let lb=bytes(&f["l"][i]["encoding"]);let rb=bytes(&f["r"][i]["encoding"]);
        assert_eq!(lb.len(),65);assert_eq!(rb.len(),65);
        let l=allocate(&mut c,&lb);let r=allocate(&mut c,&rb);
        tr.absorb_bytes(b"L",&l);tr.absorb_bytes(b"R",&r);
        let z=tr.squeeze(&mut c,b"r");assert_eq!(z.len(),512);
        l_slots.push(slots(&l));r_slots.push(slots(&r));challenges.push(slots(&z));
    }
    let suffix=tr.squeeze(&mut c,b"after");assert_eq!(suffix.len(),512);
    let ah=allocate(&mut c,&bytes(&f["a_hat"]));
    c.seal();assert!(c.check(&c.assignment));
    // Commitment/evaluation and point fixed in this isolated relation. L/R and
    // a_hat are free witness bits. All typed field and point admission MUST be
    // enforced by the consumer, since absorb_bytes only constrains hashing.
    let interfaces=json!({"format":"PNS-IPA-RAW-SLOTS/v1","curve":curve,"rounds":ell,
        "commitment":slots(&comm),"point":slots(&x),"evaluation":slots(&y),
        "l":l_slots,"r":r_slots,"a_hat":slots(&ah),"rho":slots(&rho),
        "challenges":challenges,"suffix":slots(&suffix)});
    let mut stats=c.stats();
    stats["curve"]=curve.into();stats["rounds"]=ell.into();stats["raw_hash_slots_exported"]=true.into();
    stats["elapsed_seconds"]=t.elapsed().as_secs_f64().into();
    c.export(dir).unwrap();std::fs::write(dir.join("interfaces.json"),serde_json::to_vec_pretty(&interfaces).unwrap()).unwrap();
    std::fs::write(dir.join("fixture.json"),serde_json::to_vec_pretty(f).unwrap()).unwrap();
    println!("{stats}");
}
fn main(){
    let args:Vec<_>=std::env::args().collect();assert_eq!(args.len(),3,"ipa_raw_transcript FIXTURES_JSON OUTPUT_DIR");
    let fs:Value=serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    let out=Path::new(&args[2]);
    let mut count=0;
    for f in fs["fixtures"].as_array().unwrap(){
        if f["rounds"].as_u64()==Some(1)&&f["variant"].as_u64()==Some(0){
            run(f,&out.join(f["curve"].as_str().unwrap()));count+=1;
        }
    }
    assert_eq!(count,2);
}
