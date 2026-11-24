//! PNS-04C: transcript compiler for a real Nova IPA opening. Exposes typed
//! BQS slot IDs to the limb/group backend, not an unchecked digest/challenge.
use garbled_snark_verifier::{WireId,nova::{PastaField,transcript::Transcript}};
use praxis_nova_bqs::Compiler;
use serde_json::{Value,json};
use std::{path::Path,time::Instant};

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
    let field=match curve{"Pallas"=>PastaField::VestaBase,"Vesta"=>PastaField::PallasBase,_=>panic!("curve")};
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
    let mut tr=Transcript::new(&mut c,field,b"pns-ipa-native-v1");
    tr.absorb_bytes(b"context",&context);
    tr.absorb_bytes(b"comm",&comm);
    tr.absorb_bytes(b"point",&x);
    tr.absorb_bytes(b"eval",&y);
    tr.dom_sep(b"IPA");
    let u=comm.iter().chain(&y).copied().collect::<Vec<_>>();
    tr.absorb_bytes(b"U",&u);
    let rho=tr.squeeze(&mut c,b"r");
    c.accept(rho.validity());assert_eq!(actual(&c,rho.bits()),bytes(&f["rho"]));
    let mut l_slots=vec![];let mut r_slots=vec![];let mut challenges=vec![];
    for i in 0..ell{
        let lb=bytes(&f["l"][i]["encoding"]);let rb=bytes(&f["r"][i]["encoding"]);
        assert_eq!(lb.len(),65);assert_eq!(rb.len(),65);
        let l=allocate(&mut c,&lb);let r=allocate(&mut c,&rb);
        tr.absorb_bytes(b"L",&l);tr.absorb_bytes(b"R",&r);
        let z=tr.squeeze(&mut c,b"r");c.accept(z.validity());
        assert_eq!(actual(&c,z.bits()),bytes(&f["challenges"][i]));
        l_slots.push(slots(&l));r_slots.push(slots(&r));challenges.push(slots(z.bits()));
    }
    let suffix=tr.squeeze(&mut c,b"after");c.accept(suffix.validity());
    assert_eq!(actual(&c,suffix.bits()),bytes(&f["suffix"]));
    let ah=allocate(&mut c,&bytes(&f["a_hat"]));
    c.seal();assert!(c.check(&c.assignment));
    // Commitment/evaluation and point fixed in this isolated relation. L/R and
    // a_hat are free witness bits. All typed field and point admission MUST be
    // enforced by the consumer, since absorb_bytes only constrains hashing.
    let interfaces=json!({"format":"PNS-IPA-SLOTS/v1","curve":curve,"rounds":ell,
        "commitment":slots(&comm),"point":slots(&x),"evaluation":slots(&y),
        "l":l_slots,"r":r_slots,"a_hat":slots(&ah),"rho":slots(rho.bits()),
        "challenges":challenges,"suffix":slots(suffix.bits())});
    let mut stats=c.stats();
    stats["curve"]=curve.into();stats["rounds"]=ell.into();stats["native_challenges_match"]=true.into();
    stats["elapsed_seconds"]=t.elapsed().as_secs_f64().into();
    c.export(dir).unwrap();std::fs::write(dir.join("interfaces.json"),serde_json::to_vec_pretty(&interfaces).unwrap()).unwrap();
    std::fs::write(dir.join("fixture.json"),serde_json::to_vec_pretty(f).unwrap()).unwrap();
    println!("{stats}");
}
fn main(){
    let args:Vec<_>=std::env::args().collect();assert_eq!(args.len(),3,"ipa_transcript FIXTURES_JSON OUTPUT_DIR");
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
