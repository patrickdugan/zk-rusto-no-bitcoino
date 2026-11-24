//! CPU-only three-step compressed Nova proof export. Test keys, no funds.
use ff::Field;
use nova_snark::{nova::{PublicParams,RecursiveSNARK,CompressedSNARK},provider::{PallasEngine,VestaEngine,ipa_pc},spartan::snark::RelaxedR1CSSNARK,traits::snark::RelaxedR1CSSNARKTrait};
use praxis_nova_settlement::{SettlementStep,fixture,native,check_final,state_bytes,synth};
use m18_utxo_window::elem::f_to_le;
use sha2::{Digest,Sha256};
use std::{fs,path::PathBuf,time::Instant};
type E1=PallasEngine;type E2=VestaEngine;
type S1=RelaxedR1CSSNARK<E1,ipa_pc::EvaluationEngine<E1>>;
type S2=RelaxedR1CSSNARK<E2,ipa_pc::EvaluationEngine<E2>>;
type PP=PublicParams<E1,E2,SettlementStep>;
type RS=RecursiveSNARK<E1,E2,SettlementStep>;
type CS=CompressedSNARK<E1,E2,SettlementStep,S1,S2>;
fn main(){
    let path=PathBuf::from(std::env::args().nth(1).expect("usage: praxis-nova-settlement OUTPUT_DIR"));
    fs::create_dir_all(&path).unwrap();
    let (z0,claims,expected,change)=fixture();let steps=claims.len();
    let (constraints,ok,_)=synth(&z0,&claims[0]);assert!(ok);
    let t=Instant::now();let pp=PP::setup(&SettlementStep::default(),&*S1::ck_floor(),&*S2::ck_floor()).unwrap();let pp_s=t.elapsed().as_secs_f64();
    let t=Instant::now();let mut rs=RS::new(&pp,&SettlementStep{claim:claims[0].clone()},&z0).unwrap();
    let mut want=z0;
    for c in &claims{rs.prove_step(&pp,&SettlementStep{claim:c.clone()}).unwrap();want=native(&want,c).unwrap();}
    let fold_s=t.elapsed().as_secs_f64();let verified=rs.verify(&pp,steps,&z0).unwrap();assert_eq!(verified,want);
    assert!(check_final(&z0,&verified,expected,change,steps));
    let t=Instant::now();let (pk,vk)=CS::setup(&pp).unwrap();let setup_s=t.elapsed().as_secs_f64();
    let t=Instant::now();let proof=CS::prove(&pp,&pk,&rs).unwrap();let compress_s=t.elapsed().as_secs_f64();
    let t=Instant::now();let zn=proof.verify(&vk,steps,&z0).unwrap();let verify_s=t.elapsed().as_secs_f64();
    assert_eq!(zn,want);assert!(check_final(&z0,&zn,expected,change,steps));
    let mut wrong=z0;wrong[3]+=m18_utxo_window::elem::F::ONE;
    assert!(proof.verify(&vk,steps,&wrong).is_err());
    assert!(proof.verify(&vk,steps-1,&z0).is_err());
    let p=bincode::serialize(&proof).unwrap();let k=bincode::serialize(&vk).unwrap();
    let mut journal=b"PNV1".to_vec();journal.extend_from_slice(&(steps as u32).to_le_bytes());
    journal.extend_from_slice(&state_bytes(&z0));journal.extend_from_slice(&state_bytes(&zn));
    journal.extend_from_slice(&Sha256::digest(&k));journal.extend_from_slice(&Sha256::digest(&p));
    // Journal is generated AFTER native verification, not a guest-attested SP1 journal.
    for (name,data) in [("proof.bin",p.as_slice()),("vk.bin",k.as_slice()),("z0.bin",&state_bytes(&z0)),("zn.bin",&state_bytes(&zn)),("native-journal.bin",journal.as_slice())]{fs::write(path.join(name),data).unwrap();}
    let report=serde_json::json!({"scope":"test fixture; no SP1 or Praxis settlement authorization","steps":steps,"state_arity":z0.len(),"step_constraints":constraints,"public_params_seconds":pp_s,"fold_seconds":fold_s,"compressed_setup_seconds":setup_s,"compress_seconds":compress_s,"verify_seconds":verify_s,"proof_bytes":p.len(),"vk_bytes":k.len(),"pp_digest_le":hex::encode(f_to_le(&pp.digest())),"vk_sha256":hex::encode(Sha256::digest(&k)),"journal_sha256":hex::encode(Sha256::digest(&journal)),"native_and_compressed_agree":true,"wrong_start_and_step_count_rejected":true});
    fs::write(path.join("receipt.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{report}");
}
