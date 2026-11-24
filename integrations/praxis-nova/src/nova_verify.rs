//! PNS1 native Nova verification oracle. This is the reference for a future
//! constraint compiler, not a proof of the verifier's execution.
use crate::{boundary::Boundary, SettlementStep, F, NZ, CAP, MAX_MONEY, fu, u64_field};
use ff::{Field, PrimeField};
use m18_utxo_window::elem::hash;
use nova_snark::{nova::{CompressedSNARK,VerifierKey},provider::{PallasEngine,VestaEngine,ipa_pc},spartan::snark::RelaxedR1CSSNARK};
use bincode::Options;
use serde::{Serialize,de::DeserializeOwned};
use sha2::{Digest,Sha256};
use std::{fs::File,io::Read,path::Path};
type E1=PallasEngine;type E2=VestaEngine;
type S1=RelaxedR1CSSNARK<E1,ipa_pc::EvaluationEngine<E1>>;
type S2=RelaxedR1CSSNARK<E2,ipa_pc::EvaluationEngine<E2>>;
pub type Proof=CompressedSNARK<E1,E2,SettlementStep,S1,S2>;
pub type VK=VerifierKey<E1,E2,SettlementStep,S1,S2>;
pub const JOURNAL_BYTES:usize=440;
pub const MAX_KEY:usize=256*1024*1024;
pub const MAX_PROOF:usize=8*1024*1024;
pub fn digest(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn fe(b:&[u8])->Result<F,String>{
    let mut r=<F as PrimeField>::Repr::default();
    r.as_mut().copy_from_slice(b);
    Option::<F>::from(F::from_repr(r)).ok_or("noncanonical field".into())
}
pub fn parse_statement(j:&[u8],expected_journal:[u8;32],expected_vk:[u8;32])->Result<Boundary,String>{
    if j.len()!=JOURNAL_BYTES||&j[..4]!=b"PNS1"||digest(j)!=expected_journal||
       expected_vk==[0;32]||j[408..440]!=expected_vk {
        return Err("statement or independent pin mismatch".into());
    }
    let steps=u32::from_le_bytes(j[4..8].try_into().unwrap()) as usize;
    let mut z0=[F::ZERO;NZ];
    for (i,b) in j[8..360].chunks_exact(32).enumerate(){z0[i]=fe(b)?;}
    for i in [0,1,3,4]{
        if z0[i].to_repr().as_ref()[16..].iter().any(|&x|x!=0){return Err("128-bit limb".into())}
    }
    let budget=u64_field(z0[6]).ok_or("budget integer")?;
    let change=u64::from_le_bytes(j[392..400].try_into().unwrap());
    let next=u64::from_le_bytes(j[400..408].try_into().unwrap());
    if steps==0||steps>CAP as usize||u64_field(z0[5])!=Some(steps as u64)||
       budget>MAX_MONEY||change>budget||next==0||next>CAP||
       z0[7]!=F::ZERO||z0[8]!=F::ZERO||z0[9]!=z0[6]||
       z0[10]!=hash(&[fu(crate::START),z0[0],z0[1]]) {
        return Err("invalid initial or terminal boundary".into());
    }
    let b=Boundary{z0,expected_payout:fe(&j[360..392])?,expected_change:change,
        expected_next_index:next,vk_sha256:expected_vk};
    if b.journal().map_err(str::to_owned)?.as_slice()!=j{return Err("noncanonical statement".into())}
    Ok(b)
}
fn decode<T:DeserializeOwned+Serialize>(raw:&[u8],limit:usize)->Result<T,String>{
    if raw.is_empty()||raw.len()>limit{return Err("artifact size".into())}
    let x:T=bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(limit as u64).deserialize(raw).map_err(|e|e.to_string())?;
    if bincode::serialize(&x).map_err(|e|e.to_string())?!=raw{return Err("noncanonical artifact".into())}
    Ok(x)
}
/// Requires trusted independent pins, never derives expected pins from the
/// presented artifacts. For research fixtures use process resource limits;
/// generic bincode decoding is not a hardened hostile-input parser.
pub fn verify(j:&[u8],key:&[u8],proof:&[u8],expected_journal:[u8;32],expected_vk:[u8;32])->Result<Vec<F>,String>{
    let b=parse_statement(j,expected_journal,expected_vk)?;
    if key.len()>MAX_KEY||digest(key)!=expected_vk{return Err("Nova key mismatch".into())}
    let vk:VK=decode(key,MAX_KEY)?;
    let p:Proof=decode(proof,MAX_PROOF)?;
    let n=b.count().ok_or("count")?;
    let zn=p.verify(&vk,n,&b.z0).map_err(|e|format!("Nova rejected: {e:?}"))?;
    if !b.accepts_verified_state(&zn,n){return Err("final boundary mismatch".into())}
    Ok(zn)
}
fn read(path:&Path,max:usize)->Result<Vec<u8>,String>{
    let mut b=Vec::new();File::open(path).map_err(|e|e.to_string())?.take((max+1) as u64)
        .read_to_end(&mut b).map_err(|e|e.to_string())?;
    if b.len()>max{return Err("oversize file".into())}Ok(b)
}
pub fn verify_dir(dir:&Path,j:[u8;32],vk:[u8;32])->Result<Vec<F>,String>{
    verify(&read(&dir.join("pns1-stable-statement.bin"),JOURNAL_BYTES)?,
        &read(&dir.join("vk.bin"),MAX_KEY)?,&read(&dir.join("proof.bin"),MAX_PROOF)?,j,vk)
}
