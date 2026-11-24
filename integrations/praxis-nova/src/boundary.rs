//! Stable statement for direct Nova verification and a future Praxis BQS.
//! External policy and exact Bitcoin transaction must authenticate these values.
//! This module does NOT verify M16/M18, a transaction, or a Nova proof.
use crate::{State,check_final,f_to_le,fu,u64_field,NZ,CAP,MAX_MONEY,F};
use sha2::{Digest,Sha256};
/// All fields must be fixed and authenticated before proof generation.
#[derive(Clone,Debug)]
pub struct Boundary {
    pub z0: State,
    pub expected_payout: F,
    pub expected_change: u64,
    pub expected_next_index: u64,
    pub vk_sha256: [u8;32],
}
impl Boundary{
    pub fn count(&self)->Option<usize>{
        u64_field(self.z0[5]).filter(|&n|n>0&&n<=CAP).map(|n|n as usize)
    }
    pub fn accepts_verified_state(&self,zn:&[F],steps:usize)->bool{
        self.expected_next_index>0&&self.expected_next_index<=CAP&&
        self.expected_change<=MAX_MONEY&&self.count()==Some(steps)&&
        check_final(&self.z0,zn,self.expected_payout,self.expected_change,steps)&&
        zn[8]==fu(self.expected_next_index)
    }
    /// Stable 440-byte journal. No proof bytes, proof hash, random nonce or
    /// independently supplied proof-derived digest.
    pub fn journal(&self)->Result<Vec<u8>,&'static str>{
        let count=self.count().ok_or("count")?;
        if self.expected_next_index==0||self.expected_next_index>CAP||
            self.expected_change>MAX_MONEY{return Err("boundary");}
        let mut j=b"PNS1".to_vec();j.extend_from_slice(&(count as u32).to_le_bytes());
        for x in &self.z0{j.extend_from_slice(&f_to_le(x));}
        j.extend_from_slice(&f_to_le(&self.expected_payout));
        j.extend_from_slice(&self.expected_change.to_le_bytes());
        j.extend_from_slice(&self.expected_next_index.to_le_bytes());
        j.extend_from_slice(&self.vk_sha256);
        assert_eq!(j.len(),8+NZ*32+32+8+8+32);
        Ok(j)
    }
    pub fn journal_digest(&self)->Result<[u8;32],&'static str>{Ok(Sha256::digest(self.journal()?).into())}
}
#[cfg(test)]
mod tests{
    use super::*;use crate::{fixture,native};
    #[test]fn stable_release_statement(){
        let (z0,claims,expected,change)=fixture();
        let b=Boundary{z0,expected_payout:expected,expected_change:change,
            expected_next_index:claims.last().unwrap().index+1,vk_sha256:[7;32]};
        let mut z=z0;let j=b.journal_digest().unwrap();
        for c in &claims{z=native(&z,c).unwrap();}
        assert!(b.accepts_verified_state(&z,claims.len()));
        assert_eq!(j,b.journal_digest().unwrap());
        let mut bad=b.clone();bad.expected_next_index-=1;
        assert!(!bad.accepts_verified_state(&z,claims.len()));
        assert_ne!(j,bad.journal_digest().unwrap());
        let mut bad=b.clone();bad.vk_sha256[0]^=1;
        assert_ne!(j,bad.journal_digest().unwrap());
    }
}
