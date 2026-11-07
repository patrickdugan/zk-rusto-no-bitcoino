//! One TEST-ONLY full Wots4 signature per source word, shared by both adapters.
use crate::{hints::FullSignature, registry::GraphSpec};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm::signatures::{Wots, Wots4};
use bitvm2_nova_script_oracle::wots::{id32, PublicKey, Result};
use std::collections::HashSet;
pub struct Material {
    pub keys: Vec<PublicKey>,
    pub signatures: Vec<FullSignature>,
    pub values: Vec<u32>,
}
fn seed(source: &str, name: &str, word: &str) -> Result<Vec<u8>> {
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/TEST-ONLY-AUTH-COST-FULL32-WOTS/v1\0");
    h.input(&id32(source)?);
    for text in [name, word] {
        if text.is_empty() || text.len() > 192 || !text.is_ascii() {
            return Err("test-key identity width".into());
        }
        h.input(&(text.len() as u16).to_le_bytes());
        h.input(text.as_bytes());
    }
    Ok(sha256::Hash::from_engine(h).to_byte_array().to_vec())
}
pub fn generate(spec: &GraphSpec, source: &str, name: &str, values: &[u32]) -> Result<Material> {
    spec.identity()?;
    if !matches!(spec.words.len(), 3 | 1417)
        || spec.words.len() != values.len()
        || hex::encode(id32(source)?) != source
    {
        return Err("closed key profile/dimensions/source digest".into());
    }
    let mut keys = Vec::new();
    let mut signatures = Vec::new();
    let mut key_hashes = HashSet::new();
    let mut sig_hashes = HashSet::new();
    let mut seeds = HashSet::new();
    let mut secrets = Vec::new();
    // Admit the complete seed/public-key set before the FIRST signature.
    for word in &spec.words {
        let secret = seed(source, name, &word.name)?;
        if !seeds.insert(secret.clone()) {
            return Err("test seed collision".into());
        }
        let key = Wots4::generate_public_key(&secret);
        let public: &[[u8; 20]] = key.as_ref();
        let key_bytes: Vec<u8> = public.iter().flatten().copied().collect();
        if public.len() != 10 || !key_hashes.insert(sha256::Hash::hash(&key_bytes)) {
            return Err("test public-key dimensions/collision".into());
        }
        keys.push(key);
        secrets.push(secret);
    }
    for (secret, value) in secrets.into_iter().zip(values) {
        let signature = Wots4::sign(&secret, &value.to_le_bytes());
        let digits: &[[u8; 21]] = signature.as_ref();
        if digits.len() != 10 || Wots4::signature_to_message(&signature) != value.to_le_bytes() {
            return Err("full32 signature/key/message conversion".into());
        }
        let sig_bytes: Vec<u8> = digits.iter().flatten().copied().collect();
        if !sig_hashes.insert(sha256::Hash::hash(&sig_bytes)) {
            return Err("test key/signature collision".into());
        }
        // Both representations are checked views of this ONE full signature.
        let compact = crate::hints::compact_packet(&signature)?;
        let hinted = crate::hints::hinted_packet(&signature)?;
        for i in 0..10 {
            if compact[i] != hinted[2 * i] {
                return Err("adapter views disagree on signature hash".into());
            }
        }
        signatures.push(signature);
    }
    Ok(Material {
        keys,
        signatures,
        values: values.to_vec(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_is_source_case_and_word_bound_without_value() {
        let a = seed(&"00".repeat(32), "p/m0", "a").unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, seed(&"01".repeat(32), "p/m0", "a").unwrap());
        assert_ne!(a, seed(&"00".repeat(32), "p/m1", "a").unwrap());
        assert_ne!(a, seed(&"00".repeat(32), "p/m0", "aux").unwrap());
    }
}
