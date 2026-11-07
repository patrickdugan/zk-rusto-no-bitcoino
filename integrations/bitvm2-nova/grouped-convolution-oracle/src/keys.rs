//! One TEST-ONLY full-u32 compact WOTS signature per paired global word.
//! Complete source-case seed/key admission precedes its first signature.
use crate::{
    registry::GraphSpec,
    wots::{id32, PublicKey, Result},
};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::registry::Signature;
use std::collections::HashSet;

pub struct Material {
    pub keys: Vec<PublicKey>,
    pub signatures: Vec<Signature>,
    pub values: Vec<u32>,
}
fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn seed(source: &str, case_name: &str, word: &str) -> Result<Vec<u8>> {
    require(
        hex::encode(id32(source)?) == source && identifier(case_name) && identifier(word),
        "canonical paired test-key identity",
    )?;
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/TEST-ONLY-GROUPED-CONVOLUTION-WOTS/v1\0");
    h.input(&id32(source)?);
    for text in [case_name, word] {
        h.input(&(text.len() as u16).to_le_bytes());
        h.input(text.as_bytes());
    }
    Ok(sha256::Hash::from_engine(h).to_byte_array().to_vec())
}
pub fn generate(
    spec: &GraphSpec,
    source: &str,
    case_name: &str,
    values: &[u32],
) -> Result<Material> {
    spec.identity()?;
    require(
        matches!(spec.words.len(), 634 | 579 | 7476)
            && values.len() == spec.words.len()
            && matches!(spec.field_role.as_str(), "pallas_base" | "vesta_base"),
        "closed paired key dimensions/roles",
    )?;
    let mut secrets = Vec::new();
    let mut keys = Vec::new();
    let mut seeds = HashSet::new();
    let mut key_hashes = HashSet::new();
    for word in &spec.words {
        let secret = seed(source, case_name, &word.name)?;
        require(seeds.insert(secret.clone()), "paired test seed collision")?;
        let key = Wots4::generate_public_key(&secret);
        let cells: &[[u8; 20]] = key.as_ref();
        let bytes: Vec<u8> = cells.iter().flatten().copied().collect();
        require(
            cells.len() == 10
                && bytes.len() == 200
                && key_hashes.insert(sha256::Hash::hash(&bytes)),
            "paired global public-key dimensions/collision",
        )?;
        secrets.push(secret);
        keys.push(key);
    }
    require(
        keys.len() == spec.words.len() && key_hashes.len() == keys.len(),
        "all paired keys must precede first signature",
    )?;
    let mut signatures = Vec::new();
    let mut signature_hashes = HashSet::new();
    for (secret, value) in secrets.into_iter().zip(values) {
        // Neither a BYTE nor a subtotal narrows the signed32-bit diagnostic.
        let full = Wots4::sign(&secret, &value.to_le_bytes());
        require(
            Wots4::signature_to_message(&full) == value.to_le_bytes(),
            "full-u32 signature/message identity",
        )?;
        let signature = Wots4::signature_to_compact_signature(&full);
        let bytes: Vec<u8> = signature.iter().flatten().copied().collect();
        require(
            signature.len() == 10
                && bytes.len() == 200
                && signature_hashes.insert(sha256::Hash::hash(&bytes)),
            "paired signature dimensions/collision",
        )?;
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
    fn owned_identity_grammar_is_bounded_without_crypto() {
        assert!(identifier("p/00"));
        assert!(identifier("product/ab/0/0"));
        assert!(!identifier(""));
        assert!(!identifier("a\n"));
        assert!(!identifier(&"a".repeat(193)));
    }
}
