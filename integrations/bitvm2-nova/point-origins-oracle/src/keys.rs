//! Test-only compact/full-u32 material shared by every source component.
//! All global seeds and public keys are admitted before the first signature.
//! Only physical payload BYTE identities may be reused across components.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    registry::{GraphSpec, Signature},
    wots::{id32, PublicKey, Result},
};
use std::collections::{HashMap, HashSet};

pub struct Input<'a> {
    pub spec: &'a GraphSpec,
    pub values: &'a [u32],
    pub global_ids: &'a [String],
}
pub struct Material {
    pub keys: Vec<Vec<PublicKey>>,
    pub signatures: Vec<Vec<Signature>>,
    pub values: Vec<Vec<u32>>,
    pub global_indices: Vec<Vec<usize>>,
    pub global_words: usize,
    pub local_words: usize,
    pub source_reuses: usize,
}
struct GlobalWord {
    name: String,
    bound: u32,
    value: u32,
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
fn seed(source: &str, case_name: &str, global_id: &str) -> Result<Vec<u8>> {
    require(
        hex::encode(id32(source)?) == source && identifier(case_name) && identifier(global_id),
        "canonical test-key identity",
    )?;
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/TEST-ONLY-PROOF-POINT-ORIGINS-WOTS/v1\0");
    h.input(&id32(source)?);
    for text in [case_name, global_id] {
        h.input(&(text.len() as u16).to_le_bytes());
        h.input(text.as_bytes());
    }
    Ok(sha256::Hash::from_engine(h).to_byte_array().to_vec())
}

/// `expected_reuses` is the independently derived count of decoder encoding
/// BYTEs that share the tape's physical assertion.
pub fn generate(
    inputs: &[Input<'_>],
    source: &str,
    case_name: &str,
    expected_reuses: usize,
) -> Result<Material> {
    let mut globals = Vec::<GlobalWord>::new();
    let mut lookup = HashMap::<String, usize>::new();
    let mut maps: Vec<Vec<usize>> = vec![Vec::new(); inputs.len()];
    let mut local_words = 0usize;
    // Source admission precedes this function. Recheck all physical aliases and
    // local injection before ANY public-key generation, not merely before sign.
    for (component, input) in inputs.iter().enumerate() {
        input.spec.identity()?;
        require(
            input.values.len() == input.spec.words.len()
                && input.global_ids.len() == input.spec.words.len(),
            "complete component assignment and identity map",
        )?;
        let mut local_ids = HashSet::new();
        for ((word, value), name) in input
            .spec
            .words
            .iter()
            .zip(input.values)
            .zip(input.global_ids)
        {
            require(
                identifier(name) && local_ids.insert(name.as_str()),
                "local global-ID map must be injective",
            )?;
            let index = if let Some(index) = lookup.get(name) {
                let old = &globals[*index];
                require(
                    old.bound == word.bound
                        && old.value == *value
                        && word.bound == 256
                        && name.starts_with("proof/container-byte/"),
                    "cross-component reuse must preserve the same physical BYTE assertion",
                )?;
                *index
            } else {
                let index = globals.len();
                lookup.insert(name.clone(), index);
                globals.push(GlobalWord {
                    name: name.clone(),
                    bound: word.bound,
                    value: *value,
                });
                index
            };
            maps[component].push(index);
            local_words += 1;
        }
    }
    require(
        local_words - globals.len() == expected_reuses,
        "complete global-pool quotient census",
    )?;
    let mut keys = Vec::with_capacity(globals.len());
    let mut secrets = Vec::with_capacity(globals.len());
    let mut seed_set = HashSet::new();
    let mut key_set = HashSet::new();
    // No signing occurs until this complete source-case public-key pass ends.
    for word in &globals {
        let secret = seed(source, case_name, &word.name)?;
        require(
            seed_set.insert(secret.clone()),
            "test global seed collision",
        )?;
        let key = Wots4::generate_public_key(&secret);
        let cells: &[[u8; 20]] = key.as_ref();
        let raw: Vec<u8> = cells.iter().flatten().copied().collect();
        require(
            cells.len() == 10 && raw.len() == 200 && key_set.insert(sha256::Hash::hash(&raw)),
            "complete global public-key dimensions/collision check",
        )?;
        keys.push(key);
        secrets.push(secret);
    }
    require(
        keys.len() == globals.len() && key_set.len() == globals.len(),
        "all global keys admitted before first signature",
    )?;
    let mut signatures = Vec::with_capacity(globals.len());
    let mut signature_set = HashSet::new();
    for (secret, word) in secrets.into_iter().zip(&globals) {
        // Preserve all unsigned32 bits, including the closed 256/u32::MAX probes.
        let full = Wots4::sign(&secret, &word.value.to_le_bytes());
        require(
            Wots4::signature_to_message(&full) == word.value.to_le_bytes(),
            "signed full-u32 message identity",
        )?;
        let signature = Wots4::signature_to_compact_signature(&full);
        let raw: Vec<u8> = signature.iter().flatten().copied().collect();
        require(
            signature.len() == 10
                && raw.len() == 200
                && signature_set.insert(sha256::Hash::hash(&raw)),
            "test global signature dimensions/collision check",
        )?;
        signatures.push(signature);
    }
    let local_keys = maps
        .iter()
        .map(|map| map.iter().map(|index| keys[*index].clone()).collect())
        .collect();
    let local_signatures = maps
        .iter()
        .map(|map| map.iter().map(|index| signatures[*index].clone()).collect())
        .collect();
    Ok(Material {
        keys: local_keys,
        signatures: local_signatures,
        values: inputs.iter().map(|input| input.values.to_vec()).collect(),
        global_indices: maps,
        global_words: globals.len(),
        local_words,
        source_reuses: local_words - globals.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_names_and_case_names_are_bounded_without_crypto() {
        assert!(identifier("proof/container-byte/556"));
        assert!(identifier("proof/point/pallas/42/x2/ab/31/7"));
        assert!(identifier("d/00"));
        assert!(!identifier(""));
        assert!(!identifier("proof/container-byte/556\n"));
        assert!(!identifier(&"x".repeat(193)));
    }
}
