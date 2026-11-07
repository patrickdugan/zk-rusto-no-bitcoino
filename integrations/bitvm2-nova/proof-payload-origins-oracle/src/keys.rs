//! Test-only compact/full-u32 material shared by the three source components.
//! All 19,288 global seeds and public keys are admitted before the first sign.
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
    pub keys: [Vec<PublicKey>; 3],
    pub signatures: [Vec<Signature>; 3],
    pub values: [Vec<u32>; 3],
    pub global_indices: [Vec<usize>; 3],
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
    h.input(b"BITVM2-NOVA/TEST-ONLY-PROOF-PAYLOAD-ORIGINS-WOTS/v1\0");
    h.input(&id32(source)?);
    for text in [case_name, global_id] {
        h.input(&(text.len() as u16).to_le_bytes());
        h.input(text.as_bytes());
    }
    Ok(sha256::Hash::from_engine(h).to_byte_array().to_vec())
}

pub fn generate(inputs: &[Input<'_>; 3], source: &str, case_name: &str) -> Result<Material> {
    let expected_words = [12664, 9295, 6545];
    let expected_leaves = [12664, 2873, 2023];
    let expected_roles = ["pallas_scalar", "pallas_scalar", "vesta_scalar"];
    let mut globals = Vec::<GlobalWord>::new();
    let mut lookup = HashMap::<String, usize>::new();
    let mut maps: [Vec<usize>; 3] = std::array::from_fn(|_| Vec::new());
    let mut local_words = 0usize;
    // Source admission precedes this function. Recheck all physical aliases and
    // local injection before ANY public-key generation, not merely before sign.
    for (component, input) in inputs.iter().enumerate() {
        input.spec.identity()?;
        require(
            input.spec.words.len() == expected_words[component]
                && input.spec.leaves.len() == expected_leaves[component]
                && input.spec.field_role == expected_roles[component]
                && input.values.len() == expected_words[component]
                && input.global_ids.len() == expected_words[component],
            "closed global-pool component census",
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
                    old.bound == word.bound && old.value == *value && word.bound == 256,
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
        globals.len() == 19288 && local_words == 28504 && local_words - globals.len() == 9216,
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
        keys.len() == 19288 && key_set.len() == 19288,
        "all global keys admitted before first signature",
    )?;
    let mut signatures = Vec::with_capacity(globals.len());
    let mut signature_set = HashSet::new();
    for (secret, word) in secrets.into_iter().zip(&globals) {
        // Preserve all unsigned32 bits, including the closed256/u32MAX probes.
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
    let local_keys = std::array::from_fn(|component| {
        maps[component]
            .iter()
            .map(|index| keys[*index].clone())
            .collect()
    });
    let local_signatures = std::array::from_fn(|component| {
        maps[component]
            .iter()
            .map(|index| signatures[*index].clone())
            .collect()
    });
    Ok(Material {
        keys: local_keys,
        signatures: local_signatures,
        values: std::array::from_fn(|component| inputs[component].values.to_vec()),
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
        assert!(identifier("d/00"));
        assert!(!identifier(""));
        assert!(!identifier("proof/container-byte/556\n"));
        assert!(!identifier(&"x".repeat(193)));
        assert_eq!(12664 + 9295 + 6545 - 9216, 19288);
    }
}
