//! Immutable TEST-ONLY source-wide compact/full-u32 WOTS assertions.
//! Complete declarations AND all public keys precede the first signature.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    registry::Signature,
    wots::{id32, PublicKey, Result},
};
use std::collections::{BTreeMap, HashSet};
const WORDS: usize = 155107;
const LOCAL: usize = 156163;
const BASE: u32 = 1 << 29;
#[derive(Clone, Copy)]
struct Declaration {
    bound: u32,
    value: u32,
}
struct Entry {
    declaration: Declaration,
    key: PublicKey,
    signature: Signature,
}
pub struct Declarations {
    words: BTreeMap<String, Declaration>,
    local: usize,
    failed: bool,
}
pub struct GlobalPool {
    entries: BTreeMap<String, Entry>,
    local: usize,
}
fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 192
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn seed(source: &[u8; 32], name: &str, id: &str) -> [u8; 32] {
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/TEST-ONLY-GROUPED-C-BIT-POINT-GLOBAL-WOTS/v1\0");
    h.input(source);
    for s in [name, id] {
        h.input(&(s.len() as u16).to_le_bytes());
        h.input(s.as_bytes());
    }
    sha256::Hash::from_engine(h).to_byte_array()
}
impl Default for Declarations {
    fn default() -> Self {
        Self::new()
    }
}
impl Declarations {
    pub fn new() -> Self {
        Self {
            words: BTreeMap::new(),
            local: 0,
            failed: false,
        }
    }
    pub fn len(&self) -> usize {
        self.words.len()
    }
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
    pub fn local_declarations(&self) -> usize {
        self.local
    }
    pub fn cached_signature_reuses(&self) -> usize {
        self.local - self.words.len()
    }
    fn check_add(&self, id: &str, bound: u32, value: u32) -> Result<()> {
        require(!self.failed, "global declarations are poisoned")?;
        require(
            identifier(id) && (1..=BASE).contains(&bound) && self.local < LOCAL,
            "bounded global declaration identity/count",
        )?;
        if let Some(old) = self.words.get(id) {
            require(
                old.bound == bound && old.value == value,
                "immutable shared declaration differs",
            )?;
        } else {
            require(self.words.len() < WORDS, "global declaration word cap")?;
        }
        Ok(())
    }
    pub fn add(&mut self, id: &str, bound: u32, value: u32) -> Result<()> {
        if let Err(error) = self.check_add(id, bound, value) {
            self.failed = true;
            return Err(error);
        }
        self.words
            .entry(id.into())
            .or_insert(Declaration { bound, value });
        self.local += 1;
        Ok(())
    }
    pub fn seal(self, source: &str, name: &str) -> Result<GlobalPool> {
        require(
            !self.failed && self.words.len() == WORDS && self.local == LOCAL && identifier(name),
            "complete unpoisoned global declarations required before keys",
        )?;
        let digest = id32(source)?;
        require(
            hex::encode(digest) == source,
            "canonical source identity before keys",
        )?;
        let mut pending = Vec::with_capacity(WORDS);
        let mut seeds = HashSet::new();
        let mut keys = HashSet::new();
        // No signing call exists in this complete public-key admission pass.
        for (id, declaration) in self.words {
            let secret = seed(&digest, name, &id);
            require(seeds.insert(secret), "distinct source seed collision")?;
            let key = Wots4::generate_public_key(&secret.to_vec());
            let raw: Vec<u8> = key.iter().flatten().copied().collect();
            require(
                raw.len() == 200 && keys.insert(sha256::Hash::hash(&raw)),
                "complete public-key dimensions/collision",
            )?;
            pending.push((id, declaration, secret, key));
        }
        require(
            pending.len() == WORDS && keys.len() == WORDS && seeds.len() == WORDS,
            "all155107 keys must be admitted before first signature",
        )?;
        drop(keys);
        drop(seeds);
        let mut entries = BTreeMap::new();
        let mut signatures = HashSet::new();
        for (id, declaration, secret, key) in pending {
            let full = Wots4::sign(&secret.to_vec(), &declaration.value.to_le_bytes());
            require(
                Wots4::signature_to_message(&full) == declaration.value.to_le_bytes(),
                "exact full-u32 signed assertion",
            )?;
            let signature = Wots4::signature_to_compact_signature(&full);
            let raw: Vec<u8> = signature.iter().flatten().copied().collect();
            require(
                raw.len() == 200 && signatures.insert(sha256::Hash::hash(&raw)),
                "global compact signature dimensions/collision",
            )?;
            require(
                entries
                    .insert(
                        id,
                        Entry {
                            declaration,
                            key,
                            signature,
                        },
                    )
                    .is_none(),
                "duplicate sealed source word",
            )?;
        }
        Ok(GlobalPool {
            entries,
            local: self.local,
        })
    }
}
impl GlobalPool {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn local_declarations(&self) -> usize {
        self.local
    }
    pub fn cached_signature_reuses(&self) -> usize {
        self.local - self.entries.len()
    }
    pub fn lookup(&self, id: &str, bound: u32, value: u32) -> Result<(&PublicKey, &Signature)> {
        require(
            identifier(id) && (1..=BASE).contains(&bound),
            "bounded immutable lookup",
        )?;
        let e = self
            .entries
            .get(id)
            .ok_or("source word not declared before keys")?;
        require(
            e.declaration.bound == bound && e.declaration.value == value,
            "immutable lookup value/bound differs",
        )?;
        Ok((&e.key, &e.signature))
    }
    pub fn public_key_hashes(&self) -> HashSet<[u8; 32]> {
        self.entries
            .values()
            .map(|e| {
                let mut h = sha256::Hash::engine();
                for v in &e.key {
                    h.input(v);
                }
                sha256::Hash::from_engine(h).to_byte_array()
            })
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_add_poisoning_is_sticky_and_counts_are_unchanged() {
        let mut d = Declarations::new();
        d.add("a", 256, u32::MAX).unwrap();
        assert!(d.add("a", 256, 0).is_err());
        assert_eq!(d.len(), 1);
        assert_eq!(d.local_declarations(), 1);
        assert!(d.add("b", 2, 0).is_err());
        assert!(d.seal(&"00".repeat(32), "p/h").is_err());
    }
    #[test]
    fn incomplete_source_is_rejected_without_key_generation() {
        let d = Declarations::new();
        assert!(d.seal(&"00".repeat(32), "p/h").is_err());
        assert_eq!(LOCAL - WORDS, 1056);
    }
}
