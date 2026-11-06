//! Hosted TEST-ONLY scenario-wide WOTS material for the three BYTE-rho components.
//!
//! The independently checked source maps supply declarations before any keys are
//! generated. A shared global ID has exactly one bound, value, key and signature.
//! Component admission subsequently borrows that immutable material; lookup never
//! signs. Deterministic test keys are not production assertion/key-lifecycle work.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    registry::Signature,
    wots::{id32, PublicKey, Result},
};
use std::collections::{BTreeMap, HashSet};

pub const EXPECTED_UNIQUE_WORDS: usize = 59_109;
pub const EXPECTED_LOCAL_DECLARATIONS: usize = 59_477;
const BASE: u32 = 1 << 29;
const WOTS_PAYLOAD_BYTES: usize = 200;
const KEY_DOMAIN: &[u8] = b"BITVM2-NOVA/TEST-ONLY-BYTE-RHO-GLOBAL-WOTS/v1\0";

#[derive(Clone, Copy)]
struct Declaration {
    bound: u32,
    value: u32,
}

/// Bounded declaration ledger, with no WOTS material or signing operation.
///
/// A failed addition poisons the ledger so ignoring an error cannot allow a
/// conflicting component declaration to be signed later. Counts remain unchanged
/// on failure. Values deliberately retain the whole u32 domain: signed values
/// outside a declared bound belong to the Script decoder's rejection path.
pub struct Declarations {
    words: BTreeMap<String, Declaration>,
    local_declarations: usize,
    failed: bool,
}

struct Entry {
    declaration: Declaration,
    key: PublicKey,
    signature: Signature,
}

/// One sealed, immutable key/signature entry per scenario global word ID.
///
/// No private seeds are retained, and no public constructor admits external
/// key/signature receipts. A component registry can clone the references returned
/// by lookup without retaining another full component registry.
pub struct GlobalPool {
    entries: BTreeMap<String, Entry>,
    local_declarations: usize,
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
            local_declarations: 0,
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
        self.local_declarations
    }

    pub fn cached_signature_reuses(&self) -> usize {
        self.local_declarations - self.words.len()
    }

    pub fn add(&mut self, global_id: &str, bound: u32, value: u32) -> Result<()> {
        let checked = self.check_add(global_id, bound, value);
        if checked.is_err() {
            self.failed = true;
        }
        checked?;
        self.words
            .entry(global_id.to_owned())
            .or_insert(Declaration { bound, value });
        self.local_declarations += 1;
        Ok(())
    }

    fn check_add(&self, global_id: &str, bound: u32, value: u32) -> Result<()> {
        if self.failed {
            return Err("rho global declarations already rejected".into());
        }
        if !identifier(global_id) || !(1..=BASE).contains(&bound) {
            return Err("invalid rho global word identity or bound".into());
        }
        if self.local_declarations >= EXPECTED_LOCAL_DECLARATIONS {
            return Err("rho local declaration limit exceeded".into());
        }
        if let Some(previous) = self.words.get(global_id) {
            if previous.bound != bound || previous.value != value {
                return Err("rho shared global word bound/value conflict".into());
            }
        } else if self.words.len() >= EXPECTED_UNIQUE_WORDS {
            return Err("rho unique global word limit exceeded".into());
        }
        Ok(())
    }

    pub fn seal(self, source_sha256: &str, scenario_name: &str) -> Result<GlobalPool> {
        self.seal_with(source_sha256, scenario_name, |secret, value| {
            let secret = secret.to_vec();
            let key = Wots4::generate_public_key(&secret);
            let signature = Wots4::compact_sign(&secret, &value.to_le_bytes());
            Ok((key, signature))
        })
    }

    // Private generator seam only for tiny count-gate tests; callers cannot
    // supply key material or bypass the public signing lifecycle.
    fn seal_with<F>(
        self,
        source_sha256: &str,
        scenario_name: &str,
        mut generate: F,
    ) -> Result<GlobalPool>
    where
        F: FnMut(&[u8], u32) -> Result<(PublicKey, Signature)>,
    {
        if self.failed {
            return Err("cannot seal rejected rho global declarations".into());
        }
        check_counts(self.words.len(), self.local_declarations)?;
        let source = source_digest(source_sha256)?;
        if !identifier(scenario_name) {
            return Err("invalid rho test scenario identity".into());
        }

        let mut entries = BTreeMap::new();
        let mut seeds = HashSet::new();
        let mut keys = HashSet::new();
        let mut signatures = HashSet::new();
        for (global_id, declaration) in self.words {
            // The seed excludes value and bound. Altering a signed message must
            // never silently select another one-time key for the same ID.
            let secret = seed(&source, scenario_name, &global_id);
            if !seeds.insert(secret) {
                return Err("rho distinct global word seed collision".into());
            }
            let (key, signature) = generate(&secret, declaration.value)?;
            let key_payload: Vec<_> = key.iter().flat_map(|p| p.iter().copied()).collect();
            let signature_payload: Vec<_> =
                signature.iter().flat_map(|p| p.iter().copied()).collect();
            check_payload(&key_payload, &mut keys)?;
            check_payload(&signature_payload, &mut signatures)?;
            entries.insert(
                global_id,
                Entry {
                    declaration,
                    key,
                    signature,
                },
            );
        }
        Ok(GlobalPool {
            entries,
            local_declarations: self.local_declarations,
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
        self.local_declarations
    }

    pub fn cached_signature_reuses(&self) -> usize {
        self.local_declarations - self.entries.len()
    }

    /// Borrow the already generated signature; this operation cannot re-sign.
    pub fn lookup(
        &self,
        global_id: &str,
        bound: u32,
        value: u32,
    ) -> Result<(&PublicKey, &Signature)> {
        if !identifier(global_id) || !(1..=BASE).contains(&bound) {
            return Err("invalid rho global lookup identity or bound".into());
        }
        let entry = self
            .entries
            .get(global_id)
            .ok_or("rho global word was not declared before sealing")?;
        if entry.declaration.bound != bound || entry.declaration.value != value {
            return Err("rho immutable global lookup bound/value conflict".into());
        }
        Ok((&entry.key, &entry.signature))
    }
}

fn check_counts(unique: usize, local: usize) -> Result<()> {
    if unique != EXPECTED_UNIQUE_WORDS || local != EXPECTED_LOCAL_DECLARATIONS {
        return Err("rho global/local declaration census must be 59109/59477 before keygen".into());
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn source_digest(value: &str) -> Result<[u8; 32]> {
    let digest = id32(value)?;
    if hex::encode(digest) != value {
        return Err("rho source SHA must be canonical lowercase32 hex".into());
    }
    Ok(digest)
}

fn seed(source: &[u8; 32], scenario: &str, global_id: &str) -> [u8; 32] {
    let mut h = sha256::Hash::engine();
    h.input(KEY_DOMAIN);
    h.input(source);
    for text in [scenario, global_id] {
        h.input(&(text.len() as u16).to_le_bytes());
        h.input(text.as_bytes());
    }
    sha256::Hash::from_engine(h).to_byte_array()
}

fn check_payload(payload: &[u8], hashes: &mut HashSet<[u8; 32]>) -> Result<()> {
    if payload.len() != WOTS_PAYLOAD_BYTES
        || !hashes.insert(sha256::Hash::hash(payload).to_byte_array())
    {
        return Err(
            "rho distinct global word WOTS key/signature collision or payload mismatch".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_preserve_u32_and_reject_alias_conflicts_before_signing() {
        let mut declared = Declarations::new();
        assert!(declared.is_empty());
        declared
            .add("branch/hi/byte-state/0/l0/byte0", 256, u32::MAX)
            .unwrap();
        declared
            .add("branch/hi/byte-state/0/l0/byte0", 256, u32::MAX)
            .unwrap();
        assert_eq!(
            (
                declared.len(),
                declared.local_declarations(),
                declared.cached_signature_reuses()
            ),
            (1, 2, 1)
        );
        assert!(declared
            .add("branch/hi/byte-state/0/l0/byte0", 256, 0)
            .is_err());
        assert_eq!((declared.len(), declared.local_declarations()), (1, 2));
        assert!(declared.add("different/id", 256, 0).is_err());
        let mut calls = 0;
        assert!(declared
            .seal_with(&"00".repeat(32), "scenario", |_, _| {
                calls += 1;
                Err("unexpected test signing".into())
            })
            .is_err());
        assert_eq!(calls, 0);

        let mut bound_conflict = Declarations::new();
        bound_conflict.add("same/id", 256, 1).unwrap();
        assert!(bound_conflict.add("same/id", BASE, 1).is_err());
        assert_eq!(
            (bound_conflict.len(), bound_conflict.local_declarations()),
            (1, 1)
        );
    }

    #[test]
    fn declaration_syntax_and_caps_fail_without_mutation() {
        for name in [
            "",
            "/id",
            "id/",
            "id//word",
            "id/./word",
            "id/../word",
            "id word",
            "id\\word",
            "id/\u{e9}",
        ] {
            let mut declared = Declarations::new();
            assert!(declared.add(name, 256, 0).is_err());
            assert_eq!((declared.len(), declared.local_declarations()), (0, 0));
        }
        let mut long = Declarations::new();
        assert!(long.add(&"x".repeat(193), 256, 0).is_err());
        for bound in [0, BASE + 1, u32::MAX] {
            let mut declared = Declarations::new();
            assert!(declared.add("word", bound, 0).is_err());
        }
        let mut admitted = Declarations::new();
        for (index, bound) in [1, 2, 4, 64, 256, 16_384, BASE].into_iter().enumerate() {
            admitted
                .add(&format!("word/{index}"), bound, u32::MAX)
                .unwrap();
        }
        assert_eq!(admitted.len(), 7);
        admitted.local_declarations = EXPECTED_LOCAL_DECLARATIONS;
        assert!(admitted.add("extra", 256, 0).is_err());
        assert_eq!(admitted.len(), 7);
    }

    #[test]
    fn exact_census_is_checked_before_any_generator_call() {
        check_counts(EXPECTED_UNIQUE_WORDS, EXPECTED_LOCAL_DECLARATIONS).unwrap();
        for (unique, local) in [
            (0, 0),
            (EXPECTED_UNIQUE_WORDS - 1, EXPECTED_LOCAL_DECLARATIONS),
            (EXPECTED_UNIQUE_WORDS + 1, EXPECTED_LOCAL_DECLARATIONS),
            (EXPECTED_UNIQUE_WORDS, EXPECTED_LOCAL_DECLARATIONS - 1),
            (EXPECTED_UNIQUE_WORDS, EXPECTED_LOCAL_DECLARATIONS + 1),
        ] {
            assert!(check_counts(unique, local).is_err());
        }
        for local in [0, 1, EXPECTED_LOCAL_DECLARATIONS] {
            let mut declared = Declarations::new();
            declared.local_declarations = local;
            let mut calls = 0;
            assert!(declared
                .seal_with(&"00".repeat(32), "scenario", |_, _| {
                    calls += 1;
                    Err("unexpected test signing".into())
                })
                .is_err());
            assert_eq!(calls, 0);
        }
    }

    #[test]
    fn source_scenario_and_word_seed_domains_are_distinct_without_wots() {
        let source = source_digest(&"00".repeat(32)).unwrap();
        let changed_source = source_digest(&"01".repeat(32)).unwrap();
        let original = seed(&source, "scenario/one", "branch/hi/word");
        assert_eq!(original, seed(&source, "scenario/one", "branch/hi/word"));
        for different in [
            seed(&changed_source, "scenario/one", "branch/hi/word"),
            seed(&source, "scenario/two", "branch/hi/word"),
            seed(&source, "scenario/one", "branch/lo/word"),
            seed(&source, "scenario/one", "branch/hi/word0"),
        ] {
            assert_ne!(original, different);
        }
        assert_ne!(seed(&source, "a", "bc"), seed(&source, "ab", "c"));
        assert!(source_digest(&"AA".repeat(32)).is_err());
        assert!(source_digest(&"0".repeat(63)).is_err());
        assert!(source_digest(&"gg".repeat(32)).is_err());
        // Bound/value are intentionally not seed inputs. Their consistency is
        // checked by the ledger and lookup, not by changing the one-time key.
    }

    #[test]
    fn duplicate_or_malformed_material_is_rejected_without_keygen() {
        let mut hashes = HashSet::new();
        check_payload(&[0; WOTS_PAYLOAD_BYTES], &mut hashes).unwrap();
        assert!(check_payload(&[0; WOTS_PAYLOAD_BYTES], &mut hashes).is_err());
        check_payload(&[1; WOTS_PAYLOAD_BYTES], &mut hashes).unwrap();
        assert!(check_payload(&[2; WOTS_PAYLOAD_BYTES - 1], &mut hashes).is_err());
        assert_eq!(hashes.len(), 2);
        let pool = GlobalPool {
            entries: BTreeMap::new(),
            local_declarations: 0,
        };
        assert!(pool.is_empty());
        assert_eq!(
            (
                pool.len(),
                pool.local_declarations(),
                pool.cached_signature_reuses()
            ),
            (0, 0, 0)
        );
        assert!(pool.lookup("undeclared/id", 256, 0).is_err());
        assert!(pool.lookup("undeclared/id", 0, 0).is_err());
        assert!(pool.lookup("../alias", 256, 0).is_err());
    }

    #[test]
    fn immutable_lookup_reuses_the_same_material_and_checks_the_whole_u32() {
        // Deliberately synthetic material, only to test private storage/borrows.
        // This test neither generates a key nor asserts a valid WOTS signature.
        let key: PublicKey = vec![[0u8; 20]; Wots4::TOTAL_DIGIT_LEN as usize]
            .try_into()
            .unwrap();
        let signature: Signature = vec![[1u8; 20]; Wots4::TOTAL_DIGIT_LEN as usize]
            .try_into()
            .unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(
            "shared/id".to_owned(),
            Entry {
                declaration: Declaration {
                    bound: 256,
                    value: u32::MAX,
                },
                key,
                signature,
            },
        );
        let pool = GlobalPool {
            entries,
            local_declarations: 3,
        };
        let first = pool.lookup("shared/id", 256, u32::MAX).unwrap();
        let second = pool.lookup("shared/id", 256, u32::MAX).unwrap();
        assert!(std::ptr::eq(first.0, second.0));
        assert!(std::ptr::eq(first.1, second.1));
        assert_eq!(pool.cached_signature_reuses(), 2);
        assert!(pool.lookup("shared/id", BASE, u32::MAX).is_err());
        assert!(pool.lookup("shared/id", 256, 255).is_err());
        assert!(pool.lookup("different/id", 256, u32::MAX).is_err());
        assert!(std::ptr::eq(
            first.1,
            pool.lookup("shared/id", 256, u32::MAX).unwrap().1
        ));
    }
}
