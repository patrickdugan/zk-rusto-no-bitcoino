//! Isolated full32 WOTS adapter comparison. No value-dependent modes.
//! The unchanged arithmetic catalogue is admitted independently before keys.
use crate::hints::{self, FullSignature};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    script::Builder,
    ScriptBuf,
};
use bitvm::signatures::{utils::digits_to_number, CompactWots, Wots, Wots4};
pub use bitvm2_nova_script_oracle::registry::{GraphSpec, Leaf, Word};
use bitvm2_nova_script_oracle::wots::{PublicKey, Result};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    ops::Range,
    sync::OnceLock,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Adapter {
    Compact = 0,
    Bound256Hinted = 1,
}
impl Adapter {
    pub fn index(self) -> usize {
        self as usize
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Bound256Hinted => "bound256-hinted",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Mode {
    Compact = 0,
    Hinted = 1,
}
impl Mode {
    pub fn width(self) -> usize {
        match self {
            Self::Compact => 10,
            Self::Hinted => 20,
        }
    }
}
pub fn mode(adapter: Adapter, bound: u32) -> Mode {
    if adapter == Adapter::Bound256Hinted && bound == 256 {
        Mode::Hinted
    } else {
        Mode::Compact
    }
}
fn packet_layout(
    spec: &GraphSpec,
    adapter: Adapter,
    ordinal: usize,
) -> Result<Vec<(usize, Range<usize>)>> {
    let leaf = spec.leaves.get(ordinal).ok_or("leaf ordinal")?;
    let mut seen = HashSet::new();
    let mut start = 0usize;
    let mut out = Vec::new();
    for &index in &leaf.wires {
        if !seen.insert(index) {
            continue;
        }
        let word = spec.words.get(index).ok_or("packet word index")?;
        let end = start
            .checked_add(mode(adapter, word.bound).width())
            .ok_or("packet width overflow")?;
        if end > 1000 {
            return Err("unique-word packet total exceeds1000 witness items".into());
        }
        out.push((index, start..end));
        start = end;
    }
    Ok(out)
}
fn number(code: &mut Vec<u8>, n: i64) {
    code.extend_from_slice(Builder::new().push_int(n).into_script().as_bytes());
}

/// Preserve the frozen eight-nibble decoder and its unsigned/high-bit flag.
/// Authentication (including checksum) precedes all semantic validity flags.
fn recovery(key: &PublicKey, bound: u32, selected: Mode) -> Vec<u8> {
    let mut code = match selected {
        Mode::Compact => Wots4::compact_checksig_verify(key).compile().into_bytes(),
        Mode::Hinted => {
            let mut c = hints::preflight();
            c.extend_from_slice(Wots4::checksig_verify(key).compile().as_bytes());
            c
        }
    };
    number(&mut code, 7);
    code.push(0x79);
    number(&mut code, 2);
    code.extend_from_slice(&[0x9f, 0x63]);
    code.extend_from_slice(digits_to_number::<8, 4>().compile().as_bytes());
    code.push(0x76);
    number(&mut code, i64::from(bound));
    code.push(0x9f);
    code.push(0x67);
    code.extend_from_slice(&[0x6d; 4]);
    number(&mut code, 0);
    number(&mut code, 0);
    code.extend_from_slice(&[0x68, 0x6b, 0x6b]);
    code
}

pub struct Registry {
    spec: GraphSpec,
    keys: Vec<PublicKey>,
    adapter: Adapter,
    id: [u8; 32],
    bodies: BTreeMap<String, Vec<u8>>,
    recovery: Vec<OnceLock<Vec<u8>>>,
}
impl Registry {
    pub fn key_identity(
        spec: &GraphSpec,
        keys: &[PublicKey],
        adapter: Adapter,
    ) -> Result<[u8; 32]> {
        let base = spec.key_identity(keys)?;
        let mut h = sha256::Hash::engine();
        h.input(b"BITVM2-NOVA/AUTH-COST-REGISTRY/v1\0");
        h.input(&base);
        h.input(&[adapter as u8]);
        for word in &spec.words {
            let m = mode(adapter, word.bound);
            h.input(&[m as u8, m.width() as u8]);
        }
        Ok(sha256::Hash::from_engine(h).to_byte_array())
    }
    pub fn new(
        spec: GraphSpec,
        keys: Vec<PublicKey>,
        adapter: Adapter,
        expected_spec: [u8; 32],
        expected_registry: [u8; 32],
    ) -> Result<Self> {
        if spec.identity()? != expected_spec
            || Self::key_identity(&spec, &keys, adapter)? != expected_registry
        {
            return Err("verifier-owned source/adapter/key identity mismatch".into());
        }
        for ordinal in 0..spec.leaves.len() {
            packet_layout(&spec, adapter, ordinal)?;
        }
        let mut bodies = BTreeMap::new();
        for (id, raw) in &spec.bodies {
            let bytes = hex::decode(raw)?;
            crate::engine::validate(&ScriptBuf::from_bytes(bytes.clone()))?;
            bodies.insert(id.clone(), bytes);
        }
        let recovery = keys.iter().map(|_| OnceLock::new()).collect();
        Ok(Self {
            spec,
            keys,
            adapter,
            id: expected_registry,
            bodies,
            recovery,
        })
    }
    pub fn spec(&self) -> &GraphSpec {
        &self.spec
    }
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }
    pub fn adapter(&self) -> Adapter {
        self.adapter
    }
    pub fn identity(&self) -> [u8; 32] {
        self.id
    }
    pub fn word_mode(&self, index: usize) -> Result<Mode> {
        Ok(mode(
            self.adapter,
            self.spec.words.get(index).ok_or("word index")?.bound,
        ))
    }
    pub fn unique_slots(&self, ordinal: usize) -> Result<Vec<usize>> {
        let leaf = self.spec.leaves.get(ordinal).ok_or("leaf ordinal")?;
        let mut seen = HashSet::new();
        Ok(leaf
            .wires
            .iter()
            .copied()
            .filter(|i| seen.insert(*i))
            .collect())
    }
    pub fn packet_ranges(&self, ordinal: usize) -> Result<Vec<(usize, Range<usize>)>> {
        packet_layout(&self.spec, self.adapter, ordinal)
    }
    pub fn packet(&self, index: usize, signature: &FullSignature) -> Result<Vec<Vec<u8>>> {
        match self.word_mode(index)? {
            Mode::Compact => hints::compact_packet(signature),
            Mode::Hinted => hints::hinted_packet(signature),
        }
    }
    pub fn witness(&self, ordinal: usize, signatures: &[FullSignature]) -> Result<Vec<Vec<u8>>> {
        if signatures.len() != self.spec.words.len() {
            return Err("missing/surplus full signatures".into());
        }
        self.packet_ranges(ordinal)?;
        let mut out = Vec::new();
        for word in self.unique_slots(ordinal)? {
            out.extend(self.packet(word, &signatures[word])?);
        }
        Ok(out)
    }
    pub fn script(&self, ordinal: usize, disprove: bool) -> Result<ScriptBuf> {
        let leaf = self.spec.leaves.get(ordinal).ok_or("leaf ordinal")?;
        let slots = self.unique_slots(ordinal)?;
        let width = self
            .packet_ranges(ordinal)?
            .last()
            .map(|(_, range)| range.end)
            .unwrap_or(0);
        let mut code = vec![0x74];
        number(&mut code, width as i64);
        code.push(0x88); // exact depth BEFORE PICK
        let mut tag = sha256::Hash::engine();
        tag.input(b"BITVM2-NOVA/AUTH-COST-LEAF/v1\0");
        tag.input(&self.id);
        tag.input(&(ordinal as u32).to_le_bytes());
        tag.input(&[u8::from(disprove)]);
        code.push(32);
        code.extend_from_slice(sha256::Hash::from_engine(tag).as_byte_array());
        code.push(0x75);
        // No early semantic branch. Every packet and every checksum authenticates.
        for index in slots.iter().rev() {
            code.extend_from_slice(self.recovery[*index].get_or_init(|| {
                recovery(
                    &self.keys[*index],
                    self.spec.words[*index].bound,
                    mode(self.adapter, self.spec.words[*index].bound),
                )
            }));
        }
        number(&mut code, 1);
        for _ in &slots {
            code.extend_from_slice(&[0x6c, 0x6c, 0x7b, 0x9a]);
        }
        code.push(0x63);
        code.extend_from_slice(self.bodies.get(&leaf.body_sha256).ok_or("missing body")?);
        code.push(0x67);
        for _ in 0..slots.len() / 2 {
            code.push(0x6d);
        }
        if slots.len() % 2 == 1 {
            code.push(0x75);
        }
        number(&mut code, 0);
        code.push(0x68);
        if disprove {
            code.push(0x91);
        }
        let script = ScriptBuf::from_bytes(code);
        crate::engine::validate(&script)?;
        Ok(script)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modes_depend_only_on_declared_bound() {
        for bound in [1, 2, 255, 256, 257, 1 << 18, 1 << 29] {
            assert_eq!(mode(Adapter::Compact, bound), Mode::Compact);
            assert_eq!(
                mode(Adapter::Bound256Hinted, bound),
                if bound == 256 {
                    Mode::Hinted
                } else {
                    Mode::Compact
                }
            );
        }
    }
    #[test]
    fn packet_widths_are_full32_ten_digit_views() {
        assert_eq!(Mode::Compact.width(), 10);
        assert_eq!(Mode::Hinted.width(), 20);
        assert_eq!(Wots4::TOTAL_DIGIT_LEN, 10);
        assert_eq!(Wots4::MSG_BYTE_LEN, 4);
    }
    #[test]
    fn variable_packet_admission_rejects64_unique_hinted_words_without_crypto() {
        let mut spec = GraphSpec {
            program_sha256: "00".repeat(32),
            context: "00".repeat(32),
            field_role: "pallas_scalar".into(),
            operation_id: "test/packet-admission".into(),
            words: (0..64)
                .map(|i| Word {
                    name: format!("w{i}"),
                    bound: 256,
                })
                .collect(),
            leaves: vec![Leaf {
                kind: "symbolic-only".into(),
                argument: vec![],
                wires: (0..64).collect(),
                body_sha256: "00".repeat(32),
            }],
            bodies: BTreeMap::new(),
        };
        assert!(packet_layout(&spec, Adapter::Bound256Hinted, 0).is_err());
        assert_eq!(
            packet_layout(&spec, Adapter::Compact, 0)
                .unwrap()
                .last()
                .unwrap()
                .1
                .end,
            640
        );
        spec.leaves[0].wires = (0..50).collect();
        assert_eq!(
            packet_layout(&spec, Adapter::Bound256Hinted, 0)
                .unwrap()
                .last()
                .unwrap()
                .1
                .end,
            1000
        );
        spec.leaves[0].wires.push(50);
        assert!(packet_layout(&spec, Adapter::Bound256Hinted, 0).is_err());
        spec.leaves[0].wires = vec![0, 0, 1];
        assert_eq!(
            packet_layout(&spec, Adapter::Bound256Hinted, 0).unwrap(),
            vec![(0, 0..20), (1, 20..40)]
        );
    }
}
