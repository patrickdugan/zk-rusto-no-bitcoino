//! Immutable program-wide WOTS key registry and generic arithmetic leaves.
//! Expected catalogue and registry IDs must be verifier-owned. No transactions
//! or production signing/key-lifecycle service are implemented here.
use crate::wots::{id32, PublicKey, Result};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    script::Builder,
    ScriptBuf,
};
use bitvm::signatures::{utils::digits_to_number, CompactWots, Wots, Wots4};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    sync::OnceLock,
};

const BASE: u32 = 1 << 29;
pub type Signature = <Wots4 as CompactWots>::CompactSignature;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Word {
    pub name: String,
    pub bound: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Leaf {
    pub kind: String,
    pub argument: Vec<i64>,
    pub wires: Vec<usize>,
    pub body_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSpec {
    pub program_sha256: String,
    pub context: String,
    pub field_role: String,
    pub operation_id: String,
    pub words: Vec<Word>,
    pub leaves: Vec<Leaf>,
    pub bodies: BTreeMap<String, String>,
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 192
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn text(h: &mut sha256::HashEngine, value: &str) {
    h.input(&(value.len() as u16).to_le_bytes());
    h.input(value.as_bytes());
}
fn number(code: &mut Vec<u8>, n: i64) {
    code.extend_from_slice(Builder::new().push_int(n).into_script().as_bytes());
}

impl GraphSpec {
    fn shape(&self, leaf: &Leaf) -> bool {
        let bounds: Vec<u32> = leaf.wires.iter().map(|i| self.words[*i].bound).collect();
        let empty = leaf.argument.is_empty();
        let gates = leaf.argument.len() <= 5
            && leaf.argument.iter().all(|x| (0..5).contains(x))
            && leaf.argument.iter().collect::<HashSet<_>>().len() == leaf.argument.len();
        match leaf.kind.as_str() {
            "conv_split" => {
                if leaf.argument.len() != 1 || !(1..=7).contains(&leaf.argument[0]) {
                    false
                } else {
                    let bits = leaf.argument[0] as u32;
                    bounds == [256, 1u32 << bits, 1u32 << (8 - bits)]
                }
            }
            "conv_reconstruct" => {
                !leaf.argument.is_empty()
                    && leaf.argument.len() <= 5
                    && leaf.argument.iter().all(|width| (1..=8).contains(width))
                    && leaf.argument.iter().sum::<i64>() <= 29
                    && bounds.len() == leaf.argument.len() + 1
                    && bounds[0] == BASE
                    && bounds[1..]
                        .iter()
                        .zip(&leaf.argument)
                        .all(|(bound, width)| *bound == 1u32 << (*width as u32))
            }
            "conv_ab" => {
                if leaf.argument.len() != 1 || !(1..=4).contains(&leaf.argument[0]) {
                    false
                } else {
                    let n = leaf.argument[0] as usize;
                    bounds.len() == 2 * n + 1
                        && bounds[..2 * n].iter().all(|bound| *bound == 256)
                        && bounds[2 * n] == 1 << 18
                }
            }
            "conv_pq" => {
                !leaf.argument.is_empty()
                    && leaf.argument.len() <= 8
                    && leaf
                        .argument
                        .iter()
                        .all(|coefficient| (1..=255).contains(coefficient))
                    && bounds.len() == leaf.argument.len() + 1
                    && bounds[..leaf.argument.len()]
                        .iter()
                        .all(|bound| *bound == 256)
                    && bounds[leaf.argument.len()] == 1 << 19
            }
            "conv_column" => {
                if leaf.argument.len() != 3
                    || !(0..=8).contains(&leaf.argument[0])
                    || !(0..=4).contains(&leaf.argument[1])
                    || !(0..=1).contains(&leaf.argument[2])
                {
                    false
                } else {
                    let (ab, pq, has_c) = (
                        leaf.argument[0] as usize,
                        leaf.argument[1] as usize,
                        leaf.argument[2] == 1,
                    );
                    let mut expected = vec![1u32 << 18; ab];
                    expected.extend(std::iter::repeat(1u32 << 19).take(pq));
                    expected.extend([16384, 16384]);
                    if has_c {
                        expected.push(256);
                    }
                    bounds == expected
                }
            }
            "bool_xor" | "bool_and" => empty && bounds == [2, 2, 2],
            "bool_not" => empty && bounds == [2, 2],
            "add" => empty && bounds == vec![BASE; 27],
            "mul_bit" => {
                empty
                    && bounds.len() == 28
                    && bounds
                        .iter()
                        .enumerate()
                        .all(|(i, b)| *b == if i == 18 { 2 } else { BASE })
            }
            "bits" => {
                leaf.argument.len() == 1
                    && (1..=29).contains(&leaf.argument[0])
                    && bounds.len() == leaf.argument[0] as usize + 1
                    && bounds[0] == BASE
                    && bounds[1..].iter().all(|b| *b == 2)
            }
            "const" => {
                leaf.argument.len() == 1
                    && bounds.len() == 1
                    && leaf.argument[0] >= 0
                    && leaf.argument[0] < bounds[0] as i64
            }
            "equal" => empty && bounds == vec![BASE; 18],
            "point_form" => {
                empty
                    && bounds.len() == 19
                    && bounds[0] == 2
                    && bounds[1..].iter().all(|b| *b == BASE)
            }
            "gate_equal" => {
                gates
                    && bounds.len() == 19
                    && matches!(bounds[0], 2 | 5)
                    && leaf.argument.iter().all(|a| *a < bounds[0] as i64)
                    && bounds[1..].iter().all(|b| *b == BASE)
            }
            "gate_nonzero" => {
                gates
                    && bounds.len() == 10
                    && bounds[0] == 5
                    && bounds[1..].iter().all(|b| *b == BASE)
            }
            "gate_small_equal" => gates && bounds == [5, 2, 2],
            "dispatch" => {
                empty
                    && bounds.len() == 48
                    && bounds[..2] == [2, 2]
                    && bounds[2..47].iter().all(|b| *b == BASE)
                    && bounds[47] == 5
            }
            "field_valid" => {
                empty
                    && bounds == vec![BASE; 9]
                    && leaf.wires.iter().collect::<HashSet<_>>().len() == 9
            }
            "word_valid" => empty && bounds.len() == 1,
            _ => false,
        }
    }

    pub fn identity(&self) -> Result<[u8; 32]> {
        if self.words.is_empty()
            || self.words.len() > 100_000
            || self.leaves.is_empty()
            || self.leaves.len() > 30_000
            || !identifier(&self.operation_id)
            || !matches!(
                self.field_role.as_str(),
                "pallas_base" | "pallas_scalar" | "vesta_base" | "vesta_scalar"
            )
            || self
                .words
                .iter()
                .any(|w| !identifier(&w.name) || w.bound == 0 || w.bound > BASE)
            || self
                .words
                .iter()
                .map(|w| &w.name)
                .collect::<HashSet<_>>()
                .len()
                != self.words.len()
            || self.bodies.is_empty()
            || self.bodies.len() > 512
        {
            return Err("unsupported registry catalogue".into());
        }
        let mut needed = HashSet::new();
        let mut covered = HashSet::new();
        for (ordinal, leaf) in self.leaves.iter().enumerate() {
            if leaf.wires.is_empty()
                || leaf.wires.len() > 64
                || leaf.wires.iter().any(|i| *i >= self.words.len())
                || !self.shape(leaf)
            {
                return Err(format!("unsupported catalogue leaf {ordinal}: {}", leaf.kind).into());
            }
            needed.insert(leaf.body_sha256.clone());
            covered.extend(leaf.wires.iter().copied());
        }
        if covered.len() != self.words.len() || needed != self.bodies.keys().cloned().collect() {
            return Err("missing wire coverage or extra/missing predicate body".into());
        }
        for (id, hex) in &self.bodies {
            if hex.len() > 40_000 {
                return Err("predicate body size".into());
            }
            let body = hex::decode(hex)?;
            if body.is_empty() || sha256::Hash::hash(&body).to_byte_array() != id32(id)? {
                return Err("predicate body identity mismatch".into());
            }
        }
        let mut h = sha256::Hash::engine();
        h.input(b"BITVM2-NOVA/WOTS-GRAPH/v1\0");
        h.input(&id32(&self.program_sha256)?);
        h.input(&id32(&self.context)?);
        text(&mut h, &self.field_role);
        text(&mut h, &self.operation_id);
        h.input(&(self.words.len() as u32).to_le_bytes());
        for word in &self.words {
            text(&mut h, &word.name);
            h.input(&word.bound.to_le_bytes());
        }
        h.input(&(self.leaves.len() as u32).to_le_bytes());
        for (i, leaf) in self.leaves.iter().enumerate() {
            h.input(&(i as u32).to_le_bytes());
            text(&mut h, &leaf.kind);
            h.input(&(leaf.argument.len() as u32).to_le_bytes());
            for a in &leaf.argument {
                h.input(&a.to_le_bytes());
            }
            h.input(&(leaf.wires.len() as u32).to_le_bytes());
            for wire in &leaf.wires {
                h.input(&(*wire as u32).to_le_bytes());
            }
            h.input(&id32(&leaf.body_sha256)?);
        }
        Ok(sha256::Hash::from_engine(h).to_byte_array())
    }

    pub fn key_identity(&self, keys: &[PublicKey]) -> Result<[u8; 32]> {
        let id = self.identity()?;
        if keys.len() != self.words.len() {
            return Err("one key per global wire required".into());
        }
        let mut h = sha256::Hash::engine();
        h.input(b"BITVM2-NOVA/WOTS-REGISTRY/v1\0");
        h.input(&id);
        let mut unique = HashSet::new();
        for (word, key) in self.words.iter().zip(keys) {
            text(&mut h, &word.name);
            let bytes: Vec<u8> = key.iter().flat_map(|x| x.iter().copied()).collect();
            if !unique.insert(sha256::Hash::hash(&bytes).to_byte_array()) {
                return Err("one-time key reused across global wires".into());
            }
            h.input(&bytes);
        }
        Ok(sha256::Hash::from_engine(h).to_byte_array())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fixtures exercise catalogue admission only. The dummy predicate
    // body is never executed and is not evidence for arithmetic correctness.
    fn graph(kind: &str, argument: &[i64], bounds: &[u32]) -> GraphSpec {
        let body = hex::encode(sha256::Hash::hash(&[0x51]).to_byte_array());
        GraphSpec {
            program_sha256: "00".repeat(32),
            context: "00".repeat(32),
            field_role: "pallas_base".into(),
            operation_id: "test/convolution-shape".into(),
            words: bounds
                .iter()
                .enumerate()
                .map(|(i, bound)| Word {
                    name: format!("w{i}"),
                    bound: *bound,
                })
                .collect(),
            leaves: vec![Leaf {
                kind: kind.into(),
                argument: argument.to_vec(),
                wires: (0..bounds.len()).collect(),
                body_sha256: body.clone(),
            }],
            bodies: [(body, "51".into())].into_iter().collect(),
        }
    }
    fn shaped(spec: &GraphSpec) -> bool {
        spec.shape(&spec.leaves[0])
    }

    #[test]
    fn convolution_shapes_accept_exact_public_schema_boundaries() {
        for width in 1..=7 {
            assert!(shaped(&graph(
                "conv_split",
                &[width],
                &[256, 1 << width, 1 << (8 - width)]
            )));
        }
        for widths in [
            vec![1],
            vec![8, 8, 8],
            vec![8, 8, 8, 5],
            vec![5, 6, 6, 6, 6],
        ] {
            let mut bounds = vec![BASE];
            bounds.extend(widths.iter().map(|width| 1u32 << *width as u32));
            assert!(shaped(&graph("conv_reconstruct", &widths, &bounds)));
        }
        for n in 1..=4 {
            let mut bounds = vec![256; 2 * n];
            bounds.push(1 << 18);
            assert!(shaped(&graph("conv_ab", &[n as i64], &bounds)));
        }
        for n in 1..=8 {
            let mut bounds = vec![256; n];
            bounds.push(1 << 19);
            assert!(shaped(&graph("conv_pq", &vec![255; n], &bounds)));
        }
        for ab in 0..=8 {
            for pq in 0..=4 {
                for c in 0..=1 {
                    let mut bounds = vec![1 << 18; ab];
                    bounds.extend(std::iter::repeat(1 << 19).take(pq));
                    bounds.extend([16384, 16384]);
                    if c == 1 {
                        bounds.push(256);
                    }
                    assert!(shaped(&graph(
                        "conv_column",
                        &[ab as i64, pq as i64, c],
                        &bounds
                    )));
                }
            }
        }
    }

    #[test]
    fn malformed_convolution_arguments_reject_without_shifts_or_allocations() {
        let cases = [
            (
                "conv_split",
                vec![
                    vec![],
                    vec![0],
                    vec![8],
                    vec![-1],
                    vec![i64::MAX],
                    vec![1, 2],
                ],
                vec![256, 16, 16],
            ),
            (
                "conv_reconstruct",
                vec![
                    vec![],
                    vec![0],
                    vec![9],
                    vec![8, 8, 8, 8],
                    vec![1; 6],
                    vec![i64::MAX],
                ],
                vec![BASE, 256],
            ),
            (
                "conv_ab",
                vec![
                    vec![],
                    vec![0],
                    vec![5],
                    vec![-1],
                    vec![i64::MAX],
                    vec![1, 2],
                ],
                vec![256, 256, 1 << 18],
            ),
            (
                "conv_pq",
                vec![
                    vec![],
                    vec![0],
                    vec![256],
                    vec![-1],
                    vec![i64::MAX],
                    vec![1; 9],
                ],
                vec![256, 1 << 19],
            ),
            (
                "conv_column",
                vec![
                    vec![],
                    vec![0],
                    vec![0, 0],
                    vec![0, 0, 0, 0],
                    vec![9, 0, 0],
                    vec![0, 5, 0],
                    vec![0, 0, 2],
                    vec![-1, 0, 0],
                    vec![0, -1, 0],
                    vec![0, 0, -1],
                    vec![i64::MAX, 0, 0],
                ],
                vec![16384, 16384],
            ),
        ];
        for (kind, arguments, bounds) in cases {
            for argument in arguments {
                let spec = graph(kind, &argument, &bounds);
                assert!(!shaped(&spec), "{kind} accepted {argument:?}");
                assert!(spec.identity().is_err());
            }
        }
    }

    #[test]
    fn custom_bounds_and_formal_slot_counts_are_exact() {
        let cases = [
            graph("conv_split", &[4], &[256, 16, 16]),
            graph(
                "conv_reconstruct",
                &[8, 8, 8, 5],
                &[BASE, 256, 256, 256, 32],
            ),
            graph("conv_ab", &[2], &[256, 256, 256, 256, 1 << 18]),
            graph("conv_pq", &[1, 255], &[256, 256, 1 << 19]),
            graph(
                "conv_column",
                &[2, 1, 1],
                &[1 << 18, 1 << 18, 1 << 19, 16384, 16384, 256],
            ),
        ];
        for valid in cases {
            assert!(valid.identity().is_ok());
            for i in 0..valid.words.len() {
                let mut changed = valid.clone();
                changed.words[i].bound += 1;
                assert!(!shaped(&changed));
                assert!(changed.identity().is_err());
            }
            let mut truncated = valid.clone();
            truncated.leaves[0].wires.pop();
            assert!(!shaped(&truncated));
            let mut extra = valid.clone();
            extra.leaves[0].wires.push(0);
            assert!(!shaped(&extra));
            let mut bad_index = valid.clone();
            bad_index.leaves[0].wires[0] = bad_index.words.len();
            assert!(bad_index.identity().is_err());
        }
    }

    #[test]
    fn aliases_preserve_formal_slots_and_change_catalogue_identity() {
        let mut first = graph("conv_ab", &[2], &[256, 256, 1 << 18]);
        first.leaves[0].wires = vec![0, 0, 1, 1, 2];
        assert!(shaped(&first));
        let mut second = first.clone();
        second.leaves[0].wires = vec![0, 1, 0, 1, 2];
        assert!(shaped(&second));
        assert_ne!(first.identity().unwrap(), second.identity().unwrap());
        let mut collapsed = first.clone();
        collapsed.leaves[0].wires = vec![0, 1, 2];
        assert!(!shaped(&collapsed));
        let mut wrong_role = first;
        wrong_role.leaves[0].wires[0] = 2;
        assert!(!shaped(&wrong_role));
        let mut split = graph("conv_split", &[4], &[256, 16]);
        split.leaves[0].wires = vec![0, 1, 1];
        assert!(split.identity().is_ok());
        let mut carries = graph("conv_column", &[0, 0, 0], &[16384]);
        carries.leaves[0].wires = vec![0, 0];
        assert!(carries.identity().is_ok());
    }
}

pub struct Registry {
    spec: GraphSpec,
    keys: Vec<PublicKey>,
    bodies: BTreeMap<String, Vec<u8>>,
    id: [u8; 32],
    recovery_blocks: Vec<OnceLock<Vec<u8>>>,
}

fn recovery_block(key: &PublicKey, bound: u32) -> Vec<u8> {
    let mut code = Wots4::compact_checksig_verify(key).compile().into_bytes();
    number(&mut code, 7);
    code.push(0x79);
    number(&mut code, 2);
    code.extend_from_slice(&[0x9f, 0x63]);
    code.extend_from_slice(digits_to_number::<8, 4>().compile().as_bytes());
    code.push(0x76);
    number(&mut code, bound as i64);
    code.push(0x9f);
    code.push(0x67);
    code.extend_from_slice(&[0x6d; 4]);
    number(&mut code, 0);
    number(&mut code, 0);
    code.extend_from_slice(&[0x68, 0x6b, 0x6b]);
    code
}

impl Registry {
    pub fn new(
        spec: GraphSpec,
        keys: Vec<PublicKey>,
        expected_spec: [u8; 32],
        expected_registry: [u8; 32],
    ) -> Result<Self> {
        let spec_id = spec.identity()?;
        let id = spec.key_identity(&keys)?;
        if spec_id != expected_spec || id != expected_registry {
            return Err("verifier-owned catalogue or registry identity mismatch".into());
        }
        let bodies = spec
            .bodies
            .iter()
            .map(|(id, b)| {
                let body = hex::decode(b)?;
                crate::engine::validate(&ScriptBuf::from_bytes(body.clone()))?;
                Ok((id.clone(), body))
            })
            .collect::<Result<_>>()?;
        let recovery_blocks = keys.iter().map(|_| OnceLock::new()).collect();
        Ok(Self {
            spec,
            keys,
            bodies,
            id,
            recovery_blocks,
        })
    }
    pub fn spec(&self) -> &GraphSpec {
        &self.spec
    }
    pub fn identity(&self) -> [u8; 32] {
        self.id
    }
    pub fn unique_slots(&self, ordinal: usize) -> Result<Vec<usize>> {
        let leaf = self
            .spec
            .leaves
            .get(ordinal)
            .ok_or("leaf ordinal out of bounds")?;
        let mut seen = HashSet::new();
        Ok(leaf
            .wires
            .iter()
            .copied()
            .filter(|i| seen.insert(*i))
            .collect())
    }
    pub fn witness(&self, ordinal: usize, signatures: &[Signature]) -> Result<Vec<Vec<u8>>> {
        if signatures.len() != self.spec.words.len() {
            return Err("missing or surplus global signatures".into());
        }
        let mut witness = Vec::new();
        for i in self.unique_slots(ordinal)? {
            witness.extend(signatures[i].iter().map(|s| s.to_vec()));
        }
        Ok(witness)
    }
    pub fn script(&self, ordinal: usize, disprove: bool) -> Result<ScriptBuf> {
        let leaf = self
            .spec
            .leaves
            .get(ordinal)
            .ok_or("leaf ordinal out of bounds")?;
        let slots = self.unique_slots(ordinal)?;
        let mut code = vec![0x74];
        number(
            &mut code,
            (slots.len() * Wots4::TOTAL_DIGIT_LEN as usize) as i64,
        );
        code.push(0x88);
        let mut tag = sha256::Hash::engine();
        tag.input(b"BITVM2-NOVA/WOTS-GRAPH-LEAF/v1\0");
        tag.input(&self.id);
        tag.input(&(ordinal as u32).to_le_bytes());
        tag.input(&[u8::from(disprove)]);
        code.push(32);
        code.extend_from_slice(sha256::Hash::from_engine(tag).as_byte_array());
        code.push(0x75);
        // Same decoder as the verified v1 leaf, generalized to unique global slots.
        // The v1 implementation remains unchanged as an independent baseline.
        for i in slots.iter().rev() {
            // The key and bound are immutable for the lifetime of this registry.
            // Cache only their deterministic decoder block, never a leaf tag.
            code.extend_from_slice(
                self.recovery_blocks[*i]
                    .get_or_init(|| recovery_block(&self.keys[*i], self.spec.words[*i].bound)),
            );
        }
        number(&mut code, 1);
        for _ in &slots {
            code.extend_from_slice(&[0x6c, 0x6c, 0x7b, 0x9a]);
        }
        code.push(0x63);
        code.extend_from_slice(
            self.bodies
                .get(&leaf.body_sha256)
                .ok_or("missing predicate body")?,
        );
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
        if code.len() > 100_000 {
            return Err("authenticated graph leaf size bound".into());
        }
        Ok(ScriptBuf::from_bytes(code))
    }
}
