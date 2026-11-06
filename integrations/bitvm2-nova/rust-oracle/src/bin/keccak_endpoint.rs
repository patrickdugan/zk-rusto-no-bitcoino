//! TEST-ONLY framed LO-Keccak endpoint and claimed digest reduction conformance.
//! Live registries share original framing, adjacent states and LO output WOTS
//! openings. HI and dynamic message origins remain external. No proof verifier.
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::XOnlyPublicKey,
    taproot::TapNodeHash,
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{emit, Metrics},
    registry::{GraphSpec, Registry, Signature},
    taproot_commitment::TaprootCommitment,
    taproot_forest::TaprootForest,
    wots::{id32, PublicKey, Result},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File, Metadata},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const MANIFEST_CAP: u64 = 1 << 20;
const CASE_CAP: u64 = 32 << 20;
const SUMMARY_CAP: usize = 1 << 20;
const VECTOR_HASH_CAP: u64 = 128 << 20;
const GLOBAL_SCRIPT_CAP: u64 = 5 << 28;
const STATE_BITS: usize = 1600;
const PAIRS: usize = 12;
const GLOBAL_WORDS: usize = 232809;
const LOCAL_WORDS: usize = 249710;
const PERMUTATION_LEAVES: usize = 230510;
const LEAVES: usize = 231715;
const COMPONENTS: usize = 13;
const TAIL_WORDS: usize = 1787;
const TAIL_LEAVES: usize = 1205;
const FRAME_BITS: usize = 832;
const LO_BITS: usize = 256;
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Totals {
    pairs: usize,
    components: usize,
    leaves: usize,
    pair_local_words: usize,
    tail_words: usize,
    global_words: usize,
    inter_pair_shared_words: usize,
    endpoint_shared_words: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    topology_sha256: String,
    context: String,
    role: String,
    operation_id: String,
    totals: Totals,
    scenarios: Vec<Scenario>,
}
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FalsePredicate {
    pair: usize,
    ordinal: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    name: String,
    initial_state_hex: String,
    expected_output_state_hex: String,
    expected_false: Vec<FalsePredicate>,
    selected_pair: usize,
    selected_leaf: usize,
    pairs: Vec<PairDescriptor>,
    tail: TailDescriptor,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TailDescriptor {
    filename: String,
    file_sha256: String,
    file_bytes: u64,
    catalogue_id: String,
    program_sha256: String,
    global_ids_sha256: String,
    words: usize,
    leaves: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairDescriptor {
    index: usize,
    first_round: usize,
    filename: String,
    file_sha256: String,
    file_bytes: u64,
    catalogue_id: String,
    program_sha256: String,
    global_ids_sha256: String,
    words: usize,
    leaves: usize,
    first_child_leaves: usize,
    initial_state_hex: String,
    middle_state_hex: String,
    output_state_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    ordinal: usize,
    expected_correct: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    spec: GraphSpec,
    expected_spec_id: String,
    words: Vec<u32>,
    checks: Vec<Check>,
    measure_all: bool,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn digest(value: &str) -> Result<[u8; 32]> {
    let bytes = id32(value)?;
    if hex::encode(bytes) != value {
        return Err("canonical lowercase32 digest required".into());
    }
    Ok(bytes)
}
fn state(value: &str) -> Result<[u64; 25]> {
    if value.len() != 400
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("canonical200-byte little-endian state hex required".into());
    }
    let raw = hex::decode(value)?;
    let mut lanes = [0; 25];
    for (lane, chunk) in lanes.iter_mut().zip(raw.chunks_exact(8)) {
        *lane = u64::from_le_bytes(chunk.try_into()?);
    }
    Ok(lanes)
}
fn round_leaves(round: usize) -> usize {
    9601 + ROUND_CONSTANTS[round].count_ones() as usize
}
fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema != "bitvm2-nova-keccak-endpoint-run/v1"
        || manifest.role != "pallas_scalar"
        || !identifier(&manifest.operation_id)
        || manifest.operation_id.len() + "/permutation/pair/11/child/1/round/23".len() > 192
        || manifest.totals.pairs != PAIRS
        || manifest.totals.components != COMPONENTS
        || manifest.totals.leaves != LEAVES
        || manifest.totals.pair_local_words != LOCAL_WORDS
        || manifest.totals.tail_words != TAIL_WORDS
        || manifest.totals.global_words != GLOBAL_WORDS
        || manifest.totals.inter_pair_shared_words != 17600
        || manifest.totals.endpoint_shared_words != FRAME_BITS + LO_BITS
        || manifest.scenarios.len() != 3
    {
        return Err("bounded full-Keccak manifest identity/count mismatch".into());
    }
    digest(&manifest.topology_sha256)?;
    digest(&manifest.context)?;
    let mut names = HashSet::new();
    for scenario in &manifest.scenarios {
        let padding = scenario.name == "wrong-padding";
        let selected_pair = if padding { PAIRS } else { PAIRS - 1 };
        let selected_leaf = if padding {
            492
        } else {
            round_leaves(22) + round_leaves(23) - STATE_BITS
        };
        if !matches!(
            scenario.name.as_str(),
            "honest" | "coherent-output" | "wrong-padding"
        ) || !names.insert(scenario.name.as_str())
            || scenario.pairs.len() != PAIRS
            || scenario.selected_pair != selected_pair
            || scenario.selected_leaf != selected_leaf
        {
            return Err("exact scenario/order/selection profile required".into());
        }
        let initial = state(&scenario.initial_state_hex)?;
        for (byte, bit, expected) in framing_bits() {
            let actual = ((initial[byte / 8] >> (8 * (byte % 8) + bit)) & 1) as u32;
            let expected = if padding && byte == 111 && bit == 0 {
                expected ^ 1
            } else {
                expected
            };
            if actual != expected {
                return Err("initial state fixed framing profile differs".into());
            }
        }
        state(&scenario.expected_output_state_hex)?;
        let expected = if scenario.name == "honest" {
            vec![]
        } else {
            vec![FalsePredicate {
                pair: selected_pair,
                ordinal: selected_leaf,
            }]
        };
        if scenario.expected_false != expected {
            return Err("scenario's exact false-predicate profile mismatch".into());
        }
        let mut leaves = 0;
        let mut words = 0;
        let mut catalogue_ids = HashSet::new();
        for (index, pair) in scenario.pairs.iter().enumerate() {
            let first = round_leaves(2 * index);
            let count = first + round_leaves(2 * index + 1);
            if pair.index != index
                || pair.first_round != 2 * index
                || pair.filename != format!("{}/pair-{index:02}.json", scenario.name)
                || pair.first_child_leaves != first
                || pair.leaves != count
                || pair.words != count + STATE_BITS
                || pair.file_bytes == 0
                || pair.file_bytes > CASE_CAP
                || !catalogue_ids.insert(pair.catalogue_id.as_str())
            {
                return Err("pair descriptor topology/filename/size mismatch".into());
            }
            for value in [
                &pair.file_sha256,
                &pair.catalogue_id,
                &pair.program_sha256,
                &pair.global_ids_sha256,
            ] {
                digest(value)?;
            }
            for value in [
                &pair.initial_state_hex,
                &pair.middle_state_hex,
                &pair.output_state_hex,
            ] {
                state(value)?;
            }
            if (index == 0 && pair.initial_state_hex != scenario.initial_state_hex)
                || (index > 0
                    && pair.initial_state_hex != scenario.pairs[index - 1].output_state_hex)
                || (index + 1 == PAIRS
                    && pair.output_state_hex != scenario.expected_output_state_hex)
            {
                return Err("descriptor state-chain framing mismatch".into());
            }
            leaves += pair.leaves;
            words += pair.words;
        }
        if leaves != PERMUTATION_LEAVES || words != LOCAL_WORDS {
            return Err("descriptor aggregate topology mismatch".into());
        }
        let tail = &scenario.tail;
        if tail.filename != format!("{}/tail.json", scenario.name)
            || tail.file_bytes == 0
            || tail.file_bytes > CASE_CAP
            || tail.words != TAIL_WORDS
            || tail.leaves != TAIL_LEAVES
        {
            return Err("tail descriptor topology/filename/size mismatch".into());
        }
        for value in [
            &tail.file_sha256,
            &tail.catalogue_id,
            &tail.program_sha256,
            &tail.global_ids_sha256,
        ] {
            digest(value)?;
        }
    }
    Ok(())
}

fn regular(path: &Path) -> Result<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("regular non-symlink fixture required".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("hard-linked fixture forbidden".into());
        }
    }
    Ok(metadata)
}
fn snapshot(path: &Path, cap: u64, expected_size: Option<u64>) -> Result<Vec<u8>> {
    let before = regular(path)?;
    if before.len() > cap || expected_size.is_some_and(|size| size != before.len()) {
        return Err("fixture byte budget/declared length mismatch".into());
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino(), before.len()) != (opened.dev(), opened.ino(), opened.len())
        {
            return Err("fixture changed during open".into());
        }
    }
    let mut raw = Vec::new();
    file.take(cap + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 != before.len() || raw.len() as u64 > cap {
        return Err("fixture changed length during bounded read".into());
    }
    regular(path)?;
    Ok(raw)
}
fn named_case_path(root: &Path, scenario: &Scenario, filename: &str) -> Result<PathBuf> {
    let directory = root.join(&scenario.name);
    let metadata = fs::symlink_metadata(&directory)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(&directory)? != directory
    {
        return Err("scenario directory alias/path escape".into());
    }
    let path = root.join(filename);
    regular(&path)?;
    if fs::canonicalize(&path)?.parent() != Some(directory.as_path()) {
        return Err("case path escapes scenario directory".into());
    }
    Ok(path)
}
fn case_path(root: &Path, scenario: &Scenario, pair: &PairDescriptor) -> Result<PathBuf> {
    if pair.filename != format!("{}/pair-{:02}.json", scenario.name, pair.index) {
        return Err("noncanonical pair filename".into());
    }
    named_case_path(root, scenario, &pair.filename)
}

fn number(text: &str, prefix: char, maximum: usize) -> Result<usize> {
    let rest = text
        .strip_prefix(prefix)
        .ok_or("canonical numeric name prefix")?;
    let value: usize = rest.parse()?;
    if value > maximum || rest != value.to_string() {
        return Err("numeric name alias/bound".into());
    }
    Ok(value)
}
fn global_name(pair: usize, local: &str) -> Result<String> {
    if pair >= PAIRS || !identifier(local) {
        return Err("global name input bounds".into());
    }
    if let Some(rest) = local.strip_prefix("boundary/") {
        let pieces: Vec<_> = rest.split('/').collect();
        if pieces.len() != 3 {
            return Err("state name shape".into());
        }
        let offset = match pieces[0] {
            "input" => 0,
            "middle" => 1,
            "output" => 2,
            _ => return Err("unknown state boundary".into()),
        };
        let lane = number(pieces[1], 'l', 24)?;
        let bit = number(pieces[2], 'b', 63)?;
        return Ok(format!("state/{}/l{lane}/b{bit}", 2 * pair + offset));
    }
    for child in 0..2 {
        if let Some(original) = local.strip_prefix(&format!("child/{child}/")) {
            let round = 2 * pair + child;
            if !original.starts_with(&format!("keccak/r{round}/")) || !identifier(original) {
                return Err("child round/source namespace mismatch".into());
            }
            return Ok(format!("round/{round}/{original}"));
        }
    }
    Err("unrecognized local Keccak name".into())
}
fn framing_bits() -> Vec<(usize, usize, u32)> {
    let mut fixed = [None; 200];
    fixed[0] = Some(b'w');
    let counter = 59u64.to_le_bytes();
    for (index, value) in b"NoDS".iter().chain(counter.iter()).enumerate() {
        fixed[33 + index] = Some(*value);
    }
    fixed[109] = Some(b'r');
    fixed[110] = Some(0); // LO branch; HI remains an external digest claim.
    fixed[111] = Some(1);
    for item in &mut fixed[112..200] {
        *item = Some(0);
    }
    fixed[135] = Some(128);
    let mut result = Vec::with_capacity(FRAME_BITS);
    for (byte, value) in fixed.iter().enumerate() {
        if let Some(value) = value {
            for bit in 0..8 {
                result.push((byte, bit, u32::from((value >> bit) & 1)));
            }
        }
    }
    result
}
fn tail_global_names(spec: &GraphSpec) -> Result<Vec<String>> {
    spec.words
        .iter()
        .map(|word| {
            if let Some(rest) = word.name.strip_prefix("digest/lo/") {
                let pieces: Vec<_> = rest.split('/').collect();
                if pieces.len() != 2 {
                    return Err("tail LO port name shape".into());
                }
                let lane = number(pieces[0], 'l', 3)?;
                let bit = number(pieces[1], 'b', 63)?;
                Ok(format!("state/24/l{lane}/b{bit}"))
            } else if let Some(rest) = word.name.strip_prefix("frame/byte/") {
                let pieces: Vec<_> = rest.split('/').collect();
                if pieces.len() != 3 || pieces[1] != "bit" {
                    return Err("tail framing name shape".into());
                }
                let byte: usize = pieces[0].parse()?;
                let bit: usize = pieces[2].parse()?;
                if byte >= 200
                    || bit >= 8
                    || pieces[0] != byte.to_string()
                    || pieces[2] != bit.to_string()
                {
                    return Err("tail framing name aliases/bounds".into());
                }
                Ok(format!("state/0/l{}/b{}", byte / 8, 8 * (byte % 8) + bit))
            } else if identifier(&word.name) {
                Ok(format!("tail/{}", word.name))
            } else {
                Err("tail local identifier invalid".into())
            }
        })
        .collect()
}
fn frame(hash: &mut sha256::HashEngine, text: &str) -> Result<()> {
    if !text.is_ascii() {
        return Err("ASCII global identity required".into());
    }
    hash.input(&u16::try_from(text.len())?.to_le_bytes());
    hash.input(text.as_bytes());
    Ok(())
}
fn seed(topology: &[u8; 32], scenario: &str, global: &str) -> Result<Vec<u8>> {
    let mut hash = sha256::Hash::engine();
    hash.input(b"BITVM2-NOVA/TEST-ONLY-GLOBAL-KECCAK-ENDPOINT/v1\0");
    hash.input(topology);
    frame(&mut hash, scenario)?;
    frame(&mut hash, global)?;
    Ok(sha256::Hash::from_engine(hash).to_byte_array().to_vec())
}
fn payload<T: AsRef<[u8]>>(parts: &[T]) -> Vec<u8> {
    parts
        .iter()
        .flat_map(|part| part.as_ref().iter().copied())
        .collect()
}

#[derive(Clone)]
struct Cached {
    name: String,
    key: PublicKey,
    signature: Signature,
    value: u32,
    bound: u32,
    opening: Vec<Vec<u8>>,
}
struct GlobalKeys {
    names: HashSet<String>,
    keys_hash: sha256::HashEngine,
    signatures_hash: sha256::HashEngine,
    created: usize,
    reused: usize,
}
impl GlobalKeys {
    fn new(topology: &[u8; 32], scenario: &str) -> Result<Self> {
        let mut keys_hash = sha256::Hash::engine();
        let mut signatures_hash = sha256::Hash::engine();
        keys_hash.input(b"BITVM2-NOVA/GLOBAL-KEYS/v1\0");
        signatures_hash.input(b"BITVM2-NOVA/GLOBAL-SIGNATURES/v1\0");
        for hash in [&mut keys_hash, &mut signatures_hash] {
            hash.input(topology);
            frame(hash, scenario)?;
        }
        Ok(Self {
            names: HashSet::with_capacity(GLOBAL_WORDS),
            keys_hash,
            signatures_hash,
            created: 0,
            reused: 0,
        })
    }
    fn assign(
        &mut self,
        case: &Case,
        names: &[String],
        pair: usize,
        topology: &[u8; 32],
        scenario: &str,
        previous: &[Cached],
        all_keys: &mut HashSet<[u8; 32]>,
        all_signatures: &mut HashSet<[u8; 32]>,
    ) -> Result<(Vec<PublicKey>, Vec<Signature>)> {
        let expected_reuses = if pair == 0 {
            0
        } else if pair < PAIRS {
            STATE_BITS
        } else if pair == PAIRS {
            FRAME_BITS + LO_BITS
        } else {
            return Err("component index bound".into());
        };
        if previous.len() != expected_reuses {
            return Err("adjacent cache cardinality".into());
        }
        let previous_map: HashMap<_, _> = previous
            .iter()
            .map(|entry| (entry.name.as_str(), entry))
            .collect();
        if previous_map.len() != previous.len() {
            return Err("duplicate cached global identity".into());
        }
        let mut reused = HashSet::new();
        let mut keys = Vec::with_capacity(case.words.len());
        let mut signatures = Vec::with_capacity(case.words.len());
        if names.len() != case.words.len() {
            return Err("global identity vector count".into());
        }
        for ((word, value), name) in case.spec.words.iter().zip(&case.words).zip(names) {
            if (pair > 0 && pair < PAIRS && word.name.starts_with("boundary/input/"))
                || (pair == PAIRS && previous_map.contains_key(name.as_str()))
            {
                let cached = previous_map
                    .get(name.as_str())
                    .ok_or("missing adjacent cached identity")?;
                if cached.value != *value
                    || cached.bound != word.bound
                    || !self.names.contains(name)
                    || !reused.insert(name.clone())
                {
                    return Err("adjacent state changed value or reused a slot twice".into());
                }
                if !all_keys.contains(&sha256::Hash::hash(&payload(&cached.key)).to_byte_array())
                    || !all_signatures
                        .contains(&sha256::Hash::hash(&payload(&cached.signature)).to_byte_array())
                {
                    return Err("adjacent cached key/signature was not created on first use".into());
                }
                keys.push(cached.key);
                signatures.push(cached.signature);
                self.reused += 1;
            } else {
                if !self.names.insert(name.clone()) {
                    return Err("nonadjacent/global identity reuse".into());
                }
                let secret = seed(topology, scenario, &name)?;
                let key = Wots4::generate_public_key(&secret);
                let signature = Wots4::compact_sign(&secret, &value.to_le_bytes());
                let key_bytes = payload(&key);
                let signature_bytes = payload(&signature);
                if key_bytes.len() != 200
                    || signature_bytes.len() != 200
                    || !all_keys.insert(sha256::Hash::hash(&key_bytes).to_byte_array())
                    || !all_signatures.insert(sha256::Hash::hash(&signature_bytes).to_byte_array())
                {
                    return Err("global/scenario WOTS key or signature collision/reuse".into());
                }
                frame(&mut self.keys_hash, &name)?;
                self.keys_hash.input(&word.bound.to_le_bytes());
                self.keys_hash.input(&key_bytes);
                frame(&mut self.signatures_hash, &name)?;
                self.signatures_hash.input(&value.to_le_bytes());
                self.signatures_hash.input(&signature_bytes);
                keys.push(key);
                signatures.push(signature);
                self.created += 1;
            }
        }
        if reused.len() != expected_reuses {
            return Err("incomplete incoming cache reuse".into());
        }
        Ok((keys, signatures))
    }
}

fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    let leaf = spec.leaves.get(ordinal).ok_or("truth ordinal")?;
    let v: Vec<_> = leaf.wires.iter().map(|slot| values[*slot]).collect();
    if v.iter().any(|value| *value > 1) {
        return Ok(false);
    }
    Ok(match (leaf.kind.as_str(), v.as_slice()) {
        ("bool_xor", [a, b, c]) if leaf.argument.is_empty() => *c == (*a ^ *b),
        ("bool_and", [a, b, c]) if leaf.argument.is_empty() => *c == (*a & *b),
        ("bool_not", [a, b]) if leaf.argument.is_empty() => *b == 1 - *a,
        ("const", [a]) if leaf.argument == [0] => *a == 0,
        _ => return Err("non-Boolean/constant full-Keccak predicate".into()),
    })
}
fn tail_truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    let leaf = spec.leaves.get(ordinal).ok_or("tail truth ordinal")?;
    let v: Vec<u64> = leaf
        .wires
        .iter()
        .map(|slot| u64::from(values[*slot]))
        .collect();
    if leaf
        .wires
        .iter()
        .any(|slot| values[*slot] >= spec.words[*slot].bound)
    {
        return Ok(false);
    }
    Ok(match leaf.kind.as_str() {
        "const" => v[0] == leaf.argument[0] as u64,
        "bits" => v[0] == v[1..].iter().fold(0, |n, bit| 2 * n + bit),
        "conv_split" => v[0] == v[1] + (v[2] << leaf.argument[0]),
        "conv_reconstruct" => {
            let mut offset = 0;
            let mut sum = 0;
            for (digit, width) in v[1..].iter().zip(&leaf.argument) {
                sum += digit << offset;
                offset += width;
            }
            v[0] == sum
        }
        "conv_ab" => {
            v[v.len() - 1]
                == v[..v.len() - 1]
                    .chunks_exact(2)
                    .map(|p| p[0] * p[1])
                    .sum::<u64>()
        }
        "conv_pq" => {
            v[v.len() - 1]
                == v[..v.len() - 1]
                    .iter()
                    .zip(&leaf.argument)
                    .map(|(a, b)| a * (*b as u64))
                    .sum::<u64>()
        }
        "conv_column" => {
            let ab = leaf.argument[0] as usize;
            let pq = leaf.argument[1] as usize;
            let out = if leaf.argument[2] == 1 {
                v[v.len() - 1]
            } else {
                0
            };
            v[..ab].iter().sum::<u64>() + v[ab + pq] + 255 * 8192
                == out + v[ab..ab + pq].iter().sum::<u64>() + 256 * v[ab + pq + 1]
        }
        "field_valid" => {
            // Published Pasta scalar Fq modulus, independently decomposed into
            // the nine radix-2^29 limbs used by the existing arithmetic leaves.
            let raw =
                hex::decode("0100000021eb468cdda89409fc98462200000000000000000000000000000040")?;
            let mut modulus = [0u64; 9];
            for bit in 0..256 {
                modulus[bit / 29] |= u64::from((raw[bit / 8] >> (bit % 8)) & 1) << (bit % 29);
            }
            v.iter().rev().cmp(modulus.iter().rev()).is_lt()
        }
        _ => return Err("unsupported endpoint tail predicate".into()),
    })
}

fn validate_tail(case: &Case, manifest: &Manifest, scenario: &Scenario) -> Result<Vec<String>> {
    let desc = &scenario.tail;
    if case.name != format!("keccak/endpoint/{}/tail", scenario.name)
        || !case.measure_all
        || case.expected_spec_id != desc.catalogue_id
        || case.spec.program_sha256 != desc.program_sha256
        || case.spec.context != manifest.context
        || case.spec.field_role != manifest.role
        || case.spec.operation_id != format!("{}/tail", manifest.operation_id)
        || case.spec.words.len() != TAIL_WORDS
        || case.words.len() != TAIL_WORDS
        || case.spec.leaves.len() != TAIL_LEAVES
        || case.checks.len() != TAIL_LEAVES
        || case.checks.iter().enumerate().any(|(i, c)| c.ordinal != i)
        || case
            .words
            .iter()
            .zip(&case.spec.words)
            .any(|(v, w)| *v >= w.bound)
        || case.spec.identity()? != digest(&desc.catalogue_id)?
    {
        return Err("tail differs from exact trusted endpoint descriptor".into());
    }
    let spec = &case.spec;
    let word = |name: &str, bound: u32| -> Result<usize> {
        spec.words
            .iter()
            .position(|w| w.name == name && w.bound == bound)
            .ok_or_else(|| format!("missing exact tail word {name}").into())
    };
    let unit = word("constant/byte-one", 256)?;
    if spec.leaves[0].kind != "const"
        || spec.leaves[0].argument != [1]
        || spec.leaves[0].wires != [unit]
        || spec.leaves[1204].kind != "field_valid"
        || spec
            .leaves
            .iter()
            .filter(|l| l.kind == "field_valid")
            .count()
            != 1
    {
        return Err("tail unit/field validity anchors differ".into());
    }
    for i in 0..64 {
        let mut bits = Vec::new();
        for bit in 0..8 {
            let index = word(
                &format!(
                    "digest/{}/l{}/b{}",
                    if i < 32 { "lo" } else { "hi" },
                    (i % 32) / 8,
                    8 * (i % 8) + bit
                ),
                2,
            )?;
            if index != 379 + 9 * i + bit {
                return Err("tail digest bit order/alias map differs".into());
            }
            bits.push(index);
        }
        let aux = word(&format!("digest/byte/{i}/aux"), 1 << 29)?;
        let byte = word(&format!("input/byte/{i}"), 256)?;
        let subtotal = word(&format!("input/subtotal/{i}"), 1 << 18)?;
        let mut expected = vec![aux];
        expected.extend(bits.into_iter().rev());
        if aux != 379 + 9 * i + 8
            || byte >= 379
            || subtotal >= 379
            || spec.leaves[244 + 2 * i].kind != "bits"
            || spec.leaves[244 + 2 * i].argument != [8]
            || spec.leaves[244 + 2 * i].wires != expected
            || spec.leaves[245 + 2 * i].kind != "conv_reconstruct"
            || spec.leaves[245 + 2 * i].argument != [8]
            || spec.leaves[245 + 2 * i].wires != [aux, byte]
            || spec.leaves[1 + i].kind != "conv_ab"
            || spec.leaves[1 + i].argument != [1]
            || spec.leaves[1 + i].wires != [byte, unit, subtotal]
        {
            return Err("tail bit/aux/BYTE/input adapter disconnected".into());
        }
    }
    for (j, (byte, bit, value)) in framing_bits().iter().enumerate() {
        let index = word(&format!("frame/byte/{byte}/bit/{bit}"), 2)?;
        let leaf = &spec.leaves[372 + j];
        if index != 955 + j
            || leaf.kind != "const"
            || leaf.argument != [i64::from(*value)]
            || leaf.wires != [index]
        {
            return Err("tail fixed framing order/constant differs".into());
        }
    }
    let names = tail_global_names(spec)?;
    if names.iter().collect::<HashSet<_>>().len() != TAIL_WORDS
        || sha256::Hash::hash(&serde_json::to_vec(&names)?).to_byte_array()
            != digest(&desc.global_ids_sha256)?
    {
        return Err("tail normative global identity mapping differs".into());
    }
    Ok(names)
}
fn slots(spec: &GraphSpec, prefix: &str) -> Result<Vec<usize>> {
    let names: HashMap<_, _> = spec
        .words
        .iter()
        .enumerate()
        .map(|(i, w)| (w.name.as_str(), i))
        .collect();
    let mut slots = Vec::with_capacity(STATE_BITS);
    for lane in 0..25 {
        for bit in 0..64 {
            slots.push(
                *names
                    .get(format!("boundary/{prefix}/l{lane}/b{bit}").as_str())
                    .ok_or("missing ordered state bit")?,
            );
        }
    }
    Ok(slots)
}
fn actual_state(values: &[u32], slots: &[usize]) -> Result<[u64; 25]> {
    let mut lanes = [0u64; 25];
    for (bit, slot) in slots.iter().enumerate() {
        let value = *values.get(*slot).ok_or("state slot outside assignment")?;
        if value > 1 {
            return Err("non-Boolean actual state bit".into());
        }
        lanes[bit / 64] |= u64::from(value) << (bit % 64);
    }
    Ok(lanes)
}
fn opening(
    registry: &Registry,
    signatures: &[Signature],
    ordinal: usize,
    slot: usize,
) -> Result<Vec<Vec<u8>>> {
    let unique = registry.unique_slots(ordinal)?;
    let position = unique
        .iter()
        .position(|candidate| *candidate == slot)
        .ok_or("opening absent from leaf")?;
    let witness = registry.witness(ordinal, signatures)?;
    let width = Wots4::TOTAL_DIGIT_LEN as usize;
    Ok(witness
        .get(position * width..(position + 1) * width)
        .ok_or("opening segment bound")?
        .to_vec())
}
fn consumers(
    spec: &GraphSpec,
    shared: &[usize],
    start: usize,
    end: usize,
) -> Result<Vec<Vec<usize>>> {
    let by_slot: HashMap<_, _> = shared
        .iter()
        .enumerate()
        .map(|(bit, slot)| (*slot, bit))
        .collect();
    let mut result = vec![Vec::new(); STATE_BITS];
    for ordinal in start..end {
        let leaf = &spec.leaves[ordinal];
        let (output, inputs) = leaf.wires.split_last().ok_or("empty Boolean leaf")?;
        if by_slot.contains_key(output) {
            return Err("consumer redefines shared input state".into());
        }
        for slot in inputs {
            if let Some(bit) = by_slot.get(slot) {
                result[*bit].push(ordinal);
            }
        }
    }
    if result.iter().any(|uses| uses.len() != 2) {
        return Err("exact two-use Keccak input topology required".into());
    }
    Ok(result)
}
fn boundary_links(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    names: &[String],
    first: usize,
    previous: &[Cached],
) -> Result<(usize, usize, Vec<Cached>)> {
    let spec = registry.spec();
    let middle = slots(spec, "middle")?;
    let incoming = slots(spec, "input")?;
    let outgoing = slots(spec, "output")?;
    let middle_uses = consumers(spec, &middle, first, spec.leaves.len())?;
    let incoming_uses = consumers(spec, &incoming, 0, first)?;
    let mut internal = 0;
    let mut inter = 0;
    for bit in 0..STATE_BITS {
        let producer = first - STATE_BITS + bit;
        if spec.leaves[producer].kind != "bool_xor"
            || spec.leaves[producer].wires.last() != Some(&middle[bit])
        {
            return Err("middle producer does not authenticate actual shared slot".into());
        }
        let source = opening(registry, signatures, producer, middle[bit])?;
        for consumer in &middle_uses[bit] {
            if source != opening(registry, signatures, *consumer, middle[bit])? {
                return Err("internal WOTS boundary differs".into());
            }
            internal += 1;
        }
        if !previous.is_empty() {
            let cached = &previous[bit];
            if cached.name != names[incoming[bit]]
                || cached.value != values[incoming[bit]]
                || cached.bound != spec.words[incoming[bit]].bound
            {
                return Err("ordered adjacent state cache mismatch".into());
            }
            for consumer in &incoming_uses[bit] {
                if cached.opening != opening(registry, signatures, *consumer, incoming[bit])? {
                    return Err(
                        "inter-pair WOTS opening differs from preceding actual output".into(),
                    );
                }
                inter += 1;
            }
        }
    }
    let mut cache = Vec::with_capacity(STATE_BITS);
    for (bit, slot) in outgoing.iter().enumerate() {
        let producer = spec.leaves.len() - STATE_BITS + bit;
        if spec.leaves[producer].kind != "bool_xor"
            || spec.leaves[producer].wires.last() != Some(slot)
        {
            return Err("outgoing state producer mapping mismatch".into());
        }
        cache.push(Cached {
            name: names[*slot].clone(),
            key: keys[*slot],
            signature: signatures[*slot],
            value: values[*slot],
            bound: spec.words[*slot].bound,
            opening: opening(registry, signatures, producer, *slot)?,
        });
    }
    Ok((internal, inter, cache))
}
fn initial_framing_cache(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    names: &[String],
    first: usize,
) -> Result<Vec<Cached>> {
    let incoming = slots(registry.spec(), "input")?;
    let uses = consumers(registry.spec(), &incoming, 0, first)?;
    framing_bits()
        .iter()
        .map(|(byte, bit, _)| {
            let state_bit = 8 * byte + bit;
            let slot = incoming[state_bit];
            Ok(Cached {
                name: names[slot].clone(),
                key: keys[slot],
                signature: signatures[slot],
                value: values[slot],
                bound: registry.spec().words[slot].bound,
                opening: opening(registry, signatures, uses[state_bit][0], slot)?,
            })
        })
        .collect()
}
fn tail_links(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    names: &[String],
    cached: &[Cached],
) -> Result<(usize, usize, usize, usize)> {
    if cached.len() != FRAME_BITS + LO_BITS {
        return Err("endpoint cache count".into());
    }
    let lookup: HashMap<_, _> = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.as_str(), i))
        .collect();
    let mut framing = 0;
    let mut lo = 0;
    for (j, entry) in cached.iter().enumerate() {
        let slot = *lookup
            .get(entry.name.as_str())
            .ok_or("endpoint cached identity missing")?;
        if values[slot] != entry.value
            || registry.spec().words[slot].bound != entry.bound
            || keys[slot] != entry.key
            || signatures[slot] != entry.signature
        {
            return Err("endpoint key/value/bound/signature differs from original source".into());
        }
        let ordinal = if j < FRAME_BITS {
            372 + j
        } else {
            244 + 2 * ((j - FRAME_BITS) / 8)
        };
        if entry.opening != opening(registry, signatures, ordinal, slot)? {
            return Err("endpoint opening differs from original live source leaf".into());
        }
        if j < FRAME_BITS {
            framing += 1;
        } else {
            lo += 1;
        }
    }
    let spec = registry.spec();
    let mut bytes = 0;
    for i in 0..64 {
        let aux = spec.leaves[244 + 2 * i].wires[0];
        let byte = spec.leaves[245 + 2 * i].wires[1];
        if opening(registry, signatures, 244 + 2 * i, aux)?
            != opening(registry, signatures, 245 + 2 * i, aux)?
            || opening(registry, signatures, 245 + 2 * i, byte)?
                != opening(registry, signatures, 1 + i, byte)?
        {
            return Err("tail bit/aux/BYTE opening link differs".into());
        }
        bytes += 2;
    }
    let columns: Vec<_> = spec
        .leaves
        .iter()
        .enumerate()
        .filter(|(_, l)| l.kind == "conv_column")
        .collect();
    if columns.len() != 65 {
        return Err("tail reduction must keep overflow column".into());
    }
    let mut carries = 0;
    for pair in columns.windows(2) {
        let (a, left) = pair[0];
        let (b, right) = pair[1];
        let shared = left.wires[(left.argument[0] + left.argument[1]) as usize + 1];
        if shared != right.wires[(right.argument[0] + right.argument[1]) as usize]
            || opening(registry, signatures, a, shared)?
                != opening(registry, signatures, b, shared)?
        {
            return Err("tail adjacent carry opening differs".into());
        }
        carries += 1;
    }
    Ok((framing, lo, bytes, carries))
}
fn endpoint_cache_negatives(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    names: &[String],
    cached: &[Cached],
) -> Result<usize> {
    let mut rejected = 0;
    // Each source endpoint is tested independently. A changed signed value,
    // decoder bound, key, signature or actual opening must fail before it can
    // be treated as a reusable source assertion.
    for index in [0, FRAME_BITS] {
        for mutation in 0..6 {
            let mut bad = cached.to_vec();
            match mutation {
                0 => bad[index].value ^= 1,
                1 => bad[index].bound = 256,
                2 => bad[index].key = bad[(index + 1) % bad.len()].key,
                3 => bad[index].signature = bad[(index + 1) % bad.len()].signature,
                4 => {
                    *bad[index]
                        .opening
                        .first_mut()
                        .and_then(|d| d.first_mut())
                        .ok_or("empty cached opening")? ^= 1
                }
                _ => bad[index].name = bad[(index + 1) % bad.len()].name.clone(),
            }
            if tail_links(registry, keys, signatures, values, names, &bad).is_ok() {
                return Err("altered endpoint source cache accepted".into());
            }
            rejected += 1;
        }
    }
    Ok(rejected)
}

struct VectorSink {
    hash: sha256::HashEngine,
    bytes: u64,
}
impl Write for VectorSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let total = self
            .bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| std::io::Error::other("vector size overflow"))?;
        if total > VECTOR_HASH_CAP {
            return Err(std::io::Error::other("selected vector hashing budget"));
        }
        self.hash.input(data);
        self.bytes = total;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn guards(
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    label: &str,
) -> Result<usize> {
    let mut kinds = HashSet::new();
    for (ordinal, leaf) in registry.spec().leaves.iter().enumerate() {
        if !kinds.insert(leaf.kind.as_str()) {
            continue;
        }
        let witness = registry.witness(ordinal, signatures)?;
        for disprove in [false, true] {
            let code = registry.script(ordinal, disprove)?;
            for (index, bad) in [
                vec![],
                witness[..witness.len() - 1].to_vec(),
                [vec![vec![]], witness.clone()].concat(),
                [witness.clone(), vec![vec![]]].concat(),
            ]
            .iter()
            .enumerate()
            {
                emit(
                    sink,
                    metrics,
                    &code,
                    bad,
                    false,
                    &format!("{label}/length/{ordinal}/{index}/{disprove}"),
                )?;
            }
            for position in [0, witness.len() - 1] {
                let mut bad = witness.clone();
                *bad[position].first_mut().ok_or("empty signature digit")? ^= 1;
                emit(
                    sink,
                    metrics,
                    &code,
                    &bad,
                    false,
                    &format!("{label}/forgery/{ordinal}/{position}/{disprove}"),
                )?;
            }
            let slot = registry.unique_slots(ordinal)?[0];
            let mut substituted = signatures.to_vec();
            substituted[slot] = signatures[(slot + 1) % signatures.len()];
            emit(
                sink,
                metrics,
                &code,
                &registry.witness(ordinal, &substituted)?,
                false,
                &format!("{label}/cross-wire/{ordinal}/{disprove}"),
            )?;
        }
    }
    if kinds != HashSet::from(["bool_xor", "bool_and", "bool_not", "const"]) {
        return Err("all four Boolean/constant guard shapes required".into());
    }
    Ok(14 * kinds.len())
}
fn tail_guards(
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    label: &str,
) -> Result<usize> {
    let mut kinds = HashSet::new();
    let mut constants = HashSet::new();
    let mut selected = HashSet::new();
    for (ordinal, leaf) in registry.spec().leaves.iter().enumerate() {
        if kinds.insert(leaf.kind.as_str()) {
            selected.insert(ordinal);
        }
        if leaf.kind == "const" {
            let shape = (
                leaf.body_sha256.as_str(),
                registry.spec().words[leaf.wires[0]].bound,
            );
            if constants.insert(shape) {
                selected.insert(ordinal);
            }
        }
    }
    selected.insert(245); // Additional BASE/BYTE reconstruct(8) decoder shape.
    if kinds
        != HashSet::from([
            "const",
            "bits",
            "conv_split",
            "conv_reconstruct",
            "conv_ab",
            "conv_pq",
            "conv_column",
            "field_valid",
        ])
        || constants.len() != 5
        || selected.len() != 13
    {
        return Err("exact mixed tail authentication guard shapes required".into());
    }
    let mut selected: Vec<_> = selected.into_iter().collect();
    selected.sort_unstable();
    for ordinal in &selected {
        let witness = registry.witness(*ordinal, signatures)?;
        for disprove in [false, true] {
            let code = registry.script(*ordinal, disprove)?;
            for (j, bad) in [
                vec![],
                witness[..witness.len() - 1].to_vec(),
                [vec![vec![]], witness.clone()].concat(),
                [witness.clone(), vec![vec![]]].concat(),
            ]
            .iter()
            .enumerate()
            {
                emit(
                    sink,
                    metrics,
                    &code,
                    bad,
                    false,
                    &format!("{label}/length/{ordinal}/{j}/{disprove}"),
                )?;
            }
            for position in [0, witness.len() - 1] {
                let mut bad = witness.clone();
                *bad[position]
                    .first_mut()
                    .ok_or("empty tail signature digit")? ^= 1;
                emit(
                    sink,
                    metrics,
                    &code,
                    &bad,
                    false,
                    &format!("{label}/forgery/{ordinal}/{position}/{disprove}"),
                )?;
            }
            let slot = registry.unique_slots(*ordinal)?[0];
            let mut substituted = signatures.to_vec();
            substituted[slot] = signatures[(slot + 1) % signatures.len()];
            emit(
                sink,
                metrics,
                &code,
                &registry.witness(*ordinal, &substituted)?,
                false,
                &format!("{label}/cross-wire/{ordinal}/{disprove}"),
            )?;
        }
    }
    Ok(14 * selected.len())
}
fn reject<T>(
    value: Result<T>,
    name: &'static str,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    if value.is_ok() {
        return Err(format!("negative accepted: {name}").into());
    }
    *counts.entry(name).or_default() += 1;
    Ok(())
}
fn extend_object(target: &mut Value, extra: Value) -> Result<()> {
    let (Value::Object(target), Value::Object(extra)) = (target, extra) else {
        return Err("internal summary object type".into());
    };
    for (key, value) in extra {
        if target.insert(key, value).is_some() {
            return Err("duplicate summary field".into());
        }
    }
    Ok(())
}
fn forest_negatives(
    forest: &TaprootForest,
    registry: &Registry,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    let manifest = forest.component_manifest_sha256();
    let root = forest.merkle_root();
    let key = forest.output_key();
    let component = forest.selected_component();
    let ordinal = forest.selected_ordinal();
    let script = forest.selected_script();
    let control = forest.control_block_bytes();
    let mut bad_script = script.as_bytes().to_vec();
    *bad_script.first_mut().ok_or("empty forest Script")? ^= 1;
    reject(
        forest.verify_opening(
            registry,
            manifest,
            root,
            key,
            component,
            ordinal,
            &ScriptBuf::from_bytes(bad_script),
            &control,
        ),
        "forest_altered_script",
        counts,
    )?;
    for (name, index, mask) in [
        ("forest_branch", 33, 1),
        ("forest_parity", 0, 1),
        ("forest_internal_key", 1, 1),
        ("forest_leaf_version", 0, 2),
    ] {
        let mut bad = control.clone();
        *bad.get_mut(index).ok_or("forest mutation length")? ^= mask;
        reject(
            forest.verify_opening(
                registry, manifest, root, key, component, ordinal, script, &bad,
            ),
            name,
            counts,
        )?;
    }
    reject(
        forest.verify_opening(
            registry,
            manifest,
            root,
            key,
            component,
            ordinal,
            script,
            &control[..control.len() - 1],
        ),
        "forest_truncated_control",
        counts,
    )?;
    let mut appended = control.clone();
    appended.push(0);
    reject(
        forest.verify_opening(
            registry, manifest, root, key, component, ordinal, script, &appended,
        ),
        "forest_appended_control",
        counts,
    )?;
    let mut wrong_manifest = manifest;
    wrong_manifest[0] ^= 1;
    reject(
        forest.verify_member(registry, wrong_manifest, root, key, component, ordinal),
        "forest_manifest",
        counts,
    )?;
    let mut wrong_root = root.to_byte_array();
    wrong_root[0] ^= 1;
    reject(
        forest.verify_member(
            registry,
            manifest,
            TapNodeHash::assume_hidden(wrong_root),
            key,
            component,
            ordinal,
        ),
        "forest_root",
        counts,
    )?;
    let other_key = XOnlyPublicKey::from_slice(&hex::decode(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )?)?;
    if other_key == key {
        return Err("alternate forest key equals actual key".into());
    }
    reject(
        forest.verify_member(registry, manifest, root, other_key, component, ordinal),
        "forest_output_key",
        counts,
    )?;
    reject(
        forest.verify_member(
            registry,
            manifest,
            root,
            key,
            (component + 1) % COMPONENTS,
            ordinal,
        ),
        "forest_component",
        counts,
    )?;
    reject(
        forest.verify_member(registry, manifest, root, key, component, usize::MAX),
        "forest_ordinal",
        counts,
    )?;
    Ok(())
}

fn validate_case(
    case: &Case,
    manifest: &Manifest,
    scenario: &Scenario,
    pair: &PairDescriptor,
) -> Result<()> {
    if case.name != format!("keccak/endpoint/{}/pair-{:02}", scenario.name, pair.index)
        || !case.measure_all
        || case.expected_spec_id != pair.catalogue_id
        || case.spec.program_sha256 != pair.program_sha256
        || case.spec.context != manifest.context
        || case.spec.field_role != manifest.role
        || case.spec.operation_id
            != format!("{}/permutation/pair/{}", manifest.operation_id, pair.index)
        || case.spec.words.len() != pair.words
        || case.spec.leaves.len() != pair.leaves
        || case.words.len() != pair.words
        || case.spec.words.iter().any(|word| word.bound != 2)
        || case.words.iter().any(|value| *value > 1)
        || case.checks.is_empty()
        || case.checks.len() > 128
        || case.checks.iter().any(|check| check.ordinal >= pair.leaves)
    {
        return Err("case differs from exact trusted pair/scenario descriptor".into());
    }
    if case.spec.identity()? != digest(&pair.catalogue_id)? {
        return Err("catalogue identity mismatch".into());
    }
    let ordinals: HashSet<_> = case.checks.iter().map(|check| check.ordinal).collect();
    if ordinals.len() != case.checks.len()
        || (pair.index == scenario.selected_pair && !ordinals.contains(&scenario.selected_leaf))
    {
        return Err("duplicate checks or missing actual selected Script execution".into());
    }
    // All decoder bounds are two; the versioned body hash also commits formal
    // alias expansion. Require an actually executed representative per shape.
    let shapes: HashSet<_> = case
        .spec
        .leaves
        .iter()
        .map(|leaf| leaf.body_sha256.as_str())
        .collect();
    let selected_shapes: HashSet<_> = case
        .checks
        .iter()
        .map(|check| case.spec.leaves[check.ordinal].body_sha256.as_str())
        .collect();
    if shapes != selected_shapes {
        return Err("case omits an authenticated predicate/alias shape".into());
    }
    Ok(())
}

fn scenario_run(
    manifest: &Manifest,
    scenario: &Scenario,
    root: &Path,
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    all_keys: &mut HashSet<[u8; 32]>,
    all_signatures: &mut HashSet<[u8; 32]>,
) -> Result<Value> {
    let topology = digest(&manifest.topology_sha256)?;
    let mut global = GlobalKeys::new(&topology, &scenario.name)?;
    let mut previous = Vec::new();
    let mut framing_cache = Vec::new();
    let mut components = Vec::with_capacity(COMPONENTS);
    let mut selected_registry = None;
    let mut selected_witness = Vec::new();
    let mut selected_correct = false;
    let mut ledger = Vec::new();
    let mut observed_false = Vec::new();
    let mut compiled = 0u64;
    let mut internal_links = 0;
    let mut inter_links = 0;
    let mut truth_checked = 0;
    let mut normal_checks = 0;
    let mut guard_vectors = 0;
    let started = Instant::now();
    for descriptor in &scenario.pairs {
        let path = case_path(root, scenario, descriptor)?;
        let raw = snapshot(&path, CASE_CAP, Some(descriptor.file_bytes))?;
        if sha256::Hash::hash(&raw).to_byte_array() != digest(&descriptor.file_sha256)? {
            return Err("case snapshot differs from externally authenticated manifest".into());
        }
        // Parse exactly the immutable bytes whose raw digest was checked.
        let case: Case = serde_json::from_slice(&raw)?;
        drop(raw);
        validate_case(&case, manifest, scenario, descriptor)?;
        let names: Vec<_> = case
            .spec
            .words
            .iter()
            .map(|word| global_name(descriptor.index, &word.name))
            .collect::<Result<_>>()?;
        if sha256::Hash::hash(&serde_json::to_vec(&names)?).to_byte_array()
            != digest(&descriptor.global_ids_sha256)?
        {
            return Err("normative local/global identity mapping digest mismatch".into());
        }
        for (label, expected) in [
            ("input", &descriptor.initial_state_hex),
            ("middle", &descriptor.middle_state_hex),
            ("output", &descriptor.output_state_hex),
        ] {
            if actual_state(&case.words, &slots(&case.spec, label)?)? != state(expected)? {
                return Err("actual signed state differs from descriptor".into());
            }
        }
        let false_start = observed_false.len();
        for ordinal in 0..case.spec.leaves.len() {
            if !truth(&case.spec, &case.words, ordinal)? {
                observed_false.push(FalsePredicate {
                    pair: descriptor.index,
                    ordinal,
                });
            }
            truth_checked += 1;
        }
        let expected_here: Vec<_> = scenario
            .expected_false
            .iter()
            .filter(|entry| entry.pair == descriptor.index)
            .collect();
        let actual_here: Vec<_> = observed_false[false_start..].iter().collect();
        if actual_here != expected_here {
            return Err(
                "actual pair truth differs from authenticated scenario before signing".into(),
            );
        }
        for check in &case.checks {
            if truth(&case.spec, &case.words, check.ordinal)? != check.expected_correct {
                return Err("selected check contradicts actual Boolean truth".into());
            }
        }
        let (keys, signatures) = global.assign(
            &case,
            &names,
            descriptor.index,
            &topology,
            &scenario.name,
            &previous,
            all_keys,
            all_signatures,
        )?;
        let registry_id = case.spec.key_identity(&keys)?;
        let registry = Registry::new(
            case.spec.clone(),
            keys.clone(),
            digest(&descriptor.catalogue_id)?,
            registry_id,
        )?;
        if descriptor.index == 0 {
            framing_cache = initial_framing_cache(
                &registry,
                &keys,
                &signatures,
                &case.words,
                &names,
                descriptor.first_child_leaves,
            )?;
        }
        let (inside, across, next) = boundary_links(
            &registry,
            &keys,
            &signatures,
            &case.words,
            &names,
            descriptor.first_child_leaves,
            &previous,
        )?;
        internal_links += inside;
        inter_links += across;
        previous = next;
        for check in &case.checks {
            let witness = registry.witness(check.ordinal, &signatures)?;
            for disprove in [false, true] {
                emit(
                    sink,
                    metrics,
                    &registry.script(check.ordinal, disprove)?,
                    &witness,
                    check.expected_correct != disprove,
                    &format!("{}/leaf/{}/{disprove}", case.name, check.ordinal),
                )?;
            }
            normal_checks += 1;
        }
        if descriptor.index == 0 {
            guard_vectors += guards(&registry, &signatures, sink, metrics, &case.name)?;
        }
        let selected = if descriptor.index == scenario.selected_pair {
            scenario.selected_leaf
        } else {
            case.checks[0].ordinal
        };
        let build_started = Instant::now();
        let tree = TaprootCommitment::new(&registry, selected)?;
        let build_seconds = build_started.elapsed().as_secs_f64();
        if tree.registry_id() != registry_id
            || tree.catalogue_id() != digest(&descriptor.catalogue_id)?
            || tree.leaf_count() != descriptor.leaves
        {
            return Err("live component source identity mismatch".into());
        }
        compiled = compiled
            .checked_add(tree.compiled_script_bytes())
            .ok_or("global Script bytes overflow")?;
        if compiled > GLOBAL_SCRIPT_CAP {
            return Err("global compiled Scripts exceed1.25GiB cap".into());
        }
        ledger.push(json!({"index":descriptor.index,"first_round":descriptor.first_round,
            "catalogue_id":descriptor.catalogue_id,"registry_id":hex::encode(registry_id),
            "words":descriptor.words,"leaves":descriptor.leaves,"selected_ordinal":selected,
            "compiled_script_bytes":tree.compiled_script_bytes(),
            "compiled_stream_sha256":hex::encode(tree.compiled_stream_sha256()),
            "merkle_root":tree.merkle_root().to_string(),"output_key":tree.output_key().to_string(),
            "control_block_bytes":tree.control_block_bytes().len(),"construction_seconds":build_seconds}));
        components.push(tree);
        if descriptor.index == scenario.selected_pair {
            selected_witness = registry.witness(selected, &signatures)?;
            selected_correct = truth(registry.spec(), &case.words, selected)?;
            selected_registry = Some(registry);
        }
        // case, keys, signatures and every nonselected Registry are released at
        // this pair boundary; keep the adjacent1600 and original832 fixed bits.
    }
    let mut endpoint_cache = framing_cache;
    endpoint_cache.extend(previous.into_iter().take(LO_BITS));
    let path = named_case_path(root, scenario, &scenario.tail.filename)?;
    let raw = snapshot(&path, CASE_CAP, Some(scenario.tail.file_bytes))?;
    if sha256::Hash::hash(&raw).to_byte_array() != digest(&scenario.tail.file_sha256)? {
        return Err("tail snapshot differs from externally authenticated manifest".into());
    }
    let tail: Case = serde_json::from_slice(&raw)?;
    drop(raw);
    let tail_names = validate_tail(&tail, manifest, scenario)?;
    let mut tail_checked = 0;
    for check in &tail.checks {
        let correct = tail_truth(&tail.spec, &tail.words, check.ordinal)?;
        if correct != check.expected_correct {
            return Err("tail check contradicts independent integer truth".into());
        }
        if !correct {
            observed_false.push(FalsePredicate {
                pair: PAIRS,
                ordinal: check.ordinal,
            });
        }
        tail_checked += 1;
    }
    let (tail_keys, tail_signatures) = global.assign(
        &tail,
        &tail_names,
        PAIRS,
        &topology,
        &scenario.name,
        &endpoint_cache,
        all_keys,
        all_signatures,
    )?;
    let tail_registry_id = tail.spec.key_identity(&tail_keys)?;
    let tail_registry = Registry::new(
        tail.spec.clone(),
        tail_keys.clone(),
        digest(&scenario.tail.catalogue_id)?,
        tail_registry_id,
    )?;
    let (frame_links, lo_links, byte_links, carry_links) = tail_links(
        &tail_registry,
        &tail_keys,
        &tail_signatures,
        &tail.words,
        &tail_names,
        &endpoint_cache,
    )?;
    let cache_rejections = endpoint_cache_negatives(
        &tail_registry,
        &tail_keys,
        &tail_signatures,
        &tail.words,
        &tail_names,
        &endpoint_cache,
    )?;
    for check in &tail.checks {
        let witness = tail_registry.witness(check.ordinal, &tail_signatures)?;
        for disprove in [false, true] {
            emit(
                sink,
                metrics,
                &tail_registry.script(check.ordinal, disprove)?,
                &witness,
                check.expected_correct != disprove,
                &format!("{}/leaf/{}/{disprove}", tail.name, check.ordinal),
            )?;
        }
        normal_checks += 1;
    }
    guard_vectors += tail_guards(&tail_registry, &tail_signatures, sink, metrics, &tail.name)?;
    let tail_selected = if scenario.selected_pair == PAIRS {
        scenario.selected_leaf
    } else {
        0
    };
    let build_started = Instant::now();
    let tail_tree = TaprootCommitment::new(&tail_registry, tail_selected)?;
    let build_seconds = build_started.elapsed().as_secs_f64();
    if tail_tree.registry_id() != tail_registry_id
        || tail_tree.catalogue_id() != digest(&scenario.tail.catalogue_id)?
        || tail_tree.leaf_count() != TAIL_LEAVES
    {
        return Err("live endpoint tail source identity mismatch".into());
    }
    compiled = compiled
        .checked_add(tail_tree.compiled_script_bytes())
        .ok_or("endpoint Script byte overflow")?;
    if compiled > GLOBAL_SCRIPT_CAP {
        return Err("endpoint compiled Scripts exceed unchanged1.25GiB cap".into());
    }
    ledger.push(json!({"index":PAIRS,"first_round":null,"catalogue_id":scenario.tail.catalogue_id,
        "registry_id":hex::encode(tail_registry_id),"words":TAIL_WORDS,"leaves":TAIL_LEAVES,"selected_ordinal":tail_selected,
        "compiled_script_bytes":tail_tree.compiled_script_bytes(),"compiled_stream_sha256":hex::encode(tail_tree.compiled_stream_sha256()),
        "merkle_root":tail_tree.merkle_root().to_string(),"output_key":tail_tree.output_key().to_string(),
        "control_block_bytes":tail_tree.control_block_bytes().len(),"construction_seconds":build_seconds}));
    components.push(tail_tree);
    if scenario.selected_pair == PAIRS {
        selected_witness = tail_registry.witness(tail_selected, &tail_signatures)?;
        selected_correct = tail_truth(tail_registry.spec(), &tail.words, tail_selected)?;
        selected_registry = Some(tail_registry);
    }
    if observed_false != scenario.expected_false
        || global.created != GLOBAL_WORDS
        || global.names.len() != GLOBAL_WORDS
        || global.reused != 18688
        || internal_links != 38400
        || inter_links != 35200
        || truth_checked != PERMUTATION_LEAVES
        || tail_checked != TAIL_LEAVES
        || frame_links != FRAME_BITS
        || lo_links != LO_BITS
        || byte_links != 128
        || carry_links != 64
    {
        return Err("full observed truth/signature/link census mismatch".into());
    }
    let selected_registry = selected_registry.ok_or("missing live selected Registry")?;
    let forest = TaprootForest::new(&components, scenario.selected_pair)?;
    let manifest_sha = forest.component_manifest_sha256();
    let global_root = forest.merkle_root();
    let output_key = forest.output_key();
    if forest.component_count() != COMPONENTS
        || forest.leaf_count() != LEAVES as u64
        || forest.compiled_script_bytes() != compiled
        || forest.selected_ordinal() != scenario.selected_leaf
    {
        return Err("forest does not cover the thirteen live endpoint component catalogues".into());
    }
    forest.verify_member(
        &selected_registry,
        manifest_sha,
        global_root,
        output_key,
        scenario.selected_pair,
        scenario.selected_leaf,
    )?;
    let selected_script = selected_registry.script(scenario.selected_leaf, true)?;
    if selected_script.as_bytes() != forest.selected_script().as_bytes() {
        return Err("global selected Script differs from actually executed local Script".into());
    }
    let (correctness_success, _) = bitvm2_nova_script_oracle::engine::execute(
        &selected_registry.script(scenario.selected_leaf, false)?,
        selected_witness.clone(),
    )?;
    let (disproof_success, _) =
        bitvm2_nova_script_oracle::engine::execute(&selected_script, selected_witness)?;
    if correctness_success != selected_correct || disproof_success == selected_correct {
        return Err("global selected execution contradicts relation truth".into());
    }
    let mut negatives = BTreeMap::new();
    forest_negatives(&forest, &selected_registry, &mut negatives)?;
    components.swap(0, 1);
    let reordered = TaprootForest::new(&components, scenario.selected_pair)?;
    if reordered.component_manifest_sha256() == manifest_sha {
        return Err("component order missing from manifest identity".into());
    }
    reject(
        reordered.verify_member(
            &selected_registry,
            manifest_sha,
            global_root,
            output_key,
            scenario.selected_pair,
            scenario.selected_leaf,
        ),
        "forest_reordered_components",
        &mut negatives,
    )?;
    let mut summary = json!({"name":scenario.name,"components":COMPONENTS,"unique_global_words":global.created,
        "signature_entries_created":global.created,"cached_signature_reuses":global.reused,
        "internal_boundary_words":19200,"internal_boundary_signature_links":internal_links,
        "inter_boundary_words":17600,"inter_boundary_signature_links":inter_links,
        "all_boolean_predicates_checked":truth_checked,"compiled_script_bytes":compiled,
        "tail_predicates_checked":tail_checked,"tail_leaf_checks":tail_checked,
        "endpoint_framing_cached_entries":FRAME_BITS,"endpoint_lo_cached_entries":LO_BITS,
        "endpoint_framing_opening_links":frame_links,"endpoint_lo_opening_links":lo_links,
        "endpoint_byte_opening_links":byte_links,"endpoint_carry_opening_links":carry_links,
        "endpoint_source_cache_rejections":cache_rejections,"tail_guarded_layouts":13,
        "false_predicates":observed_false.iter().map(|p| json!({"pair":p.pair,"ordinal":p.ordinal})).collect::<Vec<_>>(),
        "key_catalogue_sha256":sha256::Hash::from_engine(global.keys_hash).to_string(),
        "signature_catalogue_sha256":sha256::Hash::from_engine(global.signatures_hash).to_string(),
        "local_ledger":ledger});
    extend_object(
        &mut summary,
        json!({"normal_leaf_checks":normal_checks,"guard_vectors":guard_vectors,
        "selected_component":scenario.selected_pair,"selected_leaf":scenario.selected_leaf,
        "global_control_bytes":forest.control_block_bytes().len(),
        "global_control_sha256":sha256::Hash::hash(&forest.control_block_bytes()).to_string(),
        "global_root":global_root.to_string(),"global_output_key":output_key.to_string(),
        "component_manifest_sha256":hex::encode(manifest_sha),"forest_negative_counts":negatives}),
    )?;
    extend_object(
        &mut summary,
        json!({
        "selected_correctness_execution_success":correctness_success,
        "selected_disproof_execution_success":disproof_success,"hierarchical_membership_verified":true,
        "additional_selected_engine_executions":2,
        "reordered_component_root_equal":reordered.merkle_root()==global_root,
        "roots_independently_pinned":false,"wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    Ok(summary)
}

fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: keccak_endpoint MANIFEST CASE_DIR OUTPUT EXPECTED_MANIFEST_SHA256".into(),
        );
    }
    if !matches!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"))
        || !matches!(std::env::var("RUNNER_OS").as_deref(), Ok("Linux"))
        || !cfg!(target_os = "linux")
    {
        return Err("framed Keccak endpoint construction is hosted GitHub Linux only".into());
    }
    let started = Instant::now();
    let expected_manifest = digest(&args[4])?;
    let raw = snapshot(Path::new(&args[1]), MANIFEST_CAP, None)?;
    if sha256::Hash::hash(&raw).to_byte_array() != expected_manifest {
        return Err("external raw manifest digest mismatch before parse".into());
    }
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_manifest(&manifest)?;
    let source = Path::new(&args[2]);
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        return Err("case root symlink forbidden".into());
    }
    let root = fs::canonicalize(source)?;
    if !root.is_dir() {
        return Err("case root must be a directory".into());
    }
    for scenario in &manifest.scenarios {
        let directory = root.join(&scenario.name);
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::canonicalize(&directory)? != directory
        {
            return Err("scenario directory alias forbidden before inventory".into());
        }
        let mut expected: HashSet<_> = (0..PAIRS).map(|i| format!("pair-{i:02}.json")).collect();
        expected.insert("tail.json".into());
        let observed: HashSet<_> = fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<std::io::Result<_>>()?;
        if observed != expected {
            return Err(
                "endpoint scenario directory must contain exactly thirteen case files".into(),
            );
        }
    }
    let mut sink = VectorSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut metrics = Metrics::default();
    let mut all_keys = HashSet::with_capacity(GLOBAL_WORDS * manifest.scenarios.len());
    let mut all_signatures = HashSet::with_capacity(GLOBAL_WORDS * manifest.scenarios.len());
    let mut scenarios = Vec::new();
    for scenario in &manifest.scenarios {
        scenarios.push(scenario_run(
            &manifest,
            scenario,
            &root,
            &mut sink,
            &mut metrics,
            &mut all_keys,
            &mut all_signatures,
        )?);
    }
    let mut result = json!({"schema":"bitvm2-nova-keccak-endpoint-execution/v1","passed":true,
        "topology_sha256":manifest.topology_sha256,"manifest_sha256":hex::encode(expected_manifest),
        "scenarios":scenarios,"metrics":metrics,"selected_vectors_hashed_bytes":sink.bytes,
        "selected_vectors_sha256":sha256::Hash::from_engine(sink.hash).to_string(),
        "raw_vector_file_written":false,"graph_compiled":true,"reference_conformance_checked":true,
        "hierarchical_membership_verified":true});
    extend_object(
        &mut result,
        json!({"full_permutation_verified":false,
        "full_hash_verified":false,"keccak256_verified":false,"nova_transcript_verified_in_script":false,
        "lo_keccak_endpoint_script_bound":true,"framing_constants_script_bound":true,
        "hi_keccak_endpoint_script_bound":false,"eval_w_canonicality_script_bound":false,
        "dynamic_message_sources_script_bound":false,"complete_keccak_sponge":false,
        "proof_verified":false,"complete_bitvm2_verifier":false,"production_assertion_binding":false,
        "bitcoin_transaction_graph":false,"production_transactions_verified":false,
        "transactions_broadcast":0,"native_proofs_verified":0,"proving_jobs":0,
        "test_keys_only":true,"wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    let encoded = serde_json::to_vec(&result)?;
    if encoded.len() > SUMMARY_CAP {
        return Err("full-Keccak summary exceeds1MiB".into());
    }
    fs::write(&args[3], encoded)?;
    Ok(result)
}
fn main() -> Result<()> {
    println!("{}", run()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_global_names_bind_round_state_lane_and_bit_without_aliases() {
        assert_eq!(
            global_name(0, "boundary/input/l0/b0").unwrap(),
            "state/0/l0/b0"
        );
        assert_eq!(
            global_name(11, "boundary/output/l24/b63").unwrap(),
            "state/24/l24/b63"
        );
        assert_eq!(
            global_name(4, "child/1/keccak/r9/chi/n/0/0").unwrap(),
            "round/9/keccak/r9/chi/n/0/0"
        );
        for value in [
            "boundary/input/l00/b0",
            "boundary/input/l25/b0",
            "boundary/input/l0/b64",
            "boundary/input/l0/b00",
            "child/2/keccak/r0/zero",
            "child/1/keccak/r0/zero",
            "state/0/l0/b0",
        ] {
            assert!(global_name(0, value).is_err());
        }
        assert!(global_name(12, "boundary/input/l0/b0").is_err());
    }
    #[test]
    fn public_round_constants_independently_reproduce_full_bounded_census() {
        let leaves: usize = (0..24).map(round_leaves).sum();
        assert_eq!(leaves, PERMUTATION_LEAVES);
        assert_eq!(leaves + STATE_BITS * PAIRS, LOCAL_WORDS);
        assert_eq!(
            LOCAL_WORDS - STATE_BITS * (PAIRS - 1) + TAIL_WORDS - FRAME_BITS - LO_BITS,
            GLOBAL_WORDS
        );
        assert_eq!(PERMUTATION_LEAVES + TAIL_LEAVES, LEAVES);
        assert_eq!(round_leaves(0), 9602);
        assert_eq!(round_leaves(1), 9604);
    }
    #[test]
    fn state_hex_and_framed_test_seed_reject_ambiguous_transport() {
        assert!(state(&"00".repeat(200)).is_ok());
        assert!(state(&"AA".repeat(200)).is_err());
        assert!(state(&"00".repeat(199)).is_err());
        let topology = [7; 32];
        assert_ne!(
            seed(&topology, "a", "bc").unwrap(),
            seed(&topology, "ab", "c").unwrap()
        );
        assert_ne!(
            seed(&topology, "honest", "state/0/l0/b0").unwrap(),
            seed(&topology, "coherent-output", "state/0/l0/b0").unwrap()
        );
    }
    #[test]
    fn fixed_frame_mask_excludes_dynamic_bytes_and_pins_the_padding_bit() {
        let bits = framing_bits();
        assert_eq!(bits.len(), 832);
        assert_eq!(
            bits.iter()
                .map(|(b, k, _)| (*b, *k))
                .collect::<HashSet<_>>()
                .len(),
            832
        );
        assert!(!bits
            .iter()
            .any(|(b, _, _)| (1..33).contains(b) || (45..109).contains(b)));
        assert_eq!(bits[120], (111, 0, 1));
        assert_eq!(372 + 120, 492);
        for (byte, bit, value) in bits {
            if (136..200).contains(&byte) {
                assert_eq!(value, 0);
            }
            if byte == 135 {
                assert_eq!(value, u32::from(bit == 7));
            }
        }
    }
    #[test]
    fn endpoint_aliases_share_only_lo_and_fixed_input_bits() {
        let empty = GraphSpec {
            program_sha256: "00".repeat(32),
            context: "00".repeat(32),
            field_role: "pallas_scalar".into(),
            operation_id: "test".into(),
            words: vec![],
            leaves: vec![],
            bodies: BTreeMap::new(),
        };
        let mut spec = empty.clone();
        spec.words = [
            "digest/lo/l3/b63",
            "digest/hi/l3/b63",
            "frame/byte/111/bit/0",
            "input/byte/0",
        ]
        .iter()
        .map(|n| bitvm2_nova_script_oracle::registry::Word {
            name: (*n).into(),
            bound: 2,
        })
        .collect();
        assert_eq!(
            tail_global_names(&spec).unwrap(),
            [
                "state/24/l3/b63",
                "tail/digest/hi/l3/b63",
                "state/0/l13/b56",
                "tail/input/byte/0"
            ]
        );
        for name in [
            "digest/lo/l4/b0",
            "digest/lo/l00/b0",
            "frame/byte/111/bit/8",
            "frame/byte/0111/bit/0",
        ] {
            spec.words[0].name = name.into();
            assert!(tail_global_names(&spec).is_err());
        }
    }
}
