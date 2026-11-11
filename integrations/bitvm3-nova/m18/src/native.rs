//! The native reference of M18: block parsing and txid hashing, header and Merkle checks, and
//! the windowed UTXO map (an indexed Merkle tree of depth D over Poseidon) with membership and
//! non-membership proofs and balance queries. The circuit enforces exactly what `check` does.

use crate::elem::{f_from_le, f_to_le, fu, hash, low248, lt, F};
use ff::Field;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const D: usize = 20;

/// The script-fingerprint challenge used when a map is built without a window (unit tests).
pub const DEFAULT_RS: u64 = 0x5eed_0001;

pub fn sha256d(b: &[u8]) -> [u8; 32] {
  Sha256::digest(Sha256::digest(b)).into()
}

// ---------------------------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------------------------

pub struct In {
  pub prev_txid: [u8; 32], // internal byte order
  pub vout: u32,
}

pub struct Out {
  pub value: u64,
  pub script: Vec<u8>,
}

pub struct Tx {
  pub nonwit: Vec<u8>,
  pub txid: [u8; 32], // internal byte order (SHA-256d output)
  pub inputs: Vec<In>,
  pub outputs: Vec<Out>,
}

pub struct Block {
  pub header: [u8; 80],
  pub txs: Vec<Tx>,
}

struct Rd<'a> {
  b: &'a [u8],
  p: usize,
}

impl<'a> Rd<'a> {
  fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
    if self.p + n > self.b.len() {
      return Err(format!("read past end at {} (+{n})", self.p));
    }
    let s = &self.b[self.p..self.p + n];
    self.p += n;
    Ok(s)
  }
  fn u32(&mut self) -> Result<u32, String> {
    Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
  }
  fn u64(&mut self) -> Result<u64, String> {
    Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
  }
  fn varint(&mut self) -> Result<u64, String> {
    let t = self.take(1)?[0];
    Ok(match t {
      0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64,
      0xfe => self.u32()? as u64,
      0xff => self.u64()?,
      n => n as u64,
    })
  }
}

fn parse_tx(r: &mut Rd) -> Result<Tx, String> {
  let version = r.take(4)?;
  let segwit = r.b.get(r.p) == Some(&0) && r.b.get(r.p + 1) == Some(&1);
  if segwit {
    r.take(2)?;
  }
  let body = r.p;
  let nin = r.varint()?;
  let mut inputs = vec![];
  for _ in 0..nin {
    let prev: [u8; 32] = r.take(32)?.try_into().unwrap();
    let vout = r.u32()?;
    let sl = r.varint()? as usize;
    r.take(sl)?;
    r.take(4)?;
    inputs.push(In { prev_txid: prev, vout });
  }
  let nout = r.varint()?;
  let mut outputs = vec![];
  for _ in 0..nout {
    let value = r.u64()?;
    let sl = r.varint()? as usize;
    outputs.push(Out { value, script: r.take(sl)?.to_vec() });
  }
  let body_end = r.p;
  if segwit {
    for _ in 0..nin {
      let items = r.varint()?;
      for _ in 0..items {
        let l = r.varint()? as usize;
        r.take(l)?;
      }
    }
  }
  let lock = r.take(4)?;
  let mut nonwit = Vec::with_capacity(8 + body_end - body);
  nonwit.extend_from_slice(version);
  nonwit.extend_from_slice(&r.b[body..body_end]);
  nonwit.extend_from_slice(lock);
  let txid = sha256d(&nonwit);
  Ok(Tx { nonwit, txid, inputs, outputs })
}

pub fn parse_block(raw: &[u8]) -> Result<Block, String> {
  let mut r = Rd { b: raw, p: 0 };
  let header: [u8; 80] = r.take(80)?.try_into().unwrap();
  let n = r.varint()?;
  let mut txs = Vec::with_capacity(n as usize);
  for _ in 0..n {
    txs.push(parse_tx(&mut r)?);
  }
  if r.p != raw.len() {
    return Err(format!("{} trailing bytes", raw.len() - r.p));
  }
  Ok(Block { header, txs })
}

/// Merkle root with odd-node duplication, and the number of SHA-256d merges.
pub fn merkle_root(txids: &[[u8; 32]]) -> ([u8; 32], u64) {
  let mut layer = txids.to_vec();
  let mut merges = 0;
  while layer.len() > 1 {
    if layer.len() % 2 == 1 {
      layer.push(*layer.last().unwrap());
    }
    let mut next = Vec::with_capacity(layer.len() / 2);
    for p in layer.chunks(2) {
      let mut b = [0u8; 64];
      b[..32].copy_from_slice(&p[0]);
      b[32..].copy_from_slice(&p[1]);
      next.push(sha256d(&b));
      merges += 1;
    }
    layer = next;
  }
  (layer[0], merges)
}

/// SHA-256 blocks of the padded message.
pub fn padded_blocks(len: usize) -> u64 {
  ((len + 9 + 63) / 64) as u64
}

// ---------------------------------------------------------------------------------------------
// The map
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
  pub key: F,
  pub next_key: F, // 0 for the last leaf (no successor)
  pub next_index: u64,
  pub value: u64,
  pub script_fp: F,
  pub spent: bool,
}

impl Leaf {
  pub fn hash(&self) -> F {
    hash(&[self.key, self.next_key, fu(self.next_index), fu(self.value), self.script_fp, fu(self.spent as u64)])
  }
}

/// key = low 248 bits of Poseidon(txid_lo, txid_hi, vout); txid in internal byte order.
pub fn outpoint_key(txid: &[u8; 32], vout: u32) -> F {
  low248(&hash(&[f_from_le(&txid[..16]), f_from_le(&txid[16..]), fu(vout as u64)]))
}

/// Horner evaluation at `r_s` of (script length, byte 0, byte 1, ...), starting from 0.
pub fn script_fp(script: &[u8], r_s: F) -> F {
  let mut f = fu(script.len() as u64);
  for b in script {
    f = f * r_s + fu(*b as u64);
  }
  f
}

/// The two 16-byte little-endian limbs of an internal-order hash.
pub fn limbs(h: &[u8; 32]) -> [F; 2] {
  [f_from_le(&h[..16]), f_from_le(&h[16..])]
}

/// `r_s = Poseidon(1, hash(H-1)_lo, hash(H-1)_hi, hash(T)_lo, hash(T)_hi)`, hashes in internal
/// byte order.
pub fn derive_r_s(h0: &[u8; 32], ht: &[u8; 32]) -> F {
  let (a, b) = (limbs(h0), limbs(ht));
  hash(&[fu(1), a[0], a[1], b[0], b[1]])
}

#[derive(Clone, Debug)]
pub struct Path {
  pub index: u64,
  pub siblings: Vec<F>, // D entries, leaf level first
}

pub fn root_of(leaf_hash: F, path: &Path) -> F {
  let mut h = leaf_hash;
  let mut i = path.index;
  for s in &path.siblings {
    h = if i & 1 == 0 { hash(&[h, *s]) } else { hash(&[*s, h]) };
    i >>= 1;
  }
  h
}

#[derive(Clone, Debug)]
pub struct Proof {
  pub leaf: Leaf,
  pub path: Path,
}

/// A leaf with `key` is in the tree under `root`.
/// The index must be below 2^D: `root_of` reads only its low D bits, so a larger index would
/// name the same leaf twice.
pub fn verify_membership(root: &F, key: &F, p: &Proof) -> bool {
  p.path.siblings.len() == D && p.path.index < 1 << D && p.leaf.key == *key && root_of(p.leaf.hash(), &p.path) == *root
}

/// No leaf with `key` is in the tree under `root`: the proven leaf is the key's predecessor.
pub fn verify_nonmembership(root: &F, key: &F, p: &Proof) -> bool {
  p.path.siblings.len() == D
    && p.path.index < 1 << D
    && root_of(p.leaf.hash(), &p.path) == *root
    && lt(&p.leaf.key, key)
    && (p.leaf.next_key == F::ZERO || lt(key, &p.leaf.next_key))
}

#[derive(Debug, PartialEq, Eq)]
pub enum MapError {
  Duplicate,
  DoubleSpend,
  NotFound,
  InMap,
  BadProof,
  Full,
}

pub struct CreateProof {
  pub key: F,
  pub low: Proof,
  pub low_updated: Leaf,
  pub new_leaf: Leaf,
  pub append: Path, // siblings of the new slot after the low update
  pub root_before: F,
  pub root_mid: F,
  pub root_after: F,
}

impl CreateProof {
  /// What the circuit enforces. Returns the new root.
  pub fn check(&self, root_before: &F) -> Result<F, MapError> {
    if self.root_before != *root_before || !verify_nonmembership(root_before, &self.key, &self.low) {
      return Err(MapError::BadProof);
    }
    let l = &self.low.leaf;
    let u = &self.low_updated;
    let n = &self.new_leaf;
    let ok = u.key == l.key
      && u.value == l.value
      && u.script_fp == l.script_fp
      && u.spent == l.spent
      && u.next_key == self.key
      && u.next_index == self.append.index
      && n.key == self.key
      && n.next_key == l.next_key
      && n.next_index == l.next_index
      && !n.spent;
    if !ok {
      return Err(MapError::BadProof);
    }
    let mid = root_of(u.hash(), &self.low.path);
    if mid != self.root_mid || root_of(F::ZERO, &self.append) != mid {
      return Err(MapError::BadProof);
    }
    let after = root_of(n.hash(), &self.append);
    if after != self.root_after {
      return Err(MapError::BadProof);
    }
    Ok(after)
  }
}

pub struct SpendProof {
  pub key: F,
  pub proof: Proof,
  pub spent_leaf: Leaf,
  pub root_before: F,
  pub root_after: F,
}

impl SpendProof {
  pub fn check(&self, root_before: &F) -> Result<F, MapError> {
    let p = &self.proof;
    if self.root_before != *root_before || !verify_membership(root_before, &self.key, p) {
      return Err(MapError::BadProof);
    }
    if p.leaf.spent {
      return Err(MapError::DoubleSpend);
    }
    let mut want = p.leaf.clone();
    want.spent = true;
    if self.spent_leaf != want {
      return Err(MapError::BadProof);
    }
    let after = root_of(self.spent_leaf.hash(), &p.path);
    if after != self.root_after {
      return Err(MapError::BadProof);
    }
    Ok(after)
  }
}

pub enum SpendOutcome {
  InWindow(SpendProof),
  BeforeWindow { key: F, proof: Proof, root: F },
}

#[derive(Debug)]
pub struct BalanceEntry {
  pub txid: [u8; 32],
  pub vout: u32,
  pub proof: Proof,
}

#[derive(Debug)]
pub struct Balance {
  pub root: F,
  pub entries: Vec<BalanceEntry>,
  pub unspent_sum: u64,
}

pub struct UtxoMap {
  leaves: Vec<Leaf>,
  nodes: Vec<HashMap<u64, F>>, // level 0 = leaf hashes
  empty: Vec<F>,
  by_key: BTreeMap<[u8; 32], u64>, // key, big-endian bytes -> leaf index
  by_script: HashMap<[u8; 32], Vec<u64>>,
  outpoints: Vec<([u8; 32], u32)>, // per leaf index (sentinel: zeros)
  r_s: F,
}

fn be(k: &F) -> [u8; 32] {
  let mut b = f_to_le(k);
  b.reverse();
  b
}

impl Default for UtxoMap {
  fn default() -> Self {
    Self::new()
  }
}

impl UtxoMap {
  pub fn new() -> Self {
    Self::with_rs(fu(DEFAULT_RS))
  }

  pub fn with_rs(r_s: F) -> Self {
    let mut empty = vec![F::ZERO];
    for l in 0..D {
      empty.push(hash(&[empty[l], empty[l]]));
    }
    let mut m = UtxoMap {
      leaves: vec![],
      nodes: (0..=D).map(|_| HashMap::new()).collect(),
      empty,
      by_key: BTreeMap::new(),
      by_script: HashMap::new(),
      outpoints: vec![],
      r_s,
    };
    // Sentinel: key 0, no successor. No real key is 0 (its probability is 2^-248).
    let s = Leaf { key: F::ZERO, next_key: F::ZERO, next_index: 0, value: 0, script_fp: F::ZERO, spent: false };
    m.set_leaf(0, s);
    m.by_key.insert(be(&F::ZERO), 0);
    m.outpoints.push(([0; 32], 0));
    m
  }

  pub fn root(&self) -> F {
    self.node(D, 0)
  }

  pub fn len(&self) -> usize {
    self.leaves.len()
  }

  pub fn is_empty(&self) -> bool {
    false
  }

  fn node(&self, level: usize, i: u64) -> F {
    self.nodes[level].get(&i).copied().unwrap_or(self.empty[level])
  }

  pub fn path(&self, index: u64) -> Path {
    let mut siblings = Vec::with_capacity(D);
    let mut i = index;
    for l in 0..D {
      siblings.push(self.node(l, i ^ 1));
      i >>= 1;
    }
    Path { index, siblings }
  }

  fn set_leaf(&mut self, index: u64, leaf: Leaf) {
    let mut h = leaf.hash();
    if index as usize == self.leaves.len() {
      self.leaves.push(leaf);
    } else {
      self.leaves[index as usize] = leaf;
    }
    let mut i = index;
    self.nodes[0].insert(i, h);
    for l in 0..D {
      let sib = self.node(l, i ^ 1);
      h = if i & 1 == 0 { hash(&[h, sib]) } else { hash(&[sib, h]) };
      i >>= 1;
      self.nodes[l + 1].insert(i, h);
    }
  }

  pub fn leaf(&self, index: u64) -> &Leaf {
    &self.leaves[index as usize]
  }

  pub fn contains(&self, txid: &[u8; 32], vout: u32) -> bool {
    self.by_key.contains_key(&be(&outpoint_key(txid, vout)))
  }

  pub fn membership(&self, txid: &[u8; 32], vout: u32) -> Option<Proof> {
    let idx = *self.by_key.get(&be(&outpoint_key(txid, vout)))?;
    Some(Proof { leaf: self.leaves[idx as usize].clone(), path: self.path(idx) })
  }

  /// Non-membership proof: the predecessor leaf of the key. Refused when the key is in the map.
  pub fn nonmembership(&self, txid: &[u8; 32], vout: u32) -> Result<Proof, MapError> {
    let key = outpoint_key(txid, vout);
    let kb = be(&key);
    if self.by_key.contains_key(&kb) {
      return Err(MapError::InMap);
    }
    let (_, &idx) = self.by_key.range(..kb).next_back().expect("sentinel precedes every key");
    Ok(Proof { leaf: self.leaves[idx as usize].clone(), path: self.path(idx) })
  }

  /// Creates an output: non-membership of its key, low-leaf update, append.
  pub fn create(&mut self, txid: &[u8; 32], vout: u32, value: u64, script: &[u8]) -> Result<CreateProof, MapError> {
    let key = outpoint_key(txid, vout);
    let low = self.nonmembership(txid, vout).map_err(|_| MapError::Duplicate)?;
    let new_idx = self.leaves.len() as u64;
    if new_idx >= 1u64 << D {
      return Err(MapError::Full);
    }
    let root_before = self.root();
    let sh = script_fp(script, self.r_s);
    let mut low_updated = low.leaf.clone();
    low_updated.next_key = key;
    low_updated.next_index = new_idx;
    self.set_leaf(low.path.index, low_updated.clone());
    let root_mid = self.root();
    let append = self.path(new_idx);
    let new_leaf =
      Leaf { key, next_key: low.leaf.next_key, next_index: low.leaf.next_index, value, script_fp: sh, spent: false };
    self.set_leaf(new_idx, new_leaf.clone());
    self.by_key.insert(be(&key), new_idx);
    self.by_script.entry(f_to_le(&sh)).or_default().push(new_idx);
    self.outpoints.push((*txid, vout));
    Ok(CreateProof { key, low, low_updated, new_leaf, append, root_before, root_mid, root_after: self.root() })
  }

  /// Spends an output created in the window. Refuses a spent output and an absent one.
  pub fn spend_in_window(&mut self, txid: &[u8; 32], vout: u32) -> Result<SpendProof, MapError> {
    let key = outpoint_key(txid, vout);
    let proof = self.membership(txid, vout).ok_or(MapError::NotFound)?;
    if proof.leaf.spent {
      return Err(MapError::DoubleSpend);
    }
    let root_before = self.root();
    let mut spent_leaf = proof.leaf.clone();
    spent_leaf.spent = true;
    self.set_leaf(proof.path.index, spent_leaf.clone());
    Ok(SpendProof { key, proof, spent_leaf, root_before, root_after: self.root() })
  }

  /// Claims an input spends an output created before the window: the proof is non-membership.
  /// Refused when the output is in the map (spent or not).
  pub fn spend_before_window(&self, txid: &[u8; 32], vout: u32) -> Result<(F, Proof), MapError> {
    let proof = self.nonmembership(txid, vout)?;
    Ok((outpoint_key(txid, vout), proof))
  }

  /// One input: in-window when the outpoint is in the map, otherwise before the window.
  pub fn spend(&mut self, txid: &[u8; 32], vout: u32) -> Result<SpendOutcome, MapError> {
    if self.contains(txid, vout) {
      self.spend_in_window(txid, vout).map(SpendOutcome::InWindow)
    } else {
      let (key, proof) = self.spend_before_window(txid, vout)?;
      Ok(SpendOutcome::BeforeWindow { key, proof, root: self.root() })
    }
  }

  fn entry(&self, idx: u64) -> BalanceEntry {
    let (txid, vout) = self.outpoints[idx as usize];
    BalanceEntry { txid, vout, proof: Proof { leaf: self.leaves[idx as usize].clone(), path: self.path(idx) } }
  }

  /// Balance of a list of outpoints: a membership proof per outpoint, and the sum of the
  /// unspent ones. An outpoint outside the map is an error.
  pub fn balance_of_outpoints(&self, ops: &[([u8; 32], u32)]) -> Result<Balance, MapError> {
    let mut entries = vec![];
    for (t, v) in ops {
      let idx = *self.by_key.get(&be(&outpoint_key(t, *v))).ok_or(MapError::NotFound)?;
      entries.push(self.entry(idx));
    }
    let unspent_sum = entries.iter().filter(|e| !e.proof.leaf.spent).map(|e| e.proof.leaf.value).sum();
    Ok(Balance { root: self.root(), entries, unspent_sum })
  }

  /// Balance of a script: every map entry paying it (spent ones included, with their flag) and
  /// the sum of the unspent ones.
  pub fn balance_of_script(&self, script: &[u8]) -> Balance {
    let sh = script_fp(script, self.r_s);
    let idxs = self.by_script.get(&f_to_le(&sh)).cloned().unwrap_or_default();
    let entries: Vec<BalanceEntry> = idxs.iter().map(|&i| self.entry(i)).collect();
    let unspent_sum = entries.iter().filter(|e| !e.proof.leaf.spent).map(|e| e.proof.leaf.value).sum();
    Balance { root: self.root(), entries, unspent_sum }
  }
}

/// Checks a balance against a root; returns the unspent sum. `script`, when given, must match
/// every entry's fingerprint. Duplicate entries are refused. The script match here is by
/// `script_fp` alone, which is linear in the script bytes: it binds a script fixed before `r_s`
/// was known (the verifier's own address), not one a prover picks after seeing `r_s`. A claim
/// whose script comes from the prover goes through [`verify_output`].
pub fn verify_balance(root: &F, r_s: &F, b: &Balance, script: Option<&[u8]>) -> Result<u64, MapError> {
  let sh = script.map(|s| script_fp(s, *r_s));
  let mut seen = std::collections::HashSet::new();
  let mut sum = 0u64;
  for e in &b.entries {
    let key = outpoint_key(&e.txid, e.vout);
    if !verify_membership(root, &key, &e.proof) || !seen.insert(be(&key)) {
      return Err(MapError::BadProof);
    }
    if let Some(s) = sh {
      if e.proof.leaf.script_fp != s {
        return Err(MapError::BadProof);
      }
    }
    if !e.proof.leaf.spent {
      sum = sum.checked_add(e.proof.leaf.value).ok_or(MapError::BadProof)?;
    }
  }
  Ok(sum)
}

/// A transaction from its non-witness serialization; refuses anything else (a witness
/// serialization, trailing bytes, the 64-byte length the circuit refuses).
pub fn parse_nonwit_tx(b: &[u8]) -> Result<Tx, String> {
  if b.len() == 64 {
    return Err("64-byte transaction".into());
  }
  let mut r = Rd { b, p: 0 };
  let tx = parse_tx(&mut r)?;
  if r.p != b.len() || tx.nonwit != b {
    return Err("not a non-witness transaction serialization".into());
  }
  Ok(tx)
}

/// An output claim: output `vout` of the transaction `tx_nonwit` is in the map under `root`.
/// The script and value come from the transaction, bound to the leaf by its txid (SHA-256d), and
/// the leaf's value and fingerprint must agree with them. Returns (value, script, spent).
pub fn verify_output(root: &F, r_s: &F, tx_nonwit: &[u8], vout: u32, p: &Proof) -> Result<(u64, Vec<u8>, bool), String> {
  let tx = parse_nonwit_tx(tx_nonwit)?;
  let out = tx.outputs.get(vout as usize).ok_or("no such output")?;
  if !verify_membership(root, &outpoint_key(&tx.txid, vout), p) {
    return Err("membership proof does not verify".into());
  }
  if p.leaf.value != out.value || p.leaf.script_fp != script_fp(&out.script, *r_s) {
    return Err("leaf value or script fingerprint differs from the transaction".into());
  }
  Ok((out.value, out.script.clone(), p.leaf.spent))
}

// ---------------------------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Default, Debug)]
pub struct BlockStats {
  pub height: u64,
  pub hash: String,
  pub raw_bytes: usize,
  pub transactions: u64,
  pub nonwitness_bytes: u64,
  pub sha256_blocks_txs: u64,        // padded blocks of the first SHA-256 pass over each transaction
  pub sha256_blocks_txid_final: u64, // the second pass: one block per transaction
  pub inputs: u64,                   // all inputs, the coinbase input included
  pub outputs: u64,
  pub creates: u64,
  pub spends_in_window: u64,
  pub spends_before_window: u64,
  pub merkle_merges: u64,
  pub sha256_blocks_merkle: u64, // 3 compressions per merge
  pub sha256_blocks_header: u64, // 3 compressions for SHA-256d of 80 bytes
  pub absorb_steps_c1: u64, // sum over transactions of ceil(padded blocks / c)
  pub absorb_steps_c4: u64,
  pub absorb_steps_c8: u64,
  pub seconds: f64,
}

pub struct Window {
  pub map: UtxoMap,
  pub prev_hash: [u8; 32],
  pub verify: bool,
}

pub fn display_hex(h: &[u8; 32]) -> String {
  let mut r = *h;
  r.reverse();
  hex::encode(r)
}

impl Window {
  pub fn new(prev_hash: [u8; 32], r_s: F, verify: bool) -> Self {
    Window { map: UtxoMap::with_rs(r_s), prev_hash, verify }
  }

  /// One block: header link, Merkle root, then the events in serialization order.
  pub fn process_block(&mut self, height: u64, raw: &[u8]) -> Result<BlockStats, String> {
    let t = std::time::Instant::now();
    let b = parse_block(raw)?;
    if b.header[4..36] != self.prev_hash {
      return Err(format!("block {height}: header does not link to the previous hash"));
    }
    let txids: Vec<[u8; 32]> = b.txs.iter().map(|t| t.txid).collect();
    let (root, merges) = merkle_root(&txids);
    if root[..] != b.header[36..68] {
      return Err(format!("block {height}: Merkle root mismatch"));
    }
    let hdr = sha256d(&b.header);
    let mut st = BlockStats {
      height,
      hash: display_hex(&hdr),
      raw_bytes: raw.len(),
      transactions: b.txs.len() as u64,
      merkle_merges: merges,
      sha256_blocks_merkle: 3 * merges,
      sha256_blocks_header: 3,
      ..Default::default()
    };
    for (ti, tx) in b.txs.iter().enumerate() {
      st.nonwitness_bytes += tx.nonwit.len() as u64;
      let pb = padded_blocks(tx.nonwit.len());
      st.sha256_blocks_txs += pb;
      st.absorb_steps_c1 += pb;
      st.absorb_steps_c4 += (pb + 3) / 4;
      st.absorb_steps_c8 += (pb + 7) / 8;
      st.sha256_blocks_txid_final += 1;
      st.inputs += tx.inputs.len() as u64;
      st.outputs += tx.outputs.len() as u64;
      for inp in &tx.inputs {
        match self.map.spend(&inp.prev_txid, inp.vout).map_err(|e| format!("block {height} tx {ti}: {e:?}"))? {
          SpendOutcome::InWindow(p) => {
            if self.verify {
              p.check(&p.root_before).map_err(|e| format!("spend proof: {e:?}"))?;
            }
            st.spends_in_window += 1;
          }
          SpendOutcome::BeforeWindow { key, proof, root } => {
            if self.verify && !verify_nonmembership(&root, &key, &proof) {
              return Err("non-membership proof failed".into());
            }
            st.spends_before_window += 1;
          }
        }
      }
      for (vi, o) in tx.outputs.iter().enumerate() {
        let p = self
          .map
          .create(&tx.txid, vi as u32, o.value, &o.script)
          .map_err(|e| format!("block {height} tx {ti} out {vi}: {e:?}"))?;
        if self.verify {
          let after = p.check(&p.root_before).map_err(|e| format!("create proof: {e:?}"))?;
          assert_eq!(after, self.map.root());
        }
        st.creates += 1;
      }
    }
    self.prev_hash = hdr;
    st.seconds = t.elapsed().as_secs_f64();
    Ok(st)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn txid(n: u8) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[0] = n;
    t[31] = n.wrapping_mul(7);
    t
  }

  #[test]
  fn create_then_spend() {
    let mut m = UtxoMap::new();
    let r0 = m.root();
    let c = m.create(&txid(1), 0, 5000, &[0x51]).unwrap();
    assert_eq!(c.check(&r0).unwrap(), m.root());
    assert!(m.contains(&txid(1), 0));
    let p = m.membership(&txid(1), 0).unwrap();
    assert!(verify_membership(&m.root(), &outpoint_key(&txid(1), 0), &p));
    let s = m.spend_in_window(&txid(1), 0).unwrap();
    assert_eq!(s.check(&c.root_after).unwrap(), m.root());
    assert!(m.membership(&txid(1), 0).unwrap().leaf.spent);
  }

  #[test]
  fn double_spend_refused() {
    let mut m = UtxoMap::new();
    m.create(&txid(1), 0, 1, &[]).unwrap();
    m.spend_in_window(&txid(1), 0).unwrap();
    assert_eq!(m.spend_in_window(&txid(1), 0).err(), Some(MapError::DoubleSpend));
    assert!(matches!(m.spend(&txid(1), 0), Err(MapError::DoubleSpend)));
    // A spend proof against the spent state is refused by the checker as well.
    let mut m2 = UtxoMap::new();
    m2.create(&txid(2), 1, 1, &[]).unwrap();
    let before = m2.root();
    let sp = m2.spend_in_window(&txid(2), 1).unwrap();
    assert!(sp.check(&before).is_ok());
    let mut proof = m2.membership(&txid(2), 1).unwrap();
    proof.leaf.spent = true;
    let again = SpendProof { key: sp.key, proof, spent_leaf: sp.spent_leaf.clone(), root_before: m2.root(), root_after: m2.root() };
    assert_eq!(again.check(&m2.root()).err(), Some(MapError::DoubleSpend));
  }

  #[test]
  fn false_before_window_claim_refused() {
    let mut m = UtxoMap::new();
    for i in 1..20 {
      m.create(&txid(i), 0, i as u64, &[i]).unwrap();
    }
    m.spend_in_window(&txid(7), 0).unwrap();
    // Unspent and spent entries both refuse a before-window claim.
    assert_eq!(m.spend_before_window(&txid(3), 0).err(), Some(MapError::InMap));
    assert_eq!(m.spend_before_window(&txid(7), 0).err(), Some(MapError::InMap));
    // A forged proof (the key's own leaf, or its predecessor) fails verification.
    let key = outpoint_key(&txid(3), 0);
    let own = m.membership(&txid(3), 0).unwrap();
    assert!(!verify_nonmembership(&m.root(), &key, &own));
    let pred_idx = (0..m.len() as u64).find(|&i| m.leaf(i).next_key == key).unwrap();
    let pred = Proof { leaf: m.leaf(pred_idx).clone(), path: m.path(pred_idx) };
    assert!(!verify_nonmembership(&m.root(), &key, &pred));
  }

  #[test]
  fn nonmembership_correct() {
    let mut m = UtxoMap::new();
    for i in 1..30 {
      m.create(&txid(i), (i % 3) as u32, 1, &[]).unwrap();
    }
    for i in 100..140 {
      let p = m.nonmembership(&txid(i), 0).unwrap();
      assert!(verify_nonmembership(&m.root(), &outpoint_key(&txid(i), 0), &p));
      // The proof does not carry over to a present key.
      assert!(!verify_nonmembership(&m.root(), &outpoint_key(&txid(5), 5 % 3), &p));
    }
    // A proof is bound to its root: after a create it no longer verifies against the new root
    // when the proven leaf changed.
    let key = outpoint_key(&txid(200), 0);
    let p = m.nonmembership(&txid(200), 0).unwrap();
    let old = m.root();
    assert!(verify_nonmembership(&old, &key, &p));
    m.create(&txid(200), 0, 1, &[]).unwrap();
    assert!(!verify_nonmembership(&m.root(), &key, &p));
    // Duplicate creation is refused.
    assert_eq!(m.create(&txid(200), 0, 1, &[]).err(), Some(MapError::Duplicate));
  }

  #[test]
  fn sorted_chain_is_consistent() {
    let mut m = UtxoMap::new();
    for i in 1..60 {
      m.create(&txid(i), 0, 1, &[]).unwrap();
    }
    let mut idx = 0u64;
    let mut n = 1;
    loop {
      let l = m.leaf(idx);
      if l.next_key == F::ZERO {
        break;
      }
      let nx = m.leaf(l.next_index);
      assert_eq!(nx.key, l.next_key);
      assert!(lt(&l.key, &nx.key));
      idx = l.next_index;
      n += 1;
    }
    assert_eq!(n, m.len());
  }

  #[test]
  fn balance_query() {
    let mut m = UtxoMap::new();
    let s = [0x00, 0x14, 1, 2, 3];
    m.create(&txid(1), 0, 100, &s).unwrap();
    m.create(&txid(1), 1, 40, &[0x51]).unwrap();
    m.create(&txid(2), 0, 7, &s).unwrap();
    m.create(&txid(3), 0, 1000, &s).unwrap();
    m.spend_in_window(&txid(3), 0).unwrap();
    let b = m.balance_of_script(&s);
    assert_eq!(b.entries.len(), 3);
    assert_eq!(b.unspent_sum, 107);
    assert_eq!(verify_balance(&m.root(), &fu(DEFAULT_RS), &b, Some(&s)).unwrap(), 107);
    assert!(verify_balance(&m.root(), &fu(DEFAULT_RS), &b, Some(&[0x51])).is_err());
    let b2 = m.balance_of_outpoints(&[(txid(1), 0), (txid(1), 1)]).unwrap();
    assert_eq!(b2.unspent_sum, 140);
    assert_eq!(m.balance_of_outpoints(&[(txid(9), 0)]).err(), Some(MapError::NotFound));
    // A tampered value fails the proof.
    let mut b3 = m.balance_of_script(&s);
    b3.entries[0].proof.leaf.value += 1;
    assert!(verify_balance(&m.root(), &fu(DEFAULT_RS), &b3, Some(&s)).is_err());
    // Counting an entry twice fails.
    let mut b4 = m.balance_of_script(&s);
    let dup = BalanceEntry { txid: b4.entries[0].txid, vout: b4.entries[0].vout, proof: b4.entries[0].proof.clone() };
    b4.entries.push(dup);
    assert!(verify_balance(&m.root(), &fu(DEFAULT_RS), &b4, Some(&s)).is_err());
    // The same leaf under an index aliased above 2^D (root_of reads only D bits) fails.
    let mut b5 = m.balance_of_script(&s);
    let mut alias = b5.entries[0].proof.clone();
    assert_eq!(root_of(alias.leaf.hash(), &alias.path), m.root());
    alias.path.index += 1 << D;
    assert_eq!(root_of(alias.leaf.hash(), &alias.path), m.root());
    let (t0, v0) = (b5.entries[0].txid, b5.entries[0].vout);
    assert!(!verify_membership(&m.root(), &outpoint_key(&t0, v0), &alias));
    b5.entries.push(BalanceEntry { txid: t0, vout: v0, proof: alias });
    assert!(verify_balance(&m.root(), &fu(DEFAULT_RS), &b5, Some(&s)).is_err());
  }

  fn nonwit_tx(prev: u8, outs: &[(u64, &[u8])]) -> Vec<u8> {
    let mut t = vec![2, 0, 0, 0, 1];
    t.extend_from_slice(&[prev; 32]);
    t.extend_from_slice(&[0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    t.push(outs.len() as u8);
    for (v, s) in outs {
      t.extend_from_slice(&v.to_le_bytes());
      t.push(s.len() as u8);
      t.extend_from_slice(s);
    }
    t.extend_from_slice(&[0, 0, 0, 0]);
    t
  }

  #[test]
  fn output_claim_binds_script_by_txid() {
    let r_s = fu(DEFAULT_RS);
    let script = [0x00u8, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
    let tx = nonwit_tx(3, &[(5_000, &[0x51]), (940_000, &script)]);
    let id = sha256d(&tx);
    let mut m = UtxoMap::with_rs(r_s);
    m.create(&id, 0, 5_000, &[0x51]).unwrap();
    m.create(&id, 1, 940_000, &script).unwrap();
    let p = m.membership(&id, 1).unwrap();
    let (v, s, spent) = verify_output(&m.root(), &r_s, &tx, 1, &p).unwrap();
    assert_eq!((v, s.as_slice(), spent), (940_000, &script[..], false));
    // Another script in the claimed transaction changes its txid, so the leaf no longer matches.
    let mut other = script;
    other[5] ^= 1;
    let forged = nonwit_tx(3, &[(5_000, &[0x51]), (940_000, &other)]);
    assert!(verify_output(&m.root(), &r_s, &forged, 1, &p).is_err());
    // The wrong output index, a witness serialization or trailing bytes are refused.
    assert!(verify_output(&m.root(), &r_s, &tx, 0, &p).is_err());
    let mut trailing = tx.clone();
    trailing.push(0);
    assert!(verify_output(&m.root(), &r_s, &trailing, 1, &p).is_err());
  }

  #[test]
  fn segwit_parse_strips_witness() {
    // version 2, marker/flag, 1 input (null prevout), empty script, sequence, 1 output, 1 witness item.
    let mut raw = vec![2, 0, 0, 0, 0, 1, 1];
    raw.extend_from_slice(&[0u8; 32]);
    raw.extend_from_slice(&[0xff; 4]);
    raw.push(0);
    raw.extend_from_slice(&[0xff; 4]);
    raw.push(1);
    raw.extend_from_slice(&50u64.to_le_bytes());
    raw.push(1);
    raw.push(0x51);
    raw.extend_from_slice(&[1, 2, 0xaa, 0xbb]); // witness: 1 item of 2 bytes
    raw.extend_from_slice(&[9, 0, 0, 0]);
    let tx = parse_tx(&mut Rd { b: &raw, p: 0 }).unwrap();
    assert_eq!(tx.nonwit.len(), raw.len() - 2 - 4);
    assert_eq!(&tx.nonwit[..5], &[2, 0, 0, 0, 1]);
    assert_eq!(&tx.nonwit[tx.nonwit.len() - 4..], &[9, 0, 0, 0]);
    assert_eq!(tx.outputs[0].value, 50);
    assert_eq!(tx.txid, sha256d(&tx.nonwit));
  }

  #[test]
  fn merkle_odd_duplication() {
    let a = txid(1);
    assert_eq!(merkle_root(&[a]), (a, 0));
    let (r3, m3) = merkle_root(&[a, txid(2), txid(3)]);
    assert_eq!(m3, 3);
    let (r4, _) = merkle_root(&[a, txid(2), txid(3), txid(3)]);
    assert_eq!(r3, r4);
  }

  #[test]
  fn window_two_blocks_synthetic() {
    // Block 1 creates two outputs; block 2 spends one of them and one pre-window output.
    fn tx(ins: &[([u8; 32], u32)], outs: &[(u64, u8)]) -> Vec<u8> {
      let mut r = vec![1, 0, 0, 0, ins.len() as u8];
      for (t, v) in ins {
        r.extend_from_slice(t);
        r.extend_from_slice(&v.to_le_bytes());
        r.push(0);
        r.extend_from_slice(&[0xff; 4]);
      }
      r.push(outs.len() as u8);
      for (v, s) in outs {
        r.extend_from_slice(&v.to_le_bytes());
        r.extend_from_slice(&[1, *s]);
      }
      r.extend_from_slice(&[0; 4]);
      r
    }
    fn block(prev: [u8; 32], txs: &[Vec<u8>]) -> Vec<u8> {
      let ids: Vec<[u8; 32]> = txs.iter().map(|t| sha256d(t)).collect();
      let (root, _) = merkle_root(&ids);
      let mut b = vec![0u8; 4];
      b.extend_from_slice(&prev);
      b.extend_from_slice(&root);
      b.extend_from_slice(&[0u8; 12]);
      b.push(txs.len() as u8);
      for t in txs {
        b.extend_from_slice(t);
      }
      b
    }
    let cb = |n: u8| tx(&[([0; 32], u32::MAX)], &[(50, n)]);
    let t1 = tx(&[(txid(77), 3)], &[(10, 1), (20, 2)]);
    let id1 = sha256d(&t1);
    let b1 = block([5; 32], &[cb(1), t1]);
    let h1 = sha256d(&b1[..80]);
    let t2 = tx(&[(id1, 1), (txid(88), 0)], &[(25, 3)]);
    let b2 = block(h1, &[cb(2), t2]);
    let mut w = Window::new([5; 32], fu(DEFAULT_RS), true);
    let s1 = w.process_block(1, &b1).unwrap();
    assert_eq!((s1.creates, s1.spends_before_window, s1.spends_in_window), (3, 2, 0));
    let s2 = w.process_block(2, &b2).unwrap();
    assert_eq!((s2.creates, s2.spends_before_window, s2.spends_in_window), (2, 2, 1));
    let bal = w.map.balance_of_script(&[1]);
    assert_eq!(bal.unspent_sum, 60);
    // A broken link is refused.
    let mut w2 = Window::new([6; 32], fu(DEFAULT_RS), true);
    assert!(w2.process_block(1, &b1).is_err());
  }
}
