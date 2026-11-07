//! A transparent hash-based multilinear polynomial commitment over the
//! Pallas scalar field (Nova's primary witness field).
//!
//! A vector v of length 2^m is laid out as a 2^lr x 2^lc matrix (lr = m / 2),
//! row i holding v[i * 2^lc .. (i + 1) * 2^lc]. Each row is Reed-Solomon
//! encoded at rate 1/4 (its entries are polynomial coefficients evaluated on
//! the 2-adic domain of size 2^(lc + 2)); the commitment is a SHA-256 Merkle
//! root over the codeword columns.
//!
//! Opening at r = (r_row, r_col) (most-significant variable first) follows the
//! Ligero/Brakedown pattern: the prover sends u = sum_i gamma_i row_i
//! (proximity, gamma from Fiat-Shamir) and t = sum_i eq(r_row, i) row_i
//! (evaluation); for QUERIES Fiat-Shamir column positions the verifier checks
//! the Merkle path and that Enc(u) and Enc(t) agree with the opened column;
//! the value is <t, eq(r_col)>.
//!
//! This is a component: it says nothing about Nova's Pedersen commitments.
//! [`crate::decider_b`] adds that binding.
use crate::nova_io::F1 as F;
use ff::{Field, FromUniformBytes, PrimeField};
use sha2::{Digest, Sha256};

pub const BLOWUP_LOG: usize = 2;
/// Unique-decoding parameterization for rate 1/4 (relative distance 3/4):
/// a word farther than 3/8 from the code survives a query with probability
/// below 5/8, and (5/8)^148 < 2^-100.
pub const QUERIES: usize = 148;

/// SHA-256 Fiat-Shamir transcript.
#[derive(Clone)]
pub struct Transcript {
  state: [u8; 32],
}

impl Transcript {
  pub fn new(domain: &[u8]) -> Self {
    let mut t = Transcript { state: [0u8; 32] };
    t.absorb(b"domain", domain);
    t
  }

  pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
    let mut h = Sha256::new();
    h.update(b"M12-FS-absorb");
    h.update(self.state);
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    self.state = h.finalize().into();
  }

  pub fn absorb_fields(&mut self, label: &[u8], v: &[F]) {
    let bytes: Vec<u8> = v.iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect();
    self.absorb(label, &bytes);
  }

  fn squeeze(&mut self, label: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, half) in out.chunks_mut(32).enumerate() {
      let mut h = Sha256::new();
      h.update(b"M12-FS-squeeze");
      h.update(self.state);
      h.update(label);
      h.update([i as u8]);
      half.copy_from_slice(&h.finalize());
    }
    self.absorb(b"squeezed", label);
    out
  }

  pub fn challenge(&mut self, label: &[u8]) -> F {
    F::from_uniform_bytes(&self.squeeze(label))
  }

  pub fn challenges(&mut self, label: &[u8], n: usize) -> Vec<F> {
    (0..n).map(|_| self.challenge(label)).collect()
  }

  /// Uniform index below `bound` (a power of two).
  pub fn index(&mut self, label: &[u8], bound: usize) -> usize {
    assert!(bound.is_power_of_two());
    let b = self.squeeze(label);
    (u64::from_le_bytes(b[..8].try_into().unwrap()) as usize) & (bound - 1)
  }
}

fn root_of_unity(log_n: u32) -> F {
  assert!(log_n <= F::S);
  let mut w = F::ROOT_OF_UNITY;
  for _ in log_n..F::S {
    w = w.square();
  }
  w
}

/// In-place radix-2 NTT (coefficients -> evaluations on <omega>).
pub fn ntt(a: &mut [F]) {
  let n = a.len();
  assert!(n.is_power_of_two());
  let log_n = n.trailing_zeros();
  for i in 0..n {
    let j = i.reverse_bits() >> (usize::BITS - log_n.max(1));
    if log_n > 0 && i < j {
      a.swap(i, j);
    }
  }
  let mut len = 2;
  while len <= n {
    let w = root_of_unity(len.trailing_zeros());
    for start in (0..n).step_by(len) {
      let mut x = F::ONE;
      for k in 0..len / 2 {
        let u = a[start + k];
        let v = a[start + k + len / 2] * x;
        a[start + k] = u + v;
        a[start + k + len / 2] = u - v;
        x *= w;
      }
    }
    len <<= 1;
  }
}

pub fn encode(row: &[F]) -> Vec<F> {
  let mut c = row.to_vec();
  c.resize(row.len() << BLOWUP_LOG, F::ZERO);
  ntt(&mut c);
  c
}

/// eq(r, i) for every i in {0,1}^m, index bits most-significant first.
pub fn eq_table(r: &[F]) -> Vec<F> {
  let mut t = vec![F::ONE];
  for rj in r {
    let mut next = Vec::with_capacity(t.len() * 2);
    for x in &t {
      let hi = *x * rj;
      next.push(*x - hi);
      next.push(hi);
    }
    t = next;
  }
  t
}

/// Direct multilinear evaluation, the reference for openings.
pub fn mle_eval(v: &[F], r: &[F]) -> F {
  let eq = eq_table(r);
  v.iter().zip(eq.iter()).map(|(a, b)| *a * b).sum()
}

fn leaf_hash(pos: usize, col: &[F]) -> [u8; 32] {
  let mut h = Sha256::new();
  h.update(b"M12-PCS-leaf");
  h.update((pos as u64).to_le_bytes());
  for f in col {
    h.update(f.to_repr().as_ref());
  }
  h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
  let mut h = Sha256::new();
  h.update(b"M12-PCS-node");
  h.update(l);
  h.update(r);
  h.finalize().into()
}

pub struct Committed {
  pub num_vars: usize,
  pub log_rows: usize,
  pub log_cols: usize,
  rows: Vec<Vec<F>>,
  code: Vec<Vec<F>>,
  /// Merkle layers, leaves first.
  layers: Vec<Vec<[u8; 32]>>,
  pub root: [u8; 32],
}

pub fn shape(num_vars: usize) -> (usize, usize) {
  let lr = num_vars / 2;
  (lr, num_vars - lr)
}

pub fn commit(v: &[F], num_vars: usize) -> Committed {
  assert!(v.len() <= 1 << num_vars, "vector longer than 2^num_vars");
  let (lr, lc) = shape(num_vars);
  let cols = 1usize << lc;
  let mut padded = v.to_vec();
  padded.resize(1 << num_vars, F::ZERO);
  let rows: Vec<Vec<F>> = padded.chunks(cols).map(|c| c.to_vec()).collect();
  let code: Vec<Vec<F>> = rows.iter().map(|r| encode(r)).collect();
  let width = cols << BLOWUP_LOG;
  let leaves: Vec<[u8; 32]> = (0..width)
    .map(|j| {
      let col: Vec<F> = code.iter().map(|row| row[j]).collect();
      leaf_hash(j, &col)
    })
    .collect();
  let mut layers = vec![leaves];
  while layers.last().unwrap().len() > 1 {
    let prev = layers.last().unwrap();
    layers.push(prev.chunks(2).map(|p| node_hash(&p[0], &p[1])).collect());
  }
  let root = layers.last().unwrap()[0];
  Committed { num_vars, log_rows: lr, log_cols: lc, rows, code, layers, root }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
  pub u: Vec<F>,
  pub t: Vec<F>,
  /// (position, column entries, Merkle path siblings leaf-up)
  pub columns: Vec<(usize, Vec<F>, Vec<[u8; 32]>)>,
}

impl Opening {
  /// Serialized size: field elements at 32 bytes, hashes at 32 bytes, positions at 8.
  pub fn size_bytes(&self) -> usize {
    32 * (self.u.len() + self.t.len())
      + self.columns.iter().map(|(_, c, p)| 8 + 32 * c.len() + 32 * p.len()).sum::<usize>()
  }
}

/// Open `c` at `point` (|point| = num_vars). The caller has already absorbed
/// the root into `tr`. Returns the value and the opening.
pub fn open(c: &Committed, point: &[F], tr: &mut Transcript) -> (F, Opening) {
  assert_eq!(point.len(), c.num_vars);
  let (r_row, r_col) = point.split_at(c.log_rows);
  let gamma = tr.challenges(b"pcs-gamma", 1 << c.log_rows);
  let eq_row = eq_table(r_row);
  let cols = 1usize << c.log_cols;
  let mut u = vec![F::ZERO; cols];
  let mut t = vec![F::ZERO; cols];
  for (i, row) in c.rows.iter().enumerate() {
    for j in 0..cols {
      u[j] += gamma[i] * row[j];
      t[j] += eq_row[i] * row[j];
    }
  }
  tr.absorb_fields(b"pcs-u", &u);
  tr.absorb_fields(b"pcs-t", &t);
  let width = cols << BLOWUP_LOG;
  let mut columns = Vec::with_capacity(QUERIES);
  for _ in 0..QUERIES {
    let pos = tr.index(b"pcs-query", width);
    let col: Vec<F> = c.code.iter().map(|row| row[pos]).collect();
    let mut path = Vec::new();
    let mut idx = pos;
    for layer in &c.layers[..c.layers.len() - 1] {
      path.push(layer[idx ^ 1]);
      idx >>= 1;
    }
    columns.push((pos, col, path));
  }
  let value = t.iter().zip(eq_table(r_col).iter()).map(|(a, b)| *a * b).sum();
  (value, Opening { u, t, columns })
}

/// Check an opening of the commitment `root` to a 2^num_vars vector at
/// `point` with claimed `value`. The caller has absorbed `root` into `tr`.
pub fn verify(root: &[u8; 32], num_vars: usize, point: &[F], value: F, op: &Opening, tr: &mut Transcript) -> Result<(), String> {
  if point.len() != num_vars {
    return Err("point dimension".into());
  }
  let (lr, lc) = shape(num_vars);
  let cols = 1usize << lc;
  if op.u.len() != cols || op.t.len() != cols || op.columns.len() != QUERIES {
    return Err("opening shape".into());
  }
  let (r_row, r_col) = point.split_at(lr);
  let gamma = tr.challenges(b"pcs-gamma", 1 << lr);
  let eq_row = eq_table(r_row);
  tr.absorb_fields(b"pcs-u", &op.u);
  tr.absorb_fields(b"pcs-t", &op.t);
  let enc_u = encode(&op.u);
  let enc_t = encode(&op.t);
  let width = cols << BLOWUP_LOG;
  let depth = width.trailing_zeros() as usize;
  for (pos, col, path) in &op.columns {
    let expect = tr.index(b"pcs-query", width);
    if *pos != expect {
      return Err("query position does not follow the transcript".into());
    }
    if col.len() != 1 << lr || path.len() != depth {
      return Err("column or path length".into());
    }
    let mut h = leaf_hash(*pos, col);
    let mut idx = *pos;
    for s in path {
      h = if idx & 1 == 0 { node_hash(&h, s) } else { node_hash(s, &h) };
      idx >>= 1;
    }
    if &h != root {
      return Err(format!("Merkle path for column {pos} does not reach the root"));
    }
    let gu: F = col.iter().zip(gamma.iter()).map(|(a, b)| *a * b).sum();
    let gt: F = col.iter().zip(eq_row.iter()).map(|(a, b)| *a * b).sum();
    if gu != enc_u[*pos] {
      return Err(format!("proximity check fails at column {pos}"));
    }
    if gt != enc_t[*pos] {
      return Err(format!("evaluation check fails at column {pos}"));
    }
  }
  let v: F = op.t.iter().zip(eq_table(r_col).iter()).map(|(a, b)| *a * b).sum();
  if v != value {
    return Err("claimed value differs from <t, eq(r_col)>".into());
  }
  Ok(())
}
