//! BN254 Groth16 circuits for two Bitcoin statements, sized for a laptop.
//!
//! - [`SpvCircuit`]: one output of a transaction is in a block. Inside the
//!   circuit: txid = SHA256d(tx), the txid's Merkle branch reaches the
//!   header's merkle root, block hash = SHA256d(header), and the output's
//!   value and script hash are read from the hashed transaction bytes.
//!   Public inputs: block hash (2), txid (2), value (1), script SHA-256 (2).
//! - [`HeaderChainCircuit`]: N consecutive headers inside one difficulty
//!   epoch. Each header links to the previous hash, carries the epoch's
//!   nBits, and hashes (SHA256d) to at most the target. Public inputs: start
//!   prev-hash (2), end hash (2), nBits (1), target (2). The verifier checks
//!   natively that `target` is the decoding of `nBits`.
//!
//! 32-byte values are public as two field elements: bytes 0..16 and 16..32,
//! each read as a little-endian integer. Hashes are in internal byte order.
//!
//! The transaction circuit is specialized to a transaction layout
//! ([`TxShape`]): its length and every count and length byte are circuit
//! constants, so the parse that locates the output is forced. A different
//! layout needs its own circuit and keys.
use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    select::CondSelectGadget, uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use sha2::{Digest, Sha256};

pub type Bytes32 = [u8; 32];

pub fn sha256d(b: &[u8]) -> Bytes32 {
    Sha256::digest(Sha256::digest(b)).into()
}

/// Two field elements for a 32-byte value (see the module docs).
pub fn pack32(b: &Bytes32) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&b[..16]),
        Fr::from_le_bytes_mod_order(&b[16..]),
    ]
}

/// The 256-bit target encoded by compact `nbits`, as 32 little-endian bytes.
pub fn target_from_nbits(nbits: u32) -> Result<Bytes32, String> {
    let exp = (nbits >> 24) as usize;
    let mantissa = nbits & 0x007f_ffff;
    if nbits & 0x0080_0000 != 0 || mantissa == 0 || !(3..=32).contains(&exp) {
        return Err("unsupported compact target".into());
    }
    let mut t = [0u8; 32];
    for (i, byte) in mantissa.to_le_bytes()[..3].iter().enumerate() {
        t[exp - 3 + i] = *byte;
    }
    Ok(t)
}

// ---------- gadgets ----------

fn sha256d_var(bytes: &[UInt8<Fr>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let once = Sha256Gadget::<Fr>::digest(bytes)?.0;
    Ok(Sha256Gadget::<Fr>::digest(&once)?.0)
}

fn bits_le(bytes: &[UInt8<Fr>]) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for b in bytes {
        out.extend(b.to_bits_le()?);
    }
    Ok(out)
}

fn input32(cs: &ConstraintSystemRef<Fr>, v: &Bytes32) -> Result<[FpVar<Fr>; 2], SynthesisError> {
    let [a, b] = pack32(v);
    Ok([
        FpVar::new_input(cs.clone(), || Ok(a))?,
        FpVar::new_input(cs.clone(), || Ok(b))?,
    ])
}

fn enforce_packed(bytes: &[UInt8<Fr>], input: &[FpVar<Fr>; 2]) -> Result<(), SynthesisError> {
    Boolean::le_bits_to_fp(&bits_le(&bytes[..16])?)?.enforce_equal(&input[0])?;
    Boolean::le_bits_to_fp(&bits_le(&bytes[16..32])?)?.enforce_equal(&input[1])
}

fn enforce_bytes_eq(a: &[UInt8<Fr>], b: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    for (x, y) in a.iter().zip(b) {
        x.enforce_equal(y)?;
    }
    Ok(())
}

/// Enforce `a <= b` for little-endian bit vectors of equal length.
fn enforce_le_bits(a: &[Boolean<Fr>], b: &[Boolean<Fr>]) -> Result<(), SynthesisError> {
    let mut lt = Boolean::FALSE;
    let mut eq = Boolean::TRUE;
    for i in (0..a.len()).rev() {
        let here_lt = &!&a[i] & &b[i];
        lt = &lt | &(&eq & &here_lt);
        eq = &eq & &a[i].is_eq(&b[i])?;
    }
    (&lt | &eq).enforce_equal(&Boolean::TRUE)
}

// ---------- SPV payment ----------

/// Layout of a non-witness transaction serialization and the output read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxShape {
    pub len: usize,
    /// Every count and length byte, which the circuit fixes.
    pub structural: Vec<(usize, u8)>,
    pub vout: u32,
    pub value_offset: usize,
    pub script_offset: usize,
    pub script_len: usize,
}

fn read_varint(
    b: &[u8],
    pos: &mut usize,
    structural: &mut Vec<(usize, u8)>,
) -> Result<u64, String> {
    let first = *b.get(*pos).ok_or("truncated varint")?;
    let n = match first {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        _ => 0,
    };
    if *pos + 1 + n > b.len() {
        return Err("truncated varint".into());
    }
    for i in 0..=n {
        structural.push((*pos + i, b[*pos + i]));
    }
    let v = if n == 0 {
        first as u64
    } else {
        let mut le = [0u8; 8];
        le[..n].copy_from_slice(&b[*pos + 1..*pos + 1 + n]);
        u64::from_le_bytes(le)
    };
    *pos += 1 + n;
    Ok(v)
}

/// Parse a non-witness transaction and record its layout.
pub fn tx_shape(tx: &[u8], vout: u32) -> Result<TxShape, String> {
    if tx.len() == 64 {
        return Err("64-byte transactions are ambiguous with Merkle nodes".into());
    }
    let mut structural = Vec::new();
    let mut pos = 4;
    let inputs = read_varint(tx, &mut pos, &mut structural)?;
    if inputs == 0 {
        return Err("witness serialization or no inputs; pass the stripped form".into());
    }
    for _ in 0..inputs {
        pos += 36;
        let n = read_varint(tx, &mut pos, &mut structural)? as usize;
        pos += n + 4;
    }
    let outputs = read_varint(tx, &mut pos, &mut structural)?;
    let mut found = None;
    for i in 0..outputs {
        let value_offset = pos;
        pos += 8;
        let n = read_varint(tx, &mut pos, &mut structural)? as usize;
        if i == u64::from(vout) {
            found = Some((value_offset, pos, n));
        }
        pos += n;
    }
    pos += 4;
    if pos != tx.len() {
        return Err("transaction length does not match its layout".into());
    }
    let (value_offset, script_offset, script_len) = found.ok_or("output index out of range")?;
    Ok(TxShape {
        len: tx.len(),
        structural,
        vout,
        value_offset,
        script_offset,
        script_len,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpvPublic {
    pub block_hash: Bytes32,
    pub txid: Bytes32,
    pub value: u64,
    pub script_sha256: Bytes32,
}

impl SpvPublic {
    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = pack32(&self.block_hash).to_vec();
        v.extend(pack32(&self.txid));
        v.push(Fr::from(self.value));
        v.extend(pack32(&self.script_sha256));
        v
    }
}

#[derive(Clone, Debug)]
pub struct SpvCircuit {
    pub shape: TxShape,
    /// Non-witness serialization; `shape.len` bytes.
    pub tx: Vec<u8>,
    /// Merkle branch from the leaf upward: (sibling, current node is the right child).
    pub branch: Vec<(Bytes32, bool)>,
    pub header: [u8; 80],
    pub public: SpvPublic,
}

impl ConstraintSynthesizer<Fr> for SpvCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs first, in `SpvPublic::inputs` order.
        let block_hash = input32(&cs, &self.public.block_hash)?;
        let txid_in = input32(&cs, &self.public.txid)?;
        let value_in = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.public.value)))?;
        let script_in = input32(&cs, &self.public.script_sha256)?;

        let s = &self.shape;
        assert_eq!(
            self.tx.len(),
            s.len,
            "witness length differs from the shape"
        );
        let tx = UInt8::new_witness_vec(cs.clone(), &self.tx)?;
        for (pos, byte) in &s.structural {
            tx[*pos].enforce_equal(&UInt8::constant(*byte))?;
        }
        let txid = sha256d_var(&tx)?;
        enforce_packed(&txid, &txid_in)?;
        Boolean::le_bits_to_fp(&bits_le(&tx[s.value_offset..s.value_offset + 8])?)?
            .enforce_equal(&value_in)?;
        let script = &tx[s.script_offset..s.script_offset + s.script_len];
        enforce_packed(&Sha256Gadget::<Fr>::digest(script)?.0, &script_in)?;

        let mut node = txid;
        for (sibling, is_right) in &self.branch {
            let sib = UInt8::new_witness_vec(cs.clone(), sibling)?;
            let right = Boolean::new_witness(cs.clone(), || Ok(*is_right))?;
            let mut pair = Vec::with_capacity(64);
            for (n, m) in node.iter().zip(&sib) {
                pair.push(UInt8::conditionally_select(&right, m, n)?);
            }
            for (n, m) in node.iter().zip(&sib) {
                pair.push(UInt8::conditionally_select(&right, n, m)?);
            }
            node = sha256d_var(&pair)?;
        }

        let header = UInt8::new_witness_vec(cs.clone(), &self.header)?;
        enforce_bytes_eq(&header[36..68], &node)?;
        enforce_packed(&sha256d_var(&header)?, &block_hash)
    }
}

// ---------- header chain ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainPublic {
    pub prev: Bytes32,
    pub end: Bytes32,
    pub nbits: u32,
    pub target: Bytes32,
}

impl ChainPublic {
    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = pack32(&self.prev).to_vec();
        v.extend(pack32(&self.end));
        v.push(Fr::from(self.nbits));
        v.extend(pack32(&self.target));
        v
    }
}

#[derive(Clone, Debug)]
pub struct HeaderChainCircuit {
    pub headers: Vec<[u8; 80]>,
    pub public: ChainPublic,
}

impl ConstraintSynthesizer<Fr> for HeaderChainCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prev_in = input32(&cs, &self.public.prev)?;
        let end_in = input32(&cs, &self.public.end)?;
        let nbits_in = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.public.nbits)))?;
        let target_in = input32(&cs, &self.public.target)?;
        let target = UInt8::new_witness_vec(cs.clone(), &self.public.target)?;
        enforce_packed(&target, &target_in)?;
        let target_bits = bits_le(&target)?;

        let mut prev: Option<Vec<UInt8<Fr>>> = None;
        for h in &self.headers {
            let header = UInt8::new_witness_vec(cs.clone(), h)?;
            match &prev {
                None => enforce_packed(&header[4..36], &prev_in)?,
                Some(p) => enforce_bytes_eq(&header[4..36], p)?,
            }
            Boolean::le_bits_to_fp(&bits_le(&header[72..76])?)?.enforce_equal(&nbits_in)?;
            let hash = sha256d_var(&header)?;
            enforce_le_bits(&bits_le(&hash)?, &target_bits)?;
            prev = Some(hash);
        }
        enforce_packed(prev.as_ref().expect("at least one header"), &end_in)
    }
}

// ---------- witnesses from real data ----------

/// Branch for the single matched transaction of a `gettxoutproof` MerkleBlock.
pub fn merkle_branch(mb: &bitcoin::MerkleBlock) -> Result<(Bytes32, Vec<(Bytes32, bool)>), String> {
    use bitcoin::hashes::Hash;
    let pmt = &mb.txn;
    let n = pmt.num_transactions();
    let width = |h: u32| (n + (1 << h) - 1) >> h;
    let mut height = 0;
    while width(height) > 1 {
        height += 1;
    }
    let bits = pmt.bits();
    let hashes: Vec<Bytes32> = pmt.hashes().iter().map(|h| h.to_byte_array()).collect();
    let (mut bi, mut hi) = (0usize, 0usize);
    type Found = Option<(Bytes32, Vec<(Bytes32, bool)>)>;
    fn walk(
        h: u32,
        pos: u32,
        width: &dyn Fn(u32) -> u32,
        bits: &[bool],
        hashes: &[Bytes32],
        bi: &mut usize,
        hi: &mut usize,
    ) -> Result<(Bytes32, Found), String> {
        let flag = *bits.get(*bi).ok_or("MerkleBlock flags exhausted")?;
        *bi += 1;
        if h == 0 || !flag {
            let hash = *hashes.get(*hi).ok_or("MerkleBlock hashes exhausted")?;
            *hi += 1;
            let found = (h == 0 && flag).then(|| (hash, Vec::new()));
            return Ok((hash, found));
        }
        let (l, lf) = walk(h - 1, pos * 2, width, bits, hashes, bi, hi)?;
        let (r, rf) = if pos * 2 + 1 < width(h - 1) {
            walk(h - 1, pos * 2 + 1, width, bits, hashes, bi, hi)?
        } else {
            (l, None)
        };
        let node = sha256d(&[l, r].concat());
        let found = match (lf, rf) {
            (Some((leaf, mut b)), None) => {
                b.push((r, false));
                Some((leaf, b))
            }
            (None, Some((leaf, mut b))) => {
                b.push((l, true));
                Some((leaf, b))
            }
            (None, None) => None,
            _ => return Err("MerkleBlock matches more than one transaction".into()),
        };
        Ok((node, found))
    }
    let (root, found) = walk(height, 0, &width, bits, &hashes, &mut bi, &mut hi)?;
    if root != mb.header.merkle_root.to_byte_array() {
        return Err("MerkleBlock does not reach its header's root".into());
    }
    found.ok_or_else(|| "MerkleBlock matches no transaction".into())
}

/// SPV witness from a raw transaction (any serialization) and its MerkleBlock.
pub fn spv_from_hex(tx_hex: &str, merkleblock_hex: &str, vout: u32) -> Result<SpvCircuit, String> {
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    let mut tx: bitcoin::Transaction =
        deserialize(&hex::decode(tx_hex.trim()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let txid = tx.compute_txid().to_byte_array();
    for input in &mut tx.input {
        input.witness.clear();
    }
    let stripped = serialize(&tx);
    let mb: bitcoin::MerkleBlock =
        deserialize(&hex::decode(merkleblock_hex.trim()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let (leaf, branch) = merkle_branch(&mb)?;
    if leaf != txid || sha256d(&stripped) != txid {
        return Err("MerkleBlock does not match this transaction".into());
    }
    let shape = tx_shape(&stripped, vout)?;
    let out = &tx.output[vout as usize];
    let header: [u8; 80] = serialize(&mb.header).try_into().unwrap();
    let public = SpvPublic {
        block_hash: sha256d(&header),
        txid,
        value: out.value.to_sat(),
        script_sha256: Sha256::digest(out.script_pubkey.as_bytes()).into(),
    };
    Ok(SpvCircuit {
        shape,
        tx: stripped,
        branch,
        header,
        public,
    })
}

/// "height hex" lines -> N consecutive headers ending at `end`, all in one epoch.
pub fn chain_from_txt(txt: &str, end: u32, n: usize) -> Result<HeaderChainCircuit, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in txt.lines().filter(|l| !l.trim().is_empty()) {
        let mut it = line.split_whitespace();
        let h: u32 = it.next().unwrap().parse().map_err(|_| "bad height")?;
        let b: [u8; 80] = hex::decode(it.next().ok_or("missing header")?)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "header must be 80 bytes")?;
        map.insert(h, b);
    }
    let start = end + 1 - n as u32;
    let headers: Vec<[u8; 80]> = (start..=end)
        .map(|h| map.get(&h).copied().ok_or(format!("header {h} missing")))
        .collect::<Result<_, _>>()?;
    if start / 2016 != end / 2016 {
        return Err("range must stay inside one difficulty epoch".into());
    }
    let nbits = u32::from_le_bytes(headers[0][72..76].try_into().unwrap());
    for (i, h) in headers.iter().enumerate() {
        if i > 0 && h[4..36] != sha256d(&headers[i - 1]) {
            return Err("headers do not link".into());
        }
    }
    Ok(HeaderChainCircuit {
        public: ChainPublic {
            prev: headers[0][4..36].try_into().unwrap(),
            end: sha256d(headers.last().unwrap()),
            nbits,
            target: target_from_nbits(nbits)?,
        },
        headers,
    })
}
