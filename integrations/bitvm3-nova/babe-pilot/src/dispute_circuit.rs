//! Authenticated local dispute predicates for the CPU pilot.
//!
//! Every arithmetic auxiliary is part of the operator's committed trace. The challenger may
//! select a committed step and open it, but cannot replace its quotient, slope or coordinates.
//! `refute = authenticated_opening && !valid_committed_transition`. An unauthenticated opening
//! returns false. These fixed-step commitments do not implement a global trace or Bitcoin game.

use garbled_snark_verifier::{
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, FALSE_WIRE},
    CircuitContext,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::gates::{
    add_mod, all_true, and, bytes_to_bits_le, check_mul_mod_witness, const_bits_le, const_bytes_le,
    eq_bit, eq_vec, mul_unsigned, mux, mux_vec, not, or, sha256_bytes, sub, sub_mod, W,
};

pub const PILOT_PRIME: u64 = 0x7fff_ffff; // 2^31 - 1 (Mersenne-31)
pub const PILOT_INDEX_BITS: usize = 4; // 16 indexed dispute slots
pub const PILOT_ELEM_BITS: usize = 31;
pub const PILOT_INPUT_BITS: usize = PILOT_INDEX_BITS + 4 * PILOT_ELEM_BITS; // 128 bits exact
pub const PILOT_NUM_SLOTS: usize = 1 << PILOT_INDEX_BITS; // 16

/// Pinned on-chain / setup parameters for an indexed dispute claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedDisputeSpec {
    pub circuit_id: [u8; 32],
    pub claim_id: [u8; 32],
    pub generators: [u32; PILOT_NUM_SLOTS],
    pub step_auth_tags: [[u8; 32]; PILOT_NUM_SLOTS],
}

/// Opening of an operator-committed step (`128` bits total).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedDisputeInput {
    /// Challenger-chosen dispute slot `q in 0..16` (4 bits).
    pub index: u8,
    /// Claimed input accumulator state `s_in < p` (31 bits).
    pub s_in: u32,
    /// Claimed chunk scalar / witness operand `step_val < p` (31 bits).
    pub step_val: u32,
    /// Claimed output accumulator state `s_out < p` (31 bits).
    pub s_out: u32,
    /// Operator-committed quotient for `((s_in + g[index]) mod p) * step_val` (31 bits).
    pub witness_quotient: u32,
}

impl IndexedDisputeSpec {
    /// Builds a deterministic valid 16-step claim trace and returns `(spec, honest_inputs_per_slot)`.
    pub fn sample_honest_trace(
        claim_id: [u8; 32],
    ) -> (Self, [IndexedDisputeInput; PILOT_NUM_SLOTS]) {
        let generators: [u32; PILOT_NUM_SLOTS] =
            std::array::from_fn(|i| ((i as u32 + 3) * 0x0104_0193) % (PILOT_PRIME as u32));
        let mut s_cur: u64 = 0x1234_5678 % PILOT_PRIME;
        let mut step_auth_tags = [[0u8; 32]; PILOT_NUM_SLOTS];
        let inputs: [IndexedDisputeInput; PILOT_NUM_SLOTS] = std::array::from_fn(|q| {
            let step_val = (((q as u64 + 7) * 0x0045_d9f3) % (PILOT_PRIME - 1)) + 1;
            let sum_in = (s_cur + generators[q] as u64) % PILOT_PRIME;
            let prod = sum_in * step_val;
            let quotient = (prod / PILOT_PRIME) as u32;
            let s_out = (prod % PILOT_PRIME) as u32;
            let inp = IndexedDisputeInput {
                index: q as u8,
                s_in: s_cur as u32,
                step_val: step_val as u32,
                s_out,
                witness_quotient: quotient,
            };
            step_auth_tags[q] = compute_step_auth_tag(&claim_id, generators[q], &inp);
            s_cur = s_out as u64;
            inp
        });

        let mut spec = Self {
            circuit_id: [0; 32],
            claim_id,
            generators,
            step_auth_tags,
        };
        spec.recompute_circuit_id();
        (spec, inputs)
    }

    /// Changes the operator's statement before setup. An evaluator must use its independently
    /// agreed specification; accepting a replacement specification would change the claim.
    pub fn commit_step(&mut self, input: &IndexedDisputeInput) {
        assert!(
            input.is_representable(),
            "step does not fit the circuit input encoding"
        );
        let i = input.index as usize;
        self.step_auth_tags[i] = compute_step_auth_tag(&self.claim_id, self.generators[i], input);
        self.recompute_circuit_id();
    }

    pub fn recompute_circuit_id(&mut self) {
        let mut cid_hasher = Sha256::new();
        cid_hasher.update(b"babe-pilot/indexed-dispute-spec/v2\0");
        cid_hasher.update(self.claim_id);
        for g in &self.generators {
            cid_hasher.update(g.to_le_bytes());
        }
        for t in &self.step_auth_tags {
            cid_hasher.update(t);
        }
        self.circuit_id = cid_hasher.finalize().into();
    }

    /// Native reference adjudicator: returns `true` iff the claim is **refuted** (`verdict = Refute`).
    pub fn native_refutes(&self, input: &IndexedDisputeInput) -> bool {
        if !input.is_representable() {
            return false;
        }
        let i = input.index as usize;
        let g = self.generators[i] as u64;
        if g >= PILOT_PRIME {
            return false; // invalid fixed configuration
        }
        if compute_step_auth_tag(&self.claim_id, self.generators[i], input)
            != self.step_auth_tags[i]
        {
            return false;
        }
        let p = PILOT_PRIME;
        if (input.s_in as u64) >= p
            || (input.step_val as u64) >= p
            || (input.s_out as u64) >= p
            || (input.witness_quotient as u64) >= (1u64 << PILOT_ELEM_BITS)
        {
            return true;
        }
        let sum_in = ((input.s_in as u64) + g) % p;
        let lhs = sum_in * (input.step_val as u64);
        let rhs = (input.witness_quotient as u64) * p + (input.s_out as u64);
        lhs != rhs
    }
}

pub fn compute_step_auth_tag(
    claim_id: &[u8; 32],
    generator: u32,
    input: &IndexedDisputeInput,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"babe-pilot/step/v2\0");
    h.update(claim_id);
    h.update([input.index]);
    h.update(generator.to_le_bytes());
    for value in [
        input.s_in,
        input.step_val,
        input.s_out,
        input.witness_quotient,
    ] {
        h.update(value.to_le_bytes());
    }
    h.finalize().into()
}

impl IndexedDisputeInput {
    pub fn is_representable(&self) -> bool {
        (self.index as usize) < PILOT_NUM_SLOTS
            && [self.s_in, self.step_val, self.s_out, self.witness_quotient]
                .iter()
                .all(|&v| (v as u64) < (1u64 << PILOT_ELEM_BITS))
    }

    pub fn to_bits(&self) -> Vec<bool> {
        assert!(
            self.is_representable(),
            "step does not fit the circuit input encoding"
        );
        let mut bits = Vec::with_capacity(PILOT_INPUT_BITS);
        for i in 0..PILOT_INDEX_BITS {
            bits.push(((self.index >> i) & 1) == 1);
        }
        for val in [self.s_in, self.step_val, self.s_out, self.witness_quotient] {
            for i in 0..PILOT_ELEM_BITS {
                bits.push(((val >> i) & 1) == 1);
            }
        }
        debug_assert_eq!(bits.len(), PILOT_INPUT_BITS);
        bits
    }
}

fn select_16<C: CircuitContext>(c: &mut C, idx_bits: &[W], table: &[Vec<W>; 16]) -> Vec<W> {
    assert_eq!(idx_bits.len(), 4);
    let lvl1: Vec<Vec<W>> = (0..8)
        .map(|i| mux_vec(c, idx_bits[0], &table[2 * i], &table[2 * i + 1]))
        .collect();
    let lvl2: Vec<Vec<W>> = (0..4)
        .map(|i| mux_vec(c, idx_bits[1], &lvl1[2 * i], &lvl1[2 * i + 1]))
        .collect();
    let lvl3: Vec<Vec<W>> = (0..2)
        .map(|i| mux_vec(c, idx_bits[2], &lvl2[2 * i], &lvl2[2 * i + 1]))
        .collect();
    mux_vec(c, idx_bits[3], &lvl3[0], &lvl3[1])
}

fn pad31_to_32_le(bits31: &[W]) -> Vec<W> {
    assert_eq!(bits31.len(), 31);
    let mut out = bits31.to_vec();
    out.push(FALSE_WIRE);
    out
}

/// Evaluates the indexed predicate. Zero means no authenticated refutation, including when the
/// supplied opening is invalid; it does not by itself prove the entire claim valid.
pub fn eval_indexed_dispute_circuit<C: CircuitContext>(
    c: &mut C,
    spec: &IndexedDisputeSpec,
    wires: &[W],
) -> Vec<W> {
    assert_eq!(wires.len(), PILOT_INPUT_BITS);
    assert!(
        spec.generators.iter().all(|&g| (g as u64) < PILOT_PRIME),
        "non-canonical fixed generator"
    );
    let idx = &wires[0..4];
    let s_in = &wires[4..35];
    let step_val = &wires[35..66];
    let s_out = &wires[66..97];
    let q_wit = &wires[97..128];

    let p_bits = const_bits_le(PILOT_PRIME as u128, PILOT_ELEM_BITS);

    // 1. Canonicality checks: s_in < p, step_val < p, s_out < p.
    let (_, ge_sin) = sub(c, s_in, &p_bits, PILOT_ELEM_BITS);
    let (_, ge_sval) = sub(c, step_val, &p_bits, PILOT_ELEM_BITS);
    let (_, ge_sout) = sub(c, s_out, &p_bits, PILOT_ELEM_BITS);
    let c_sin = not(c, ge_sin);
    let c_sval = not(c, ge_sval);
    let c_sout = not(c, ge_sout);
    let canonical_ok = all_true(c, &[c_sin, c_sval, c_sout]);

    // 2. Select pinned generator g[idx] and authentication tag tau[idx].
    let gen_table: [Vec<W>; 16] =
        std::array::from_fn(|i| const_bits_le(spec.generators[i] as u128, PILOT_ELEM_BITS));
    let tag_table: [Vec<W>; 16] = std::array::from_fn(|i| const_bytes_le(&spec.step_auth_tags[i]));
    let g_sel = select_16(c, idx, &gen_table);
    let expected_tag = select_16(c, idx, &tag_table);

    // 3. Authenticate the complete operator-owned tuple, including the quotient and generator.
    let mut msg_bits = Vec::new();
    msg_bits.extend_from_slice(&const_bytes_le(b"babe-pilot/step/v2\0"));
    msg_bits.extend_from_slice(&const_bytes_le(&spec.claim_id));
    let mut idx_byte = idx.to_vec();
    idx_byte.resize(8, FALSE_WIRE);
    msg_bits.extend_from_slice(&idx_byte);
    msg_bits.extend_from_slice(&pad31_to_32_le(&g_sel));
    msg_bits.extend_from_slice(&pad31_to_32_le(s_in));
    msg_bits.extend_from_slice(&pad31_to_32_le(step_val));
    msg_bits.extend_from_slice(&pad31_to_32_le(s_out));
    msg_bits.extend_from_slice(&pad31_to_32_le(q_wit));
    let digest_bits = sha256_bytes(c, &msg_bits);
    let auth_ok = eq_vec(c, &digest_bits, &expected_tag);

    // 4. Witness-assisted modular transition: ((s_in + g_sel) mod p) * step_val == q_wit * p + s_out.
    let sum_in = add_mod(c, s_in, &g_sel, &p_bits);
    let rel_ok = check_mul_mod_witness(c, &sum_in, step_val, q_wit, s_out, &p_bits);

    let transition_ok = and(c, canonical_ok, rel_ok);
    let invalid = not(c, transition_ok);
    let refute = and(c, auth_ok, invalid);
    vec![refute]
}

// ============================================================================================
// Full-Scale 255-Bit Pasta Witness-Assisted Windowed Pedersen Binding Step (Phase 4 Benchmark)
// ============================================================================================

/// Pallas base field (= Vesta scalar field) modulus `p_pallas = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
pub fn pallas_base_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
        16,
    )
    .unwrap()
}

pub fn biguint_to_bits_le(v: &BigUint, width: usize) -> Vec<bool> {
    assert!(
        v.bits() <= width as u64,
        "integer encoding would truncate its input"
    );
    let bytes = v.to_bytes_le();
    (0..width)
        .map(|i| {
            let b = bytes.get(i / 8).copied().unwrap_or(0);
            ((b >> (i % 8)) & 1) == 1
        })
        .collect()
}

fn const_biguint_le(v: &BigUint, width: usize) -> Vec<W> {
    biguint_to_bits_le(v, width)
        .into_iter()
        .map(|b| {
            if b {
                garbled_snark_verifier::circuit::TRUE_WIRE
            } else {
                FALSE_WIRE
            }
        })
        .collect()
}

/// Operator-owned opening of one Pallas addition step. All fields, including slope, modular
/// quotients and the opaque auxiliary bytes, are hashed into `expected_step_hash` before setup.
/// The encoding uses 3,832 input bits: 4 + 2*(1+255+255) + 10*255 + 256.
#[derive(Clone, Debug)]
pub struct PastaWindowStepWitness {
    pub window: u8,
    pub inf1: bool,
    pub x1: BigUint,
    pub y1: BigUint,
    pub inf3: bool,
    pub x3: BigUint,
    pub y3: BigUint,
    pub inv: BigUint,
    pub lambda: BigUint,
    pub x1_sq: BigUint,
    pub lam_sq: BigUint,
    pub lam_dx3: BigUint,
    pub quotients: [BigUint; 5],
    /// Committed opaque bytes. This local predicate does not interpret these as a Merkle path.
    pub sibling_hash: [u8; 32],
}

pub const PASTA_INPUT_BITS: usize = 3832;
pub type PastaAffinePoint = (bool, BigUint, BigUint);

/// Fixed configuration agreed before garbling. This pilot uses the fixed Pallas generator
/// G=(-1,2); it does not yet import Nova's Pedersen generator set. Window c contains u*2^(4c)*G.
/// `expected_step_hash` is a full SHA-256 commitment to one operator-owned step, not a trace root.
#[derive(Clone, Debug)]
pub struct PastaWindowTable {
    pub claim_id: [u8; 32],
    pub step_index: u64,
    pub window_index: u8,
    pub points: [PastaAffinePoint; 16],
    pub expected_step_hash: [u8; 32],
}

fn mod_inv(a: &BigUint, p: &BigUint) -> BigUint {
    if a.is_zero() {
        return BigUint::zero();
    }
    a.modpow(&(p - BigUint::from(2u32)), p)
}

fn point_valid_native(point: &PastaAffinePoint, p: &BigUint) -> bool {
    let (inf, x, y) = point;
    if x >= p || y >= p {
        return false;
    }
    if *inf {
        return x.is_zero() && y.is_zero();
    }
    (y * y) % p == ((x * x * x) + BigUint::from(5u8)) % p
}

fn pasta_add_native(p1: &PastaAffinePoint, p2: &PastaAffinePoint, p: &BigUint) -> PastaAffinePoint {
    if p1.0 {
        return p2.clone();
    }
    if p2.0 {
        return p1.clone();
    }
    if p1.1 == p2.1 && (&p1.2 + &p2.2) % p == BigUint::zero() {
        return (true, BigUint::zero(), BigUint::zero());
    }
    let (num, den) = if p1.1 == p2.1 {
        (
            (BigUint::from(3u8) * &p1.1 * &p1.1) % p,
            (BigUint::from(2u8) * &p1.2) % p,
        )
    } else {
        ((&p2.2 + p - &p1.2) % p, (&p2.1 + p - &p1.1) % p)
    };
    let lam = (&num * mod_inv(&den, p)) % p;
    let x3 = ((&lam * &lam) + p + p - &p1.1 - &p2.1) % p;
    let y3 = ((&lam * (&p1.1 + p - &x3)) + p - &p1.2) % p;
    (false, x3, y3)
}

pub fn deterministic_pasta_window_points(window_index: u8) -> [PastaAffinePoint; 16] {
    assert!(
        window_index < 64,
        "255-bit scalar has at most 64 four-bit windows"
    );
    let p = pallas_base_modulus();
    let mut g = (false, &p - BigUint::one(), BigUint::from(2u8));
    for _ in 0..(4 * usize::from(window_index)) {
        g = pasta_add_native(&g, &g, &p);
    }
    let mut current = (true, BigUint::zero(), BigUint::zero());
    std::array::from_fn(|_| {
        let point = current.clone();
        current = pasta_add_native(&current, &g, &p);
        point
    })
}

fn biguint_to_32le(v: &BigUint) -> [u8; 32] {
    assert!(v.bits() <= 255, "field encoding would truncate its input");
    let mut out = [0u8; 32];
    let bytes = v.to_bytes_le();
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

impl PastaWindowTable {
    pub fn new(claim_id: [u8; 32], step_index: u64, window_index: u8) -> Self {
        Self {
            claim_id,
            step_index,
            window_index,
            points: deterministic_pasta_window_points(window_index),
            expected_step_hash: [0; 32],
        }
    }

    pub fn valid_configuration(&self) -> bool {
        self.window_index < 64
            && self.points == deterministic_pasta_window_points(self.window_index)
    }

    /// Binds the curve/generator convention, full deterministic table, claim and step/window indices.
    pub fn context_digest(&self) -> [u8; 32] {
        assert!(
            self.valid_configuration(),
            "invalid deterministic Pallas window table"
        );
        let mut h = Sha256::new();
        h.update(b"babe-pilot/pallas-fixed-generator-minus1-2/window/v2\0");
        h.update(self.claim_id);
        h.update(self.step_index.to_le_bytes());
        h.update([self.window_index]);
        h.update(biguint_to_32le(&pallas_base_modulus()));
        for (inf, x, y) in &self.points {
            h.update([u8::from(*inf)]);
            h.update(biguint_to_32le(x));
            h.update(biguint_to_32le(y));
        }
        h.finalize().into()
    }

    /// Operator-side statement construction, permitted only before the claim is agreed.
    pub fn commit_step(&mut self, witness: &PastaWindowStepWitness) {
        self.expected_step_hash = compute_pasta_step_hash(self, witness);
    }

    /// Constructs a fully specified honest opening for tests and CPU measurements.
    pub fn honest_witness(&self, p1: PastaAffinePoint, window: u8) -> PastaWindowStepWitness {
        assert!(self.valid_configuration());
        assert!(window < 16 && (self.window_index < 63 || window < 8));
        let p = pallas_base_modulus();
        assert!(
            point_valid_native(&p1, &p),
            "input point must be canonical and on curve"
        );
        let p2 = &self.points[window as usize];
        let p3 = pasta_add_native(&p1, p2, &p);
        let slope_case =
            !(p1.0 || p2.0 || (p1.1 == p2.1 && (&p1.2 + &p2.2) % &p == BigUint::zero()));
        let (den, num) = if slope_case && p1.1 == p2.1 {
            (
                (BigUint::from(2u8) * &p1.2) % &p,
                (BigUint::from(3u8) * &p1.1 * &p1.1) % &p,
            )
        } else if slope_case {
            ((&p2.1 + &p - &p1.1) % &p, (&p2.2 + &p - &p1.2) % &p)
        } else {
            (BigUint::zero(), BigUint::zero())
        };
        let inv = mod_inv(&den, &p);
        let lambda = (&num * &inv) % &p;
        let x1_sq = (&p1.1 * &p1.1) % &p;
        let lam_sq = (&lambda * &lambda) % &p;
        let dx13 = (&p1.1 + &p - &p3.1) % &p;
        let lam_dx3 = (&lambda * &dx13) % &p;
        let quotients = [
            (&den * &inv) / &p,
            (&den * &lambda) / &p,
            (&p1.1 * &p1.1) / &p,
            (&lambda * &lambda) / &p,
            (&lambda * &dx13) / &p,
        ];
        PastaWindowStepWitness {
            window,
            inf1: p1.0,
            x1: p1.1,
            y1: p1.2,
            inf3: p3.0,
            x3: p3.1,
            y3: p3.2,
            inv,
            lambda,
            x1_sq,
            lam_sq,
            lam_dx3,
            quotients,
            sibling_hash: [0x33; 32],
        }
    }

    pub fn sample_valid() -> (Self, PastaWindowStepWitness) {
        let mut table = Self::new([0x5a; 32], 0, 0);
        let witness = table.honest_witness(table.points[3].clone(), 5);
        table.commit_step(&witness);
        (table, witness)
    }

    pub fn native_refutes(&self, witness: &PastaWindowStepWitness) -> bool {
        if !self.valid_configuration()
            || !witness.is_representable()
            || compute_pasta_step_hash(self, witness) != self.expected_step_hash
        {
            return false;
        }
        let p = pallas_base_modulus();
        if witness.field_elements().iter().any(|v| *v >= &p)
            || (self.window_index == 63 && witness.window >= 8)
        {
            return true;
        }
        let p1 = (witness.inf1, witness.x1.clone(), witness.y1.clone());
        let p3 = (witness.inf3, witness.x3.clone(), witness.y3.clone());
        if !point_valid_native(&p1, &p) || !point_valid_native(&p3, &p) {
            return true;
        }
        let p2 = &self.points[witness.window as usize];
        if p1.0 {
            return p3 != *p2;
        }
        if p2.0 {
            return p3 != p1;
        }
        if p1.1 == p2.1 && (&p1.2 + &p2.2) % &p == BigUint::zero() {
            return !p3.0;
        }
        let (den, num) = if p1.1 == p2.1 {
            (
                (BigUint::from(2u8) * &p1.2) % &p,
                (BigUint::from(3u8) * &witness.x1_sq) % &p,
            )
        } else {
            ((&p2.1 + &p - &p1.1) % &p, (&p2.2 + &p - &p1.2) % &p)
        };
        let dx13 = (&p1.1 + &p - &p3.1) % &p;
        let products = [
            &den * &witness.inv,
            &den * &witness.lambda,
            &p1.1 * &p1.1,
            &witness.lambda * &witness.lambda,
            &witness.lambda * &dx13,
        ];
        let residues = [
            BigUint::one(),
            num,
            witness.x1_sq.clone(),
            witness.lam_sq.clone(),
            witness.lam_dx3.clone(),
        ];
        products
            .iter()
            .zip(&witness.quotients)
            .zip(&residues)
            .any(|((lhs, q), r)| *lhs != q * &p + r)
            || witness.lam_sq != (&p1.1 + &p2.1 + &p3.1) % &p
            || witness.lam_dx3 != (&p1.2 + &p3.2) % &p
            || p3.0
    }
}

impl PastaWindowStepWitness {
    fn field_elements(&self) -> [&BigUint; 14] {
        [
            &self.x1,
            &self.y1,
            &self.x3,
            &self.y3,
            &self.inv,
            &self.lambda,
            &self.x1_sq,
            &self.lam_sq,
            &self.lam_dx3,
            &self.quotients[0],
            &self.quotients[1],
            &self.quotients[2],
            &self.quotients[3],
            &self.quotients[4],
        ]
    }

    pub fn is_representable(&self) -> bool {
        self.window < 16 && self.field_elements().iter().all(|v| v.bits() <= 255)
    }

    pub fn to_bits(&self) -> Vec<bool> {
        assert!(
            self.is_representable(),
            "step does not fit the circuit input encoding"
        );
        let mut bits = Vec::with_capacity(PASTA_INPUT_BITS);
        for i in 0..4 {
            bits.push(((self.window >> i) & 1) == 1);
        }
        bits.push(self.inf1);
        bits.extend(biguint_to_bits_le(&self.x1, 255));
        bits.extend(biguint_to_bits_le(&self.y1, 255));
        bits.push(self.inf3);
        bits.extend(biguint_to_bits_le(&self.x3, 255));
        bits.extend(biguint_to_bits_le(&self.y3, 255));
        for v in &self.field_elements()[4..] {
            bits.extend(biguint_to_bits_le(v, 255));
        }
        bits.extend(bytes_to_bits_le(&self.sibling_hash));
        debug_assert_eq!(bits.len(), PASTA_INPUT_BITS);
        bits
    }
}

pub fn compute_pasta_step_hash(
    table: &PastaWindowTable,
    witness: &PastaWindowStepWitness,
) -> [u8; 32] {
    assert!(
        witness.is_representable(),
        "step does not fit the circuit input encoding"
    );
    let mut h = Sha256::new();
    h.update(b"babe-pilot/pasta-step/v2\0");
    h.update(table.context_digest());
    h.update([
        witness.window,
        u8::from(witness.inf1),
        u8::from(witness.inf3),
    ]);
    for value in witness.field_elements() {
        h.update(biguint_to_32le(value));
    }
    h.update(witness.sibling_hash);
    h.finalize().into()
}

/// Computes a product and its canonical remainder inside the circuit. This deliberately avoids
/// extra point-validity witnesses: an untrusted curve-check quotient cannot bypass the check.
fn computed_mul_mod<C: CircuitContext>(c: &mut C, a: &[W], b: &[W], p: &[W]) -> Vec<W> {
    let n = p.len();
    let product = mul_unsigned(c, a, b);
    let mut remainder = vec![FALSE_WIRE; n];
    let mut p_ext = p.to_vec();
    p_ext.push(FALSE_WIRE);
    for bit in product.into_iter().rev() {
        let mut doubled = Vec::with_capacity(n + 1);
        doubled.push(bit);
        doubled.extend_from_slice(&remainder);
        let (reduced, ge) = sub(c, &doubled, &p_ext, n + 1);
        remainder = mux_vec(c, ge, &doubled[..n], &reduced[..n]);
    }
    remainder
}

fn curve_point_ok<C: CircuitContext>(c: &mut C, inf: W, x: &[W], y: &[W], p: &[W]) -> W {
    let x_sq = computed_mul_mod(c, x, x, p);
    let x_cube = computed_mul_mod(c, &x_sq, x, p);
    let y_sq = computed_mul_mod(c, y, y, p);
    let rhs = add_mod(c, &x_cube, &const_bits_le(5, p.len()), p);
    let curve_ok = eq_vec(c, &y_sq, &rhs);
    let zero = vec![FALSE_WIRE; p.len()];
    let x_zero = eq_vec(c, x, &zero);
    let y_zero = eq_vec(c, y, &zero);
    let canonical_infinity = and(c, x_zero, y_zero);
    mux(c, inf, curve_ok, canonical_infinity)
}

fn padded_field_bytes(bits: &[W]) -> Vec<W> {
    assert_eq!(bits.len(), 255);
    let mut padded = bits.to_vec();
    padded.push(FALSE_WIRE);
    padded
}

/// Returns a refutation only for an authenticated, invalid operator-owned Pallas step. Both
/// endpoints are checked on curve; infinity is encoded (1,0,0). All arithmetic auxiliaries and
/// their full encodings belong to the committed claim. The last scalar window has three bits.
pub fn eval_pasta_window_ec_step<C: CircuitContext>(
    c: &mut C,
    table: &PastaWindowTable,
    wires: &[W],
) -> Vec<W> {
    assert_eq!(wires.len(), PASTA_INPUT_BITS);
    let context_digest = table.context_digest(); // validates the fixed generator table
    let p = pallas_base_modulus();
    let p_bits = const_biguint_le(&p, 255);
    let one_bits = const_bits_le(1, 255);
    let zero_bits = const_bits_le(0, 255);
    let mut off = 0;
    let mut take = |n: usize| -> &[W] {
        let s = &wires[off..off + n];
        off += n;
        s
    };
    let win = take(4);
    let inf1 = take(1)[0];
    let x1 = take(255);
    let y1 = take(255);
    let inf3 = take(1)[0];
    let x3 = take(255);
    let y3 = take(255);
    let inv = take(255);
    let lambda = take(255);
    let x1_sq = take(255);
    let lam_sq = take(255);
    let lam_dx3 = take(255);
    let q0 = take(255);
    let q1 = take(255);
    let q2 = take(255);
    let q3 = take(255);
    let q4 = take(255);
    let sib = take(256);
    assert_eq!(off, wires.len());
    let fields = [
        x1, y1, x3, y3, inv, lambda, x1_sq, lam_sq, lam_dx3, q0, q1, q2, q3, q4,
    ];
    let mut canon_checks = Vec::new();
    for field_elem in fields {
        let (_, ge) = sub(c, field_elem, &p_bits, 255);
        canon_checks.push(not(c, ge));
    }
    if table.window_index == 63 {
        canon_checks.push(not(c, win[3]));
    }
    let canon_ok = all_true(c, &canon_checks);

    let tbl_wires: [Vec<W>; 16] = std::array::from_fn(|u| {
        let (inf, x, y) = &table.points[u];
        let mut entry = vec![if *inf {
            garbled_snark_verifier::circuit::TRUE_WIRE
        } else {
            FALSE_WIRE
        }];
        entry.extend(const_biguint_le(x, 255));
        entry.extend(const_biguint_le(y, 255));
        entry
    });
    let p2_packed = select_16(c, win, &tbl_wires);
    let inf2 = p2_packed[0];
    let x2 = &p2_packed[1..256];
    let y2 = &p2_packed[256..511];
    let input_on_curve = curve_point_ok(c, inf1, x1, y1, &p_bits);
    let output_on_curve = curve_point_ok(c, inf3, x3, y3, &p_bits);

    let x_eq = eq_vec(c, x1, x2);
    let y_eq = eq_vec(c, y1, y2);
    let y_sum = add_mod(c, y1, y2, &p_bits);
    let y_opp = eq_vec(c, &y_sum, &zero_bits);
    let n_inf1 = not(c, inf1);
    let n_inf2 = not(c, inf2);
    let non_inf = and(c, n_inf1, n_inf2);
    let is_inverse = all_true(c, &[non_inf, x_eq, y_opp]);
    let n_y_opp = not(c, y_opp);
    let is_double = all_true(c, &[non_inf, x_eq, y_eq, n_y_opp]);
    let n_x_eq = not(c, x_eq);
    let is_chord = and(c, non_inf, n_x_eq);
    let is_slope_case = or(c, is_chord, is_double);
    let dx = sub_mod(c, x2, x1, &p_bits);
    let dy = sub_mod(c, y2, y1, &p_bits);
    let two_y1 = add_mod(c, y1, y1, &p_bits);
    let two_x1_sq = add_mod(c, x1_sq, x1_sq, &p_bits);
    let three_x1_sq = add_mod(c, &two_x1_sq, x1_sq, &p_bits);
    let den = mux_vec(c, is_double, &dx, &two_y1);
    let num = mux_vec(c, is_double, &dy, &three_x1_sq);
    let den_checked = mux_vec(c, is_slope_case, &one_bits, &den);
    let inv_checked = mux_vec(c, is_slope_case, &one_bits, inv);
    let m0 = check_mul_mod_witness(c, &den_checked, &inv_checked, q0, &one_bits, &p_bits);
    let m1 = check_mul_mod_witness(c, &den, lambda, q1, &num, &p_bits);
    let m2 = check_mul_mod_witness(c, x1, x1, q2, x1_sq, &p_bits);
    let m3 = check_mul_mod_witness(c, lambda, lambda, q3, lam_sq, &p_bits);
    let dx13 = sub_mod(c, x1, x3, &p_bits);
    let m4 = check_mul_mod_witness(c, lambda, &dx13, q4, lam_dx3, &p_bits);
    let x1_plus_x2 = add_mod(c, x1, x2, &p_bits);
    let x_sum_all = add_mod(c, &x1_plus_x2, x3, &p_bits);
    let y1_plus_y3 = add_mod(c, y1, y3, &p_bits);
    let slope_x_ok = eq_vec(c, lam_sq, &x_sum_all);
    let slope_y_ok = eq_vec(c, lam_dx3, &y1_plus_y3);
    let slope_not_inf = not(c, inf3);
    let slope_all = all_true(
        c,
        &[
            is_slope_case,
            m0,
            m1,
            m2,
            m3,
            m4,
            slope_x_ok,
            slope_y_ok,
            slope_not_inf,
        ],
    );
    let e_inf32 = eq_bit(c, inf3, inf2);
    let e_x32 = eq_vec(c, x3, x2);
    let e_y32 = eq_vec(c, y3, y2);
    let p3_eq_p2 = all_true(c, &[e_inf32, e_x32, e_y32]);
    let e_inf31 = eq_bit(c, inf3, inf1);
    let e_x31 = eq_vec(c, x3, x1);
    let e_y31 = eq_vec(c, y3, y1);
    let p3_eq_p1 = all_true(c, &[e_inf31, e_x31, e_y31]);
    let e_x30 = eq_vec(c, x3, &zero_bits);
    let e_y30 = eq_vec(c, y3, &zero_bits);
    let p3_is_inf = all_true(c, &[inf3, e_x30, e_y30]);
    let non_inf_case = mux(c, is_inverse, slope_all, p3_is_inf);
    let inf2_or_non_inf = mux(c, inf2, non_inf_case, p3_eq_p1);
    let case_ok = mux(c, inf1, inf2_or_non_inf, p3_eq_p2);

    let mut auth_msg = const_bytes_le(b"babe-pilot/pasta-step/v2\0");
    auth_msg.extend(const_bytes_le(&context_digest));
    let mut win_byte = win.to_vec();
    win_byte.resize(8, FALSE_WIRE);
    auth_msg.extend(win_byte);
    for inf in [inf1, inf3] {
        let mut byte = vec![inf];
        byte.resize(8, FALSE_WIRE);
        auth_msg.extend(byte);
    }
    for value in fields {
        auth_msg.extend(padded_field_bytes(value));
    }
    auth_msg.extend_from_slice(sib);
    let digest = sha256_bytes(c, &auth_msg);
    let auth_ok = eq_vec(c, &digest, &const_bytes_le(&table.expected_step_hash));
    let valid = all_true(c, &[canon_ok, input_on_curve, output_on_curve, case_ok]);
    let invalid = not(c, valid);
    vec![and(c, auth_ok, invalid)]
}

/// Helper to execute any Boolean circuit on plaintext bits via `ExecuteMode`, returning `(output_bits, nonfree_gates)`.
pub fn execute_boolean_circuit<F>(input_bits: Vec<bool>, f: F) -> (Vec<bool>, usize)
where
    F: Fn(&mut garbled_snark_verifier::circuit::StreamingMode<ExecuteMode>, &Vec<W>) -> Vec<W>,
{
    struct PlainIn(Vec<bool>);
    impl CircuitInput for PlainIn {
        type WireRepr = Vec<W>;
        fn allocate(&self, mut issue: impl FnMut() -> W) -> Self::WireRepr {
            (0..self.0.len()).map(|_| issue()).collect()
        }
        fn collect_wire_ids(w: &Self::WireRepr) -> Vec<W> {
            w.clone()
        }
    }
    impl EncodeInput<ExecuteMode> for PlainIn {
        fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
            for (&id, &bit) in w.iter().zip(&self.0) {
                mode.feed_wire(id, bit);
            }
        }
    }
    let res = CircuitBuilder::streaming_execute(PlainIn(input_bits), 65_536, f);
    (
        res.output_value,
        res.gate_count.nonfree_gate_count() as usize,
    )
}
