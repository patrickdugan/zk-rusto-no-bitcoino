//! Reference Dispute Circuits for the BABE-Inspired Transparent Nova Pilot:
//! 1. `IndexedDisputeCircuit` (`128` input wires): CPU-scale indexed local transition check with
//!    FIPS 180-4 SHA-256 authentication and witness-assisted modular arithmetic (`p = 2^31 - 1`),
//!    emitting `refute = 1` iff the claimed transition or authentication fails.
//! 2. `pasta_witness_ec_window_step`: Full 255-bit Pasta (`y^2 = x^3 + 5`) `w = 4`-bit windowed
//!    witness-assisted complete affine EC point-addition check for Phase 4 architectural pricing
//!    against FC03's 1-bit projective RCB `BindingStep` (`7,285,647` non-free gates) and M14.

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
    eq_bit, eq_vec, mux, mux_vec, not, or, sha256_bytes, sub, sub_mod, W,
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
    pub step_auth_tags: [[u8; 4]; PILOT_NUM_SLOTS],
}

/// Dynamic challenger-selected dispute input `x` (`128` bits total).
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
    /// Witness quotient `q_wit < p` such that `(s_in + g[index]) * step_val == q_wit * p + s_out` (31 bits).
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
        let mut step_auth_tags = [[0u8; 4]; PILOT_NUM_SLOTS];
        let inputs: [IndexedDisputeInput; PILOT_NUM_SLOTS] = std::array::from_fn(|q| {
            let step_val = (((q as u64 + 7) * 0x0045_d9f3) % (PILOT_PRIME - 1)) + 1;
            let sum_in = (s_cur + generators[q] as u64) % PILOT_PRIME;
            let prod = sum_in * step_val;
            let quotient = (prod / PILOT_PRIME) as u32;
            let s_out = (prod % PILOT_PRIME) as u32;
            let tag =
                compute_step_auth_tag(&claim_id, q as u8, s_cur as u32, step_val as u32, s_out);
            step_auth_tags[q] = tag;
            let inp = IndexedDisputeInput {
                index: q as u8,
                s_in: s_cur as u32,
                step_val: step_val as u32,
                s_out,
                witness_quotient: quotient,
            };
            s_cur = s_out as u64;
            inp
        });

        let mut cid_hasher = Sha256::new();
        cid_hasher.update(b"babe-pilot/indexed-dispute-spec/v1\0");
        cid_hasher.update(claim_id);
        for g in &generators {
            cid_hasher.update(g.to_le_bytes());
        }
        for t in &step_auth_tags {
            cid_hasher.update(t);
        }
        let circuit_id: [u8; 32] = cid_hasher.finalize().into();

        (
            Self {
                circuit_id,
                claim_id,
                generators,
                step_auth_tags,
            },
            inputs,
        )
    }

    /// Native reference adjudicator: returns `true` iff the claim is **refuted** (`verdict = Refute`).
    pub fn native_refutes(&self, input: &IndexedDisputeInput) -> bool {
        if (input.index as usize) >= PILOT_NUM_SLOTS {
            return true;
        }
        let p = PILOT_PRIME;
        if (input.s_in as u64) >= p
            || (input.step_val as u64) >= p
            || (input.s_out as u64) >= p
            || (input.witness_quotient as u64) >= (1u64 << PILOT_ELEM_BITS)
        {
            return true;
        }
        let expected_tag = self.step_auth_tags[input.index as usize];
        let got_tag = compute_step_auth_tag(
            &self.claim_id,
            input.index,
            input.s_in,
            input.step_val,
            input.s_out,
        );
        if got_tag != expected_tag {
            return true;
        }
        let g = self.generators[input.index as usize] as u64;
        let sum_in = ((input.s_in as u64) + g) % p;
        let lhs = sum_in * (input.step_val as u64);
        let rhs = (input.witness_quotient as u64) * p + (input.s_out as u64);
        lhs != rhs
    }
}

pub fn compute_step_auth_tag(
    claim_id: &[u8; 32],
    index: u8,
    s_in: u32,
    step_val: u32,
    s_out: u32,
) -> [u8; 4] {
    let mut msg = Vec::with_capacity(63);
    msg.extend_from_slice(b"babe-pilot/step/v1"); // 18 bytes
    msg.extend_from_slice(claim_id); // +32 = 50 bytes
    msg.push(index); // +1 = 51 bytes
    msg.extend_from_slice(&s_in.to_le_bytes()); // +4 = 55 bytes
    msg.extend_from_slice(&step_val.to_le_bytes()); // +4 = 59 bytes
    msg.extend_from_slice(&s_out.to_le_bytes()); // +4 = 63 bytes (2 SHA-256 blocks)
    let digest = Sha256::digest(&msg);
    digest[..4].try_into().unwrap()
}

impl IndexedDisputeInput {
    pub fn to_bits(&self) -> Vec<bool> {
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

/// Evaluates the indexed local dispute check in Boolean gates, outputting `[refute]` (`1` = refute, `0` = accept).
pub fn eval_indexed_dispute_circuit<C: CircuitContext>(
    c: &mut C,
    spec: &IndexedDisputeSpec,
    wires: &[W],
) -> Vec<W> {
    assert_eq!(wires.len(), PILOT_INPUT_BITS);
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

    // 3. Authenticate step operands with FIPS 180-4 SHA-256 over the exact 63-byte framing.
    let mut msg_bits = Vec::with_capacity(63 * 8);
    msg_bits.extend_from_slice(&const_bytes_le(b"babe-pilot/step/v1"));
    msg_bits.extend_from_slice(&const_bytes_le(&spec.claim_id));
    let mut idx_byte = idx.to_vec();
    idx_byte.resize(8, FALSE_WIRE);
    msg_bits.extend_from_slice(&idx_byte);
    msg_bits.extend_from_slice(&pad31_to_32_le(s_in));
    msg_bits.extend_from_slice(&pad31_to_32_le(step_val));
    msg_bits.extend_from_slice(&pad31_to_32_le(s_out));
    let digest_bits = sha256_bytes(c, &msg_bits);
    let auth_ok = eq_vec(c, &digest_bits[..32], &expected_tag);

    // 4. Witness-assisted modular transition: ((s_in + g_sel) mod p) * step_val == q_wit * p + s_out.
    let sum_in = add_mod(c, s_in, &g_sel, &p_bits);
    let rel_ok = check_mul_mod_witness(c, &sum_in, step_val, q_wit, s_out, &p_bits);

    let all_ok = all_true(c, &[canonical_ok, auth_ok, rel_ok]);
    let refute = not(c, all_ok);
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

/// Witness-assisted 255-bit Pasta (`y^2 = x^3 + 5`) complete affine point-addition + `w = 4`-bit
/// window lookup + SHA-256 chunk authentication (`1` transition covers `4` scalar bits!).
///
/// Inputs (`3,869` wires):
/// - `window_bits`: `4` bits (`d in 0..16`, selecting pre-committed `[0, G, 2G, ..., 15G]`)
/// - `p1 = (inf1, x1, y1)`: `1 + 255 + 255 = 511` bits
/// - `p3 = (inf3, x3, y3)`: `1 + 255 + 255 = 511` bits
/// - Witness-assisted slope & quotient bundle (5 modular multiplications: `(dx_or_2y) * inv = 1`,
///   `(dx_or_2y) * lambda = dy_or_3x2`, `x1 * x1 = x1_sq`, `lambda * lambda = lam_sq`,
///   `lambda * (x1 - x3) = lam_dx3`):
///   `inv` (255), `lambda` (255), `x1_sq` (255), `lam_sq` (255), `lam_dx3` (255), plus 5 quotients `q0..q4` (`5 * 255 = 1275`)
/// - SHA-256 32-byte sibling digest for trace authentication (`256` bits)
///
/// Total = `4 + 511 + 511 + 10*255 + 256 + 32 = 3,864` bits.
#[derive(Clone)]
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
    pub sibling_hash: [u8; 32],
}

pub struct PastaWindowTable {
    /// `table[0]` = infinity `(1, 0, 0)`, `table[u]` = `(0, x_u, y_u)` for `u = 1..16`.
    pub points: [(bool, BigUint, BigUint); 16],
    pub expected_root_prefix: [u8; 4],
}

fn mod_inv(a: &BigUint, p: &BigUint) -> BigUint {
    if a.is_zero() {
        return BigUint::zero();
    }
    a.modpow(&(p - BigUint::from(2u32)), p)
}

fn pasta_add_native(
    p1: &(bool, BigUint, BigUint),
    p2: &(bool, BigUint, BigUint),
    p: &BigUint,
) -> (bool, BigUint, BigUint) {
    if p1.0 {
        return p2.clone();
    }
    if p2.0 {
        return p1.clone();
    }
    if p1.1 == p2.1 {
        if (&p1.2 + &p2.2) % p == BigUint::zero() {
            return (true, BigUint::zero(), BigUint::zero());
        }
        let num = (BigUint::from(3u32) * &p1.1 * &p1.1) % p;
        let den = (BigUint::from(2u32) * &p1.2) % p;
        let lam = (&num * mod_inv(&den, p)) % p;
        let x3 = ((&lam * &lam) + p + p - &p1.1 - &p2.1) % p;
        let y3 = ((&lam * (&p1.1 + p - &x3)) + p - &p1.2) % p;
        return (false, x3, y3);
    }
    let num = (&p2.2 + p - &p1.2) % p;
    let den = (&p2.1 + p - &p1.1) % p;
    let lam = (&num * mod_inv(&den, p)) % p;
    let x3 = ((&lam * &lam) + p + p - &p1.1 - &p2.1) % p;
    let y3 = ((&lam * (&p1.1 + p - &x3)) + p - &p1.2) % p;
    (false, x3, y3)
}

impl PastaWindowTable {
    /// Constructs a valid 4-bit generator window table on `y^2 = x^3 + 5 (mod p_pallas)` and a valid witness.
    pub fn sample_valid() -> (Self, PastaWindowStepWitness) {
        let p = pallas_base_modulus();
        // Generator on Pallas: x = p - 1 => x^3 + 5 = -1 + 5 = 4 = 2^2! So (-1, 2) is an exact rational point on y^2 = x^3 + 5!
        let g = (false, &p - BigUint::one(), BigUint::from(2u32));
        let mut pts: [(bool, BigUint, BigUint); 16] =
            std::array::from_fn(|_| (true, BigUint::zero(), BigUint::zero()));
        let mut cur = (true, BigUint::zero(), BigUint::zero());
        for slot in &mut pts {
            *slot = cur.clone();
            cur = pasta_add_native(&cur, &g, &p);
        }
        // Take p1 = 3*G, window = 5 (p2 = 5*G), so p3 = 8*G (chord case).
        let p1 = pts[3].clone();
        let window = 5u8;
        let p2 = pts[window as usize].clone();
        let p3 = pasta_add_native(&p1, &p2, &p);

        let dx = (&p2.1 + &p - &p1.1) % &p;
        let dy = (&p2.2 + &p - &p1.2) % &p;
        let inv = mod_inv(&dx, &p);
        let lambda = (&dy * &inv) % &p;
        let x1_sq = (&p1.1 * &p1.1) % &p;
        let lam_sq = (&lambda * &lambda) % &p;
        let dx3 = (&p1.1 + &p - &p3.1) % &p;
        let lam_dx3 = (&lambda * &dx3) % &p;

        let q0 = (&dx * &inv) / &p;
        let q1 = (&dx * &lambda) / &p;
        let q2 = (&p1.1 * &p1.1) / &p;
        let q3 = (&lambda * &lambda) / &p;
        let q4 = (&lambda * &dx3) / &p;

        let sibling_hash = [0x33u8; 32];
        let mut msg = Vec::with_capacity(64);
        msg.push(window);
        msg.push(p1.0 as u8);
        msg.push(p3.0 as u8);
        let x1b = biguint_to_32le(&p1.1);
        let x3b = biguint_to_32le(&p3.1);
        msg.extend_from_slice(&x1b[..14]);
        msg.extend_from_slice(&x3b[..15]);
        msg.extend_from_slice(&sibling_hash);
        let root = Sha256::digest(&msg);

        (
            Self {
                points: pts,
                expected_root_prefix: root[..4].try_into().unwrap(),
            },
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
                quotients: [q0, q1, q2, q3, q4],
                sibling_hash,
            },
        )
    }
}

fn biguint_to_32le(v: &BigUint) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = v.to_bytes_le();
    let n = b.len().min(32);
    out[..n].copy_from_slice(&b[..n]);
    out
}

impl PastaWindowStepWitness {
    pub fn to_bits(&self) -> Vec<bool> {
        let mut bits = Vec::with_capacity(3832);
        for i in 0..4 {
            bits.push(((self.window >> i) & 1) == 1);
        }
        bits.push(self.inf1);
        bits.extend(biguint_to_bits_le(&self.x1, 255));
        bits.extend(biguint_to_bits_le(&self.y1, 255));
        bits.push(self.inf3);
        bits.extend(biguint_to_bits_le(&self.x3, 255));
        bits.extend(biguint_to_bits_le(&self.y3, 255));
        for v in [
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
        ] {
            bits.extend(biguint_to_bits_le(v, 255));
        }
        bits.extend(bytes_to_bits_le(&self.sibling_hash));
        bits
    }
}

/// Evaluates the 255-bit Pasta `w = 4`-bit windowed witness-assisted complete affine EC step in Boolean gates.
/// Output wire is `[refute]` (`0` = valid transition, `1` = refuted).
pub fn eval_pasta_window_ec_step<C: CircuitContext>(
    c: &mut C,
    table: &PastaWindowTable,
    wires: &[W],
) -> Vec<W> {
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

    // Canonicality of point coordinates & witness values.
    let mut canon_checks = Vec::new();
    for field_elem in [x1, y1, x3, y3, inv, lambda, x1_sq, lam_sq, lam_dx3] {
        let (_, ge) = sub(c, field_elem, &p_bits, 255);
        canon_checks.push(not(c, ge));
    }
    let canon_ok = all_true(c, &canon_checks);

    // 16-entry generator window lookup for P2 = (inf2, x2, y2).
    let tbl_wires: [Vec<W>; 16] = std::array::from_fn(|u| {
        let mut entry = Vec::with_capacity(511);
        entry.push(if table.points[u].0 {
            garbled_snark_verifier::circuit::TRUE_WIRE
        } else {
            FALSE_WIRE
        });
        entry.extend(const_biguint_le(&table.points[u].1, 255));
        entry.extend(const_biguint_le(&table.points[u].2, 255));
        entry
    });
    let p2_packed = select_16(c, win, &tbl_wires);
    let inf2 = p2_packed[0];
    let x2 = &p2_packed[1..256];
    let y2 = &p2_packed[256..511];

    // Complete case flags:
    let x_eq = eq_vec(c, x1, x2);
    let y_sum = add_mod(c, y1, y2, &p_bits);
    let y_opp = eq_vec(c, &y_sum, &zero_bits);
    let n_inf1 = not(c, inf1);
    let n_inf2 = not(c, inf2);
    let non_inf = and(c, n_inf1, n_inf2);
    let is_inverse = all_true(c, &[non_inf, x_eq, y_opp]);
    let n_y_opp = not(c, y_opp);
    let is_double = all_true(c, &[non_inf, x_eq, n_y_opp]);
    let n_x_eq = not(c, x_eq);
    let is_chord = and(c, non_inf, n_x_eq);
    let is_slope_case = or(c, is_chord, is_double);

    // Denominator & numerator for chord vs tangent:
    let dx = sub_mod(c, x2, x1, &p_bits);
    let dy = sub_mod(c, y2, y1, &p_bits);
    let two_y1 = add_mod(c, y1, y1, &p_bits);
    let two_x1_sq = add_mod(c, x1_sq, x1_sq, &p_bits);
    let three_x1_sq = add_mod(c, &two_x1_sq, x1_sq, &p_bits);

    let den = mux_vec(c, is_double, &dx, &two_y1);
    let num = mux_vec(c, is_double, &dy, &three_x1_sq);
    // Dummy `(1, 1)` when not in slope case so modular inverse check holds cleanly without branching circuits.
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
        &[m0, m1, m2, m3, m4, slope_x_ok, slope_y_ok, slope_not_inf],
    );

    // Identity & inverse case checks:
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

    // SHA-256 authentication of `(window, inf1, inf3, x1[..14B], x3[..15B], sibling_hash)` (64 bytes -> 2 blocks).
    let mut auth_msg = Vec::with_capacity(64 * 8);
    let mut win_b = win.to_vec();
    win_b.resize(8, FALSE_WIRE);
    let mut inf1_b = vec![inf1];
    inf1_b.resize(8, FALSE_WIRE);
    let mut inf3_b = vec![inf3];
    inf3_b.resize(8, FALSE_WIRE);
    auth_msg.extend_from_slice(&win_b);
    auth_msg.extend_from_slice(&inf1_b);
    auth_msg.extend_from_slice(&inf3_b);
    auth_msg.extend_from_slice(&x1[..14 * 8]);
    auth_msg.extend_from_slice(&x3[..15 * 8]);
    auth_msg.extend_from_slice(sib);
    let digest = sha256_bytes(c, &auth_msg);
    let auth_ok = eq_vec(
        c,
        &digest[..32],
        &const_bytes_le(&table.expected_root_prefix),
    );

    let valid = all_true(c, &[canon_ok, case_ok, auth_ok]);
    vec![not(c, valid)]
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
