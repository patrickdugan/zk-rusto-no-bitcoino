//! Transparent Zero-Knowledge Nova/Spartan (`CompressedSNARK`) Soldering Certificate.
//!
//! Proves in zero knowledge over the Pallas/Vesta cycle (`nova-snark = 0.76.0` + `ipa_pc`) that
//! published Free-XOR translation parameters `(S_{j,i}, Gamma_j)` map the base retained instance's
//! Bitcoin Tapscript `OP_SHA256` hashlocks `h_tap[b][i][0..=1]` to every soldered retained
//! instance's hiding Poseidon wire commitments `R_pos[j]`, bound to `(session_id, circuit_id, nonce)`.

use std::sync::OnceLock;

use anyhow::{bail, ensure, Context, Result};
use ff::Field;
use garbled_snark_verifier::S;
use nova_snark::{
    frontend::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            num::AllocatedNum,
            poseidon::{Elt, IOPattern, Simplex, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait},
            sha256::sha256_compression_function,
            uint32::UInt32,
        },
        ConstraintSystem, LinearCombination, SynthesisError,
    },
    nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey},
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::elem::{
    bytes32_to_limbs, f_from_canonical, poseidon_constants, poseidon_hash, sha256_digest_halves,
    u128_to_f, E1, E2, F, S1, S2,
};

pub const SOLDER_BATCH_WIRES: usize = 2;
pub const PILOT_SOLDERED_INSTANCES: usize = 2; // M - 1 for M = 3 retained instances

const TAG_BIND: u64 = 0x4241_4245_534c_4401; // "BABESLD\x01"
const TAG_BASE_INIT: u64 = 0x4241_4245_4241_5301; // "BABEBAS\x01"
const TAG_POS_INIT: u64 = 0x4241_4245_504f_5301; // "BABEPOS\x01"
const TAG_POS_LBL: u64 = 0x4241_4245_4c42_4c01; // "BABELBL\x01"
const TAG_DELTA_INIT: u64 = 0x4241_4245_444c_5401; // "BABEDLT\x01"

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Raw 16-byte SHA-256 preimage hashlock directly compatible with Bitcoin Tapscript `OP_SHA256 <h> OP_EQUALVERIFY`.
pub fn tap_label_sha256(label: S) -> [u8; 32] {
    Sha256::digest(label.to_le_bytes()).into()
}

/// Deterministic domain-separated Poseidon blinding factors derived from an instance's 256-bit garbler seed.
pub fn derive_wire_blindings(
    seed: &[u8; 32],
    instance_idx: usize,
    num_wires: usize,
) -> Vec<(F, F)> {
    let mut hasher = Sha256::new();
    hasher.update(b"babe-pilot/poseidon-blinding/v1\0");
    hasher.update(seed);
    hasher.update((instance_idx as u64).to_le_bytes());
    let derived_seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha20Rng::from_seed(derived_seed);

    let mut sample_f = || -> F {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes[31] &= 0x1f; // strictly < 2^253 < p_pallas
        f_from_canonical(&bytes).expect("253-bit integer is canonical in Pallas scalar field")
    };
    (0..num_wires).map(|_| (sample_f(), sample_f())).collect()
}

/// Computes the Poseidon accumulator root over base instance `b`'s public Tapscript SHA-256 hashlock pairs.
pub fn compute_base_tap_root(
    session_id: &[u8; 32],
    circuit_id: &[u8; 32],
    instance_idx: usize,
    tap_hashes: &[([u8; 32], [u8; 32])],
) -> F {
    let sid = bytes32_to_limbs(session_id);
    let cid = bytes32_to_limbs(circuit_id);
    let mut acc = poseidon_hash(&[
        F::from(TAG_BASE_INIT),
        sid[0],
        sid[1],
        cid[0],
        cid[1],
        F::from(instance_idx as u64),
    ]);
    for (wire_idx, (h0, h1)) in tap_hashes.iter().enumerate() {
        let (h0_hi, h0_lo) = sha256_digest_halves(h0);
        let (h1_hi, h1_lo) = sha256_digest_halves(h1);
        acc = poseidon_hash(&[acc, F::from(wire_idx as u64), h0_hi, h0_lo, h1_hi, h1_lo]);
    }
    acc
}

pub fn compute_pos_label_commitment(
    sid_lo: F,
    instance_idx: usize,
    wire_idx: usize,
    bit: bool,
    label: u128,
    blinding: F,
) -> F {
    poseidon_hash(&[
        F::from(TAG_POS_LBL),
        sid_lo,
        F::from(instance_idx as u64),
        F::from(wire_idx as u64),
        F::from(u64::from(bit)),
        u128_to_f(label),
        blinding,
    ])
}

/// Computes the Poseidon accumulator root over an instance's blinded wire label commitments.
pub fn compute_pos_instance_root(
    session_id: &[u8; 32],
    circuit_id: &[u8; 32],
    instance_idx: usize,
    wires: &[(S, S)],
    blindings: &[(F, F)],
) -> F {
    assert_eq!(wires.len(), blindings.len());
    let sid = bytes32_to_limbs(session_id);
    let cid = bytes32_to_limbs(circuit_id);
    let mut acc = poseidon_hash(&[
        F::from(TAG_POS_INIT),
        sid[0],
        sid[1],
        cid[0],
        cid[1],
        F::from(instance_idx as u64),
    ]);
    for (wire_idx, ((l0, l1), (b0, b1))) in wires.iter().zip(blindings).enumerate() {
        let c0 =
            compute_pos_label_commitment(sid[0], instance_idx, wire_idx, false, l0.to_u128(), *b0);
        let c1 =
            compute_pos_label_commitment(sid[0], instance_idx, wire_idx, true, l1.to_u128(), *b1);
        acc = poseidon_hash(&[acc, c0, c1]);
    }
    acc
}

pub fn compute_binding_tag<const K: usize>(
    session_id: &[u8; 32],
    circuit_id: &[u8; 32],
    nonce: &[u8; 32],
    base_idx: usize,
    soldered_indices: &[usize; K],
    num_wires: usize,
    gammas: &[u128; K],
) -> F {
    let sid = bytes32_to_limbs(session_id);
    let cid = bytes32_to_limbs(circuit_id);
    let nlim = bytes32_to_limbs(nonce);
    let mut inputs = Vec::with_capacity(9 + 2 * K);
    inputs.push(F::from(TAG_BIND));
    inputs.push(sid[0]);
    inputs.push(sid[1]);
    inputs.push(cid[0]);
    inputs.push(cid[1]);
    inputs.push(nlim[0]);
    inputs.push(nlim[1]);
    inputs.push(F::from(base_idx as u64));
    inputs.push(F::from(num_wires as u64));
    for &j in soldered_indices {
        inputs.push(F::from(j as u64));
    }
    for &gamma in gammas {
        inputs.push(u128_to_f(gamma));
    }
    poseidon_hash(&inputs)
}

pub fn compute_delta_acc_root<const K: usize>(
    binding_tag: F,
    wire_deltas: &[[u128; K]],
    gammas: &[u128; K],
) -> F {
    let mut acc = poseidon_hash(&[F::from(TAG_DELTA_INIT), binding_tag]);
    for (wire_idx, per_inst) in wire_deltas.iter().enumerate() {
        for m in 0..K {
            acc = poseidon_hash(&[
                acc,
                F::from(wire_idx as u64),
                F::from(m as u64),
                u128_to_f(per_inst[m]),
                u128_to_f(gammas[m]),
            ]);
        }
    }
    acc
}

// ============================================================================================
// Nova R1CS Step Circuit for Relation R_solder
// ============================================================================================

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WireBatchWitness<const K: usize> {
    pub base_label0: u128,
    pub wire_deltas: [u128; K],
    #[zeroize(skip)]
    pub solder_blind0: [F; K],
    #[zeroize(skip)]
    pub solder_blind1: [F; K],
}

#[derive(Clone)]
pub struct SolderingStepCircuit<const K: usize> {
    pub sid_lo: F,
    pub soldered_indices: [usize; K],
    pub base_delta: u128,
    pub gammas: [u128; K],
    pub batch: [WireBatchWitness<K>; SOLDER_BATCH_WIRES],
}

impl<const K: usize> SolderingStepCircuit<K> {
    pub fn blank() -> Self {
        Self {
            sid_lo: F::ZERO,
            soldered_indices: [1; K],
            base_delta: 1,
            gammas: [0; K],
            batch: std::array::from_fn(|_| WireBatchWitness {
                base_label0: 0,
                wire_deltas: [0; K],
                solder_blind0: [F::ZERO; K],
                solder_blind1: [F::ZERO; K],
            }),
        }
    }
}

fn pow2(k: u32) -> F {
    F::from(2u64).pow_vartime([k as u64])
}

fn alloc_u128_bits_le<CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: u128,
) -> Result<(AllocatedNum<F>, [AllocatedBit; 128]), SynthesisError> {
    let bits: [AllocatedBit; 128] = std::array::from_fn(|i| {
        AllocatedBit::alloc(
            cs.namespace(|| format!("bit_{i}")),
            Some(((value >> i) & 1) == 1),
        )
        .expect("bit allocation")
    });
    let num = pack_bits_le_128(cs.namespace(|| "pack"), &bits)?;
    Ok((num, bits))
}

fn pack_bits_le_128<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits: &[AllocatedBit; 128],
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut lc = LinearCombination::zero();
    let mut val = 0u128;
    let mut coeff = F::ONE;
    for (i, b) in bits.iter().enumerate() {
        lc = lc + (coeff, b.get_variable());
        if b.get_value().unwrap_or(false) {
            val |= 1u128 << i;
        }
        coeff = coeff.double();
    }
    let num = AllocatedNum::alloc(cs.namespace(|| "num"), || Ok(u128_to_f(val)))?;
    cs.enforce(
        || "recompose_128",
        |zero| zero,
        |zero| zero,
        |_| lc - num.get_variable(),
    );
    Ok(num)
}

fn xor_bits_128<CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &[AllocatedBit; 128],
    b: &[AllocatedBit; 128],
) -> Result<[AllocatedBit; 128], SynthesisError> {
    let mut out_vec = Vec::with_capacity(128);
    for i in 0..128 {
        out_vec.push(AllocatedBit::xor(
            cs.namespace(|| format!("xor_{i}")),
            &a[i],
            &b[i],
        )?);
    }
    Ok(out_vec.try_into().expect("128 bits"))
}

fn enforce_nonzero<CS: ConstraintSystem<F>>(
    mut cs: CS,
    x: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let inv = AllocatedNum::alloc(cs.namespace(|| "inv"), || {
        let xv = x.get_value().unwrap_or(F::ONE);
        Ok(xv.invert().unwrap_or(F::ONE))
    })?;
    cs.enforce(
        || "x_times_inv_eq_1",
        |lc| lc + x.get_variable(),
        |lc| lc + inv.get_variable(),
        |lc| lc + CS::one(),
    );
    Ok(())
}

/// Computes `SHA256(label_le16)` inside R1CS from 128 little-endian bits, returning `(hi_be, lo_be)` matching `sha256_digest_halves`.
fn sha256_label16_halves_gadget<CS: ConstraintSystem<F>>(
    mut cs: CS,
    le_bits: &[AllocatedBit; 128],
) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError> {
    let mut pad_tail = [0u8; 48];
    pad_tail[0] = 0x80;
    pad_tail[47] = 0x80; // 128-bit message length in big-endian u64 = 0x0000_0000_0000_0080

    let mut block_bits = Vec::with_capacity(512);
    for byte_idx in 0..16 {
        for bit_in_byte in 0..8 {
            // SHA-256 reads each byte MSB-first: `(byte >> (7 - bit_in_byte)) & 1`.
            let le_idx = byte_idx * 8 + (7 - bit_in_byte);
            block_bits.push(Boolean::from(le_bits[le_idx].clone()));
        }
    }
    for j in 0..(48 * 8) {
        let bit = ((pad_tail[j / 8] >> (7 - (j % 8))) & 1) == 1;
        block_bits.push(Boolean::constant(bit));
    }

    let iv_words: Vec<UInt32> = SHA256_IV.iter().map(|&w| UInt32::constant(w)).collect();
    let digest_words =
        sha256_compression_function(cs.namespace(|| "sha256_block"), &block_bits, &iv_words)?;

    let mut halves = Vec::with_capacity(2);
    for (h_idx, four_words) in digest_words.chunks_exact(4).enumerate() {
        let bits_be: Vec<Boolean> = four_words
            .iter()
            .flat_map(|w| w.clone().into_bits_be())
            .collect();
        let mut lc = LinearCombination::zero();
        let mut val = F::ZERO;
        for (j, b) in bits_be.iter().enumerate() {
            let c = pow2(127 - j as u32);
            lc = b.lc(CS::one(), c) + &lc;
            if b.get_value().unwrap_or(false) {
                val += c;
            }
        }
        let num = AllocatedNum::alloc(cs.namespace(|| format!("half_{h_idx}")), || Ok(val))?;
        cs.enforce(
            || format!("half_pack_{h_idx}"),
            |zero| zero,
            |zero| zero,
            |_| lc - num.get_variable(),
        );
        halves.push(num);
    }
    Ok((halves[0].clone(), halves[1].clone()))
}

fn poseidon_gadget<CS: ConstraintSystem<F>>(
    mut cs: CS,
    xs: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut ns = cs.namespace(|| "poseidon");
    let mut sponge = SpongeCircuit::new_with_constants(poseidon_constants(), Simplex);
    sponge.start(
        IOPattern(vec![
            SpongeOp::Absorb(xs.len() as u32),
            SpongeOp::Squeeze(1),
        ]),
        None,
        &mut ns,
    );
    let elts: Vec<Elt<F>> = xs.iter().cloned().map(Elt::Allocated).collect();
    SpongeAPI::absorb(&mut sponge, elts.len() as u32, &elts, &mut ns);
    let out = SpongeAPI::squeeze(&mut sponge, 1, &mut ns);
    sponge
        .finish(&mut ns)
        .expect("Poseidon circuit sponge finish");
    let squeezed = Elt::ensure_allocated(&out[0], &mut ns.namespace(|| "squeeze_out"))?;
    Ok(squeezed)
}

fn alloc_const<CS: ConstraintSystem<F>>(
    mut cs: CS,
    val: F,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let a = AllocatedNum::alloc(cs.namespace(|| "c"), || Ok(val))?;
    cs.enforce(
        || "eq_const",
        |lc| lc + a.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (val, CS::one()),
    );
    Ok(a)
}

impl<const K: usize> StepCircuit<F> for SolderingStepCircuit<K> {
    fn arity(&self) -> usize {
        4 + K
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(z.len(), 4 + K);
        let binding_tag = z[0].clone();
        let mut cursor = z[1].clone();
        let mut base_tap_acc = z[2].clone();
        let mut solder_accs: [AllocatedNum<F>; K] = std::array::from_fn(|m| z[3 + m].clone());
        let mut delta_acc = z[3 + K].clone();

        let tag_pos_lbl = alloc_const(cs.namespace(|| "tag_pos_lbl"), F::from(TAG_POS_LBL))?;
        let zero_const = alloc_const(cs.namespace(|| "zero_const"), F::ZERO)?;
        let one_const = alloc_const(cs.namespace(|| "one_const"), F::ONE)?;
        let sid_lo = AllocatedNum::alloc(cs.namespace(|| "sid_lo"), || Ok(self.sid_lo))?;

        let (base_delta_num, base_delta_bits) =
            alloc_u128_bits_le(cs.namespace(|| "base_delta"), self.base_delta)?;
        enforce_nonzero(cs.namespace(|| "base_delta_nz"), &base_delta_num)?;

        let mut gamma_nums = Vec::with_capacity(K);
        let mut solder_delta_bits = Vec::with_capacity(K);
        let mut solder_idx_nums = Vec::with_capacity(K);
        for m in 0..K {
            let (g_num, g_bits) =
                alloc_u128_bits_le(cs.namespace(|| format!("gamma_{m}")), self.gammas[m])?;
            let dj_bits = xor_bits_128(
                cs.namespace(|| format!("delta_j_xor_{m}")),
                &base_delta_bits,
                &g_bits,
            )?;
            let dj_num = pack_bits_le_128(cs.namespace(|| format!("delta_j_pack_{m}")), &dj_bits)?;
            enforce_nonzero(cs.namespace(|| format!("delta_j_nz_{m}")), &dj_num)?;
            let j_num = AllocatedNum::alloc(cs.namespace(|| format!("solder_idx_{m}")), || {
                Ok(F::from(self.soldered_indices[m] as u64))
            })?;
            gamma_nums.push(g_num);
            solder_delta_bits.push(dj_bits);
            solder_idx_nums.push(j_num);
        }

        let m_consts: [AllocatedNum<F>; K] = std::array::from_fn(|m| {
            alloc_const(cs.namespace(|| format!("m_const_{m}")), F::from(m as u64))
                .expect("const m")
        });

        for slot in 0..SOLDER_BATCH_WIRES {
            let w = &self.batch[slot];
            let wire_idx = cursor.clone();

            // 1. Base labels L_{b,i,0} and L_{b,i,1} = L_{b,i,0} ^ Delta_b, hashed via SHA-256.
            let (_, lb0_bits) =
                alloc_u128_bits_le(cs.namespace(|| format!("w{slot}_lb0")), w.base_label0)?;
            let lb1_bits = xor_bits_128(
                cs.namespace(|| format!("w{slot}_lb1_xor")),
                &lb0_bits,
                &base_delta_bits,
            )?;
            let (h0_hi, h0_lo) =
                sha256_label16_halves_gadget(cs.namespace(|| format!("w{slot}_sha0")), &lb0_bits)?;
            let (h1_hi, h1_lo) =
                sha256_label16_halves_gadget(cs.namespace(|| format!("w{slot}_sha1")), &lb1_bits)?;

            base_tap_acc = poseidon_gadget(
                cs.namespace(|| format!("w{slot}_base_acc")),
                &[base_tap_acc, wire_idx.clone(), h0_hi, h0_lo, h1_hi, h1_lo],
            )?;

            // 2. Soldered translations and blinded Poseidon commitments for each retained instance m in 0..K.
            for m in 0..K {
                let (s_num, s_bits) = alloc_u128_bits_le(
                    cs.namespace(|| format!("w{slot}_m{m}_s")),
                    w.wire_deltas[m],
                )?;
                let lj0_bits = xor_bits_128(
                    cs.namespace(|| format!("w{slot}_m{m}_lj0_xor")),
                    &lb0_bits,
                    &s_bits,
                )?;
                let lj1_bits = xor_bits_128(
                    cs.namespace(|| format!("w{slot}_m{m}_lj1_xor")),
                    &lj0_bits,
                    &solder_delta_bits[m],
                )?;
                let lj0_num =
                    pack_bits_le_128(cs.namespace(|| format!("w{slot}_m{m}_lj0_num")), &lj0_bits)?;
                let lj1_num =
                    pack_bits_le_128(cs.namespace(|| format!("w{slot}_m{m}_lj1_num")), &lj1_bits)?;

                let blind0 =
                    AllocatedNum::alloc(cs.namespace(|| format!("w{slot}_m{m}_b0")), || {
                        Ok(w.solder_blind0[m])
                    })?;
                let blind1 =
                    AllocatedNum::alloc(cs.namespace(|| format!("w{slot}_m{m}_b1")), || {
                        Ok(w.solder_blind1[m])
                    })?;

                let c0 = poseidon_gadget(
                    cs.namespace(|| format!("w{slot}_m{m}_c0")),
                    &[
                        tag_pos_lbl.clone(),
                        sid_lo.clone(),
                        solder_idx_nums[m].clone(),
                        wire_idx.clone(),
                        zero_const.clone(),
                        lj0_num,
                        blind0,
                    ],
                )?;
                let c1 = poseidon_gadget(
                    cs.namespace(|| format!("w{slot}_m{m}_c1")),
                    &[
                        tag_pos_lbl.clone(),
                        sid_lo.clone(),
                        solder_idx_nums[m].clone(),
                        wire_idx.clone(),
                        one_const.clone(),
                        lj1_num,
                        blind1,
                    ],
                )?;
                solder_accs[m] = poseidon_gadget(
                    cs.namespace(|| format!("w{slot}_m{m}_pos_acc")),
                    &[solder_accs[m].clone(), c0, c1],
                )?;

                delta_acc = poseidon_gadget(
                    cs.namespace(|| format!("w{slot}_m{m}_delta_acc")),
                    &[
                        delta_acc,
                        wire_idx.clone(),
                        m_consts[m].clone(),
                        s_num,
                        gamma_nums[m].clone(),
                    ],
                )?;
            }

            // Increment wire cursor by 1:
            let next_cursor =
                AllocatedNum::alloc(cs.namespace(|| format!("w{slot}_cursor_next")), || {
                    Ok(cursor.get_value().unwrap_or(F::ZERO) + F::ONE)
                })?;
            cs.enforce(
                || format!("w{slot}_cursor_inc"),
                |lc| lc + cursor.get_variable() + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + next_cursor.get_variable(),
            );
            cursor = next_cursor;
        }

        let mut out = Vec::with_capacity(4 + K);
        out.push(binding_tag);
        out.push(cursor);
        out.push(base_tap_acc);
        for acc in solder_accs {
            out.push(acc);
        }
        out.push(delta_acc);
        Ok(out)
    }
}

// ============================================================================================
// Public Certificate, Cached Transparent Keys, Prover, and Verifier
// ============================================================================================

type PilotStep = SolderingStepCircuit<PILOT_SOLDERED_INSTANCES>;
type PpPilot = PublicParams<E1, E2, PilotStep>;
type RsPilot = RecursiveSNARK<E1, E2, PilotStep>;
type CsPilot = CompressedSNARK<E1, E2, PilotStep, S1, S2>;

pub struct SolderingKeys {
    pub pp: PpPilot,
    pub pk: ProverKey<E1, E2, PilotStep, S1, S2>,
    pub vk: VerifierKey<E1, E2, PilotStep, S1, S2>,
    pub setup_pp_seconds: f64,
    pub setup_cs_seconds: f64,
}

pub fn pilot_soldering_keys() -> &'static SolderingKeys {
    static KEYS: OnceLock<SolderingKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let t0 = std::time::Instant::now();
        let pp = PpPilot::setup(&PilotStep::blank(), &*S1::ck_floor(), &*S2::ck_floor())
            .expect("transparent Nova PublicParams setup");
        let setup_pp_seconds = t0.elapsed().as_secs_f64();
        let t1 = std::time::Instant::now();
        let (pk, vk) = CsPilot::setup(&pp).expect("transparent Spartan/IPA CompressedSNARK setup");
        let setup_cs_seconds = t1.elapsed().as_secs_f64();
        SolderingKeys {
            pp,
            pk,
            vk,
            setup_pp_seconds,
            setup_cs_seconds,
        }
    })
}

/// Returns `(primary_constraints, secondary_constraints)` of `PilotStep`.
pub fn step_constraint_counts() -> (usize, usize) {
    pilot_soldering_keys().pp.num_constraints()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolderingCertificate {
    pub base_index: usize,
    pub soldered_indices: [usize; PILOT_SOLDERED_INSTANCES],
    pub num_wires: usize,
    /// Per-instance Free-XOR global offset translations `Gamma_m = Delta_{j_m} ^ Delta_b`.
    pub gammas: [u128; PILOT_SOLDERED_INSTANCES],
    /// Per-wire base-0 label translations `S_{j_m, i} = L_{j_m, i, 0} ^ L_{b, i, 0}`.
    pub wire_deltas: Vec<[u128; PILOT_SOLDERED_INSTANCES]>,
    /// Serialized zero-knowledge `CompressedSNARK` over Pallas/Vesta with Spartan/IPA.
    pub compressed_snark_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolderingTimings {
    pub num_steps: usize,
    pub primary_constraints: usize,
    pub secondary_constraints: usize,
    pub setup_pp_seconds: f64,
    pub setup_cs_seconds: f64,
    pub recursive_fold_seconds: f64,
    pub compress_prove_seconds: f64,
    pub verify_seconds: f64,
    pub proof_bytes: usize,
    pub vk_bytes: usize,
}

/// Secret garbler witness used exclusively to generate `SolderingCertificate` (never shared with evaluator).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GarblerSolderingSecret {
    pub base_delta: u128,
    pub base_labels0: Vec<u128>,
    pub soldered_deltas: [u128; PILOT_SOLDERED_INSTANCES],
    pub soldered_labels0: Vec<[u128; PILOT_SOLDERED_INSTANCES]>,
    #[zeroize(skip)]
    pub soldered_blindings: [Vec<(F, F)>; PILOT_SOLDERED_INSTANCES],
}

pub fn initial_soldering_state(
    session_id: &[u8; 32],
    circuit_id: &[u8; 32],
    nonce: &[u8; 32],
    base_idx: usize,
    soldered_indices: &[usize; PILOT_SOLDERED_INSTANCES],
    num_wires: usize,
    gammas: &[u128; PILOT_SOLDERED_INSTANCES],
) -> Vec<F> {
    let sid = bytes32_to_limbs(session_id);
    let cid = bytes32_to_limbs(circuit_id);
    let binding_tag = compute_binding_tag(
        session_id,
        circuit_id,
        nonce,
        base_idx,
        soldered_indices,
        num_wires,
        gammas,
    );
    let base_init = poseidon_hash(&[
        F::from(TAG_BASE_INIT),
        sid[0],
        sid[1],
        cid[0],
        cid[1],
        F::from(base_idx as u64),
    ]);
    let pos_inits: [F; PILOT_SOLDERED_INSTANCES] = std::array::from_fn(|m| {
        poseidon_hash(&[
            F::from(TAG_POS_INIT),
            sid[0],
            sid[1],
            cid[0],
            cid[1],
            F::from(soldered_indices[m] as u64),
        ])
    });
    let delta_init = poseidon_hash(&[F::from(TAG_DELTA_INIT), binding_tag]);

    let mut z0 = Vec::with_capacity(4 + PILOT_SOLDERED_INSTANCES);
    z0.push(binding_tag);
    z0.push(F::ZERO);
    z0.push(base_init);
    for p in pos_inits {
        z0.push(p);
    }
    z0.push(delta_init);
    z0
}

pub fn prove_soldering_certificate(
    session_id: &[u8; 32],
    circuit_id: &[u8; 32],
    nonce: &[u8; 32],
    base_idx: usize,
    soldered_indices: [usize; PILOT_SOLDERED_INSTANCES],
    secret: &GarblerSolderingSecret,
) -> Result<(SolderingCertificate, SolderingTimings)> {
    let num_wires = secret.base_labels0.len();
    ensure!(
        num_wires > 0 && num_wires.is_multiple_of(SOLDER_BATCH_WIRES),
        "wire count {num_wires} must be a positive multiple of {SOLDER_BATCH_WIRES}"
    );
    ensure!(
        secret.soldered_labels0.len() == num_wires,
        "soldered label length mismatch"
    );
    for m in 0..PILOT_SOLDERED_INSTANCES {
        ensure!(
            secret.soldered_blindings[m].len() == num_wires,
            "blinding count mismatch for soldered instance {m}"
        );
    }

    let gammas: [u128; PILOT_SOLDERED_INSTANCES] =
        std::array::from_fn(|m| secret.soldered_deltas[m] ^ secret.base_delta);
    let wire_deltas: Vec<[u128; PILOT_SOLDERED_INSTANCES]> = (0..num_wires)
        .map(|i| std::array::from_fn(|m| secret.soldered_labels0[i][m] ^ secret.base_labels0[i]))
        .collect();

    let sid = bytes32_to_limbs(session_id);
    let num_steps = num_wires / SOLDER_BATCH_WIRES;
    let steps: Vec<PilotStep> = (0..num_steps)
        .map(|step_idx| {
            let batch: [WireBatchWitness<PILOT_SOLDERED_INSTANCES>; SOLDER_BATCH_WIRES] =
                std::array::from_fn(|slot| {
                    let i = step_idx * SOLDER_BATCH_WIRES + slot;
                    WireBatchWitness {
                        base_label0: secret.base_labels0[i],
                        wire_deltas: wire_deltas[i],
                        solder_blind0: std::array::from_fn(|m| secret.soldered_blindings[m][i].0),
                        solder_blind1: std::array::from_fn(|m| secret.soldered_blindings[m][i].1),
                    }
                });
            SolderingStepCircuit {
                sid_lo: sid[0],
                soldered_indices,
                base_delta: secret.base_delta,
                gammas,
                batch,
            }
        })
        .collect();

    let keys = pilot_soldering_keys();
    let z0 = initial_soldering_state(
        session_id,
        circuit_id,
        nonce,
        base_idx,
        &soldered_indices,
        num_wires,
        &gammas,
    );

    let t_fold = std::time::Instant::now();
    let mut rs = RsPilot::new(&keys.pp, &steps[0], &z0)
        .map_err(|e| anyhow::anyhow!("RecursiveSNARK::new failed: {e:?}"))?;
    for (idx, step) in steps.iter().enumerate() {
        rs.prove_step(&keys.pp, step)
            .map_err(|e| anyhow::anyhow!("RecursiveSNARK::prove_step {idx} failed: {e:?}"))?;
    }
    let recursive_fold_seconds = t_fold.elapsed().as_secs_f64();

    let t_comp = std::time::Instant::now();
    let compressed = CsPilot::prove(&keys.pp, &keys.pk, &rs)
        .map_err(|e| anyhow::anyhow!("CompressedSNARK::prove failed: {e:?}"))?;
    let compress_prove_seconds = t_comp.elapsed().as_secs_f64();

    let compressed_snark_bytes =
        bincode::serialize(&compressed).context("serialize CompressedSNARK")?;
    let proof_bytes = compressed_snark_bytes.len();
    let vk_bytes = bincode::serialize(&keys.vk)
        .context("serialize VerifierKey")?
        .len();
    let (primary_constraints, secondary_constraints) = keys.pp.num_constraints();

    let cert = SolderingCertificate {
        base_index: base_idx,
        soldered_indices,
        num_wires,
        gammas,
        wire_deltas,
        compressed_snark_bytes,
    };

    Ok((
        cert,
        SolderingTimings {
            num_steps,
            primary_constraints,
            secondary_constraints,
            setup_pp_seconds: keys.setup_pp_seconds,
            setup_cs_seconds: keys.setup_cs_seconds,
            recursive_fold_seconds,
            compress_prove_seconds,
            verify_seconds: 0.0,
            proof_bytes,
            vk_bytes,
        },
    ))
}

/// Independently verifies `SolderingCertificate` against public setup roots and session parameters.
/// Uses ONLY public information (no seeds, deltas, or secret wire labels).
#[allow(clippy::too_many_arguments)]
pub fn verify_soldering_certificate(
    session_id: &[u8; 32],
    circuit_id: &[u8; 32],
    nonce: &[u8; 32],
    expected_base_idx: usize,
    expected_soldered_indices: [usize; PILOT_SOLDERED_INSTANCES],
    expected_num_wires: usize,
    expected_base_tap_root: F,
    expected_soldered_pos_roots: [F; PILOT_SOLDERED_INSTANCES],
    cert: &SolderingCertificate,
) -> Result<f64> {
    ensure!(
        cert.base_index == expected_base_idx,
        "certificate base instance index mismatch"
    );
    ensure!(
        cert.soldered_indices == expected_soldered_indices,
        "certificate soldered instance indices mismatch"
    );
    ensure!(
        cert.num_wires == expected_num_wires && cert.wire_deltas.len() == expected_num_wires,
        "certificate wire count mismatch"
    );
    ensure!(
        expected_num_wires > 0 && expected_num_wires.is_multiple_of(SOLDER_BATCH_WIRES),
        "unsupported wire batch alignment"
    );
    ensure!(
        cert.compressed_snark_bytes.len() <= 4 * 1024 * 1024,
        "CompressedSNARK exceeds bounded size limit"
    );

    let keys = pilot_soldering_keys();
    let proof: CsPilot = bincode::deserialize(&cert.compressed_snark_bytes)
        .context("malformed CompressedSNARK bytes")?;

    let z0 = initial_soldering_state(
        session_id,
        circuit_id,
        nonce,
        expected_base_idx,
        &expected_soldered_indices,
        expected_num_wires,
        &cert.gammas,
    );
    let expected_delta_acc = compute_delta_acc_root(z0[0], &cert.wire_deltas, &cert.gammas);
    let num_steps = expected_num_wires / SOLDER_BATCH_WIRES;

    let t0 = std::time::Instant::now();
    let zn = match proof.verify(&keys.vk, num_steps, &z0) {
        Ok(zn) => zn,
        Err(e) => bail!("CompressedSNARK cryptographic verification failed: {e:?}"),
    };
    let verify_seconds = t0.elapsed().as_secs_f64();

    ensure!(
        zn.len() == 4 + PILOT_SOLDERED_INSTANCES,
        "unexpected zn arity"
    );
    ensure!(zn[0] == z0[0], "binding tag mutated across IVC steps");
    ensure!(
        zn[1] == F::from(expected_num_wires as u64),
        "final wire cursor mismatch"
    );
    ensure!(
        zn[2] == expected_base_tap_root,
        "base Tapscript SHA-256 commitment root mismatch"
    );
    for m in 0..PILOT_SOLDERED_INSTANCES {
        ensure!(
            zn[3 + m] == expected_soldered_pos_roots[m],
            "soldered Poseidon commitment root mismatch at slot {m}"
        );
    }
    ensure!(
        zn[3 + PILOT_SOLDERED_INSTANCES] == expected_delta_acc,
        "published translation deltas do not match ZK certificate accumulator"
    );
    Ok(verify_seconds)
}

/// Pure public unsoldering transform: given base active labels `{L_{b,i,x_i}}` for input `x`,
/// derives active labels `{L_{j_m,i,x_i}}` for soldered retained slot `m`.
pub fn unsolder_active_labels(
    base_active_labels: &[S],
    input_bits: &[bool],
    cert: &SolderingCertificate,
    slot: usize,
) -> Result<Vec<S>> {
    ensure!(slot < PILOT_SOLDERED_INSTANCES, "invalid soldered slot");
    ensure!(
        base_active_labels.len() == cert.num_wires && input_bits.len() == cert.num_wires,
        "active label / input bit count mismatch"
    );
    let gamma = S::from_u128(cert.gammas[slot]);
    Ok((0..cert.num_wires)
        .map(|i| {
            let s_delta = S::from_u128(cert.wire_deltas[i][slot]);
            let mut translated = base_active_labels[i] ^ &s_delta;
            if input_bits[i] {
                translated ^= &gamma;
            }
            translated
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;

    use super::*;

    #[test]
    fn sha256_label16_gadget_matches_native_sha2() {
        let sample = S::from_u128(0xdead_beef_cafe_babe_0123_4567_89ab_cdef);
        let expected_digest = tap_label_sha256(sample);
        let (exp_hi, exp_lo) = sha256_digest_halves(&expected_digest);

        let mut cs = TestConstraintSystem::<F>::new();
        let (_, bits) = alloc_u128_bits_le(cs.namespace(|| "lbl"), sample.to_u128()).unwrap();
        let (got_hi, got_lo) = sha256_label16_halves_gadget(cs.namespace(|| "sha"), &bits).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(got_hi.get_value().unwrap(), exp_hi);
        assert_eq!(got_lo.get_value().unwrap(), exp_lo);
    }
}
