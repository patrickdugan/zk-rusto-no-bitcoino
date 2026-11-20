//! Optional single-signature BIP340 experiment over Nova's Secq/Secp cycle.
//!
//! The primary scalar field is secp256k1's base field. This lets the circuit
//! reuse Nova 0.76's `AllocatedPoint<Secp256k1Engine>` rather than implement
//! foreign-field elliptic-curve arithmetic. The relation verifies one BIP340
//! signature for an exact 32-byte message and commits to the key, message and
//! signature with SHA256. Every signature check is inside R1CS.
//!
//! This is a separate proof statement from the Pallas settlement fold. It does
//! not prove that the key belongs to a DLC party or oracle, derive an application
//! message from a DLC summary, or authenticate the LNMarkets journal. Those
//! bindings require an additional constrained relation and a pinned composite
//! verifier. It also does not prove a Bitcoin spend or an adaptor signature.
//!
//! `SignatureStep` permits exactly one step from `[0, 0, 0]`; its output is
//! `[1, claim_hash_low128, claim_hash_high128]`. Claim hash halves follow the
//! existing LNMarkets little-endian byte convention. The claim is:
//! `SHA256(CLAIM_DOMAIN || key32 || message32 || signature64)`.
//!
//! The byte inputs are private circuit witnesses. A receiver must independently
//! pin the verifier key, one-step count, zero initial state and expected claim.
//! Publishing a proof under a prover-supplied verifier key establishes no
//! application authorization. Privacy of a later composite proof needs its own
//! review; the claim hash exposes a deterministic commitment to its inputs.

use ff::{Field, PrimeFieldBits};
use nova_snark::frontend::gadgets::boolean::{AllocatedBit, Boolean};
use nova_snark::frontend::gadgets::num::AllocatedNum;
use nova_snark::frontend::gadgets::sha256::sha256;
use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::gadgets::ecc::AllocatedPoint;
use nova_snark::gadgets::utils::{alloc_constant, alloc_zero};
use nova_snark::provider::traits::DlogGroup;
use nova_snark::provider::{Secp256k1Engine, Secq256k1Engine};
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::{Engine, Group};

/// Secq's scalar field equals the base field of secp256k1.
pub type F = <Secq256k1Engine as Engine>::Scalar;
type SecpPoint = <Secp256k1Engine as Engine>::GE;
type PointVar = AllocatedPoint<Secp256k1Engine>;

pub const STATE_ARITY: usize = 3;
pub const CLAIM_DOMAIN: &[u8] = b"UTXORef/LNMarkets/Nova/BIP340/claim/v1";
const ORDER_MINUS_ONE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
];

#[derive(Clone, Debug)]
pub struct SignatureWitness {
    pub public_key: [u8; 32],
    pub message: [u8; 32],
    pub signature: [u8; 64],
}

impl Default for SignatureWitness {
    /// Public BIP340 vector 0, also used as the fixed circuit-shape witness.
    fn default() -> Self {
        Self {
            public_key: decode_hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
            message: [0; 32],
            signature: decode_hex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
        }
    }
}

fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex)
        .expect("literal hex")
        .try_into()
        .expect("literal length")
}

fn field_from_be(bytes: &[u8]) -> F {
    bytes
        .iter()
        .fold(F::ZERO, |n, b| n * F::from(256) + F::from(u64::from(*b)))
}

fn field_from_le(bytes: &[u8]) -> F {
    bytes
        .iter()
        .rev()
        .fold(F::ZERO, |n, b| n * F::from(256) + F::from(u64::from(*b)))
}

/// The native commitment is only an expected public input, not a signature proof.
pub fn signature_claim(witness: &SignatureWitness) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(CLAIM_DOMAIN.len() + 128);
    bytes.extend_from_slice(CLAIM_DOMAIN);
    bytes.extend_from_slice(&witness.public_key);
    bytes.extend_from_slice(&witness.message);
    bytes.extend_from_slice(&witness.signature);
    lnm_batch_statement::sha256(&bytes)
}

pub fn initial_state() -> [F; STATE_ARITY] {
    [F::ZERO; STATE_ARITY]
}

pub fn expected_final_state(witness: &SignatureWitness) -> [F; STATE_ARITY] {
    let claim = signature_claim(witness);
    [
        F::ONE,
        field_from_le(&claim[..16]),
        field_from_le(&claim[16..]),
    ]
}

fn constant_bytes(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|b| {
            (0..8)
                .rev()
                .map(move |i| Boolean::constant((b >> i) & 1 == 1))
        })
        .collect()
}

fn allocate_bytes<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bytes: &[u8],
) -> Result<Vec<Boolean>, SynthesisError> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .enumerate()
        .map(|(i, value)| {
            AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some(value)).map(Boolean::from)
        })
        .collect()
}

fn equal_bits<CS: ConstraintSystem<F>>(
    mut cs: CS,
    left: &[Boolean],
    right: &[Boolean],
) -> Result<(), SynthesisError> {
    assert_eq!(left.len(), right.len());
    for (i, (a, b)) in left.iter().zip(right).enumerate() {
        Boolean::enforce_equal(cs.namespace(|| format!("bit {i}")), a, b)?;
    }
    Ok(())
}

/// Compare bytes as integers, without reducing a 256-bit encoding in Fp.
fn constrain_s_below_order<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits_be: &[Boolean],
) -> Result<(), SynthesisError> {
    assert_eq!(bits_be.len(), 256);
    let limit = constant_bytes(&ORDER_MINUS_ONE);
    let mut equal_prefix = Boolean::constant(true);
    for (i, (actual, bound)) in bits_be.iter().zip(limit).enumerate() {
        if bound.get_value() == Some(true) {
            equal_prefix = Boolean::and(
                cs.namespace(|| format!("equal prefix {i}")),
                &equal_prefix,
                actual,
            )?;
        } else {
            let forbidden = Boolean::and(
                cs.namespace(|| format!("above bound {i}")),
                &equal_prefix,
                actual,
            )?;
            Boolean::enforce_equal(
                cs.namespace(|| format!("reject above bound {i}")),
                &forbidden,
                &Boolean::constant(false),
            )?;
        }
    }
    Ok(())
}

fn canonical_encoding<CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    bytes_be: &[Boolean],
) -> Result<(), SynthesisError> {
    let mut canonical = value.to_bits_le_strict(cs.namespace(|| "canonical field bits"))?;
    canonical.reverse();
    equal_bits(cs.namespace(|| "same bytes"), &canonical, bytes_be)
}

fn force_noninfinity<CS: ConstraintSystem<F>>(mut cs: CS, point: &PointVar) {
    cs.enforce(
        || "finite point",
        |lc| lc + point.is_infinity.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
}

fn force_even_y<CS: ConstraintSystem<F>>(
    mut cs: CS,
    point: &PointVar,
) -> Result<(), SynthesisError> {
    let y = point
        .y
        .to_bits_le_strict(cs.namespace(|| "canonical y bits"))?;
    Boolean::enforce_equal(cs.namespace(|| "even y"), &y[0], &Boolean::constant(false))
}

/// Normalize SHA Boolean expressions to constrained bits required by Nova's ECC API.
fn allocated_scalar_bits<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits_be: &[Boolean],
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    assert_eq!(bits_be.len(), 256);
    bits_be
        .iter()
        .rev()
        .enumerate()
        .map(|(i, source)| {
            let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), source.get_value())?;
            Boolean::enforce_equal(
                cs.namespace(|| format!("bind bit {i}")),
                &Boolean::from(bit.clone()),
                source,
            )?;
            Ok(bit)
        })
        .collect()
}

fn digest_halves<CS: ConstraintSystem<F>>(
    mut cs: CS,
    digest_be: &[Boolean],
) -> Result<[AllocatedNum<F>; 2], SynthesisError> {
    assert_eq!(digest_be.len(), 256);
    let mut halves = Vec::with_capacity(2);
    for (half, bits) in digest_be.as_chunks::<128>().0.iter().enumerate() {
        // SHA exposes big-endian bits per byte; each 16-byte half is interpreted
        // little-endian for the LNMarkets journal convention.
        let bits_le: Vec<_> = bits
            .as_chunks::<8>()
            .0
            .iter()
            .flat_map(|byte| byte.iter().rev())
            .collect();
        let mut value = F::ZERO;
        let mut coefficient = F::ONE;
        let mut lc = LinearCombination::zero();
        for bit in bits_le {
            if bit.get_value().unwrap_or(false) {
                value += coefficient;
            }
            lc = lc + &bit.lc(CS::one(), coefficient);
            coefficient = coefficient.double();
        }
        let number = AllocatedNum::alloc(cs.namespace(|| format!("half {half}")), || Ok(value))?;
        cs.enforce(
            || format!("bind half {half}"),
            |_| lc,
            |lc| lc + CS::one(),
            |lc| lc + number.get_variable(),
        );
        halves.push(number);
    }
    Ok(halves.try_into().expect("two digest halves"))
}

/// Verify one BIP340 signature and return a SHA256 commitment to its exact bytes.
///
/// The native point lift supplies witness values only. Canonical x bytes, curve
/// membership, even y and non-infinity are independently constrained. Invalid
/// public-key encodings still produce a complete unsatisfied R1CS assignment.
pub fn verify_gadget<CS: ConstraintSystem<F>>(
    mut cs: CS,
    witness: &SignatureWitness,
) -> Result<[AllocatedNum<F>; 2], SynthesisError> {
    let key_bits = allocate_bytes(cs.namespace(|| "public key bytes"), &witness.public_key)?;
    let message_bits = allocate_bytes(cs.namespace(|| "message bytes"), &witness.message)?;
    let signature_bits = allocate_bytes(cs.namespace(|| "signature bytes"), &witness.signature)?;
    let (r_bits, s_bits) = signature_bits.split_at(256);
    constrain_s_below_order(cs.namespace(|| "canonical s"), s_bits)?;

    let (gx, gy, _) = SecpPoint::gen().to_coordinates();
    let x = field_from_be(&witness.public_key);
    let (a, b, _, _) = SecpPoint::group_params();
    let y = Option::<F>::from((x.square() * x + a * x + b).sqrt());
    let (px, mut py) = y.map_or((gx, gy), |y| (x, y));
    if py.to_le_bits()[0] {
        py = -py;
    }
    let public_key = PointVar::alloc(cs.namespace(|| "public key point"), Some((px, py, false)))?;
    force_noninfinity(cs.namespace(|| "public key finite"), &public_key);
    public_key.check_on_curve(cs.namespace(|| "public key on curve"))?;
    canonical_encoding(
        cs.namespace(|| "public key encoding"),
        &public_key.x,
        &key_bits,
    )?;
    force_even_y(cs.namespace(|| "public key parity"), &public_key)?;

    let tag = lnm_batch_statement::sha256(b"BIP0340/challenge");
    let mut challenge_input = constant_bytes(&tag);
    challenge_input.extend(constant_bytes(&tag));
    challenge_input.extend_from_slice(r_bits);
    challenge_input.extend_from_slice(&key_bits);
    challenge_input.extend_from_slice(&message_bits);
    let challenge = sha256(cs.namespace(|| "challenge hash"), &challenge_input)?;
    let challenge_bits = allocated_scalar_bits(cs.namespace(|| "challenge scalar"), &challenge)?;
    let scalar_bits = allocated_scalar_bits(cs.namespace(|| "signature scalar"), s_bits)?;

    // All 256 challenge bits are used. Since P has order n, multiplying by the
    // unreduced integer equals multiplying by that integer modulo n. The input
    // message is hashed as bytes and is never reduced modulo either field.
    let zero = alloc_zero(cs.namespace(|| "generator finite"));
    let generator = PointVar::alloc_constant(cs.namespace(|| "generator"), (gx, gy), zero)?;
    let s_g = generator.scalar_mul(cs.namespace(|| "s times G"), &scalar_bits)?;
    let e_p = public_key.scalar_mul(cs.namespace(|| "e times P"), &challenge_bits)?;
    let neg_e_p = e_p.negate(cs.namespace(|| "negate eP"))?;
    let r = s_g.add(cs.namespace(|| "sG minus eP"), &neg_e_p)?;
    force_noninfinity(cs.namespace(|| "result finite"), &r);
    canonical_encoding(cs.namespace(|| "result x encoding"), &r.x, r_bits)?;
    force_even_y(cs.namespace(|| "result parity"), &r)?;

    let mut claim = constant_bytes(CLAIM_DOMAIN);
    claim.extend(key_bits);
    claim.extend(message_bits);
    claim.extend(signature_bits);
    let digest = sha256(cs.namespace(|| "signature claim"), &claim)?;
    digest_halves(cs.namespace(|| "claim output"), &digest)
}

#[derive(Clone, Debug, Default)]
pub struct SignatureStep {
    pub witness: SignatureWitness,
}

impl StepCircuit<F> for SignatureStep {
    fn arity(&self) -> usize {
        STATE_ARITY
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        if z.len() != STATE_ARITY {
            return Err(SynthesisError::Unsatisfiable(
                "expected three BIP340 state limbs".into(),
            ));
        }
        for (i, value) in z.iter().enumerate() {
            cs.enforce(
                || format!("one-shot initial state {i}"),
                |lc| lc + value.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );
        }
        let claim = verify_gadget(cs.namespace(|| "bip340"), &self.witness)?;
        let count = alloc_constant(cs.namespace(|| "one signature"), &F::ONE)?;
        Ok(vec![count, claim[0].clone(), claim[1].clone()])
    }
}

#[derive(Debug)]
pub struct ConstraintReport {
    pub constraints: usize,
    pub satisfied: bool,
    pub first_failure: Option<String>,
}

/// Count and evaluate R1CS for the signature step. This does not create a proof.
pub fn constraint_report(witness: &SignatureWitness) -> Result<ConstraintReport, SynthesisError> {
    let mut cs = TestConstraintSystem::<F>::new();
    let initial: Vec<_> = initial_state()
        .iter()
        .enumerate()
        .map(|(i, value)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(*value)))
        .collect::<Result<_, _>>()?;
    let output = SignatureStep {
        witness: witness.clone(),
    }
    .synthesize(&mut cs, &initial)?;
    let expected = expected_final_state(witness);
    if output
        .iter()
        .zip(expected)
        .any(|(a, b)| a.get_value() != Some(b))
    {
        return Err(SynthesisError::Unsatisfiable(
            "signature claim differs from native SHA256".into(),
        ));
    }
    let first_failure = cs.which_is_unsatisfied().map(str::to_owned);
    Ok(ConstraintReport {
        constraints: cs.num_constraints(),
        satisfied: first_failure.is_none(),
        first_failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_snark::frontend::r1cs::NovaShape;
    use nova_snark::frontend::test_shape_cs::TestShapeCS;

    const KEY: &str = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";
    const MSG: &str = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";

    // Official Bitcoin BIP340 vectors 0..14 use 32-byte messages, matching this
    // application profile. Vectors15..18 cover other message lengths, outside
    // this fixed-shape relation. Source: bitcoin/bips/bip-0340/test-vectors.csv.
    // Reproduced using the upstream CC0-1.0 licensing option.
    fn vectors() -> Vec<(u8, SignatureWitness, bool)> {
        let data = [
            (1, KEY, MSG, "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", true),
            (2, "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", true),
            (3, "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", true),
            (4, "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", true),
            (5, "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", MSG, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
            (6, KEY, MSG, "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", false),
            (7, KEY, MSG, "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", false),
            (8, KEY, MSG, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", false),
            (9, KEY, MSG, "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", false),
            (10, KEY, MSG, "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", false),
            (11, KEY, MSG, "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
            (12, KEY, MSG, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
            (13, KEY, MSG, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", false),
            (14, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", MSG, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
        ];
        let mut out = vec![(0, SignatureWitness::default(), true)];
        out.extend(
            data.into_iter()
                .map(|(id, key, message, signature, valid)| {
                    (
                        id,
                        SignatureWitness {
                            public_key: decode_hex(key),
                            message: decode_hex(message),
                            signature: decode_hex(signature),
                        },
                        valid,
                    )
                }),
        );
        out
    }

    #[test]
    fn official_bip340_vectors_match_r1cs() {
        let mut shape_constraints = None;
        for (id, witness, valid) in vectors() {
            let report = constraint_report(&witness).unwrap();
            assert_eq!(
                report.satisfied, valid,
                "vector {id}: {:?}",
                report.first_failure
            );
            if let Some(n) = shape_constraints {
                assert_eq!(report.constraints, n, "vector {id} changes shape size");
            }
            shape_constraints = Some(report.constraints);
            assert_eq!(
                lnm_batch_statement::verify_bip340(
                    &witness.public_key,
                    &witness.message,
                    &witness.signature
                )
                .is_ok(),
                valid
            );
        }
        println!(
            "single-signature R1CS constraints: {}",
            shape_constraints.unwrap()
        );
    }

    #[test]
    fn entire_r1cs_shape_is_witness_independent() {
        fn shape(witness: SignatureWitness) -> Vec<u8> {
            let mut cs = TestShapeCS::<Secq256k1Engine>::new();
            let initial: Vec<_> = (0..STATE_ARITY)
                .map(|i| {
                    AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || F::ZERO)
                })
                .collect();
            SignatureStep { witness }
                .synthesize(&mut cs, &initial)
                .unwrap();
            bincode::serialize(&cs.r1cs_shape().unwrap()).unwrap()
        }
        let shape0 = shape(SignatureWitness::default());
        assert_eq!(shape0, shape(vectors().remove(3).1));
        assert_eq!(shape0, shape(vectors().remove(5).1));
    }

    #[test]
    fn full_256_bit_scalar_multiplication_reduces_by_group_order() {
        type Scalar = <Secp256k1Engine as Engine>::Scalar;
        let mut n = ORDER_MINUS_ONE;
        n[31] += 1;
        let mut n_plus_one = n;
        n_plus_one[31] += 1;
        let mut one = [0; 32];
        one[31] = 1;
        for scalar in [[0; 32], one, ORDER_MINUS_ONE, n, n_plus_one, [0xff; 32]] {
            let mut cs = TestConstraintSystem::<F>::new();
            let (x, y, _) = SecpPoint::gen().to_coordinates();
            let zero = alloc_zero(cs.namespace(|| "finite"));
            let point = PointVar::alloc_constant(cs.namespace(|| "G"), (x, y), zero).unwrap();
            let bits = allocate_bytes(cs.namespace(|| "scalar bytes"), &scalar).unwrap();
            let bits = allocated_scalar_bits(cs.namespace(|| "scalar bits"), &bits).unwrap();
            let result = point
                .scalar_mul(cs.namespace(|| "multiply"), &bits)
                .unwrap();
            let reduced = scalar.iter().fold(Scalar::ZERO, |n, b| {
                n * Scalar::from(256) + Scalar::from(u64::from(*b))
            });
            let (expected_x, expected_y, infinity) = (SecpPoint::gen() * reduced).to_coordinates();
            assert!(cs.is_satisfied());
            assert_eq!(
                result.is_infinity.get_value(),
                Some(if infinity { F::ONE } else { F::ZERO })
            );
            if !infinity {
                assert_eq!(result.x.get_value(), Some(expected_x));
                assert_eq!(result.y.get_value(), Some(expected_y));
            }
        }
    }

    #[test]
    fn canonical_scalar_boundaries() {
        let mut n = ORDER_MINUS_ONE;
        n[31] += 1;
        let mut n_plus_one = n;
        n_plus_one[31] += 1;
        for (bytes, accepted) in [
            ([0; 32], true),
            (ORDER_MINUS_ONE, true),
            (n, false),
            (n_plus_one, false),
            ([0xff; 32], false),
        ] {
            let mut cs = TestConstraintSystem::<F>::new();
            let bits = allocate_bytes(cs.namespace(|| "s"), &bytes).unwrap();
            constrain_s_below_order(cs.namespace(|| "bound"), &bits).unwrap();
            assert_eq!(cs.which_is_unsatisfied().is_none(), accepted);
        }
    }

    #[test]
    fn one_shot_step_rejects_nonzero_initial_state() {
        for index in 0..STATE_ARITY {
            let mut cs = TestConstraintSystem::<F>::new();
            let initial: Vec<_> = (0..STATE_ARITY)
                .map(|i| {
                    AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || {
                        if i == index {
                            F::ONE
                        } else {
                            F::ZERO
                        }
                    })
                })
                .collect();
            SignatureStep::default()
                .synthesize(&mut cs, &initial)
                .unwrap();
            assert!(cs.which_is_unsatisfied().is_some());
        }
    }

    #[test]
    #[ignore = "real Secq/Secp Nova proving benchmark; run explicitly with two Rayon threads"]
    fn real_recursive_and_compressed_signature_proof() {
        use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK};
        use nova_snark::provider::ipa_pc::EvaluationEngine;
        use nova_snark::spartan::snark::RelaxedR1CSSNARK;
        use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
        use std::time::Instant;

        type E1 = Secq256k1Engine;
        type E2 = Secp256k1Engine;
        type S1 = RelaxedR1CSSNARK<E1, EvaluationEngine<E1>>;
        type S2 = RelaxedR1CSSNARK<E2, EvaluationEngine<E2>>;
        type Pp = PublicParams<E1, E2, SignatureStep>;
        type Rs = RecursiveSNARK<E1, E2, SignatureStep>;
        type Compressed = CompressedSNARK<E1, E2, SignatureStep, S1, S2>;

        let step = SignatureStep::default();
        let start = Instant::now();
        let pp = Pp::setup(&step, &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
        let setup_seconds = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let z0 = initial_state();
        let mut proof = Rs::new(&pp, &step, &z0).unwrap();
        proof.prove_step(&pp, &step).unwrap();
        let recursive_prove_seconds = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let zn = proof.verify(&pp, 1, &z0).unwrap();
        let recursive_verify_seconds = start.elapsed().as_secs_f64();
        assert_eq!(zn, expected_final_state(&step.witness));
        let start = Instant::now();
        let (pk, vk) = Compressed::setup(&pp).unwrap();
        let compression_setup_seconds = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let compressed = Compressed::prove(&pp, &pk, &proof).unwrap();
        let compressed_prove_seconds = start.elapsed().as_secs_f64();
        let start = Instant::now();
        assert_eq!(compressed.verify(&vk, 1, &z0).unwrap(), zn);
        let compressed_verify_seconds = start.elapsed().as_secs_f64();
        assert!(compressed.verify(&vk, 2, &z0).is_err());
        let mut wrong_initial = z0;
        wrong_initial[0] = F::ONE;
        assert!(compressed.verify(&vk, 1, &wrong_initial).is_err());
        let proof_bytes = bincode::serialize(&compressed).unwrap();
        let vk_bytes = bincode::serialize(&vk).unwrap();
        let report = serde_json::json!({
            "schema": "lnmarkets-bip340-secq-single-signature/v1",
            "signature_verification_inside_r1cs": true,
            "dlc_signer_membership_or_application_message_proved": false,
            "pallas_batch_composition_proved": false,
            "bitcoin_spendability_proved": false,
            "fixture": "official BIP340 vector 0",
            "step_constraints": constraint_report(&step.witness).unwrap().constraints,
            "nova_state_arity": STATE_ARITY,
            "setup_seconds": setup_seconds,
            "recursive_prove_seconds": recursive_prove_seconds,
            "recursive_verify_seconds": recursive_verify_seconds,
            "compression_setup_seconds": compression_setup_seconds,
            "compressed_prove_seconds": compressed_prove_seconds,
            "compressed_verify_seconds": compressed_verify_seconds,
            "compressed_proof_bytes": proof_bytes.len(),
            "compressed_proof_sha256": hex::encode(lnm_batch_statement::sha256(&proof_bytes)),
            "verifier_key_sha256": hex::encode(lnm_batch_statement::sha256(&vk_bytes)),
            "signature_claim_sha256": hex::encode(signature_claim(&step.witness)),
            "recursive_verified": true,
            "compressed_verified": true,
            "wrong_initial_state_rejected": true,
            "wrong_step_count_rejected": true,
        });
        if let Ok(path) = std::env::var("LNM_BIP340_REPORT") {
            std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        }
        println!("{report}");
    }
}
