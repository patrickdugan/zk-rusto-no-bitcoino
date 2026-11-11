//! Field identifiers, canonical encodings and curve-point codecs for both Pasta engines.
//!
//! The R1CS of a Nova engine E is over E::Scalar; its Pedersen commitments are points of E::GE,
//! whose coordinates are in E::Base (the other Pasta field). Pallas: Scalar = Fq, Base = Fp.
//! Vesta: Scalar = Fp, Base = Fq.
use ff::{Field, PrimeField};
use halo2curves::CurveAffine;
use nova_snark::{
    provider::{
        pasta::{pallas, vesta},
        traits::{DlogGroup, DlogGroupExt},
        PallasEngine, VestaEngine,
    },
    traits::Engine,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldId {
    /// Pallas engine: R1CS over Fq, commitments on Pallas (coordinates in Fp).
    PallasScalar,
    /// Vesta engine: R1CS over Fp, commitments on Vesta (coordinates in Fq).
    VestaScalar,
}

impl FieldId {
    pub fn byte(self) -> u8 {
        match self {
            FieldId::PallasScalar => 1,
            FieldId::VestaScalar => 2,
        }
    }
    pub fn from_byte(b: u8) -> Option<FieldId> {
        match b {
            1 => Some(FieldId::PallasScalar),
            2 => Some(FieldId::VestaScalar),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            FieldId::PallasScalar => "pasta/pallas-engine/scalar-Fq",
            FieldId::VestaScalar => "pasta/vesta-engine/scalar-Fp",
        }
    }
    /// Modulus of the R1CS (scalar) field.
    pub fn modulus(self) -> BigUint {
        match self {
            FieldId::PallasScalar => modulus_of::<pallas::Scalar>(),
            FieldId::VestaScalar => modulus_of::<vesta::Scalar>(),
        }
    }
    /// Modulus of the commitment group's coordinate (base) field.
    pub fn base_modulus(self) -> BigUint {
        match self {
            FieldId::PallasScalar => modulus_of::<pallas::Base>(),
            FieldId::VestaScalar => modulus_of::<vesta::Base>(),
        }
    }
}

pub fn modulus_of<F: PrimeField>() -> BigUint {
    let m = F::MODULUS.trim_start_matches("0x");
    BigUint::parse_bytes(m.as_bytes(), 16).expect("modulus hex")
}

/// Canonical 32-byte little-endian encoding.
pub fn fe_bytes<F: PrimeField>(f: &F) -> [u8; 32] {
    let r = f.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(r.as_ref());
    out
}

/// Decode a canonical representative; `None` for any value >= the modulus.
pub fn fe_from_bytes<F: PrimeField>(b: &[u8; 32]) -> Option<F> {
    let mut r = F::Repr::default();
    r.as_mut().copy_from_slice(b);
    Option::from(F::from_repr(r))
}

pub fn fe_from_biguint<F: PrimeField>(v: &BigUint) -> Option<F> {
    let mut b = v.to_bytes_le();
    if b.len() > 32 {
        return None;
    }
    b.resize(32, 0);
    fe_from_bytes(&b.try_into().unwrap())
}

pub fn biguint_le(b: &[u8]) -> BigUint {
    BigUint::from_bytes_le(b)
}

/// The two Nova engines FC03 supports, with their point codecs.
pub trait FcEngine: Engine<CE = nova_snark::provider::pedersen::CommitmentEngine<Self>>
where
    Self::GE: DlogGroup + DlogGroupExt,
{
    const FIELD: FieldId;
    fn affine_from_xy(x: Self::Base, y: Self::Base) -> Option<<Self::GE as DlogGroup>::AffineGroupElement>;
}

impl FcEngine for PallasEngine {
    const FIELD: FieldId = FieldId::PallasScalar;
    fn affine_from_xy(x: pallas::Base, y: pallas::Base) -> Option<pallas::Affine> {
        Option::from(pallas::Affine::from_xy(x, y))
    }
}

impl FcEngine for VestaEngine {
    const FIELD: FieldId = FieldId::VestaScalar;
    fn affine_from_xy(x: vesta::Base, y: vesta::Base) -> Option<vesta::Affine> {
        Option::from(vesta::Affine::from_xy(x, y))
    }
}

pub type PointBytes = [u8; 65];

/// `inf(1) || x(32 LE) || y(32 LE)`; the identity is `01 || 0^64`.
pub fn point_bytes<E: FcEngine>(p: &E::GE) -> PointBytes
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let (x, y, inf) = p.to_coordinates();
    let mut out = [0u8; 65];
    if inf {
        out[0] = 1;
    } else {
        out[1..33].copy_from_slice(&fe_bytes(&x));
        out[33..].copy_from_slice(&fe_bytes(&y));
    }
    out
}

/// Strict decode: canonical coordinates, on the curve, identity only as `01 || 0^64`.
pub fn point_from_bytes<E: FcEngine>(b: &PointBytes) -> Option<E::GE>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    match b[0] {
        1 => {
            if b[1..].iter().any(|&v| v != 0) {
                return None;
            }
            Some(<E::GE as DlogGroup>::zero())
        }
        0 => {
            let x: E::Base = fe_from_bytes(b[1..33].try_into().unwrap())?;
            let y: E::Base = fe_from_bytes(b[33..].try_into().unwrap())?;
            let a = E::affine_from_xy(x, y)?;
            Some(<E::GE as DlogGroup>::group(&a))
        }
        _ => None,
    }
}

/// Affine point over a coordinate field, as committed in trace records (no curve check).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aff<F> {
    pub x: F,
    pub y: F,
    pub inf: bool,
}

/// Canonical decode of the 65-byte encoding into field coordinates; `None` if any byte is
/// non-canonical (inf not 0/1, identity with non-zero coordinates, coordinate >= modulus).
pub fn aff_from_bytes<F: PrimeField>(b: &PointBytes) -> Option<Aff<F>> {
    let x: F = fe_from_bytes(b[1..33].try_into().unwrap())?;
    let y: F = fe_from_bytes(b[33..].try_into().unwrap())?;
    match b[0] {
        0 => Some(Aff { x, y, inf: false }),
        1 if x.is_zero_vartime() && y.is_zero_vartime() => Some(Aff { x, y, inf: true }),
        _ => None,
    }
}

/// Projective (X : Y : Z) with the identity as (0 : 1 : 0).
#[derive(Clone, Copy, Debug)]
pub struct Proj<F> {
    pub x: F,
    pub y: F,
    pub z: F,
}

pub fn to_proj<F: Field>(a: &Aff<F>) -> Proj<F> {
    if a.inf {
        Proj { x: F::ZERO, y: F::ONE, z: F::ZERO }
    } else {
        Proj { x: a.x, y: a.y, z: F::ONE }
    }
}

/// Renes–Costello–Batina 2016, Algorithm 7: complete addition on y^2 = x^3 + b (a = 0), with
/// b3 = 3b = 15 for both Pasta curves. Complete for prime-order curves, including doubling and
/// the identity. This exact sequence is what the garbled binding-step circuit computes.
pub fn rcb_add<F: PrimeField>(p: &Proj<F>, q: &Proj<F>) -> Proj<F> {
    let b3 = F::from(15u64);
    let (x1, y1, z1, x2, y2, z2) = (p.x, p.y, p.z, q.x, q.y, q.z);
    let mut t0 = x1 * x2;
    let mut t1 = y1 * y2;
    let mut t2 = z1 * z2;
    let mut t3 = x1 + y1;
    let mut t4 = x2 + y2;
    t3 *= t4;
    t4 = t0 + t1;
    t3 -= t4;
    t4 = y1 + z1;
    let mut x3 = y2 + z2;
    t4 *= x3;
    x3 = t1 + t2;
    t4 -= x3;
    x3 = x1 + z1;
    let mut y3 = x2 + z2;
    x3 *= y3;
    y3 = t0 + t2;
    y3 = x3 - y3;
    x3 = t0 + t0;
    t0 = x3 + t0;
    t2 = b3 * t2;
    let mut z3 = t1 + t2;
    t1 -= t2;
    y3 = b3 * y3;
    x3 = t4 * y3;
    t2 = t3 * t1;
    x3 = t2 - x3;
    y3 *= t0;
    t1 *= z3;
    y3 = t1 + y3;
    t0 *= t3;
    z3 *= t4;
    z3 += t0;
    Proj { x: x3, y: y3, z: z3 }
}

/// Does projective `p` represent affine `a`? (identity iff Z = 0; else X = xZ, Y = yZ.)
pub fn proj_eq_aff<F: Field>(p: &Proj<F>, a: &Aff<F>) -> bool {
    if a.inf {
        p.z.is_zero_vartime()
    } else {
        !p.z.is_zero_vartime() && p.x == a.x * p.z && p.y == a.y * p.z
    }
}

pub fn aff_of<E: FcEngine>(p: &E::GE) -> Aff<E::Base>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let (x, y, inf) = p.to_coordinates();
    Aff { x, y, inf }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_are_little_endian_and_strict() {
        assert_eq!(fe_bytes(&pallas::Scalar::ONE)[0], 1);
        let m = FieldId::PallasScalar.modulus().to_bytes_le();
        let mut b = [0u8; 32];
        b[..m.len()].copy_from_slice(&m);
        assert!(fe_from_bytes::<pallas::Scalar>(&b).is_none(), "the modulus itself is non-canonical");
        assert_ne!(FieldId::PallasScalar.modulus(), FieldId::VestaScalar.modulus());
        assert_eq!(FieldId::PallasScalar.modulus(), FieldId::VestaScalar.base_modulus());
    }

    fn check_rcb<E: FcEngine>()
    where
        E::GE: DlogGroup + DlogGroupExt,
    {
        let g = <E::GE as DlogGroup>::gen();
        let mut p = <E::GE as DlogGroup>::zero();
        for i in 0..20u64 {
            let q = g * E::Scalar::from(i * i + 3);
            let (pa, qa) = (aff_of::<E>(&p), aff_of::<E>(&q));
            let s = rcb_add(&to_proj(&pa), &to_proj(&qa));
            assert!(proj_eq_aff(&s, &aff_of::<E>(&(p + q))));
            let d = rcb_add(&to_proj(&qa), &to_proj(&qa));
            assert!(proj_eq_aff(&d, &aff_of::<E>(&(q + q))), "doubling via complete addition");
            let bytes = point_bytes::<E>(&q);
            assert!(point_from_bytes::<E>(&bytes).unwrap() == q);
            p = q;
        }
        let z = <E::GE as DlogGroup>::zero();
        let s = rcb_add(&to_proj(&aff_of::<E>(&z)), &to_proj(&aff_of::<E>(&z)));
        assert!(proj_eq_aff(&s, &aff_of::<E>(&z)));
        let mut off = point_bytes::<E>(&g);
        off[40] ^= 1;
        assert!(point_from_bytes::<E>(&off).is_none(), "off-curve point rejected");
    }

    #[test]
    fn complete_addition_matches_group_law_both_curves() {
        check_rcb::<PallasEngine>();
        check_rcb::<VestaEngine>();
    }
}
