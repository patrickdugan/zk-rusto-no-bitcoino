use crate::{sha256, Hash, Result, Script};
use k256::elliptic_curve::{
    sec1::{FromEncodedPoint, ToEncodedPoint},
    PrimeField,
};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

fn bip_tagged(tag: &str, bytes: &[u8]) -> Hash {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(bytes);
    h.finalize().into()
}

fn lift_x(x: &Hash) -> Result<AffinePoint> {
    let mut bytes = [0; 33];
    bytes[0] = 2;
    bytes[1..].copy_from_slice(x);
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| "invalid compressed point")?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| "invalid x-only curve point".to_owned())
}

fn nums_key() -> Result<Hash> {
    // Same construction as UTXO-Ref/dlc_funding_output.js. Every candidate is
    // SHA256 of a public fixed string; no private scalar is chosen here.
    for counter in 0..1024 {
        let x = sha256(format!("UTXORef DLC funding NUMS internal key v1:{counter}").as_bytes());
        if lift_x(&x).is_ok() {
            return Ok(x);
        }
    }
    Err("could not derive the pinned NUMS point".to_owned())
}

fn script_num(value: u16) -> Vec<u8> {
    if value <= 16 {
        return vec![0x50 + value as u8];
    }
    let mut remaining = value;
    let mut bytes = Vec::new();
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        bytes.push(0);
    }
    let mut result = vec![bytes.len() as u8];
    result.extend(bytes);
    result
}

fn tapleaf(script: &[u8]) -> Hash {
    // These two fixed templates are under 253 bytes, so this is the complete
    // canonical CompactSize encoding for their lengths.
    let mut bytes = vec![0xc0, script.len() as u8];
    bytes.extend_from_slice(script);
    bip_tagged("TapLeaf", &bytes)
}

pub fn derive_funding_script(first: &Hash, second: &Hash, refund_csv: u16) -> Result<Script> {
    if first == second || refund_csv == 0 {
        return Err("two distinct keys and positive CSV are required".to_owned());
    }
    lift_x(first)?;
    lift_x(second)?;
    let internal = nums_key()?;
    if *first == internal || *second == internal {
        return Err("party key cannot be the NUMS internal key".to_owned());
    }
    let (a, b) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    let mut cet = vec![0x20];
    cet.extend_from_slice(a);
    cet.extend_from_slice(&[0xad, 0x20]);
    cet.extend_from_slice(b);
    cet.push(0xac);
    let mut refund = script_num(refund_csv);
    refund.extend_from_slice(&[0xb2, 0x75]);
    refund.extend_from_slice(&cet);
    let left = tapleaf(&cet);
    let right = tapleaf(&refund);
    let mut branch = Vec::with_capacity(64);
    if left < right {
        branch.extend_from_slice(&left);
        branch.extend_from_slice(&right);
    } else {
        branch.extend_from_slice(&right);
        branch.extend_from_slice(&left);
    }
    let root = bip_tagged("TapBranch", &branch);
    let mut tweak_input = Vec::with_capacity(64);
    tweak_input.extend_from_slice(&internal);
    tweak_input.extend_from_slice(&root);
    let tweak_bytes: FieldBytes = bip_tagged("TapTweak", &tweak_input).into();
    // BIP341 rejects tweaks >= n. Reducing modulo n would silently accept a
    // different construction. A zero tweak is valid.
    let tweak = Option::<Scalar>::from(Scalar::from_repr(tweak_bytes))
        .ok_or_else(|| "Taproot tweak is outside the scalar field".to_owned())?;
    let output = ProjectivePoint::from(lift_x(&internal)?) + ProjectivePoint::GENERATOR * tweak;
    if output == ProjectivePoint::IDENTITY {
        return Err("Taproot output point is infinity".to_owned());
    }
    let encoded = output.to_affine().to_encoded_point(true);
    let x = encoded.x().ok_or("missing Taproot x coordinate")?;
    let mut script = [0; 34];
    script[..2].copy_from_slice(&[0x51, 0x20]);
    script[2..].copy_from_slice(x);
    Ok(script)
}
