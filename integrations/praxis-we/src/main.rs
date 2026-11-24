//! Artifact validation only. No witness encryption or secret release.
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

type Check<T> = Result<T, String>;
const MAX: usize = 64 * 1024;
const MAX_INPUTS: usize = 256;

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn bounded(path: &Path) -> Check<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path).map_err(|e| e.to_string())?
        .take((MAX + 1) as u64).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > MAX { return Err("oversize artifact".into()); }
    Ok(bytes)
}

fn canonical<T: CanonicalDeserialize + CanonicalSerialize>(bytes: &[u8]) -> Check<T> {
    let mut rest = bytes;
    let value = T::deserialize_compressed(&mut rest).map_err(|e| e.to_string())?;
    if !rest.is_empty() { return Err("trailing bytes".into()); }
    let mut encoded = Vec::new();
    value.serialize_compressed(&mut encoded).map_err(|e| e.to_string())?;
    if encoded != bytes { return Err("noncanonical encoding".into()); }
    Ok(value)
}

fn verify(vk_bytes: &[u8], inputs_bytes: &[u8], proof_bytes: &[u8],
          vk_pin: [u8;32], inputs_pin: [u8;32]) -> Check<()> {
    if [vk_bytes.len(), inputs_bytes.len(), proof_bytes.len()].iter().any(|n| *n > MAX) {
        return Err("oversize artifact".into());
    }
    if digest(vk_bytes) != vk_pin || digest(inputs_bytes) != inputs_pin {
        return Err("artifact pin mismatch".into());
    }
    // Arkworks 0.5 Vec encoding starts with an eight-byte little-endian count.
    // Bound the count *before* allocating/decoding.
    let prefix: [u8;8] = inputs_bytes.get(..8).ok_or("missing input count")?
        .try_into().map_err(|_| "invalid count")?;
    let count = u64::from_le_bytes(prefix);
    if count > MAX_INPUTS as u64 || inputs_bytes.len() != 8 + 32 * count as usize {
        return Err("invalid public-input vector size".into());
    }
    // BN254 compressed VK has alpha_g1 (32), beta/gamma/delta_g2 (64 each),
    // then gamma_abc_g1 Vec prefix (8) and its points (32 each).
    let offset = 32 + 3 * 64;
    let abc_prefix: [u8;8] = vk_bytes.get(offset..offset+8).ok_or("missing VK count")?
        .try_into().map_err(|_| "invalid VK count")?;
    let abc = u64::from_le_bytes(abc_prefix);
    if abc != count + 1 || vk_bytes.len() != offset + 8 + 32 * abc as usize {
        return Err("invalid VK vector size".into());
    }
    if proof_bytes.len() != 128 { return Err("invalid proof size".into()); }
    let vk: VerifyingKey<Bn254> = canonical(vk_bytes)?;
    let inputs: Vec<Fr> = canonical(inputs_bytes)?;
    let proof: Proof<Bn254> = canonical(proof_bytes)?;
    let pvk = Groth16::<Bn254>::process_vk(&vk).map_err(|e| e.to_string())?;
    if !Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof)
        .map_err(|e| e.to_string())? {
        return Err("Groth16 rejected".into());
    }
    Ok(())
}

fn pin(s: &str) -> Check<[u8;32]> {
    hex::decode(s).map_err(|e| e.to_string())?.try_into().map_err(|_| "expected 32-byte SHA256".into())
}

fn run() -> Check<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: praxis-we-preflight DIR EXPECTED_VK_SHA256 EXPECTED_INPUTS_SHA256".into());
    }
    let dir = Path::new(&args[1]);
    verify(&bounded(&dir.join("vk.bin"))?, &bounded(&dir.join("public_inputs.bin"))?,
           &bounded(&dir.join("proof.bin"))?, pin(&args[2])?, pin(&args[3])?)?;
    println!("groth16_verified=true witness_encryption_implemented=false");
    Ok(())
}

fn main() {
    if let Err(e) = run() { eprintln!("{e}"); std::process::exit(1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::{lc, r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError}};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    #[derive(Clone)]
    struct Square;
    impl ConstraintSynthesizer<Fr> for Square {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(3u64)))?;
            let b = cs.new_input_variable(|| Ok(Fr::from(9u64)))?;
            cs.enforce_constraint(lc!() + a, lc!() + a, lc!() + b)
        }
    }
    fn ser<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
        let mut b = Vec::new(); x.serialize_compressed(&mut b).unwrap(); b
    }
    #[test]
    fn proof_and_mutations() {
        let mut rng = StdRng::seed_from_u64(1); // Known toxic waste; test only.
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Square, &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, Square, &mut rng).unwrap();
        let (v,i,p) = (ser(&vk), ser(&vec![Fr::from(9u64)]), ser(&proof));
        let (vh,ih) = (digest(&v),digest(&i));
        assert!(verify(&v,&i,&p,vh,ih).is_ok());
        let wrong = ser(&vec![Fr::from(10u64)]);
        assert!(verify(&v,&wrong,&p,vh,ih).is_err());
        assert!(verify(&v,&wrong,&p,vh,digest(&wrong)).is_err());
        assert!(verify(&v,&i,&p,[0;32],ih).is_err());
        let (_, other_vk) = Groth16::<Bn254>::circuit_specific_setup(Square, &mut rng).unwrap();
        let other = ser(&other_vk);
        assert!(verify(&other,&i,&p,vh,ih).is_err());
        assert!(verify(&other,&i,&p,digest(&other),ih).is_err());
        let mut tail = p.clone(); tail.push(0);
        assert!(verify(&v,&i,&tail,vh,ih).is_err());
        let mut bad = p.clone(); bad[0] ^= 1;
        assert!(verify(&v,&i,&bad,vh,ih).is_err());
        let bomb = u64::MAX.to_le_bytes();
        assert!(verify(&v,&bomb,&p,vh,digest(&bomb)).is_err());
        let mut vb = v.clone(); vb[224..232].copy_from_slice(&bomb);
        assert!(verify(&vb,&i,&p,digest(&vb),ih).is_err());
        assert!(verify(&v,&i,&vec![0;MAX+1],vh,ih).is_err());
    }
}
