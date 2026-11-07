#![cfg(feature = "native-reference")]
//! Host-side byte-contract tests against the exact pinned Nova crate.
//! No hashing in a garbled circuit is claimed by this test.
use ff::PrimeField;
use nova_snark::{
    provider::{PallasEngine, VestaEngine, keccak::Keccak256Transcript},
    traits::{Engine, TranscriptEngineTrait},
};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

#[derive(Clone)]
struct Mirror {
    state: [u8; 64],
    round: u64,
    pending: Vec<u8>,
}
fn hash_pair(bytes: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for suffix in 0..2u8 {
        let mut h = Keccak256::new();
        h.update(bytes);
        h.update([suffix]);
        out[32 * suffix as usize..32 * (suffix as usize + 1)].copy_from_slice(&h.finalize());
    }
    out
}
impl Mirror {
    fn new(label: &[u8]) -> Self {
        Self { state: hash_pair(&[b"NoTR".as_slice(), label].concat()), round: 0, pending: vec![] }
    }
    fn absorb(&mut self, label: &[u8], repr: &[u8]) {
        self.pending.extend_from_slice(label);
        self.pending.extend_from_slice(repr);
    }
    fn dom_sep(&mut self, label: &[u8]) {
        self.pending.extend_from_slice(b"NoDS");
        self.pending.extend_from_slice(label);
    }
    fn squeeze(&mut self, label: &[u8], modulus: &BigUint) -> Vec<u8> {
        self.pending.extend_from_slice(b"NoDS");
        self.pending.extend_from_slice(&self.round.to_le_bytes());
        self.pending.extend_from_slice(&self.state);
        self.pending.extend_from_slice(label);
        self.state = hash_pair(&self.pending);
        self.round = self.round.checked_add(1).unwrap();
        self.pending.clear();
        let mut bytes = (BigUint::from_bytes_le(&self.state) % modulus).to_bytes_le();
        bytes.resize(32, 0);
        bytes
    }
}

fn compare<E: Engine>() {
    let modulus = BigUint::parse_bytes(E::Scalar::MODULUS.trim_start_matches("0x").as_bytes(), 16).unwrap();
    let mut native = Keccak256Transcript::<E>::new(b"nova-bitvm3-m3");
    let mut mirror = Mirror::new(b"nova-bitvm3-m3");
    for round in 0..8u64 {
        if round % 2 == 0 {
            native.dom_sep(b"phase");
            mirror.dom_sep(b"phase");
        }
        for (label, value) in [(b"a".as_slice(), round + 2), (b"b".as_slice(), round * 11 + 5)] {
            let scalar = E::Scalar::from(value);
            native.absorb(label, &scalar);
            let mut repr = value.to_le_bytes().to_vec();
            repr.resize(32, 0);
            assert_eq!(scalar.to_repr().as_ref(), repr.as_slice());
            mirror.absorb(label, &repr);
        }
        let challenge = native.squeeze(b"challenge").unwrap();
        assert_eq!(challenge.to_repr().as_ref(), mirror.squeeze(b"challenge", &modulus).as_slice());
        // Consecutive squeeze tests the round counter, previous-state binding and reset.
        let next = native.squeeze(b"again").unwrap();
        assert_eq!(next.to_repr().as_ref(), mirror.squeeze(b"again", &modulus).as_slice());
    }
    eprintln!("M3 transcript={} 16 challenge bytes matched", std::any::type_name::<E>());
}

#[test]
fn exact_nova_076_pallas_transcript() { compare::<PallasEngine>(); }
#[test]
fn exact_nova_076_vesta_transcript() { compare::<VestaEngine>(); }

#[test]
fn labels_order_domain_and_counter_change_challenges() {
    type E = PallasEngine;
    let get = |domain: &'static [u8], first: u64, second: u64, label: &'static [u8], twice: bool| {
        let mut t = Keccak256Transcript::<E>::new(domain);
        t.absorb(b"a", &<E as Engine>::Scalar::from(first));
        t.absorb(b"b", &<E as Engine>::Scalar::from(second));
        if twice { let _ = t.squeeze(label).unwrap(); }
        t.squeeze(label).unwrap()
    };
    let baseline = get(b"m3", 2, 5, b"c", false);
    assert_ne!(baseline, get(b"different", 2, 5, b"c", false));
    assert_ne!(baseline, get(b"m3", 5, 2, b"c", false));
    assert_ne!(baseline, get(b"m3", 2, 5, b"other", false));
    assert_ne!(baseline, get(b"m3", 2, 5, b"c", true));
}
