//! Constraint-satisfaction checks on the real mainnet fixtures: the honest
//! witness satisfies each circuit and every tampered statement or witness
//! does not. (Full Groth16 prove/verify runs in the bench binary.)
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use groth16_gym::{chain_from_txt, sha256d, spv_from_hex, target_from_nbits, tx_shape, SpvCircuit};

const TX_HEX: &str = include_str!("../fixtures/fd2fdd44.tx.hex");
const MB_HEX: &str = include_str!("../fixtures/fd2fdd44.merkleblock.hex");
const HEADERS: &str = include_str!("../fixtures/headers_959617_959994.txt");

fn satisfied<C: ConstraintSynthesizer<Fr>>(c: C) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

fn spv() -> SpvCircuit {
    spv_from_hex(TX_HEX, MB_HEX, 0).unwrap()
}

#[test]
fn spv_fixture_is_the_known_mainnet_payment() {
    let c = spv();
    let mut display = c.public.txid;
    display.reverse();
    assert_eq!(
        hex::encode(display),
        "fd2fdd448e15a74e661b7b058bf7ffba0a1a575aca7da75d1358a2c31217daa6"
    );
    let mut block = c.public.block_hash;
    block.reverse();
    assert_eq!(
        hex::encode(block),
        "000000000000000000000b99348eebd2f4863aa49a0d2fb2203c549e7b16372b"
    );
    assert_eq!(c.public.value, 2_010_000);
    assert_eq!(c.branch.len(), 13);
    assert!(satisfied(c));
}

#[test]
fn spv_rejects_tampered_statements_and_witnesses() {
    type Tamper = Box<dyn Fn(&mut SpvCircuit)>;
    let cases: Vec<(&str, Tamper)> = vec![
        ("value", Box::new(|c| c.public.value += 1)),
        ("txid", Box::new(|c| c.public.txid[0] ^= 1)),
        ("block hash", Box::new(|c| c.public.block_hash[31] ^= 1)),
        ("script hash", Box::new(|c| c.public.script_sha256[5] ^= 1)),
        ("tx byte", Box::new(|c| c.tx[10] ^= 1)),
        (
            "value byte",
            Box::new(|c| {
                let o = c.shape.value_offset;
                c.tx[o] ^= 1
            }),
        ),
        ("merkle sibling", Box::new(|c| c.branch[3].0[0] ^= 1)),
        (
            "merkle direction",
            Box::new(|c| c.branch[0].1 = !c.branch[0].1),
        ),
        ("header nonce", Box::new(|c| c.header[79] ^= 1)),
        (
            "structural byte",
            Box::new(|c| {
                let p = c.shape.structural[0].0;
                c.tx[p] ^= 1
            }),
        ),
    ];
    for (name, tamper) in cases {
        let mut c = spv();
        tamper(&mut c);
        assert!(!satisfied(c), "{name} accepted");
    }
}

#[test]
fn tx_shape_refuses_ambiguous_or_witness_forms() {
    assert!(tx_shape(&[0u8; 64], 0).is_err());
    let c = spv();
    assert!(tx_shape(&c.tx, 1).is_err(), "the fixture has one output");
    assert!(tx_shape(&c.tx[..c.tx.len() - 1], 0).is_err());
}

#[test]
fn header_chain_accepts_real_headers_and_rejects_tampering() {
    let good = chain_from_txt(HEADERS, 959_994, 4).unwrap();
    assert_eq!(
        good.public.target,
        target_from_nbits(good.public.nbits).unwrap()
    );
    assert!(satisfied(good.clone()));

    let mut link = good.clone();
    link.headers[2][10] ^= 1;
    assert!(!satisfied(link), "broken link accepted");

    let mut end = good.clone();
    end.public.end[0] ^= 1;
    assert!(!satisfied(end), "wrong end hash accepted");

    let mut prev = good.clone();
    prev.public.prev[0] ^= 1;
    assert!(!satisfied(prev), "wrong start accepted");

    // A target below a header's hash: that header's PoW no longer counts.
    let mut target = good.clone();
    let mut t = sha256d(&good.headers[1]);
    t[0] = t[0].wrapping_sub(1);
    target.public.target = t;
    assert!(!satisfied(target), "insufficient work accepted");

    let mut bits = good;
    bits.public.nbits ^= 1;
    assert!(!satisfied(bits), "wrong nBits accepted");

    assert!(
        chain_from_txt(HEADERS, 959_620, 10).is_err(),
        "crosses an epoch"
    );
}
