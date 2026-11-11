//! FC03 native acceptance: the adversarial suite on both Pasta engines, exhaustive honest binding
//! traces, the forged (W, E) pair, the malformed FlatMerkle stream, and the frozen vector file the
//! Python reference replays.
use flatcheck_fc03::{
    cases::{self, locate_fault, Suite},
    checker::adjudicate,
    enc,
    fixture::{self, Toy},
    flatmerkle,
    protocol::*,
    sha,
};
use nova_snark::provider::{PallasEngine, VestaEngine};
use std::sync::OnceLock;

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/fc03_vectors.json");

fn suites() -> &'static (Suite<PallasEngine>, Suite<VestaEngine>) {
    static S: OnceLock<(Suite<PallasEngine>, Suite<VestaEngine>)> = OnceLock::new();
    S.get_or_init(|| (Suite::<PallasEngine>::build(0xFC03_0001), Suite::<VestaEngine>::build(0xFC03_0002)))
}

fn all_cases() -> Vec<cases::Case> {
    let (p, v) = suites();
    let mut all = p.cases.clone();
    all.extend(v.cases.clone());
    all.extend(cases::cross_field_cases(p, v));
    all
}

#[test]
fn adversarial_suite_native_verdicts() {
    let (p, v) = suites();
    let mut failures = Vec::new();
    let all = all_cases();
    for c in &all {
        let got = cases::run_native(c, &p.toy.pinned.tc, &v.toy.pinned.tc);
        if got.code() != c.expected || got.refutes() != c.expected_refutes {
            failures.push(format!("{}: expected {}, got {:?}", c.name, c.expected, got));
        }
    }
    eprintln!("FC03-NATIVE cases={} failures={}", all.len(), failures.len());
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The vector file is a deterministic function of the seeds; regenerate with FC03_WRITE_VECTORS=1.
#[test]
fn frozen_vectors_match_the_suite() {
    let (p, v) = suites();
    let mut claims = std::collections::BTreeMap::new();
    let all: Vec<serde_json::Value> = all_cases()
        .into_iter()
        .map(|c| {
            let id = hex::encode(c.claim.id());
            claims.entry(id.clone()).or_insert_with(|| serde_json::to_value(&c.claim).unwrap());
            let mut j = serde_json::to_value(&c).unwrap();
            let o = j.as_object_mut().unwrap();
            o.remove("claim");
            o.insert("claim_id".into(), id.into());
            j
        })
        .collect();
    let doc = serde_json::json!({
        "format": "flatcheck-fc03-vectors/v1",
        "generator": "integrations/bitvm3-nova/flatcheck-lab/fc03/tests/native.rs",
        "configs": { "PallasScalar": p.toy.pinned.tc, "VestaScalar": v.toy.pinned.tc },
        "moduli": {
            "PallasScalar": { "scalar": flatcheck_fc03::field::FieldId::PallasScalar.modulus().to_str_radix(16), "base": flatcheck_fc03::field::FieldId::PallasScalar.base_modulus().to_str_radix(16) },
            "VestaScalar": { "scalar": flatcheck_fc03::field::FieldId::VestaScalar.modulus().to_str_radix(16), "base": flatcheck_fc03::field::FieldId::VestaScalar.base_modulus().to_str_radix(16) },
        },
        "claims": claims,
        "cases": all,
    });
    let text = serde_json::to_string(&doc).unwrap() + "\n";
    if std::env::var("FC03_WRITE_VECTORS").is_ok() {
        std::fs::write(VECTORS, &text).unwrap();
    }
    let on_disk = std::fs::read_to_string(VECTORS).expect("fixtures/fc03_vectors.json (FC03_WRITE_VECTORS=1 writes it)");
    assert!(on_disk == text, "fc03_vectors.json is stale; regenerate with FC03_WRITE_VECTORS=1");
    eprintln!("FC03-VECTORS cases={} bytes={} sha256={}", all.len(), text.len(), hex::encode(sha::sha256(text.as_bytes())));
}

fn exhaustive<E: flatcheck_fc03::field::FcEngine>(s: &Suite<E>) -> usize
where
    E::GE: nova_snark::provider::traits::DlogGroup + nova_snark::provider::traits::DlogGroupExt,
    E::Scalar: ff::PrimeFieldBits,
    E::Base: ff::PrimeFieldBits,
{
    let t = &s.toy;
    let tc = &t.pinned.tc;
    let mut n = 0;
    for v in [Vector::W, Vector::E] {
        for step in 0..tc.trace_steps(v) {
            let ch = cases::challenge_for(&t.claim, ChallengeKind::BindingStep { vec: v, step }, "x");
            let r = t.respond(&t.committed, &ch);
            let got = adjudicate::<E>(tc, &t.claim, &ch, r.as_ref());
            assert_eq!(got.code(), "holds", "{v:?} step {step}: {got:?}");
            n += 1;
        }
    }
    for row in 0..tc.num_cons {
        let ch = cases::challenge_for(&t.claim, ChallengeKind::Row { row }, "x");
        let r = t.respond(&t.committed, &ch);
        assert_eq!(adjudicate::<E>(tc, &t.claim, &ch, r.as_ref()).code(), "holds");
        n += 1;
    }
    assert!(locate_fault(t, &t.claim, &t.committed).is_none(), "honest claim has no refutable check");
    n
}

#[test]
fn every_honest_local_check_holds_both_fields() {
    let (p, v) = suites();
    let n = exhaustive(p) + exhaustive(v);
    eprintln!("FC03-EXHAUSTIVE honest local checks={n}");
}

/// W' with E' = A z' o B z' - u C z' satisfies every row; the FlatMerkle roots of (W', E') open
/// correctly; the challenger's search finds the Pedersen binding, not a row.
fn forged_pair<E: flatcheck_fc03::field::FcEngine>(s: &Suite<E>) -> (ChallengeKind, ChallengeKind)
where
    E::GE: nova_snark::provider::traits::DlogGroup + nova_snark::provider::traits::DlogGroupExt,
    E::Scalar: ff::PrimeFieldBits,
    E::Base: ff::PrimeFieldBits,
{
    use ff::Field;
    let t = &s.toy;
    let mut w: Vec<E::Scalar> = t.committed.w.iter().map(|b| flatcheck_fc03::field::fe_from_bytes(b).unwrap()).collect();
    w[3] += E::Scalar::ONE;
    let e = cases::forge_error(t, &w);
    // Nova's own check: the relaxed-R1CS equations hold for (W', E'); only its commitment
    // comparison fails.
    let (_, r_w, r_e) = t.nova.w.derandomize();
    let nova_w = nova_snark::r1cs::RelaxedR1CSWitness::<E>::new(&t.nova.s, w.clone(), r_w, e.clone(), r_e).unwrap();
    let err = t.nova.s.is_sat_relaxed(&t.nova.ck, &t.nova.u, &nova_w).unwrap_err();
    assert!(format!("{err:?}").contains("Invalid commitments"), "{err:?}");
    let c = fixture::commit::<E>(&t.gens, t.pinned.tc.ck_len as usize, &w, r_w, &e, r_e);
    let claim = Toy::<E>::claim_for(&t.nova, &t.pinned.tc, &c, t.replay.clone());
    for row in 0..t.pinned.tc.num_cons {
        let ch = cases::challenge_for(&claim, ChallengeKind::Row { row }, "fp");
        let r = t.respond(&c, &ch);
        assert_eq!(adjudicate::<E>(&t.pinned.tc, &claim, &ch, r.as_ref()).code(), "holds");
    }
    let found = locate_fault(t, &claim, &c).expect("the binding exposes the forged pair");
    // Patch the trace end to Nova's comm_W: the search moves to the last transition.
    let mut c2 = c.clone();
    let last = t.pinned.tc.trace_steps(Vector::W) as usize;
    c2.trace_w[last].0 = t.claim.instance.comm_w;
    fixture::restream(&mut c2, Vector::W);
    let claim2 = Toy::<E>::claim_for(&t.nova, &t.pinned.tc, &c2, t.replay.clone());
    let found2 = locate_fault(t, &claim2, &c2).expect("still exposed");
    (found, found2)
}

#[test]
fn forged_witness_error_pair_is_caught_by_binding_only() {
    let (p, v) = suites();
    let (a, b) = forged_pair(p);
    assert_eq!(a, ChallengeKind::BindingEnd { vec: Vector::W });
    assert!(matches!(b, ChallengeKind::BindingEnd { vec: Vector::E } | ChallengeKind::BindingStep { vec: Vector::W, .. }), "{b:?}");
    let (a, _) = forged_pair(v);
    assert_eq!(a, ChallengeKind::BindingEnd { vec: Vector::W });
    eprintln!("FC03-FORGED first refutable check: {a:?}; after patching the W trace end: {b:?}");
}

/// A stream whose MID block carries a wrong checkpoint has an ordinary SHA-256 digest, but the
/// items under that node cannot be opened against it, and rebuilding from the items detects it.
#[test]
fn malformed_flatmerkle_stream() {
    let items: Vec<[u8; 64]> = (0..16u32).map(|i| enc::item(1, b'W', i, &sha::sha256(&i.to_be_bytes()))).collect();
    let honest = flatmerkle::build(&items).unwrap();
    let mut bytes = flatmerkle::payload(&items).unwrap();
    // The MID block of node (start=0, k=1) is the 3rd block of the stream.
    bytes[2 * 64] ^= 1;
    let bad_digest = sha::sha256(&bytes);
    assert_ne!(bad_digest, honest.digest, "rebuilding the structured stream from the items detects the malformation");
    for i in 0..16 {
        let o = flatmerkle::open(&honest, i);
        assert!(!flatmerkle::verify(16, &bad_digest, i, &items[i], &o), "an honest opening never verifies against the malformed digest");
    }
    // The operator's best openings come from the states its malformed stream really produces.
    // A wrong MID block breaks every later checkpoint the verifier recomputes, so a suffix of
    // the items becomes unopenable (a challenge there ends in the response timeout); items before
    // it still open, and no item opens to a different value.
    for (block, want) in [(2usize, (0..16).collect::<Vec<usize>>()), (17, (8..16).collect()), (20, (12..16).collect())] {
        let mut bytes = flatmerkle::payload(&items).unwrap();
        bytes[64 * block] ^= 1;
        let bad = flatmerkle::build_from_payload(&items, &bytes).unwrap();
        assert_eq!(bad.digest, sha::sha256(&bytes));
        let unopen: Vec<usize> = (0..16).filter(|&i| !flatmerkle::verify(16, &bad.digest, i, &items[i], &flatmerkle::open(&bad, i))).collect();
        assert_eq!(unopen, want, "corrupted block {block}");
        for i in 0..16 {
            let mut other = items[i];
            other[20] ^= 1;
            let mut o = flatmerkle::open(&bad, i);
            o.pair[i & 1] = other;
            assert!(!flatmerkle::verify(16, &bad.digest, i, &other, &o), "no item opens to another value");
        }
        eprintln!("FC03-MALFORMED corrupted MID block {block}: unopenable items {unopen:?}");
    }
}
