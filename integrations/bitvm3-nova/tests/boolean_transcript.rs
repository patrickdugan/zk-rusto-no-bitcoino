#![cfg(feature = "native-reference")]
//! M4: real Boolean hashing/reduction and streamed transcript verification.
use ff::PrimeField;
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire, GarbledWire,
    Gate, GateHasher, S, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput,
        EvaluateMode, ExecuteMode, FileSource, GarbleMode, StreamingResult, TRUE_WIRE,
    },
    nova::{PastaField, Word, transcript::{Transcript, keccak256, reduce_wide}},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine, keccak::Keccak256Transcript},
    traits::{Engine, TranscriptEngineTrait},
};
use num_bigint::BigUint;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use sha3::{Digest, Keccak256, Sha3_256};
use std::{io::{BufWriter, Write}, path::PathBuf};

const CAP: usize = 65536; // allocation reserve, not an OS memory ceiling
#[derive(Clone, Copy)]
enum Kind { Hash, Reduce(PastaField), Sequence(PastaField, usize, bool, u8) }
fn bytes_bits(bytes: &[u8]) -> Vec<bool> {
    bytes.iter().flat_map(|v| (0..8).map(move |i| (v >> i) & 1 == 1)).collect()
}
fn word_bytes(x: &BigUint, n: usize) -> Vec<u8> {
    let mut out = x.to_bytes_le();
    assert!(out.len() <= n);
    out.resize(n, 0);
    out
}
fn modulus(f: PastaField) -> BigUint {
    BigUint::from_bytes_le(&f.modulus_le().iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>())
}
fn and<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let out = c.issue_wire(); c.add_gate(Gate::and(a, b, out)); out
}
fn equal<C: CircuitContext>(c: &mut C, a: &Word, b: &Word) -> WireId {
    let mut ok = TRUE_WIRE;
    for i in 0..256 {
        let d = c.issue_wire(); c.add_gate(Gate::xor(a[i], b[i], d));
        let same = c.issue_wire(); c.add_gate(Gate::xor(d, TRUE_WIRE, same));
        ok = and(c, ok, same);
    }
    ok
}
fn build<C: CircuitContext>(c: &mut C, w: &[WireId], kind: Kind) -> WireId {
    match kind {
        Kind::Hash => {
            let n = w.len() - 256;
            let digest = keccak256(c, &w[..n]);
            equal(c, &digest, &w[n..].try_into().unwrap())
        }
        Kind::Reduce(field) => {
            assert_eq!(w.len(), 768);
            let raw = w[..512].try_into().unwrap();
            let value = reduce_wide(c, field, &raw);
            equal(c, &value, &w[512..].try_into().unwrap())
        }
        Kind::Sequence(field, count, leading, variant) => {
            assert_eq!(w.len(), 1536);
            let a: Word = w[..256].try_into().unwrap();
            let b: Word = w[256..512].try_into().unwrap();
            let label: &[u8] = if variant == 1 { b"nova-bitvm3-mX" } else { b"nova-bitvm3-m4" };
            let mut t = Transcript::new(c, field, label);
            t.dom_sep(b"phase0");
            if variant == 2 {
                t.absorb_scalar(c, b"b", &b); t.absorb_scalar(c, b"a", &a);
            } else {
                t.absorb_scalar(c, b"a", &a); t.absorb_scalar(c, b"b", &b);
            }
            let first = t.squeeze(c, if variant == 3 { b"cx" } else { b"c1" });
            let second = t.squeeze(c, b"again");
            t.dom_sep(b"phase1");
            t.absorb_scalar(c, b"a", &a);
            let third = t.squeeze_bits(c, b"bits", count, leading);
            let fourth = t.squeeze(c, b"final");
            let mut ok = TRUE_WIRE;
            for (i, value) in [first, second, third, fourth].iter().enumerate() {
                let claim = w[512 + 256*i..768 + 256*i].try_into().unwrap();
                let checked = value.check(c, &claim);
                ok = and(c, ok, checked);
            }
            ok
        }
    }
}
struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, value) in w.iter().zip(&self.0) { mode.feed_wire(*id, *value); }
    }
}
fn execute(kind: Kind, input: Vec<bool>) -> bool {
    let run: StreamingResult<ExecuteMode, _, bool> = CircuitBuilder::streaming_execute(
        Plain(input), CAP, |c, w| build(c, w, kind));
    run.output_value
}

#[test]
fn keccak_matches_sha3_crate_at_padding_boundaries() {
    for n in [0, 1, 7, 32, 64, 134, 135, 136, 137, 270, 271, 272, 273, 1024] {
        let data: Vec<u8> = (0..n).map(|i| (i * 17 + 3) as u8).collect();
        let expected = Keccak256::digest(&data);
        let mut input = bytes_bits(&data);
        input.extend(bytes_bits(&expected));
        assert!(execute(Kind::Hash, input.clone()), "length {n}");
        let last = input.len() - 1; input[last] = !input[last];
        assert!(!execute(Kind::Hash, input), "changed digest length {n}");
        // Explicitly reject SHA3 padding on the same message.
        let mut wrong = bytes_bits(&data); wrong.extend(bytes_bits(&Sha3_256::digest(&data)));
        assert!(!execute(Kind::Hash, wrong));
    }
}
#[test]
fn wide_reduction_matches_biguint_and_rejects_aliases() {
    let mut rng = ChaChaRng::seed_from_u64(6004);
    for field in [PastaField::PallasBase, PastaField::VestaBase] {
        let p = modulus(field);
        let one = BigUint::from(1u8);
        let mut cases = vec![0u8.into(), one.clone(), &p - 1u8, p.clone(), &p + 1u8,
            &p * 2u8 - 1u8, &p * 2u8, &p * &p, (&one << 512usize) - 1u8];
        for bit in [253, 254, 255, 256, 257, 258, 511] { cases.push(&one << bit); }
        for _ in 0..16 {
            let mut raw = [0u8; 64]; rng.fill_bytes(&mut raw);
            cases.push(BigUint::from_bytes_le(&raw));
        }
        for x in cases {
            let z = &x % &p;
            let input = |claim: &BigUint| {
                let mut b = bytes_bits(&word_bytes(&x, 64));
                b.extend(bytes_bits(&word_bytes(claim, 32))); b
            };
            assert!(execute(Kind::Reduce(field), input(&z)));
            assert!(!execute(Kind::Reduce(field), input(&((&z + 1u8) % &p))));
            assert!(!execute(Kind::Reduce(field), input(&(&z + &p))));
        }
    }
}

fn native_sequence<E: Engine>(a: &BigUint, b: &BigUint, count: usize, leading: bool) -> Vec<u8> {
    let scalar = |v: &BigUint| {
        let mut repr = <E::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&word_bytes(v, 32));
        Option::<E::Scalar>::from(E::Scalar::from_repr(repr)).unwrap()
    };
    let mut t = Keccak256Transcript::<E>::new(b"nova-bitvm3-m4");
    t.dom_sep(b"phase0");
    t.absorb(b"a", &scalar(a)); t.absorb(b"b", &scalar(b));
    let first = t.squeeze(b"c1").unwrap();
    let second = t.squeeze(b"again").unwrap();
    t.dom_sep(b"phase1"); t.absorb(b"a", &scalar(a));
    let third = t.squeeze_bits(b"bits", count, leading).unwrap();
    let fourth = t.squeeze(b"final").unwrap();
    [first, second, third, fourth].iter().flat_map(|v| v.to_repr().as_ref().to_vec()).collect()
}
fn expected(field: PastaField, a: &BigUint, b: &BigUint, count: usize, leading: bool) -> Vec<u8> {
    match field {
        PastaField::VestaBase => native_sequence::<PallasEngine>(a, b, count, leading),
        PastaField::PallasBase => native_sequence::<VestaEngine>(a, b, count, leading),
    }
}
fn sequence_input(a: &BigUint, b: &BigUint, claims: &[u8]) -> Vec<bool> {
    let mut input = bytes_bits(&word_bytes(a, 32));
    input.extend(bytes_bits(&word_bytes(b, 32))); input.extend(bytes_bits(claims)); input
}

// Raw-byte oracle permits a noncanonical scalar encoding, to show admission
// rejects it even when every supplied hash-derived challenge matches.
fn raw_sequence(field: PastaField, a: &BigUint, b: &BigUint, count: usize, leading: bool) -> Vec<u8> {
    fn pair(message: &[u8]) -> Vec<u8> {
        (0..2u8).flat_map(|suffix| {
            let mut h = Keccak256::new(); h.update(message); h.update([suffix]); h.finalize().to_vec()
        }).collect()
    }
    let mut state = pair(b"NoTRnova-bitvm3-m4");
    let mut pending = b"NoDSphase0a".to_vec(); pending.extend(word_bytes(a, 32));
    pending.extend(b"b"); pending.extend(word_bytes(b, 32));
    let mut output = Vec::new();
    for (round, label) in [b"c1".as_slice(), b"again", b"bits", b"final"].iter().enumerate() {
        if round == 2 {
            pending.extend(b"NoDSphase1a"); pending.extend(word_bytes(a, 32));
        }
        pending.extend(b"NoDS"); pending.extend((round as u64).to_le_bytes());
        pending.extend(&state); pending.extend(*label);
        state = pair(&pending); pending.clear();
        let x = BigUint::from_bytes_le(&state);
        let value = if round == 2 {
            let mask = (BigUint::from(1u8) << count) - 1u8;
            let mut v = x & mask;
            if leading { v |= BigUint::from(1u8) << (count - 1); }
            v
        } else { x % modulus(field) };
        output.extend(word_bytes(&value, 32));
    }
    output
}

#[test]
fn full_boolean_transcript_matches_pinned_nova_on_both_engines() {
    for field in [PastaField::PallasBase, PastaField::VestaBase] {
        let p = modulus(field);
        let vectors = [(2u8.into(), 5u8.into()), (&p - 1u8, BigUint::from(1u8) << 254usize)];
        for (a, b) in vectors {
            for (count, leading) in [(2, false), (7, true), (8, false), (17, true), (127, false), (254, true)] {
                let claims = expected(field, &a, &b, count, leading);
                assert_eq!(claims, raw_sequence(field, &a, &b, count, leading));
                let input = sequence_input(&a, &b, &claims);
                assert!(execute(Kind::Sequence(field, count, leading, 0), input));
            }
        }
    }
}
#[test]
fn transcript_rejects_wrong_challenges_labels_and_noncanonical_scalars() {
    for field in [PastaField::PallasBase, PastaField::VestaBase] {
        let a = BigUint::from(2u8); let b = BigUint::from(5u8);
        let claims = expected(field, &a, &b, 17, true);
        let input = sequence_input(&a, &b, &claims);
        for index in [512, 768, 1024, 1280] {
            let mut wrong = input.clone(); wrong[index] = !wrong[index];
            assert!(!execute(Kind::Sequence(field, 17, true, 0), wrong));
        }
        for variant in 1..=3 {
            assert!(!execute(Kind::Sequence(field, 17, true, variant), input.clone()));
        }
        let p = modulus(field);
        let claims = raw_sequence(field, &p, &b, 17, true);
        assert!(!execute(Kind::Sequence(field, 17, true, 0), sequence_input(&p, &b, &claims)));
    }
}

struct GarbleInput(usize);
impl CircuitInput for GarbleInput {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H, T>> for GarbleInput {
    fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<H, T>) {
        for id in w { let value = mode.issue_garbled_wire(); mode.feed_wire(*id, value); }
    }
}
struct EvalInput(Vec<EvaluatedWire>);
impl CircuitInput for EvalInput {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvalInput {
    fn encode(&self, w: &Self::WireRepr, mode: &mut M) {
        assert_eq!(w.len(), self.0.len());
        for (id, v) in w.iter().zip(&self.0) { mode.feed_wire(*id, v.clone()); }
    }
}
struct Sink { writer: BufWriter<std::fs::File>, hash: Blake3AccumulatingHash, count: u64 }
impl CiphertextHandler for Sink {
    type Result = ([u8; 32], u64);
    fn handle(&mut self, ct: S) {
        self.writer.write_all(&ct.to_bytes()).unwrap(); self.hash.update(ct); self.count += 1;
    }
    fn finalize(mut self) -> Self::Result {
        self.writer.flush().unwrap(); (self.hash.finalize(), self.count)
    }
}
struct Cleanup(PathBuf);
impl Drop for Cleanup { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }

#[test]
fn disk_streamed_transcript_accepts_native_and_rejects_mutations() {
    for field in [PastaField::PallasBase, PastaField::VestaBase] {
        let kind = Kind::Sequence(field, 17, true, 0);
        let seed = 6004u64; // deterministic test labels; not production input delivery
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let hasher = AesCcrGateHasher::from_rng(&mut rng);
        let path = Cleanup(std::env::temp_dir().join(format!("nova-m4-{}-{field:?}.ct", std::process::id())));
        let writer = std::fs::OpenOptions::new().create_new(true).write(true).open(&path.0).unwrap();
        let sink = Sink { writer: BufWriter::with_capacity(65536, writer), hash: Blake3AccumulatingHash::default(), count: 0 };
        let g: StreamingResult<GarbleMode<AesCcrGateHasher, Sink>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling(GarbleInput(1536), CAP, seed, sink, |c, w| build(c, w, kind));
        let (digest, count) = g.ciphertext_handler_result;
        let bytes = std::fs::metadata(&path.0).unwrap().len(); assert_eq!(bytes, count * 16);
        eprintln!("M4 field={field:?} four_challenges nonfree={count} ciphertext_bytes={bytes} gates={}", g.gate_count);
        let a = BigUint::from(2u8); let b = BigUint::from(5u8);
        let claims = expected(field, &a, &b, 17, true);
        let good = sequence_input(&a, &b, &claims);
        let mut assignments = vec![(good.clone(), true)];
        for index in [0, 512, 768, 1024, 1280] {
            let mut wrong = good.clone(); wrong[index] = !wrong[index]; assignments.push((wrong, false));
        }
        let p = modulus(field); let invalid_claims = raw_sequence(field, &p, &b, 17, true);
        assignments.push((sequence_input(&p, &b, &invalid_claims), false));
        for (values, accept) in assignments {
            let input = EvalInput(g.input_wire_values.iter().zip(values)
                .map(|(w, b)| EvaluatedWire::new_from_garbled(w, b)).collect());
            let e: StreamingResult<EvaluateMode<AesCcrGateHasher, FileSource>, _, EvaluatedWire> =
                CircuitBuilder::streaming_evaluation(input, CAP,
                    g.true_wire_constant.label1.to_u128(), g.false_wire_constant.label0.to_u128(),
                    hasher.clone(), FileSource::from_path(&path.0).unwrap(), |c, w| build(c, w, kind));
            assert_eq!(e.output_value.active_label, g.output_value.select(accept));
            assert_eq!(e.ciphertext_handler_result, digest);
        }
    }
}
