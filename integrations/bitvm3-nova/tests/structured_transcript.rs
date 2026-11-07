#![cfg(all(feature = "native-reference", feature = "curve-reference"))]
//! M5: structured transcript bytes and strict witness admission.
//! Checks Nova 0.76.0's affine (64-byte) and commitment (65-byte) paths.
use ff::PrimeField;
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire,
    GarbledWire, GateHasher, S, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput,
        EvaluateMode, ExecuteMode, FileSource, GarbleMode, StreamingResult,
    },
    nova::{
        PastaField, Word,
        curve::PastaCurve,
        transcript::Transcript,
    },
};
use halo2curves::{
    CurveAffine,
    group::Curve,
    pasta::{Fp, Fq, Pallas, Vesta},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine, keccak::Keccak256Transcript, pedersen::Commitment},
    traits::{Engine, TranscriptEngineTrait, TranscriptReprTrait},
};
use num_bigint::BigUint;
use rand::{SeedableRng};
use rand_chacha::ChaChaRng;
use sha3::{Digest, Keccak256};
use std::io::{BufWriter, Write};
const CAP: usize = 65536;

fn bits(bytes: &[u8]) -> Vec<bool> {
    bytes.iter().flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1)).collect()
}
fn le(x: &BigUint, width: usize) -> Vec<u8> {
    let mut out = x.to_bytes_le();
    assert!(out.len() <= width);
    out.resize(width, 0);
    out
}
fn modulus(field: PastaField) -> BigUint {
    BigUint::from_bytes_le(&field.modulus_le().iter()
        .flat_map(|limb| limb.to_le_bytes()).collect::<Vec<_>>())
}
fn field(curve: PastaCurve) -> PastaField {
    match curve {
        PastaCurve::Pallas => PastaField::VestaBase,
        PastaCurve::Vesta => PastaField::PallasBase,
    }
}
fn base_field(curve: PastaCurve) -> PastaField {
    match curve {
        PastaCurve::Pallas => PastaField::PallasBase,
        PastaCurve::Vesta => PastaField::VestaBase,
    }
}
fn point_bytes<A: CurveAffine>(p: A) -> Vec<u8> {
    if bool::from(p.is_identity()) {
        return vec![0u8; 64];
    }
    let coords = Option::<halo2curves::Coordinates<A>>::from(p.coordinates())
        .expect("finite point coordinates");
    [coords.x().to_repr().as_ref(), coords.y().to_repr().as_ref()].concat()
}
fn generator(curve: PastaCurve, times: u64) -> Vec<u8> {
    match curve {
        PastaCurve::Pallas =>
            point_bytes((Pallas::generator() * Fq::from(times)).to_affine()),
        PastaCurve::Vesta =>
            point_bytes((Vesta::generator() * Fp::from(times)).to_affine()),
    }
}
fn native_expected<E, T>(label: &'static [u8], encoded: &T) -> Vec<u8>
where E: Engine, T: TranscriptReprTrait<E::GE> {
    let mut t = Keccak256Transcript::<E>::new(b"nova-bitvm3-m5");
    t.absorb(label, encoded);
    t.squeeze(b"challenge").expect("native squeeze").to_repr().as_ref().to_vec()
}
fn raw_expected(field: PastaField, label: &[u8], bytes: &[u8]) -> Vec<u8> {
    fn pair(m: &[u8]) -> Vec<u8> {
        [0u8, 1u8].iter().flat_map(|suffix| {
            let mut h = Keccak256::new();
            h.update(m); h.update([*suffix]); h.finalize().to_vec()
        }).collect()
    }
    let initial = pair(b"NoTRnova-bitvm3-m5");
    let mut pending = Vec::new();
    pending.extend_from_slice(label);
    pending.extend_from_slice(bytes);
    pending.extend_from_slice(b"NoDS");
    pending.extend_from_slice(&0u64.to_le_bytes());
    pending.extend_from_slice(&initial);
    pending.extend_from_slice(b"challenge");
    let challenge = pair(&pending);
    le(&(BigUint::from_bytes_le(&challenge) % modulus(field)), 32)
}

#[derive(Clone, Copy)]
enum Kind {
    Affine(PastaCurve),
    Commitment(PastaCurve),
    Scalars(PastaField),
    Commitments(PastaCurve),
}
impl Kind {
    fn input_bits(self) -> usize {
        match self {
            Self::Affine(_) => 512+256,
            Self::Commitment(_) => 520+256,
            Self::Scalars(_) => 512+256,
            Self::Commitments(_) => 1040+256,
        }
    }
}
fn build<C: CircuitContext>(c: &mut C, kind: Kind, wires: &[WireId]) -> WireId {
    assert_eq!(wires.len(), kind.input_bits());
    let mut t = match kind {
        Kind::Affine(curve) | Kind::Commitment(curve) | Kind::Commitments(curve) =>
            Transcript::new(c, field(curve), b"nova-bitvm3-m5"),
        Kind::Scalars(f) => Transcript::new(c, f, b"nova-bitvm3-m5"),
    };
    match kind {
        Kind::Affine(curve) => {
            let p: [WireId; 512] = wires[..512].try_into().unwrap();
            t.absorb_affine_encoded(c, b"affine", curve, &p);
        }
        Kind::Commitment(curve) => {
            let p: [WireId; 520] = wires[..520].try_into().unwrap();
            t.absorb_commitment_encoded(c, b"commit", curve, &p);
        }
        Kind::Scalars(_) => {
            let a: Word = wires[..256].try_into().unwrap();
            let b: Word = wires[256..512].try_into().unwrap();
            t.absorb_scalar_slice(c, b"batch", &[a, b]);
        }
        Kind::Commitments(curve) => {
            let a: [WireId; 520] = wires[..520].try_into().unwrap();
            let b: [WireId; 520] = wires[520..1040].try_into().unwrap();
            t.absorb_commitment_slice(c, b"batch_commit", curve, &[a, b]);
        }
    }
    let claim: Word = wires[wires.len()-256..].try_into().unwrap();
    t.squeeze(c, b"challenge").check(c, &claim)
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
        for (id, bit) in w.iter().zip(&self.0) { mode.feed_wire(*id, *bit); }
    }
}
fn execute(kind: Kind, encoded: &[u8], claim: &[u8]) -> bool {
    let mut input = bits(encoded);
    input.extend(bits(claim));
    let result: StreamingResult<ExecuteMode, _, bool> =
        CircuitBuilder::streaming_execute(Plain(input), CAP, |c, w| build(c, kind, w));
    result.output_value
}

#[test]
fn affine_bytes_match_native_pasta_transcript_and_reject_aliases() {
    for curve in [PastaCurve::Pallas, PastaCurve::Vesta] {
        let kind = Kind::Affine(curve);
        for factor in [0, 1, 2, 7] {
            let encoded = generator(curve, factor);
            assert_eq!(encoded.len(), 64);
            let native = match curve {
                PastaCurve::Pallas => {
                    let p = (Pallas::generator() * Fq::from(factor)).to_affine();
                    native_expected::<PallasEngine, _>(b"affine", &p)
                }
                PastaCurve::Vesta => {
                    let p = (Vesta::generator() * Fp::from(factor)).to_affine();
                    native_expected::<VestaEngine, _>(b"affine", &p)
                }
            };
            assert_eq!(native, raw_expected(field(curve), b"affine", &encoded));
            assert!(execute(kind, &encoded, &native), "curve={curve:?} factor={factor}");
            let mut wrong = native.clone(); wrong[0] ^= 1;
            assert!(!execute(kind, &encoded, &wrong));
        }
        let good = generator(curve, 1);
        let mut bad = good.clone();
        let modulus_bytes = le(&modulus(base_field(curve)), 32);
        bad[..32].copy_from_slice(&modulus_bytes);
        let claim = raw_expected(field(curve), b"affine", &bad);
        assert!(!execute(kind, &bad, &claim), "noncanonical x rejected");
        let mut bad = good.clone();
        bad[33] ^= 0x04;
        let claim = raw_expected(field(curve), b"affine", &bad);
        assert!(!execute(kind, &bad, &claim), "off-curve point rejected");
    }
}
#[test]
fn commitments_use_65_bytes_and_reject_nonboolean_infinity() {
    for curve in [PastaCurve::Pallas, PastaCurve::Vesta] {
        let kind = Kind::Commitment(curve);
        let zero_commit = match curve {
            PastaCurve::Pallas =>
                native_expected::<PallasEngine, _>(b"commit", &Commitment::<PallasEngine>::default()),
            PastaCurve::Vesta =>
                native_expected::<VestaEngine, _>(b"commit", &Commitment::<VestaEngine>::default()),
        };
        let mut identity = vec![0u8; 65]; identity[64] = 1;
        assert_eq!(zero_commit, raw_expected(field(curve), b"commit", &identity));
        assert!(execute(kind, &identity, &zero_commit));
        let mut altered = identity.clone(); altered[64] = 2;
        let claim = raw_expected(field(curve), b"commit", &altered);
        assert!(!execute(kind, &altered, &claim), "flag=2 must reject");
        let mut altered = identity.clone(); altered[64] = 0;
        let claim = raw_expected(field(curve), b"commit", &altered);
        assert!(!execute(kind, &altered, &claim), "finite (0,0) rejects");
        let mut altered = generator(curve, 1); altered.push(1);
        let claim = raw_expected(field(curve), b"commit", &altered);
        assert!(!execute(kind, &altered, &claim), "finite coords with infinity flag");
        let mut finite = generator(curve, 1); finite.push(0);
        let claim = raw_expected(field(curve), b"commit", &finite);
        assert!(execute(kind, &finite, &claim));
    }
}
#[test]
fn slice_absorption_uses_one_label_and_checks_every_record() {
    for curve in [PastaCurve::Pallas, PastaCurve::Vesta] {
        let scalar = field(curve);
        let (a,b) = (BigUint::from(2u8),BigUint::from(5u8));
        let encoded = [le(&a,32),le(&b,32)].concat();
        let native = match curve {
            PastaCurve::Pallas => {
                let values=[Fq::from(2u64),Fq::from(5u64)];
                native_expected::<PallasEngine,_>(b"batch", &values.as_slice())
            }
            PastaCurve::Vesta => {
                let values=[Fp::from(2u64),Fp::from(5u64)];
                native_expected::<VestaEngine,_>(b"batch", &values.as_slice())
            }
        };
        assert_eq!(native,raw_expected(scalar,b"batch",&encoded));
        assert!(execute(Kind::Scalars(scalar),&encoded,&native));
        let mut bad=encoded.clone();
        bad[..32].copy_from_slice(&le(&modulus(scalar),32));
        let claim=raw_expected(scalar,b"batch",&bad);
        assert!(!execute(Kind::Scalars(scalar),&bad,&claim));
        let mut two=vec![0u8;130];
        two[64]=1; two[129]=1;
        let expected=raw_expected(scalar,b"batch_commit",&two);
        assert!(execute(Kind::Commitments(curve),&two,&expected));
        two[129]=3;
        let claim=raw_expected(scalar,b"batch_commit",&two);
        assert!(!execute(Kind::Commitments(curve),&two,&claim));
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
    fn encode(&self, wires: &Self::WireRepr, mode: &mut GarbleMode<H, T>) {
        for wire in wires {
            let value = mode.issue_garbled_wire();
            mode.feed_wire(*wire, value);
        }
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
    fn encode(&self, wires: &Self::WireRepr, mode: &mut M) {
        for (id,v) in wires.iter().zip(&self.0) { mode.feed_wire(*id, v.clone()); }
    }
}
struct Sink {
    writer: BufWriter<std::fs::File>,
    hash: Blake3AccumulatingHash,
    count: u64,
}
impl CiphertextHandler for Sink {
    type Result = ([u8;32],u64);
    fn handle(&mut self, ct: S) {
        self.writer.write_all(&ct.to_bytes()).unwrap();
        self.hash.update(ct);
        self.count += 1;
    }
    fn finalize(mut self) -> Self::Result {
        self.writer.flush().unwrap();
        (self.hash.finalize(), self.count)
    }
}
struct Cleanup(std::path::PathBuf);
impl Drop for Cleanup { fn drop(&mut self) { let _=std::fs::remove_file(&self.0); } }
#[test]
fn disk_streamed_structured_commitment_matches_native_challenge() {
    let curve=PastaCurve::Pallas;
    let kind=Kind::Commitment(curve);
    let seed=6005u64;
    let mut rng=ChaChaRng::seed_from_u64(seed);
    let hasher=AesCcrGateHasher::from_rng(&mut rng);
    let path=Cleanup(std::env::temp_dir().join(format!(
        "nova-m5-{}-{seed}.ct",std::process::id())));
    let file=std::fs::OpenOptions::new().create_new(true).write(true).open(&path.0).unwrap();
    let sink=Sink {
        writer:BufWriter::with_capacity(65536,file),
        hash:Blake3AccumulatingHash::default(),count:0
    };
    let g:StreamingResult<GarbleMode<AesCcrGateHasher,Sink>,_,GarbledWire>=
        CircuitBuilder::streaming_garbling(GarbleInput(kind.input_bits()),CAP,seed,sink,
            |c,w|build(c,kind,w));
    let (digest,count)=g.ciphertext_handler_result;
    assert_eq!(std::fs::metadata(&path.0).unwrap().len(),count*16);
    eprintln!("M5 commitment nonfree={count} ciphertext_bytes={}",count*16);
    let mut correct=vec![0u8;65];correct[64]=1;
    let challenge=native_expected::<PallasEngine,_>(
        b"commit",&Commitment::<PallasEngine>::default()
    );
    let mut corrupted=correct.clone();corrupted[64]=2;
    let invalid_challenge=raw_expected(field(curve),b"commit",&corrupted);
    let pairs=[
        (correct.clone(),challenge.clone(),true),
        (corrupted,invalid_challenge,false),
        (correct.clone(),{let mut x=challenge.clone();x[0]^=1;x},false)
    ];
    for (witness,claim,expected) in pairs {
        let mut values=bits(&witness);values.extend(bits(&claim));
        let input=EvalInput(g.input_wire_values.iter().zip(values)
            .map(|(w,b)|EvaluatedWire::new_from_garbled(w,b)).collect());
        let e:StreamingResult<EvaluateMode<AesCcrGateHasher,FileSource>,_,EvaluatedWire>=
            CircuitBuilder::streaming_evaluation(
                input,CAP,
                g.true_wire_constant.label1.to_u128(),
                g.false_wire_constant.label0.to_u128(),
                hasher.clone(),FileSource::from_path(&path.0).unwrap(),
                |c,w|build(c,kind,w));
        assert_eq!(e.output_value.active_label,g.output_value.select(expected));
        assert_eq!(e.ciphertext_handler_result,digest);
    }
}
