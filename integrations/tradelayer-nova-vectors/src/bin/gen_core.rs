//! Vectors 3 (generators), 4 (keccak, transcript), 5 (poseidon).
use ff::{FromUniformBytes, PrimeField, PrimeFieldBits};
use group::GroupEncoding;
use halo2curves::pasta::{Fp, Fq, Pallas, Vesta};
use halo2curves::CurveAffine;
use nova_snark::provider::keccak::Keccak256Transcript;
use nova_snark::provider::poseidon::{PoseidonConstantsCircuit, PoseidonRO};
use nova_snark::provider::traits::DlogGroup;
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::spartan::polys::univariate::UniPoly;
use nova_snark::traits::commitment::CommitmentEngineTrait;
use nova_snark::traits::{Engine, ROMode, ROTrait, TranscriptEngineTrait, TranscriptReprTrait};
use nova_vectors::grain;
use nova_vectors::util::*;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use serde::Deserialize;
use sha2::Sha256;
use sha3::{Digest, Keccak256, Sha3_256, Shake256};

fn s(x: &str) -> String {
    x.to_string()
}

fn ptx<A: CurveAffine>(a: &A) -> String
where
    A::Base: PrimeField,
{
    if bool::from(a.is_identity()) {
        s("inf")
    } else {
        let c = a.coordinates().unwrap();
        format!("{}:{}", fe(c.x()), fe(c.y()))
    }
}

// ---------------------------------------------------------------- generators
macro_rules! gens_section {
    ($t:expr, $name:expr, $P:ty, $A:ty, $extra:expr) => {{
        let (t, name) = (&mut *$t, $name);
        // labels used by nova: b"ck" (R1CS commitment key, from_label(label, n.next_power_of_two()+1)) and b"ipa" (IPA scale key, from_label(label, 2))
        for (label, ns) in [(&b"ck"[..], vec![1025usize, 16385usize]), (&b"ipa"[..], vec![2usize])] {
            let mut ns = ns;
            for e in $extra.iter() {
                if label == b"ck" && !ns.contains(e) {
                    ns.push(*e);
                }
            }
            let label_static: &'static [u8] = if label == b"ck" { b"ck" } else { b"ipa" };
            for n in ns {
                let pts = <$P as DlogGroup>::from_label(label_static, n);
                assert_eq!(pts.len(), n);
                if n <= 16385 || true {
                    for (i, p) in pts.iter().take(16).enumerate() {
                        t.line(&[s(name), s("gen"), String::from_utf8(label.to_vec()).unwrap(), n.to_string(), i.to_string(), ptx(p), hx(p.to_bytes().as_ref())]);
                    }
                }
                let mut comp = Sha256::new();
                let mut unc = Sha256::new();
                let mut bin = Sha256::new();
                for p in pts.iter() {
                    comp.update(p.to_bytes().as_ref());
                    let c = p.coordinates().unwrap();
                    unc.update(c.x().to_repr().as_ref());
                    unc.update(c.y().to_repr().as_ref());
                }
                bin.update(&bincode::serialize(&pts).unwrap());
                t.line(&[
                    s(name),
                    s("gens_sha256"),
                    String::from_utf8(label.to_vec()).unwrap(),
                    n.to_string(),
                    hx(&comp.finalize()),
                    hx(&unc.finalize()),
                    hx(&bin.finalize()),
                ]);
            }
        }
    }};
}

fn gens_file() {
    let mut t = Tsv::default();
    t.comment(
        "generators.tsv: nova-snark 0.76.0 DlogGroup::from_label output.\n\
from_label(label, n): SHAKE256(label) is read as a stream; point i = Point::hash_to_curve(\"from_uniform_bytes\")(32 bytes i of the stream), i = 0..n (see hash_to_curve.tsv for the map).\n\
Labels nova uses (grep of src/): b\"ck\" in R1CS commitment_key (E::CE::setup(b\"ck\", max_size) -> from_label(b\"ck\", max_size.next_power_of_two() + 1); the FIRST point is h (blinding generator, DerandKey.h) and the remaining max_size.next_power_of_two() points are the ck generators) and b\"ipa\" in provider/ipa_pc.rs (E::CE::setup(b\"ipa\", 1) -> from_label(b\"ipa\", 2): h, then the single ck_s generator).\n\
Columns:\n\
 gen <curve> <label> <n> <index> <x:y> <compressed 32B hex>   first 16 points of from_label(label, n)\n\
 gens_sha256 <curve> <label> <n> <sha256 of n concatenated 32B compressed encodings> <sha256 of n concatenated x||y (64B)> <sha256 of bincode1 Vec<Affine> (u64 len + 32B each)>\n\
Pallas generators for label b\"ck\" are used by the primary (E1) commitment key, Vesta by the secondary (E2).",
    );
    let extra: Vec<usize> = std::env::var("NOVA_VEC_EXTRA_N").ok().map(|v| v.split(',').filter_map(|x| x.parse().ok()).collect()).unwrap_or_default();
    gens_section!(&mut t, "pallas", Pallas, PallasAffine, extra);
    gens_section!(&mut t, "vesta", Vesta, VestaAffine, extra);
    t.save("generators.tsv");
}

// ---------------------------------------------------------------- keccak
fn keccak_file() {
    let mut t = Tsv::default();
    t.comment(
        "keccak.tsv: hash vectors from the sha3 0.10.9 / sha2 0.10.9 crates (the ones nova uses).\n\
keccak256 <msg hex> <digest hex>   original Keccak (0x01 padding), used by Keccak256Transcript\n\
sha3_256 <msg> <digest>            NIST SHA3-256 (0x06 padding), used by nova's DigestComputer (pp_digest, vk digest)\n\
shake256 <msg> <outlen> <out>      SHAKE256, used by from_label\n\
sha256 <msg> <digest>              SHA-256, used by hash-to-curve expand_message_xmd\n\
The empty-message lines are standard known answers (asserted).",
    );
    let mut r = rng_for("keccak");
    let mut msgs: Vec<Vec<u8>> = vec![vec![], b"abc".to_vec()];
    for l in [1usize, 31, 32, 33, 55, 56, 63, 64, 65, 71, 72, 73, 100, 135, 136, 137, 199, 200, 271, 272, 273, 500, 1000, 4096] {
        msgs.push(rbytes(&mut r, l));
    }
    for _ in 0..16 {
        let l = (r.next_u32() % 300) as usize;
        msgs.push(rbytes(&mut r, l));
    }
    for m in &msgs {
        let k = Keccak256::digest(m);
        t.line(&[s("keccak256"), hx(m), hx(&k)]);
        t.line(&[s("sha3_256"), hx(m), hx(&Sha3_256::digest(m))]);
        t.line(&[s("sha256"), hx(m), hx(&Sha256::digest(m))]);
        for outlen in [32usize, 64, 136, 137, 300] {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = Shake256::default();
            h.update(m);
            let mut rd = h.finalize_xof();
            let mut out = vec![0u8; outlen];
            rd.read(&mut out);
            t.line(&[s("shake256"), hx(m), outlen.to_string(), hx(&out)]);
        }
    }
    assert_eq!(hx(&Keccak256::digest(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(hx(&Sha3_256::digest(b"")), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq!(hx(&Sha256::digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    t.save("keccak.tsv");
}

// ---------------------------------------------------------------- transcript
const LABELS: [&[u8]; 8] = [b"a", b"vk", b"U", b"p", b"c", b"r", b"t", b"s1"];

struct RefTranscript {
    round: u64,
    state: [u8; 64],
    buf: Vec<u8>,
}

fn lohi(prefix: &[u8], input: &[u8]) -> [u8; 64] {
    let mut h = Keccak256::new();
    h.update(prefix);
    h.update(input);
    let mut lo = h.clone();
    let mut hi = h;
    lo.update([0u8]);
    hi.update([1u8]);
    let mut o = [0u8; 64];
    o[..32].copy_from_slice(&lo.finalize());
    o[32..].copy_from_slice(&hi.finalize());
    o
}

impl RefTranscript {
    fn new(label: &[u8]) -> Self {
        let input = [b"NoTR".as_slice(), label].concat();
        RefTranscript { round: 0, state: lohi(&[], &input), buf: vec![] }
    }
    fn absorb(&mut self, label: &[u8], bytes: &[u8]) {
        self.buf.extend_from_slice(label);
        self.buf.extend_from_slice(bytes);
    }
    fn dom_sep(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b"NoDS");
        self.buf.extend_from_slice(b);
    }
    fn squeeze_raw(&mut self, label: &[u8]) -> [u8; 64] {
        let input = [b"NoDS".as_slice(), &self.round.to_le_bytes(), &self.state, label].concat();
        let out = lohi(&self.buf, &input);
        self.round += 1;
        self.state = out;
        self.buf.clear();
        out
    }
}

fn state_of<E: Engine>(t: &Keccak256Transcript<E>) -> ([u8; 64], u64) {
    let b = bincode::serialize(t).unwrap();
    // round u64 | state len u64 (=64) | state | buffer len u64 | buffer
    let round = u64::from_le_bytes(b[0..8].try_into().unwrap());
    assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 64);
    let mut st = [0u8; 64];
    st.copy_from_slice(&b[16..80]);
    (st, round)
}

fn rand_scalar<F: PrimeField + FromUniformBytes<64>>(r: &mut ChaCha20Rng) -> F {
    let mut b = [0u8; 64];
    r.fill_bytes(&mut b);
    <F as FromUniformBytes<64>>::from_uniform_bytes(&b)
}

fn transcript_scripts<E>(name: &str, t: &mut Tsv, r: &mut ChaCha20Rng, count: usize)
where
    E: Engine,
    E::Scalar: FromUniformBytes<64>,
{
    let ck = <E::CE as CommitmentEngineTrait<E>>::setup(b"transcript-test", 8).unwrap();
    for id in 0..count {
        t.line(&[s("begin"), format!("{name}-{id}"), s(name)]);
        let tl = LABELS[id % LABELS.len()];
        let mut tr = Keccak256Transcript::<E>::new(tl);
        let mut rf = RefTranscript::new(tl);
        t.line(&[s("new"), String::from_utf8(tl.to_vec()).unwrap()]);
        let nops = 3 + (r.next_u32() % 10) as usize;
        for _ in 0..nops {
            let lab = LABELS[(r.next_u32() % 8) as usize];
            let ls = String::from_utf8(lab.to_vec()).unwrap();
            match r.next_u32() % 8 {
                0 | 1 => {
                    let v: E::Scalar = rand_scalar(r);
                    tr.absorb(lab, &v);
                    let by = <E::Scalar as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&v);
                    rf.absorb(lab, &by);
                    t.line(&[s("absorb"), ls, s("scalar"), hx(&by)]);
                }
                2 | 3 => {
                    let n = 1 + (r.next_u32() % 6) as usize;
                    let v: Vec<E::Scalar> = (0..n).map(|_| rand_scalar(r)).collect();
                    tr.absorb(lab, &v.as_slice());
                    let by = <&[E::Scalar] as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&v.as_slice());
                    rf.absorb(lab, &by);
                    t.line(&[s("absorb"), ls, s("scalars"), hx(&by)]);
                }
                4 | 5 => {
                    let n = 1 + (r.next_u32() % 8) as usize;
                    let v: Vec<E::Scalar> = (0..n).map(|_| rand_scalar(r)).collect();
                    let blind: E::Scalar = rand_scalar(r);
                    let c = <E::CE as CommitmentEngineTrait<E>>::commit(&ck, &v, &blind);
                    tr.absorb(lab, &c);
                    let by = <_ as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&c);
                    rf.absorb(lab, &by);
                    t.line(&[s("absorb"), ls, s("commitment"), hx(&by)]);
                }
                6 => {
                    let ev: Vec<E::Scalar> = (0..4).map(|_| rand_scalar(r)).collect();
                    let poly = UniPoly::<E::Scalar>::from_evals_deg3(&ev);
                    tr.absorb(lab, &poly);
                    let by = <UniPoly<E::Scalar> as TranscriptReprTrait<E::GE>>::to_transcript_bytes(&poly);
                    rf.absorb(lab, &by);
                    t.line(&[s("absorb"), ls, s("unipoly"), hx(&by)]);
                }
                _ => {
                    // squeeze
                    let c = tr.squeeze(lab).unwrap();
                    let raw = rf.squeeze_raw(lab);
                    let (st, round) = state_of(&tr);
                    assert_eq!(st, raw);
                    assert_eq!(c, <E::Scalar as FromUniformBytes<64>>::from_uniform_bytes(&raw));
                    t.line(&[s("squeeze"), ls, fe(&c), hx(&raw), (round - 1).to_string()]);
                }
            }
            if r.next_u32() % 9 == 0 {
                let ds = b"dom";
                tr.dom_sep(ds);
                rf.dom_sep(ds);
                t.line(&[s("domsep"), s("dom")]);
            }
            if r.next_u32() % 5 == 0 {
                let lab = LABELS[(r.next_u32() % 8) as usize];
                let ls = String::from_utf8(lab.to_vec()).unwrap();
                let nb = [2usize, 8, 63, 64, 100, 128, 200, 250, 253][(r.next_u32() % 9) as usize];
                let one = r.next_u32() % 2 == 0;
                let c = tr.squeeze_bits(lab, nb, one).unwrap();
                let raw = rf.squeeze_raw(lab);
                let (st, _) = state_of(&tr);
                assert_eq!(st, raw);
                t.line(&[s("squeeze_bits"), ls, nb.to_string(), s(if one { "1" } else { "0" }), fe(&c), hx(&raw)]);
            }
        }
        // finish with a squeeze so each script ends in a challenge
        let c = tr.squeeze(b"end").unwrap();
        let raw = rf.squeeze_raw(b"end");
        let (st, round) = state_of(&tr);
        assert_eq!(st, raw);
        t.line(&[s("squeeze"), s("end"), fe(&c), hx(&raw), (round - 1).to_string()]);
        t.line(&[s("end")]);
    }
}

fn transcript_file() {
    let mut t = Tsv::default();
    t.comment(
        "transcript.tsv: scripted Keccak256Transcript<E> (nova-snark 0.76.0 provider/keccak.rs) sessions, engine = pallas | vesta.\n\
Challenges are E::Scalar: pallas engine -> fq, vesta engine -> fp. Field elements 64 hex (32 B LE).\n\
Algorithm (also re-implemented independently in this generator and asserted equal):\n\
 new(label):    state = lohi(\"\", \"NoTR\" || label), round = 0, buf = \"\"\n\
 absorb(label, o): buf += label || o.to_transcript_bytes()\n\
 dom_sep(b):    buf += \"NoDS\" || b\n\
 squeeze(label): input = \"NoDS\" || round.to_le_bytes() (u64) || state (64 B) || label; state' = lohi(buf, input); round += 1; buf = \"\"; challenge = Scalar::from_uniform_bytes(state')\n\
 lohi(prefix, input): h = Keccak256(prefix || input); lo = Keccak256(prefix || input || 0x00), hi = Keccak256(prefix || input || 0x01); output = lo || hi (64 B). (Keccak256 original padding.)\n\
 squeeze_bits(label, nb, one): same state update; value = little-endian integer from the first nb bits of state' (byte i = state'[i], the partial byte masked), then if one the bit nb-1 is forced to 1\n\
to_transcript_bytes: scalar = 32 B LE repr; &[scalar] = concatenation; Commitment = x(32 LE) || y(32 LE) || infinity byte (1 = identity, then x=y=0); UniPoly = coefficients except the linear term (coeffs[0], coeffs[2], coeffs[3] for a cubic), 32 B LE each.\n\
Records:\n\
 begin <id> <engine>\n\
 new <label>\n\
 absorb <label> <kind> <bytes hex>      (kind: scalar|scalars|commitment|unipoly, informational; the hex is exactly what is appended after the label)\n\
 domsep <ascii>\n\
 squeeze <label> <challenge hex> <state' 64 B hex> <round index used>\n\
 squeeze_bits <label> <nb> <start_with_one 0|1> <challenge hex> <state' hex>\n\
 end",
    );
    let mut r = rng_for("transcript");
    transcript_scripts::<PallasEngine>("pallas", &mut t, &mut r, 40);
    transcript_scripts::<VestaEngine>("vesta", &mut t, &mut r, 40);
    t.save("transcript.tsv");
}

// ---------------------------------------------------------------- poseidon
#[derive(Deserialize)]
struct Mds<F> {
    m: Vec<Vec<F>>,
    _m_inv: Vec<Vec<F>>,
    _m_hat: Vec<Vec<F>>,
    _m_hat_inv: Vec<Vec<F>>,
    _m_prime: Vec<Vec<F>>,
    _m_double_prime: Vec<Vec<F>>,
}
#[derive(Deserialize)]
struct Sparse<F> {
    _w_hat: Vec<F>,
    _v_rest: Vec<F>,
}
#[derive(Deserialize)]
struct Pc<F> {
    mds: Mds<F>,
    crc: Vec<F>,
    _psm: Vec<Vec<F>>,
    _sm: Vec<Sparse<F>>,
    _strength: u32,
    rf: u64,
    rp: u64,
    _ht: u32,
}
#[derive(Deserialize)]
struct Pcc<F> {
    wide: Pc<F>,
    narrow: Pc<F>,
}

struct Plain<F> {
    width: usize,
    rf: usize,
    rp: usize,
    m: Vec<Vec<F>>,
    rc: Vec<F>,
}

impl<F: PrimeField + PrimeFieldBits> Plain<F> {
    fn new(p: &Pc<F>, width: usize) -> Self {
        let (rf, rp) = (p.rf as usize, p.rp as usize);
        let rc = grain::generate_constants::<F>(1, 1, 255, width as u16, rf as u16, rp as u16);
        assert_eq!(rc.len(), width * (rf + rp));
        // sanity: the library's compressed constants have rf*width + rp entries
        assert_eq!(p.crc.len(), rf * width + rp);
        // MDS: Cauchy matrix M[i][j] = 1 / (i + width + j)
        for i in 0..width {
            for j in 0..width {
                let v = (F::from((i + width + j) as u64)).invert().unwrap();
                assert!(v == p.mds.m[i][j], "mds is not the Cauchy matrix");
            }
        }
        Plain { width, rf, rp, m: p.mds.m.clone(), rc }
    }
    fn permute(&self, st: &mut Vec<F>) {
        let t = self.width;
        let sbox = |x: &mut F| {
            let x2 = x.square();
            *x = x2.square() * *x;
        };
        let mds = |st: &mut Vec<F>| {
            let old = st.clone();
            for j in 0..t {
                let mut a = F::ZERO;
                for i in 0..t {
                    a += self.m[i][j] * old[i];
                }
                st[j] = a;
            }
        };
        let total = self.rf + self.rp;
        for r in 0..total {
            for i in 0..t {
                st[i] += self.rc[r * t + i];
            }
            let full = r < self.rf / 2 || r >= self.rf / 2 + self.rp;
            if full {
                for x in st.iter_mut() {
                    sbox(x);
                }
            } else {
                sbox(&mut st[0]);
            }
            mds(st);
        }
    }
    /// SAFE-style sponge used by nova's PoseidonRO: IO pattern [Absorb(n), Squeeze(1)]
    fn ro(&self, input: &[F]) -> F {
        let rate = self.width - 1;
        let tag = io_tag(input.len() as u32);
        let mut st = vec![F::ZERO; self.width];
        st[0] = u128_to_f::<F>(tag);
        let mut pos = 0usize;
        for e in input {
            if pos == rate {
                self.permute(&mut st);
                pos = 0;
            }
            st[1 + pos] += *e;
            pos += 1;
        }
        self.permute(&mut st);
        st[1]
    }
}

fn u128_to_f<F: PrimeField>(v: u128) -> F {
    let mut repr = F::Repr::default();
    repr.as_mut()[..16].copy_from_slice(&v.to_le_bytes());
    Option::from(F::from_repr(repr)).unwrap()
}

/// IOPattern([Absorb(n), Squeeze(1)]).value(0) of the SAFE API in neptune/nova.
fn io_tag(n: u32) -> u128 {
    let base: u128 = (0i32 - 159) as i128 as u128;
    let (mut x_i, mut state): (u128, u128) = (1, 0);
    let mut upd = |a: u32| {
        x_i = x_i.wrapping_mul(base);
        state = state.wrapping_add(x_i.wrapping_mul(a as u128));
    };
    // ops: Absorb(n) (skipped when n == 0, count 0), Squeeze(1), then domain separator 0
    if n > 0 {
        upd(n + (1u32 << 31));
    }
    upd(1);
    upd(0);
    state
}

fn trunc<F: PrimeField + PrimeFieldBits>(h: F, nb: usize, one: bool) -> F {
    let bits = h.to_le_bits();
    let mut res = F::ZERO;
    let mut coeff = F::ONE;
    for i in 0..nb {
        if bits[i] {
            res += coeff;
        }
        coeff = coeff + coeff;
    }
    if one {
        let msb = coeff * F::from(2u64).invert().unwrap();
        if !bits[nb - 1] {
            res += msb;
        }
    }
    res
}

fn poseidon_field<F>(name: &str, t: &mut Tsv, pf: &mut Tsv, r: &mut ChaCha20Rng)
where
    F: PrimeField + PrimeFieldBits + FromUniformBytes<64> + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let consts = PoseidonConstantsCircuit::<F>::default();
    let bytes = bincode::serialize(&consts).unwrap();
    let pc: Pcc<F> = bincode::deserialize(&bytes).unwrap();
    // the serialization of the constants is long; record its size and hash for reference
    pf.line(&[s(name), s("constants_bincode_len"), bytes.len().to_string(), hx(&Sha256::digest(&bytes))]);
    for (mode, p, width) in [("wide", &pc.wide, 25usize), ("narrow", &pc.narrow, 6usize)] {
        let pl = Plain::<F>::new(p, width);
        pf.line(&[s(name), s(mode), s("params"), format!("width={}", width), format!("rate={}", width - 1), format!("full_rounds={}", pl.rf), format!("partial_rounds={}", pl.rp), s("alpha=5"), s("capacity=1 (state[0])")]);
        pf.line(&[s(name), s(mode), s("grain_init"), s("field=1"), s("sbox=1"), s("field_size=255"), format!("t={}", width), format!("rf={}", pl.rf), format!("rp={}", pl.rp)]);
        for i in 0..width {
            pf.line(&[s(name), s(mode), s("mds_row"), i.to_string(), pl.m[i].iter().map(|x| fe(x)).collect::<Vec<_>>().join("")]);
        }
        for rd in 0..(pl.rf + pl.rp) {
            pf.line(&[s(name), s(mode), s("rc_round"), rd.to_string(), pl.rc[rd * width..(rd + 1) * width].iter().map(|x| fe(x)).collect::<Vec<_>>().join("")]);
        }
    }
    let pw = Plain::<F>::new(&pc.wide, 25);
    let pn = Plain::<F>::new(&pc.narrow, 6);
    let rnd = |r: &mut ChaCha20Rng| rand_scalar::<F>(r);
    let mut sid = 0usize;
    let mut run = |t: &mut Tsv, r: &mut ChaCha20Rng, mode: ROMode, plan: &[(usize, usize, bool)]| {
        // plan: for each squeeze: (number of elements absorbed before it, num_bits, start_with_one)
        let mname = if mode == ROMode::Wide { "wide" } else { "narrow" };
        let pl = if mode == ROMode::Wide { &pw } else { &pn };
        let mut ro = <PoseidonRO<F> as ROTrait<F>>::new_with_mode(consts.clone(), mode);
        t.line(&[s("begin"), format!("{name}-{mname}-{sid}"), s(name), s(mname)]);
        sid += 1;
        let mut state: Vec<F> = vec![];
        for &(n, nb, one) in plan {
            for k in 0..n {
                let v = match (k % 7, r.next_u32() % 11) {
                    (_, 0) => F::ZERO,
                    (_, 1) => F::ONE,
                    (_, 2) => -F::ONE,
                    _ => rnd(r),
                };
                ro.absorb(v);
                state.push(v);
                t.line(&[s("absorb"), fe(&v)]);
            }
            let out = ro.squeeze(nb, one);
            let raw = pl.ro(&state);
            assert_eq!(out, trunc(raw, nb, one), "plain Poseidon disagrees with nova ({name} {mname} n={n} nb={nb})");
            state = vec![raw];
            t.line(&[s("squeeze"), nb.to_string(), s(if one { "1" } else { "0" }), fe(&out), fe(&raw)]);
        }
        t.line(&[s("end")]);
    };
    // every absorb count 0..=60 for wide, then boundaries around multiples of 24
    for n in 0..=60 {
        run(t, r, ROMode::Wide, &[(n, 128, false)]);
    }
    for n in [71usize, 72, 73, 95, 96, 97, 120, 121] {
        run(t, r, ROMode::Wide, &[(n, 250, false)]);
    }
    let nbs: [(usize, bool); 8] = [(128, false), (128, true), (250, false), (2, false), (64, true), (254, false), (253, true), (1 + 7, false)];
    for _ in 0..40 {
        let k = 1 + (r.next_u32() % 4) as usize;
        let plan: Vec<(usize, usize, bool)> = (0..k).map(|_| {
            let (nb, one) = nbs[(r.next_u32() % 8) as usize];
            ((r.next_u32() % 30) as usize, nb, one)
        }).collect();
        run(t, r, ROMode::Wide, &plan);
    }
    // narrow mode (not used by CompressedSNARK but part of the RO type)
    for n in 0..=16 {
        run(t, r, ROMode::Narrow, &[(n, 128, false)]);
    }
    for _ in 0..10 {
        let k = 1 + (r.next_u32() % 3) as usize;
        let plan: Vec<(usize, usize, bool)> = (0..k).map(|_| {
            let (nb, one) = nbs[(r.next_u32() % 8) as usize];
            ((r.next_u32() % 12) as usize, nb, one)
        }).collect();
        run(t, r, ROMode::Narrow, &plan);
    }
}

fn poseidon_file() {
    let mut t = Tsv::default();
    t.comment(
        "poseidon.tsv: nova-snark 0.76.0 provider/poseidon.rs PoseidonRO<F> scripted sessions with PoseidonConstantsCircuit::default().\n\
Field name = the field the RO is over (its elements are Base elements of the engine): fp (= Pallas base = Vesta scalar) or fq. Elements 64 hex (32 B LE).\n\
CompressedSNARK uses ROMode::Wide (the default, ROTrait::new). Narrow is only provided as a reference for the type.\n\
Records:\n\
 begin <id> <field> <mode>\n\
 absorb <element>                      (appended to the RO state)\n\
 squeeze <num_bits> <start_with_one 0|1> <output> <raw>\n\
     output = nova's squeeze(num_bits, start_with_one): the first num_bits LITTLE-endian bits of raw's canonical integer, as a field element, then bit num_bits-1 forced to 1 if start_with_one.\n\
     raw = the full Poseidon output before truncation. After a squeeze the RO state becomes the single element [raw] (NOT the truncated output).\n\
 end\n\
Hash definition (verified here by an independent plain implementation, see poseidon_params.tsv): SAFE sponge, width t = arity+1 (wide arity 24 -> t = 25, rate 24; narrow arity 5 -> t = 6, rate 5), state[0] = capacity tag, state[1..t] = rate.\n\
 tag = x*(n + 2^31) + x^2   (mod 2^128, as a little-endian u128 -> field element) for n >= 1 absorbed elements, with x = (2^128 - 159); for n = 0 tag = x.  (This is IOPattern[Absorb(n), Squeeze(1)].value(0).)\n\
 absorb: for each element, if the absorb position == rate then permute and reset the position to 0; state[1 + pos] += element; pos += 1.   squeeze: permute once, raw = state[1].\n\
 permutation: for round r in 0..rf+rp: state[i] += rc[r*t + i] for all i; S-box x^5 on all t elements if r < rf/2 or r >= rf/2 + rp else only on state[0]; state = M * state (M symmetric, so M*state == state*M).",
    );
    let mut pf = Tsv::default();
    pf.comment(
        "poseidon_params.tsv: the Poseidon parameters behind PoseidonConstantsCircuit::<F>::default() (Neptune-derived, Strength::Standard, HashType::Sponge, domain tag 0).\n\
They are generated deterministically; nothing is random:\n\
 - round numbers (rf full, rp partial) from calc_round_numbers (the Poseidon paper's script with a security margin: rf += 2, rp = ceil(1.075*rp)), the values are listed below;\n\
 - MDS matrix: Cauchy, M[i][j] = 1 / (i + t + j) over the field (t = width), symmetric (asserted equal to the matrix nova serialises);\n\
 - round constants: the Grain LFSR of the Poseidon reference (generate_parameters_grain.sage) with init (field=1 prime field, sbox=1 x^5, field_size=255, t, rf, rp) -> constants taken 255-bit (top bits masked, rejection sampled below p), (rf+rp)*t of them. The generator is the file src/grain.rs (copy of nova's round_constants.rs).\n\
 The library additionally stores compressed/sparse versions (optimised, equivalent); a plain implementation with the raw constants reproduces every output in poseidon.tsv (asserted).\n\
Records: <field> <mode> params ... | grain_init ... | mds_row <i> <t elements concat, 32 B LE each> | rc_round <round> <t constants concat>\n\
 <field> constants_bincode_len <bytes> <sha256>: size/hash of bincode1(PoseidonConstantsCircuit) as stored inside the vk (ro_consts_primary/secondary fields).",
    );
    let mut r = rng_for("poseidon");
    poseidon_field::<Fp>("fp", &mut t, &mut pf, &mut r);
    poseidon_field::<Fq>("fq", &mut t, &mut pf, &mut r);
    t.save("poseidon.tsv");
    pf.save("poseidon_params.tsv");
}

fn main() {
    gens_file();
    keccak_file();
    transcript_file();
    poseidon_file();
}
