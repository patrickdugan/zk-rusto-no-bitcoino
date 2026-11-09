//! Vectors 1-3: fields, curves, serialization, hash-to-curve.
use ff::{Field, FromUniformBytes, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding};
use halo2curves::pasta::{Fp, Fq, Pallas, PallasAffine, Vesta, VestaAffine};
use halo2curves::CurveAffine;
use nova_vectors::h2c;
use nova_vectors::util::*;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use sha2::Sha256;

fn modulus_le<F: PrimeField>() -> [u8; 32] {
    let s = F::MODULUS.trim_start_matches("0x");
    let be = hex::decode(format!("{:0>64}", s)).unwrap();
    let mut le: [u8; 32] = be.try_into().unwrap();
    le.reverse();
    le
}

fn le_add_small(a: &[u8; 32], k: u64) -> Option<[u8; 32]> {
    let mut o = *a;
    let mut carry = k as u128;
    for b in o.iter_mut() {
        let v = *b as u128 + (carry & 0xff);
        *b = v as u8;
        carry = (carry >> 8) + (v >> 8);
    }
    if carry != 0 {
        None
    } else {
        Some(o)
    }
}

fn from_repr<F: PrimeField>(b: &[u8; 32]) -> Option<F> {
    let mut r = F::Repr::default();
    r.as_mut().copy_from_slice(b);
    Option::from(F::from_repr(r))
}

fn opt<F: PrimeField>(o: Option<F>) -> String {
    match o {
        Some(f) => fe(&f),
        None => "none".into(),
    }
}

fn s(x: &str) -> String {
    x.to_string()
}

fn field_vectors<F>(name: &str, t: &mut Tsv, r: &mut ChaCha20Rng)
where
    F: PrimeField + FromUniformBytes<64> + FromUniformBytes<48>,
{
    let rnd = |r: &mut ChaCha20Rng| -> F {
        let mut b = [0u8; 64];
        r.fill_bytes(&mut b);
        <F as FromUniformBytes<64>>::from_uniform_bytes(&b)
    };
    t.line(&[s(name), s("const"), s("modulus_le"), hx(&modulus_le::<F>())]);
    t.line(&[s(name), s("const"), s("num_bits"), F::NUM_BITS.to_string()]);
    t.line(&[s(name), s("const"), s("s"), F::S.to_string()]);
    t.line(&[s(name), s("const"), s("root_of_unity"), fe(&F::ROOT_OF_UNITY)]);
    t.line(&[s(name), s("const"), s("root_of_unity_inv"), fe(&F::ROOT_OF_UNITY_INV)]);
    t.line(&[s(name), s("const"), s("delta"), fe(&F::DELTA)]);
    t.line(&[s(name), s("const"), s("multiplicative_generator"), fe(&F::MULTIPLICATIVE_GENERATOR)]);
    t.line(&[s(name), s("const"), s("two_inv"), fe(&F::TWO_INV)]);

    let mut elems: Vec<F> = vec![
        F::ZERO,
        F::ONE,
        -F::ONE,
        F::from(2u64),
        F::from(3u64),
        F::TWO_INV,
        F::ROOT_OF_UNITY,
        F::DELTA,
    ];
    for _ in 0..192 {
        elems.push(rnd(r));
    }
    assert_eq!(elems.len(), 200);
    for i in 0..200 {
        let a = elems[i];
        let b = if i < 8 { elems[(i + 3) % 8] } else { rnd(r) };
        t.line(&[s(name), s("add"), fe(&a), fe(&b), fe(&(a + b))]);
        t.line(&[s(name), s("sub"), fe(&a), fe(&b), fe(&(a - b))]);
        t.line(&[s(name), s("mul"), fe(&a), fe(&b), fe(&(a * b))]);
        t.line(&[s(name), s("sqr"), fe(&a), fe(&a.square())]);
        t.line(&[s(name), s("neg"), fe(&a), fe(&(-a))]);
        t.line(&[s(name), s("inv"), fe(&a), opt::<F>(Option::<F>::from(a.invert()))]);
        t.line(&[s(name), s("sqrt"), fe(&a), opt::<F>(Option::<F>::from(a.sqrt()))]);
        let sq = a.square();
        let rt: F = Option::from(sq.sqrt()).expect("square has root");
        assert!(rt == a || rt == -a);
        t.line(&[s(name), s("sqrt"), fe(&sq), fe(&rt)]);
    }
    let mut specials64: Vec<Vec<u8>> = vec![vec![0u8; 64], vec![0xffu8; 64]];
    let mut one = vec![0u8; 64];
    one[0] = 1;
    specials64.push(one);
    for i in 0..200 {
        let b = if i < specials64.len() { specials64[i].clone() } else { rbytes(r, 64) };
        let arr: [u8; 64] = b.clone().try_into().unwrap();
        t.line(&[s(name), s("from_uniform64"), hx(&b), fe(&<F as FromUniformBytes<64>>::from_uniform_bytes(&arr))]);
    }
    for i in 0..200 {
        let b = match i {
            0 => vec![0u8; 48],
            1 => vec![0xffu8; 48],
            _ => rbytes(r, 48),
        };
        let arr: [u8; 48] = b.clone().try_into().unwrap();
        t.line(&[s(name), s("from_uniform48"), hx(&b), fe(&<F as FromUniformBytes<48>>::from_uniform_bytes(&arr))]);
    }
    let p = modulus_le::<F>();
    let mut reprs: Vec<[u8; 32]> = Vec::new();
    for e in elems.iter() {
        let mut b = [0u8; 32];
        b.copy_from_slice(e.to_repr().as_ref());
        reprs.push(b);
    }
    let pm1 = {
        let mut x = p;
        x[0] -= 1;
        x
    };
    reprs.push(pm1);
    for k in 0..4u64 {
        if let Some(x) = le_add_small(&p, k) {
            reprs.push(x);
        }
    }
    reprs.push(le_add_small(&p, 1u64 << 40).unwrap());
    reprs.push([0xff; 32]);
    let mut hi = [0u8; 32];
    hi[31] = 0x80;
    reprs.push(hi);
    let mut hi2 = pm1;
    hi2[31] |= 0x80;
    reprs.push(hi2);
    for _ in 0..40 {
        let mut b = [0u8; 32];
        r.fill_bytes(&mut b);
        reprs.push(b);
    }
    for b in reprs {
        let v: Option<F> = from_repr::<F>(&b);
        if let Some(f) = v {
            assert_eq!(f.to_repr().as_ref(), &b[..]);
        }
        t.line(&[s(name), s("from_repr"), hx(&b), opt(v)]);
    }
}

fn pt<A: CurveAffine>(a: &A) -> String
where
    A::Base: PrimeField,
{
    if bool::from(a.is_identity()) {
        "inf".into()
    } else {
        let c = a.coordinates().unwrap();
        format!("{}:{}", fe(c.x()), fe(c.y()))
    }
}

macro_rules! curve_vectors {
    ($name:expr, $P:ty, $A:ty, $B:ty, $S:ty, $t:expr, $sr:expr, $r:expr) => {{
        let (name, t, sr, r) = ($name, &mut *$t, &mut *$sr, &mut *$r);
        let rs = |r: &mut ChaCha20Rng| -> $S {
            let mut b = [0u8; 64];
            r.fill_bytes(&mut b);
            <$S as FromUniformBytes<64>>::from_uniform_bytes(&b)
        };
        let g = <$A as PrimeCurveAffine>::generator();
        t.line(&[s(name), s("const"), s("b"), s("5")]);
        t.line(&[s(name), s("const"), s("a"), s("0")]);
        t.line(&[s(name), s("gen"), pt(&g)]);
        t.line(&[s(name), s("id"), pt(&<$A as PrimeCurveAffine>::identity())]);
        t.line(&[s(name), s("order_minus_one_scalar"), fe(&-<$S>::ONE)]);
        let mut pts: Vec<$P> = vec![<$P>::identity(), <$P>::generator(), <$P>::generator().double(), -<$P>::generator()];
        for _ in 0..60 {
            pts.push(<$P>::generator() * rs(r));
        }
        let n = pts.len();
        for i in 0..100 {
            let p = pts[i % n];
            let q = if i < 8 { pts[(i + 1) % 4] } else { pts[(i * 7 + 3) % n] };
            let (pa, qa) = (p.to_affine(), q.to_affine());
            t.line(&[s(name), s("add"), pt(&pa), pt(&qa), pt(&(p + q).to_affine())]);
            t.line(&[s(name), s("dbl"), pt(&pa), pt(&p.double().to_affine())]);
            t.line(&[s(name), s("neg"), pt(&pa), pt(&(-p).to_affine())]);
            if i < 60 {
                t.line(&[s(name), s("add"), pt(&pa), pt(&pa), pt(&(p + p).to_affine())]);
                t.line(&[s(name), s("add"), pt(&pa), pt(&(-p).to_affine()), pt(&(p + (-p)).to_affine())]);
            }
        }
        let order_m1 = -<$S>::ONE;
        let mut ks: Vec<$S> = vec![
            <$S>::ZERO,
            <$S>::ONE,
            <$S>::from(2u64),
            order_m1,
            order_m1 - <$S>::ONE,
            <$S>::from(0xffff_ffff_ffff_ffffu64),
        ];
        for _ in 0..120 {
            ks.push(rs(r));
        }
        for (i, k) in ks.iter().enumerate() {
            let p = if i < 6 { pts[i % 4] } else { pts[(i * 5 + 1) % n] };
            t.line(&[s(name), s("mul"), pt(&p.to_affine()), fe(k), pt(&(p * *k).to_affine())]);
        }
        assert!(bool::from((<$P>::generator() * order_m1 + <$P>::generator()).is_identity()));
        for p in pts.iter().take(40) {
            let a = p.to_affine();
            let c = a.to_bytes();
            t.line(&[s(name), s("comp"), pt(&a), hx(c.as_ref())]);
            let back = <$A as GroupEncoding>::from_bytes(&c);
            assert!(bool::from(back.is_some()) && back.unwrap() == a);
        }
        let mut cases: Vec<[u8; 32]> = Vec::new();
        for p in pts.iter().take(12) {
            let a = p.to_affine();
            let mut c: [u8; 32] = a.to_bytes().as_ref().try_into().unwrap();
            cases.push(c);
            c[31] ^= 0x80;
            cases.push(c);
        }
        cases.push([0u8; 32]);
        let mut z = [0u8; 32];
        z[31] = 0x80;
        cases.push(z);
        cases.push([0xff; 32]);
        for i in 0..80 {
            let mut b = [0u8; 32];
            r.fill_bytes(&mut b);
            if i % 2 == 0 {
                b[31] &= 0x3f;
            }
            cases.push(b);
        }
        cases.push(modulus_le::<$B>());
        for c in cases {
            let mut rp = <$A as GroupEncoding>::Repr::default();
            rp.as_mut().copy_from_slice(&c);
            let d: Option<$A> = Option::from(<$A as GroupEncoding>::from_bytes(&rp));
            let ds = match d {
                Some(a) => pt(&a),
                None => s("none"),
            };
            t.line(&[s(name), s("decomp"), hx(&c), ds]);
        }
        for _ in 0..40 {
            let x = {
                let mut b = [0u8; 64];
                r.fill_bytes(&mut b);
                <$B as FromUniformBytes<64>>::from_uniform_bytes(&b)
            };
            let y2 = x.square() * x + <$B>::from(5u64);
            let y: Option<$B> = Option::from(y2.sqrt());
            if let Some(y) = y {
                let a: Option<$A> = Option::from(<$A as CurveAffine>::from_xy(x, y));
                assert!(a.is_some());
                t.line(&[s(name), s("from_xy"), fe(&x), fe(&y), s("1")]);
                let y1 = y + <$B>::ONE;
                let a2: Option<$A> = Option::from(<$A as CurveAffine>::from_xy(x, y1));
                t.line(&[s(name), s("from_xy"), fe(&x), fe(&y1), s(if a2.is_some() { "1" } else { "0" })]);
            } else {
                let a2: Option<$A> = Option::from(<$A as CurveAffine>::from_xy(x, x));
                t.line(&[s(name), s("from_xy"), fe(&x), fe(&x), s(if a2.is_some() { "1" } else { "0" })]);
            }
        }

        let mut sp: Vec<$P> = vec![<$P>::identity(), <$P>::generator()];
        for _ in 0..30 {
            sp.push(<$P>::generator() * rs(r));
        }
        for p in sp.iter() {
            let a = p.to_affine();
            let ba = bincode::serialize(&a).unwrap();
            let bp = bincode::serialize(p).unwrap();
            assert_eq!(ba.len(), 32);
            assert_eq!(ba, bp);
            assert_eq!(ba.as_slice(), a.to_bytes().as_ref());
            sr.line(&[s(name), s("affine"), pt(&a), hx(&ba)]);
            sr.line(&[s(name), s("proj"), pt(&a), hx(&bp)]);
            let back: $A = bincode::deserialize(&ba).unwrap();
            assert_eq!(back, a);
            let backp: $P = bincode::deserialize(&bp).unwrap();
            assert_eq!(backp.to_affine(), a);
        }
        let va: Vec<$A> = sp.iter().take(5).map(|p| p.to_affine()).collect();
        let bv = bincode::serialize(&va).unwrap();
        assert_eq!(bv.len(), 8 + 5 * 32);
        sr.line(&[s(name), s("affine_vec5"), va.iter().map(|a| pt(a)).collect::<Vec<_>>().join(","), hx(&bv)]);
        for _ in 0..10 {
            let k = rs(r);
            let bk = bincode::serialize(&k).unwrap();
            assert_eq!(bk.len(), 32);
            assert_eq!(bk.as_slice(), k.to_repr().as_ref());
            sr.line(&[s(name), s("scalar"), fe(&k), hx(&bk)]);
        }
        let sv: Vec<$S> = (0..4).map(|_| rs(r)).collect();
        sr.line(&[s(name), s("scalar_vec4"), sv.iter().map(|k| fe(k)).collect::<Vec<_>>().join(","), hx(&bincode::serialize(&sv).unwrap())]);
    }};
}

fn xmd_vectors(t: &mut Tsv, r: &mut ChaCha20Rng) {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let o = h2c::expand_message::<Sha256>(dst, b"", b"", 0x20);
    assert_eq!(hx(&o), "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
    let o = h2c::expand_message::<Sha256>(dst, b"", b"abc", 0x20);
    assert_eq!(hx(&o), "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615");
    t.comment(
        "xmd <dst_hex> <message_hex> <len_in_bytes> <output_hex>: expand_message_xmd with SHA-256 (RFC 9380 5.3.1).\n\
The first two lines are RFC 9380 K.1 test vectors (asserted); the rest are produced by the halo2curves 0.9.0 function (copied verbatim into this crate).\n\
DST is the full DST bytes (nova uses \"from_uniform_bytes\" || \"pallas:SHA-256_SVDW_RO_\" etc.).",
    );
    let mut cases: Vec<(Vec<u8>, Vec<u8>, usize)> = vec![(dst.to_vec(), vec![], 32), (dst.to_vec(), b"abc".to_vec(), 32), (dst.to_vec(), vec![], 128)];
    let d_p: Vec<u8> = [b"from_uniform_bytes".as_slice(), b"pallas:SHA-256_SVDW_RO_"].concat();
    let d_v: Vec<u8> = [b"from_uniform_bytes".as_slice(), b"vesta:SHA-256_SVDW_RO_"].concat();
    for i in 0..60 {
        let dstc = if i % 2 == 0 { d_p.clone() } else { d_v.clone() };
        cases.push((dstc, rbytes(r, 32), 96));
    }
    for (i, l) in [1usize, 31, 32, 33, 63, 64, 65, 96, 255, 256, 500].iter().enumerate() {
        let msg = rbytes(r, i * 5);
        cases.push((d_p.clone(), msg, *l));
    }
    for (dstv, msg, l) in cases {
        let o = h2c::expand_message::<Sha256>(&dstv, b"", &msg, l);
        t.line(&[s("xmd"), hx(&dstv), hx(&msg), l.to_string(), hx(&o)]);
    }
}

macro_rules! h2c_vectors {
    ($name:expr, $P:ty, $dom:expr, $t:expr, $inputs:expr) => {{
        let (name, t) = ($name, &mut *$t);
        let z = <$P>::SVDW_Z;
        let suite = h2c::Suite::<$P, Sha256, 48>::new($dom, z, h2c::Method::SVDW);
        let [c1, c2, c3, c4] = h2c::svdw_precomputed_constants::<$P>(z);
        t.line(&[s(name), s("svdw_const"), fe(&z), fe(&c1), fe(&c2), fe(&c3), fe(&c4)]);
        for msg in $inputs.iter() {
            let (u0, u1) = suite.hash_to_field(b"from_uniform_bytes", msg);
            let q0 = h2c::svdw_map_to_curve::<$P>(u0, c1, c2, c3, c4, z).to_affine();
            let q1 = h2c::svdw_map_to_curve::<$P>(u1, c1, c2, c3, c4, z).to_affine();
            let sum = (q0.to_curve() + q1.to_curve()).to_affine();
            let lib = <$P as halo2curves::CurveExt>::hash_to_curve("from_uniform_bytes")(msg).to_affine();
            assert_eq!(sum, lib, "hash_to_curve disagrees with the local copy");
            t.line(&[s(name), s("h2c"), hx(msg), fe(&u0), fe(&u1), pt(&q0), pt(&q1), pt(&lib)]);
        }
    }};
}

fn main() {
    {
        let mut t = Tsv::default();
        t.comment(
            "fields.tsv: halo2curves 0.9.0 pasta fields.\n\
fp = Fp = Pallas base field = Vesta scalar field, modulus 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001\n\
fq = Fq = Pallas scalar field = Vesta base field, modulus 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001\n\
Every field element is 64 hex chars = 32 bytes little-endian canonical repr (ff::PrimeField::to_repr). `none` = the operation returns None.\n\
Columns (tab separated): <field> <op> <args...> <result>\n\
 const modulus_le|num_bits|s|root_of_unity|root_of_unity_inv|delta|multiplicative_generator|two_inv <value>\n\
 add|sub|mul a b r ; sqr|neg a r ; inv a r|none (none for a=0)\n\
 sqrt a r|none (none when a is a non-residue; r is one root, either root is mathematically valid)\n\
 from_uniform64 <64 bytes hex> r : FromUniformBytes<64>::from_uniform_bytes (little-endian 512-bit integer mod p)\n\
 from_uniform48 <48 bytes hex> r : FromUniformBytes<48>::from_uniform_bytes (little-endian 384-bit integer mod p; used by hash-to-curve)\n\
 from_repr <32 bytes hex> r|none : PrimeField::from_repr, none for non-canonical (>= modulus)",
        );
        let mut r = rng_for("fields");
        field_vectors::<Fp>("fp", &mut t, &mut r);
        field_vectors::<Fq>("fq", &mut t, &mut r);
        t.save("fields.tsv");
    }
    {
        let mut t = Tsv::default();
        t.comment(
            "curves.tsv: halo2curves 0.9.0 Pallas (y^2 = x^3 + 5 over fp) and Vesta (y^2 = x^3 + 5 over fq).\n\
Field elements: 64 hex chars (32 bytes LE). Scalars: the curve's scalar field (pallas: fq, vesta: fp).\n\
Point token: `inf` or `<x hex>:<y hex>` (affine). Compressed bytes: 32 bytes, x little-endian, bit 7 of byte 31 is the sign (1 iff y is odd); the identity encodes as 32 zero bytes (see `comp inf`).\n\
Columns: <curve> <op> <args...> <result>\n\
 const a|b ; gen P ; id P ; order_minus_one_scalar k\n\
 add P Q R ; dbl P R ; neg P R ; mul P k R\n\
 comp P bytes32 ; decomp bytes32 P|none (GroupEncoding::from_bytes: none for invalid x, non-canonical x, or not-on-curve)\n\
 from_xy x y ok(1|0) : CurveAffine::from_xy accepts iff the point is on the curve",
        );
        let mut sr = Tsv::default();
        sr.comment(
            "serde_points.tsv: exact bincode 1.3 (bincode::serialize, fixint little-endian) bytes of group elements and scalars.\n\
Both Affine and Projective serialize through GroupEncoding::to_bytes as a fixed-size array (serde_arrays, no length prefix): 32 bytes, identical to the compressed encoding.\n\
This is how nova's Commitment<E> (field `comm: E::GE`), the commitment-key generators (Vec<Affine>) and every point in proofs are written.\n\
Columns: <curve> <kind> <value> <bytes hex>\n\
 affine|proj P bytes(32) ; affine_vec5 P,P,P,P,P bytes (u64 LE count = 5, then 5*32) ; scalar k bytes(32) ; scalar_vec4 k,k,k,k bytes (u64 LE count, then 4*32)",
        );
        let mut r = rng_for("curves");
        curve_vectors!("pallas", Pallas, PallasAffine, Fp, Fq, &mut t, &mut sr, &mut r);
        curve_vectors!("vesta", Vesta, VestaAffine, Fq, Fp, &mut t, &mut sr, &mut r);
        t.save("curves.tsv");
        sr.save("serde_points.tsv");
    }
    {
        let mut t = Tsv::default();
        let mut r = rng_for("h2c");
        xmd_vectors(&mut t, &mut r);
        t.comment(
            "h2c <curve> <msg32 hex> <u0> <u1> <Q0> <Q1> <result>\n\
Point::hash_to_curve(\"from_uniform_bytes\")(msg) as nova's DlogGroup::from_label calls it (halo2curves 0.9.0):\n\
 DST = \"from_uniform_bytes\" || suite, suite = \"pallas:SHA-256_SVDW_RO_\" or \"vesta:SHA-256_SVDW_RO_\"\n\
 uniform = expand_message_xmd_sha256(msg, DST, 96); u0 = Base::from_uniform_bytes(reverse(uniform[0..48])), u1 likewise on uniform[48..96] (each 48-byte chunk is read big-endian)\n\
 Q0 = svdw_map_to_curve(u0), Q1 = svdw_map_to_curve(u1) (RFC 9380 6.6.1 Shallue-van de Woestijne, Z = -13, g(x)=x^3+5), result = Q0 + Q1 (cofactor 1)\n\
svdw_const <curve> z c1 c2 c3 c4 : precomputed SvdW constants (RFC 9380 F.1), c3 normalised to even sgn0.\n\
Field elements 64 hex (32 B LE). Points `x:y` affine. Base field of pallas = fp, of vesta = fq.",
        );
        let mut inputs: Vec<Vec<u8>> = vec![vec![0u8; 32], vec![0xffu8; 32]];
        for i in 0..4u8 {
            let mut b = [0u8; 32];
            b[0] = i + 1;
            inputs.push(b.to_vec());
        }
        while inputs.len() < 54 {
            inputs.push(rbytes(&mut r, 32));
        }
        h2c_vectors!("pallas", Pallas, b"pallas:SHA-256_SVDW_RO_", &mut t, &inputs);
        h2c_vectors!("vesta", Vesta, b"vesta:SHA-256_SVDW_RO_", &mut t, &inputs);
        t.save("hash_to_curve.tsv");
    }
}
