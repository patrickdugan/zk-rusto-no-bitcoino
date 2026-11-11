//! The four-row relaxed-R1CS fixture, folded by Nova 0.76's own NIFS on either Pasta engine, and
//! the operator side of FC03: committing (W, E) and the binding traces, and answering challenges.
//!
//! Relation over z = (W0, W1, W2, W3, u, X0, X1), with x = X0 and y = X1:
//!   row 0:  X0 * X0                 = W0          (x^2)
//!   row 1:  W0 * X0                 = W1          (x^3)
//!   row 2:  (W1 + 5u + X0) * u      = X1          (y = x^3 + x + 5)
//!   row 3:  (W0 - 2 W1 + W3 + X1) * (W0 + u) = W2   (W3 free; W0 read twice)
//! Three strict instances (x = 3, 5, 7) are folded twice, so the claimed instance has u != 1 and
//! E != 0, as a Nova running instance does.
use crate::{
    binding,
    enc::{self, tag},
    field::{fe_bytes, point_bytes, FcEngine, PointBytes},
    flatmerkle::{self, Stream},
    protocol::*,
    sha,
    shape::Shape,
};
use ff::{Field, PrimeField, PrimeFieldBits};
use nova_snark::{
    constants::NUM_CHALLENGE_BITS,
    gadgets::utils::{base_as_scalar, scalar_as_base},
    nova::nifs::NIFS,
    provider::traits::{DlogGroup, DlogGroupExt},
    r1cs::{R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness},
    traits::{commitment::CommitmentEngineTrait, commitment::CommitmentTrait, AbsorbInROTrait, ROConstants, ROTrait},
    provider::pedersen::{Commitment, CommitmentKey},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub const NETWORK: &str = "regtest";

pub fn toy_shape<F: PrimeField>() -> Shape<F> {
    let one = F::ONE;
    let (w0, w1, w2, w3, u, x0, x1) = (0u32, 1, 2, 3, 4, 5, 6);
    let a = vec![vec![(x0, one)], vec![(w0, one)], vec![(w1, one), (u, F::from(5)), (x0, one)], vec![(w0, one), (w1, -F::from(2)), (w3, one), (x1, one)]];
    let b = vec![vec![(x0, one)], vec![(x0, one)], vec![(u, one)], vec![(w0, one), (u, one)]];
    let c = vec![vec![(w0, one)], vec![(w1, one)], vec![(x1, one)], vec![(w2, one)]];
    Shape { num_cons: 4, num_vars: 4, num_io: 2, rows: [a, b, c] }
}

/// Satisfying strict assignment for input x: (W, X).
pub fn toy_assignment<F: PrimeField>(x: u64) -> (Vec<F>, Vec<F>) {
    let xf = F::from(x);
    let w0 = xf * xf;
    let w1 = w0 * xf;
    let y = w1 + xf + F::from(5);
    let w3 = xf + F::from(11);
    let w2 = (w0 - (w1 + w1) + w3 + y) * (w0 + F::ONE);
    (vec![w0, w1, w2, w3], vec![xf, y])
}

/// The Nova objects of the fixture.
pub struct NovaFold<E: FcEngine>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    pub shape: Shape<E::Scalar>,
    pub s: R1CSShape<E>,
    pub ck: CommitmentKey<E>,
    pub pp_digest: E::Scalar,
    pub u1: RelaxedR1CSInstance<E>,
    pub w1: RelaxedR1CSWitness<E>,
    pub u2: R1CSInstance<E>,
    pub w2: R1CSWitness<E>,
    pub comm_t: Commitment<E>,
    pub r: E::Scalar,
    pub u: RelaxedR1CSInstance<E>,
    pub w: RelaxedR1CSWitness<E>,
}

/// A pp digest for the fixture: SHA-256 of the shape digest, truncated to 250 bits as Nova's
/// `NUM_HASH_BITS` digest is.
pub fn toy_pp_digest<F: PrimeField>(shape_digest: &[u8; 32]) -> F {
    let mut e = enc::Enc::new("fixture-pp-digest");
    e.field("shape", shape_digest);
    let mut d = e.digest();
    d[31] &= 0x03;
    crate::field::fe_from_bytes(&d).expect("250-bit value is canonical")
}

pub fn comm_point<E: FcEngine>(c: &Commitment<E>) -> PointBytes
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let (x, y, inf) = c.to_coordinates();
    let mut out = [0u8; 65];
    if inf {
        out[0] = 1;
    } else {
        out[1..33].copy_from_slice(&fe_bytes(&x));
        out[33..].copy_from_slice(&fe_bytes(&y));
    }
    out
}

/// One deterministic NIFS fold (Nova's `NIFS::prove` with a seeded cross-term blind).
#[allow(clippy::too_many_arguments)]
fn fold<E: FcEngine>(
    ck: &CommitmentKey<E>,
    s: &R1CSShape<E>,
    pp: &E::Scalar,
    u1: &RelaxedR1CSInstance<E>,
    w1: &RelaxedR1CSWitness<E>,
    u2: &R1CSInstance<E>,
    w2: &R1CSWitness<E>,
    rng: &mut ChaChaRng,
) -> (Commitment<E>, E::Scalar, RelaxedR1CSInstance<E>, RelaxedR1CSWitness<E>)
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let mut ro = E::RO::new(ROConstants::<E>::default());
    ro.absorb(scalar_as_base::<E>(*pp));
    u2.absorb_in_ro(&mut ro);
    let r_t = E::Scalar::random(&mut *rng);
    let (t, comm_t) = s.commit_T(ck, u1, w1, u2, w2, &r_t).expect("commit_T");
    comm_t.absorb_in_ro(&mut ro);
    let r = base_as_scalar::<E>(ro.squeeze(NUM_CHALLENGE_BITS, false));
    let u = u1.fold(u2, &comm_t, &r);
    let w = w1.fold(w2, &t, &r_t, &r).expect("fold witness");
    (comm_t, r, u, w)
}

pub fn nova_fold<E: FcEngine>(seed: u64) -> NovaFold<E>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let shape = toy_shape::<E::Scalar>();
    let s = shape.to_nova::<E>();
    let hint: &nova_snark::r1cs::CommitmentKeyHint<E> = &|_| 0;
    let ck = R1CSShape::commitment_key(&[&s], &[hint]).expect("commitment key");
    let pp_digest = toy_pp_digest::<E::Scalar>(&shape.digest(E::FIELD.byte()));
    let mut rng = ChaChaRng::seed_from_u64(seed);
    let strict = |x: u64, rng: &mut ChaChaRng| {
        let (w, xs) = toy_assignment::<E::Scalar>(x);
        let wit = R1CSWitness::new(&s, &w, rng).unwrap();
        let comm = wit.commit(&ck);
        let inst = R1CSInstance::new(&s, &comm, &xs).unwrap();
        s.is_sat(&ck, &inst, &wit).expect("strict instance satisfied");
        (inst, wit)
    };
    let (ua, wa) = strict(3, &mut rng);
    let (ub, wb) = strict(5, &mut rng);
    let (uc, wc) = strict(7, &mut rng);
    let r0 = RelaxedR1CSInstance::from_r1cs_instance(&ck, &s, &ua);
    let w0 = RelaxedR1CSWitness::from_r1cs_witness(&s, &wa);
    let (_, _, u1, w1) = fold(&ck, &s, &pp_digest, &r0, &w0, &ub, &wb, &mut rng);
    s.is_sat_relaxed(&ck, &u1, &w1).expect("first fold satisfied");
    let (comm_t, r, u, w) = fold(&ck, &s, &pp_digest, &u1, &w1, &uc, &wc, &mut rng);
    s.is_sat_relaxed(&ck, &u, &w).expect("second fold satisfied");
    // Nova's own verifier recomputes the same folded instance from (U1, U2, comm_T).
    let nifs: NIFS<E> = bincode::deserialize(&bincode::serialize(&comm_t).unwrap()).unwrap();
    let uv = nifs.verify(&ROConstants::<E>::default(), &pp_digest, &u1, &uc).unwrap();
    assert_eq!(bincode::serialize(&uv).unwrap(), bincode::serialize(&u).unwrap(), "NIFS::verify reproduces U");
    NovaFold { shape, s, ck, pp_digest, u1, w1, u2: uc, w2: wc, comm_t, r, u, w }
}

pub fn relaxed_bytes<E: FcEngine>(u: &RelaxedR1CSInstance<E>) -> RelaxedInstanceBytes
where
    E::GE: DlogGroup + DlogGroupExt,
{
    RelaxedInstanceBytes { comm_w: comm_point(u.comm_W()), comm_e: comm_point(u.comm_E()), u: fe_bytes(&u.u()), x: u.X().iter().map(fe_bytes).collect() }
}

/// Generators G_0..G_{ck_len-1} then H, as group elements.
pub fn ck_points<E: FcEngine>(ck: &CommitmentKey<E>) -> Vec<E::GE>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let mut g: Vec<E::GE> = ck.generators().iter().map(<E::GE as DlogGroup>::group).collect();
    // Com(empty; 1) = H.
    let h = <E::CE as CommitmentEngineTrait<E>>::commit(ck, &[], &E::Scalar::ONE);
    let hb = comm_point(&h);
    g.push(crate::field::point_from_bytes::<E>(&hb).expect("H decodes"));
    g
}

/// Everything verifier-side derived from the pinned shape and commitment key.
pub struct Pinned {
    pub tc: TrustedConfig,
    pub matrix: Stream,
    pub ck: Stream,
    pub gen_bytes: Vec<PointBytes>,
}

pub fn pin<E: FcEngine>(shape: &Shape<E::Scalar>, gens: &[E::GE], pp_digest: &E::Scalar, network: &str) -> Pinned
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let fid = E::FIELD.byte();
    let k = shape.k();
    let matrix = flatmerkle::build(&shape.matrix_items(fid, k)).unwrap();
    let gen_bytes: Vec<PointBytes> = gens.iter().map(point_bytes::<E>).collect();
    let ck = flatmerkle::build(&binding::gen_items(fid, &gen_bytes)).unwrap();
    let pow = |n: usize| n.max(4).next_power_of_two() as u32;
    let ck_len = (gens.len() - 1) as u32;
    let tc = TrustedConfig {
        field: fid,
        network: network.into(),
        shape_digest: shape.digest(fid),
        matrix_root: matrix.digest,
        matrix_leaves: matrix.items.len() as u32,
        num_cons: shape.num_cons as u32,
        num_vars: shape.num_vars as u32,
        num_io: shape.num_io as u32,
        k: [k[0] as u32, k[1] as u32, k[2] as u32],
        w_leaves: pow(shape.num_vars + 1),
        e_leaves: pow(shape.num_cons + 1),
        ck_len,
        ck_root: ck.digest,
        ck_leaves: ck.items.len() as u32,
        trace_w_leaves: pow((shape.num_vars + 1) * 256 + 1),
        trace_e_leaves: pow((shape.num_cons + 1) * 256 + 1),
        pp_digest: fe_bytes(pp_digest),
        ro: RO_ID.into(),
    };
    Pinned { tc, matrix, ck, gen_bytes }
}

/// What the operator commits and keeps: the vectors, their streams, the traces.
#[derive(Clone)]
pub struct Committed {
    pub fid: u8,
    pub w: Vec<[u8; 32]>,
    pub r_w: [u8; 32],
    pub e: Vec<[u8; 32]>,
    pub r_e: [u8; 32],
    pub w_stream: Stream,
    pub e_stream: Stream,
    pub trace_w: Vec<(PointBytes, PointBytes)>,
    pub trace_e: Vec<(PointBytes, PointBytes)>,
    pub trace_w_stream: Stream,
    pub trace_e_stream: Stream,
}

impl Committed {
    pub fn trace(&self, v: Vector) -> (&Vec<(PointBytes, PointBytes)>, &Stream) {
        match v {
            Vector::W => (&self.trace_w, &self.trace_w_stream),
            Vector::E => (&self.trace_e, &self.trace_e_stream),
        }
    }
    pub fn values(&self, v: Vector) -> &Stream {
        match v {
            Vector::W => &self.w_stream,
            Vector::E => &self.e_stream,
        }
    }
}

/// Commit to (W, r_W, E, r_E) with honest binding traces. `w`/`e` are the padded vectors.
pub fn commit<E: FcEngine>(gens: &[E::GE], ck_len: usize, w: &[E::Scalar], r_w: E::Scalar, e: &[E::Scalar], r_e: E::Scalar) -> Committed
where
    E::GE: DlogGroup + DlogGroupExt,
    E::Scalar: PrimeFieldBits,
{
    let fid = E::FIELD.byte();
    let trace_of = |v: &[E::Scalar], r: E::Scalar| {
        let mut sc = v.to_vec();
        sc.push(r);
        let mut g: Vec<E::GE> = gens[..v.len()].to_vec();
        g.push(gens[ck_len]);
        binding::trace_states::<E>(&sc, &g)
    };
    let trace_w = trace_of(w, r_w);
    let trace_e = trace_of(e, r_e);
    let wb: Vec<[u8; 32]> = w.iter().map(fe_bytes).collect();
    let eb: Vec<[u8; 32]> = e.iter().map(fe_bytes).collect();
    let (rwb, reb) = (fe_bytes(&r_w), fe_bytes(&r_e));
    Committed {
        fid,
        w_stream: flatmerkle::build(&binding::scalar_items(fid, Vector::W, &wb, &rwb)).unwrap(),
        e_stream: flatmerkle::build(&binding::scalar_items(fid, Vector::E, &eb, &reb)).unwrap(),
        trace_w_stream: flatmerkle::build(&binding::trace_items(fid, Vector::W, &trace_w)).unwrap(),
        trace_e_stream: flatmerkle::build(&binding::trace_items(fid, Vector::E, &trace_e)).unwrap(),
        w: wb,
        r_w: rwb,
        e: eb,
        r_e: reb,
        trace_w,
        trace_e,
    }
}

/// Rebuild the trace stream after a test overwrote trace states.
pub fn restream(c: &mut Committed, v: Vector) {
    match v {
        Vector::W => c.trace_w_stream = flatmerkle::build(&binding::trace_items(c.fid, v, &c.trace_w)).unwrap(),
        Vector::E => c.trace_e_stream = flatmerkle::build(&binding::trace_items(c.fid, v, &c.trace_e)).unwrap(),
    }
}

pub fn contract_id(label: &str) -> [u8; 32] {
    let mut e = enc::Enc::new("fixture-contract");
    e.field("label", label.as_bytes());
    e.digest()
}

pub fn make_claim(tc: &TrustedConfig, folding: Folding, instance: RelaxedInstanceBytes, statement: Statement, session: [u8; 32], replay: ReplayDomain, c: &Committed) -> FlatCheckClaim {
    FlatCheckClaim {
        version: VERSION,
        tc_digest: tc.digest(),
        field: tc.field,
        session_id: session,
        replay,
        statement,
        folding,
        instance,
        root_w: c.w_stream.digest,
        root_e: c.e_stream.digest,
        root_trace_w: c.trace_w_stream.digest,
        root_trace_e: c.trace_e_stream.digest,
    }
}

/// The honest operator's answer to a challenge (None for the public-data `Claim` kind).
pub fn respond(p: &Pinned, shape_rows: &dyn Fn(usize) -> Vec<u8>, c: &Committed, ch: &FlatCheckChallenge) -> Option<FlatCheckResponse> {
    let tc = &p.tc;
    let cid = ch.id();
    let rec_open = |s: &Stream, recs: &dyn Fn(usize) -> Vec<u8>, i: usize| RecordOpen { record: recs(i), open: (&flatmerkle::open(s, i)).into() };
    match ch.kind {
        ChallengeKind::Row { row } => {
            let row = row as usize;
            let rec = shape_rows(row);
            let k = [tc.k[0] as usize, tc.k[1] as usize, tc.k[2] as usize];
            let cols = row_cols(&rec, k);
            let terms = cols.iter().map(|&(col, active)| {
                let idx = if active && col < tc.num_vars { col } else { 0 };
                (&flatmerkle::open(&c.w_stream, idx as usize)).into()
            });
            Some(FlatCheckResponse::Row(RowResponse {
                challenge_id: cid,
                row_open: (&flatmerkle::open(&p.matrix, row)).into(),
                row_record: rec,
                terms: terms.collect(),
                e_open: (&flatmerkle::open(&c.e_stream, row)).into(),
            }))
        }
        ChallengeKind::BindingStep { vec, step } => {
            let (states, ts) = c.trace(vec);
            let recs = |t: usize| binding::trace_record(c.fid, vec, t as u32, &states[t].0, &states[t].1);
            let (j, b) = (step / 256, step % 256);
            let n = tc.n_vec(vec);
            let g = if b == 255 && j < n { binding::gen_index(n, tc.ck_len, j + 1) } else { 0 };
            let grec = |i: usize| binding::gen_record(c.fid, i as u32, &p.gen_bytes[i]);
            Some(FlatCheckResponse::Step(StepResponse {
                challenge_id: cid,
                cur: rec_open(ts, &recs, step as usize),
                next: rec_open(ts, &recs, step as usize + 1),
                scalar: (&flatmerkle::open(c.values(vec), j as usize)).into(),
                gen: rec_open(&p.ck, &grec, g as usize),
            }))
        }
        ChallengeKind::BindingStart { vec } => {
            let (states, ts) = c.trace(vec);
            let recs = |t: usize| binding::trace_record(c.fid, vec, t as u32, &states[t].0, &states[t].1);
            let grec = |i: usize| binding::gen_record(c.fid, i as u32, &p.gen_bytes[i]);
            Some(FlatCheckResponse::Start(StartResponse { challenge_id: cid, first: rec_open(ts, &recs, 0), gen0: rec_open(&p.ck, &grec, 0) }))
        }
        ChallengeKind::BindingEnd { vec } => {
            let (states, ts) = c.trace(vec);
            let last = tc.trace_steps(vec) as usize;
            let recs = |t: usize| binding::trace_record(c.fid, vec, t as u32, &states[t].0, &states[t].1);
            Some(FlatCheckResponse::End(EndResponse { challenge_id: cid, last: rec_open(ts, &recs, last) }))
        }
        ChallengeKind::Claim => None,
    }
}

/// (column, active) for each slot of a row record, A then B then C (no field decoding).
pub fn row_cols(rec: &[u8], k: [usize; 3]) -> Vec<(u32, bool)> {
    let mut out = Vec::new();
    let mut off = 16;
    for km in k {
        let nnz = u32::from_be_bytes(rec[off..off + 4].try_into().unwrap());
        off += 4;
        for j in 0..km {
            out.push((u32::from_be_bytes(rec[off..off + 4].try_into().unwrap()), (j as u32) < nnz));
            off += 36;
        }
    }
    out
}

/// The fixture end to end for engine E: Nova fold, pinned config, honest commitment and claim.
pub struct Toy<E: FcEngine>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    pub nova: NovaFold<E>,
    pub gens: Vec<E::GE>,
    pub pinned: Pinned,
    pub committed: Committed,
    pub claim: FlatCheckClaim,
    pub replay: ReplayDomain,
}

impl<E: FcEngine> Toy<E>
where
    E::GE: DlogGroup + DlogGroupExt,
    E::Scalar: PrimeFieldBits,
{
    pub fn new(seed: u64) -> Self {
        let nova = nova_fold::<E>(seed);
        let gens = ck_points::<E>(&nova.ck);
        let pinned = pin::<E>(&nova.shape, &gens, &nova.pp_digest, NETWORK);
        let (_, r_w, r_e) = nova.w.derandomize();
        let committed = commit::<E>(&gens, pinned.tc.ck_len as usize, nova.w.W(), r_w, nova.w.E(), r_e);
        let replay = ReplayDomain { network: NETWORK.into(), contract_id: contract_id(E::FIELD.name()) };
        let claim = Self::claim_for(&nova, &pinned.tc, &committed, replay.clone());
        Toy { nova, gens, pinned, committed, claim, replay }
    }

    pub fn claim_for(nova: &NovaFold<E>, tc: &TrustedConfig, c: &Committed, replay: ReplayDomain) -> FlatCheckClaim {
        let folding = Folding {
            u1: relaxed_bytes(&nova.u1),
            u2: StrictInstanceBytes { comm_w: comm_point(nova.u2.comm_W()), x: nova.u2.X().iter().map(fe_bytes).collect() },
            comm_t: comm_point(&nova.comm_t),
        };
        let mut app = enc::Enc::new("fixture-app");
        app.field("inputs", b"x=3,5,7");
        let statement = Statement { pp_digest: fe_bytes(&nova.pp_digest), steps: 3, app_digest: app.digest() };
        let mut sess = enc::Enc::new("fixture-session");
        sess.field("field", E::FIELD.name().as_bytes());
        make_claim(tc, folding, relaxed_bytes(&nova.u), statement, sess.digest(), replay, c)
    }

    pub fn row_record(&self, i: usize) -> Vec<u8> {
        let k = self.nova.shape.k();
        self.nova.shape.row_record(E::FIELD.byte(), i, k)
    }

    pub fn challenge(&self, kind: ChallengeKind) -> FlatCheckChallenge {
        let mut n = enc::Enc::new("fixture-nonce");
        n.u8("kind", kind.code().0).u32("index", kind.code().1);
        FlatCheckChallenge { version: VERSION, claim_id: self.claim.id(), kind, challenger: [0x11; 32], nonce: n.digest(), replay: self.replay.clone() }
    }

    pub fn respond(&self, c: &Committed, ch: &FlatCheckChallenge) -> Option<FlatCheckResponse> {
        let shape = &self.nova.shape;
        let k = shape.k();
        let fid = E::FIELD.byte();
        respond(&self.pinned, &|i| shape.row_record(fid, i, k), c, ch)
    }
}

pub fn item_digest(b: &[u8]) -> [u8; 32] {
    sha::sha256(b)
}

pub fn pad_tag() -> u8 {
    tag::PAD
}
