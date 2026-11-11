//! The FC03 adversarial suite. Each case fixes (trusted config, claim, challenge, response) and the
//! verdict the protocol requires; the native checker, the Python reference and the garbled
//! circuits are all run against the same list.
use crate::{
    binding,
    checker::{adjudicate, Verdict},
    enc,
    field::{fe_bytes, fe_from_bytes, point_bytes, FcEngine, FieldId},
    fixture::{self, Committed, Toy},
    flatmerkle,
    protocol::*,
};
use ff::{Field, PrimeField, PrimeFieldBits};
use nova_snark::provider::traits::{DlogGroup, DlogGroupExt};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Case {
    pub name: String,
    pub group: &'static str,
    pub field: FieldId,
    /// Which trusted configuration adjudicates: the case's own field, or the other one.
    pub tc_field: FieldId,
    pub claim: FlatCheckClaim,
    pub challenge: FlatCheckChallenge,
    pub response: Option<FlatCheckResponse>,
    pub expected: &'static str,
    pub expected_refutes: bool,
}

fn refutes(code: &str) -> bool {
    !matches!(code, "challenge_invalid" | "holds")
}

pub fn nonce(tag: &str) -> [u8; 32] {
    let mut e = enc::Enc::new("suite-nonce");
    e.field("tag", tag.as_bytes());
    e.digest()
}

pub fn challenge_for(claim: &FlatCheckClaim, kind: ChallengeKind, nonce_tag: &str) -> FlatCheckChallenge {
    FlatCheckChallenge { version: VERSION, claim_id: claim.id(), kind, challenger: [0x11; 32], nonce: nonce(nonce_tag), replay: claim.replay.clone() }
}

pub struct Suite<E: FcEngine>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    pub toy: Toy<E>,
    pub cases: Vec<Case>,
}

fn fes<F: PrimeField>(v: &[[u8; 32]]) -> Vec<F> {
    v.iter().map(|b| fe_from_bytes::<F>(b).unwrap()).collect()
}

/// E' = A z' o B z' - u C z': the error vector that makes any W' satisfy the relaxed relation.
pub fn forge_error<E: FcEngine>(toy: &Toy<E>, w: &[E::Scalar]) -> Vec<E::Scalar>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let (u, x) = (toy.nova.u.u(), toy.nova.u.X().to_vec());
    (0..toy.nova.shape.num_cons)
        .map(|i| {
            let [a, b, c] = toy.nova.shape.row_products(i, w, u, &x);
            a * b - u * c
        })
        .collect()
}

/// The challenger's search over published data: the first refutable local check, if any.
pub fn locate_fault<E: FcEngine>(toy: &Toy<E>, claim: &FlatCheckClaim, c: &Committed) -> Option<ChallengeKind>
where
    E::GE: DlogGroup + DlogGroupExt,
    E::Scalar: PrimeFieldBits,
    E::Base: PrimeFieldBits,
{
    let tc = &toy.pinned.tc;
    let mut kinds = vec![ChallengeKind::Claim];
    kinds.extend((0..tc.num_cons).map(|row| ChallengeKind::Row { row }));
    for v in [Vector::W, Vector::E] {
        kinds.push(ChallengeKind::BindingStart { vec: v });
        kinds.push(ChallengeKind::BindingEnd { vec: v });
        kinds.extend((0..tc.trace_steps(v)).map(|step| ChallengeKind::BindingStep { vec: v, step }));
    }
    kinds.into_iter().find(|&k| {
        let ch = challenge_for(claim, k, "locate");
        let r = toy.respond(c, &ch);
        adjudicate::<E>(tc, claim, &ch, r.as_ref()).refutes()
    })
}

impl<E: FcEngine> Suite<E>
where
    E::GE: DlogGroup + DlogGroupExt,
    E::Scalar: PrimeFieldBits,
    E::Base: PrimeFieldBits,
{
    pub fn build(seed: u64) -> Self {
        let toy = Toy::<E>::new(seed);
        let mut s = Suite { toy, cases: Vec::new() };
        s.populate();
        s
    }

    fn push(&mut self, group: &'static str, name: &str, claim: &FlatCheckClaim, ch: FlatCheckChallenge, resp: Option<FlatCheckResponse>, expected: &'static str) {
        self.cases.push(Case {
            name: format!("{}/{}", E::FIELD.name(), name),
            group,
            field: E::FIELD,
            tc_field: E::FIELD,
            claim: claim.clone(),
            challenge: ch,
            response: resp,
            expected,
            expected_refutes: refutes(expected),
        });
    }

    fn honest_pair(&self, claim: &FlatCheckClaim, c: &Committed, kind: ChallengeKind, tag: &str) -> (FlatCheckChallenge, Option<FlatCheckResponse>) {
        let ch = challenge_for(claim, kind, tag);
        let r = self.toy.respond(c, &ch);
        (ch, r)
    }

    fn commit_fe(&self, w: &[E::Scalar], e: &[E::Scalar]) -> Committed {
        let (_, r_w, r_e) = self.toy.nova.w.derandomize();
        fixture::commit::<E>(&self.toy.gens, self.toy.pinned.tc.ck_len as usize, w, r_w, e, r_e)
    }

    fn claim_over(&self, c: &Committed) -> FlatCheckClaim {
        Toy::<E>::claim_for(&self.toy.nova, &self.toy.pinned.tc, c, self.toy.replay.clone())
    }

    fn populate(&mut self) {
        let tc = self.toy.pinned.tc.clone();
        let fid = tc.field;
        let base = self.toy.claim.clone();
        let hc = self.toy.committed.clone();
        let w0: Vec<E::Scalar> = fes(&hc.w);
        let e0: Vec<E::Scalar> = fes(&hc.e);
        let steps_w = tc.trace_steps(Vector::W);
        let steps_e = tc.trace_steps(Vector::E);

        // ---------------------------------------------------------------- honest
        for row in 0..tc.num_cons {
            let (ch, r) = self.honest_pair(&base, &hc, ChallengeKind::Row { row }, "h");
            self.push("honest", &format!("honest/row{row}"), &base, ch, r, "holds");
        }
        let (ch, r) = self.honest_pair(&base, &hc, ChallengeKind::Claim, "h");
        self.push("honest", "honest/claim-fold", &base, ch, r, "holds");
        for v in [Vector::W, Vector::E] {
            let (ch, r) = self.honest_pair(&base, &hc, ChallengeKind::BindingStart { vec: v }, "h");
            self.push("honest", &format!("honest/binding-start-{v:?}"), &base, ch, r, "holds");
            let (ch, r) = self.honest_pair(&base, &hc, ChallengeKind::BindingEnd { vec: v }, "h");
            self.push("honest", &format!("honest/binding-end-{v:?}"), &base, ch, r, "holds");
            let last = tc.trace_steps(v) - 1;
            for step in [0, 1, 254, 255, 256, 700, 1024, last - 256, last - 1, last] {
                let (ch, r) = self.honest_pair(&base, &hc, ChallengeKind::BindingStep { vec: v, step }, "h");
                self.push("honest", &format!("honest/binding-step-{v:?}-{step}"), &base, ch, r, "holds");
            }
        }

        // ---------------------------------------------------------------- malformed encodings
        let modulus = {
            let mut b = [0u8; 32];
            let m = E::FIELD.modulus().to_bytes_le();
            b[..m.len()].copy_from_slice(&m);
            b
        };
        let mut cl = base.clone();
        cl.instance.u = modulus;
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Row { row: 0 }, "m");
        self.push("malformed-encoding", "u-equals-modulus", &cl, ch, r, "claim_invalid");
        let mut cl = base.clone();
        cl.instance.x[0] = [0xff; 32];
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Row { row: 0 }, "m");
        self.push("malformed-encoding", "x0-all-ones", &cl, ch, r, "claim_invalid");
        // A committed W value at or above the modulus.
        let mut c = hc.clone();
        let mut wb = hc.w.clone();
        wb[1] = modulus;
        c.w_stream = flatmerkle::build(&binding::scalar_items(fid, Vector::W, &wb, &hc.r_w)).unwrap();
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::Row { row: 1 }, "m");
        self.push("malformed-encoding", "committed-W1-non-canonical", &cl, ch, r, "violated");
        let mut c = hc.clone();
        let mut eb = hc.e.clone();
        eb[2] = modulus;
        c.e_stream = flatmerkle::build(&binding::scalar_items(fid, Vector::E, &eb, &hc.r_e)).unwrap();
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::Row { row: 2 }, "m");
        self.push("malformed-encoding", "committed-E2-non-canonical", &cl, ch, r, "violated");
        // Row record with a coefficient replaced by the modulus: no longer the pinned row.
        let (ch, r) = self.honest_pair(&base, &hc, ChallengeKind::Row { row: 2 }, "m");
        let mut r = r.unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            let off = 16 + 4 + 36 + 4; // A slot 1 coefficient
            rr.row_record[off..off + 32].copy_from_slice(&modulus);
        }
        self.push("malformed-encoding", "row-record-coefficient-non-canonical", &base, ch, Some(r), "response_invalid");
        // A committed trace state with a coordinate at the base-field modulus.
        let mut c = hc.clone();
        let bm = {
            let mut b = [0u8; 32];
            let m = E::FIELD.base_modulus().to_bytes_le();
            b[..m.len()].copy_from_slice(&m);
            b
        };
        c.trace_w[1].1[1..33].copy_from_slice(&bm);
        fixture::restream(&mut c, Vector::W);
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::BindingStep { vec: Vector::W, step: 0 }, "m");
        self.push("malformed-encoding", "trace-state-coordinate-non-canonical", &cl, ch, r, "violated");
        let mut c = hc.clone();
        c.trace_w[0].0 = [2u8; 65];
        fixture::restream(&mut c, Vector::W);
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::BindingStart { vec: Vector::W }, "m");
        self.push("malformed-encoding", "trace-infinity-flag-2", &cl, ch, r, "violated");

        // ---------------------------------------------------------------- wrong row identifiers
        let ch1 = challenge_for(&base, ChallengeKind::Row { row: 1 }, "r");
        let ch2 = challenge_for(&base, ChallengeKind::Row { row: 2 }, "r");
        let r2 = self.toy.respond(&hc, &ch2);
        self.push("wrong-row", "response-for-row2-to-row1", &base, ch1.clone(), r2.clone(), "response_invalid");
        let mut r = r2.clone().unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            rr.challenge_id = ch1.id();
        }
        self.push("wrong-row", "row2-data-relabelled-row1", &base, ch1.clone(), Some(r), "response_invalid");
        let ch4 = challenge_for(&base, ChallengeKind::Row { row: tc.num_cons }, "r");
        self.push("wrong-row", "row-out-of-range", &base, ch4, None, "challenge_invalid");
        let mut r = self.toy.respond(&hc, &ch1).unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            rr.e_open = (&flatmerkle::open(&hc.e_stream, 2)).into();
        }
        self.push("wrong-row", "E-opening-of-another-row", &base, ch1.clone(), Some(r), "response_invalid");
        let ch3 = challenge_for(&base, ChallengeKind::Row { row: 3 }, "r");
        let mut r = self.toy.respond(&hc, &ch3).unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            rr.terms[1] = (&flatmerkle::open(&hc.w_stream, 3)).into(); // A slot 1 reads W1
        }
        self.push("wrong-row", "W-opening-at-wrong-column", &base, ch3.clone(), Some(r), "response_invalid");

        // ---------------------------------------------------------------- switched fields
        let mut cl = base.clone();
        cl.field = if E::FIELD == FieldId::PallasScalar { 2 } else { 1 };
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Row { row: 0 }, "f");
        self.push("switched-field", "claim-field-byte-switched", &cl, ch, r, "claim_invalid");
        let other = if E::FIELD == FieldId::PallasScalar { 2u8 } else { 1u8 };
        let mut c = hc.clone();
        c.w_stream = flatmerkle::build(&binding::scalar_items(other, Vector::W, &hc.w, &hc.r_w)).unwrap();
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::Row { row: 1 }, "f");
        self.push("switched-field", "W-items-tagged-other-field", &cl, ch, r, "response_invalid");

        // ---------------------------------------------------------------- altered public inputs
        let one = E::Scalar::ONE;
        let bump = |b: &[u8; 32]| fe_bytes(&(fe_from_bytes::<E::Scalar>(b).unwrap() + one));
        let mut cl = base.clone();
        cl.instance.x[0] = bump(&cl.instance.x[0]);
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Row { row: 0 }, "p");
        self.push("altered-public", "x0-plus-one/row0", &cl, ch, r, "violated");
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Claim, "p");
        self.push("altered-public", "x0-plus-one/claim-fold", &cl, ch, r, "violated");
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Row { row: 3 }, "p");
        self.push("altered-public", "x0-plus-one/row3-does-not-read-x0", &cl, ch, r, "holds");
        let mut cl = base.clone();
        cl.instance.u = bump(&cl.instance.u);
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Row { row: 2 }, "p");
        self.push("altered-public", "u-plus-one/row2", &cl, ch, r, "violated");
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Claim, "p");
        self.push("altered-public", "u-plus-one/claim-fold", &cl, ch, r, "violated");
        let mut cl = base.clone();
        cl.statement.pp_digest = bump(&cl.statement.pp_digest);
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Claim, "p");
        self.push("altered-public", "pp-digest/claim-fold", &cl, ch, r, "violated");
        let g = <E::GE as DlogGroup>::gen();
        let mut cl = base.clone();
        cl.folding.comm_t = point_bytes::<E>(&(crate::field::point_from_bytes::<E>(&cl.folding.comm_t).unwrap() + g));
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Claim, "p");
        self.push("altered-public", "comm-T-shifted/claim-fold", &cl, ch, r, "violated");
        let mut cl = base.clone();
        cl.instance.comm_w = point_bytes::<E>(&(crate::field::point_from_bytes::<E>(&cl.instance.comm_w).unwrap() + g));
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Claim, "p");
        self.push("altered-public", "comm-W-shifted/claim-fold", &cl, ch, r, "violated");
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::BindingEnd { vec: Vector::W }, "p");
        self.push("altered-public", "comm-W-shifted/binding-end", &cl, ch, r, "violated");
        let mut cl = base.clone();
        cl.instance.comm_w[40] ^= 1;
        let (ch, r) = self.honest_pair(&cl, &hc, ChallengeKind::Claim, "p");
        self.push("altered-public", "comm-W-off-curve/claim-fold", &cl, ch, r, "violated");

        // ---------------------------------------------------------------- forged openings
        let mut r = self.toy.respond(&hc, &ch3).unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            rr.terms[0].reveals[0][3] ^= 0x40;
        }
        self.push("forged-opening", "flipped-reveal-byte", &base, ch3.clone(), Some(r), "response_invalid");
        let mut r = self.toy.respond(&hc, &ch3).unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            let o = &mut rr.terms[1];
            let k = (o.index & 1) as usize;
            o.pair[k][12] ^= 1;
        }
        self.push("forged-opening", "item-value-changed", &base, ch3.clone(), Some(r), "response_invalid");
        let mut r = self.toy.respond(&hc, &ch1).unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            rr.e_open = (&flatmerkle::open(&hc.w_stream, 1)).into();
        }
        self.push("forged-opening", "E-opening-from-W-tree", &base, ch1.clone(), Some(r), "response_invalid");
        let chs = challenge_for(&base, ChallengeKind::BindingStep { vec: Vector::W, step: 5 }, "o");
        let mut r = self.toy.respond(&hc, &chs).unwrap();
        if let FlatCheckResponse::Step(sr) = &mut r {
            let (st, ts) = hc.trace(Vector::E);
            sr.cur = RecordOpen { record: binding::trace_record(fid, Vector::E, 5, &st[5].0, &st[5].1), open: (&flatmerkle::open(ts, 5)).into() };
        }
        self.push("forged-opening", "trace-state-from-E-trace", &base, chs, Some(r), "response_invalid");
        let chg = challenge_for(&base, ChallengeKind::BindingStep { vec: Vector::W, step: 255 }, "o");
        let mut r = self.toy.respond(&hc, &chg).unwrap();
        if let FlatCheckResponse::Step(sr) = &mut r {
            sr.gen = RecordOpen { record: binding::gen_record(fid, 2, &self.toy.pinned.gen_bytes[2]), open: (&flatmerkle::open(&self.toy.pinned.ck, 2)).into() };
        }
        self.push("forged-opening", "generator-substituted", &base, chg, Some(r), "response_invalid");
        // Proof substitution: a W opening from another witness's tree.
        let mut w_other = w0.clone();
        w_other[0] += one;
        let c_other = self.commit_fe(&w_other, &e0);
        let ch0 = challenge_for(&base, ChallengeKind::Row { row: 0 }, "o");
        let mut r = self.toy.respond(&hc, &ch0).unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            rr.terms[self.slot(2, 0)] = (&flatmerkle::open(&c_other.w_stream, 0)).into(); // C slot 0 reads W0
        }
        self.push("forged-opening", "opening-from-another-commitment", &base, ch0, Some(r), "response_invalid");

        // ---------------------------------------------------------------- repeated operands
        let (ch, r) = self.honest_pair(&base, &hc, ChallengeKind::Row { row: 3 }, "d");
        self.push("repeated-operand", "W0-read-twice-honest", &base, ch.clone(), r.clone(), "holds");
        let mut r = r.unwrap();
        if let FlatCheckResponse::Row(rr) = &mut r {
            let s = self.slot(1, 0); // B slot 0 reads W0
            let o = &mut rr.terms[s];
            let k = (o.index & 1) as usize;
            o.pair[k][12] ^= 1;
        }
        self.push("repeated-operand", "W0-second-read-different-value", &base, ch, Some(r), "response_invalid");

        // ---------------------------------------------------------------- replayed contexts
        let mut cl2 = base.clone();
        cl2.session_id = nonce("session-2");
        let foreign = challenge_for(&cl2, ChallengeKind::Row { row: 0 }, "c");
        let r = self.toy.respond(&hc, &foreign);
        self.push("replay", "challenge-of-another-claim", &base, foreign, r, "challenge_invalid");
        let mut ch = challenge_for(&base, ChallengeKind::Row { row: 0 }, "c");
        ch.replay.contract_id = fixture::contract_id("another contract");
        let r = self.toy.respond(&hc, &ch);
        self.push("replay", "challenge-other-contract", &base, ch, r, "challenge_invalid");
        let mut ch = challenge_for(&base, ChallengeKind::Row { row: 0 }, "c");
        ch.replay.network = "mainnet".into();
        self.push("replay", "challenge-other-network", &base, ch, None, "challenge_invalid");
        let mut ch = challenge_for(&base, ChallengeKind::Row { row: 0 }, "c");
        ch.version = 2;
        self.push("replay", "challenge-version-2", &base, ch, None, "challenge_invalid");
        let old = challenge_for(&base, ChallengeKind::Row { row: 0 }, "earlier");
        let stale = self.toy.respond(&hc, &old);
        let fresh = challenge_for(&base, ChallengeKind::Row { row: 0 }, "later");
        self.push("replay", "response-to-earlier-challenge", &base, fresh, stale, "response_invalid");

        // ---------------------------------------------------------------- witness / error substitution
        let mut w1 = w0.clone();
        w1[2] += one;
        let c = self.commit_fe(&w1, &e0);
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::Row { row: 3 }, "w");
        self.push("witness-substitution", "W2-changed-row3", &cl, ch, r, "violated");
        let mut e1 = e0.clone();
        e1[0] += one;
        let c = self.commit_fe(&w0, &e1);
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::Row { row: 0 }, "w");
        self.push("witness-substitution", "E0-changed-row0", &cl, ch, r, "violated");
        // W' and E' = A z' o B z' - u C z': every row holds; only the Pedersen binding sees it.
        let mut wf = w0.clone();
        wf[1] += E::Scalar::from(1234567);
        let ef = forge_error(&self.toy, &wf);
        let cf = self.commit_fe(&wf, &ef);
        let clf = self.claim_over(&cf);
        for row in 0..tc.num_cons {
            let (ch, r) = self.honest_pair(&clf, &cf, ChallengeKind::Row { row }, "wf");
            self.push("witness-substitution", &format!("forged-WE/row{row}"), &clf, ch, r, "holds");
        }
        let (ch, r) = self.honest_pair(&clf, &cf, ChallengeKind::Claim, "wf");
        self.push("witness-substitution", "forged-WE/claim-fold", &clf, ch, r, "holds");
        for v in [Vector::W, Vector::E] {
            let (ch, r) = self.honest_pair(&clf, &cf, ChallengeKind::BindingEnd { vec: v }, "wf");
            self.push("witness-substitution", &format!("forged-WE/binding-end-{v:?}"), &clf, ch, r, "violated");
        }
        // The operator also overwrites the last W trace state with Nova's comm_W.
        let mut cg = cf.clone();
        let last = steps_w as usize;
        cg.trace_w[last].0 = base.instance.comm_w;
        fixture::restream(&mut cg, Vector::W);
        let clg = self.claim_over(&cg);
        let (ch, r) = self.honest_pair(&clg, &cg, ChallengeKind::BindingEnd { vec: Vector::W }, "wg");
        self.push("witness-substitution", "forged-WE-end-patched/binding-end-W", &clg, ch, r, "holds");
        let (ch, r) = self.honest_pair(&clg, &cg, ChallengeKind::BindingStep { vec: Vector::W, step: steps_w - 1 }, "wg");
        self.push("witness-substitution", "forged-WE-end-patched/last-step-W", &clg, ch, r, "violated");
        // The operator commits W' values but Nova's own W trace (which ends at comm_W).
        let mut ch_ = cf.clone();
        ch_.trace_w = hc.trace_w.clone();
        ch_.trace_w_stream = hc.trace_w_stream.clone();
        ch_.trace_e = hc.trace_e.clone();
        ch_.trace_e_stream = hc.trace_e_stream.clone();
        let clh = self.claim_over(&ch_);
        for v in [Vector::W, Vector::E] {
            let (ch, r) = self.honest_pair(&clh, &ch_, ChallengeKind::BindingEnd { vec: v }, "wh");
            self.push("witness-substitution", &format!("forged-WE-nova-trace/binding-end-{v:?}"), &clh, ch, r, "holds");
        }
        let first_bad = (0..steps_w)
            .find(|&step| {
                let ch = challenge_for(&clh, ChallengeKind::BindingStep { vec: Vector::W, step }, "scan");
                let r = self.toy.respond(&ch_, &ch);
                adjudicate::<E>(&tc, &clh, &ch, r.as_ref()).refutes()
            })
            .expect("a wrong transition exists");
        let (ch, r) = self.honest_pair(&clh, &ch_, ChallengeKind::BindingStep { vec: Vector::W, step: first_bad }, "wh");
        self.push("witness-substitution", "forged-WE-nova-trace/first-wrong-W-step", &clh, ch, r, "violated");
        let _ = steps_e;

        // ---------------------------------------------------------------- withheld / binding start
        let ch = challenge_for(&base, ChallengeKind::Row { row: 2 }, "n");
        self.push("withheld", "row2-no-response", &base, ch, None, "response_missing");
        let ch = challenge_for(&base, ChallengeKind::BindingStep { vec: Vector::E, step: 9 }, "n");
        self.push("withheld", "binding-step-no-response", &base, ch, None, "response_missing");
        let mut c = hc.clone();
        c.trace_w[0].0 = self.toy.pinned.gen_bytes[0];
        fixture::restream(&mut c, Vector::W);
        let cl = self.claim_over(&c);
        let (ch, r) = self.honest_pair(&cl, &c, ChallengeKind::BindingStart { vec: Vector::W }, "b");
        self.push("binding-start", "acc0-not-identity", &cl, ch, r, "violated");
        let chb = challenge_for(&base, ChallengeKind::BindingStart { vec: Vector::E }, "b");
        let mut r = self.toy.respond(&hc, &chb).unwrap();
        if let FlatCheckResponse::Start(sr) = &mut r {
            sr.gen0 = RecordOpen { record: binding::gen_record(fid, 1, &self.toy.pinned.gen_bytes[1]), open: (&flatmerkle::open(&self.toy.pinned.ck, 1)).into() };
        }
        self.push("binding-start", "generator-1-offered-as-0", &base, chb, Some(r), "response_invalid");
    }

    /// Index into `RowResponse::terms` of slot j of matrix m.
    pub fn slot(&self, m: usize, j: usize) -> usize {
        let k = self.toy.pinned.tc.k;
        (0..m).map(|i| k[i] as usize).sum::<usize>() + j
    }
}

/// Run one case natively under the trusted configuration of `tc_field`.
pub fn run_native(case: &Case, pallas_tc: &TrustedConfig, vesta_tc: &TrustedConfig) -> Verdict {
    use nova_snark::provider::{PallasEngine, VestaEngine};
    match case.tc_field {
        FieldId::PallasScalar => adjudicate::<PallasEngine>(pallas_tc, &case.claim, &case.challenge, case.response.as_ref()),
        FieldId::VestaScalar => adjudicate::<VestaEngine>(vesta_tc, &case.claim, &case.challenge, case.response.as_ref()),
    }
}

/// Cases that put one field's honest claim before the other field's configuration.
pub fn cross_field_cases(p: &Suite<nova_snark::provider::PallasEngine>, v: &Suite<nova_snark::provider::VestaEngine>) -> Vec<Case> {
    let mut out = Vec::new();
    for (src, tcf, cases) in [(FieldId::PallasScalar, FieldId::VestaScalar, &p.cases), (FieldId::VestaScalar, FieldId::PallasScalar, &v.cases)] {
        for name in ["honest/row1", "honest/binding-step-W-255"] {
            let c = cases.iter().find(|c| c.name.ends_with(name)).unwrap();
            let mut c = c.clone();
            c.name = format!("{}-claim-under-{}-config/{name}", src.name(), tcf.name());
            c.group = "switched-field";
            c.tc_field = tcf;
            c.expected = "claim_invalid";
            c.expected_refutes = true;
            out.push(c);
        }
    }
    out
}
