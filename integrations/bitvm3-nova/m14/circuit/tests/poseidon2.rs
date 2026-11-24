//! The Poseidon2 gadget against p3's own permutation and sponge (p3-poseidon2 and p3-koala-bear
//! 0.4.3-succinct, the crates SP1 6.9.0 builds its hasher from), instantiated as SP1 does: 8
//! external and 20 internal rounds, `Poseidon2ExternalMatrixGeneral`, `DiffusionMatrixKoalaBear`.
//! `m14/e2e/tests/statement.rs` checks the same gadget against `sp1_primitives::poseidon2_hasher`
//! itself and against the digests of real wrap proofs.
use garbled_snark_verifier::{
    AesCcrGateHasher, GarbleMode, GarbledWire, GateHasher, S, WireId,
    circuit::{CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult},
};
use m14_circuit::{
    field::{self as f, Fe, P},
    poseidon2,
};
use p3_field::{AbstractField, PrimeField32};
use p3_koala_bear::{DiffusionMatrixKoalaBear, KoalaBear as KB};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

const CAP: usize = 1 << 22;
const FB: usize = 31;

/// Non-free gates of the hash of 53 elements (the root public-values digest): seven permutations.
const HASH_53_GATES: u64 = 7_103_933;
/// The same hash, its comparison with 8 digest elements, and the AND of the 8 results.
const DIGEST_CHECK_GATES: u64 = 7_104_180;

type Perm = Poseidon2<KB, Poseidon2ExternalMatrixGeneral, DiffusionMatrixKoalaBear, 16, 3>;

fn native_perm() -> Perm {
    let kb = |x: &u32| KB::from_canonical_u32(*x);
    let external: Vec<[KB; 16]> = poseidon2::EXTERNAL_INITIAL
        .iter()
        .chain(poseidon2::EXTERNAL_FINAL.iter())
        .map(|row| core::array::from_fn(|i| kb(&row[i])))
        .collect();
    let internal: Vec<KB> = poseidon2::INTERNAL.iter().map(kb).collect();
    Poseidon2::new(8, external, Poseidon2ExternalMatrixGeneral, 20, internal, DiffusionMatrixKoalaBear)
}

struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, v) in w.iter().zip(&self.0) {
            mode.feed_wire(*id, *v);
        }
    }
}
struct GIn(usize);
impl CircuitInput for GIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, CTH: CiphertextHandler> EncodeInput<GarbleMode<H, CTH>> for GIn {
    fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<H, CTH>) {
        for id in w {
            let v = mode.issue_garbled_wire();
            mode.feed_wire(*id, v);
        }
    }
}
struct Count(u64);
impl CiphertextHandler for Count {
    type Result = u64;
    fn handle(&mut self, _ct: S) {
        self.0 += 1;
    }
    fn finalize(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy)]
enum Op {
    Permute,
    Hash(usize),
    /// Hash of 53 inputs compared with 8 more: the check the final verifier adds.
    DigestCheck,
}

impl Op {
    fn inputs(self) -> usize {
        match self {
            Op::Permute => 16,
            Op::Hash(n) => n,
            Op::DigestCheck => 53 + 8,
        }
    }
    fn build<C: garbled_snark_verifier::CircuitContext>(self, c: &mut C, w: &[WireId]) -> Vec<WireId> {
        let x: Vec<Fe> = w.chunks_exact(FB).map(Fe::from_wires).collect();
        let flat = |v: &[Fe]| v.iter().flat_map(|e| e.0.iter().copied()).collect::<Vec<_>>();
        match self {
            Op::Permute => {
                let mut s: [Fe; 16] = core::array::from_fn(|i| x[i].clone());
                poseidon2::permute(c, &mut s);
                flat(&s)
            }
            Op::Hash(_) => flat(&poseidon2::hash(c, &x)),
            Op::DigestCheck => {
                let d = poseidon2::hash(c, &x[..53]);
                let oks: Vec<WireId> = (0..8).map(|i| f::eq(c, &d[i], &x[53 + i])).collect();
                vec![f::and_all(c, &oks)]
            }
        }
    }
}

fn bits(xs: &[u32]) -> Vec<bool> {
    xs.iter().flat_map(|&x| (0..FB).map(move |i| (x >> i) & 1 == 1)).collect()
}

fn exec(op: Op, xs: &[u32]) -> (Vec<bool>, u64) {
    assert_eq!(xs.len(), op.inputs());
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(Plain(bits(xs)), CAP, |c, w| op.build(c, w));
    (r.output_value, r.gate_count.nonfree_gate_count())
}

fn exec_fes(op: Op, xs: &[u32]) -> Vec<u32> {
    exec(op, xs).0.chunks(FB).map(|b| b.iter().enumerate().map(|(i, &v)| (v as u32) << i).sum()).collect()
}

/// Non-free gates, counted in ExecuteMode and as GarbleMode ciphertexts.
fn count(op: Op) -> u64 {
    let n = op.inputs() * FB;
    let e: StreamingResult<ExecuteMode, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(Plain(vec![false; n]), CAP, |c, w| op.build(c, w));
    let g: StreamingResult<GarbleMode<AesCcrGateHasher, Count>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(n), CAP, 12, Count(0), |c, w| op.build(c, w));
    assert_eq!(e.gate_count.nonfree_gate_count(), g.ciphertext_handler_result, "execute vs garble count");
    g.ciphertext_handler_result
}

fn states(rng: &mut ChaChaRng) -> Vec<[u32; 16]> {
    let mut v = vec![[0; 16], [P - 1; 16], core::array::from_fn(|i| i as u32), core::array::from_fn(|i| P - 1 - i as u32)];
    v.extend((0..12).map(|_| core::array::from_fn(|_| rng.gen_range(0..P))));
    v
}

#[test]
fn montgomery_inverse_constant() {
    assert_eq!(poseidon2::MONTY_INVERSE as u64 * (1u64 << 32) % P as u64, 1);
}

#[test]
fn permutation_equals_p3_on_edge_and_random_states() {
    let perm = native_perm();
    let mut rng = ChaChaRng::seed_from_u64(14);
    for s in states(&mut rng) {
        let want: [KB; 16] = perm.permute(s.map(KB::from_canonical_u32));
        assert_eq!(exec_fes(Op::Permute, &s), want.map(|x| x.as_canonical_u32()).to_vec(), "state {s:?}");
    }
}

#[test]
fn sponge_equals_p3_for_whole_and_partial_last_blocks() {
    let sponge = PaddingFreeSponge::<Perm, 16, 8, 8>::new(native_perm());
    let mut rng = ChaChaRng::seed_from_u64(15);
    for n in [1usize, 7, 8, 9, 16, 53] {
        for _ in 0..3 {
            let xs: Vec<u32> = (0..n).map(|_| rng.gen_range(0..P)).collect();
            let want: [KB; 8] = sponge.hash_iter(xs.iter().map(|&x| KB::from_canonical_u32(x)));
            assert_eq!(exec_fes(Op::Hash(n), &xs), want.map(|x| x.as_canonical_u32()).to_vec(), "{n} inputs");
        }
    }
}

#[test]
fn digest_check_accepts_the_hash_and_refuses_any_changed_element() {
    let sponge = PaddingFreeSponge::<Perm, 16, 8, 8>::new(native_perm());
    let mut rng = ChaChaRng::seed_from_u64(16);
    let mut xs: Vec<u32> = (0..53).map(|_| rng.gen_range(0..P)).collect();
    let digest: [KB; 8] = sponge.hash_iter(xs.iter().map(|&x| KB::from_canonical_u32(x)));
    xs.extend(digest.map(|x| x.as_canonical_u32()));
    assert_eq!(exec(Op::DigestCheck, &xs).0, vec![true]);
    for at in [0usize, 7, 8, 39, 40, 41, 48, 49, 52, 53, 60] {
        let mut bad = xs.clone();
        bad[at] = (bad[at] + 1) % P;
        assert_eq!(exec(Op::DigestCheck, &bad).0, vec![false], "element {at} changed");
    }
}

#[test]
fn gate_counts_agree_between_execution_and_garbling() {
    let (permute, hash, check) = (count(Op::Permute), count(Op::Hash(53)), count(Op::DigestCheck));
    eprintln!("M14 poseidon2_permutation nonfree={permute}");
    eprintln!("M14 poseidon2_hash_53 nonfree={hash}");
    eprintln!("M14 root_digest_check nonfree={check}");
    assert_eq!(hash, HASH_53_GATES);
    assert_eq!(check, DIGEST_CHECK_GATES);
}
