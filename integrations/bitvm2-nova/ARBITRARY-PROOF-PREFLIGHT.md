# Admission requirements beyond the retained proof

This is a source-review checklist, not an implemented arbitrary-proof parser
or a proof of panic freedom. The native NHT4 harness must keep its retained
fixture digest gate. Strict EOF decoding and canonical reserialization are
useful additional checks; they do not replace bounded structural admission
before invoking the complete upstream verifier. No local Rust build, proof
generation or parameter reconstruction was used for this review.

The reviewed Nova files were byte-compared with the published 0.76.0 archive,
whose SHA-256 is
`c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31`.
The release records VCS commit
`98576efa884072bfe69bfad8f275a3a5cd8754e5`. Source links below use that commit.
The group-encoding review uses the resolved halo2curves 0.9.0 source. All
requirements apply to the non-EVM Pallas/Vesta Spartan/IPA backend; other
engines, features and proof systems require separate admission rules.

## Verifier-owned dimensions

Obtain dimensions from an authenticated, trusted verifier key, separately for
`vk_primary` and `vk_secondary`. Serde paths in each Spartan key are
`S.num_cons`, `S.num_vars`, `S.num_io`, and `vk_ee.ck_v.ck` / `vk_ee.ck_s.ck`.
These fields are private Rust fields despite their public serde representation.
Do not obtain them from a purported proof, an unauthenticated key, or a
proof-supplied round count. Record a bounded dimension descriptor tied to the
exact key digest; avoid materializing a large key as an extra JSON tree merely
to inspect these fields.

For each curve define:

```
Nc = S.num_cons                 Nv = S.num_vars
mc = log2(Nc)                   mv = log2(Nv)
m = max(mc, mv)                 n = 2**m = max(Nc, Nv)
```

Require positive power-of-two `Nc` and `Nv`, `S.num_io == 2` for this Nova
augmented-circuit route, and the pinned circuit's exact expected dimensions.
Do not assume `Nc == Nv`: `R1CSShape::pad()` preserves already regular
nonsquare shapes. Require `mv >= 1 + ceil(log2(1 + S.num_io))`; with two public
outputs this is `mv >= 3`. This prevents underflow in the optimized public-input
sparse evaluator. Bound `m < 32`, all checked shifts/products/conversions, and
`n` by a much smaller explicit resource policy appropriate to the pinned key.
The upstream 32-round IPA check alone permits impractically large allocations.

Require the IPA vector commitment key to contain at least `n` generators and
the scalar commitment key at least one. Authenticate all generators and the
blinding/derandomization keys through the pinned key identity. Reconstructing
known transparent public parameters is compatible with the no-trusted-setup
requirement; accepting substitute generators is not.

Relevant source: [Spartan dimensions and terminal checks](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/snark.rs#L259),
[shape padding](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/r1cs/mod.rs#L639),
and [IPA evaluation dimension](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/provider/ipa_pc.rs#L79).

## Proof shape checklist

Paths below are relative to the serialized `CompressedSNARK`. Vector lengths
must be checked while parsing, before allocating from untrusted lengths.

| Serde field path | Required condition |
| --- | --- |
| `zn` | Exactly the trusted outer `F_arity`, 17 for this header circuit; canonical E1 scalars and header-state widths. |
| `r_U_primary.X`, `l_ur_primary.X` | Exactly two canonical E1 scalars each. |
| `r_U_secondary.X`, `l_ur_secondary.X`, `l_u_secondary.X` | Exactly two canonical E2 scalars each. |
| `snark_primary.sc_proof_outer.compressed_polys` | Exactly primary `mc` rows. |
| `snark_secondary.sc_proof_outer.compressed_polys` | Exactly secondary `mc` rows. |
| `snark_{primary,secondary}.sc_proof_inner.compressed_polys` | Exactly that curve's `mv + 1` rows. |
| `snark_{primary,secondary}.sc_proof_batch.compressed_polys` | Exactly that curve's `m` rows. |
| Every row's `coeffs_except_linear_term` | Nonempty; at most three canonical scalars for outer, at most two for inner/batch. Preserve trailing zeroes and encoded degree. |
| `snark_{primary,secondary}.claims_outer` | Fixed tuple of exactly three canonical scalars, not an open-ended vector. |
| `snark_{primary,secondary}.evals_batch` | Exactly two canonical scalars. |
| `snark_{primary,secondary}.eval_arg.L_vec` / `R_vec` | Each exactly that curve's `m` canonical commitments; validate before any shift or upstream IPA call. |
| `snark_{primary,secondary}.eval_E`, `.eval_W`, `.eval_arg.a_hat` | Canonical scalars in that SNARK's scalar field. |
| `ri_primary`, `ri_secondary`, four `*_blind_r_Wn_*` fields, each relaxed instance's `u` | Canonical scalars in the declared curve role. |

The four blind field names are `wit_blind_r_Wn_primary`,
`err_blind_r_Wn_primary`, `wit_blind_r_Wn_secondary`, and
`err_blind_r_Wn_secondary`. E1 is Pallas with scalar Q; E2 is Vesta with scalar P.
The actual prover emits three coefficients per outer row and two per
inner/batch row. The table gives the broader degree-bounded representation
accepted by upstream verification; enforcing exact producer widths would be
an additional explicitly versioned serialization profile.

The complete outer verifier checks `z0`/`zn` arity and all five X-vector
lengths before its indexed hash checks. Duplicate these conditions in bounded
admission rather than deserialize arbitrary allocations first. Keep
`num_steps > 0`, checked conversion to the verifier's `u64` step encoding,
the authenticated network/circuit/key/`k`/initial-state claim, and the expected
final state. Shape checks cannot replace those relations.

Relevant source: [outer proof fields](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/nova/mod.rs#L722),
[outer verification](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/nova/mod.rs#L914),
[Spartan proof fields](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/snark.rs#L72),
[sumcheck](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/sumcheck.rs),
and [evaluation batching](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/mod.rs#L434).

## Commitments and exact bytes

Validate every commitment in the declared curve, including:

- `r_U_primary`, `l_ur_primary`, `r_U_secondary`, `l_ur_secondary`:
  each `.comm_W` and `.comm_E`.
- `l_u_secondary.comm_W`.
- `nifs_Uf_secondary.comm_T`, `nifs_Un_secondary.comm_T`,
  `nifs_Un_primary.comm_T`.
- Both SNARKs' `eval_arg.L_vec[*]` and `R_vec[*]`.

Each Nova Pedersen commitment has a serde `comm` field. Non-EVM binary
Pasta point encoding is a fixed 32-byte compressed group encoding. Use the
checked group decoder, preserve the curve role, and require original bytes to
equal canonical reserialization. Scalars likewise require canonical 32-byte
field encodings. Identity commitments can be legitimate; do not reject all
identity points or use a finite-affine-only decoder for commitments.

One specific alias was identified in halo2curves
0.9.0: `src/serde.rs` lines 326-377 removes the SingleSpare sign bit, then
identifies `x == 0` with infinity without checking that sign is zero. Source
inspection therefore predicts that 32 zero bytes with byte 31 changed to
`0x80` decode as identity and reserialize as 32 zero bytes. This
source inference was subsequently confirmed on both Pasta curves by the
[native run at `7b2e262`](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42118077893):
upstream decoding accepted the alias, while the canonical roundtrip guard
rejected it.
Both Pasta curves select SingleSpare in `src/pasta/{pallas,vesta}.rs`.
The point serde implementation in `src/derive/curve.rs` lines 190-215 uses
the checked compressed decoder, but that does not itself establish unique
byte representation. A strict whole-proof decode/serialize byte equality
check rejects this alias after bounded decoding, while the retained-fixture
gate must precede the decoding itself. Arbitrary proof admission remains open.

## Concrete panic and resource hazards

- `CompressedUniPoly::decompress` indexes coefficient zero before checking
  anything; reject empty rows first. Checking degree after decompression does
  not protect this path (`spartan/polys/univariate.rs`).
- `batch_eval_verify` asserts that `evals_batch.len() == 2`. Its number of
  instances is fixed by the two W/E opening claims, not chosen by the proof
  (`spartan/mod.rs` lines 444-456).
- The optimized sparse public-input evaluator subtracts
  `1 + ceil(log2(prefix_length))` from its dimension. Its public prefix is
  `[u] + X`, hence the trusted-dimension guard above
  (`spartan/polys/multilinear.rs`).
- IPA verification splits the generator key at `n` **before** its input-length
  check. Its next condition computes `1 << L_vec.len()` **before** checking
  `L_vec.len() >= 32`. Require exact trusted lengths and generator capacity
  before calling it (`provider/ipa_pc.rs` lines 294-301;
  `provider/pedersen.rs` lines 461-469).
- IPA constructs dense equality, coefficient and generator/MSM vectors of
  length `n`. Small proof bytes and logarithmic L/R vectors do not imply small
  verification RAM. Enforce process time/memory limits and verifier-owned
  dimension caps before allocating them.
- Keep strict legacy fixed-integer little-endian bincode, a total byte budget,
  and exact EOF. A byte budget does not express the field-specific vector
  conditions above. Use a bounded cursor/serde visitor or equivalent structural
  preflight before general upstream deserialization; check lengths, arithmetic
  and remaining bytes before reserving memory. No panic may be caught and
  reclassified as proof rejection evidence.

If a verification key ever becomes a serialized input, it needs its own
bounded admission and authentication. For each `S.A`, `S.B`, `S.C`, validate
CSR `indptr` length `Nc+1`, initial zero, monotonic pointers, terminal pointer
equal to `data.len() == indices.len()`, bounded nonzero count and column indices
inside the padded assignment domain (`< 2*Nv`, with the pinned matrix's exact
declared column count). Upstream evaluation indexes both matrix rows and
columns unchecked. The present route should keep keys trusted and pinned
instead of accepting proof-supplied matrices.

## Verification still required after admission

The exact call chain is outer arity/hash checks, secondary ordinary NIFS fold,
secondary and primary relaxed NIFS folds, commitment derandomization, both
Spartan verifications, and each Spartan's outer/inner/batch sumchecks followed
by IPA. Nova's outer hash/NIFS stages use its Poseidon random oracle; Spartan
and IPA use the Keccak transcript. Implementing only Keccak does not implement
all verifier hash computation.

After admission, call the actual complete verifier and preserve all hash,
folding, initial/terminal claim, matrix and opening equations. IPA must reject
zero inversion challenges through its existing error path. No proof-supplied
transcript snapshot or challenge is authoritative. Retain the pinned policy
and full output-state binding. For Bitcoin, these computations still require
authenticated Script composition, production WOTS lifecycle/assertion binding
and the transaction/dispute graph described in `NATIVE-CONFORMANCE.md`.

The next bounded implementation should first export a trusted dimension
descriptor, add negative shape/length/alias corpora under resource caps, and
demonstrate deterministic rejection without panics. Keep the retained-proof
gate until that admission layer and complete native replay have independent
evidence. This checklist makes no claim that arbitrary compressed proofs are
currently safe to admit.
