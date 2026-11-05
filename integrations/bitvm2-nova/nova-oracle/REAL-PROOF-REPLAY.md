# Real-proof transcript replay boundary

This records the exact non-EVM Nova 0.76.0 verifier sequence needed to connect
the retained NHT4 proof to the arithmetic/Script components. A native forwarding
engine and an independent Python replay are being integrated. Their current-head
hosted execution is pending. A trace or partial replay does not establish a
complete authenticated BitVM2 verifier or general proof validity.

Fixture paths below are relative to `integrations/bitvm2-nova/`.

The route remains transparent Nova -> Spartan/IPA. The authoritative crate is
`nova-snark = 0.76.0`, archive SHA-256
`c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31`,
VCS revision `98576efa884072bfe69bfad8f275a3a5cd8754e5`. The retained header
circuit is pinned at `de607d3db17d400dd6c2923d357f1d4a7bf233c7`.

## Roles and trusted inputs

| Role | Group/base field | Scalar/Keccak challenge field | Native Poseidon RO field |
| --- | --- | --- | --- |
| E1 / primary | Pallas / P | Q | P |
| E2 / secondary | Vesta / Q | P | Q |

Equal field moduli in different roles do not identify protocol contexts. Bind
the network, circuit/backend/key identity, k, step count, z0, expected output
state and exact container/proof bytes through verifier-owned NHT4 expectations.
Preserve the actual upstream labels and object order; adding application labels
inside the upstream transcript changes its challenges.

The actual dimension descriptor is independently pinned in
`fixtures/nht4-genesis-0-2020-k5.dimensions.json`, canonical SHA-256
`de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc`.
Its primary shape has Nc=Nv=524288, mc=mv=m=19; secondary has Nc=Nv=16384,
mc=mv=m=14. The replay must use authenticated dimensions, not proof row counts.
The general formulas below also cover regular nonsquare shapes.

Tiny replay bindings must be exported from the already SHA-pinned actual key:

| Private serde path | Meaning |
| --- | --- |
| `pp_digest` | Outer public-parameter digest, an E1 scalar. |
| `vk_primary` / `vk_secondary` | Entire Spartan key, hashed by actual `DigestComputer` into that role's scalar field. |
| `dk_primary.h` / `dk_secondary.h` | Main commitment-key blinding generators used to remove the proof's W/E blinds. |
| `vk_{primary,secondary}.vk_ee.ck_s.ck[0]` | Trusted IPA scalar commitment generator U0; the checked scalar key has one generator. |

`vk_ee.ck_s.h` is a separate scalar-key blinding generator. IPA verification
commits with zero blinding. It is not the main `dk.h` and is not U0.
Key affine points use canonical 32-byte compressed encoding. Export and import
must preserve their curve roles and reject identity-sign aliases.

Spartan's `DigestComputer` uses **SHA3-256**, legacy fixed-integer little-endian
bincode2 serde, and the low 250 digest bits as a scalar. This differs from the
Keccak-256 transcript and the exterior full-VK SHA-256 pin. Digest/cache fields
are skipped by serde. A delegating `Serialize` view implementing public
`SimpleDigestible` can hash each selected private child through the actual
library without materializing the whole key. Replay bindings need their own
independently authenticated digest. An embedded VK digest or `passed: true`
report does not authenticate editable JSON.

## Exact Spartan and IPA transcript

Each role constructs one fresh transcript with label `RelaxedR1CSSNARK`. Let
mc=log2(Nc), mv=log2(Nv), m=max(mc,mv). All scalar representations below are
canonical 32-byte little-endian encodings; slices add no length prefix.

1. Absorb `vk`: the actual Spartan VK digest scalar. Absorb `U`: the folded,
   derandomized relaxed R1CS instance. Its transcript representation is
   `comm_W || comm_E || u || X`, with 65-byte Pedersen commitment representations
   `(x || y || infinity_flag)`. This order differs from its bincode field order
   `comm_W, comm_E, X, u`.
2. Squeeze `t` mc times to obtain tau. Verify the outer degree-three sumcheck
   from initial claim zero, using mc rounds. Each round decompresses its proof
   row, absorbs `p`, squeezes `c`, then evaluates the polynomial at that challenge.
3. Check the outer terminal claim:
   `Eq(tau, rx) * (Az*Bz - U.u*Cz - eval_E)`.
4. Absorb `claims_outer`: `[Az, Bz, Cz, eval_E]`. Squeeze `r`. The inner initial
   claim is `Az + r*Bz + r^2*Cz`. Verify mv+1 degree-two `p`/`c` rounds.
5. Check the inner terminal claim:
   `(A(rx,ry) + r*B(rx,ry) + r^2*C(rx,ry)) * eval_Z`, where
   `eval_Z = (1-ry[0])*eval_W + ry[0]*SparseEval([U.u]+U.X, ry[1:])`.
   The matrix evaluations come from the authenticated key's matrices.
6. Absorb `w`: `[eval_W]`. Form opening claims in order W then E, with
   commitments `[U.comm_W, U.comm_E]`, points `[ry[1:], rx]`, evaluations
   `[eval_W, eval_E]` and dimensions `[mv, mc]`.
7. Squeeze `r` to obtain rho. The batch sumcheck initial claim is
   `sum_i rho^i * 2^(m-dim_i) * claim_i`. Verify m degree-two `p`/`c` rounds.
   Its terminal expectation is
   `sum_i Eq(batch_r_tail_i, opening_point_i) * evals_batch[i] * rho^i`.
8. Absorb `l`: `evals_batch`. Squeeze `c` to obtain gamma. Derive the joint
   commitment `C_W + gamma*C_E`, the joint point `batch_r`, and the joint
   evaluation `sum_i gamma^i * L0(batch_r_prefix_i) * evals_batch[i]`.
   Here each prefix has length `m-dim_i`, and `L0(prefix)=product(1-x)`.
   Those L0 factors belong to zero-padding in the final joint opening; they
   do not replace the Eq factors in the preceding sumcheck terminal test.
9. On the same transcript, domain-separate with `IPA`. Absorb `U`:
   `commitment_repr(joint_C) || scalar_repr(joint_eval)`. The dense public
   b-vector is deliberately omitted because it is derived from `batch_r`.
   Squeeze `r` for the scalar-generator scale r0.
10. For each IPA round, absorb `L`, absorb `R`, then squeeze `r` to obtain ui.
    Verify the IPA group equality. There is no later absorption of `a_hat`.

Important representation detail: although the sumcheck call absorbs a
**decompressed UniPoly**, its `TranscriptReprTrait` recompresses it. The actual
`p` bytes are only `coeffs_except_linear_term`, preserving encoded row width
and trailing zeros. They exclude the reconstructed linear coefficient. The
producer uses three scalars for outer rows and two for inner/batch rows.

For this retained profile, recording only transcript trait calls gives 204
primary events including `new` and 100 squeezes; secondary gives 154 events
including `new` and 75 squeezes: 358 events total. Per role the count is
`14 + 3*mc + 2*mv + 5*m`, including `new`. Snapshot/export bookkeeping is not an
additional protocol event.

The five Poseidon streams add 159 events (149 absorbs, five constructors and
five squeezes), giving seven streams and 517 recorded trait events overall.
Session order within E1 RO is outer hash then primary relaxed fold; within E2
RO it is outer hash, ordinary secondary fold, relaxed secondary fold.

The IPA equality is

```
C + r0*e*U0 + sum(ui^2*Li) + sum(ui^-2*Ri)
  = a_hat*sum(si*Gi) + r0*a_hat*<b,s>*U0
```

The public vector is `b=EqPolynomial(batch_r).evals()`. In upstream order,
`si` uses ui inverse for a zero index bit and ui for a one bit, most-significant
bit first. Thus `<b,s>` factorizes as
`product((1-batch_r[j])/ui[j] + batch_r[j]*ui[j])`. Computing that scalar does
not verify the generator MSM or the final group equality. All generators must
remain bound to the trusted key. Zero inversion challenges must reject.

## Exact outer and NIFS Poseidon sequence

`NUM_HASH_BITS=250`, `NUM_CHALLENGE_BITS=128`. The complete verifier uses five
native RO instances here, all created with default Wide mode. A commitment is
absorbed as three base-field elements `(x,y,infinity_flag)`. An ordinary
instance absorbs its W commitment followed by each X scalar switched to the
base field (five elements with X length two). A relaxed instance absorbs W,
E, switched u, then each X as four little-endian 64-bit limbs switched to the
base field: fifteen elements. This is neither its bincode nor Keccak encoding.

Let switch_E denote upstream `scalar_as_base<E>`. Its implementation switches
fields through little-endian bits and target-field arithmetic. Preserve the
declared source and target fields even when a particular small value fits both.

| Instance, in verifier construction order | Absorbed values | Count | Squeeze |
| --- | --- | ---: | --- |
| E2 RO, primary outer hash | pp_digest, steps, z0[17], zn[17], r_U_secondary as RO, ri_primary | 52 | 250 bits, false |
| E1 RO, secondary outer hash | switch_E1(pp_digest), steps, 0, 0, r_U_primary as RO, ri_secondary | 20 | 250 bits, false |
| E2 RO, ordinary secondary fold | switch_E2(switch_E1(pp_digest)), l_u_secondary as RO, nifs_Uf_secondary.comm_T | 9 | 128 bits, false |
| E2 RO, relaxed secondary fold | same switched digest, derived r_Uf_secondary as RO, l_ur_secondary as RO, nifs_Un_secondary.comm_T | 34 | 128 bits, false |
| E1 RO, relaxed primary fold | switch_E1(pp_digest), r_U_primary as RO, l_ur_primary as RO, nifs_Un_primary.comm_T | 34 | 128 bits, false |

The first outer hash must equal `base_as_scalar<E1>(l_u_secondary.X[0])`;
the second must equal `l_u_secondary.X[1]`. The code constructs and fills both
outer hashers before squeezing them. Global collector order must not invent
extra ordering between otherwise independent streams.

Each NIFS challenge is the corresponding 128-bit RO result switched back to
the engine's scalar field. Ordinary folding uses
`W=W1+r*W2`, `E=E1+r*T`, `X=X1+r*X2`, `u=u1+r`. Relaxed folding uses the same W/X
formulas, `E=E1+r*T+r^2*E2`, and `u=u1+r*u2`. Derandomization then subtracts
`dk.h * wit_blind` from W and `dk.h * err_blind` from E. This derives the U
absorbed by each Spartan verifier. A replay cannot substitute the raw running
instance for that derived U.

Poseidon uses the actual Neptune Simplex sponge, its authenticated Wide
constants and I/O pattern `Absorb(number_of_elements), Squeeze(1)`. After a
squeeze, native state retains the full field hash; the returned low 128/250
bits are a different value. A trace can check truncation against captured full
state without independently checking the sponge permutation. No RO2 instance
is required by this complete-verification call chain; key digests use SHA3.

## Forwarding and evidence boundaries

The intended native architecture reuses the original Base/Scalar/GE types,
Pedersen commitment engine and actual `Keccak256Transcript`/`PoseidonRO`
implementations. Engine wrappers observe forwarding calls. Circuit RO types
and constants remain the original types. Full key byte identity and successful
verification must be checked; matching type signatures alone is insufficient.

The transcript wrapper must serialize an absorbed object once, or read the
actual appended bytes from the upstream serialized buffer. A generic encoded
view may forward the same bytes to the real transcript. Poseidon absorption
arguments and full after-state can be captured without serializing all sponge
constants on every event. Every event/byte-cap failure must invalidate the
report; truncated logs are not complete-execution evidence.

The two Spartan verifiers run under `rayon::join`. Use a shared collector with
explicit role, run/session identity and per-instance local ordinals. A
thread-local enable flag can miss worker events. Global interleaving is not
canonical protocol order. Enable collection only around the intended positive
verification, excluding setup and separate negative runs.

Python must reconstruct expected absorption bytes and relations from the
decoded proof, externally pinned key bindings/dimensions, external NHT4 state
and derived folded instances. Replaying arbitrary logged bytes into Keccak
and comparing the resulting challenges is only transcript self-consistency.
The retained conformance path should independently pin its native trace digest;
an input's self-declared digest and successful-looking report are not authority.

TE/RO callbacks do not expose all matrix evaluation arithmetic or the final
generator MSM. If Poseidon, matrix evaluations or that MSM remain unchecked by
the independent replay, report those individual fields as false. Keep overall
`proof_verified` false for the partial replay, even when its source is a proof
already accepted by the actual native library. A generator-free IPA scalar
calculation does not close the group equation.

All Rust builds, key reconstruction and full native verification remain on
hosted runners under explicit caps. The intended retained replay scope keeps
the 3 GiB address-space and 600-second bounds used for native reconstruction.
Local work is limited to bounded Python checks and source/format review. No
proving, GPU work, transaction broadcast or deployment is part of this stage.

Primary source links: [Spartan verify](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/snark.rs#L259),
[sumcheck](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/sumcheck.rs#L87),
[polynomial transcript representation](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/polys/univariate.rs#L177),
[batch opening](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/mod.rs#L434),
[IPA](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/provider/ipa_pc.rs#L286),
[outer verification](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/nova/mod.rs#L914),
[NIFS](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/nova/nifs.rs#L75),
and [key digests](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/digest.rs).
