# Next implementation boundary

M2 and the subsequent arithmetic/WOTS milestones are integrated on main. The
opt-in M2.1 footprint comparison is documented
in [M2-COMPACT.md](M2-COMPACT.md); `m2` remains the default compiler. Its complete
point graph still totals 14,148,063 Script bytes before transaction/assertion
overhead. This bounded optimization does not complete M3 or M4 below.

[M2-CONVOLUTION.md](M2-CONVOLUTION.md) records the further opt-in integer
convolution argument and its identical-accounting fixed-claim/WOTS comparison.
The Horner builder remains the default; fewer signed words do not by themselves
establish a smaller authenticated Script graph.

[WOTS-LEAF.md](WOTS-LEAF.md) describes the next bounded adapter: one upstream-
WOTS-authenticated multiplication step, including disputable malformed signed
values. The global registry is described separately below; the Bitcoin
transaction graph required by M4 remains unimplemented.

[WOTS-REGISTRY.md](WOTS-REGISTRY.md) extends that boundary to a complete global
wire/key catalogue, explicit field-validity leaves, and signature reuse across
linked constraints. It remains an arithmetic adapter pending production key
lifecycle, transaction commitments and the actual Nova/Spartan verifier.

## Arithmetic argument for M1

Let B=2^29 and write a field value as nine radix-B limbs. Both Pasta moduli
are below 2^255, while the representation holds 261 bits. For canonical inputs,
x+y < 2p < 2^256, so the ninth carry is zero. The emitted script enforces it.
At each addition limb, x_i+y_i+carry is at most 2B-1, below 2^30. Each operand
of a numeric opcode therefore fits a four-byte signed ScriptNum. The
subtraction limb lies in [-B,B-1], also within that bound.

The subtraction pass computes s-p and its borrow. A final borrow selects s;
otherwise it selects s-p. Since s<2p, this is the unique canonical field sum.
The bit-step composes two such additions, with the second addend selected
from a and zero by a checked Boolean bit. It therefore checks
`t_next = (2t+bit*a) mod p`.

For a complete multiplication, initialize t=0 and feed the 255 authenticated
bits of b from most to least significant. Induction gives t=a*b mod p.
M1 executes that induction in the local test runner. The on-chain trace still
needs authenticated bit extraction, t=0 anchoring, step indexing, link checks
and a final-output check. Independent leaf correctness alone cannot supply
those obligations.

## M2: Pasta point arithmetic and authenticated arithmetic trace

Implement complete curve-operation dispatch, including infinity, doubling
and inverse-point cases. Treat noncanonical coordinates and points off-curve
as explicit disputable validity failures. For a generic affine addition, the
slope must satisfy `(x2-x1)*lambda = y2-y1`, with a nonzero denominator;
for doubling use `(2*y1)*lambda=3*x1^2`. Verify the resulting x/y equations.
A multiplication witness needs every Horner transition bound to one operation
ID. The field role, ordinal and context digest must be committed as well.

Extend the differential harness to randomly generated field vectors and
Pasta curve vectors from halo2curves. Run Bitcoin Core script tests with the
intended flags. Preserve upstream's enabled stack limit. The present Rust
probe uses upstream BitVM's interpreter, which is a different acceptance
layer from a mined Bitcoin transaction.

## M3: exact production transcript and Spartan/Nova verifier

The bounded implementation in [NATIVE-CONFORMANCE.md](NATIVE-CONFORMANCE.md)
adds the published Nova 0.76.0 non-EVM Keccak transcript, strict retained NHT4
framing, production sumcheck folds and terminal-equation helpers. Independent
native oracles call actual Nova APIs; hosted execution is required before
claiming their conformance. Genuine proof coefficients exercised from synthetic
transcript states do not establish the actual proof's Fiat-Shamir replay.
The Keccak Script work covers one permutation round with Boolean gates; linked
round boundaries and a complete authenticated sponge remain open.

[PROOF-ADMISSION.md](PROOF-ADMISSION.md) records actual k=5 IPA dimensions from
the authenticated key (524,288 primary generators and 16,384 secondary), a
separately pinned descriptor and bounded inner decoding. The independent native
admission oracle must pass current-head CI before use. Complete native proof
verification still retains the fixture gate; whole-proof protocol replay and
Script composition remain separate work.

The [real-proof replay boundary](nova-oracle/REAL-PROOF-REPLAY.md) now captures
the actual verifier with forwarding engines and reconstructs proof-bound Keccak
events independently. It replaces synthetic transcript states for this retained
conformance path. [Independent Poseidon hashing](nova-oracle/POSEIDON.md) now
computes all five full hashes from separately pinned actual-key parameters.
[Authenticated matrix streams](nova-oracle/MATRIX-PROFILE.md) now support the
independent evaluation of all six actual matrices and both inner sumcheck
terminals on the retained proof. The full generator MSM remains unchecked by
Python, but both native library IPA terminal checks now pass over the complete
generator vectors through direct trusted helper execution as recorded below.
The complete authenticated Script verifier is still unfinished.

Instrument the pinned Nova implementation rather than substitute the
TEST-ONLY transcript. Account for its challenge reduction and byte encodings.
Bind network, circuit/key identity, k, step count, expected initial/final state
and proof bytes to verifier-owned expectations. Implement both curve roles,
the outer compressed-Nova checks, Spartan's sumchecks, matrix evaluations,
and the IPA openings. Reject surplus/truncated proof data and all unsupported
variants. Compare against the real NHT4 fixtures on the pinned header branch.

The k=5 dimension is now measured; k=1 remains unmeasured here. Stream generator
access and coefficient computation. Include cold parameter generation and
verification in the RAM measurement. The native upstream IPA implementation
uses a generator MSM whose length depends on circuit width; the retained run
below measures its actual k=5 dimension.

The actual ordered `vk_ee.ck_v.ck` generator export and the next bounded native
IPA execution step have now passed. Main
`024802628267d2fa1f55e8e73e91c17398fb019f` completed the
[hosted native job](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42150230495/job/127671408410)
with **524,288 primary generators / 19 rounds** and **16,384 secondary generators /
14 rounds**, authenticating **17,301,520 serialized bytes**. The independently
pinned collection SHA-256 is
`db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4`.
All weights, factorized `b_hat` and small-side terms were recomputed from sealed
proof-derived requests before the released mature CPU MSM results were compared
to their required residuals. Seven native toy test groups also passed in
0.07 seconds.

Primary native MSM time was 1.308729368 s, native wall 16.415079313 s and direct
execution 16.456441837 s; secondary was 0.066018545 s, 0.556989169 s and 0.575105887 s.
The overall IPA benchmark took 18.684226907 s with 31,440,896 bytes of parent peak
RSS. A separate `/usr/bin/time` measurement for the wrapper and children recorded
157,904 KiB (161,693,696 bytes) peak RSS; the parent figure alone does not measure
worker or combined pipeline memory. Exact request digests, execution limits and
result scope are recorded in
[NATIVE-CONFORMANCE.md](NATIVE-CONFORMANCE.md#executed-native-ipa-terminals).
No raw generator payload, native helper or large MSM ran on the local PC.

This enables only `ipa_native_msm_executed` and `ipa_native_relation_checked`.
Independent Python MSM, full IPA verification, general proof acceptance and
BitVM2 Script verification remain false. Next, compose the independently replayed
transcript/matrix checks and this directly executed native terminal boundary
without treating a stored JSON receipt as authority, then bind the production
computation into the complete authenticated dispute graph. A native result or
sampled generator weights cannot authorize proof acceptance.

[MATH-COMPOSITION.md](MATH-COMPOSITION.md) introduces the mandatory retained-profile
composition call: fresh replay with all six authenticated matrices and both
inner equations, matched sealed requests, then both direct native IPA executions.
It accepts no imported result receipt and preserves every general proof/Script
verification flag as false. Literal policy preflight precedes bulk work. Code
commit `2bee4dde7f160be029f40fcd659bac7fd6d0ae0b` passed all eight workflows and
244 Python tests. The real composed call checked six matrices / 2,667,462 entries
and both IPA terminals / 540,672 generators in 25.583282246 seconds. The result
enables only `retained_math_checks_composed`; it remains scoped to the retained
profile and is not a Script verifier or general proof-acceptance API.

## M4: BitVM2 graph adapter

[TAPROOT-COMMITMENT.md](TAPROOT-COMMITMENT.md) records the implemented offline
commitment to actual registry Scripts using mature BIP341 APIs. Code commit
`5a82788780bf9b4c3f17777cf5367ad1edd0250e` passed all seven workflows, including
eight complete tree constructions, 108 membership negatives and unchanged
Script-stream goldens. The hosted Taproot run took 44.503489095 seconds and
69,420 KiB peak RSS. It creates no assertion UTXO or Bitcoin transaction binding.

[SUMCHECK-GRAPH.md](SUMCHECK-GRAPH.md) implements the next bounded arithmetic
composition: two proof-derived outer sumcheck rounds in one global WOTS graph,
sharing the first output wire with the next prior claim. Only the initial zero
claim is a protocol anchor; coefficients and challenges are canonical ports
with explicit source identities. Code commit
`abd2d29afe0c872dcd0b98cf9c109d78864700d0` passed all eight workflows. The linked
sumcheck run executed 20 signed cases / 1,204 Script vectors / 728 rejections,
including both coherent shared-claim attacks and their Taproot-member disproofs.
The complete two-round catalogues cost 42,398,317 primary and 42,351,061 secondary
Script bytes with identical accounting. The benchmark records canonical-input
`VERIFY` aborts separately from ordinary false predicates; all malformed-field
cases and witness guards remain.
This establishes arithmetic given authenticated ports. Their proof-byte and
Fiat-Shamir Script binding remains a separate obligation. Whole-hash chunk
composition and curve scalar multiplication/MSM lowering also remain open;
isolated additions or native terminal checks do not supply those graphs.

A bounded next hash-composition step is a sealed two-round Keccak catalogue,
freshly building its child programs and merging exactly 1,600 producer-output /
consumer-input slots. It must preserve each child's injective word mapping and
every leaf's occurrence/alias partition, commit the complete source topology,
and retain both current Program and registry caps. Two rounds 0/1 have a
calculated 19,206 leaves / 20,806 global words; Script costs are unmeasured.
This would close one internal boundary only. Twelve such pairs still leave
eleven inter-pair boundaries, absorption/padding/squeeze and the complete Nova
transcript framing to authenticate. Registry/key and Taproot commitment order
must remain acyclic; a resulting root cannot be its own input context.

Integrate authenticated assertions using the existing BitVM2 commitment
mechanism. Define a static chunk graph and prove complete dispute coverage
for every invalid execution, including bad encodings and missing links.
The fixed-claim SHA-256 opening fixtures are not this adapter. Evaluate
assertion data, presigned transactions, challenge paths, timelocks, witnesses
and transaction weight. Keep UTXORef behind a versioned statement adapter.

Ship an end-to-end negative test before accepting any deposit or withdrawal:
an invalid Nova proof must have a spendable disproof path, while every
purported disproof of the valid proof must fail. Neither security property
has been established for a complete Nova graph by M1.
