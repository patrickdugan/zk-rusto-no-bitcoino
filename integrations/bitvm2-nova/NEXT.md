# Next implementation boundary

[The full-width WOTS cost comparison](AUTH-COST.md) passed its separate hosted
experiment on `d70edde33ba0d5d585713f9d8b279a94c19ca9c2`
([run 42317646563](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42317646563)).
Complete disproof Script costs are 7,394 to 6,236 bytes for the mixed component
(-15.6613%) and 6,304,498 to 4,306,948 bytes for one BYTE round (-31.6845%), in
both roles. The round's normal combined-stack/witness-item/payload peaks rise
from 35/30/600 to 69/60/612; guard-inclusive peaks are separately 62/60/612 and
69/61/617. All 54,888 Script calls match expected outcomes, including 45,080
expected rejections. Root and independent artifact reconciliation passed. The
dedicated M18 workflow and all twenty-two tested-code workflows passed. No
candidate Taproot/forest, complete permutation, proof or production result follows.

[The retained scalar-source extension](RETAINED-SCALAR-SOURCES.md) passes its
separate thirteen-component hosted experiment on
`3c55e4c31748661b8c157fd14406186490653cd1`, with all twenty-one workflows green.
Its 687,412 Script calls include 372,924 expected rejections; complete costs are
851,805,689 Pallas / 851,891,830 Vesta bytes under unchanged accounting and caps.
The eleven old components retain their exact baseline costs. An asserted 112-byte
block and canonical eval_W encoding add 328,021/328,020 bytes of coverage.
Two honest cases execute fully; four coherent canonical substitutions pass their
local targeted relations. Native reference admission and those joins do not
authenticate claimed whole-proof bytes in Script. Whole-proof origins and EOF,
full scalar/MSM/IPA, production binding and the Bitcoin graph remain open.

[The challenge-bit/conditional-point extension](BYTE-C-BIT-POINT.md) now binds
the actual canonical sumcheck scalar to one fixed bit and `R=A+bP`, retaining
the complete `E=A+P` relation even when the bit is zero. Hosted execution on
`9ebd0cfc451801a15cf37c72e63c86aa6600d390` passes all twenty workflows and
680,120 Script calls, including 366,674 expected rejections. Its eleven
components measure 851,477,668 Pallas / 851,563,810 Vesta Script bytes under
unchanged limits. Two honest cases execute fully; four coherent main faults
and the private point probes have explicitly targeted coverage. Complete
scalar multiplication, IPA, proof origins and the full transcript remain open.

[The linked rho/sumcheck challenge](BYTE-RHO-CHAIN.md) closes the
next actual transcript boundary: rho's 64 raw digest producer bytes feed the
following two-block challenge. The shared prefix, canonical `c0,c2` encodings,
rate absorption and unchanged-capacity forwarding form nine components with
five full permutations. Its census is 147,043 leaves and 147,355 unique words.
Hosted execution passed 623,600 Script calls with 324,792 expected rejections,
measuring 762,253,538 complete Script bytes for Pallas scalar and 762,237,292
for Vesta scalar under the unchanged limits. All 19 workflows passed. Two
honest main cases execute fully; four coherent main cases are targeted and
twenty small probes have separately bound keys/trees. This source does not
complete the transcript or IPA verifier.

[The framed BYTE rho composition](BYTE-RHO.md) connects both LO/HI permutations
to the unchanged uniform reducer through a three-component source. It shares
exactly 96 external message-byte origins, anchors 208 branch-private framing
bytes and links all 64 digest producers directly to the original reducer
adapters. Its source has 58,943 leaves and 59,109 unique words. Hosted execution
passed 487,176 Script calls with 249,580 expected rejections, and measured
305,359,705 complete Script bytes for Pallas scalar and 305,351,582 for Vesta
scalar. All live component/forest streams, shared openings and selected
disproofs passed within the unchanged caps. Full and targeted execution profiles
are reported separately. Script
eval_W canonicality, proof/message origins and prior-state provenance remain
open; this composition does not complete transcript, IPA or proof verification.

## Transcript roadmap and size constraint

The retained trace `fixtures/nht4-genesis-0-2020-k5.trace.json` has SHA-256
`394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8`.
Its primary Keccak stream has 100 squeezes (`t:19`, `c:59`, `r:22`); the
secondary stream has 75 (`t:14`, `c:44`, `r:17`). Including initialization,
there are 354 LO/HI branch hashes. The literal multiblock schedule uses 642
permutations, not 354 single-block permutations. Preimages range from 21 to
339 bytes and require one to three padded rate blocks.

Multiplying the measured isolated BYTE permutation cost by that schedule gives
97,219,675,272 Script bytes (90.543 GiB), before absorption, reductions and
other verifier work. Explicitly sharing complete prefix blocks between LO/HI
reduces the analytical schedule to 498 permutations and its linear subtotal to
75,413,392,968 bytes (70.234 GiB). Neither transcript composition has been
measured, and neither projection is a lower bound on future implementations.
The unchanged 1.25-GiB forest and 16-component policies prevent straightforward
replication of this backend. They are experimental constructor budgets, not a
theorem about Bitcoin or all possible verifiers.

The completed linked experiment connects RHO's actual raw `LO || HI` 64-byte
producers to the immediately following batch-sumcheck challenge. These are primary events
103/104/105 (counter 60) and secondary events 78/79/80 (counter 45). The next
143-byte preimage contains two encoded polynomial coefficients and puts the
previous raw state at message bytes 77-140. Its first 136 bytes are identical
across LO/HI, permitting one explicitly shared prefix permutation followed by
two branch-final permutations. Together with RHO, five full permutations have
a 757,162,580-byte isolated subtotal before bridges and tails. Complete measured
totals are now 762,253,538 and 762,237,292 bytes, with all original cost, record,
memory and component limits passed. This remains a bounded source relation.

That experiment authenticates rate-XOR absorption, unchanged-capacity forwarding,
raw-state producer links, counters, selectors, padding and canonical coefficients.
Coherent changed-state attacks, both block boundaries, exact witness lengths and
actual forest disproofs passed. Further extensions must stop or optimize if
existing limits fail. Proof-byte/length/EOF parsing,
scalar-to-BYTE source bridges, compressed-point transcript encodings, initial
state/key origins and authenticated folded commitments remain explicit gaps.
After those source boundaries, authenticated scalar multiplication and IPA/MSM
verification still require their own measured implementations before end-to-end
proof verification can be claimed.

## Next curve boundary

[The challenge-bit/conditional-point extension](BYTE-C-BIT-POINT.md) has passed
its separate eleven-component hosted experiment. The complete nine-component
chain and the original point-addition backends remain unchanged baselines.

The implemented scalar-action boundary is `R = A + bP`: compute `E = A+P`
with one unchanged complete convolution point-add child, then select `R = b?E:A`.
This still checks `P` when `b=0`. The measured 219,498,908-byte "Horner point"
component is affine addition using thirteen Horner field products; it is not a
scalar-bit point transition. The existing convolution alternative contributes
88,586,200 Pallas / 88,688,588 Vesta bytes before any new selector or bridge.

Nine actual challenge limbs now feed nine unchanged reconstruction leaves
with 255 bound-2 bits, widths `29*8,23`: 264 words and nine leaves. The bridge
retains the actual Uniform canonical guard and real reconstruction/guard
openings, with a verifier-fixed bit index. Only that chosen bound-2 bit crosses
to the corresponding curve base role, selected by role name. Point-coordinate
openings remain asserted ports, not new SSA producers. Existing point dispatch,
on-curve, infinity form, canonicality and witness guards remain intact.

A fresh point/selector Program has 7,498 words and 6,161 leaves,
with explicit projection of all original arithmetic and relocated canonical
guards. The mixed-role wrapper extends the chain to eleven components,
153,213 leaves and 155,107 unique words; all three profiles per role have the
same complete measured cost. The scalar-only chain factory and exact fixed-count
key helper remain unchanged. Conformance covers both bits, signed invalid2,
index/endianness boundaries, coherent changed-bit and scalar-modulus aliases,
invalid unused points, infinity/dispatch cases and 138 new actual opening
comparisons across the six main profiles. The bit bridge costs 435,945 bytes;
the selector adds 201,985 bytes to either unchanged complete-add baseline.
Authenticated doubling would next give `R=2A+bP`; full-width scalar action and
MSM still require their own cost experiment. Generator/proof origins and the
complete IPA remain open.

## Next bounded cost experiment

M19 is a proposed comparison of both adapters on the unchanged complete
Pallas/Vesta point-addition graphs: 7,476 words and 6,151 leaves per role, under
new isolated source admission. Executing every normal leaf in C/D modes under
both adapters gives 49,208 normal calls across the two roles; targeted adversarial
and authentication checks require their own bounded inventory.

Historical compact measurements are 88,586,200 Pallas and 88,688,588 Vesta Script
bytes. Remeasure the matched baselines alongside the candidate under identical
accounting. Only 1,152 words in either graph have BYTE bounds, so M18's one-round
31.6845% reduction cannot be projected onto this mixture of BYTE, limb, product,
carry and selector bounds. New point-graph costs are unmeasured, and neither
witness nor combined-stack fit is guaranteed by the round result.

Preserve every complete curve/field constraint and actual shared opening,
full-u32 signatures, canonical ten-digit hints, bound-only mode selection and
exact witness-length guards before indexed reads. Keep the old implementation
and executor intact. Authentication forgeries must fail both modes even beside
authentic out-of-bound values; raw parser failures and panics never earn
rejection credit. Measure normal and guard-inclusive peaks separately and stop
on an accepted forgery, binding mismatch, unexpected abort, cap failure or honest
negative result. No whole-verifier fit or solution to the transcript footprint
follows from M18's isolated round.

## Route to an end-to-end Nova SNARK verifier

1. Bind bounded proof decoding to the source graph: exact spans, lengths and
   EOF, network/k/key identity, canonical scalars and compressed points, and
   actual transcript message origins. Use the corrected native verifier from
   `feat/testnet4-recursive-chain` (`de607d3`) and the existing real NHT4/NHC1
   proofs as the differential baseline. No new proving is needed for this gate.
2. Extend the authenticated bit/point boundary into measured scalar action and
   MSM. Preserve the complete curve checks, scalar canonicality and real opening
   links. Compare implementations before repeating point steps at full width;
   a count projection is insufficient evidence that the source fits its limits.
3. Implement the complete IPA and Nova/Spartan algebra with authenticated
   proof/key/generator origins, every round's commitments and challenge uses,
   and independently tested adversarial folding and equation cases.
4. Compose the complete transcript and proof source, then compare actual Script
   outcomes with native verification on real valid and invalid proofs. This is
   the experimental end-to-end verification gate. Separately verified fragments
   and successful native verification cannot substitute for this composition.

Cost work must intervene wherever the unchanged limits fail. The roughly
70-GiB prefix-sharing transcript projection above prevents straightforward
replication of the present backend; more host RAM does not reduce that Script
footprint. It is not a measured complete verifier or a lower bound on future
designs. Production assertion/key-lifecycle binding and the Bitcoin transaction
graph remain separate later gates, with no deployment claim from these steps.

[The opt-in full BYTE permutation](BYTE-KECCAK-PERMUTATION.md) flattens six
fresh sealed blocks into one 29,245-leaf, 29,445-word GraphSpec. Its program
identity is explicitly a versioned manifest hash, while every small child
retains its actual Program digest. The factory preserves all 23 round states,
4,600 shared entries and 9,200 actual consumer coordinates, with a separate
source hash after the parent catalogue. The hosted run measured 151,432,516
Script bytes per full parent, passed 470,512 executions with 236,544 expected
rejections, and checked 73,600 actual opening links across eight cases. Its
complete component trees and 481/513-byte selected controls passed under the
existing 256-MiB Script and 512-MiB worker caps; the complete Python suite passed
407 tests. The kernel-only workflow retains its 180-second budget without
accidentally running full-graph tests. This remains a permutation on external
byte states. The separate rho composition above now shares the framed LO/HI
message bytes, anchors the fixed BYTEs and feeds actual digest producers into
the unchanged uniform reducer. Proof/message origins, full transcript and IPA
Script binding remain open.

[The opt-in four-round BYTE component](BYTE-KECCAK-BLOCK.md) composes four fresh
sealed child rounds under one actual Program and one authenticated registry.
It preserves the child predicate bodies and aliases, merges exactly three
ordered 200-byte states, and records each actual producer and both next-round
consumer occurrences. Its hosted run passed 318,248 Script executions with
162,274 expected rejections and 38,400 actual opening comparisons across 32
parents. The six aligned ranges measured 25,228,060-25,248,161 Script bytes per
parent in either scalar role. All 16 workflows and 391 Python tests passed.
The separate full-permutation boundary above flattens six sealed blocks into one
29,245-leaf GraphSpec, using an explicit manifest program identity because a
29,245-constraint Program is forbidden. Its five additional state joins and all
23 round boundaries now have full execution, memory and tree/disproof evidence
above. Independent four-round receipts are not that evidence.

[The opt-in byte Keccak round](BYTE-KECCAK-ROUND.md) uses natural terminal
outputs tied to actual SSA producers, a conversion-complete unchanged Boolean
baseline and a separate cached-signature consumer probe. This is a one-round
measurement boundary. The complete BYTE permutation now has its separate
evidence above; both framed hash branches remain to be composed.
Its hosted run passed 339,296 Script executions with 175,024 expected rejections
and 12,800 actual producer/consumer opening links. Four directly compared rounds
measured 6,304,498-6,314,561 source Script bytes versus 52,487,418-52,500,750 for
the conversion-complete Boolean BYTE-port baselines in either scalar role.
The 665,600-byte copy probe is accounted separately for each case. All 24 rounds
ran independently; no whole-permutation savings or cross-round binding is
claimed. The separate four-round component above now measures its own
authenticated joins and parent costs.

[The opt-in byte-kernel experiment](BYTE-KERNELS.md) adds internally derived
byte operations and a conversion-complete Boolean comparison before any byte
permutation is built. Existing Boolean/convolution compilers and graphs remain
the baselines. Authenticated measurements, rather than leaf-count projections,
determine the next footprint decision.
Its hosted run passed 3,232 WOTS vectors with 2,834 expected rejections, separate
exhaustive XOR/AND checks and explicit numeric-abort probes. Complete isolated
byte-port XOR/AND/NOT statements measured 5,610/5,594/3,336 Script bytes versus
95,018/94,954/63,476 for conversion-complete Boolean baselines in either scalar
role. These are kernel results, not full-permutation savings. The sealed
one-round experiment above now measures authenticated producer-linked outputs.

[The framed LO endpoint composition](KECCAK-ENDPOINT.md) adds a separate
thirteen-component experiment: one streamed permutation, its 256 LO output
links to the reduction tail, and 832 fixed framing/padding/capacity anchors at
the actual input. HI, eval_W canonicality/proof origins and prior-state
transcript validity remain open. No existing graph or resource limit changes.
Its hosted run passed 8,952 Script vectors, including 4,833 expected rejections,
with actual wrong-output and wrong-padding hierarchical disproofs. Each of the
three complete scenarios measured 231,715 leaves and 1,087,930,741 Script bytes;
the 1,205-leaf tail accounts for 4,723,663 bytes. This added source boundary is
not a footprint reduction. Two existing full Boolean permutations exceed both
the current component count and global Script budget. The next footprint
experiment is a separate byte-kernel backend with authenticated cost
measurements before binding HI.

[The claimed digest-bit reduction bridge](DIGEST-REDUCTION.md) connects two
256-bit LO/HI bit strings to the exact BYTE ports of a fresh unsigned 512-bit
reducer, using existing predicates and all original arithmetic guards. Its
373-leaf graph closes this encoding boundary. Authenticated Keccak provenance,
sponge framing and whole-transcript Script composition remain open.
Its dedicated hosted run passed 10,048 Script vectors, including 5,248 expected
rejections, ten mature field reductions and six complete coherent disproof
studies. Complete graph sizes were 3,321,743 Pallas-scalar and 3,313,620
Vesta-scalar Script bytes: 1,177,984 bytes above each unchanged child baseline.
The next bounded source link is one streamed permutation's 256 LO output bits;
HI and proof-derived message origins remain separate obligations.

[Actual proving under k-sized folds and aligned shards](ACTUAL-PROVING.md) now
has a separate optional Windows coordinator, using the unchanged transparent
header prover and mandatory cold verification/full-state joins. Its explicit
resource budget is independent of the retained low-RAM conformance profiles.
The actual k=10 run generated and cold-verified two 12,976-byte proofs spanning
genesis through height 40, with the full 17-scalar join checked. Peak export Job
commit was 2.23 GiB in the sequential baseline. The 16-GiB parallel validation
also cold-verified both proofs, completing in 242.21 seconds with maximum
individual export Job commit 2.21 GiB. The configured total budget admits two
six-GiB child jobs plus a separate two-GiB host reserve check. All 12 workflows
passed on `5aa6c05`; complete Script verification remains open.
The same 16-GiB budget has now also supported a real **k=20** run: two
13,288-byte proofs covering 80 headers, separate cold key reconstruction and
verification, and the full 17-scalar height-40 join. It completed in 544.76
seconds with maximum individual export Job commit 4.19 GiB. No default k,
child ceiling or existing fixture/key gate changed.

[The streamed full-permutation graph](KECCAK-PERMUTATION.md) extends the linked
Keccak pair to twelve bounded components with globally reused state signatures
and hierarchical offline Taproot membership. All ten workflows passed on source
commit `46448d9`; each full scenario measured 230,510 leaves and 1,083,207,078
Script bytes. Authenticated sponge endpoints and the complete verifier remain
unfinished.

[The separate unsigned 512-bit reduction graph](UNIFORM-REDUCTION.md) addresses
Nova's 258-bit quotient requirement while preserving the existing multiplication
path. Its hosted run passed 12 mature field reductions and 3,048 Script vectors,
including 1,622 expected rejections; the 245-leaf catalogues measured 2,143,759
Pallas-scalar and 2,135,636 Vesta-scalar Script bytes. Keccak/proof-byte input
origins remain unbound by this arithmetic adapter.

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
The Keccak Script work covers individual rounds and a measured linked pair.
The streamed 24-round graph and hierarchical membership now have dedicated
hosted checks; a complete authenticated sponge remains open.

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

[KECCAK-PAIR.md](KECCAK-PAIR.md) implements a sealed two-round Keccak catalogue,
freshly building its child programs and merging exactly 1,600 producer-output /
consumer-input slots. It preserves each child's injective word mapping and every
leaf's occurrence/alias partition, commits the complete source topology, and
retains both current Program and registry caps. Code commit
`f85621920ca8598d2397f4d516353eee5293b501` passed all nine workflows / 258 Python
tests. Two rounds 0/1 have 19,206 leaves / 20,806 global words and cost 90,256,702
actual authenticated disproof Script bytes. The native helper checked all 3,200
shared opening comparisons separately from 24 selected honest leaf executions;
five signed cases passed 116 Script vectors / 86 rejections, including a coherent
wrong-middle disproof and complete-tree membership. The native run used
133.105726144 seconds and 201,456 KiB peak RSS on the hosted runner.
This would close one internal boundary only. Twelve such pairs still leave
eleven inter-pair boundaries, absorption/padding/squeeze and the complete Nova
transcript framing to authenticate. Registry/key and Taproot commitment order
must remain acyclic; a resulting root cannot be its own input context.

Read-only full-permutation design gives 230,510 total leaves, 249,710 summed
pair-local words and 232,110 unique global words after the 17,600 inter-pair
joins. Keep twelve bounded registries, not one oversized flat registry. A global
topology/key catalogue must enforce injective local maps, exact adjacent
intersections, disjoint nonadjacent maps, global key uniqueness and a single
fixture signature/value per global word. Production signer equivocation is
still open; fixture reuse alone does not supply assertion authority.

A hierarchical Taproot constructor can combine twelve raw pair Merkle roots
using mature `NodeInfo` APIs, retaining only the selected Script/path. It needs
a separate combined-depth verifier; the existing local verifier must remain
strict. Calculated global controls are 577..641 bytes. From the measured pair
and source gate counts, all 24 rounds project to `1,083,080,424 + 38*L_NOT`
Script bytes, at most 1,083,269,474 using the measured largest leaf as a bound,
assuming unchanged compiler/key encodings. This is an unexecuted projection,
not a full-24 measurement or runtime estimate. Any future orchestration needs
an explicit global streaming budget while preserving per-pair caps, and must
measure key/signature work, compilation and selected execution separately.

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


The earlier unchanged-kernel linkage design used `bits(width=8)` to reconstruct one
BASE-bound auxiliary word from eight MSB-first Boolean ports, followed by
`conv_reconstruct((8,))` to equate it to a BYTE-bound word. Connecting two
256-bit digests to the uniform input therefore needs 128 leaves and 64 auxiliary
words. Keccak bits are lane-major/LSB-first, so each byte's bit list must be
reversed for the existing `bits` predicate. Global bit, byte and auxiliary IDs
retain their distinct declared bounds and actual shared opening checks in the
implemented digest-reduction bridge. The byte kernels and isolated BYTE round
measurements above now evaluate a separate backend. Their isolated savings do
not establish a composed full-permutation footprint.
