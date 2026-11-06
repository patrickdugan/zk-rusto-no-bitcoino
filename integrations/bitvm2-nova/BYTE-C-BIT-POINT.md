# Challenge bit and conditional point relation

This bounded extension links the actual next sumcheck challenge from
[the nine-component rho/c chain](BYTE-RHO-CHAIN.md) to one conditional point
relation, `E=A+P; R=A if b=0 else E`. It retains the existing chain as the
baseline and adds separate scalar-bit and point components. Hosted execution
passed on source `9ebd0cfc451801a15cf37c72e63c86aa6600d390`, with all twenty
workflows green. The source census and complete compiled costs below are now
checked by that run. This remains a bounded relation, not a complete verifier.

## Exact source boundary

The scalar bridge consumes the nine actual Uniform result limbs, using the
same global identities, bounds, signatures and actual opening coordinates.
Nine unchanged `bits` predicates reconstruct all 255 output bits with widths
`29,29,29,29,29,29,29,29,23`. The input limbs retain their full radix-2^29
bounds, so unused high bits cannot disappear during a byte conversion. The
bridge declares no independent canonical field: the original upstream Uniform
`field_valid` leaf 244 remains mandatory. Public bit indices are little endian;
formal `bits` operands are most significant first within each limb.

The verifier fixes the selected index 0-254 in the fresh source identity. Only
that bound-2 bit crosses from scalar role to the corresponding curve base
role: `pallas_scalar -> pallas_base`, `vesta_scalar -> vesta_base`. Equal Pasta
moduli across the curve cycle never determine this semantic mapping. The
selected bit has five actual point predicate occurrences.

The point component includes the complete unchanged convolution addition
`E=A+P`, even when `b=0`. It appends three Boolean infinity-selection predicates,
four gated coordinate comparisons, one infinity-form predicate, and two
canonical result-coordinate guards. The original 6,116 arithmetic predicates,
35 canonical fields, aliases and body bytes are explicitly projected. Its
original canonical guards move after the eight new arithmetic predicates.
Result coordinates are authenticated asserted ports, not new SSA producers.

| Source | Local words | Leaves |
| --- | ---: | ---: |
| Unchanged rho/c chain | 148,401 | 147,043 |
| Scalar bits | 264 | 9 |
| Complete addition and selector | 7,498 | 6,161 |
| Eleven-component source | 156,163 | 153,213 |

Exactly nine upstream limbs and one selected bit are additionally shared. The
fresh fixed-count key profile therefore has 155,107 unique global words and
1,056 declaration reuses. The old nine-component profile and all old helpers
remain unchanged. New native code is isolated in `point-oracle`, reusing the
existing Script library and pinning Halo2curves 0.9.0 for the independent curve
oracle. Native group-decoding rejection is distinct from actual Script disproof.
The new native checker also requires a static body-hash table from the unchanged
verifier-owned predicate compiler, keyed by base role, public arguments and
formal alias partition. This pins the baseline compiler outputs; it does not
claim an independent reimplementation of that compiler. A first-observed body
hash or a caller-supplied catalogue is insufficient for this check.

## Closed adversarial corpus

Both retained transcript roles have three main profiles: honest, coherent
changed selected bit, and coherent `c+p, q-1` scalar alias. Two honest profiles
execute all leaves. Four coherent profiles use explicitly reported targeted
execution, while their full sources, assignments, measurements, key pools and
trees still require validation.

The scalar alias is a deliberate canonicality attack. It retains
`X = (c+p) + p*(q-1)` and, for these retained inputs, stays below 2^255 while
flipping bit zero. All byte decompositions, quotient products, carries, bits
and the selected point are re-witnessed. All integer and bit predicates can
remain true; the authenticated original canonical guard must reject. The
closed constructor accepts neither an imported graph/assignment nor an
arbitrary alternative. A separate 634-word/254-leaf private probe merges fresh
Uniform and bit children; its sole canonical guard moves from 244 to 253.

Private probes are separately keyed and measured: the existing twenty
frame/absorb cases, twelve point-edge cases, two scalar-alias cases, and
eighteen selected point negatives. The twelve Script edge probes use bits
`0,1,0,1,0,1` on each curve's six point pairs. A tiny independent Jacobian
oracle covers both bits on all pairs, 24 cases; that is not a claim that all
24 have full Script execution. Selected negatives cover invalid unused `P`,
wrong `E`, wrong selected result/flag, nonzero infinity coordinates, an
auxiliary flip, signed invalid bit 2, and coordinate encodings `p,p+1`.

Raw native predicates classify ordinary true/false values separately from
numeric-domain aborts. Every executed ordinary leaf must have a defined
verdict. Noncanonical coordinate tests select actual field-validity disproofs;
an unselected arithmetic abort or a native point decoder error cannot count
as a successful Script rejection. The signed bit-2 fixture uses only its
explicit private invalid-message profile. No private key/signature becomes
authority for the main forest.

## Verification and stop conditions

The dedicated hosted job must pass fresh source/map/program/catalogue binding,
canonicality, field-role identity, opening joins, complete catalogue and tree
cost accounting, independent Halo2 group checks and actual WOTS Script tests.
It retains empty, truncated, prepended and appended witness regressions, exact
witness-length guards, forged openings and cross-wire negatives. Interpreter
panics, process failures and unexpected aborts fail the job.

All existing limits remain: 100,000-byte leaf Script, 1,000 stack/witness items,
520-byte elements, 256-MiB component Script, 1.25-GiB global Script, sixteen
components, depth nineteen, 8-MiB maps and 128-MiB compact records. Python
conformance uses 256 MiB/480 seconds; native execution uses 512 MiB with the
existing CPU and wall limits. New guard/tree string identifiers have a stricter
32-byte bound; old 64-byte identifiers are unchanged. The closed record upper
bound is 132,472,024 bytes, below 134,217,728. Actual bytes must also be measured.
Any failed bound must be corrected or documented, never raised to force a pass.

No local full graphs, native builds, key generation, Script execution or
proving are required for this milestone. Existing local transparent proofs
remain available; no proof binaries are published by this change.

## Measured hosted result

[Run 42288688921](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42288688921)
and [job 128136122494](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42288688921/job/128136122494)
passed on source `9ebd0cfc451801a15cf37c72e63c86aa6600d390`. These are complete
WOTS-adapted disproof Script bytes under the same accounting as the prior
nine-component chain. They exclude witness/assertion signatures, control blocks
and transaction framing.

| Complete source or component | Pallas role | Vesta role |
| --- | ---: | ---: |
| Prior nine-component rho/c chain | 762,253,538 | 762,237,292 |
| Scalar-bit bridge | 435,945 | 435,945 |
| Complete point addition plus selector | 88,788,185 | 88,890,573 |
| Eleven-component source | **851,477,668** | **851,563,810** |
| Added coverage versus prior chain | 89,224,130 | 89,326,518 |

The unchanged complete-add baseline costs 88,586,200/88,688,588 bytes. The
selector and two additional canonical guards add exactly 201,985 bytes in
either base role. All three profiles per role have the same complete measured
catalogue cost, and live tree streams match those measurements. This extension
adds coverage and cost; it establishes no whole-verifier savings ratio.
The roots are constructed from these streams; independent production assertion
root binding remains unimplemented.

The run passed **680,120 actual Script calls**, including **366,674 expected
rejections**. The accounting is 620,324 main normal calls, 6,452 private normal
calls, 53,228 malformed-authentication guards, and 116 live selected-tree calls.
Every normal/selected-tree correctness-disproof pair has one expected rejection;
every malformed-authentication guard must reject. No interpreter panic or process
failure counts as rejection evidence.

Both honest main cases execute all 153,213 leaves. Each of four coherent main
cases executes all 827 small-component leaves and 107 selected point leaves,
934 total; unchanged full permutations have no normal calls in those targeted
profiles, while all their 23 authenticated layouts still receive guard tests.
Every main profile has 358 layouts and 5,012 guard calls. The canonical scalar
alias has only upstream field-validity leaf 244 false; the coherent selected-bit
fault has only bit-reconstruction leaf 0 false. Their selected global disproof
controls are 353 and 257 bytes; honest selected controls are 513 bytes.

The twelve point-edge probes each execute 107 selected leaves and guard all
100 authenticated point layouts. The eighteen point-negative probes execute
30 selected leaves in total and guard only their selected layouts; their full
false/abort lists are classified independently, without claiming all false
leaves were executed. Both scalar-alias probes execute all 254 leaves, with
only field-validity leaf 253 false. All twenty old frame/absorb probes remain
fully executed. All 52 private catalogues and local trees are measured in full.

The six main pools create 930,642 signatures for 936,978 local declarations,
reusing 6,336; the 228,636 private signatures have separately checked keys.
Actual opening comparisons total 289,266: 12,852 prior cross-component,
276 prior canonical, 276,000 internal producer/consumer, and 138 new joins
(54 scalar reconstruction, 54 canonical, 30 selected-bit). All source, map,
program, field-role, registry and witness guards pass, including empty,
truncated, prepended, appended, forged and cross-wired witnesses.

The largest Script is 79,381 bytes. Observed maxima are 485 stack items,
481 witness items and 9,600 witness payload bytes, including negative guards.
The compact execution stream is 127,050,830 bytes, below both its 132,472,024-byte
closed upper bound and the unchanged 134,217,728-byte hard limit. Its SHA-256 is
`55843e592ca0d7388a1598ca36b1d3c617515e2313e1c4f6be305bc068d6f523`.

Native wall time is 699.472629802 seconds; the parent plus fixture generation
takes 1,064.042608931 seconds. The parent-reported peak is 132,771,840 bytes.
External GNU time reports a 390,768-KiB maximum (400,146,432 bytes) for its
observation scope. This is separate from the parent measurement, is not a
standalone native RSS measurement, and must not be summed with it. All existing
memory, time, Script, tree, input, map and record caps pass unchanged.

The dedicated Python job passes all twenty tests in 121.068 seconds under
256 MiB. Native tests pass 61 worker tests plus nine registry and five forest
tests. The broad M2 suite passes 453 of 458 collected tests with five explicit
opt-in skips; the four new skips run in this dedicated job and the prior chain
skip runs in its own job. The original 74 independent curve vectors, 10,884
M2 Script vectors and 19,216 compact vectors also pass. Local validation is
limited to sixteen lightweight tests with four hosted skips, syntax/format and
bounded compiler-body hashing; no local full graphs, native builds or proving ran.

The first hosted attempt compiled but failed a strict native decoder unit:
Halo2 `from_xy(0,0)` returns its identity sentinel even under the finite flag.
The adapter now explicitly rejects a decoded identity on that path; the
explicit infinity path and every negative assertion remain unchanged. The
successful run above includes that correction. The failed assertion stopped
the earlier job before conformance execution; it was never rejection evidence.

### Reproducible evidence

[Artifact 13540301962](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42288688921/artifacts/13540301962)
is a 182,179-byte ZIP, SHA-256
`6be8342980730a217906266b18d352e462ced67da3f5bfbc169d4a9fd2725b85`.
Its report is 287,673 bytes, SHA-256
`6d6508e972ae80798f1faf5147c2d3c0974c8e4efa203e60b8792952808f608d`;
the manifest is 400,313 bytes, SHA-256
`9f1ee062fca9addd72ddf13dacf21c1816c7b83bf149b89bddf09007b9c0fe6f`.
The parsed artifact report, artifact stdout and direct job stdout agree; native
execution pins that exact raw manifest. The bounded pre/post source and binary
snapshots agree. Their source-list SHA-256 is
`64bcfe09ce7833d123bd2f3fdde28b6124caef04ce8d7108555c348ca8c78a8c`;
the 5,560,768-byte worker SHA-256 is
`3b572c40ffb15192f5fd186b0be1fd3b0f538f0db3af2d3f78bce14a492846c4`.
These are observed snapshots, not a binary/source-equivalence attestation.

## Remaining verifier work

This source relation does not implement scalar multiplication, MSM, full IPA,
the surrounding sumcheck equation, a complete Nova/Spartan transcript, proof
byte/span/length/EOF admission, NHT4 Script decoding, compressed-point origins,
generator/key origins, production assertion binding or a Bitcoin transaction
graph. `A` and `P` are external ports. Those gaps prevent any complete verifier
or deployment claim.

The full-transcript size projection in [NEXT.md](NEXT.md) remains a design
constraint. This measured boundary establishes additional coverage; it does not
establish full-verifier savings or Bitcoin practicality.
