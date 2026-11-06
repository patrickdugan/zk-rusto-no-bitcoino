# Retained scalar-source relation

This separate thirteen-component experiment adds an asserted 112-byte scalar
block and a canonical `eval_W` encoder to the completed
[challenge-bit/conditional-point relation](BYTE-C-BIT-POINT.md). Hosted execution
passed on source `3c55e4c31748661b8c157fd14406186490653cd1`, with all twenty-one
workflows green. The eleven-component baseline and its measured costs remain
unchanged. This is a local source relation, not a complete Nova SNARK or BitVM2
verifier.

## Reference and assertion boundary

The reference is the existing real testnet4/k=5 fixture
`fixtures/nht4-genesis-0-2020-k5.nht4`, from corrected header revision
`de607d3db17d400dd6c2923d357f1d4a7bf233c7`, Nova 0.76.0. Its bundle is
13,220 bytes and SHA-256
`c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9`.
The 556-byte header precedes a 12,664-byte compressed proof, SHA-256
`2137c6e8621cedb7423e0ef7f9ff7c27b2c6fdf3ceb227e644b3d9660d056617`.
Its key identity is
`1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24`.
No setup or new proving is needed.

The Python source admits this exact reference with the existing strict bounded
proof codec. A separate native helper independently checks header/network/k/key
identity, fixed dimensions, every length before its bounded loop, canonical
scalars, mature Halo2 compressed-point round trips, and exact EOF. Its grammar
contains 119 length prefixes, 288 scalars and 78 compressed commitments. This
is native structural admission; the helper does not call proof verification.
The corrected header CLI is the historical native proof baseline, but its raw
`bincode::deserialize` entry point alone is not strict arbitrary-input/EOF
admission. The separate `nova-oracle` wrapper supplies that stricter boundary.

For each curve role, a fresh decoded layout selects one contiguous block:

| Role | Proof-relative range | Container-relative range |
| --- | --- | --- |
| Pallas scalar | [4624, 4736) | [5180, 5292) |
| Vesta scalar | [10048, 10160) | [10604, 10716) |

The block contains `eval_W` (32 bytes), little-endian u64 batch-row count
(19 or 14), little-endian u64 first-row coefficient count (2), and canonical
`c0,c2` encodings (32 bytes each). These are the first batch-sumcheck quadratic
row's compressed coefficients. They are not an outer/inner sumcheck row or the
omitted linear coefficient. The factory derives spans from fresh admission;
caller offsets, receipts and imported source maps have no authority.

The WOTS assertion block is supplied separately. It can differ coherently from
the native reference. A reference hash in source metadata does not authenticate
the asserted byte values. The new Tape checks its sixteen selected length-prefix
bytes and authenticates the remaining 96 BYTE ports. These dynamic ports are
`word_valid` leaves, not hardcoded proof-value constants or SSA producers.
Whole-container decoding, proof SHA-256, length and EOF checks in Script remain
unimplemented. A coherent canonical change must pass this local relation.

## Source and opening census

| Source | Local words | Leaves |
| --- | ---: | ---: |
| Unchanged eleven-component relation | 156,163 | 153,213 |
| Asserted scalar block | 112 | 112 |
| Canonical eval_W encoder | 55 | 17 |
| Thirteen-component relation | 156,330 | 153,342 |

The source declares 155,146 unique global words and 1,184 declaration reuses.
The encoder preserves all 256 input bits in its unsigned diagnostic path and
projects sixteen unchanged reconstruction predicates plus one canonical guard
from the checked convolution encoding. It cannot silently reduce noncanonical
inputs modulo the field. The block's 32 eval bytes share the original rho
message identities; its 64 coefficient bytes share the original frame identities.

The new relation adds 352 direct opening comparisons per main profile: 160 eval
BYTE comparisons and 192 coefficient BYTE comparisons. The old 128
frame-to-prefix comparisons remain present. Twenty-three additional encoder
comparisons connect actual split/reconstruction/field-validity occurrences.
All comparisons capture real registry openings after complete source and
registry validation. Six main profiles therefore add 2,250 comparisons to the
baseline's 289,266, giving 291,516 main comparisons. Private encoder probes add
322 separately reported comparisons. The successful run captures and compares
all these actual registry openings; the counters are not metadata-only links.

## Closed execution corpus

The six main profiles are `p/h,p/c,p/w,v/h,v/c,v/w`: honest, coherent changed
coefficient, and coherent changed eval_W. Their claimed scalar inputs and every
downstream consumer are re-witnessed consistently; every local predicate is
true in the successful run. Both honest profiles execute all 153,342 leaves. Each coherent profile
executes all 956 small-component leaves and 107 selected point leaves; five full
permutations have no normal calls in those targeted profiles. Full catalogue
measurement and authenticated guard-layout coverage remain mandatory. Only the
two honest profiles may claim full-statement execution. Every main profile
selects the actual encoder canonicality leaf (component 12, leaf 16) for its
live hierarchical correctness/disproof pair.

The private corpus preserves all 52 previous frame/absorb, scalar-alias and point
probes. It adds fourteen complete 17-leaf eval_W probes and eight selected
single-leaf Tape probes. Encoder probes cover modulus, modulus plus one, exact
bit 255, isolated BYTE/limb/split faults, and an authenticated `u32::MAX` BYTE.
Tape probes cover low/high count corruption and an authenticated BYTE value 256.
Their values are reconstructed independently from the admitted reference before
signing. A diagnostic unsigned integer is never truncated through a u8 cast.

Empty, truncated, prepended, appended, forged and cross-wired witness guards stay
mandatory. An upstream panic, process failure or bare unexpected VERIFY abort
cannot count as a successful rejection. Existing point diagnostic abort domains
remain separately classified. Private registries use separate probe seed domains
and check their keys against the corresponding complete honest main pool. No
production assertion-root/key-lifecycle binding is claimed.

## Resource and evidence gates

The unchanged compact-record hard limit is 134,217,728 bytes. Independent closed
serialization accounting bounds this corpus at 133,969,276 bytes, leaving
248,452 bytes between the closed bound and hard limit. The measured stream is
128,420,666 bytes, below both limits. The native worker and report validator enforce
the exact corpus and identifier lengths; the upper bound authorizes no extra
Script calls or limit increase.

The dedicated workflow uses the existing 256-MiB Python-test and 512-MiB parent
execution address-space limits, bounded wall/CPU time, two build threads, and
unchanged Script/stack/input/map/tree/forest policies. Large graph generation,
native builds, signing and Script execution run in hosted CI. Local validation
is restricted to bounded parser/math tests, syntax, formatting and body hashing.
No local proving or GPU work is required. New evidence artifacts contain only
JSON/text reports and lockfiles, with no additional proof binary upload.

Publication requires strict transport admission before keys/output, independent
source and assignment reconstruction, complete cost/forest-stream agreement,
actual opening comparisons, exact expected execution/rejection totals, unchanged
witness guards, bounded pre/post source/binary snapshots, and independent report
review. These gates pass for the hosted run below. The generated lockfiles and
source/binary observations are evidence for that run, not a fully fixed release
build or a binary/source-equivalence attestation.

## Measured hosted result

[Run 42307107515](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42307107515)
and [job 128199100341](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42307107515/job/128199100341)
pass on source `3c55e4c31748661b8c157fd14406186490653cd1`. Complete measurements
and live tree streams agree for all six main profiles. All eleven old component
costs match the prior measured baseline exactly, under the same accounting.

These are complete WOTS-adapted disproof Script bytes. They exclude witnesses/
assertion signatures, control blocks and transaction framing.

| Complete source or added component | Pallas role | Vesta role |
| --- | ---: | ---: |
| Unchanged eleven-component baseline | 851,477,668 | 851,563,810 |
| Asserted scalar block | 187,889 | 187,888 |
| Canonical eval_W encoder | 140,132 | 140,132 |
| Thirteen-component source | **851,805,689** | **851,891,830** |
| Added coverage versus baseline | 328,021 | 328,020 |

The one-byte Tape difference comes from the different fixed row-count constants.
This experiment adds coverage and cost. It establishes no multiplication or
whole-verifier savings ratio.

The job passes **687,412 actual Script calls**, including **372,924 expected
rejections**. Calls comprise 621,872 main normal, 6,944 private normal, 58,436
malformed-authentication guards, and 160 selected-tree calls. Every normal/tree
correctness-disproof pair has one expected rejection; every malformed guard must
reject. Panics, process failures and unexpected VERIFY aborts never count as
successful rejection evidence.

Both honest profiles execute all 153,342 leaves. Each coherent profile executes
1,063 leaves: all 956 small-component leaves and 107 selected point leaves.
All six have 379 authenticated layouts and 5,306 guard calls. Coherent canonical
coefficient/eval substitutions pass, demonstrating the explicit claimed/reference
separation rather than whole-proof origin authentication. Their selected
canonicality leaf is also true; only the two honest cases claim full-statement
execution. All six selected hierarchical controls are 257 bytes, for component
12, leaf 16. Comparing these controls to a different baseline selected point leaf
would not establish a control-size optimization.

The preserved 52 private probes retain their prior execution/guard scopes. The
fourteen encoder probes execute all 238 leaves and 3,332 guard calls in total.
The eight Tape probes execute eight selected leaves and 112 guard calls. Full
catalogues and local trees are measured even for selected-only probes. Each
private registry checks key disjointness against the complete corresponding
honest main pool and uses a separate probe seed domain.

Main pools create 930,876 signature entries for 937,980 declarations, reusing
7,104. Private pools create 230,302 entries. Actual main opening comparisons total
291,516; private encoder comparisons add 322 separately. All expected source/map/
cache/registry rejections pass, along with empty, truncated, prepended, appended,
forged and cross-wired witness guards. Nine independent mutations of the completed
report's nested reference summary reject, including false verification claims,
changed sizes/offsets/roles, missing/extra fields and Boolean/integer aliases.

The maximum Script is 79,381 bytes. Observed maxima remain 485 stack
items, 481 witness items and 9,600 witness payload bytes, including negative guards.
The compact stream is 128,420,666 bytes, SHA-256
`250ec3cf8bb7a50474c5c6c2513ab3f7c9141b4cfd4ffadba68613cabb6a2f11`.
Existing Script, stack, input, map, tree, record and time limits pass unchanged.

Native wall time is 658.275418474 seconds; the parent plus generation takes
1,025.788528847 seconds. Parent-reported peak RSS is 138,928,128 bytes. External
GNU time observes 392,768 KiB (402,194,432 bytes) for its invocation scope. This
is distinct from parent RSS, is not a standalone native-worker RSS measurement,
and must not be summed with it. Different hosted timings do not establish a
runtime improvement over the baseline.

The dedicated job passes all ten Python tests in 100.421 seconds and 77 worker
unit tests, plus nine registry and five forest tests. The broad M2 job passes
459 of 468 collected tests, with nine explicit hosted opt-in skips, in 749.544
seconds. The four new skips run in the dedicated job; the older opt-in scopes
have their own jobs. Original independent checks still pass: 74 curve vectors,
10,884 M2 Script vectors with 1,630 rejections, and 19,216 compact vectors with
9,958 rejections. All twenty-one workflows pass on the source above. Local work
is restricted to six lightweight tests/four hosted skips, syntax/format/body
checks, and bounded report/hash audits. No local full graphs, native builds,
key generation, Script execution or proving ran.

Two earlier attempts failed and supply no completed conformance/cost result.
The first stopped at two imports referring to the new transport instead of the
frozen legacy point DTOs/helper. The second passed native tests but failed strict
report assembly because old point hashes collided with outer source hash names.
The successful source separates those labels and includes a regression through
the actual identity helper; strict duplicate rejection remains enabled.

### Evidence pins

[Artifact 13548227064](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42307107515/artifacts/13548227064)
is a 246,147-byte ZIP, SHA-256
`209341b7314428549bb3782d2ede817732c2efcbebf2d8e6f6a1951a93976835`.
Its 370,145-byte report has SHA-256
`e0e08c9480bf9b8d0a416110d96692009f4259a1ee31e08ae5581896a0ac659e`;
the 447,229-byte manifest has SHA-256
`dfb719227afbe4638d92808126009803c0841eb002b4875bbe4f22f83fe7ecbd`.
Parsed compact report, artifact stdout and direct job stdout agree. The native
worker pins that exact raw manifest before parsing it.

Pre/post source snapshots agree: 141 files, 3,898,760 bytes, list SHA-256
`4421f1ca360c4d6b0bc0fa7d6e8f7aa71848347b7c4a6a7f132421b8ed707247`.
All 138 non-lock entries match exact source Git blobs; all three generated locks
match artifact bytes and the pinned BitVM revision. Both curve-worker locks pin
Halo2curves 0.9.0. The 6,072,672-byte configured executable has SHA-256
`0ea68e12f5fb3c895dc93b4781b9dfa26a7f13f049ce996d23fa670df970c813`.
These are observed source/binary pins, not binary/source-equivalence attestation.

## Remaining verifier work

The completed baseline measures 851,477,668 Pallas / 851,563,810 Vesta Script
bytes, excluding witnesses/assertion signatures, control blocks and transaction
framing. This extension adds coverage and cost; it is not a multiplication or
whole-verifier size reduction result.

Whole-proof authentication and canonical decoding in Script, compressed-point
origins, prior transcript state, generator/key and point origins remain open.
`A` and `P` remain external test ports. Full-width scalar action/MSM, the complete
IPA, every Nova/Spartan equation and transcript round, production WOTS assertion
binding and the Bitcoin transaction graph still require separate implementations
and adversarial differential execution on real proofs.

The roughly 70-GiB prefix-sharing transcript projection in [NEXT.md](NEXT.md)
remains an unresolved design constraint. More host RAM does not reduce Script
footprint. No complete-verifier or Bitcoin deployment claim follows from this
milestone.
