# Streamed full Keccak permutation graph

This optional research integration extends the measured [two-round graph](KECCAK-PAIR.md)
to all 24 Keccak-f1600 rounds. It is a graph construction, reference conformance
and offline membership milestone. It does not accept a hash, transcript, Nova
proof or Bitcoin transaction. Production assertion binding remains open.

## Construction and resource boundary

`keccak_permutation.py` freshly constructs twelve sealed pair descriptors, then
regenerates one pair at a time for binding. Canonical `state/{round}/l{lane}/b{bit}`
identifiers give each adjacent output/input exactly the same 1,600 ordered state
words. Internal identifiers contain the actual round. Nonadjacent pairs have
disjoint domains. The topology has 230,510 leaves, 249,710 pair-local words,
17,600 inter-pair repetitions and 232,110 unique global words. No oversized flat
Program or Registry is created; existing per-pair caps remain unchanged.

The topology digest commits an ordered, versioned manifest with external
context, role, operation, catalogue/program identities and complete global-ID
map hashes. It is a distinct identity from a Program digest. Values, keys and
Taproot roots are derived later, avoiding a circular commitment. Descriptors
and JSON receipts cannot construct a trusted plan. Iterator callers must release
all large aliases before requesting the next pair.

Full topology construction, bindings and native work reject execution before
allocation unless running in hosted GitHub Linux. Local tests use tiny symbolic
maps and transport fixtures only. There are no local proving or Rust build jobs.

## WOTS and hierarchical membership

The separately compiled `keccak_full` worker authenticates the manifest's raw
SHA-256 from a separate command-line argument before parsing. Each capped case
is hashed and parsed from the same snapshot; identities, shape and canonical
state transport are checked. Files are confined to the owned case directory.
The configured executable runs directly; no external result receipt is accepted.

Each scenario creates one TEST-ONLY WOTS key/signature per global word, with a
domain-separated seed binding topology, scenario and global ID. The worker
caches exactly the outgoing 1,600 openings for the next pair. It reuses their
key, value and signature bytes, rejecting conflicting values rather than signing
again. All 38,400 internal and 35,200 inter-pair consumer opening links are
checked. First-use key/signature stream digests and uniqueness checks cover the
entire session and separate the honest and malicious scenarios.

Every actual disproof Script leaf is compiled and included in its local Taproot
tree. `TaprootForest` accepts live typed commitments and combines their **raw
Merkle roots**, retaining the selected genuine subtree and hiding the others.
It independently checks the roots-only construction, ordered component manifest,
NUMS output key, exact selected Script, component and ordinal. The unchanged
local cap is 256 MiB compiled Script bytes per tree; the separate global cap is
1.25 GiB per scenario, at most 16 components and depth 19. The twelve-component
schedule gives combined control blocks of 577–641 bytes. These are offline
commitments; the roots are not independently pinned to a production assertion.

## Verification and accounting

The dedicated hosted workflow runs full topology tests and small native forest
and admission unit tests. It then directly executes two streamed scenarios:
an honest padded empty-input reference and a coherent incorrect state after
round 1. The latter changes one bit, feeds that same state to every later pair
and exposes exactly pair 0's final producer leaf 17,606. Both selected
correctness/disproof outcomes and complete hierarchical membership are checked.
All Boolean predicates are checked in the native reference; representative
authenticated Script shapes and selected boundary samples execute in the Script
engine. Every leaf is compiled and measured, but every leaf is not executed.

Empty, truncated, prepended and appended witnesses, forged digits and cross-wire
signatures reject in both modes for all four Boolean/constant kinds. Thirteen
forest mutation categories per scenario cover Script, branch, parity, internal
key, leaf version, control length, external identities and component order.
Interpreter panics terminate the job and never count as successful rejection.

Script sizes use the earlier identical accounting: serialized disproof Script
bytes only, excluding transaction framing, control blocks and assertion
signatures. Before hosted execution, the source-only upper projection is
1,083,269,474 bytes per scenario, derived from the measured default pair catalogue,
repeated and adjusted for source round-constant differences. This projection is **not a measured full-run
result**. Actual costs and timings must come from the current-head hosted report.
The native worker is limited to 512 MiB address space, 1,200 CPU seconds and
1,260 wall seconds; the parent orchestration is bounded separately. Bulk case
files and key/signature payloads are excluded from artifacts.

## Current-head hosted measurements

All ten workflows passed on source commit
[`46448d9637f9b4c6d43995ece0f58d3416036adf`](https://github.com/patrickdugan/zk-rusto-no-bitcoino/commit/46448d9637f9b4c6d43995ece0f58d3416036adf).
The [full run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42167659949)
passed all thirteen dedicated Python tests, five forest unit groups and three
native admission unit tests. The complete Python suite passed all 271 tests.

The native worker measured these Pallas-scalar catalogues from every actual
compiled disproof leaf, using the same Script-only accounting as the pair:

| Scope | Leaves | Unique signed words | Disproof Script bytes |
| --- | ---: | ---: | ---: |
| Earlier default two-round baseline | 19,206 | 20,806 | 90,256,702 |
| Full 24 rounds, honest scenario | 230,510 | 232,110 | 1,083,207,078 |
| Full 24 rounds, coherent wrong state 2 | 230,510 | 232,110 | 1,083,207,078 |

The full run's pair 0 exactly reproduces the baseline byte count. Each additional
round-constant NOT leaf contributes 3,333 measured bytes, so
`12*90,256,702 + 38*3,333 = 1,083,207,078`. The earlier upper projection used
the largest Boolean leaf size, 4,975 bytes, and exceeds measurement by 62,396
bytes. This is a more precise measurement, not a further footprint optimization.
The aggregate footprint remains approximately 1.083 GB per scenario.

Across both scenarios the worker created 464,220 signatures, reused 35,200
cached signatures, checked 147,200 boundary-opening links and evaluated all
461,020 Boolean predicates. There were 336 selected leaf checks, 784 emitted
Script vectors and 448 expected rejections; four additional selected
correctness/disproof executions ran outside that vector counter. All 26 forest
mutation checks rejected. The malicious graph had exactly one false predicate,
pair 0 leaf 17,606, whose actual disproof executed successfully with a verified
609-byte global control block. The honest selected disproof failed as expected.
Largest Script was 4,975 bytes, maximum stack 35 items and witness payload 600
bytes. Maximum witness length 31 includes a deliberately malformed length case.

Swapping components 0 and 1 preserved the sorted Taproot root in both scenarios.
The ordered external component manifest still rejected that substitution. This
demonstrates why the manifest/selection checks cannot be replaced by root
equality alone.

Direct native execution took 844.077056162 seconds; generation plus orchestration
took 884.57880344 seconds. Parent peak RSS was 83,886,080 bytes. External
`/usr/bin/time` reported maximum RSS 262,952 KiB (269,262,848 bytes), the maximum
reported process footprint rather than a simultaneous parent-plus-child sum.
No resource ceiling was raised, and no full graph or native work ran locally.

The small hosted evidence artifact contains reports, manifest, timings and
dependency lock/tree, excluding raw case files and all key/signature payloads.
Its reproducibility identifiers are:

| Identity | SHA-256 |
| --- | --- |
| Sealed topology | `45fd7c512a793855a32bda32df89baf5559eaecf95e95967797bceceb2b27da1` |
| Exact run manifest bytes | `9e3d2356617752562b934d7b9f3fac6d848b36d5de39abacf1937660fd8db009` |
| 8,036,760 hashed selected-vector bytes | `e958addefe1529d901baa9054cb396e886e6ef0215e9bd9df2ed7855faeb0dc7` |

These identify offline conformance evidence; they are not proof acceptance or
production assertion anchors.


## Optimized hosted worker

Commit [`d7cf40214807164a83c02fb896801a492d8c2261`](https://github.com/patrickdugan/zk-rusto-no-bitcoino/commit/d7cf40214807164a83c02fb896801a492d8c2261)
builds the hosted worker and its unit tests with Rust's optimized release profile.
The [corresponding run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42172734434)
passed all 13 topology tests, five forest groups and three worker groups, followed
by both complete native scenarios. The 512 MiB, CPU and wall limits are unchanged.

Native time was 61.199725139 seconds versus 844.077056162 in the earlier debug
run, an observed ratio of about 13.8 for these hosted runs. Generation plus
orchestration took 84.454053712 seconds. Runner timing varies; this is not a
controlled hardware benchmark. Parent peak RSS was 84,013,056 bytes and external
maximum process RSS was 261,572 KiB (267,849,728 bytes).

An exact comparison with the debug baseline matched topology and run-manifest
identities; both key/signature catalogues; every component's catalogue, registry,
compiled-stream hash, root and output key; both global roots/output keys and
control hashes; and the complete selected-vector digest and execution metrics.
The measured 1,083,207,078 Script bytes per scenario are unchanged. This improves
hosted execution time and does not change verifier semantics or Script footprint.

## Remaining verifier work

An independently checked empty-input Keccak known answer validates the reference
construction only. Padding, sponge absorption, squeeze/reduction, proof-byte
origins and Nova transcript messages are not bound by this permutation graph.
The selected reference cases do not establish a complete permutation acceptance
API. All full-hash, transcript-in-Script, proof, production assertion and
transaction flags remain false.

Reusing a WOTS key cannot prevent a malicious secret holder from signing two
different messages. Production assertion/signature/key lifecycle enforcement,
authenticated transcript endpoints, the full Nova/Spartan/IPA Script verifier
and the Bitcoin transaction graph remain necessary. No trusted setup or final
compression scheme is introduced by this milestone.

The next bounded source target is the retained primary Keccak stream's event
103, squeeze label `r`: each branch hashes a 111-byte message and needs one
permutation. Its layout is `w || eval_W_LE32 || NoDS || counter_LE64(59) ||
previous_state_64 || r || branch_byte`, followed by standard Keccak padding.
The previous transcript state is message data; each hash starts from zero.
Nova concatenates the two 32-byte hash outputs in branch order and reduces the
result as a little-endian 512-bit integer into the scalar field. The actual
quotient is 257 bits and the general bound is 258 bits, so the existing
multiplication argument's unsigned 32-byte quotient cannot implement that
reduction unchanged. Both branches, a bounded wider reduction and authenticated
proof/transcript-byte origins are needed before a squeeze verification claim.
These offline source observations introduce no Script verification flags.
