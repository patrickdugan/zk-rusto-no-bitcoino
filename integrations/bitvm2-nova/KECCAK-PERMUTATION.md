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
1,083,269,474 bytes per scenario, derived from twelve measured pair catalogues
and round-constant differences. This projection is **not a measured full-run
result**. Actual costs and timings must come from the current-head hosted report.
The native worker is limited to 512 MiB address space, 1,200 CPU seconds and
1,260 wall seconds; the parent orchestration is bounded separately. Bulk case
files and key/signature payloads are excluded from artifacts.

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
