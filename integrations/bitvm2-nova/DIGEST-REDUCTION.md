# Claimed digest bits to scalar reduction

This separate graph connects two claimed 256-bit Keccak digest bit strings to
the 64 bytes consumed by the existing unsigned 512-bit Pasta reduction. It uses
the unchanged `bits(8)` and `conv_reconstruct(8)` predicates. The complete Nova
SNARK verifier, authenticated Keccak endpoints, transcript replay in Script,
production assertion binding and Bitcoin transaction graph remain unfinished.

## Ordered encoding boundary

The factory takes two exact 32-byte strings, LO then HI, and constructs its own
fresh uniform-reduction child. Each digest exposes four little-endian 64-bit
lanes with bits ordered from least to most significant. For byte j, the eight
exposed bits are reversed for the existing MSB-first `bits(8)` predicate. That
predicate reconstructs a distinct radix-2^29 auxiliary word; a second predicate
equates the auxiliary to the exact BYTE-bound input word used by reduction.
The two digest halves are concatenated without reversal, then interpreted as
one unsigned little-endian 512-bit integer.

The bound-two bit wires, radix-2^29 auxiliaries and BYTE-bound input wires have
distinct identities. Each auxiliary is shared between its bit reconstruction
and byte adapter. Each BYTE input is shared between its adapter and the original
reduction input multiplication. The native conformance worker compares the
actual WOTS opening slices across these two links for every byte. Source maps
describe the ordered correspondence; they are not proof of a Keccak origin.

The child retains all 244 arithmetic constraints, its canonical result field,
258-bit quotient restriction, multiplication-by-one anchor, 65 integer columns
and both carry endpoint anchors. Appending 128 encoding constraints produces
955 words, 372 constraints and one field-validity leaf: 373 authenticated leaves.
The unchanged child baseline has 379 words and 245 authenticated leaves.
Context, role, operation identity and the ordered source map enter the sealed
composition identity. Input values do not specialize its topology or predicates.

## Verification boundary

The dedicated hosted workflow constructs both roles from fresh factories,
measures complete digest and standalone child catalogues with identical Script
accounting, and executes correctness and disproof modes. It checks independent
bit order, coherent wrong inputs, swapped digest halves, reversed bits, anchors
and noncanonical results. Exact witness-length, empty, truncated, prepended,
appended, forged-signature and cross-wire regressions cover the new authenticated
shapes. Interpreter panics remain fatal worker failures.

Coherently replacing all external bits and reduction witnesses can satisfy this
graph. That is expected: the graph establishes an encoding and arithmetic
relation, while the digest's authenticated Keccak provenance remains open.
An offline Taproot membership check establishes membership in the freshly
constructed test catalogue; it does not establish an assertion UTXO or a pinned
production root. Test keys do not supply a production WOTS lifecycle.

## Executed hosted evidence

The [dedicated run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42207085946)
passed on source commit `dafab871bbe038bb4b57b0cc875ed6331075ba4c`.
All 11 digest tests ran on hosted Linux, including the seven real graph/Script
tests that skip locally. The primitive workflow also passed all 315 Python tests.
The existing uniform workflow reproduced both earlier Script byte totals and
compiled-stream hashes unchanged.

| Catalogue | Words | Leaves | Authenticated disproof Script bytes |
| --- | ---: | ---: | ---: |
| Pallas scalar, unchanged uniform child | 379 | 245 | 2,143,759 |
| Pallas scalar, digest bridge plus child | 955 | 373 | 3,321,743 |
| Vesta scalar, unchanged uniform child | 379 | 245 | 2,135,636 |
| Vesta scalar, digest bridge plus child | 955 | 373 | 3,313,620 |

The encoding boundary adds **1,177,984 Script bytes** in either field: 54.95%
and 55.16% over the respective standalone reduction baselines. This is measured
boundary overhead, not a footprint reduction. All 373 leaves of each complete
digest catalogue and all 245 leaves of each direct child baseline executed in
both correctness and disproof modes. The baselines use the same fresh child's
context and operation identity. The new catalogue identity and signing session
change their compiled-stream hashes while their byte totals remain unchanged.

Script accounting includes every compiled authenticated disproof leaf. It
excludes transaction framing, control blocks, public-key catalogue transport and
assertion signatures. Each digest catalogue has 191,000 bytes of signature
payload, compared with 75,800 for its child; public-key payload has the same
respective sizes. These payloads are recorded separately from Script totals.

The native worker executed 30 cases and **10,048 Script vectors**, including
**5,248 expected rejections** and 448 malformed/authentication guard vectors.
It also checked 132 native admission failures, including 24 ordered-map
substitutions; 256 original carry links; 256 actual shared auxiliary/input-byte
opening links; and 27,498 test signatures created once per wire per case. The
mature `halo2curves` oracle independently matched all ten 512-bit reductions,
five in each Pasta field. Its work is field reduction, not proof verification.

Each of the six coherent attack graphs executed all 373 leaves in both modes.
The low-byte consumer attack fails only at ordinal 245, the high-byte consumer
attack only at 309, and the bit producer attack only at 244. The selected real
disproofs passed offline Taproot membership with 289-byte control blocks. Roots
were freshly constructed test roots; no independent production root is claimed.
The complete coherent source-substitution test also passed as expected, with
every provenance/hash/transcript/proof flag remaining false.

Largest disproof leaves were 18,509 bytes for Pallas scalar and 18,291 for Vesta
scalar, both unchanged from their child baselines. Maximum stack was 95 items;
maximum witness length was 91 items including malformed vectors, with 1,800
payload bytes. The optimized native worker took 10.2897 seconds and peaked at
21,796 KiB RSS (22,319,104 bytes); the mature worker peaked at 8,092 KiB. Fixture
generation took 1.0139 seconds and peaked at 40,271,872 bytes. These are one
hosted conformance run's measurements, not prover or Bitcoin spend costs.

Exact generated corpus: 6,848,462 bytes,
SHA-256 `a7be7413562d89e8c9987a54994e98ce9ffdeebff89beef34c56118c5c4da5d5`.
The ten-case mature input was 3,012 bytes,
SHA-256 `0ea36ee3ae42f59e27c762e715db2a215e2684c62f6cbf9bb4cd4ff34c4e2184`.
Full digest compiled-stream SHA-256 values were
`019036e5a2f2b5ba854f6c4313f63cf96d05553567dfeaf90de5dc510b92380b`
(Pallas scalar) and
`9c17e3b7730a53203d61263d4f6d2227545478b0fa52991b7ac2a8d423ad5b9a`
(Vesta scalar). Generation reports describe generation only; actual execution
comes from the separate native workers and the checked hosted run.

The existing real k-sized proving coordinator and its 16-GiB budget remain
separate from this hosted conformance path. No new proving job, setup ceremony,
GPU work or transaction is needed for this encoding milestone.

## Remaining source boundary

The next bounded composition can share 256 LO bit ports with the last pair of
one streamed Keccak permutation, using identical global keys, values,
signatures and actual openings. Twelve permutation pairs plus this tail fit the
existing 16-component limit. This design is not implemented or measured here.
HI remains external until its own hash is authenticated; proof-derived message
inputs, framing/padding anchors and complete transcript composition also remain
open. Two existing full permutations alone exceed the unchanged forest's
`5 << 28` compiled-Script budget, so nesting alone cannot solve that limit.
