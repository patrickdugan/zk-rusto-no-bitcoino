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

Script accounting includes every compiled authenticated disproof leaf. It
excludes transaction framing, control blocks, public-key catalogue transport and
assertion signatures. The new bridge adds obligations; no footprint reduction
is claimed. Actual hosted measurements are recorded after execution.

The existing real k-sized proving coordinator and its 16-GiB budget remain
separate from this hosted conformance path. No new proving job, setup ceremony,
GPU work or transaction is needed for this encoding milestone.
