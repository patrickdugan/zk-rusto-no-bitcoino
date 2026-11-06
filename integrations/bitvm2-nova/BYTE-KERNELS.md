# Opt-in byte predicates and authenticated kernel costs

This experiment adds five byte predicates without replacing the existing
Boolean Keccak backend. Each formal operand, including an output or repeated
alias, has exclusive bound 256. Bits needed for an operation are derived inside
Script from these byte values; no independent bit witness is accepted.

| Predicate | Relation | Public parameters |
| --- | --- | --- |
| `byte_xor(a,b,out)` | `out = a XOR b` | none |
| `byte_and(a,b,out)` | `out = a AND b` | none |
| `byte_not(a,out)` | `out = 255-a` | none |
| `byte_rol(a,b,out;r)` | `out = ((a << r) & 255) + (b >> (8-r))` | integer r in 1-7 |
| `byte_xor_const(a,out;mask)` | `out = a XOR mask` | integer mask in 0-255 |

`byte_rol` joins fragments of two neighboring bytes. It is a unary byte rotation
only when a and b alias. For a future little-endian 64-bit lane rotation
`s=8*q+r`, output byte j would consume a at `(j-q) mod 8` and b at
`(j-q-1) mod 8`. Byte-aligned routing needs no such join. Mask zero is a copy;
mask 255 is a complement. These are fixed public choices, not specialization
using witness values.

The compiler uses descending comparisons and subtractions, Boolean operations,
addition and public powers of two. It uses no disabled bitwise opcode, OP_MUL,
OP_CAT or experimental opcode. Public field, kind and immutable integer
parameters are checked before cache lookup, so a warmed integer shape cannot
admit Python Boolean aliases. Every formal bound and arity is checked before a
constraint is appended. The optional `byte-v1` compiler and ByteProgram digest
domain separate its identity from existing compilers.

## Failure and authentication semantics

A wrong bounded output returns ordinary false: correctness fails and disproof
succeeds. Negative, out-of-range, oversized or nonminimal numeric bare inputs
can abort both modes. Such an abort is not a successful disproof. The separate
WOTS adapter retains its existing invalid-message rules: a valid signature over
an out-of-bound u32 value can be disputed through its decoder flag, while forged
signatures and malformed witness lengths abort authentication in both modes.

The existing exact witness-length and opening checks are reused, including
empty, truncated, prepended and appended witnesses. Repeated formal wires
recover one authenticated value and use the existing alias-expansion script.
Context, field role, operation, program, catalogue and key identities remain
bound. Native interpreter panics are fatal worker failures and never successful
rejections.

## Comparable byte-level statements

For XOR, AND and NOT, the measured Boolean baseline has the same external BYTE
input and output ports as the candidate. Every distinct port is connected to a
BASE-bound auxiliary and eight Boolean words using the unchanged `bits(8)`
predicate in MSB-first order and `conv_reconstruct(8)`. Eight Boolean operation
leaves connect those bit ports. Thus the unaliased binary baseline has 30 words
and 14 leaves; the unary baseline has 20 words and 12 leaves. No conversion or
bit-reconstruction check is omitted to favor a candidate.

Candidate binary kernels have three words and one leaf; unary kernels have two
words and one leaf. Both Pasta scalar roles use the same controlled byte values
and accounting. Alias, coherent wrong-output and signed oversized-value cases
retain their own expected catalogue topology. Actual shared auxiliary and bit
opening comparisons verify the baseline links, including repeated formal uses.

This comparison is a complete isolated byte-port statement. An existing bit
permutation already keeps values as bits and does not pay these conversions at
every gate. Bit rotations can be pure rewiring, and unchanged public-mask bits
can alias existing wires. Therefore rotation and public-mask candidates are
reported with their actual authenticated costs without claiming a universal
Boolean replacement cost. No whole-permutation saving or two-branch fit follows
from this isolated comparison.

The unaliased bare-body diagnostic has an honest negative result for XOR and
AND. These byte counts include each predicate's own range checks but exclude
authentication and all baseline conversion bridges:

| Operation | One byte body | Eight Boolean gate bodies |
| --- | ---: | ---: |
| XOR | 674 | 360 |
| AND | 658 | 296 |
| NOT | 31 | 256 |

Thus fewer byte leaves do not by themselves establish lower Script cost.
Rotation bodies for r=1-7 are 143, 243, 343, 439, 535, 631 and 727 bytes;
public-mask bodies for 0, 1, 128, 129 and 255 are 23, 321, 83, 337 and 31 bytes.
Their authenticated costs still require actual registry construction.

## Verification boundary

The bounded local kernel tests pin all three old Boolean bodies and five
representative convolution bodies by length and SHA-256. They exercise both
Pasta fields, all shifts, masks, aliases, strict bounds/types, warmed-cache
parameter rejection, program/claim identity and exact witness/opening guards.
They distinguish ordinary false predicates from numeric aborts in both modes.
Additional tiny fixture and transport tests do not constitute native execution.

The dedicated hosted worker measures complete catalogues and each actual
authenticated leaf, executes every selected relation in both modes, checks
catalogue/key/JSON mutations and records malformed/authentication guards.
Independent integer references and bare exhaustive XOR/AND checks are counted
separately from WOTS vectors. Inputs are freshly generated and hashed before a
direct resource-capped configured worker is launched; imported result receipts
are not accepted. Actual costs and runtime coverage are recorded only after
that execution succeeds.

No byte Keccak permutation, full hash, transcript or Nova/Spartan verifier is
implemented by this kernel experiment. Production WOTS lifecycle, assertions
and the Bitcoin transaction graph remain open. Existing Boolean graphs,
framed-LO conformance, header provers and k-sized proving profiles are retained.
Script accounting excludes transaction framing, control blocks and assertion
signature payloads.
