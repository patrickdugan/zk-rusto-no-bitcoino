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
Their measured authenticated costs are recorded below.

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
are not accepted.

## Executed hosted measurements

The [byte-kernel run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42217850012)
passed on source commit `17e687831aaaf1c16a96aa1f2c868440f3438114`.
All 16 focused Python tests passed, including the 1,912 bounded Script calls in
the nine kernel tests. Nine native registry tests and five worker tests also
passed. All fourteen workflows passed on that source commit, including the
primitive workflow's 351 Python tests.

The complete isolated statements measured identically in both Pasta scalar
roles. All byte-to-bit conversions are included in the Boolean baseline:

| Operation | Byte candidate | Complete Boolean baseline | Reduction |
| --- | ---: | ---: | ---: |
| XOR | 5,610 | 95,018 | 89,408 bytes (94.10%) |
| AND | 5,594 | 94,954 | 89,360 bytes (94.11%) |
| NOT | 3,336 | 63,476 | 60,140 bytes (94.74%) |

All figures are actual compiled authenticated disproof Script bytes. The binary
baselines comprise 55,218 conversion bytes plus 39,800 XOR or 39,736 AND gate
bytes. The unary baseline comprises 36,812 conversion bytes plus 26,664 NOT gate
bytes. Each preserved bridge pair is 14,882 bytes for `bits(8)` plus 3,524 for
`conv_reconstruct(8)`. The gate-only diagnostic excludes conversions and is not
an alternative complete byte-port baseline.

| Cross-byte shift r | Authenticated join bytes |
| --- | ---: |
| 1 | 5,079 |
| 2 | 5,179 |
| 3 | 5,279 |
| 4 | 5,375 |
| 5 | 5,471 |
| 6 | 5,567 |
| 7 | 5,663 |

Public-mask leaf costs were 3,328 bytes for mask 0, 3,626 for 1, 3,388 for 128,
3,642 for 129 and 3,336 for 255. An already-bit-encoded one-bit mask may need
only one measured Boolean NOT leaf, 3,333 bytes. Thus mask 1 and mask 128 have
higher gate-only costs in this comparison; rotations also add work where a
bit-level graph could route wires for free. These negative cases reinforce why
the table does not establish whole-permutation savings.

The worker measured all 398 leaves in 60 tiny catalogues containing 672 words,
creating each test signature once per wire. Every leaf executed in correctness
and disproof mode. It passed **3,232 WOTS Script vectors**, including **2,834
expected rejections**, of which 2,436 were malformed/authentication guards over
174 authenticated layouts. It also rejected 1,432 native catalogue/API
mutations, compared 416 distinct baseline bit-opening links and 52 auxiliary
opening links, and checked all 544 formal bit uses including aliases. All 21
actual byte kind/parameter/alias body shapes matched across P and Q.

Separate bare checks exhaustively covered all 65,536 byte-input pairs for each
of XOR and AND: **131,072 pairs**. These plus 512 ordinary-false inverse probes
and 512 correctness inverse probes used 132,608 engine executions. Another 78
malformed/range probes used 156 executions and required both modes to fail;
these numeric aborts were not counted as successful disproofs or WOTS vectors.
No native panic was counted as rejection.

Maximum WOTS vector Script size was 14,882 bytes, maximum stack 95 items and
maximum observed witness 91 items including malformed tests, with 1,800 payload
bytes. Bare checks peaked at 24 stack items. The native worker took
4.302114341 seconds; generation plus execution took 4.35903158 seconds. Parent
peak RSS and the outer `time -v` maximum were both 24,195,072 bytes (23,628 KiB);
these are the same observed peak and are not added together. The original
512-MiB worker cap remained in force. These are small-kernel conformance
measurements, not prover timings or Bitcoin transaction costs.

Exact input corpus: 231,223 bytes, SHA-256
`528540befdec842433e1fee0d3de385fa970ed93e95936ce9b5962123493f46c`.
The WOTS vector stream was hashed without writing a raw vector file:
40,438,918 bytes, SHA-256
`ddbf1faf870724dbf3508b693c8c8bc4fd7623aeb5c0b45071591352b2cc8076`.
All hash, full-permutation, transcript, proof and production authority flags
remain false.

No byte Keccak permutation, full hash, transcript or Nova/Spartan verifier is
implemented by this kernel experiment. Production WOTS lifecycle, assertions
and the Bitcoin transaction graph remain open. Existing Boolean graphs,
framed-LO conformance, header provers and k-sized proving profiles are retained.
Script accounting excludes transaction framing, control blocks and assertion
signature payloads.

The next bounded backend step is a sealed byte round with 200 ordered BYTE
inputs and 200 distinct terminal outputs, each tied to one actual producer.
Public Rho/Pi routing may alias references; output identities must not depend
on claim values. Differential and authenticated one-round measurements are
required before composing multiple rounds or claiming that two branches fit
the current forest budget.
