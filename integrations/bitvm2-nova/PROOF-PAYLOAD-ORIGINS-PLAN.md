# Retained proof-payload scalar origins: independent next boundary

This is an unimplemented design derived from the completed legacy baseline.
It does not resume the unpublished point-authentication cost candidate. No new
Script costs, graphs, native execution, key generation or proving are reported.

The smallest independent experiment is a standalone three-component source:
one asserted proof-payload BYTE tape and two canonical scalar-encoding batches.
Use the original compact registry/interpreter and preserve all old workers.
Do not introduce a new cryptographic backend or trusted setup.

## Reference and supported serialization profile

The retained testnet4 fixture has a 13,220-byte NHT4 container, comprising a
556-byte header and 12,664-byte Nova 0.76.0 compressed proof. The reference is
`fixtures/nht4-genesis-0-2020-k5.nht4`, with the independently pinned expectation
and dimension descriptors beside it. Retain the network/k verifier-key pin and
the corrected native baseline from header revision
`de607d3db17d400dd6c2923d357f1d4a7bf233c7`.

The compressed proof partitions exactly into:

| Kind | Count | Bytes |
| --- | ---: | ---: |
| Scalars | 288 | 9,216 |
| Compressed commitments | 78 | 2,496 |
| Little-endian u64 vector prefixes | 119 | 952 |
| Total proof payload | | 12,664 |

There are 169 Pallas scalars modulo Q and 119 Vesta scalars modulo P, plus
43 Pallas and 35 Vesta compressed commitments. The existing bounded codec and
independent native cursor support this partition; neither partitioning nor
scalar canonicality establishes proof verification.

Only 18 vector counts are fixed by the authenticated dimensions. The other
101 prefixes describe compressed polynomial rows: 33 allow one to three
coefficients and 68 allow one to two. The retained producer uses every maximum.
Constant offsets and prefixes therefore define a **retained maximum-width
serialization profile**, not a general Nova decoder. Do not tighten the old
generic decoder or claim support for legitimate shorter representations.

The final 17 `zn` scalars also have narrower widths than their scalar field:
32, 128, 128, 200, then thirteen 32-bit values. Their encodings require
431 high BYTEs anchored to zero. Field canonicality alone misses this rule.

## Analytical source census

The proof-payload-only version excludes the 556-byte NHT4 header. Each tape
position has a full-u32 authenticated BYTE assertion. Give its source leaf an
exact constant predicate where a prefix or width-zero is required, and a
`word_valid` predicate elsewhere. The 952 prefix bytes and 431 high-zero bytes
are disjoint: 1,383 constant leaves and 11,281 other BYTE-validity leaves.
Preserve the unchanged 10,000-constraint Program cap: the tape Program contains
only the 1,383 constant constraints. Follow the existing M17 sealed-GraphSpec
pattern to add the 11,281 deterministic `word_valid` leaves under the separate
30,000-leaf cap. Do not flatten all tape leaves into Program constraints. Derive
and validate the byte-to-leaf order explicitly; it need not equal byte order.

Reuse the existing exact 55-word, seven-split/nine-reconstruction/one-field-guard
encoding pattern for each scalar, without reducing noncanonical input values.
Batch each role in a separate component. The encoder batches have 16 arithmetic
leaves per scalar plus one canonical field guard; their actual ordering must be
derived and checked, not assumed to be interleaved.

| Component | Local words | Program constraints | Field guards | Extra word-valid leaves | Total leaves |
| --- | ---: | ---: | ---: | ---: | ---: |
| Proof-payload BYTE tape | 12,664 | 1,383 | 0 | 11,281 | 12,664 |
| 169 Pallas/Q scalar encodings | 9,295 | 2,704 | 169 | 0 | 2,873 |
| 119 Vesta/P scalar encodings | 6,545 | 1,904 | 119 | 0 | 2,023 |
| Total | 28,504 | 5,991 | 288 | 11,281 | 17,560 |

Sharing the 9,216 scalar BYTE ports gives 19,288 unique global words.
One complete honest correctness/disproof pass would require 35,120 executions,
before guards, probes and any tree checks. These are analytical counts, not
executed results or Script/RAM estimates. Prove the closed record/result budgets
before allocating graphs or keys, and measure the actual byte/stack/memory costs.

Use physical container-offset identities for BYTEs, even when the component
contains only the payload: `container_offset = 556 + payload_offset`. Keep
scalar role, path and interval explicit. Existing primary/secondary pools use
names such as `rho/message/eval_w` independently; merging those names would
incorrectly alias distinct proof positions.

The six selected M17 scalar slices are useful cross-checks, not a substitute
for deriving all 288 spans:

| Role | eval_W proof offset | c0 proof offset | c2 proof offset |
| --- | ---: | ---: | ---: |
| Pallas/Q | 4,624 | 4,672 | 4,704 |
| Vesta/P | 10,048 | 10,096 | 10,128 |

Every slice is 32 bytes. Add 556 for container offsets. The two coefficient
entries are compressed batch-row indices zero and one: c0 and c2, because
the linear coefficient is omitted. The final `zn[16]` interval is proof bytes
`[12632,12664)`, ending exactly at the container boundary.

## Verification contract before implementation

The new factory must derive roles, spans, prefix values, widths and all local/
global maps from verifier-owned policy. It must not import a caller's decoded
graph, receipt or span map as authority. Independently reconstruct that layout
and the exact encoding relations natively before keys. Preserve the old strict
reference admission and verifier-key/network/k binding.

Claims must retain every raw unsigned value. Test each role's scalar modulus
and modulus+1 as actual signed assertions; the field-validity leaf supplies the disproof.
Test the 431 width-zero obligations independently of field canonicality. Keep
BYTE 256/u32::MAX diagnostics and exact witness-length empty, truncated,
prepended and appended regressions. Interpreter panics and process failures
must never count as successful rejection.

Each case needs a complete source-key preflight before its first signature.
The same global BYTE key/value/signature must feed the tape and its actual
encoding occurrence. Check captures and aliases from real openings, not matching
metadata alone. Measure complete honest coverage and explicitly scoped faults
separately, with normal and guard-inclusive peaks.

Use bounded coherent substitutions to demonstrate the actual statement:
canonical scalar changes may still satisfy all local relations; changes to
opaque commitment bytes may also pass. Those are expected limits, not proof
verification or soundness results for a complete Nova verifier.

Keep existing Script, stack, element, component, forest, record and summary caps.
Any new parser-work bound needs its own fixed-topology derivation and boundary
tests. No fit claim follows from these word/leaf counts. Standalone measurement
comes before appending to or replacing completed M17 components. Any later
integration requires a fresh projection, global key and tree audit.

## Remaining origins and full-verifier dependencies

Fixed catalogue coverage and native/reference EOF checks do not authenticate an
external blob's SHA-256 or EOF in Script. The 556-byte container header, its
public-state relationship to proof `zn`, production assertion roots and complete
input provenance remain separate in the payload-only design. Do not promote
a matching proof hash written in metadata into source authority.

The 78 compressed commitment encodings remain opaque. Commitment subobjects
and individual IPA L/R points use 65-byte affine transcript encodings, not the
32-byte proof encodings. Spartan U is a compound instance containing commitments,
u and public-input scalars; the initial instance also involves NIFS folding and
derandomization. IPA U combines a 65-byte joint commitment and a 32-byte joint
evaluation (97 bytes). Point decoding, curve/group relations, blinding/key origins
and affine serialization must be supplied before claiming those transcript
origins. Hashing raw compressed commitments is not the required relation.

IPA `a_hat` is unabsorbed by the transcript. Its canonical encoding does not
establish the IPA/MSM equation. Existing native IPA terminal evidence remains
native evidence; complete Script scalar multiplication, MSM, IPA, transcript
equations, assertion binding and Bitcoin transaction/dispute integration are
still required before end-to-end verification can be claimed.

Stop on an accepted malformed opening, incorrect origin/alias, unexpected abort,
panic, resource failure or unsupported serialization being presented as general
acceptance. Document honest negative results without relaxing the boundary.
