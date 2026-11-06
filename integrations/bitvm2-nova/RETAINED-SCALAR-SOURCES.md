# Retained scalar-source relation

This separate thirteen-component experiment adds an asserted 112-byte scalar
block and a canonical `eval_W` encoder to the completed
[challenge-bit/conditional-point relation](BYTE-C-BIT-POINT.md). Hosted execution
and new Script costs are pending. The eleven-component baseline and its evidence
remain unchanged. This is a local source relation, not a complete Nova SNARK or
BitVM2 verifier.

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
322 separately reported comparisons. These are planned/source-derived counts
until hosted execution reports them.

## Closed execution corpus

The six main profiles are `p/h,p/c,p/w,v/h,v/c,v/w`: honest, coherent changed
coefficient, and coherent changed eval_W. Their claimed scalar inputs and every
downstream consumer are re-witnessed consistently; every local predicate should
be true. Both honest profiles execute all 153,342 leaves. Each coherent profile
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
remain separately classified. All private registries use disjoint test keys;
no production assertion-root/key-lifecycle binding is claimed.

## Resource and evidence gates

The unchanged compact-record hard limit is 134,217,728 bytes. Independent closed
serialization accounting bounds this corpus at 133,969,276 bytes, leaving
248,452 bytes. This is an upper-bound calculation, not a measured run. The native
worker and report validator must enforce the exact corpus and identifier lengths;
no extra Script calls or limit increase is authorized by that estimate.

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
review. The new measured Pallas/Vesta costs, runtime, memory and artifact hashes
will be recorded only after those gates pass.

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
