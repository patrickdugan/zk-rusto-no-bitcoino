# Grouped byte-product arithmetic experiment

This independent arithmetic experiment groups existing convolution AB checks
while keeping the legacy full-width WOTS format, word recovery and interpreter.
The isolated candidate passed its first hosted conformance run on
`df6c6f377ba88525ae0659451d521cde662d6f2c`
([run 42346318825](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42346318825)).
All 394,416 Script executions match expected outcomes, including 369,766
expected rejections. Complete point Script bytes fall by 27,062,411 in each
field. Root and independent actual-artifact audits pass. Standalone
multiplication's largest leaf and stack/witness peaks increase as detailed below.
The unpublished point-authentication/hinted candidate remains paused and is not
an input to this implementation.

## Preserved relation and explicit candidate identity

An original AB row asserts one subtotal equals the sum of at most four BYTE
products. Keep every original subtotal output, word bound and consumer. For each
multiplication, split the old rows into lower diagonals 0..31 and upper diagonals
32..62, then group up to four successive rows within each block-index strip.
The exact partition has 280 rows / 1,024 products and 72 groups:

| Row product counts in one group | Groups |
| --- | ---: |
| 1, 2, 3, 4 | 8 |
| 4, 4, 4, 4 | 56 |
| 3, 2, 1 | 8 |

The new `conv_ab_all` predicate returns the AND of every old row equality.
It copies each row's ordered operands, executes the frozen old `conv_ab` body
byte for byte, accumulates its Boolean and continues through every row. It
does not turn a false equality into a VERIFY abort or sum equation residuals.
Each row still computes at most `4*255^2 = 260100 < 2^18`. The original 64 column
equations, both carry anchors and all canonical field guards remain unchanged.

The candidate has a separate Program digest domain and explicit GraphSpec
factory. Its isolated registry copy adds only the strictly bounded new shape;
the frozen registry keeps rejecting that new kind. The existing registry's
identity, key, witness, exact-depth, recovery and Script code remain the
baseline. Native preflight must reconstruct the complete old topology and the
new partition, including the inverse leaf/row map, before any key work.

Actual word identities select aliases. Two equal-valued input fields retain
distinct names and keys; true same-wire squaring retains its shared identities.
All four ordinary alias layouts also occur among the ten squaring layouts, so
the combined new layout inventory is ten. The maximum is 36 formal operands
and 15 unique openings. That is 150 initial compact witness items for this new
kind, not an observed combined-stack peak.

## Source census confirmed by hosted admission

| Source | Words, unchanged | Old leaves | Grouped leaves |
| --- | ---: | ---: | ---: |
| Distinct-input multiplication | 634 | 489 | 281 |
| True same-wire square | 579 | 472 | 264 |
| Complete point addition | 7,476 | 6,151 | 3,447 |

These independently checked source counts also pass hosted source admission.
Each complete point graph contains thirteen multiplications, including seven
true squares. It retains all 35 canonical fields. Within ordinary AB
checks, unique opening occurrences fall from 2,328 to 1,008; within square AB
checks, from 2,200 to 952. Actual matched costs and normal/guard-inclusive peaks
are recorded below; source counts alone would not establish a byte saving.

The bounded local compiler check covers three raw patterns and all ten expanded
alias layouts in both fields. Raw bodies are 7,131 / 12,676 / 3,962 bytes;
the largest expanded body is 12,826 bytes, below the unchanged 20,000-byte body
cap. No graph, Script execution, keys or proving run locally for this check.
The generated native inventory contains four frozen row bodies and 26 bounded
hashes. Native source admission independently rebuilds the wrapper and alias
expansion before accepting an actual candidate body.

## Closed adversarial corpus

The planned corpus has forty cases, `p/00..19` and `v/00..19`. Per role, four
honest cases execute every baseline and candidate leaf: distinct inputs 257/259,
equal-valued distinct inputs 257/257, a true square of 257, and complete point
addition of the test point `(p-1,2)` to its double. The point is a test input;
no Nova generator derivation is claimed.

Sixteen targeted cases per role cover each row position of all three group
patterns, coherent cancellation witnesses under both identity policies, an AB
fault on an inactive point branch, a real signed BYTE 256, and a real signed
subtotal u32::MAX. Each target must select every false/abort predicate, affected
occurrence and fixed controls, with a 128-leaf cap TOTAL across both adapters.
Raw unsigned assertions retain their original value and declared bound, without
casting or manufacturing an impossible BYTE witness.

The cancellation witness is essential. With `a=b=257`, claim `c=65794`, `q=0`;
change subtotal `(0,0)` from 1 to 2 and `(1,0)` from 2 to 1. Every column and
both endpoint anchors pass with all 65 encoded carries equal to 8192, while
two AB equalities in the first group are false. Their unweighted residual sum
is zero. The conjunction must reject this wrong multiplication.

Baseline and candidate share the same complete word catalogue, assignments,
per-case keys and once-created full signatures. Every source pair is preflighted
before any case is signed, and every global key is checked before its first
signature. Actual captures must bind every word at a concrete opening, plus
every mapped subtotal/carry coordinate and old-to-new interface link. This
separate material pass does not visit every unexecuted target-leaf packet;
`opening_link_pass_all_leaves` remains false. Honest cases execute all leaves,
while the negative cases retain their explicit targeted Script coverage.

Every selected or full leaf receives all fourteen existing standard guard
executions. Empty, truncated, prepended, appended, changed-hash and foreign-key
witness cases remain. Sixteen separately counted reserve calls additionally
cover actual malformed authentication beside an earlier invalid bound or false
row. A last-row operand is not necessarily recovered last: recovery positions
must be reported from the actual reversed key-recovery order. Panics, timeouts,
process failures and malformed source files never count as successful Script
rejections.

## Before-execution budgets and stop conditions

The eight honest pairs contain 23,748 measured leaves in total. With thirty-two
targets of at most 128 leaves across both adapters, at most 27,844 lossless
cost rows are needed. Normal C/D plus fourteen guards gives 445,504 calls;
a 2,048-call reserve makes the pre-key bound 447,552. Owned ASCII guard IDs and
the six-field compact record format give 218 bytes per line, or 97,566,336 bytes,
below the unchanged 134,217,728-byte hard cap. The record is streamed and hashed.

Three-integer cost rows use at most 21 bytes each. Adding the 300,000-byte
metadata reserve yields 884,724 bytes, below the unchanged 1,048,576-byte summary
cap. Every measured row must compile C and D and check D=C+1. Full and targeted
costs, normal and guard-inclusive metrics, native and Script rejections remain
separate scopes.

There are exactly 81 inputs: the manifest plus eighty adapter case files. The
new corpus-specific preparse bound is 550,000 lexical nodes, justified by
`8*7476 + 6151*(16+48+7) + 7*6151 + 7476 + 4*256 + 1024 = 549110`.
Its premises are enforced: at most 7,476 words, 6,151 leaves/checks, 48 formal
operands, eight arguments and 256 body entries per case. Old parsers are
unchanged. Actual lexical counts must pass before writing and native parsing.

Unchanged limits include 32-MiB case files, 20,000-byte bodies, 100,000-byte
authenticated leaves, 1,000 combined-stack items, 520-byte elements, 256-MiB
component Script streams and 512-MiB worker address space. Native/parent limits
are 1,260/1,500 seconds. No tree or forest is constructed. Stop on an incorrect
conjunction, source/alias/opening mismatch, accepted malformed authentication,
unexpected abort or any cap failure. There is no silent fallback or cap increase.

Matched measured baseline/candidate costs must precede any savings claim. The
historical complete-point baseline is 88,586,200 Pallas / 88,688,588 Vesta Script
bytes under the same accounting. Assertion signatures, witness bytes, control
blocks and transaction framing are excluded. A genuine negative cost/resource
result is recorded as such.

This milestone does not establish proof origins, complete transcript, scalar
multiplication/MSM/IPA, production assertions or a Bitcoin dispute graph. It
does not run proving, setup or GPU jobs or change header provers. A successful
arithmetic cost experiment is not a complete Nova or BitVM2 verifier.

## Checks and hosted evidence

The combined local suite collects sixteen tests: fourteen pure tests pass and
two hosted-only tests skip, in 3.123 seconds. All new Rust files pass rustfmt;
both the new bounded body inventory and the 196 existing legacy body pins pass
their checks. The candidate registry differs from the frozen registry only by
the new strict arithmetic shape arm. The old Program/GraphSpec factories and
authentication implementation remain unchanged.

The dedicated hosted workflow passes all sixteen Python tests (5.042 seconds),
including both formerly skipped binding/macro tests, and all twenty-four Rust
tests (0.01 seconds). Its complete/targeted C/D execution, standard/extra witness
regressions and source/binary snapshot checks pass. The local checks remain
distinct from this direct execution evidence.

The broad primitive workflow also passes: 513 Python tests collected, 499 passed
and fourteen explicitly skipped, in 575.713 seconds. This is separate from the
dedicated sixteen-test hosted execution scope.

All 24 workflows for tested code commit
`df6c6f377ba88525ae0659451d521cde662d6f2c` passed.

## Matched complete Script measurements

| Complete source | Legacy Script bytes | Grouped Script bytes | Reduction |
| --- | ---: | ---: | ---: |
| Pallas multiplication | 6,993,315 | 4,849,451 | 30.6559% |
| Vesta multiplication | 7,001,191 | 4,857,327 | 30.6214% |
| Pallas true square | 6,646,421 | 4,617,960 | 30.5196% |
| Vesta true square | 6,654,297 | 4,625,836 | 30.4835% |
| Pallas complete point addition | 88,586,200 | 61,523,789 | 30.5492% |
| Vesta complete point addition | 88,688,588 | 61,626,177 | 30.5140% |

Both equal-valued, separately named input fields have exactly the same full
costs as distinct-valued inputs: no value-based aliasing chooses topology.
The ordinary multiplication saving is 2,143,864 bytes; the true-square saving
is 2,028,461 bytes. Independently summing the observed savings of six ordinary
products and seven squares gives exactly each measured point saving:
`6*2143864 + 7*2028461 = 27062411`. All original non-AB point predicates and
canonical guards retain their body bytes and ordered word occurrences in the
projection.

The table sums disproof Script bytes and includes the exact witness guard,
full-width WOTS recovery and predicate code. It excludes assertion signatures,
witness bytes, control blocks and transaction framing. It is not transaction
weight, fees or a measured whole-verifier total. Old/new catalogues and registry
IDs remain distinct and actually checked; the paired word/key/signature material
is shared within each case. The frozen default implementation is unchanged.

Eight honest pairs execute every baseline and candidate leaf: 23,748 measured
leaves / 47,496 C/D calls. Thirty-two targets measure another 902 leaves,
18-94 per pair, including every false/abort predicate and their required
affected/control selections. Their costs are scoped selected sums. Both delta
and ratio remain null for targeted cases; they are not complete-source savings.

Across all eighty adapter ledgers, normal execution has 49,300 calls and 24,650
expected rejections. All 345,100 standard guards and sixteen separate actual
authentication probes reject as expected, totaling 394,416/369,766 overall.
There are 200 proper disproof checks, zero abort leaves and 720 native-only
admission rejections; native failures are not included in Script counts. All
52,508 full signatures are created once per global word/case and reused by the
paired adapters. The actual first-word material pass checks 525,080 shared
signature-chunk links, plus every mapped subtotal/carry coordinate and interface
projection. Its scope remains all words/all mapped coordinates, not every
unexecuted target-leaf packet.

The concrete cancellation cases have exactly two false legacy AB rows and one
false candidate conjunction, with all column/end-anchor/canonical predicates
true. Signed BYTE 256 has 33 false old predicates and nine false grouped
predicates without casting its actual assertion. Profile 19 uses the derived
last row of the first all-four group, subtotal AB7/0, for unsigned u32::MAX.
The sixteen extra probes use actual packet/hash mutations. Recovery-order
evidence establishes authentication after an invalid decoded-bound flag where
claimed; last-row authentication coverage beside an earlier semantic false row
does not imply that the last row's key is recovered last.

## Actual resource tradeoff

| Ordinary multiplication / true square peak | Legacy | Grouped |
| --- | ---: | ---: |
| Largest disproof Script | 22,639 bytes | 37,333 bytes |
| Normal combined stack | 135 items | 155 items |
| Normal witness | 130 items / 2,600 bytes | 150 items / 3,000 bytes |
| Guard-inclusive witness | 131 items / 2,600 bytes | 151 items / 3,000 bytes |

Guard-inclusive multiplication/square combined-stack peaks are also 135/155.
Fewer aggregate bytes do not improve these isolated maxima. Complete point
addition's maximum disproof leaf remains 79,381 bytes and combined stack remains
485 items for both adapters/roles. Its normal witness peak remains 480 items /
9,600 bytes; guard-inclusive items remain 481 with 9,600 payload bytes. No
complete-point maximum-leaf or maximum-stack reduction is claimed.

Native execution takes 146.292700952 seconds. The Python parent's elapsed time
is 151.941772482 seconds and reported peak RSS is 45,559,808 bytes. GNU time's
outer-command observation is separately 152.08 seconds and 128,980 KiB maximum
RSS. These are different process/resource scopes. All unchanged limits pass.

The execution record is 75,812,182 bytes, below the 97,566,336-byte derived bound
and 134,217,728-byte hard cap. The canonical report is 570,152 bytes, below the
884,724-byte derived bound and 1,048,576-byte hard cap. Actual largest lexical
case counts are 263,012 nodes for a full old point and 203,508 for the grouped
point, both below the isolated 550,000-node bound. The record is streamed and
hashed, not exported. No tree, forest, proof, setup, proving, GPU or Bitcoin
transaction call occurs.

## Independent reconciliation and pins

Root and independent audits reconcile all 24,650 lossless cost rows and eighty
ledgers, exact normal/all folds, coverage, signature/link counts, source and
resource scopes. The strict validator rejects twenty-three contradictory
mutations of the actual observation. The offline reviewer independently
reconstructs all thirty-six small multiplication/square profiles, including
their numeric declarations, assignments, truth, selections and opening census,
without Program/GraphSpec/compiler/Script/key calls. The four point cases are
checked against their fixed source census, historical old-cost pins and actual
transported per-leaf observations; they are not a fresh local full point-graph
reconstruction. The hosted native cursor supplies the independently rebuilt
point topology and mature curve references.

Canonical report JSON equals parsed artifact stdout. Root and reviewer each
independently match the direct job stdout line plus LF to artifact stdout.
All 165 non-lock snapshot files match exact Git blobs at the tested commit;
the six generated lockfiles match supplied bytes and the frozen BitVM pin.
The snapshot has 171 files / 4,288,486 bytes and includes recursive literal
compiled inputs. Removing only the new strict shape arm reproduces the frozen
registry source exactly. Runtime shadow checks also verify old catalogue/key
IDs, witnesses and C/D Script bytes on every measured baseline leaf.

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Artifact 13563519143 ZIP | 170,136 | `883ac61d981c06d3084080fee29bb9c2777d58f94b026668977c2a02cca4d2e7` |
| Canonical conformance report | 570,152 | `adb4ba0668677c30faffee142517116741d56070d8aa60ff89d3d9bf8ff350c9` |
| Direct/artifact stdout | 656,096 | `6422c55f8a3527fee0940a976e4ac5d40b734d0ec52b1b5bb8297ec83d881eef` |
| Input manifest | 62,106 | `d88225299c5b0e3fca05da4d1bb1dcae26fd21c76f7e1b36aad750b772dd708e` |
| Native execution record | 75,812,182 | `dcd77a826092d37aee2b225dd3eac5e12c343eefe175c15d5fc37a6e07d96588` |
| Configured worker observation | 3,666,688 | `db50dc33f6c53e06d0eb7a1520c2d622debc6d34a8e106a06bce0578fc690d19` |

The canonical snapshot file-list SHA-256 is
`ef6dc657b92423ee69c305ce7ee8f5f5c0332751a7509664442bf9a7cb97ed51`.
The worker hash observes a configured executable; it is not binary/source
equivalence attestation. Evidence artifacts omit raw cases, proofs, key material,
witness streams and executables. This optional arithmetic worker has no candidate
Taproot/forest membership result and does not replace any existing complete
source, default compiler or header prover. Integrating the candidate into those
sources needs its own checked identity/opening/tree boundary and measurement.
