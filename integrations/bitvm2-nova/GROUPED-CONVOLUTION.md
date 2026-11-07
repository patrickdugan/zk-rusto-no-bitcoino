# Grouped byte-product arithmetic experiment

This independent arithmetic experiment groups existing convolution AB checks
while keeping the legacy full-width WOTS format, word recovery and interpreter.
The isolated candidate is implemented and passed independent static source
review. The bounded predicate-body compile check passes; hosted graph, Script,
cost and stack results are pending.
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

## Expected source census, before hosted measurement

| Source | Words, unchanged | Old leaves | Grouped leaves |
| --- | ---: | ---: | ---: |
| Distinct-input multiplication | 634 | 489 | 281 |
| True same-wire square | 579 | 472 | 264 |
| Complete point addition | 7,476 | 6,151 | 3,447 |

These are independently checked source expectations, not measured Script-byte
savings. Each complete point graph contains thirteen multiplications, including
seven true squares. It retains all 35 canonical fields. Within ordinary AB
checks, unique opening occurrences fall from 2,328 to 1,008; within square AB
checks, from 2,200 to 952. The complete graph's byte cost, largest leaf, runtime
and normal/guard-inclusive stack peaks require actual matched execution.

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

## Local checks and pending hosted evidence

The combined local suite collects sixteen tests: fourteen pure tests pass and
two hosted-only tests skip, in 3.123 seconds. All new Rust files pass rustfmt;
both the new bounded body inventory and the 196 existing legacy body pins pass
their checks. The candidate registry differs from the frozen registry only by
the new strict arithmetic shape arm. The old Program/GraphSpec factories and
authentication implementation remain unchanged.

Native unit tests, all forty actual source bindings, the frozen-body macro's
execution, matched all-leaf C/D runs, standard/extra witness regressions, source
and binary snapshots, actual costs and resource peaks require the dedicated
hosted workflow. A source-publication review is not execution evidence. No
Script-byte reduction or whole-verifier fit follows from the local checks.
