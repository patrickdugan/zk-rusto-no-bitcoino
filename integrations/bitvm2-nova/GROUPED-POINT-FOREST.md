# Grouped conditional point in a live commitment forest

Status: implementation in progress. There is no M22 execution result yet.
The measured M21 arithmetic baseline is commit
`df6c6f377ba88525ae0659451d521cde662d6f2c`, documented in
[GROUPED-CONVOLUTION.md](GROUPED-CONVOLUTION.md). Main at the start of this work
was `4c8f555bc473a6ff7b028ae2b4fe75933c6b10cd`.

## Statement and scope

This opt-in experiment connects the grouped point arithmetic to the existing
eleven-component challenge-bit source: the canonical scalar's fixed bit feeds
`E = A + P; R = b ? E : A`. It must construct and check actual component and
forest commitments over the new registry's Scripts. The original factories,
registries, body tables, commitment modules and experiments remain baselines.

The experiment does not establish proof or verification-key origins for A/P,
full scalar multiplication, IPA, the complete Nova transcript, proof acceptance,
production assertion authority, Bitcoin transactions or deployability. Existing
scope flags for those statements remain false. An honest grouped-leaf opening
is a membership check with C=true/D=false. A private faulty fixture's D=true
result belongs only to that fixture's separately constructed key catalogue and
tree.

## Source and authentication gates

The new sealed sources construct the original typed source freshly, preserve
components 0 through 9 under the same caller parameters, and transform the actual
conditional-point Program/GraphSpec. They do not accept an imported graph as
construction authority. Every field guard, selector, operand bound, subtotal,
carry, anchor and word remains. Selectors, openings and fault ordinals derive
from the complete old-to-new projection.

The native checker independently admits a genuine old conditional-point
reference with its original identities, then derives the grouped program,
catalogue, bodies and projection. It must not relabel a grouped graph as an old
one. Old components require exact typed conversion and catalogue parity before
the new local Registry is used for execution and commitments.

Every main source and private numeric recipe must pass a streaming preflight
before key generation. The new outer source identity changes the test key
domain. All eleven live commitments must therefore be rebuilt. The complete 155,107-word declaration
and public-key collision admission must finish before the first fixture
signature. Opening lookup never signs. Failed admission remains rejected.

The existing Taproot modules are included unchanged against the local grouped
Registry. A second honest point commitment selects the first grouped AB leaf
using the same Registry and material as the final-R-guard commitment. Both must
have identical catalogue, registry identity, root, output, complete Script bytes
and u32-length-framed stream hash. Replacing only the selected point commitment
in the live forest must preserve its ordered component manifest, root and output.

## Planned census and execution budget

These are reviewed source/budget calculations, not M22 measurements.

| Item | Planned value |
| --- | ---: |
| Conditional-point words | 7,498 |
| Conditional-point arithmetic / canonical fields | 3,420 / 37 |
| Conditional-point leaves | 3,457 |
| Eleven-component leaves | 150,509 |
| Local / unique global word declarations | 156,163 / 155,107 |
| Shared signature reuses | 1,056 |
| Main cases / private probes, per role | 3 / 27 |
| Normal / guard / selected-tree calls, per role | 308,506 / 33,236 / 62 |
| Maximum total calls, per role | 341,804 |
| Expected rejection upper bound, per role | 187,520 |
| Compact-record upper bound, per role | 65,235,280 bytes |
| Compact-record upper bound, both roles | 130,470,560 bytes |

Two hosted jobs each retain the complete scalar-to-corresponding-base relation.
Both same-commit, same-policy role reports are required for combined success.
Their actual record byte counts are summed, while their actual stream hashes
remain separate. Aggregation supplies accounting; it does not supply authority
for a proof or a worker verdict.

The old honest/full and coherent-bit/scalar-alias profiles remain. All 52 old
private recipes remain with projected ordinals. One additional AB-subtotal fault
per role selects both the grouped equality and the retained column equality;
both are false. The selected private tree leaf is the grouped equality. All
empty, truncated, prepended and appended witness regressions remain. Interpreter
panics and process failures cannot count as successful rejection. Semantic
aborts are labeled separately from ordinary false predicates. Truth is
tri-state: an abort fails both C and D.

Existing limits remain: 256 MiB compiled Scripts per component, 1.25 GiB per
forest, 16 components, depth 19, 100,000 bytes per Script, 20,000 bytes per body,
1,000 stack items, 520-byte elements, 128 MiB combined records, 1 MiB summary,
512 MiB native address space, 1,260-second native and 1,500-second parent limits.
Full catalogue cost/tree construction and targeted Script execution are separate
coverage statements.

The genuine old reference has 7,498 words and 6,161 leaves, so its parser has its
own bound. The spec bound is `8*7498 + 71*6161 + 4*256 + 1024 = 499463` lexical
nodes, including fixed headers and the wrapper. The closed old maps use 14,144
nodes; their separate cap is 50,000. The combined bound is at most 549,463, below
550,000. Whole-file bytes, depth, string and node checks, and a quote-aware map
span check, must precede serde allocation.

## Required result before publication of a measured claim

Both role jobs must pass source admission, actual execution, component/forest
membership, same-live-tree comparisons and existing resource caps. Root and
independent reviews must reconcile the actual artifacts, separate targeted from
full execution, and distinguish native errors from Script rejections. Actual
costs, peak witnesses/stacks, runtime and memory remain pending. An honest
negative result or a cap failure must be recorded without expanding a limit or
claiming complete verification.
