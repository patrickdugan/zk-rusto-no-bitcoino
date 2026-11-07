# Grouped conditional point in a live commitment forest

Status: M22 passed hosted compilation and execution at
`6697b7ffb20dadc3c7e0639baabad8adefc3bbb5`
([run 42353843912](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42353843912)).
Implementation commit: `0422b29bfb4f07d2c25f736295e335c7d655c7c8`.
Root and independent actual-artifact audits agree. All 24 existing workflows
passed the implementation commit; the new two-role workflow and its dependent
accounting job passed the tested head above. The same fourteen Python and
eighty-nine Rust tests passed in each role job; these are repeated suites.

The measured M21 arithmetic baseline is commit
`df6c6f377ba88525ae0659451d521cde662d6f2c`, documented in
[GROUPED-CONVOLUTION.md](GROUPED-CONVOLUTION.md). Main at the start of this work
was `4c8f555bc473a6ff7b028ae2b4fe75933c6b10cd`.
The remaining complete-verifier work is in [CLAUDE-HANDOFF.md](CLAUDE-HANDOFF.md).

## Measured result

| Script-only disproof catalogue | Historical baseline | M22 | Fewer bytes |
| --- | ---: | ---: | ---: |
| Pallas conditional point | 88,788,185 | 61,725,774 | 27,062,411 |
| Vesta conditional point | 88,890,573 | 61,828,162 | 27,062,411 |
| Pallas complete eleven-component forest | 851,477,668 | 824,415,257 | 27,062,411 |
| Vesta complete eleven-component forest | 851,563,810 | 824,501,399 | 27,062,411 |

The conditional-point reduction is 30.479743% / 30.444636%; the whole-forest
reduction is 3.178288% / 3.177966%. All ten other component byte totals match.
The delta also equals M21's independently measured six ordinary-product and
seven squaring deltas: `6*2143864 + 7*2028461 = 27062411`.
Baseline totals come from measured M16 commit
`9ebd0cfc451801a15cf37c72e63c86aa6600d390`; M22 did not rerun a complete old forest.
The comparison uses identical Script-only accounting, excluding transaction
framing, control blocks, assertion signatures and witness serialization.
The new context/source/key identities rebuild every live commitment; old roots
and stream hashes are not reused or compared as if they had identical domains.

Both roles together execute **668,076 Script calls**, with **360,190 expected
rejections**: 615,648 normal C/D calls / 307,824 rejections, 52,304 malformed
witness/authentication guard calls (all rejected), and 124 selected-tree C/D
calls / 62 rejections. Native API failures are separate: per role, 1,440 registry
negatives, 388 membership negatives, 66 map negatives, 90 source negatives and
324 cache negatives. Panics and failed processes never count as rejection.

There are two complete honest 150,509-leaf main executions and four targeted
main executions (924 normal leaf pairs each). All six main forests have complete
cost and tree construction. Of 54 private registries, 22 small cases execute
fully and 32 point cases have targeted execution. Every selected path's scope
remains explicit. The new AB fault has false leaves `[54,56]`: group and column,
both executed, with 28 guards and its own 417-byte local control. The honest
final-R control is 481 bytes; the alternate honest group has a 417-byte local
control and a 513-byte forest control under the same live roots and material.

Largest Script / normal stack / normal witness items / normal payload are
79,381 bytes / 485 / 480 / 9,600 bytes in both roles. Guard-inclusive witness
items reach 481; payload remains 9,600 bytes. Limits remain unchanged.
Each role creates 587,137 fixture signatures (465,321 main and 121,816 private),
with 3,168 main declaration reuses. Private keys are separately admitted against
the complete honest key set; this is not a claim of production key lifecycle or
an additional cross-private global public-key uniqueness pass.

| Hosted observation | Pallas | Vesta |
| --- | ---: | ---: |
| Native worker wall seconds | 241.531970 | 263.330954 |
| Parent wall seconds | 358.885938 | 383.950636 |
| Parent-only peak RSS, bytes | 142,499,840 | 142,295,040 |
| Outer GNU maximum RSS, KiB | 434,152 | 408,772 |

The GNU observations include waited children and are not standalone native RSS
or a simultaneous sum of process memory. Parent and native address-space limits
are enforced separately. No graph, native worker, key generation, signing,
Script execution, proving or GPU work ran on the local PC. Local checks were
eleven pure schema/parameter tests, AST parsing, formatting and artifact audits.

Actual record bytes are 62,398,168 per role, 124,796,336 combined, below both the
130,470,560 derived bound and 134,217,728 hard cap. Their separate actual hashes
are `6769866011468bf84c720c2500ed7e70c99a6ebc9fd45c95bca9fb50364779bf`
(Pallas) and `d9bad33d67e8d5901bbaf52d98e2d67e8fd577fea0e0e45b899b388d2bcb74bd`
(Vesta). There is no invented combined raw-stream hash.

Both snapshots contain 189 files / 5,132,098 bytes: 182 exact tested Git blobs
and seven generated locks. The canonical list hash is
`050ab5b7e02b479d4bd7f1fd0cec8b0ef4109d5477e6ace4f9cf55efc24a6b88`.
Executable hashes are observations, not source-equivalence attestations.
Root and independent audits rejected 24 and 32 contradictions of the actual
reports, respectively, and compared direct stdout, report, manifests, locks,
source bytes and both-role accounting. Offline audits do not reconstruct full
graphs, authenticate a proof, or turn observed native reference IDs into
independently recomputed source authority.

Evidence artifacts: [Pallas 13566883430](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42353843912/artifacts/13566883430),
[Vesta 13566833665](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42353843912/artifacts/13566833665),
[paired accounting 13567081794](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42353843912/artifacts/13567081794).
Verified ZIP byte sizes / SHA-256:

- Pallas: 196,054 / `3dd6605267b07b4974cfec999e5ccc9d6281d644934607a5224647a99e523095`
- Vesta: 195,953 / `ed3b7296d89b679495ecde9ac0fa955bde313b174686188f3954ef4e7df76915`
- Accounting: 3,424 / `a6348bf5f6914316903fff0b15afb260c0c3ad447a5f64406fc42c4e0f4679d6`

The first [attempt 42353543313](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42353543313)
stopped before tests/build/execution: rustfmt exited 127 while the grouped-pin
generator inherited a 256-MiB graph address-space limit. The workflow-only fix
keeps that bounded formatter check outside the graph limit, matching M21, with
60-second wall / 30-second subprocess timeouts. Graph and worker limits were
not relaxed. That attempt contributes no execution or rejection evidence.

## Entry points and reproduction

Use [the hosted workflow](../../.github/workflows/bitvm2-nova-grouped-byte-c-bit-point.yml).
It generates each exact 155-file role corpus, builds the isolated
`grouped-point-oracle` worker, directly invokes it under the recorded caps,
and requires both roles in a dependent accounting job. The Python entry point is
`bench_grouped_byte_c_bit_point.py --role pallas_scalar|vesta_scalar` with the
fresh cases directory, configured native worker and output arguments shown in
that workflow. Source factories are `build_grouped_conditional_point` and
`build_grouped_byte_c_bit_point`. Graph construction/execution is hosted Linux
only. The aggregate mode is accounting only and cannot feed a receipt into the
worker or authorize proof acceptance.

## Statement and scope

This opt-in experiment connects the grouped point arithmetic to the existing
eleven-component challenge-bit source: the canonical scalar's fixed bit feeds
`E = A + P; R = b ? E : A`. It constructs and checks actual component and
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

## Verification gates

Both role jobs must pass source admission, actual execution, component/forest
membership, same-live-tree comparisons and existing resource caps. Root and
independent reviews must reconcile the actual artifacts, separate targeted from
full execution, and distinguish native errors from Script rejections. Actual
costs, peak witnesses/stacks, runtime and memory are recorded above. An honest
negative result or a cap failure must be recorded without expanding a limit or
claiming complete verification.
