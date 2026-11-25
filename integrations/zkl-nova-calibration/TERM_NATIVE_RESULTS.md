# ZKL-17 native differential and sharing receipt

Native audit: 4,096 generated seed-indexed depth-5 term pairs/cutoffs; direct substitution equals independent depth-accumulator substitution, and one generated beta certificate per seed replays. Five committed public fixtures, 34 rows, all 17 local cases covered. Six coherent mutated native rows rejected. Fixture SHA256 e31a5c06617e5e01bde3d301e6ca719fc76a1e2c7e2d59cb9fc4df549cf674b3. This is finite differential evidence, not a general proof of implementation soundness.

Sharing experiment: 256 new public roots at each component depth (3/5/7). The baseline deliberately disables memoization of lift and sub judgments; the DAG arm memoizes identical judgments. Both produce and replay valid explicit certificates for the same raw beta redex. Rows are local derivation count, not optimal lengths or measured Nova constraint counts.

| depth | unfolded rows | shared rows | improved roots | fits 64-node arena and 64-row log |
|---:|---:|---:|---:|---:|
| 3 | 1393 | 1291 | 42 | 256 |
| 5 | 1918 | 1671 | 63 | 256 |
| 7 | 2148 | 1675 | 56 | 254 |

No cost claims about the two over-capacity shared DAGs. No training or paid GPU. Reproduce: python audit.py; python term_sharing.py. The native reference is an exploratory source generator and differential replay, not a hardened untrusted input parser.

A separate simple-type unifier inferred common types for both sides of all five public fixture equalities, with an occurs check and explicit free-variable types. typed_export.py produces complete Lean 4 equality examples using rfl; Lean kernel replay is in a separate pinned CI workflow. This is an external check of the five typed endpoint statements, not a verification of every Nova certificate row or a dependent-type kernel. In particular the congruence fixture's terminal goal is reflexive; its intermediate derivation rules are checked by the Nova relation.

Future DataGoblin curriculum: generate capture-avoidance tasks and explicit lift/sub/conv judgment sequences; use memoized reference vs unfolded certificate costs, preserve distinct source term roots, reject malformed scopes and certify independent validity. No general optimality or curriculum release claim. Future circuit work should bind typed contexts and dependent Pi rather than treating untyped beta equality as theoremhood. Existing affine proof-cost profile remains separate.
