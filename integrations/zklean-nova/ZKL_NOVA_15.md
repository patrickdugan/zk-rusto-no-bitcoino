# ZKL-NOVA-15: fixed public Nat environment and checked dependent elimination

2026-11-25. Native extension, reference type checking, and certificate corruption tests PASS. Arithmetic circuit, authenticated history integration and Nova proofs for the new rules remain OPEN. The earlier independent-path dependent circuit (12) has verified recursive and compressed proofs. Both optimization runs (13,14) passed full assignment generation and Rust compilation but failed the strict canonical sparse loader before Nova setup. The two patches 8fec08ae48298492333e6d3df538d6ce057a4303 and ecaaa297b788d436c2017066eb2134d6324b163c remove exactly 18 explicit zero terms per matrix by canonicalizing linear combinations at emission. All other local sample fields remain identical. Hosted reruns are pending; no new optimized proof timing claim.

## Public signature

The new source is additive to the earlier dependent.cjs checker. Reproduce with Node >=18:
```
node integrations/zklean-nova/nat_inductive.cjs > /tmp/nat.json
diff -u integrations/zklean-nova/nat_inductive_results.json /tmp/nat.json
node integrations/zklean-nova/nat_inductive.cjs --fixtures > /tmp/nat-fixtures.json
```
The immutable environment is six numeric constant IDs. No user-supplied axioms or arbitrary recursive definitions are accepted.

| ID | Constant | Signature |
|---:|---|---|
| 0 | Nat | Sort 1 |
| 1 | Nat.zero | Nat |
| 2 | Nat.succ | Nat -> Nat |
| 3 | Nat.rec.{0} | recursor into Sort 0 |
| 4 | Nat.rec.{1} | recursor into Sort 1 |
| 5 | Nat.rec.{2} | recursor into Sort 2 |

For each fixed u in {0,1,2} the recursor has type
```
Pi (M : Nat -> Sort u),
  M zero ->
  (Pi (n : Nat), M n -> M (succ n)) ->
  Pi (n : Nat), M n
```
The actual implementation stores a closed de Bruijn AST with fixed numeric constant IDs. A separate de Bruijn reference checker verifies each signature has the expected sort; the six sort indices are [2,1,1,0,2,3]. A dependency traversal checks that every referenced constant in a signature is an earlier public type/constructor (IDs <=2), and every signature is closed. The six signatures are a trusted primitive inductive environment, not arbitrary user-provided inductive declarations checked for positivity. The reference checker shares the fixed environment table with the certificate checker; its inference, substitution and reduction implementations are separate.

## Four new certificate tags

- C(id): closed constant term, id must be 0..5; free and loose scope bounds both zero. Substitution treats it as an inert atom.
- JK(ctx,constant,type): a typing judgment for a public constant. The selected term's type AST must equal the exact pinned environment signature; ordinary judgment scope checks apply.
- VZ(lhs,rhs): a saturated Nat.rec application with scrutinee zero. Verify the entire application spine, recursor ID and constructor, then require the RHS term ID to equal the base argument.
- VN(lhs,rhs): a saturated Nat.rec application with scrutinee succ(n). Verify the recursor ID, constructor and predecessor, then require the RHS DAG to be App(App(step,n),App(rec_partial,n)), where rec_partial is the exact original application to motive, base and step.

Conversion endpoints must be locally closed. Iota is checked by earlier term IDs and bounded spine inspection; no host evaluator is used as an authority for the equation. The witness generator normalizes beta/iota and emits conversion chains. In contrast, the independent oracle reduces ordinary de Bruijn terms with a separately written spine collector, beta substitution and recursive iota reducer. Typing still uses the locally nameless opening, scope, context lookup, and impredicative product rules from 10. The generator now explicitly normalizes a judgment's type to a sort via checked conversion where required.

## Observed native results

| Fixture | Rows |
|---|---:|
| polymorphic_identity | 52 |
| dependent_application | 340 |
| beta_conversion | 276 |
| impredicative_predicate_identity | 289 |
| nat_zero | 4 |
| nat_recursion | 350 |
| iota_zero_type | 376 |
| iota_succ_type | 528 |
| dependent_nat_elimination | 1865 |
| prop_nat_elimination | 1863 |
| Total | 5943 |

All ten fixtures passed certificate replay and independent type checking. The original four certificate row counts and rule histograms are unchanged. nat_recursion uses the recursive result to compute a numeral. The type-level recursor examples force two zero and two successor iota equations in their certificate derivations, including the recursive predecessor case. The dependent family in the elimination example is indexed by n:
```
M(n) = Pi (F : Nat -> Type), F n -> F n
```
The Prop counterpart replaces Type by Prop, exercising the impredicative product rule and the fixed universe-zero recursor. Both use well-typed base and step functions. These are primitive recursion examples, not a proof of an arbitrary user-declared inductive family's well-formedness.

Eleven invalid mathematical inputs failed both reference inference and certificate generation, including unknown constant ID, zero incorrectly given a sort, invalid motive, malformed step function, and non-Nat scrutinee, plus the six earlier dependent-calculus controls. All ten changed-goal checks rejected. 2,000 random single-field/tag mutations (200 per fixture): 1,977 rejected and 23 accepted. Every accepted mutation replayed to a derivation independently valid against the original goal. 26 inherited targeted rule attacks plus 62 Nat-specific controls rejected (4 forged iota RHS, 4 swapped constructor-rule tags, 32 forged constant typing signatures and 22 unknown constant declarations). Including changed goals, 98 targeted rejection checks, separate from the eleven invalid source examples and random mutations. The results are deterministic; the experiment does not cover coordinated malicious certificates or establish formal soundness.

## Next gate

Encode C, JK, VZ, VN in the fixed local arithmetic relation. Preserve old numeric tag assignments when extending the record enum. JK must bind the type's authenticated structural digest to the pinned environment entry for the constant ID; never admit arbitrary signature ASTs, untrusted environment roots, or a host-derived equality flag. VZ/VN need authenticated bounded spine records and exact input/output term IDs; derive all additional read addresses from already verified record fields. Count the actual maximum read slots and synthesize a single fixed matrix before folding.

The longest new certificate has 1,865 rows, so depth nine is insufficient. Either choose a larger history depth and wider record fields (at least eleven bits for these fixtures) or reduce the witness generator's repeated instantiations. The existing 14-field record packs safely in one field at eleven or twelve bits per component including its address, but all count/scope comparisons and bounds must be reviewed when changing widths. Measure deduplicated term/instantiation certificates separately, with exact theorem goals unchanged. New logical rules have not been arithmetized. The fixture checker still expands ASTs and lacks hardened adversarial input budgets. Native test coverage is finite, and the scope excludes general inductive declarations, positivity checking, indexed inductives, universe polymorphism, eta, proof irrelevance, quotients, Lean import, proof privacy, and Bitcoin settlement. No paid GPU allocation.
