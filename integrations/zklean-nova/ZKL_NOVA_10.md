# ZKL-NOVA-10: locally nameless dependent-calculus certificate pilot

2026-11-25. Native certifying checker, independent de Bruijn reference and targeted/random corruption tests PASS in the JavaScript execution sandbox. Arithmetic circuit, Nova proof, and Lean conformance for this fragment remain OPEN. ZKL-NOVA-09 compression is a separate hosted job, not a prerequisite for this native pilot.

## Reproduce

Node >=18, standard library only:

```sh
node integrations/zklean-nova/dependent.cjs > /tmp/dependent.json
diff -u integrations/zklean-nova/dependent_results.json /tmp/dependent.json
node integrations/zklean-nova/dependent.cjs --fixtures > /tmp/dependent-fixtures.json
```

The checked-in dependent_fixtures.json contains the four full native certificate arrays and the public goals. No upstream zkLean source is incorporated. The reference implementation is a separate ordinary de Bruijn checker with its own shifting, substitution and normalization; it does share the syntax and universe rule. The experiment is synthetic, with finite test and normalization budgets, not a full soundness audit.

## Term language and environment

Sort u, bound index B(k), free level F(l), dependent product Pi(A,B), lambda(A,b), application(f,a). Sort 0 is impredicative Prop; Sort 1 is Type. Sort u : Sort(u+1); product universe is imax(u,v)=0 for v=0 and max(u,v) otherwise. The pilot bounds sort levels by 8 and variable levels/indices by 255. This is a fragment of the calculus of constructions, without inductives, constants, universe polymorphism, proof irrelevance, eta, or quotient types. These limits and absence of Lean-specific rules must be retained in any comparison.

A globally ordered heterogeneous row stream represents term nodes, contexts, lookups, instantiations, conversion equations, and judgments. All references point to strictly earlier rows and are checked by type/tag. Terms carry exact derived free-level and loose-index bounds F and G. For an atom, the appropriate bound is index+1; for an application take the componentwise maximum; for a binder reduce the loose bound of its body by one (saturating at zero), then take the maximum with the domain. Context extension requires a previous judgment that the new hypothesis is a well-scoped type of some sort. A judgment in context depth d requires its subject and type to satisfy G=0 and F<=d. Context lookup either selects the last assumption or walks the checked parent lookup.

Opening at depth k replaces exactly B(k) with a locally closed term, leaving other bound indices unchanged; under the body of Pi/lambda increase k by one. Instantiation rows check both child instantiations for compound terms and the exact atomic replacement condition. This is locally nameless opening, not arbitrary de Bruijn substitution with index decrement. In well-scoped redexes and binder openings, the replacement has no loose bound variables, and the body has no loose index above the one being opened.

Conversion rows are reflexivity, symmetry, transitivity, beta, application congruence, and Pi/lambda congruence. A beta row links to an instantiation row. Binder congruence links to a previous domain equation, two instantiations of the bodies at the same fresh free level, and an explicit prior body equation. Freshness is checked against the free-level bound of both terms. No conversion rule scans the history or performs recursive normalization when validating its premises. Term normalization and hash-consing are witness-generator operations. Term AST materialization and structural comparison of the final goal are native conveniences; the next arithmetic circuit must instead use bounded DAG encodings, pinned public goal rows and authenticated row payloads.

Typing rules:

| Tag | Premises |
|---|---|
| JS | Sort successor |
| JV | Matching context lookup |
| JP | Domain sort, opened body sort in extended context, exact imax |
| JL | Well-typed dependent product, opened body judgment, matching opened codomain |
| JA | Function product type, matching argument type, instantiated result |
| JC | Prior typing, conversion equation between types, well-typed target |

Rows use exact term IDs for premise equality. The witness generator interns terms structurally, which avoids needless conversions. The root requires the last row to be a judgment in an empty context with closed proof and the exact caller-pinned theorem AST. A deployed checker must pin the entire public environment/goal, and enforce the terminal rule from the authenticated state.

## Tests and observed results

| Fixture | Rows |
|---|---:|
| polymorphic_identity | 52 |
| dependent_application | 340 |
| beta_conversion | 276 |
| impredicative_predicate_identity | 289 |
| Total | 957 |

Each valid certificate was accepted by the local relation and the independent reference checker. Six invalid mathematical examples rejected by both: Type-in-Type, Prop-in-Prop, open variable, application of a non-function, wrong polymorphic identity type, and a wrong beta-conversion target. All four changed theorem statements rejected by certificate admission.

Deterministic single-field/tag corruption campaign, 500 per fixture (2,000 total): 1,968 rejected; 32 accepted. Each accepted mutated certificate was independently checked again against the original goal; all 32 represented valid derivations. Some mutations affect irrelevant rows or leave a valid alternative justification. They are not automatically failures. Additional 26 targeted cases rejected, comprising self-references at prior-reference positions and earlier-index substitutions that falsify selected sort, instantiation, beta or conversion premises. The complete machine-readable receipt records exact tag histograms. Tests are not a coordinated forgery search and do not establish formal soundness.

## Next gate

Port one fixed-width record encoding with explicit row-type selectors and bounded F/G/context metadata to a field-safe circuit. Bind every referenced record to the exact earlier address, using the proven append/lookup architecture from 01–08; preserve the public statement from genesis through terminal admission. Start with the 52-row identity certificate, then the 340-row dependent application and beta fixture. Use separate logical conformance and adversarial tests before folding. Measure actual constraints, proof payload and RSS, with a distinct independent-path baseline before introducing shared multiproofs. The prototype's native AST expansion is not hardened against adversarially large shared DAGs; production needs bounded canonical parsing and no unbounded expansion. No real Lean/Mathlib claim, private theoremhood claim, compressed dependent proof, or Bitcoin settlement claim. No GPU allocation.
