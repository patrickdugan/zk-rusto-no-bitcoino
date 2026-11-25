# ZKL-18: bounded dependent Pi typing with public semantic compilation

Original annotated de Bruijn grammar: Sort u, Var i, Pi A B, Lam A t, App f x. Numeric universes with Lean-style imax, no constants or axioms, no general inductives, eta, quotients, universe polymorphism or proof irrelevance. Public canonical term arena and structural context arena. The native semantic compiler validates each public descriptor without reading witness steps, reconstructs exact judgment signatures and compiles them to an authenticated inference table. Nova verifies rule membership, backward references, premise identity, append, and state. The verifier reconstructs canonical initial state, pins exact step count and checks final goal. The two 128-bit statement digest scalars bind the schema, public term/context arenas, descriptor table and goal, excluding witness steps; this also distinguishes isomorphic rule graphs. The native compiler is part of the TCB. The ZKL-17 conversion circuit is not integrated into this typed circuit. Shift, substitution and bounded beta normalization for public terms are checked outside Nova. This is a hybrid public-syntax typing verifier.

## Rules
WF(empty) is unconditional. WF(ctx,A) requires WF(ctx) and ctx |- A : Sort u. Sort u has type Sort(u+1) in a well-formed context. Var i looks up the i-th binder in its prefix context and lifts its type by i+1. Pi A B has sort imax(u,v) from A : Sort u and B : Sort v in the extended context. Lam A t : Pi A B requires formation of the Pi type and t : B in the extended context. App f x : B[x/0] requires f : Pi A B and x : A. Conversion requires t : A, B : Sort v and a bounded public beta-normalization check that A and B are convertible.

Induction on verified backwards rows yields derivability conditional on native admission, Poseidon binding and Nova soundness. This is a design argument, not a mechanized metatheorem. The native compiler uses independent depth-accumulator substitution with resource caps. The public syntax and candidate table expose potential derivations; no private theoremhood claim.

## Frozen public fixtures
Five native replays, 92 rows, all eight local rule kinds.

| case | terms | contexts | candidate rules | proof rows |
|---|---:|---:|---:|---:|
| identity | 8 | 3 | 13 | 11 |
| dependent_app | 23 | 7 | 37 | 30 |
| weakening | 12 | 5 | 22 | 19 |
| conversion | 13 | 4 | 22 | 21 |
| impredicative_pi (universe formation fixture) | 7 | 4 | 13 | 11 |

The last fixture is type-valued Pi formation at Sort 2; impredicativity is exercised by the Prop identity example. Fixture SHA256 267f96336aaa3e582a353296137e816741d2ef5ae1fbdcd3ac123294a087586f. Independent Lean endpoints exported as closed definitions. CI checks native malformed descriptors, coherent wrong premise, forged paths, synthesis and recursive/Spartan IPA compressed proofs. Hosted results pending. No Groth16, paid GPU or sealed data. Next integrate substitution, conversion and typing in a single constrained relation and audit its scope and soundness before moving term syntax into a private witness.
