# ZKL-NOVA-07: authenticated theorem admission

2026-11-25. Integrated sparse R1CS synthesis and direct assignment verification PASS. This is not a Nova proof, a ZK proof of theoremhood, or a Lean-compatible kernel. The ZKL-NOVA-06 hosted folding job remains a separate gate. Use a follow-on branch based on the ZKL-NOVA-06 commit to avoid cancelling its queued CI via the concurrency group.

## Reproduce

```
node integrations/zklean-nova/admission.cjs > /tmp/admission.json
diff -u integrations/zklean-nova/admission_results.json /tmp/admission.json
```

Node >=18. The Node entry point checks the existing Poseidon parameter fixture's SHA-256 against the pinned b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67. The sandbox execution used the fixture fetched at Git commit 80ee5f18903a20702104b5f68f3a52c734d65de6 and confirmed the profile identity; Node crypto was not available in that execution. Source blob 4379c2ba82838e7e56ba4b5bf60b0a6c3637f4fb. Standard library only, no paid GPU compute.

The circuit is an independent small implicational logic checker, using the existing project's own R1CS generator and pinned Vesta-base narrow Poseidon arithmetic. No upstream zkLean source copied. This pilot uses independent historical Merkle paths rather than ZKL-NOVA-05's multiproof to isolate the integration of semantics with commitment opening. All five read slots, including inactive ones, receive the same fixed hash schedule. It is a depth-four tree (16 total rows including four genesis rows), not a scale benchmark.

## State and commitments

State is (root,n,goal,empty_ctx,sealed). A real recursive verifier must pin genesis exactly: root 8292702296760616536293423984468546471320845560884722282801420769833046234621, n=4, goal=1, empty_ctx=3, sealed=0. Genesis contains atom P, type P->P, type (P->P)->(P->P), and empty context. The root commits to the genesis rows and fixture salts. The theorem statement is given by type row 1, in context 3.

Each step checks sealed=0 and 4<=n<16, commits a single new row at address n, increments n, and preserves goal/empty_ctx. Input/output state is public for the standalone R1CS pilot. A recursive circuit must bind these endpoints across steps; mere verification of individual isolated assignments is insufficient. Final admission requires sealed=1. A step may seal only for a valid judgment at the immutable goal and empty-context IDs. A full unsealed tree cannot extend and is not an accepted certificate.

Each fixed row consists of five four-bit scalars (tag,a,b,c,d). Unused fields must be zero. Encode row and four-bit address injectively as tag + 16a + 16^2 b + 16^3 c + 16^4 d + 16^5 index. The 24-bit result is below the field modulus. A leaf is the narrow sponge hash of [0x5a4b4c30372f4c46,packed_row_and_address,salt]. Internal nodes use the previously tested node domain 0x5a4b4c30352f4e4f. Empty leaf is zero; active leaf commitments are constrained nonzero. Fixture salts i+101 are deterministic and provide no hiding. The salt is an allocated field witness; a production proof would use private fresh random salts and a hiding proof wrapper. Both hash domains use the same pinned width-six parameters and three-input sponge framing; no independent Rust parity for the new leaf domain was checked.

Each active historical read has an address below n, five bounded fields and a salt, and a path that authenticates their exact leaf under the input root. Its address is tied to a reference or a derived reference of the selected rule. Inactive address, fields, salt and siblings are constrained zero. Each new leaf is nonzero. The append path checks the old leaf was zero at n and computes the new root with the exact same siblings. The circuit's rule selector is constrained to one of nine tags, and the selected rule controls activity of every read slot.

## Logical rules

| Tag | Rule | Historical refs |
|---|---|---|
| 0 | Atom(label) | none |
| 1 | Arrow(domain,codomain) | two type rows |
| 2 | Nil | none |
| 3 | Extend(parent,type) | context and type |
| 4 | Here(ctx,type) | extension context and matching type |
| 5 | There(ctx,type,previous_lookup) | extension context, type, parent lookup |
| 6 | Var(ctx,type,lookup) | matching context/type/lookup |
| 7 | Lam(ctx,type,body) | context, arrow type, body judgment, its extended context |
| 8 | App(ctx,type,fn,arg) | context, result type, function and argument judgments, function type |

For lambda the body context must extend the requested context with exactly the arrow domain and the body type must equal the codomain. For application both judgments share context, the argument type must equal the function arrow domain and the result type equals the codomain. Row identity is used as type equality (sound but incomplete for structural equality). A judgment encodes an implicit proof term DAG; THERE witnesses variable lookup through the parent context. Induction on accepted rows from pinned genesis, plus collision resistance and correct arithmetic constraints, gives the restricted typing derivation invariant. This is a soundness sketch, not a formal proof or independent adversarial solver.

## Results

Generated and checked actual sparse matrices in the sandbox. The independent direct native rule checker agrees on all accepted logical transitions. Fifteen valid assignments consist of three isolated atom/arrow/nil transitions and a chained twelve-row certificate using all remaining rule types. At the terminal state n=16 and sealed=1, the last APP judgment proves the fixed P->P goal. The receipt records every root transition; its terminal root is 1428547338094671197299858150693881127055436017647795909497136294511328706173.

| Metric | Value |
|---|---:|
| R1CS rows per step | 11023 |
| Wires incl. ONE | 10947 |
| Sparse matrix terms | 285971 |
| Poseidon hashes | 34 |
| Hash equations | 10608 |
| Other equations | 415 |
| Valid assignments | 15 |
| Valid-assignment exact matrix shape comparisons | 14 |
| Malformed transitions rejected | 11 |
| Single-wire corrupted assignments rejected | 10 |

The 34 hashes consist of five times (one leaf plus four path nodes), one new leaf and eight append path nodes. All 11 invalid transition matrices also exactly match the baseline shape. Invalid transitions include wrong lambda type, changed terminal empty-context ID, wrong derived historical index, sealed-state replay, altered append root, wrong variable lookup type, non-type arrow operand, wrong HERE type, wrong THERE parent, sealing a nonjudgment, and a self/forward reference. Single-wire mutations exercise new row fields, historical index/fields/salt/siblings, new salt, append sibling, S-box assignments and output root. The separate matrix checker evaluates the supplied assignments without rerunning witness generation. This is targeted testing, not exhaustive search for coordinated forgeries.

## Follow-on

First obtain the actual ZKL-NOVA-06 hosted recursive membership result. Then adapt the fixed-matrix bridge to this state with private per-step assignments and an independently generated trusted matrix. Chain the twelve transitions from pinned genesis, require sealed=1, verify the expected theorem state, and test changed genesis and goal. Pin the matrix independently of the witness. Record native field-hash parity for both domains, actual augmented constraints, proof payload and memory. The verifier may choose to expose only goal and a commitment to the terminal proof rather than a fixture-specific root; specify the actual privacy contract. Do not interpret the raw RecursiveSNARK payload as a private proof until its privacy properties have been established.

After the small real fold, integrate the fixed append frontier and shared-path authentication, scale D and K with a canonical field-safe row encoding, and add dependent types, substitution, conversion, universes and inductive rules. The current theorem is deliberately trivial and cannot establish performance or completeness for Lean/Mathlib. No Rust compilation or recursive proof was performed for ZKL-NOVA-07 in this sandbox.
