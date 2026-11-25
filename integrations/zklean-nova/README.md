# ZKL-NOVA-01 — authenticated certificate-memory pilot

2026-11-25. Status: native prototype PASS; Nova circuit and Lean conformance OPEN. No paid compute.

## Motivation and scope

Reference: https://github.com/rain-1/zero-knowledge-lean/tree/d5279fcfb0f3583bc98dd04f0ae57256c6821f46 . The upstream Go project implements a locally checkable dependent-type-theory certificate using Groth16. Its design explicitly proposes folding. This independent Python model exercises a smaller implicational calculus and append-only authenticated memory. No upstream source code was incorporated; confirm licensing before importing or adapting upstream code. No Groth16 dependency is introduced.

Run: python3 integrations/zklean-nova/model.py

## Relation

The public genesis state fixes a canonical public type DAG, empty-context row, target type ID, and environment digest. The sample target is P -> P. The nine row tags are ATOM, ARR, NIL, EXT, HERE, THERE, VAR, LAM, APP. Types and contexts precede their consumers. Lookup rows carry the context and type ID, with THERE referencing a valid lookup in the parent context. VAR requires a matching lookup; LAM discharges exactly one hypothesis; APP requires the same context and exact domain/codomain IDs. Judgments implicitly describe a term DAG. Row identity is stricter than structural equality; completeness for the full calculus is outside this pilot.

Let S=(R,n,g,e,E) consist of the memory root, next address, goal ID, empty-context ID, and environment digest. All transitions preserve g,e,E. The verifier must pin S_0 to deterministic genesis and chain from there. Finish authenticates the last judgment under R and requires context=e and type=g. Arbitrary initial states must never be admitted.

For address i, define L_i=H(domain_leaf || i || canonical_row || salt_i). Branch hashes are separately domain separated. SHA-256 is a native reference hash, not an R1CS recommendation. Fixture salts are deterministic; they provide no privacy. A real ZK design requires fresh private randomness and a ZK IVC or suitable hiding proof wrapper.

A batch begins at root R_0 and next index n_0. Each historical read i<n_0 is authenticated once against R_0. Subsequent uses refer to the same authenticated payload. Local reads n_0<=i<n are resolved by their exact index among already accepted batch rows. A reference i>=n is invalid. Each append authenticates the old empty leaf at n against the current root; the same path computes the new root with L_n. This binds append positions, preserves earlier leaves and prevents overwrites. A final batch may have fewer than B active rows in this native model; fixed-shape IVC needs a checked active-prefix mask and a terminal finalization flag.

Induction on accepted row number: assuming genesis validity and collision resistance, old reads refer to the unique historical row and local reads to already checked rows. Each type/context/lookup/typing rule preserves its interpretation under these premises. Thus a terminal accepted judgment reconstructs a simply typed proof of the pinned goal. This is a proof sketch, not a formal Lean proof or full soundness audit.

## Results

Python standard library only, sandbox CPU, depth 17 (capacity 131,072 rows including genesis). Both workloads prove the same trivial goal by synthetic application chains. Chain always reads the previous application; scatter uses a deterministic PRNG seed 20261125 and picks an older application roughly half the time, otherwise reads the base identity. Both deliberately reuse types, context and function; neither is a representative Mathlib trace.

All 18 native benchmark configurations completed, with 14/14 targeted tests rejected (six direct semantic attacks and eight memory/terminal attacks). Tests include bad function domain, wrong context/result/lookup/binder, bad parent lookup, self reference, modified row and salt, missing opening, altered append path, replay, wrong goal and terminal row. A weakening example also passed.

| Workload | Rows | Batch | Naive reads | Batched reads | Batched internal hashes | Native seconds |
|---|---:|---:|---:|---:|---:|---:|
| chain | 1000 | 16 | 4982 | 314 | 39338 | 0.068 |
| chain | 1000 | 64 | 4982 | 79 | 35343 | 0.064 |
| chain | 1000 | 256 | 4982 | 19 | 34323 | 0.063 |
| chain | 10000 | 16 | 49982 | 3124 | 393108 | 0.777 |
| chain | 10000 | 64 | 49982 | 784 | 353328 | 0.653 |
| chain | 10000 | 256 | 49982 | 199 | 343383 | 0.634 |
| chain | 100000 | 16 | 499982 | 31249 | 3931233 | 7.434 |
| chain | 100000 | 64 | 499982 | 7814 | 3532838 | 7.050 |
| chain | 100000 | 256 | 499982 | 1954 | 3433218 | 6.990 |
| scatter | 1000 | 16 | 4982 | 773 | 47141 | 0.083 |
| scatter | 1000 | 64 | 4982 | 477 | 42109 | 0.072 |
| scatter | 1000 | 256 | 4982 | 290 | 38930 | 0.073 |
| scatter | 10000 | 16 | 49982 | 8032 | 476544 | 0.966 |
| scatter | 10000 | 64 | 49982 | 5590 | 435030 | 0.798 |
| scatter | 10000 | 256 | 49982 | 4713 | 420121 | 0.794 |
| scatter | 100000 | 16 | 499982 | 81129 | 4779193 | 9.268 |
| scatter | 100000 | 64 | 499982 | 57546 | 4378282 | 8.511 |
| scatter | 100000 | 256 | 499982 | 51229 | 4270893 | 8.381 |

Naive reference counts distinct row reads per step; batched counts distinct historical reads per batch. With N new rows, D=17, A historical reads, internal verifier hash count is D(A+2N), excluding genesis, terminal authentication and leaf hashes. Naive count substitutes distinct per-step reads for A. This is an operation-count control, not a measured unbatched proving run. At 100k, baseline 11,899,694 hashes; chain B=256 saves 71.15%; scatter saves 64.11%. Times are single native runs including witness preparation and checking. No peak RAM or R1CS constraints measured.

## Circuit implications

For each fixed B, the Python dictionary must become constrained memory. A witness table of sorted unique (index,row,salt,path) historical openings should be authenticated against the initial root. Every read must be constrained to the matching entry or an earlier local row, with index equality and payload binding; one-hot selection is a simple expensive baseline. Worst-case capacity of historical slots must be fixed up front, and unused slots masked safely. Variable native distinct-read counts do not translate directly into lower fixed-shape constraints. Measure the padded worst-case shape and the selection cost, including comparison, range, flags, and leaf hashing.

A second candidate is a contiguous append frontier. Because append addresses are sequential, maintain the frontier of the occupied prefix and update via binary carries. For N insertions starting from empty, fewer than N occupied-subtree merges are needed, although deriving the externally readable root at each batch boundary has additional O(D) cost. The frontier must itself be committed in the folded state and linked to the public history root. This can eliminate repeated empty-leaf authentication under a proven prefix invariant. It is a design proposal, not implemented.

## Next registered gates

1. Port the nine-row relation to Rust with canonical encoding, deterministic genesis, explicit terminal checks, and independent reference tests. Add variable-length trace handling, all inactive-slot forgery cases, and randomized differential tests.
2. Implement Nova step circuit with Pasta-compatible field hash and fixed B=1,16,64,256; start with the simplest memory baseline. Measure actual constraints, peak RAM, proof time, verification time and proof payload; report setup and final compression choices explicitly. Include worst-case high-entropy historical references and compare frontier optimization on identical traces.
3. Add typed term DAG, locally nameless substitution and conversion rules, universes and inductive reduction. Compare imported certificates against an independent Lean-compatible checker under an explicit supported-fragment policy. Obtain source reuse permission before copying upstream code.
4. Only after native/circuit parity, terminal binding, and actual Nova verification pass, evaluate the existing BitVM3 verifier interface. Do not infer Bitcoin settlement feasibility from native SHA-256 timing or upstream Groth16 size.

Decision: continue bounded CPU R&D; no GPU allocation or deployment claim. Rust was unavailable in the sandbox, so this commit is a Python pilot and measured operation-count study. The fixed depth, synthetic theorem, deterministic salts, restricted logical rules and unimplemented folding circuit constrain all conclusions.
