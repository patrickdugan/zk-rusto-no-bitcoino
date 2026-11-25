# ZKL-NOVA-05: actual sparse R1CS authentication circuits

2026-11-25. Sparse matrix synthesis and assignment checking PASS in the JavaScript execution sandbox. Nova backend integration and recursive proving OPEN. No GPU or paid proving allocation.

## Reproduction and provenance

Run `node integrations/zklean-nova/r1cs.cjs` from a checkout of this branch, with Node >=18. The input is the existing 702,325-byte parameter fixture at `integrations/bitvm2-nova/fixtures/nht4-genesis-0-2020-k5.poseidon.json`. This experiment loaded that file via the GitHub connector from repository commit 02239adb9dccc24f67092205543508f79b45d1a8. The standalone Node entry point additionally checks the entire fixture SHA-256 against the existing independent pin b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67 before parsing. The connector sandbox does not expose Node crypto, so the local execution was pinned by commit and profile identity rather than an independent SHA-256 calculation. The GitHub Actions job runs the Node entry point and compares the JSON receipt.

Use Nova 0.76.0's Vesta base narrow profile (rate 5, width 6, 8 full rounds, 56 partial rounds). The field modulus is 28948022309329048855892746252171976963363056481941647379679742748393362948097. This is the scalar field of Pallas. The Merkle node domain is 0x5a4b4c30352f4e4f, encoded as a field scalar. The hash is a fresh simplex sponge absorbing three scalars [domain,left,right], using the documented wrapping IO tag for Absorb(3),Squeeze(1), and output lane 1. All three absorbed elements fit one permutation. Use the optimized compressed constants and exact matrix orientation from the existing poseidon_reference.py source map. Each x^5 is constrained by x^2,x^4,x^5 with three products. Affine mixing and key addition are sparse linear combinations. This yields 3*(8*6+56)=312 explicit multiplication constraints per permutation. No claim of independent native Rust parity for this new domain yet; the native arithmetic reference and R1CS generator share the pinned profile and round schedule.

The fixture leaves are synthetic field digests i+1 or zero for unused positions. Real row commitments, leaf address binding, private random salts and a separate leaf domain remain to be integrated.

## Matrix relation

Each allocated wire has a field assignment. A row stores three sparse linear combinations A,B,C and checks <A,w>*<B,w>=<C,w> modulo p. Wire 0 is fixed to one. Constants, outputs of selection, packed address/active flags and affine hash mixing are expressions over allocated wires, not unconstrained host outputs. The standalone assignment checker evaluates the stored rows using the supplied assignment and caller-pinned public values. It does not invoke the witness generator when checking a mutated assignment.

Inputs in this pilot are public root, occupied count and K caller-bound activity/address/digest records. Count bounds and active address bounds are explicit; inactive rows have zero address and digest. The independent-path control uses one selection per level and computes all D*K Poseidon hashes including inactive paths.

The packed circuit uses the same Beneš permutation construction as 04. Sorting and network controls are computed by the witness generator, but the circuit constrains every switch bit and every routed field. Sorted active-prefix and address gaps enforce order; duplicate heads are zeroed only after equal-digest checks. Packed zero-test decoding uses two equations. Each layer routes children to distinct left/right parent slots, constrains parity and parent index, enforces sorted active-prefix parents, constrains canonical unused slots and missing sibling selection, and computes every scheduled Poseidon hash. All active paths must reach the pinned root. With no requests, the memory check has no obligations and the enclosing transition must still bind the root. The witness generator's branches only choose assignments; the eight direct matrix equality tests across distinct witnesses confirm identical coefficients and variable topology for the tested shapes.

## Results

| D | K | Method | Hashes | Non-hash equations | Total equations | Wires (incl. one) | Stored sparse terms |
|---:|---:|---|---:|---:|---:|---:|---:|
| 4 | 5 | Independent | 20 | 107 | 6347 | 6353 | 167515 |
| 4 | 5 | Packed | 12 | 726 | 4470 | 4368 | 105209 |
| 5 | 10 | Independent | 50 | 234 | 15834 | 15855 | 418713 |
| 5 | 10 | Packed | 25 | 1786 | 9586 | 9369 | 222864 |

Each method/shape checks three request distributions: duplicate-heavy, distinct addresses and empty. All 12 valid assignments checked; eight full sparse-matrix comparisons across witnesses matched. A standalone hash vector plus mutations of hash output, S-box wires, sibling digest, range bit, switch bit, parent address and public digest yielded 65/65 rejected corrupted assignments. These are direct targeted assignment mutations, not an exhaustive malicious-witness search. The complete machine-readable receipt is r1cs_results.json.

The D=4 and D=5 examples reduce total constraints by 29.57% and 39.46%, respectively. Sparse-term reductions are material as well. The large D=17 projections below combine the measured 312 hash constraints with the previous ZKL-NOVA-04 equation counts; these are not synthesized large matrices:

| B | Independent authentication estimate | Packed authentication estimate | Reduction |
|---:|---:|---:|---:|
| 16 | 428998 | 398378 | 7.14% |
| 64 | 1715878 | 1385946 | 19.23% |
| 256 | 6863398 | 4600602 | 32.97% |

No write frontier, leaf hashes, full proof-rule semantics, public-state commitments, or folding overhead are included. Do not use these counts to predict prover memory without measuring matrix sparsity and the backend's padded dimensions. In particular, affine Poseidon combinations are fairly dense: multiplication count alone is insufficient to estimate sparse matrix work.

## Next gates

1. Port the fixed sparse matrix relation to Nova 0.76.0's StepCircuit frontend using PallasEngine, VestaEngine and the actual field type. Start with D=4,K=5; independently compare the native Poseidon gadget with the pinned input/output vector. Check exact coefficient/variable parity or disclose any different affine allocation strategy. Use the existing M17 and M18 gadget patterns, and a pinned Rust 1.90 toolchain in bounded hosted CI. Rust is absent and external networking is unavailable in the local execution sandbox.
2. Fold at least two membership steps, binding the actual requested records to a pinned public schedule or authenticated state. A circuit that accepts arbitrary private empty reads would be vacuous. Verify the recursive proof against the initial state and expected endpoint, reject changed root/occupied count/request records and invalid membership, record proof serialization and memory. A membership smoke test is not theoremhood.
3. Integrate the fixed append frontier and an address-bound leaf commitment with explicit field serialization, fresh salts and a distinct leaf domain. Bind every semantic reference to a consumed membership record or earlier checked local row; pin genesis and terminal theorem/context. Prove the sealed endpoint. Only then evaluate a ZK theoremhood wrapper and BitVM3.

Decision: continue packed multiproofs for the next small CPU circuit trial; retain independent paths as baseline and the PR in draft. No Rust compilation, recursive proof, actual Lean theorem proof, privacy guarantee or Bitcoin deployment has been demonstrated by this experiment. The Node runner and CI workflow reproduce the sparse-matrix pilot without Rust.
