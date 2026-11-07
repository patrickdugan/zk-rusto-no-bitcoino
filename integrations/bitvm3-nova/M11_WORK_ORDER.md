# M11 revision: verifier cost gate before header-scale garbled IPA

Decision recorded 2026-11-06 against fork revision
`a013dd5739368d4edc87a1b7f08b22886adf0a9b`.

## Immediate direction for the coding agent

This work order supersedes the instruction to finish a full header-size
Spartan/IPA garbled verifier before assessing feasibility. Pause that scale-up.
Keep bounded proof parsing, authenticated fixture import and native differential
verification moving. Preserve the M1-M10 components and their passing evidence.
A small IPA component can remain a conformance oracle; allocating header-scale
MSM graphs requires a measured cost decision first.

Work only in `patrickdugan/garbled-snark-verifier`, committing to its main as
previously authorized. Leave upstream BitVM unchanged. Local full-chain proving
remains paused. This file is a repository handoff; it does not cancel or message
an already-running external coding session.

The proof path must remain transparent through the final wrapper. Keep the
Pallas/Vesta Nova 0.76.0 baseline, existing headers/checkpoints and fold width k
unchanged while evaluating a separate final proof format.

## Step A verified-key inventory captured (source commit 596cb73)

Read [the k=20 fixture README](fixtures/bitcoin-header/README.md) and
[k20 inventory](fixtures/bitcoin-header/k20-testnet4-verifier-inventory.json)
before further implementation. Source proof: testnet4 NHT4, k=20, two
shards covering genesis to height 40 and then 80. The key stays off Git.
Its SHA-256 is
`9e94b9083b5be30e796e974218804214b7106284c071eeec9b15945735321727`,
length **500,333,512 bytes**. A bincode 1.x fixed-int mirror decoded the
key, consuming exactly all bytes, reusing Nova 0.76.0's public matrix,
Poseidon and commitment types.

| Actual recorded count | Primary/Pallas | Secondary/Vesta |
| --- | ---: | ---: |
| Padded rows and variables | 2,097,152 | 16,384 |
| Matrix A+B+C nonzeros | 9,409,295 | 126,487 |
| Matrix evaluation field multiplications | 25,110,046 | 302,126 |
| IPA s-vector field multiplications | 2,097,151 | 16,383 |
| IPA opening terms | 2,097,152 | 16,384 |

Total inventoried linear scalar work: **27,525,706** field multiplies.
Total IPA MSM terms: **2,113,536**. The corresponding M2 checked-mul
*proxy* price is 9,935,761,414,878 gates, or 158,972,182,638,048
ciphertext bytes (**158.97 TB decimal**) for one unreplicated circuit.
The 12 checked-point-adds-per-MSM-term sensitivity scenario yields
110,079,777,374,208 gates and 1.7613 PB. These proxy scenarios are
neither measured complete garbled circuits nor optimized lower bounds.

Native proof verification on the original machine was reported successful
for both 13,288-byte compressed proofs, including mutation rejections.
This repo now retains proof bundles and their receipts. Its
`real_header_proof_native` and `real_header_verifier_inventory` tests
**skip when NOVA_REAL_VK is missing**; a green GitHub job alone does not
reverify the real proof. The small CI fixture audit independently checks
the committed bundles, receipt hashes, full 17-field-state continuity,
inventory arithmetic and mutation detection. That audit performs
**no cryptographic proof verification**.

**Open reproducibility gates:** deterministically regenerate the k=20
key using `vk-export 20 --network testnet4` and match the recorded
SHA-256; acquire a controlled CI/keyed test arrangement that actually
executes the native proof verification; capture all Poseidon/NIFS operations
and installed Nova IPA source hashes. Record explicit statement binding
(network, k, steps, checkpoint and final tip).

**Next decision:** prototype a transparent outer argument over the complete
native verifier, with binding to the authenticated key and public state,
at a small k first. Alternatively design and test a commitment-consistency
proof from the original Pedersen commitments to the proposed hash PCS.
Never treat a WHIR/BaseFold-only opening as a native Nova proof replacement.

## Evidence and scope

M2 measured 360,963 non-free gates per checked Pasta multiplication predicate.
M3 measured 4,340,269 per complete checked Pasta point-addition predicate.
Both emit 16 bytes of ciphertext per non-free gate in this implementation.
Those predicate costs include validity checks; they are proxy prices for a
naive composition, not lower bounds for an optimized arithmetic kernel or MSM.

The installed Nova 0.76.0 `spartan/snark.rs` retained in the M10 evidence shows
`verify` evaluating every nonzero in A/B/C at the derived points before calling
`EE::verify`. Source SHA-256:
`c67d985f77e50b15a0bf4675d92b6766a0b2d2a3a3f018e15bbeac85cc14b69f`.
The upstream IPA source inspected for this revision builds n scalars and calls
`CE::commit` against n generators. Retain and hash the exact installed 0.76.0
IPA, commitment and preprocessing sources in the next native report too; do not
substitute a moving upstream branch for the dependency identity.

The user reports a k=20 proof with about 1.7 million constraints, a padded
length 2^21, about 10^7 matrix nonzeros and a roughly 500 MB verifier key. Treat
these as reported sizing inputs until the actual key/proof receipt is captured.
The existing header README records k=1 at 97,049 primary constraints and k=10
at 842,330. Linear extrapolation gives k=20 at 1,670,420, which is compatible
with that report but is not a new measurement. Measure witness dimensions,
padded commitment lengths and nonzeros independently for BOTH curve engines.

### Conditional cost arithmetic

| Supplied scenario | Non-free gates | Ciphertext for one instance |
| --- | ---: | ---: |
| 20,000,000 generic multiplication predicates | 7,219,260,000,000 | 115,508,160,000,000 bytes (115.50816 TB) |
| Sensitivity: 12 checked point-add predicates per each of 2^21 terms | 109,226,445,766,656 | 1,747,623,132,266,496 bytes (1.747623 PB) |
| 100,000,000 non-free gates | 100,000,000 | 1.6 GB |
| 1,000,000,000 non-free gates | 1,000,000,000 | 16 GB |
| 10,000,000,000 non-free gates | 10,000,000,000 | 160 GB |

TB/GB/PB here are decimal. The MSM row is a sensitivity scenario, not an
implemented schedule, benchmark, or minimum cost. An n-term MSM need not be
implemented as n separate scalar multiplications. Fixed-base precomputation,
shared validation, coefficients 0/+1/-1, sparse reuse and fused arithmetic can
change constants. Count the proposed circuit, including scalar construction.
Tensor-structured dot products can sometimes be factored; do not automatically
price each as a dense generic loop. None of these optimizations proves the
header-scale design fits a practical resource envelope.

A standard Keccak-f[1600] permutation has 24*1600 = 38,400 chi ANDs under
free XOR/NOT/rotations. This is an analytic primitive count, not a new measured
repo result. One million such permutations would already emit 614.4 GB at the
same accounting. Count all Merkle, transcript and challenge-sampling hashes,
with their actual hash functions and padding; they are not automatically all
Keccak and they are not free.

A 9 GiB RAM ceiling limits live state. It does not imply a maximum total gate
count. Report separate caps for live RAM, temporary disk and wall time, along
with communication and total setup work. Generated and retained cut-and-choose
instances need separate counts. Their counts must come from a security analysis.

## Final-proof compatibility comes first

Preprocessing Spartan removes the explicit full A/B/C evaluation from the
outer verifier algebra. When its evaluation engine is still IPA, the linear
opening remains. The inspected upstream `ppsnark` pads its representation using
matrix nonzero counts as well as circuit dimensions, so measure its actual
opening vector length; it can exceed the non-preprocessing length.

WHIR/BaseFold offer transparent hash-based polynomial commitment paths worth
benchmarking. They are not drop-in authenticators for the Pedersen commitments
already carried by a Nova proof. Nova's evaluation-engine interface verifies
against the commitment type supplied by the engine's commitment scheme.
Showing that a polynomial opens correctly under a new Merkle root alone does
not prove that it is the polynomial bound by Nova's original W/E commitments.

Choose and specify one of these architectures before claiming compatibility:

1. **Wrapper of the existing native verifier.** A transparent outer argument
   proves execution of the complete, version-pinned Nova verifier for the exact
   proof and authenticated key/statement. It moves the large MSM/matrix workload
   into the outer prover. Its proving trace and RAM costs must be measured.
2. **New compression/decider with a binding proof.** Use folded witness access
   and prove equality between the old homomorphic commitments and the new
   hash-committed witness, including the exact generators and any blinding
   terms. Account for all commitment-consistency work in proving and verification.
   Recovering an existing compressed proof alone is not sufficient to recompress
   its hidden witness. Document which recursive checkpoints/witnesses are needed.

A fresh hash-based header proof is also a possible separate research branch.
Label it as a new proof pipeline and re-establish its header statement and
checkpoint guarantees. It is not a re-encoding of an existing NHC1/NHT4 proof.
A hash wrapper does not by itself remove discrete-log assumptions from an
underlying Nova proof that it merely verifies.

Keep the NIFS check in the cost accounting until the architecture assigns its
responsibility. In a complete outer wrapper, it is checked by that wrapper's
prover and need not be duplicated outside it. A split design must bind its
folded commitments and public state to the other proof. Current NIFS/Poseidon
size estimates remain unmeasured.

## Next native experiments, in order

### A. Capture the existing proof and operation inventory

Import the actual k=20 receipt with proof/key digests, network, steps, start
state and expected final state. Retain the resolved lockfile and source hashes.
Verify the original bundle natively with all statement checks. Count n, matrix
nonzeros, scalar operations, each MSM's length and all hash permutations on both
engines. Start with an existing small proof; no full-chain proving is authorized.

The current non-preprocessing/IPA path and ppsnark/IPA are diagnostic baselines.
A ppsnark/IPA timing improvement alone is insufficient to pass the garbled-cost
gate. Recompression uses the proper proof type, keys and witness/checkpoint.

### B. Test a transparent candidate and its binding boundary

Build the smallest end-to-end native prototype of the chosen architecture.
A WHIR/BaseFold opening microbenchmark is useful but cannot stand in for a
complete wrapper or commitment-equality proof. Require wrong-key, changed-tip,
wrong-network and swapped-commitment rejection. Add an explicit test where a
valid new-PCS proof for witness W' is paired with an old commitment to W.

Freeze security parameters, including claimed soundness and any conjectures,
base/extension fields, hashes, queries and grinding. Count the COMPLETE verifier,
including decoding, range/reduction checks, public-input binding and the
commitment-consistency mechanism. Small-field arithmetic must count extension
operations and non-native Pasta/curve emulation inside the prover.

### C. Garble the candidate verifier only after native counts pass

Measure a minimal primitive for every operation that still lacks a gate price.
Map actual counts to emitted ciphertext and protocol replication costs. Provide
counts separately for canonical admission and already-validated internal values.
Benchmark native proving under a real 9 GiB OS limit only after the operator
resumes local experiments. Treat CI and sandbox measurements as their own hosts.

A pass needs a real proof, native soundness checks, complete counted verifier,
explicit statement/commitment binding, and budgets for time/disk/communication.
Unmeasured operations and an unproved commitment bridge make the decision
incomplete. Do not infer end-to-end feasibility from a PCS-only test.

## Cost calculator

`cost_envelope.py` performs integer accounting for supplied operation counts.
It never launches proving or garbling. Unknown operation prices remain explicit;
it never certifies full-verifier coverage or derives a gate limit from RAM.

```sh
python nova-bitvm3/test_cost_envelope.py
python nova-bitvm3/cost_envelope.py --pasta-muls 20000000
python nova-bitvm3/cost_envelope.py --point-adds 25165824
python nova-bitvm3/cost_envelope.py --other-nonfree 1000000000 --ram-gib 9
python nova-bitvm3/cost_envelope.py --unknown smallfield_extension_mul --single-stream-cap-bytes 2000000000
```

The helper's 11 Python tests passed in the assistant sandbox. This revision
performs no Rust/cryptographic benchmark and changes no verifier equations.

## Source references

- [M2 costs](../docs/nova-bitvm3-m2-radix4.md)
- [M3 predicate scope and costs](../docs/nova-bitvm3-m3-results.md)
- [M10 proof boundary and pinned source hashes](../docs/engineering/nova-bitvm3-m10-results.md)
- [Header baseline](https://github.com/patrickdugan/zk-rusto-no-bitcoino/blob/feat/nova-testnet4/integrations/nova-header-chain/README.md)
- [Upstream IPA implementation inspected](https://github.com/microsoft/Nova/blob/main/src/provider/ipa_pc.rs)
- [Upstream preprocessing implementation inspected](https://github.com/microsoft/Nova/blob/main/src/spartan/ppsnark.rs)
- [Evaluation-engine commitment contract](https://github.com/microsoft/Nova/blob/main/src/traits/evaluation.rs)
- [WHIR paper](https://eprint.iacr.org/2024/1586)
- [BaseFold authors' project page](https://www.basefold.info/)
