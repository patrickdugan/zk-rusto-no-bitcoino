# ZKL-NOVA-13: constrained shared-path dependent memory

2026-11-25. ZKL-NOVA-12 hosted four-proof gate PASS. ZKL-NOVA-13 synthesized shared-path R1CS and authenticated sample gate PASS. Full 957-row hosted folding/compression comparison submitted, not yet observed.

## Verified independent-path baseline

Run https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45591941642; job 139128101998; source head 02138873f638aa0a45af04ba24303929f86c9340. The full exporter, all 957 frontend checks, four recursive proofs and four compressed proofs passed. The exact logged receipt is retained in nova12_hosted_receipt.json.

| Case | Rows | Mean steady fold (s) | Compression (s) | Compressed verify (s) | Compressed bytes |
|---|---:|---:|---:|---:|---:|
| polymorphic_identity | 52 | 0.3242078931 | 12.813180738 | 0.265937264 | 11312 |
| dependent_application | 340 | 0.3442668560 | 13.011001206 | 0.264605153 | 11312 |
| beta_conversion | 276 | 0.3462919954 | 12.837859506 | 0.264247907 | 11312 |
| impredicative_predicate_identity | 289 | 0.3482676199 | 12.828317443 | 0.266264066 | 11312 |

One shared verifier key: 58,415,656 bytes. Public parameter setup 4.851443963 s; compression setup 0.391476363 s. Primary/secondary constraints 52,620/10,349. Recursive object 4,335,544 bytes per proof. All 48 changed-initial-state or step-count verifier checks rejected, 8 malformed local steps rejected, and all four unfinished prefixes refused admission. No hiding claim. Timing comparisons across different hosted jobs must account for machine variation.

## Shared-path relation

The 25 logical rule checks, fourteen ten-bit record fields, ten read slots, leaf and structural term digest domains, depth-nine tree, append relation and public four-field state are unchanged. Raw addresses and active flags are determined by the semantic rule selectors. Each slot still hashes its exact address, record, term digest and salt into a leaf. Only the nine-level historical membership path computation is replaced.

Represent the active leaf key by its address in [0,511]; the inactive key is 512, with zero digest. A fixed bubble sorting network sorts ten key/digest pairs. For keys a,b in [0,512], bit 10 of a-b+1023, constrained by an eleven-bit decomposition, is exactly the strict comparison a>b. A switch computes d=s*(b-a) per field and outputs a+d,b-d; a derived Boolean comparison controls the switch. This preserves every raw pair. Adjacent equal active keys must have equal leaf digests before duplicates are masked to zero. Stable compaction uses s=(1-active_left)*active_right to exchange adjacent inactive/active records and retains the order of active records. The result is a sorted unique active prefix.

For each level, constrain the bounded index and parity of each child. In sorted unique order, a child is paired with its next neighbor precisely when it has even index and the next active index is one greater. Those two siblings produce one parent group; every other active child produces one singleton group requiring a missing sibling digest. The sibling input must be zero for paired, consumed, or inactive records. Parent index is the integer quotient of child index by two, masked by group activity. The left/right inputs are constrained to the correct order. Each level stably compacts its groups before hashing. All tail records beyond the parent capacity are constrained to zero, so no active group can be dropped.

For K distinct reads in a depth-d tree, the number of active parent nodes at level l above the leaves is at most min(K,2^(d-l)). Summing for l=1,...,d gives the exact worst-case parent capacity. With K=10,d=9 this is 10+10+10+10+10+8+4+2+1=65. A fixed schedule hashes every parent slot and masks inactive output digests. The last active root must equal the prior state root. With no reads, the membership layer imposes no root condition, but the unchanged empty-leaf append relation still binds the old root.

Soundness sketch: sorting preserves all requests; dedup removes only equal address/digest aliases; each active child belongs to exactly one parent group; compaction preserves every group, and index/parity rules bind it to its unique parent. Induction through the levels gives authenticated paths from all required leaves to a common root, conditional on collision resistance and the constraint system's soundness. This is a bounded argument, not a formal Lean proof or an exhaustive malicious-witness audit.

## Observed synthesis and tests

| Metric | Independent (12) | Shared (13) |
|---|---:|---:|
| Read node hashes | 90 | 65 |
| All Poseidon hashes | 120 | 95 |
| Hash multiplication equations | 37440 | 29640 |
| Other equations | 3797 | 7031 |
| Total R1CS equations | 41237 | 36671 |
| Wires incl. ONE | 40448 | 35736 |
| Sparse matrix terms | 1019955 | 897078 |

Net reduction 4,566 equations, 11.07%, including the cost of sorting/deduplication/compaction. Expected explicit Rust StepCircuit size 36,679 after eight recursive state bindings. This is measured sparse-matrix synthesis; Nova augmented sizes, timing, key and proof bytes for the new matrix remain unmeasured.

The 957-row native commitment trace has 3,608 active raw reads, 3,189 unique within-row addresses, and 17,471 actual shared parent nodes before padding. Maximum raw and unique count both ten. Native activity counts are diagnostic; the fixed circuit executes 65 read-node hashes at every step, including padding, and continues to hash ten leaf slots. All four initial and terminal states exactly match the prior independent-path sample.

28 valid sampled assignments checked, covering all 25 tags and all four terminal judgments. 16 targeted mutations rejected (per-terminal wrong goal, sibling, salt or output root). Another 28 attacks rejected after regenerating auxiliary witness values from corrupted external inputs: four dirty-sibling empty read sets, 20 terminal payload/sibling/salt/root corruptions and four conflicting duplicate-address salt changes. These are targeted controls, not a full cryptographic soundness proof.

## Hosted comparison

```sh
node integrations/zklean-nova/dependent_shared.cjs
node integrations/zklean-nova/dependent_shared.cjs --full /tmp/dependent-shared-fixture
cargo +1.90.0 run --release --manifest-path integrations/zklean-nova/nova-smoke/Cargo.toml --bin dependent_shared -- /tmp/dependent-shared-fixture /tmp/dependent-shared-proof
```

The Node CLI pins the full Poseidon parameter fixture hash. Sandbox execution fetched the pinned repository fixture and checked its profile identity. Full mode streams each field assignment as a canonical 32-byte little-endian scalar file and checks the fixed R1CS. The Rust frontend independently checks genesis/goal/native Poseidon, checks every assignment, uses one shared Nova/Spartan key and folds, verifies and compresses all four certificates. Require the same cross-goal and incorrect-count rejection controls as 12. Preserve individual proof receipts, compressed payloads, shared verifier key, peak RSS and dependency lockfile. CPU job capped at 45 minutes, two build/Rayon threads; no GPU allocation. The source is uncompiled locally, and successful hosted verification remains a gate.

## Next

If the shared-path gate passes, compare actual prover time, memory and verifier key size with 12 rather than extrapolating from constraint counts. Retain the independent-path circuit as a conformance reference. Apply the append frontier optimization separately, with proof of equality of prior/new roots and a fixed shape; then add public constants and checked inductive recursors. Full Lean coverage, proof privacy, formal soundness, and BitVM settlement remain open. Fixture salts are deterministic. No GPU expenditure.

## Canonical sparse export repair (2026-11-25)

Initial hosted run 45595770231 completed sample reproduction, all 957 assignment checks and Rust compilation. It stopped before Nova setup at the strict Rust loader's nonzero-coefficient assertion. The JavaScript constraint emitter had retained explicit zero coefficients in otherwise valid linear combinations. Canonicalize each linear combination at emission (merge equal wire indices, reduce mod p, drop zeros, sort). This preserves the matrix relation and wire numbering; the local sample receipt reproduces every field except the sparse term count, which changes from 897096 to 897078. The Rust loader retains strict canonical checks. Rerun the complete hosted proof gate; no optimized cryptographic performance result is available from the failed run.
