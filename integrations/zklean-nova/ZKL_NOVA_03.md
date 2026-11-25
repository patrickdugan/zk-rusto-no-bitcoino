# ZKL-NOVA-03: shared-path historical authentication

2026-11-25. Native relation and hash-slot bound PASS. Actual arithmetic routing and Nova folding OPEN. No paid compute.

## Reproduce

Python standard library, run alongside frontier.py and block_frontier.py:

    python3 integrations/zklean-nova/multiproof.py 100000

The source matches the tested sandbox file (Git blob adf36939720fd75852be6f072ee40a8090694cde). The JSONL receipt records every completed configuration. SHA-256 is a native reference hash. Rust/cargo are unavailable in this sandbox.

## Relation and soundness argument

Pin the prior history root R, prior occupied prefix n, depth D and required read map A (address -> leaf digest). The eventual kernel must derive A from all actual historical references and bind the digest to the canonical row encoding and private salt. The current verifier takes A as caller-bound input; it does not independently check certificate semantics. Duplicate requests can use one opening only when their address and payload agree.

Sort unique requested addresses, all in [0,n). At each level consume child nodes in increasing index order. If the next two children are siblings, combine their digests and consume both. Otherwise require the missing sibling digest and consume one. The claimed parent index must be the child's integer index divided by two (floor), and the mask must match exactly the supplied children. Require complete consumption, canonical dummy rows, and a single root equal to R for nonempty requests. Zero requests require all witness slots inactive and leave the already pinned root unchanged.

Induction on height: every active output digest is the ordered hash of its two child digests. Every original requested leaf has a unique path to the resulting root; all such paths share any common ancestor. Given collision resistance, canonical address-bound leaf commitments and a pinned root, this authenticates the required leaf digests. This is a native soundness sketch; it is not a proof that an R1CS realizes the relation.

## Exact worst-case schedule

For K unique requested leaves in a depth-D complete binary tree, there are at most min(K,2^l) distinct active nodes at depth l measured from root. Each active internal node takes exactly one hash. Therefore M(D,K) = sum_{l=0}^{D-1} min(K,2^l). This is tight: take leaves floor(j*2^D/K) for j=0,...,K-1. At a level with at most K nodes these leaves hit every interval, and at a level with at least K nodes they occupy distinct intervals. All level bounds are attained simultaneously. For K<2^D and m=floor(log2 K), M = 2^(m+1)-1+(D-m-1)K; for K=2^D, M=2^D-1. For actual nonempty sets, the number of supplied missing-sibling digests is H-(K_actual-1), because every two-child merge reduces the active count by one; exactly K_actual-1 such merges occur.

Fixed mode pads each level to its corresponding bound. It hashes every parent slot, including dummy slots; active prefix and complete child consumption are checked. Across 510 depth/capacity combinations (D=1..8, every K including full capacity), evenly spaced leaves attain the bound. Another 256 randomized cases compare independent paths and padded vs unpadded results; 16 targeted malformed witnesses are rejected (wrong root, historical limit, missing/extra request, wrong order/duplicate/payload, noncanonical padding, modified sibling, bad mask/index, early truncation, wrong layer length). Includes empty request sets.

At D=17 and K=5B:

| B | K | Independent slots D*K | Shared slots M | Shared write slots (02) | Shared total |
|---:|---:|---:|---:|---:|---:|
| 16 | 80 | 1360 | 927 | 41 | 968 |
| 64 | 320 | 5440 | 3071 | 85 | 3156 |
| 256 | 1280 | 21760 | 9727 | 273 | 10000 |

Five reads per row is the chosen memory workload bound, not a proven bound for a full zkLean kernel. The largest observed read set for chain/scatter is much smaller, but K is not chosen retrospectively. At B=256 the fixed read hash slot saving is 12033 per step (55.3%). The full fixed shared schedule for 391 steps is 3,910,000 internal hashes including writes, before leaf hashing, terminal membership, selectors, memory routing, range checks, and semantic constraints. Actual R1CS constraints and proving time are not measured.

## 100k-row results

Aligned block schedule including four public genesis leaves. Chain and scatter are the same synthetic proof traces as ZKL-NOVA-02. Entropy uses the same leaf fixture and five independently sampled unique prior indices per row (PRNG seed 20261125), regardless of logical validity. It is an access-pattern stress test, not an additional proof-of-theorem workload. All nine configurations passed variable multiproof checking on every block and frontier/root parity against the independent sparse reference tree. Fixed-slot verifier executed on the first two, every 127th, and final block (219 sampled block checks across all nine runs). Remaining fixed totals are arithmetic counts from the exact proven per-level schedule, not a fully executed fixed circuit trace.

| Workload | B | Max reads | Actual independent read hashes | Actual shared read hashes | Fixed shared read slots |
|---|---:|---:|---:|---:|---:|
| chain | 16 | 5 | 531250 | 223058 | 5794677 |
| chain | 64 | 5 | 132770 | 55747 | 4799973 |
| chain | 256 | 5 | 33150 | 13919 | 3803257 |
| scatter | 16 | 20 | 1379363 | 730189 | 5794677 |
| scatter | 64 | 51 | 978452 | 540167 | 4799973 |
| scatter | 256 | 158 | 870893 | 417963 | 3803257 |
| entropy | 16 | 80 | 8469060 | 4504368 | 5794677 |
| entropy | 64 | 320 | 8394736 | 3493884 | 4799973 |
| entropy | 256 | 1277 | 8161360 | 2507186 | 3803257 |

These are native counts and single-run wall times, not Nova performance. The benchmark verifies historical membership and appended root conformance, not actual dependent type theory, proof privacy, or Bitcoin settlement. Real Lean traces and fresh hiding salts remain necessary.

## Next gate: constrain the routing

The model uses Python sorting, branching, dynamic indexing, and compact active lists. These must be replaced by explicit fixed-shape arithmetic constraints. An initial baseline can use constrained index selections; its cost may be quadratic. A candidate more efficient circuit uses authenticated leaf requests sorted by address, checks equality of all aliases, and uses a permutation/compaction network at each level. One can instead prove that child-consumption records are a permutation of exactly the active child list using a properly transcript-bound multiset argument, including indices, digests, activity and multiplicity. Neither construction has been implemented here. At every level enforce strict ordering of active nodes, prefix activity, exact one/two-child consumption, mask parity and bounded parent/child indices, canonical dummy slots and root equality. Empty requests must not reset root. For a hash gadget of cost h, incremental routing cost versus independent paths must be below (D*K-M)*h to retain the predicted advantage (12,033*h at B=256). Measure it, rather than equating hash savings with total constraints.

For lower-read workloads, explore a fixed small public K profile or persistent authenticated cache. An overflow must be rejected or handled by a separately constrained continuation before admitting the block; it cannot silently omit references. A public profile/step schedule may leak upper bounds on proof size; enforce the privacy policy in the final wrapper.

Next: implement and synthesize the routing constraints, bind leaf digests to each semantic row and pinned environment/goal, then fold a concrete proof in the existing Nova stack. Preserve draft status pending actual cryptographic verification. No upstream source copied; verify reuse rights before porting zkLean code.
