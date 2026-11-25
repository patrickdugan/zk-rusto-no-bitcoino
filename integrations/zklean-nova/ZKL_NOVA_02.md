# ZKL-NOVA-02: sequential append frontier

2026-11-25. Native memory conformance PASS; fixed hash schedule PASS; actual R1CS/Nova OPEN.

## Reproduce

Python 3.10+ standard library:
    python3 integrations/zklean-nova/frontier.py 100000
    python3 integrations/zklean-nova/block_frontier.py 100000

Both use SHA-256 with the same leaf/node encodings and deterministic synthetic fixtures as ZKL-NOVA-01. They independently implement sparse reference trees, check roots at every batch boundary and authenticate all distinct historical reads. The tests exercise the memory layer only: semantic row validity is the responsibility of model.py and ultimately the kernel circuit. The leaf values are fixture commitments, not private proof receipts. Deterministic salts do not provide hiding. No external compute was allocated. Rust/cargo were unavailable in the current sandbox.

## Append invariant

For depth D, occupied prefix length n and the bit decomposition n = sum_k 2^k b_k, slot F_k holds the complete aligned subtree of length 2^k in the canonical binary partition of [0,n) exactly when b_k=1; all other slots are canonical empty markers. Include F_D for the full tree. Let Z_0 be the empty leaf and Z_{k+1}=H(Z_k,Z_k). Starting a_0=Z_0, set a_{k+1}=H(F_k,a_k) if b_k=1, or H(a_k,Z_k) otherwise. For n<2^D, a_D is the original sparse tree root. At full capacity use F_D.

Append a leaf by merging the occupied slots encountered by binary addition, clearing each consumed slot and inserting the resulting subtree at the first zero bit. The invariant follows by induction, since a carry combines adjacent, equally sized subtrees in canonical order. For N appended leaves the number of occupied-subtree merges is N+popcount(n_start)-popcount(n_end). Existing rows retain their indices. The frontier root equals the reference tree after each update.

For 100,000 new rows after 4 genesis rows, depth 17, the carry count is 99,994. Boundary reconstruction costs 17 hashes per batch. Original per-row append witness verification costs 34 internal hashes (empty-path verification plus updated-root calculation). Table counts exclude leaf hashes, constant zero-subtree construction, terminal membership proof and genesis setup; historical reads cost 17 hashes per distinct external index. A Nova state must pin the starting frontier, bind the theorem and environment, and maintain the root invariant at every transition. A standalone step verifier that accepts an externally supplied state must additionally recompute or authenticate its old frontier/root linkage.

| Workload | B | Historical reads | Original total hashes | Frontier total hashes | Frontier write hashes |
|---|---:|---:|---:|---:|---:|
| chain | 16 | 31249 | 3931233 | 737477 | 206244 |
| chain | 64 | 7814 | 3532838 | 259403 | 126565 |
| chain | 256 | 1954 | 3433218 | 139859 | 106641 |
| scatter | 16 | 81129 | 4779193 | 1585437 | 206244 |
| scatter | 64 | 57546 | 4378282 | 1104847 | 126565 |
| scatter | 256 | 51229 | 4270893 | 977534 | 106641 |

132 randomized transitions over depths 1..10; 12 targeted and 10 full-capacity rejections. All six 100k runs checked root parity at every batch and authenticated the listed historical reads.

## Fixed aligned block schedule

Use B=2^b and h=D-b. Start with an empty tree and include the four exact public genesis leaves in the first block (the final integrated circuit must explicitly check those leaves). Within each block build its complete binary subtree, and run a fixed h-level carry schedule over the upper frontier, computing a candidate merge at *every* level. Boolean carry and count bits select the correct updated slots. Reconstruct the root with h further hash calls, selecting the full-tree slot at capacity. Per step, exactly B-1+2h internal hashes are evaluated. The initial state is pinned. The prior root invariant is inherited from the previous step, not recomputed in the IVC transition count.

The final block may contain fewer than B active rows. Inactive leaves must be canonical empty leaves, all active positions precede inactive positions, and a partial block must seal. Seal also prevents any further transition, including at full capacity. Count real rows separately from physical blocks. A finalized proof must bind the final active judgment, its position n-1, the pinned goal, and empty context; the present model checks terminal membership only. Do not disclose real row count or raw frontier state if theorem proof size privacy is required; design a hiding final wrapper and pad to a public capacity schedule.

| Workload | B | Steps | Historical reads | Fixed writes | Total internal hashes |
|---|---:|---:|---:|---:|---:|
| chain | 16 | 6251 | 31250 | 256291 | 787541 |
| chain | 64 | 1563 | 7810 | 132855 | 265625 |
| chain | 256 | 391 | 1950 | 106743 | 139893 |
| scatter | 16 | 6251 | 81139 | 256291 | 1635654 |
| scatter | 64 | 1563 | 57556 | 132855 | 1111307 |
| scatter | 256 | 391 | 51229 | 106743 | 977636 |

The first block now includes genesis; hence slight differences in historical reads/step count versus the unaligned pilot. The fixed write count includes genesis, whereas the previous write control excludes it. These operation counts are exact for the modeled schedule, excluding leaf hashes, selector/range constraints, state binding, terminal membership and historical-read slot padding. 185 small-tree cases spanning depths 1..8 and all block sizes, 1,411 transitions, 185 sealed-continuation rejections and 12 targeted rejections. All six large runs checked reference-root equality and historical openings. Native run receipts are included; times include reference tree maintenance and witness preparation, so are not optimized proving times.

## Next gates

- Synthesize a field-native hash and checked boolean/range/select rules, then measure actual Nova constraints for B in {16,64,256}. Include immutable D,b, pinned genesis, explicit root-state linkage, count bounds, prefix activity, canonical inactive slots and terminal checks.
- Historical reads now dominate the scattered trace. Native deduplication uses sets; it is not a fixed-size constrained lookup argument. If K distinct historical reads are provisioned, independent paths cost D*K hashes regardless of observed reuse. A sparse Merkle multiproof can share internal nodes. The maximum number of distinct active parents is bounded by sum_{l=0}^{D-1} min(2^l,K), before shape, ordering and boundary-sibling constraints. Measure actual worst-case padded cost, not just average compressed proof length. Compare unique-leaf and position binding, collision/alias attacks, and high-entropy traces; do not infer fixed historical-read savings from native sets.
- Integrate the nine-row type/lookup/judgment checker, then dependent type theory. Use a canonical field-safe leaf encoding, domain separation and hiding commitments; prove final theorem admission from pinned genesis. No reuse of upstream code without checking permissions.
- Fold and verify an actual Nova proof, record payload and memory, then investigate the BitVM3 verifier. No Groth16 dependency.

Decision: continue CPU-only memory optimization; retain draft PR #35. This is a native fixed-schedule model rather than a Rust implementation or actual recursive proof. Depth 17 imposes a finite capacity. The synthetic traces are not representative Lean/Mathlib benchmarks.
