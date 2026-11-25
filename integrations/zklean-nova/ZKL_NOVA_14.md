# ZKL-NOVA-14: single-pass append frontier

2026-11-25. Native full-capacity frontier conformance and sparse R1CS sample gate PASS. The full shared-path predecessor (13) is queued in hosted CI at run 45595770231. The frontier circuit has not yet been folded or compressed in Nova; the hosted job is a prospective gate. The verified independent-path reference remains ZKL-NOVA-12, run 45591941642.

## Invariant and state

The history is a depth-nine binary Merkle tree containing a prefix of n nonzero row commitments, with every unused leaf equal to zero. Let Z_l be the canonical empty-subtree root of height l, with Z_0=0 and Z_{l+1}=H(Z_l,Z_l). The frontier F_l, for 0 <= l < d, holds the complete subtree corresponding to bit l of the binary decomposition of n if that bit is set, otherwise zero. The corresponding subtree is the rightmost occupied block of size 2^l in the canonical decomposition of the prefix.

The recursive state is now (history_root, occupied_count, public_goal_digest, sealed, F_0, ..., F_8), arity 13. Genesis pins the original empty-tree root, count zero, the independent public theorem digest, seal zero, and all nine frontier slots zero. Every state coordinate is bound at both ends of the Nova StepCircuit. The goal and terminal admission rules are unchanged.

The frontier/root relationship is an inductive invariant of a *verified chain from pinned genesis*. The new step does not separately authenticate an arbitrary supplied prior root against the supplied frontier. In particular, an isolated satisfying row with a free initial state is not a proof of the invariant. The verifier must use the prescribed genesis, not a prover-selected initial state. For a full tree (n=512) the slots are zero and the root is the complete tree root; the depth-nine input count range prevents further append. The fixture theorem proofs stop below capacity.

## One-pass transition

Let b_l be bit l of n and c_l the binary carry into level l, initialized c_0=1. Let h_0 be the new nonzero row commitment. The update is
```
c_{l+1} = c_l b_l
F'_l = (1-c_l) F_l + (c_l-c_{l+1}) h_l
left_l  = (1-b_l) h_l + b_l F_l
right_l = (1-b_l) Z_l + b_l h_l
h_{l+1} = H(left_l, right_l)
```
The input slots with b_l=0 must be zero. All bits and carries are constrained; outputs must equal the displayed arithmetic expressions. The final root is h_d. The count increments by one, and the goal, logical row checks, seal rule, nonzero leaf check and all shared historical-read authentication constraints remain as in 13.

Proof sketch: at level l, h_l commits to the subtree of height l containing the appended leaf and its occupied siblings and padded unused leaves. If b_l=1, F_l is precisely the left sibling; otherwise the right sibling is the empty subtree Z_l. Thus the hash equals the root of the correct larger subtree. If c_l=1, all lower bits of n are one, so h_l is a *complete* subtree, suitable for installing into the first zero-bit frontier slot or combining with the occupied sibling when b_l=1. A slot is retained if no carry reaches it, cleared if a carry consumes it, and filled if the carry stops there. This is exactly binary increment of the canonical prefix decomposition. Induction on levels proves the new root and frontier, and induction on steps from pinned genesis proves the recursive invariant. No extra old-empty-leaf path is required. This is a mathematical argument for the bounded relation; a mechanized proof and comprehensive adversarial audit are still open.

## Observed local synthesis

| Metric | Independent paths (12) | Shared paths (13) | Frontier (14) |
|---|---:|---:|---:|
| Read-node hashes | 90 | 65 | 65 |
| Append-node hashes | 18 | 18 | 9 |
| Total Poseidon calls | 120 | 95 | 86 |
| Hash equations | 37440 | 29640 | 26832 |
| Total R1CS equations | 41237 | 36671 | 33907 |
| Wires incl. ONE | 40448 | 35736 | 32964 |
| Sparse matrix terms | 1019955 | 897096 | 822076 |

The nine removed hashes save 2808 multiplication equations, with 44 extra non-hash equations for a net 2764-row reduction (7.54% relative to 13). Combined with shared paths, the reduction relative to 12 is 7330 equations (17.78%). The Rust bridge adds 26 state bindings, for an expected 33933 explicit constraints before Nova recursion overhead. The larger state arity will add overhead in the augmented circuit. Net prover speed, peak memory, key size and compressed proof size must be measured rather than inferred from raw R1CS counts.

Native conformance checked the frontier against a separate reference full-tree update at every one of the 512 prefix insertions through full capacity, including carries across all nine occupied slots. All 957 certificate-history transitions also agreed with the independently extracted frontier slots and reference root. All four initial and terminal four-field projections match 13 exactly. The existing all-tag deterministic sample (28 rows) checked every logical rule and every terminal judgment against the fixed synthesized matrix.

All 16 inherited targeted mutations and 40 regenerated-witness controls were rejected. The latter include four dirty sibling controls for empty read sets, 20 terminal payload/sibling/salt/root mutations, four conflicting duplicate-address salts, four dirty inactive input frontier slots, four corrupted output frontier slots, and four corrupted occupied input slots. These controls keep other public state coordinates fixed; they are not a proof of standalone arbitrary-state soundness. No coordinated-forgery exhaustive search was performed.

## Hosted gate

```sh
node integrations/zklean-nova/dependent_frontier.cjs
node integrations/zklean-nova/dependent_frontier.cjs --full /tmp/dependent-frontier-fixture
cargo +1.90.0 run --release --manifest-path integrations/zklean-nova/nova-smoke/Cargo.toml --bin dependent_frontier -- /tmp/dependent-frontier-fixture /tmp/dependent-frontier-proof
```

The Node runner verifies the pinned Poseidon parameter file SHA-256. Local synthesis used the pinned repository fixture and checked profile identity. The hosted exporter streams and checks all 957 assignments. The Rust verifier independently recomputes the public goal and empty root, pins the zero frontier genesis, and binds every one of the 13 input and output state coordinates. It folds and compresses all four cases with one shared VK, verifies the unfinished prefix and rejects its admission, checks all 13 initial-state coordinate substitutions (including all nine frontier coordinates), and rejects two altered step counts for each recursive and compressed proof. Thus the proposed gate has 30 verifier mutation checks per case, 120 total, in addition to local malformed-step controls. Full hosted results are pending. Retain proof payloads, VK, receipts, lockfile and RSS. The 45-minute CPU-only job uses two build/Rayon threads.

The additional frontier coordinates are part of the recursive state; revealing them at the endpoint is another consideration for a future hiding wrapper. Deterministic fixture salts do not establish privacy. No Lean kernel compatibility, proof privacy, formal soundness, or Bitcoin settlement claim. The next kernel extension after the optimization gates is public constants and checked inductive recursor reduction; preserve the independent-path and shared-path versions as conformance references. No GPU allocation.

## Canonical sparse export repair (2026-11-25)

Initial hosted run 45597515328 completed sample reproduction, all 957 assignment checks and Rust compilation. It stopped before Nova setup at the strict Rust loader's nonzero-coefficient assertion. The JavaScript constraint emitter had retained explicit zero coefficients in otherwise valid linear combinations. Canonicalize each linear combination at emission (merge equal wire indices, reduce mod p, drop zeros, sort). This preserves the matrix relation and wire numbering; the local sample receipt reproduces every field except the sparse term count, which changes from 822094 to 822076. The Rust loader retains strict canonical checks. Rerun the complete hosted proof gate; no optimized cryptographic performance result is available from the failed run.
