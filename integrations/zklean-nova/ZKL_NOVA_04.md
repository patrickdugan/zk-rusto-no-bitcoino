# ZKL-NOVA-04: deterministic arithmetic routing

2026-11-25. Native arithmetic-equation model PASS; synthesized R1CS and actual Nova OPEN. No paid compute.

Reproduce with Python 3 standard library: `python3 integrations/zklean-nova/routing.py`.
Raw output: `gzip -dc integrations/zklean-nova/routing_results.jsonl.gz`.
Source blob 2dbcb65e2da80456150a7c2259f74405524ea35b; raw JSONL Git blob hash bb18e81384d74120a6e2cca804c9139da1fc46f7.

## Scope

This pilot replaces dynamic compaction in 03 with a fixed switch topology. It evaluates multiplication/equality equations over a Pasta-sized prime field and counts them as R1CS-compatible equations. The host computes witness values and evaluates equations; it does not export sparse R1CS matrices or use an independent malicious-witness solver. SHA-256 reduced to the field is an external hash oracle, with synthetic leaf digests i+1. It changes the history-root fixture from 03 to isolate the one-field digest case. There is no constrained hash, theorem-admission circuit, hiding salt, actual Nova proof, or Bitcoin settlement claim.

## Relation

Inputs are K activity/address/digest records bound by the future semantic circuit. Enforce activity Boolean, canonical inactive record, bounded index, and active index below the prior row count. Sort via a Beneš switch network: each switch uses one Boolean bit s, one product per routed field x'=x+s(y-x), and the second output y'=x+y-x'. Hence all outputs are a permutation of the original complete records, including pads. Topology is fixed; recursive bipartite edge coloring is witness generation only. Sorted records have active-prefix and bounded nondecreasing address-gap constraints. Equal adjacent active addresses require equal digests; a zero test constrains the duplicate bit (x*inv=1-z, x*z=0). Mask duplicate records to zero and retain unique heads. The standard version compacts them using a second network. Packed version routes key=activity+index and digest; canonical padding key=0, active keys 1..2^D, so zero-test decoding is injective. It routes sparse heads directly to the first parent layer.

At each level route every child record to a left or right slot of one of the fixed parent pairs. Active lane address equals 2p or 2p+1 respectively; parent indices bounded, strictly increasing among active parents. Parent activity is OR of lane activities. One missing-sibling field is used exactly when one lane is active; it is zero otherwise. Compute ordered hash inputs using activity selectors and mask inactive parent digest to zero. Extra network outputs must be canonical zero. The last active root must match the pinned history root; empty request sets leave the pinned root unconstrained by reads (the enclosing transition must preserve it).

Conditional on a sound implementation of these equations and collision resistance of the actual hash, switches preserve all input records, dedup preserves each distinct address/digest, and each child is consumed exactly once into a parent at the correct address. Induction through layers authenticates every required request under the same root. The witness generator's sorting/branching is not part of the verifier relation; translating this evaluator into independently assigned, constrained wires is an outstanding gate.

## Results

155 permutation cases (all permutations for N<=4, randomized larger powers of two); 228 random routing cases, each checked in both multiproof modes and independent paths; nine targeted invalid cases in both multiproof modes rejected (18/18). Tests cover nonboolean switch, parent address, sibling digest, conflicting aliases, out-of-history address, nonboolean activity, dirty padding, incorrect digest, and wrapped address. Depth-17 tree with 100,000 occupied leaves; 36 single-batch configurations (B=16,64,256; independent, standard Beneš, packed Beneš; chain-style, scattered, entropy, and empty request patterns). Each uses five raw request slots per row. This is a single-batch fixed-shape benchmark, not a re-run of all 100k trace transitions. Counts are identical across the four access patterns for each profile.

| B | K | Independent equations | Standard Beneš equations | Packed equations | Independent hashes | Shared hashes |
|---:|---:|---:|---:|---:|---:|---:|
| 16 | 80 | 4678 | 129765 | 109154 | 1360 | 927 |
| 64 | 320 | 18598 | 522565 | 427794 | 5440 | 3071 |
| 256 | 1280 | 74278 | 1961285 | 1565778 | 21760 | 9727 |

The independent control authenticates every original raw request, reusing its bounded address bits to select sibling order with one product per level. All hash calls excluded from routing counts. Affine expressions are treated as wire aliases; implementation-specific allocation/equality overhead must be measured on the real backend. Packed mode lowers non-hash equations by 15.9%, 18.1%, 20.2%. At B=256, entropy sample had 1271 unique reads. For this shape, packed routing uses 1021957 layer-switch equations; this is the next optimization target.

For hash gadget cost h, total modeled authentication cost = routing equations + hash_slots*h. Packed break-even thresholds (strict): h>241.284, 172.729, 123.951 for B=16,64,256. At B=256,h=100 independent wins (2250278 vs 2538478); h=200 packed wins (3511178 vs 4426278); h=300 packed wins (4483878 vs 6602278). These are estimates before leaf hashing, write frontier, semantics, state commitments, and other common costs. No particular production hash cost asserted.

## Next gate

Use the existing Rust/Nova infrastructure or a pinned CI toolchain to synthesize independently assigned routing equations and a field-native hash, then compare actual constraint counts and prover memory. Start with B=16 plus smaller test shapes. Test malicious switch controls, missing/extra requests, duplicate alias conflicts, invalid activity/indices, cross-layer wire binding and bad hash witnesses. Choose independent paths if actual gadget cost is below threshold; do not commit to multiproof prematurely. Consider non-power-of-two Waksman routing and a monotone sparse compaction network to reduce the padded switch overhead. Verify the precise field and hash parameters and their security before real proving. Bind raw requests to the semantic checker, exact leaf encodings, pinned genesis, theorem, and terminal admission before any Nova theoremhood claim. Rust unavailable in this sandbox; retain draft status. No upstream source copied.
