# Transparent STARK final-compression route (M24 onward)

The [IPA MSM feasibility gate](NEXT.md#ipa-msm-feasibility-gate-projection)
showed that the transparent Spartan/IPA verifier cannot be disputed in
non-interactive BitVM2. Its terminal MSM over 540,672 generators projects to
about 588 TiB of Script. This route keeps transparency and BitVM2. An outer
transparent STARK attests that the Nova verifier accepted. BitVM2 then
disputes only the STARK verifier, whose size does not grow with the Nova
circuit.

## Why the linear work moves rather than disappears

Nova folds Pedersen-committed instances, so the final proof must open
`comm_W` and `comm_E`. A hash-based PCS cannot open a Pedersen commitment. Any
final SNARK therefore recomputes the n-term MSM, or proves that computation:
natively (IPA, the present design) or inside an outer proof. This route puts
it inside the outer prover. The disputed object becomes a fixed-shape STARK
proof. The prover pays Θ(n) non-native Pasta work, which garbled-snark-verifier
M12 measured: the SP1 6.9 wrapper of the complete Nova verifier at k=1 costs
72.3 × 10^9 instructions, 71% of it decompressing the key's points. A pinned
affine key encoding would remove most of that, leaving about 18.1 × 10^9.
Recorded SP1 CPU provers peak at 19–30 GiB, above the 16-GiB proving budget.

## M24: measured hash primitive

The dominant cost of a STARK verifier is hashing. M24 measures the pinned
upstream BitVM implementations (`c620dbf`) in the pinned interpreter. It uses
Tapscript rules, minimal encoding, the 1,000-item stack limit and OP_CAT off,
and checks each case against a reference digest and a changed digest. Code:
[stark-hash-oracle](stark-hash-oracle), workflow
`bitvm2-nova-stark-hash.yml`. Hosted result:
[run 42377941685](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42377941685)
on `de7a3f5`, report SHA-256
`3857d5c61dbd21fff470e1288bab6ef648d10e2c3ebf43a935cee5c150d274bd`.

| BLAKE3 message | Blocks | Optimized Script bytes | Unoptimized | Peak stack |
| ---: | ---: | ---: | ---: | ---: |
| 32 B | 1 | 76,761 | 77,843 | 644 |
| 64 B (one Merkle node) | 1 | 76,695 | 77,777 | 644 |
| 136 B (34 KoalaBear elements) | 3 | 228,934 | 232,181 | 680 |
| 208 B (52 elements) | 4 | 304,980 | 309,310 | 698 |
| 1,024 B (largest supported) | 16 | 1,217,626 | 1,234,952 | 914 |

Every BLAKE3 case accepted the reference digest and rejected the changed one.
One block fits a single leaf under the repository's 100,000-byte cap.

The SHA-256 rows did not pass this harness's reference check for 32, 64 or
80 bytes: the correct digest was not accepted either. Their compiled sizes
(512,428 / 1,060,200 / 1,034,930 bytes) are recorded in the report but are
not claimed as measured costs. The failure is in this harness's input or
output ordering, or in upstream; it is unresolved.

## Projection for the counted final proof

[stark_route_projection.py](stark_route_projection.py) applies the measured
block cost to the SP1 6.9 compressed shape counted in M12: 1,272,893 bytes,
124 queries, 33,976 Merkle compressions and 39,727 permutations. It assumes
BLAKE3 in place of Poseidon2, one block per permutation.

| Quantity | Value |
| --- | ---: |
| Hash Script, lower bound | 3,046,862,265 bytes (2.84 GiB) |
| Compared with the IPA MSM projection | about 2.1 × 10^5 times smaller |
| One 22-node Merkle path in one leaf | 1,687,290 bytes |
| WOTS assertion of the proof bytes | 63,644,800 bytes |
| Standard transactions for that assertion | 160 |
| Largest proof asserted in 1 / 10 standard transactions | 8,000 / 80,000 bytes |

The route turns an impossible MSM into a large but bounded hash workload.
The new binding constraint is assertion data. Every value a disproof reads
must be WOTS-signed, at 200 bytes per 32-bit word (measured in M23). That
includes the final proof's bytes and every chunk-boundary digest. A
1.27-MB proof alone needs 160 standard transactions. Splitting each Merkle
path into one-block leaves would add another 1.6 KB of signatures per
intermediate digest. Chip constraint evaluation, the jagged evaluation and
extension-field arithmetic are excluded, so these figures are lower bounds,
not a fit.

## Next milestones

1. **M25: a size-targeted final layer.** Specify a transparent recursion layer
   over the SP1 compressed proof, for example a Plonky3 STARK with a BLAKE3
   MMCS. Choose its blowup, grinding and query count for a proof of at most
   about 80 KB (10 standard transactions). Count its exact shape (queries,
   Merkle depth, leaf widths, field operations) natively, without proving, and
   rerun this projection on it, assertion and chunk-boundary words included.
2. **M26: Script Merkle-path chunking.** Measure BLAKE3 Merkle-path leaves
   under the actual chunking, with digests asserted only at the chosen
   boundaries, and the extension-field fold arithmetic, under unchanged caps.
3. **M27: outer prover.** Pin an affine key encoding and measure the wrapper
   proof's time and RAM against the 16-GiB budget. This is the first step in
   this route that needs a proving job.

Proving the header chain directly in the same zkVM (M12 control C) was 14×
cheaper than wrapping a k=1 Nova proof. That would leave Nova as the off-chain
fast path. It changes the objective, so it is Patrick's decision, not part of
this route.
