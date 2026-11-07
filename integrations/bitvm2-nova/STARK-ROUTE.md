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

## M25a: final-layer size model

[final_layer_model.py](final_layer_model.py) models a FRI-based final STARK:
* KoalaBear base field, with degree-4 extension elements of 16 bytes;
* 32-byte BLAKE3 Merkle digests and a Merkle cap;
* one main, one auxiliary and one quotient tree;
* FRI with folding arity 2^a.

For each assumed final trace it searches blowup, grinding, arity,
final-polynomial length and cap for the smallest proof meeting a
conjectured-security target. The low-degree extension must stay within the
16-GiB proving budget. Script and assertion use the measured M24 and M23
prices. The trace of the in-circuit verifier for the SP1 compressed proof has
not been built, so its height and width are swept as assumptions.

| Final trace (rows x base columns) | Proof bytes, 100 bits | Standard txs | Hash Script | Proof bytes, 128 bits |
| --- | ---: | ---: | ---: | ---: |
| 2^16 x 64 | 46,088 | 6 | 79.7 MiB | 59,528 |
| 2^16 x 128 | 53,256 | 7 | 87.0 MiB | 66,888 |
| 2^16 x 256 | 65,416 | 9 | 97.4 MiB | 84,872 |
| 2^18 x 64 | 55,816 | 7 | 97.4 MiB | 73,736 |
| 2^18 x 128 | 67,656 | 9 | 113.2 MiB | 89,992 |
| 2^18 x 256 | 90,504 | 12 | 141.6 MiB | 113,864 |
| 2^20 x 64 | 84,616 | 11 | 152.1 MiB | 107,976 |
| 2^20 x 128 | 101,288 | 13 | 166.8 MiB | 134,216 |
| 2^22 x 128 | 190,088 | 24 | 314.1 MiB | 252,808 |

Every selected shape uses 20–24 grinding bits and FRI arity 16. Blowup falls
from 2^9 to 2^1 as the trace grows, because the 16-GiB low-degree extension
budget binds.

* **80 KB is reachable** for a final trace of at most 2^18 rows and 128
  columns at 100 conjectured bits, or 2^16 x 128 at 128 bits.
* **It is out of reach** at 2^20 rows or more under the prover budget.
* **Hash Script for such a final layer** is 80–170 MiB, inside the 1.25-GiB
  policy, versus at least 2.84 GiB for the SP1 compressed shape.
* **Security assumption:** conjectured security is queries × log blowup plus
  grinding. A Johnson-bound estimate needs about twice the queries (reported
  per shape as `proven_queries_for_100_bits`), which roughly doubles the
  proof bytes.

The model excludes:
* transcript hashing;
* Merkle multi-proof deduplication, which would shrink the proofs;
* chip constraint evaluation in Script.

So M25a decides which trace size must be hit, not whether the verifier fits.

## M25b: measured trace of the compressed-proof verifier

[sp1-shrink-shape](sp1-shrink-shape) builds SP1 6.9.0's shrink program exactly
as `ShrinkProver::new` does. That is the recursion circuit verifying one
compressed proof. It is built from the fixed compress-shape dummy input, so
its trace does not depend on which compressed proof is shrunk. The compiled
program's per-chip event counts are its trace heights. No setup or proving is
needed: the run took 2.94 s and 202 MB of peak RSS in WSL. The result is
[results/m25b-sp1-shrink-shape.json](results/m25b-sp1-shrink-shape.json),
SHA-256 `a3f3de9e47a5fe15b335fde79d144c55004c00266adb6689e851d8f0204b0460`.

| Chip | Rows | Main columns | Preprocessed columns | Main area |
| --- | ---: | ---: | ---: | ---: |
| Poseidon2WideDeg3 | 39,607 | 179 | 49 | 7,089,653 |
| ExtAlu | 198,809 | 12 | 8 | 2,385,708 |
| Select | 271,952 | 5 | 8 | 1,359,760 |
| MemoryVar | 165,505 | 8 | 4 | 1,324,040 |
| BaseAlu | 148,558 | 3 | 8 | 445,674 |
| PrefixSumChecks | 18,368 | 15 | 9 | 275,520 |
| MemoryConst | 123,294 | 1 | 6 | 123,294 |
| PublicValues | 1 | 1 | 10 | 1 |
| Total | | | | 13,003,650 (+ 8,462,401 preprocessed) |

The 39,607 Poseidon2 events agree within 0.3% with the 39,727 permutations
M12 counted independently from a real compressed proof. The tallest chip has
271,952 rows, just above 2^18.

Feeding the measured shape into `final_layer_model.py`:

| Final-layer layout | 100 bits | 128 bits | Hash Script | Prover LDE |
| --- | ---: | ---: | ---: | ---: |
| Stacked into 2^20-row columns (22 columns, as SP1's jagged PCS stacks) | 50,768 B (7 txs) | 67,760 B (9 txs) | 93.3 / 127.3 MiB | 11.0 GiB |
| Per-chip uni-STARK, chips padded to 2^19 (326 columns) | 118,288 B (15 txs) | 155,192 B (20 txs) | 175.1 / 239.6 MiB | 11.7 GiB |

**Conclusion:** one BLAKE3-committed final layer directly over the SP1
compressed proof meets the ~80-KB target, if it commits the trace stacked
rather than per chip. No additional shrinking recursion step is needed.

This is still the M25a model, now applied to a measured trace:
* The Johnson-bound estimate (22 queries instead of 11 at 100 bits) roughly
  doubles the stacked proof, to about 100 KB.
* A stacked layout needs a zerocheck and jagged-evaluation sumcheck in place
  of quotient openings. Those proof bytes, a few kilobytes, are not modelled.
* Transcript hashing and Script constraint evaluation remain excluded.

The 11-GiB low-degree extension fits the 16-GiB budget without sharding.
Committing the stacked columns in streamed chunks, the Groth16 sharding
method, would lower that peak further.

## Review corrections (2026-11-07)

A review of the "Spartan + hash-based PCS" alternative to the SP1 wrapper
raised four points, all adopted here.
* **The Pasta cycle helps one curve at a time.** Pallas coordinate arithmetic
  is native over the Vesta scalar field, but the Vesta-side MSM and the
  scalar-field work are not. One outer circuit needs non-native arithmetic
  somewhere, or two field-specific proofs and a binding between them.
* **The earlier 2^26-constraint figure was arithmetic, not a measurement.** It
  is replaced by the measurement below.
* **Basefold and WHIR are not drop-in replacements for Nova's folding
  commitment.** The design keeps Nova's folding intact and proves its
  verifier in a separate outer wrapper. That wrapper also needs a succinct
  treatment of the R1CS matrices, for example transparent preprocessing.
* **Transparent succinct proofs are not all hash-based.** Spartan has a
  transparent discrete-log option. A hash-based outer commitment is a design
  choice made for Bitcoin Script, not a necessity.

Both outer routes stay open: the SP1 STARK wrapper, and Spartan over R1CS with
a hash-based PCS. They are compared on measured gadgets.

## M26a: measured in-circuit IPA MSM (R1CS route)

[msm-gadget-bench](msm-gadget-bench) builds the IPA generator MSM's terms in
Nova 0.76's own frontend:
* the circuit field is the Pallas base field Fp, so Pallas points are native
  with Nova's ECC gadget;
* the IPA weights are Fq values, non-native via Nova's BigNat (4 × 64-bit
  limbs);
* each term derives `s = parent · u`, decomposes it into bits, multiplies the
  verifier-key constant generator by fixed-base windows, and accumulates the
  result with a complete addition.

Every unit is synthesized into a counting constraint system (constraints,
variables and exact A/B/C nonzeros). It is also synthesized into Nova's
`TestConstraintSystem` with real values; every unit was satisfied and matched
native Pasta arithmetic. The run took 8.33 s and 63 MB in WSL. The result is
[results/m26a-msm-gadget.json](results/m26a-msm-gadget.json), SHA-256
`62a05b1b94807f9fa40c3da774e855a00f14b7af6e262df50e9e03f0e04ca66a`.

| Unit | Constraints | A+B+C nonzeros |
| --- | ---: | ---: |
| Nova variable-base `scalar_mul`, 255 bits (256 of them allocate the bits) | 2,656 | 11,674 |
| Nova complete `add` / `double` | 33 / 8 | 151 / 38 |
| Fixed-base, constant tables, window 1 / 3 / **4** / 5 / 7 | 9,181 / 3,401 / **3,002** / 3,163 / 5,657 | 15,437 at window 4 |
| Non-native Fq `mult_mod` / 256-bit decomposition | 994 / 260 | 6,252 together |
| **One MSM term**, slope over n = 1, 2, 4, 8 (4,301 → 34,373) | **4,296** | **21,102** |

Over the 524,288 primary generators that is 2.25 × 10^9 constraints (about
2^31), 2.18 × 10^9 witness variables (69.8 GB at 32 bytes each) and 1.1 ×
10^10 nonzeros. The secondary (Vesta) MSM, the transcript and the rest of the
verifier are excluded. The earlier 2^26 figure was about 32 times too low for
this gadget.

Known reductions, not yet measured:
* incomplete addition with a fixed-base offset in place of the 33-constraint
  complete add, which accounts for 2,112 of each term's constraints;
* sharing the non-native scalar work across the IPA's product tree.

Even a threefold reduction leaves roughly 7 × 10^8 constraints and a witness
over 16 GiB. The R1CS route therefore needs the prover sharded, as the Groth16
work was, or it loses to the SP1 wrapper. SP1's verifier execution was
18.1 × 10^9 instructions after a pinned affine key; its recorded CPU provers
peaked at 19–30 GiB.

## Next milestones

1. **M26b: optimized MSM gadget and sharded prover memory.** Replace complete
   additions with offset incomplete additions and amortize the non-native
   scalar products. Re-measure constraints, nonzeros and RAM per shard against
   the SP1 wrapper.
2. **M26c: price a real WHIR or Basefold verifier in Script.** Model 32-byte
   field elements and the full transcript at a stated security level, for the
   R1CS route's outer proof.
3. **M25c: build the final layer.** A transparent STARK with a BLAKE3 MMCS and
   stacked commitments that verifies the SP1 compressed proof, with blowup
   2^7, 11 queries and 24 grinding bits (or the 128-bit parameters). Measure
   its real proof size, prover time and RAM under a hard cgroup cap, sharding
   the commitment if the cap binds.
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
