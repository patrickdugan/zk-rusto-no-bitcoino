# M12: a transparent final proof for the Nova Bitcoin-header proofs

M12 asks whether the existing compressed Nova header proofs can be re-proved by a transparent
system whose verifier is cheap to garble for BitVM3. It runs real proofs end to end: the
k=20 testnet4 baseline, a new k=1 testnet4 proof, and the folded witnesses behind both.

## Decision

**Choose architecture A for the security relation, but do not integrate it at k=20.**

- **Architecture A** runs the pinned verifier, unchanged, inside a transparent zkVM. Its
  security relation is complete with no new cryptography.
- **Architecture B** is a new decider over the folded witness. Its relation is implemented and
  tested here, including the commitment-binding attack. Making it succinct needs the same
  non-native Pallas MSM inside the outer proof that A needs, so it saves no proving work. It
  also needs prover-side artifacts that a compressed proof does not carry.

Both architectures put Θ(n) non-native Pallas work into the outer prover, where n is the
step-circuit size: 2^17 at k=1 and 2^21 at k=20. That work is the limiting operation.

At k=1 the complete wrapper costs **72.3 billion SP1 instructions**, measured:
- 71% decompresses the key's points, an encoding choice;
- 25% is the verifier's n-term MSM, matrix evaluation and sumchecks.

That is 14× the cost of proving every testnet4 header directly in the same zkVM (control C,
[results](#control-c-the-statement-proved-directly)). At k=20 the extrapolation is 9.0 × 10^11.

The final STARK verifier is a fixed-size circuit whatever the Nova size. Its garbled price is
dominated by the hash: Poseidon2 costs about 81× BLAKE3 per permutation in Boolean gates
([pricing](#phase-4-pricing)).

**Next BitVM3 milestone:** [recommendation](#recommendation-for-the-next-bitvm3-milestone).

## Phase 1: baseline reproduced

[`results/phase1-baseline.json`](results/phase1-baseline.json) records each run's binary hash,
wall time, peak private bytes and exit code. All runs used the de607d3 binaries
(`btc-header-fold.exe` `ad531c22…be40`, `nova-chain.exe` `01075ba2…539f`).

| Run | Result | Wall | Peak |
| --- | --- | ---: | ---: |
| `vk-export 20 --network testnet4` | SHA-256 `9e94b9083b5be30e796e974218804214b7106284c071eeec9b15945735321727`, **identical to the M11 key** | 110.6 s | 2.43 GB |
| `verify-bundle k20-testnet4-0-40.nht4` | genesis → 40, end hash `00000000a27e…70d6` | 261.2 s (Nova verify 21.4 s) | 1.92 GB |
| `verify-bundle k20-testnet4-40-80.nht4` | 40 → 80, end hash `00000000f2d5…ebc2`, chainwork `0x5100510051` | 247.8 s | 1.91 GB |
| `vk-export 1 --network testnet4` | `6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a` | 13.4 s | 0.20 GB |

The k=20 key regeneration gate from M11 is closed. Wall times include key decoding on a
machine shared with a training job; the M11 report measured 6.3 s for verification alone.

**Statement binding.** `native::verify_statement` ([`native/src/nova_io.rs`](native/src/nova_io.rs))
accepts a bundle only under the key pinned for its (network, k)
([`native/src/pins.rs`](native/src/pins.rs)). It also refuses a key pinned to any other pair.

The accepted statement is a fixed 1,164-byte encoding: magic | k | steps | z0 | zn | sha256(key)
| sha256(proof) ([`native/src/bundle.rs`](native/src/bundle.rs)). The SP1 guest commits the same
bytes. It therefore binds:
- network (magic, plus the pin);
- fold width;
- step count;
- initial checkpoint;
- final state;
- verifier-key identity.

## The real small fixture (k=1)

[`fixtures/`](fixtures/README.md) holds testnet4 headers 0–80 and a real compressed proof for
genesis → height 4 at k=1. The end hash `000000008f57…4265` and chainwork `0x500050005` match
Bitcoin Core 31.1.

| | Primary | Secondary |
| --- | ---: | ---: |
| Constraints (padded) | 97,409 (2^17) | 10,349 (2^14) |
| Matrix nonzeros | 710,229 | — |

The k=1 verifier key is 42.27 MB. Three Windows exports gave the same digest, and CI rebuilt it
on Linux to the same digest. Folding 4 headers took 1.65 s and compressing took
15.9 s, at 0.39 GB peak.

[`results/k1-verifier-inventory.json`](results/k1-verifier-inventory.json) has its exact
verifier work: 2,263,254 field multiplications and 147,456 MSM terms. At k=20 the figures are
27,525,706 and 2,113,536.

**Tests.** [`native/tests/k1_statement.rs`](native/tests/k1_statement.rs) rebuilds the k=1 key
from the circuit shape, checks it against the pin and verifies the fixture, so CI runs real Nova
verification. These are all rejected:
- each of 4 flipped proof bytes;
- a truncated proof;
- zn altered inside the proof (the final tip);
- 6 altered checkpoint fields;
- step count ±1;
- network relabelled to mainnet;
- fold width relabelled;
- a flipped key byte, pinned or unpinned;
- a valid key of another shape (k=2).

## Architecture A: SP1 wrapper of the complete verifier

[`sp1/program`](sp1/program/src/main.rs) is an SP1 6.9.0 guest. It:
- reads the verifier key and the bundle as private inputs;
- hashes the key and enforces the (network, k) pin table;
- decodes the key and proof with Nova 0.76.0's own serde;
- runs `CompressedSNARK::verify`;
- commits the 1,164-byte statement.

A refused input panics, and the guest exits with code 1 having committed nothing. SP1 6.9
reports this as an exit code, not an error. The first mutation run's host only checked for
errors and logged a panicked case as accepted
([`results/sp1-mutations-k1-first-run-host-bug.jsonl`](results/sp1-mutations-k1-first-run-host-bug.jsonl)), which is how this was found. The wrapper's
statement verifier must therefore require **exit code 0 and the full 1,164-byte statement**,
and the host now checks both.

Proving would stop at SP1's compressed STARK (KoalaBear, Poseidon2 Merkle trees). No Groth16 or
PLONK wrap is used, and there is no trusted setup.

| Measurement (k=1, real fixture) | Value |
| --- | ---: |
| Guest ELF SHA-256 | `2db52978545be814d9a57de44c150ff36258c507377d28fe98aabbe8e72babca` |
| Instructions | **72,298,156,913** |
| Committed statement SHA-256 | `d3b478b0…2fa0`, equal to the native verifier's |
| Execution (no proof) | 21–26 min, 4.6–7.9 GB peak RSS |
| Decode verifier key (bincode, point decompression) | 51,625,243,796 (71.4%) |
| `CompressedSNARK::verify` (Spartan + IPA on both curves, NIFS, Poseidon, Keccak) | 18,139,334,251 (25.1%) |
| SHA-256 of the 42.27 MB key | 2,506,507,858 (3.5%) |
| Decode proof | 26,024,411 |
| Mutation suite in the guest ([`results/sp1-mutations-k1.jsonl`](results/sp1-mutations-k1.jsonl)) | **13 of 13 refused** (exit code 1, nothing committed): 4 proof bytes, zn inside the proof, key byte, z0 chainwork, hash and height, steps + 1, NHC1 relabel, k relabel, truncated proof. 2 h 06 min, 8.65 GB peak |
| k=20, extrapolated | **9.0 × 10^11** (verify × 14.33 MSM-term ratio + key work × 11.84 key-size ratio) |
| k=20 verify only, extrapolated | 2.6 × 10^11 |

**The proof was not generated.** Recorded SP1 6.9.0 CPU proofs on the zk VPS (8 vCPU) peaked
at 19.1–30.4 GiB for programs of 1–7 million instructions. The peak is set by shard size, not
program length. That exceeds this milestone's 9 GiB envelope, and this host was shared with a
training job. A 72-billion-instruction proof is about 10,000 times the largest recorded SP1
program here, so its proving time is not extrapolated from those fixed-overhead runs.

## Architecture B: binding-aware replacement decider

Nova's running primary instance U = (comm_W, comm_E, X, u) is satisfied by (W, r_W, E, r_E)
when two things hold:
1. relaxed R1CS: A z ∘ B z = u · C z + E;
2. binding: comm_W = Com(W; r_W) and comm_E = Com(E; r_E) under the Pedersen key in the
   verifier key.

[`native/src/decider_b.rs`](native/src/decider_b.rs) implements both, independently of Nova's
code. It reads the folded witness from a real RecursiveSNARK through an exact serde mirror
([`native/src/mirror.rs`](native/src/mirror.rs)). [`native/src/pcs.rs`](native/src/pcs.rs) is
the hash-based multilinear PCS: rate-1/4 Reed–Solomon rows, SHA-256 Merkle columns,
Ligero-style proximity and evaluation checks, and 148 queries.

**The adversarial test** is `opening_of_other_witness_with_original_commitment_is_rejected` in
[`native/tests/decider_b.rs`](native/tests/decider_b.rs). Without binding, relaxed R1CS proves
nothing: for any W′, the choice E′ = A z′ ∘ B z′ − u · C z′ satisfies it. The test commits such a
(W′, E′) with the hash PCS and checks three things:
- the openings verify;
- relaxed R1CS holds;
- the Pedersen binding to Nova's original comm_W and comm_E rejects it.

Two more cases are rejected: honest vectors with a wrong blinding factor, and a root that commits
W′ passed off as W. A combined check, comm_W + γ comm_E = Com(W + γE; r_W + γ r_E), replaces two
MSMs with one and gives the same verdicts.

| Real folded witness | k=1 (genesis → 4) | k=20 (genesis → 40, shard 0's accumulator) |
| --- | ---: | ---: |
| Accumulator bytes | 7,223,800 | 108,262,456 |
| \|W\| / \|E\| (primary, unpadded) | 97,267 / 97,409 | 1,674,514 / 1,677,620 |
| End state | `eee9c074…` (height 4) | `e8b8cf09…` (height 40, equal to bundle 0–40) |
| Relaxed R1CS check | 0.09 s | 1.33 s |
| Two Pedersen MSMs / one combined | 0.20 s / 0.10 s | 1.90 s / 1.70 s |
| Hash-PCS commit + open (W and E) | 0.64 s | 13.3 s |
| PCS proof size (W and E) | 2.60 MB | 10.1 MB |
| PCS-only verification | 0.010 s | 0.033 s |
| Forgery: PCS accepts / relaxed R1CS accepts / binding rejects | yes / yes / yes | yes / yes / yes |
| Peak private memory | — | 1.79 GB |

**Artifacts B needs.** A compressed proof does not contain the witness. B needs the
RecursiveSNARK's running instances and witnesses:
- the primary (W, r_W, E, r_E), about 2 × 2^21 field elements at k=20;
- the secondary relaxed pair;
- the fresh secondary instance and its witness.

`nova-chain` keeps exactly this as `accumulator.bin` in each durable generation (108 MB at k=20).
A B deployment must retain the final generation, not only the exported bundle.

**Why B is not cheaper than A.** The relation's linear work is close to A's: per nonzero one
multiplication instead of two, plus 3 per row. But making it succinct needs the Pedersen
recomputation proved inside the outer proof: an n-term Pallas MSM, the same limiting operation.
A Spartan sumcheck over the hash PCS would remove only the linear R1CS check.

| Linear work the outer prover must carry (from the exact inventories) | k=1 | k=20 |
| --- | ---: | ---: |
| A: Nova verifier field multiplications | 2,263,254 | 27,525,706 |
| A: IPA MSM terms | 147,456 | 2,113,536 |
| B: relation field multiplications | 1,279,084 | 15,876,390 |
| B: combined binding MSM terms | 147,458 | 2,113,538 |

## Control C: the statement proved directly

Control C answers one question: what does the same statement cost in the same zkVM without
Nova? [`sp1/program-direct`](sp1/program-direct/src/main.rs) applies zk-rusto-no-bitcoino's
native header transition (`State::apply_on` at de607d3, the circuit's native mirror) from the
consensus genesis state. It commits magic | n | z0 | zn in the 17-element state encoding.
SHA-256 uses SP1's precompile patch.

| Headers (testnet4 from genesis) | Instructions | Per header | End-state SHA-256 |
| --- | ---: | ---: | --- |
| 4 | 512,784 | 128,196 | `eee9c074…2971`, **equal to the k=1 Nova statement** |
| 80 | 2,925,505 | 36,569 | `df3824ed…7991`, **equal to the k=20 shard-1 Nova statement** |
| 4,100 (two retargets) | 130,463,147 | **31,820** | `777e9757…b2df` |

At 31,820 instructions per header (this code is unoptimized; Lighto's tuned Litecoin guest
measured about 4,500):

| Whole chain, proved directly | Instructions | A at k=1 (measured) ÷ C | A at k=20 (extrapolated) ÷ C |
| --- | ---: | ---: | ---: |
| testnet4 to 158,970 | 5.06 × 10^9 | **14.3×** (verify only: 3.6×) | **178×** (verify only: 51×) |
| mainnet to 974,264 | 3.10 × 10^10 | **2.3×** (verify only: 0.59×) | **29×** (verify only: 8.4×) |

Both A and C end in SP1 compressed proofs, so their final verifiers are the same circuit.
As built, proving one Nova decider wrapper at k=1 costs more than proving all of mainnet's
headers directly. With a key that needs no point decompression it would cost 0.59× as much. C does not attest to the Nova proof itself, which the M12 objective requires. It is
the cost floor any Nova-wrapping design has to beat.

## Phase 4: pricing

All prices come from [`price_m12.py`](price_m12.py), which writes
[`results/pricing.json`](results/pricing.json). It uses the measured M2/M3 Pasta predicates in
[`../cost_envelope.py`](../cost_envelope.py) and the gate measurements below. CI reruns it and
requires the output to be unchanged.

**Measured Boolean primitives** ([`gates/`](gates/README.md)). Each circuit is checked against a
native reference on at least 64 random inputs. The non-free count is asserted equal to the
garble-mode ciphertext count.

| Primitive | Non-free gates |
| --- | ---: |
| Keccak-f[1600] | 38,400 |
| SHA-256 compression | 22,573 |
| BLAKE3 compression (7 rounds) | 10,410 |
| KoalaBear multiplication / addition | 2,068 / 94 |
| BabyBear multiplication / addition | 2,161 / 94 |
| KoalaBear degree-4 extension multiplication | 34,693 |
| BabyBear degree-4 extension multiplication | 36,688 |
| Poseidon2-KoalaBear width-16 permutation | 846,808 to 1,347,048 (*derived*, not built) |

The Poseidon2 range is derived from the measured multiplication, addition and constant prices
over Plonky3's round structure. The low end prices the internal diagonal as small constants; the
high end prices it as full multiplications.

**Garbling the inner Nova verifier directly (the M11 path).** Neither size fits a BitVM3
instance.

| | k=1 | k=20 |
| --- | ---: | ---: |
| Field multiplications at 360,963 gates | 8.17 × 10^11 gates, 13.1 TB | 9.94 × 10^12 gates, 159 TB |
| MSM sensitivity, 12 point additions per term | 7.68 × 10^12 gates, 123 TB | 1.10 × 10^14 gates, 1.76 PB |

**The final verifier (architecture A, and C as well).**
[`final_verifier_counts.py`](final_verifier_counts.py) counts the work from a real SP1 6.9.0
compressed proof, 1,272,893 bytes; its shape is recorded in
[`results/sp1-compressed-proof-shape.tsv`](results/sp1-compressed-proof-shape.tsv). That shape
is fixed by SP1's recursion program, not by the guest.

| Count (exact from the proof unless noted) | Value |
| --- | ---: |
| BaseFold queries | 124 |
| Component Merkle depth / leaf widths | 22 / 34 and 52 |
| FRI rounds / leaf width | 20 / 8 |
| Merkle path compressions | 33,976 |
| Poseidon2 permutations, total (leaves and transcript derived) | 39,727 |
| Extension multiplications, **lower bound** (folds and sumcheck Horner) | 3,656 |

| Final verifier, garbled | Non-free gates | Ciphertext per circuit |
| --- | ---: | ---: |
| As proved: Poseidon2-KoalaBear | 3.38 × 10^10 to 5.59 × 10^10 | 540–894 GB |
| Same shape, SHA-256 compression | ≥ 9.89 × 10^8 | ≥ 15.8 GB |
| Same shape, BLAKE3 compression | ≥ 5.25 × 10^8 | ≥ 8.4 GB |
| Reference: upstream garbled Groth16 (BN254) | ~1.12 × 10^10 total gates | — |

The hash dominates the final verifier. With a Boolean hash the same proof shape garbles in fewer
gates than the upstream Groth16 verifier. These are lower bounds, because chip constraint
evaluation at the opened point and the jagged evaluation are not counted yet.

## Resource envelope

| Metric | A: SP1 wrapper, k=1 | A: SP1 wrapper, k=20 | B: decider relation, k=20 | C: direct, testnet4 chain |
| --- | --- | --- | --- | --- |
| Native proving time | not run; 72.3 × 10^9 instructions measured | not run; 9.0 × 10^11 instructions (extrapolated) | relation 1.3 s + combined MSM 1.7 s + PCS 13.3 s, native, not succinct | not run; 5.06 × 10^9 instructions |
| Native proving peak RAM | execution 4.6–7.9 GB; recorded SP1 6.9 CPU provers peak 19–30 GiB, over the 9 GiB envelope | same per-shard peak | 1.79 GB (key decode included) | as A |
| Final proof bytes | 1,272,893 (SP1 6.9 compressed, fixed shape) | same | PCS openings 10.1 MB (component only) | same as A |
| Final verifier time | not measured | same | PCS-only check 0.03 s | same as A |
| Non-free garbled gates | 3.38 × 10^10 as proved (≥ 5.25 × 10^8 with BLAKE3) | same circuit | needs the A-class outer proof | same as A |
| Ciphertext per circuit | 540 GB (≥ 8.4 GB with BLAKE3) | same | — | same as A |
| Disk / communication | proof input is 10.2 M bits, i.e. 163 MB of 16-byte input labels; key 42.3 MB | key 500.3 MB | accumulator 108 MB, key 500.3 MB | headers 80 B each |
| Cut-and-choose (repo's n=181, f=7, 2^-40) | ships 7 circuits: 3.8 TB (≥ 59 GB with BLAKE3); garbles 181 and regenerates 174 | same | — | same as A |
| Trusted setup | none | none | none | none |

Measured disk outside git:
- run artifacts (keys, accumulators, logs): 606 MB;
- SP1 build trees: 2.6 GB;
- native and gate build trees: 0.8 GB.

The k=20 key and accumulator are 500 MB and 108 MB, both read from the M11 Codex run directory.

## Recommendation for the next BitVM3 milestone

1. **M13: a garbled verifier for a STARK with a Boolean hash.**
   - Take the counted SP1 6.9 compressed shape (or one recursion layer over it) with BLAKE3 or
     SHA-256 Merkle trees and transcript in place of Poseidon2.
   - Garble its complete verifier, including the chip constraint evaluation not counted here.
   - The measured shape puts the hash at about 4 × 10^8 BLAKE3 gates, against 3.4 × 10^10 for
     Poseidon2. SP1 does not provide that layer, so M13 has to build it: for example a Plonky3
     STARK with a BLAKE3 MMCS that verifies the SP1 compressed proof.
2. **Do not wrap the k=20 accumulator.** If the Nova proof itself must be attested, wrap the
   smallest step circuit. k=1 is 72.3 × 10^9 instructions, measured; k=20 is 9.0 × 10^11,
   extrapolated. 71% of the k=1 cost is decoding the key's compressed points. A pinned key
   encoding that ships affine points (checked on-curve, with its own pinned digest) removes most
   of that, leaving the 18.1 × 10^9-instruction verifier. That is below proving mainnet directly
   with this repo's unoptimized transition code, but about 4× above a Lighto-tuned direct guest
   (about 4,500 instructions per header). SP1 has no Pasta precompile, so the remaining cost is
   software Pasta arithmetic.
3. **Weigh control C before investing in A.** It proves the identical statement (same state
   encoding, same transition code) 14× cheaper than wrapping a k=1 Nova proof for testnet4. It
   leaves Nova as the off-chain fast path. That is a change of objective, so it is for you to
   decide.
4. **Keep the Nova path as it is.** Nothing here modifies the prover, the pinned keys or the
   bundles. The M12 pins add k=1 (`6894f490…`) and k=20 (`9e94b908…`).

## Reproduce

```
# native: k=1 fixture, statement tests, PCS, decider B (CI runs this)
cargo +1.90.0 test --release --locked --manifest-path nova-bitvm3/m12/native/Cargo.toml -- --test-threads=2
# gate prices
cargo +1.90.0 test --release --locked --manifest-path nova-bitvm3/m12/gates/Cargo.toml -- --test-threads=1 --nocapture
# pricing from recorded counts
python3 nova-bitvm3/m12/final_verifier_counts.py && python3 nova-bitvm3/m12/price_m12.py
# baseline and B on real witnesses (keys and accumulators outside git)
m12 vk-export testnet4 20 k20.vk            # expect 9e94b908...1727
m12 verify nova-bitvm3/fixtures/bitcoin-header/k20-testnet4-0-40.nht4 k20.vk
m12 decider-b k20.vk <shard-000 gen-000002 accumulator.bin>
# architecture A and control C (Linux/WSL with SP1 6.9.0: cargo-prove sp1 b8387fa)
cd nova-bitvm3/m12/sp1/script && cargo build --release
m12-nova-wrapper-script execute k1.vk ../../fixtures/testnet4-k1-0-4.nht4 d3b478b0ed0055bbd43a59775729c990a33d1df07bd0a66ee728a3573c832fa0
m12-nova-wrapper-script mutations k1.vk ../../fixtures/testnet4-k1-0-4.nht4
m12-nova-wrapper-script direct headers_0_4100.bin 4100
M12_ENABLE_PROVING=1 m12-nova-wrapper-script prove k1.vk BUNDLE EXPECT OUT   # needs > 19 GiB, not run
```

## Not verified

- **No wrapper proof was generated.** Architecture A ran in SP1's executor only. The 9 GiB envelope
  and the shared host ruled out SP1 6.9's 19–30 GiB CPU prover, so proving time is not reported.
  The committed statement and every refusal come from execution.
- **Extension work in the final-verifier price is a lower bound.** Chip constraint evaluation
  and the jagged evaluation are not counted. Poseidon2 is derived, not built.
- **The final-proof shape comes from a different guest.** It was counted from a Lighto H1
  compressed proof of the same SP1 version, on the stated basis that the compressed shape is
  fixed by SP1's recursion program.
- **The k=20 wrapper cost is an extrapolation** from k=1 by the measured inventory ratios.
- **B's succinct proof is not built.** Its relation, the hash PCS and the binding attack are
  implemented and tested. The outer proof of that relation does not exist.
- **The PCS soundness parameters are not audited.** 148 queries at rate 1/4 is the textbook
  unique-decoding setting.
- **The k=20 key was regenerated on Windows only** (MSVC with asm), the same platform as the M11
  original. The k=1 key also matched on Linux:
  [run 42309499011](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42309499011)
  rebuilt it from the circuit shape on ubuntu-latest, matched the pin, verified the fixture and
  passed every test.
