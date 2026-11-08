# M13: a BLAKE3 final proof for architecture A, and its garbled verifier

M12 chose architecture A: the pinned Nova verifier runs unchanged inside SP1 6.9.0. It ends in
SP1's compressed STARK. That proof is checked with Poseidon2 over KoalaBear, which garbles at
3.4 × 10^10 gates, and M12 recommended replacing that hash with a Boolean one.

M13 builds that final layer and prices its complete verifier from exact counts.

## Result

- **The final layer exists and is SP1's own.** SP1 6.9.0 already has a last recursion step, the
  *wrap* program, which it proves under BN254 Poseidon2 for gnark. M13 proves the same program
  under a BLAKE3 configuration: BLAKE3 Merkle trees and a BLAKE3 Fiat-Shamir transcript. There is
  no pairing and no trusted setup.
  - SP1's AIRs, jagged PCS, BaseFold and wrap FRI parameters are unchanged.
  - The rebuilt wrap program yields SP1's shipped BN254 wrap key `fce92406…fb78` bit for bit, so
    the program proved under BLAKE3 is the one SP1 ships.
- **Real proofs.** Our control-C guest (testnet4 heights 1–4, public inputs) runs through SP1's
  compressed proof (369 s), SP1's shrink (27 s) and the BLAKE3 wrap (67 s). The result:
  - a **1,099,069-byte proof** with a 104-byte key;
  - native verification in **0.012 s on one thread, 5.7 MB peak RSS**.

  A second guest's compressed proof gave the same key and the same proof size, so the final key is
  one pin for every guest.
- **The complete verifier, counted exactly.** One verification performs:
  - **33,626 BLAKE3 compressions**;
  - **744,425 KoalaBear multiplications** (344,386 general, 400,039 by small constants);
  - **588,415 additions, subtractions and sum terms**.

  Every field operation is counted by instrumenting KoalaBear's arithmetic itself, including chip
  constraint evaluation, the jagged evaluation and the sumchecks. M12 could only bound those.
- **Garbled price: 1.21–1.97 × 10^9 non-free gates (19–32 GB of ciphertext per circuit).** That
  is:
  - **5.7–9.3× below** the upstream garbled Groth16 verifier (1.12 × 10^10);
  - **17–28× below** M12's Poseidon2 final verifier.

  The range comes only from how products by small constants are priced.
- **Field arithmetic now dominates**, at 82% of the upper figure; BLAKE3 is the other 18%. M12's
  BLAKE3 estimate (≥ 5.2 × 10^8) counted the hash plus a lower bound of the field work.
- **Architecture A's final proof exists (2026-11-08).** A at k=1 is 72.3 × 10^9 SP1
  instructions. SP1's own provers could not prove it on this host; the resumable GPU prover
  [`nb3-prove-gpu`](../prover-gpu/README.md) did, on the laptop GPU
  ([Architecture A's full chain](#architecture-as-full-chain)). Its final proof,
  [`fixtures/a-wrap-blake3-v2.bin`](fixtures/README.md), matches every pin. The final layer does
  not depend on the guest: its key, shape and verifier circuit are the ones measured here.

## The pipeline

```
Nova k=1 proof ─► SP1 guest A (complete Nova 0.76 verifier, 1,164-byte statement)
               ─► SP1 6.9.0 compressed STARK (Poseidon2-KoalaBear, SP1's recursion)
               ─► SP1 shrink (Poseidon2-KoalaBear, SP1's shrink program, unchanged)
               ─► SP1 wrap program proved under Blake3KoalaBear   ◄── M13
               ─► m13-verify: pinned key + STARK + statement      ◄── garbled in BitVM3
```

| Crate | What |
| --- | --- |
| [`verify/`](verify) | `Blake3KoalaBear` ([`ctx.rs`](verify/src/ctx.rs)), the wrap machine and parameters, statement decoding, `verify_final`. Depends on SP1's verifier crates only. CI builds and tests it. |
| [`wrap/`](wrap) | Prover side: `compress-direct`, `compress-a`, `shrink-wrap`, `wrap-only`, `program-vk`, `check-wrap-program`. It needs the SP1 6.9.0 toolchain and is not built in CI. |
| [`verify/opcount/patch_koala_bear.py`](verify/opcount/patch_koala_bear.py) | Copies p3-koala-bear 0.4.3-succinct from the cargo registry and adds operation counters. Used only for the counting build. |

### The BLAKE3 configuration

[`verify/src/ctx.rs`](verify/src/ctx.rs) implements SP1's `IopCtx` trait. SP1 instantiates the
same trait for KoalaBear Poseidon2 and for BN254.

| Piece | SP1 wrap (gnark) | M13 |
| --- | --- | --- |
| Field / extension | KoalaBear / degree 4 | same |
| AIR, PCS, protocol | wrap machine, jagged + stacked BaseFold, zerocheck, LogUp-GKR | same |
| FRI | log blowup 3, 94 queries, 22 proof-of-work bits | same |
| Merkle leaf | Poseidon2-BN254 sponge | BLAKE3 of the row's canonical 4-byte LE limbs |
| Merkle node | Poseidon2-BN254 truncated permutation | BLAKE3(left ‖ right), one compression |
| Transcript | Poseidon2-BN254 multi-field duplex | BLAKE3 hash chain with Plonky3 `HashChallenger` semantics, domain-separated; field elements by rejection from 31-bit words |
| Digest | 1 BN254 element | 32 bytes |

SP1's CPU prover accepted the configuration with no changes to SP1. Its generic
`CpuShardProver`, stacked PCS prover and `FieldMerkleTreeProver` take byte digests.

### What the final verifier checks

[`verify_final`](verify/src/lib.rs) refuses unless all of these hold:

1. **Wrap key:** its SHA-256 equals the pin `d42c63e3…b0d7` ([`pins.json`](pins.json)).
2. **STARK:** the proof verifies under that key, with the key observed into the transcript first.
3. **Exit code:** the guest's is 0. This is M12's lesson: SP1 reports a refused input as exit code 1, not as an error.
4. **Completeness:** `is_complete` is 1.
5. **Guest program:** its key digest equals the pin for the expected guest (A or C).
6. **Recursion key map:** SP1's root equals the pin `7487c217…f257`.
7. **Statement:** the committed-values digest equals SHA-256 of the expected statement. For A at
   k=1 that is the 1,164-byte statement `d3b478b0…2fa0` (network, k, steps, z0, zn, key and proof
   digests).

**Tests** ([`verify/tests/final_verifier.rs`](verify/tests/final_verifier.rs); CI runs them on
the committed proof). These are all refused:
- 7 flipped bytes across the file;
- 5 altered public values: exit code, statement digest, guest key, `is_complete` and key-map
  root. The **STARK itself** refuses each of these, not only the statement comparison;
- 4 altered pins.

## Counting the verifier

The counts come from one complete `verify_final` run of the committed proof on one thread. With
more threads, rayon's parallel reductions add one partial sum per thread, so the addition count
varies with the thread count and between runs. `m13-verify` therefore pins rayon to one thread.
The binary is built two ways:

- **BLAKE3** is counted inside `ctx.rs`, per role. One compression is one 64-byte block, plus one
  per parent node of BLAKE3's chunk tree.
- **KoalaBear** is counted by
  [`patch_koala_bear.py`](verify/opcount/patch_koala_bear.py), which adds atomic counters to
  p3-koala-bear's scalar `Add`, `Sub`, `Mul`, `Sum`, `halve` and `mul_2exp_u64`. Every field
  operation the verifier performs reaches those:
  - negation is `0 − x`;
  - squaring is `x · x`;
  - degree-4 extension products and inverses are written in terms of them;
  - without AVX2 or NEON, `Field::Packing` is the scalar type.

  A multiplication with an operand within 2^8 of 0 or p is recorded as `mul_const`.

| Count, one verification ([`results/verify-counts-c4.json`](results/verify-counts-c4.json)) | Value |
| --- | ---: |
| BLAKE3, Merkle nodes | 30,199 compressions (30,199 calls) |
| BLAKE3, Merkle leaves | 2,283 compressions (2,187 calls, 78,200 bytes) |
| BLAKE3, transcript | 1,144 compressions (504 squeezes) |
| KoalaBear multiplications, general | 344,386 |
| KoalaBear multiplications by small constants | 400,039 |
| KoalaBear additions / subtractions / sum terms | 520,663 / 67,374 / 378 |
| Native verification time (one thread) / peak RSS | 0.012 s / 5.7 MB |

The second guest's proof gave identical counts except
([`results/verify-counts-second-guest.json`](results/verify-counts-second-guest.json)):
- 2 more transcript squeezes;
- 37 fewer multiplications, of which 45 more are small-constant ones.

Both depend on the transcript: challenges are sampled by rejection, and some verifier arithmetic
depends on sampled values. A circuit must cover the worst case. The price takes the larger run per counter and adds 10,000
multiplications and 64 compressions.

**Transcript v2 (added in M14).** `ctx::Blake3KoalaBearV2` keeps everything except challenge
sampling:
- each field challenge takes 8 bytes, as a u64 mod p;
- query bits are unchanged.

`m13 wrap-only-v2` re-proved the c4 shrink proof under it:
- [`fixtures/c4-wrap-blake3-v2.bin`](fixtures/c4-wrap-blake3-v2.bin);
- same key, statement and size as v1;
- proved in 55 s at the same memory.

`m13-verify verify-v2` counts it
([`results/verify-counts-c4-v2.json`](results/verify-counts-c4-v2.json)):
- 1,177 transcript compressions in 537 squeezes;
- Merkle counts as above;
- 33,659 compressions in total.

With v2 the transcript's byte schedule no longer depends on the challenges; see
[`../m14/README.md`](../m14/README.md).

## Garbled price

[`price_m13.py`](price_m13.py) writes [`results/pricing.json`](results/pricing.json) from the
counts and M12's measured gate prices. CI re-runs it and requires the output to be unchanged.

| Part | Non-free gates |
| --- | ---: |
| 33,692 BLAKE3 compressions (with margin) at 10,410 | 350,733,720 |
| Merkle path swaps (256 AND per node) and root comparisons (255 per path) | 8,288,629 |
| 588,415 linear field operations at 94 | 55,311,010 |
| 354,386 general multiplications (with margin) at 2,068 | 732,870,248 |
| 400,084 small-constant multiplications | 63.6 M (at ×3, 159) / 131.2 M (at ×11, 328) / 827.4 M (full) |
| **Final verifier** | **1.21 × 10^9 / 1.28 × 10^9 / 1.97 × 10^9** |
| Ciphertext per circuit (16 B per gate) | 19.4 / 20.5 / 31.6 GB |
| Proof as circuit input | 8.79 M bits, 141 MB of input labels |
| Cut-and-choose, ships 7 of 181 circuits (2^-40) | 136 / 143 / 221 GB |

| Final verifier | Non-free gates | Relative to M13 (upper) |
| --- | ---: | ---: |
| M12: SP1 compressed proof as proved (Poseidon2-KoalaBear) | 3.38 × 10^10 | 17.1× |
| Upstream garbled Groth16 (BN254) | 1.12 × 10^10 | 5.7× |
| **M13: SP1 wrap layer with BLAKE3** | **1.97 × 10^9** | 1 |

Not priced:
- byte serialization of field elements, which is wiring;
- 31-bit rejection compares;
- equality checks of sumcheck claims, at most 124 gates each.

## Resources

All measured on the M12 host (20 threads, WSL2) with RAM capped by a cgroup and the rest allowed
into the NVMe swapfile set up for SP1 runs:
- 7 GiB RAM cap;
- `RAYON_NUM_THREADS=8`;
- one SP1 worker of each kind.

| Run | Wall | Peak RAM / swap | Output |
| --- | ---: | ---: | --- |
| `compress-direct`, heights 1–4 ([`results/compress-c4.json`](results/compress-c4.json)) | 12 min 19 s (prove 369 s) | 7.0 GiB / 8.1 GB | 1,273,665-byte compressed proof, verified |
| `shrink-wrap` ([`results/shrink-wrap-c4.json`](results/shrink-wrap-c4.json)) | 3 min 30 s (shrink 27 s, wrap setup 7 s, wrap prove 67 s) | 7.0 GiB / 3.5 GB | 1,099,173-byte final proof, verified |
| `compress-direct`, heights 1–4,100 (throughput probe) | stopped at 14 min 39 s | 7.0 GiB / 27.5 GB | none: swap-bound |
| `check-wrap-program` ([`results/check-wrap-program.json`](results/check-wrap-program.json)) | 2 min 05 s | 3.1 GB / 0 | BN254 key equal to SP1's |
| `m13-verify verify` (one thread) | 0.03 s (verification 0.012 s) | 5.7 MB / 0 | statement |

Peak RAM sits at the 7 GiB cap in every proving run; the rest went to swap. Without swap, both
the compressed proof and the BLAKE3 wrap were killed at a 9 GiB cgroup cap. The final layer
needs about 10.5 GB in all (7.0 GiB RAM plus 3.5 GB swap) during the wrap commitment.

## Architecture A's full chain

[`run_full_a.sh`](run_full_a.sh) runs every step from this repository's fixtures:
1. builds the k=1 key (expect `6894f490…c12a`);
2. proves guest A compressed;
3. shrinks and wraps under BLAKE3;
4. runs `m13-verify` with the pins.

For A the final verifier pins:
- guest key `5df3760f…f46b` (ELF `2db52978…babca`, the M12 guest rebuilt bit for bit), from
  [`results/program-vk.json`](results/program-vk.json);
- committed statement `d3b478b0…2fa0`, the 1,164-byte k=1 testnet4 statement M12's native
  verifier and SP1 execution both produce.

The wrap key and recursion key root are the same pins as for every guest.

**A's compressed proof: produced 2026-11-08 with [`nb3-prove-gpu`](../prover-gpu/README.md).**
27,058 shard tasks at 2^27 elements per shard on the RTX 5080 Laptop GPU (16 GB), 14.9 h from
first start to proof. `m13 shrink-wrap` and `m13 wrap-only-v2` then produced the final proof in
2 min 40 s. Its statement has committed values `d3b478b0…2fa0`, guest key `5df3760f…f46b`, and
the shared wrap key and recursion root. Fixtures: `a-compressed.bin`, `a-wrap-blake3-v2.bin`,
`a-statement.json`.

Before that tool, SP1's own CPU prover could not do it here. This host shared its RAM with a
training job, so SP1 ran capped at 7 GiB of RAM with the rest in swap. Measured:
- **4 headers (0.51 × 10^6 instructions):** proved compressed in 369 s, with 8.1 GB of swap.
- **4,100 headers (1.3 × 10^8 instructions):** reached 27.5 GB of swap in 14.6 minutes and was
  stopped before the swapfile filled. Its timing would have measured the disk.

A is 72.3 × 10^9 instructions, 556 times that run. SP1 6.9.0's CPU prover peaks at 19–30 GiB,
and SP1's GPU prover requires 24 GB of device memory. `run_full_a.sh` is written for such a host.

## Recommendation for the next BitVM3 milestone

1. **M14: build the garbled circuit for this verifier.** The counts say what it contains:
   - a BLAKE3 Merkle and transcript core of 3.6 × 10^8 gates;
   - a KoalaBear arithmetic core of 0.85–1.6 × 10^9 gates.

   Start from the field part, which dominates. Two levers are worth measuring first:
   - lazy reduction in degree-4 products (sum the raw 62-bit products, reduce once);
   - common-subexpression elimination in the chip constraint evaluation. The native verifier
     evaluates constraints as written.
2. **Cut A's prover cost before proving it.** Two measures:
   - A pinned key encoding that ships affine points removes most of the 71% key-decode share
     (M12).
   - Run A's proof on SP1's GPU prover or on a host with at least 32 GiB of RAM.
3. **Keep the final layer's key pinned per SP1 version.** `wrap_vk_sha256`, the recursion key
   root and the guest key digests change whenever SP1's recursion programs change.
   `check-wrap-program` re-checks equality with SP1's shipped program after an upgrade.

## Reproduce

```
# verifier, tests, counts (CI runs these)
cargo test --release --locked --manifest-path nova-bitvm3/m13/verify/Cargo.toml
python3 nova-bitvm3/m13/verify/opcount/patch_koala_bear.py ~/.cargo/registry/src/index.crates.io-*/ /tmp/p3kb
cargo build --release --features opcount --manifest-path <copy of verify>/Cargo.toml --config 'patch.crates-io.p3-koala-bear.path="/tmp/p3kb"'
m13-verify verify nova-bitvm3/m13/fixtures/c4-wrap-blake3.bin nova-bitvm3/m13/fixtures/c4-statement.json
python3 nova-bitvm3/m13/price_m13.py
# prover (Linux/WSL, SP1 6.9.0 toolchain)
cargo build --release --manifest-path nova-bitvm3/m13/wrap/Cargo.toml
M13_ENABLE_PROVING=1 m13 compress-direct nova-bitvm3/m12/fixtures/testnet4-headers-0-80.bin 4 c4.compressed.bin
m13 shrink-wrap c4.compressed.bin OUT
m13 check-wrap-program OUT/shrink-shape.json
```

## Not verified

- **No garbled circuit was built.** The gate figures apply M12's measured primitive prices to exact
  operation counts of the native verifier. A circuit that folds constants or shares
  subexpressions comes in at or below the upper figure.
- **Architecture A's compressed proof was not generated.** Everything after it (shrink, BLAKE3
  wrap, final verifier) ran on proofs of the control-C guest and of a second SP1 6.9.0 guest.
- **BLAKE3's role is SP1's Poseidon2's.** M13 does not re-derive SP1's soundness analysis for a
  different hash. The wrap FRI parameters are SP1's unique-decoding parameters for 100 bits, and
  BLAKE3 supplies 128-bit collision resistance to the Merkle trees and transcript.
