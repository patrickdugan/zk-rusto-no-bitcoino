# Groth16 gym results

## Machine `MSI` (2026-11-04)

AMD Ryzen AI 9 365 with 20 threads and 31.1 GB RAM, Windows 11, MSVC
build. The raw output is `results/msi-20261104-1124.jsonl`. Every run below
verified its proof and rejected a wrong public input. Proofs are 128 bytes
(compressed BN254), verifying keys are 488 bytes, and verification takes
2–5 ms.

| Circuit | Constraints | Setup | Prove | Peak RSS | Proving key |
| --- | --- | --- | --- | --- | --- |
| SPV payment (13-level branch, 123-byte tx) | 1,796,669 | 46 s | 45 s | 4.7 GB | 336 MB |
| Header chain, 1 header | 121,782 | 2.3 s | 2.7 s | 0.33 GB | 22 MB |
| Header chain, 2 headers | 243,334 | 6.8 s | 4.6 s | 0.64 GB | 45 MB |
| Header chain, 4 headers | 486,438 | 12.8 s | 10.7 s | 1.3 GB | 90 MB |
| Header chain, 8 headers | 972,646 | 23 s | 25 s | 2.5 GB | 179 MB |
| Header chain, 16 headers | 1,945,062 | 50 s | 59 s | 4.8 GB | 358 MB |
| Header chain, 32 headers | 3,889,894 | 182 s | 127 s | 8.0 GB | 717 MB |
| Header chain, 64 headers | 7,779,558 | 396 s | 437 s | 10.4 GB | 1.4 GB |

A first SPV run on the same machine took 42 s setup and 76 s prove, with a
4.5 GB peak. Prove time varies with background load.

## Reading it for a 15.5 GB DDR4 laptop

**SPV payment.** Peak 4.7 GB, so it fits with a large margin. This is the
payment statement the SP1 route proves, as a BN254 Groth16 proof BitVM can
verify. The SP1 route's Groth16 step (`pay-wrap`) peaked at 19.1 GB host RSS
and took 15:21 on the 8-vCPU VPS (`btc-wrap.time` in the VPS archive), so it
does not fit that laptop.

**Header chains.** Peak memory per constraint is 2.0–2.5 KB up to 32
headers, and 1.3 KB at 64 headers. That gives:
- 32 headers (8.0 GB): fit comfortably;
- 64 headers (10.4 GB): fit if Windows leaves about 11 GB free;
- the laptop's ceiling, estimated (not measured) from the 64-header rate:
  about 64–70 headers per proof.

Longer chains need recursion or folding, for example the Nova header-chain
proofs (1.4 GB flat), with Groth16 only on the final statement.

**Time on DDR4 with fewer cores.** These runs used 20 threads. Expect
proportionally longer times; memory figures carry over. `run-gym.ps1 -CapGB
12` measures it directly.

**Reference.** RISC0's STARK-to-Groth16 step (`bsb-r0 groth16`, storage-prover
bootstrap) peaked at 1.46 GB and took 3:17 on the VPS. Wrapping through a
zkVM whose setup already exists stays cheap when the STARK side is small.

## What these numbers do not cover

- **Keys.** They come from a seeded, known-toxic-waste setup and are for
  measurement only.
- **Layout.** The SPV circuit is specialized to one transaction layout.
- **Header rules.** The header circuit omits retargets, median-time-past and
  version rules.

See `README.md` for both points.
