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

"Peak RSS" here is Windows' `PeakWorkingSetSize`. Windows can trim a
process's working set, so this figure can be lower than the memory the
process committed.

## Cross-check: Linux VM (2026-11-04)

4-thread Xeon with 15.7 GB RAM, Linux, where peak RSS is `VmHWM`. This was a
partial sweep, stopped during the 32-header run, and its raw output is not
in `results/`. Every run verified and rejected a wrong public input.

| Circuit | Constraints | Prove | Peak RSS | MSI peak |
| --- | --- | --- | --- | --- |
| SPV payment | 1,796,669 | 24.3 s | 5.3 GB | 4.7 GB |
| Header chain, 1 header | 121,782 | 1.2 s | 0.38 GB | 0.33 GB |
| Header chain, 2 headers | 243,334 | 2.3 s | 0.76 GB | 0.64 GB |
| Header chain, 4 headers | 486,438 | 4.4 s | 1.5 GB | 1.3 GB |
| Header chain, 8 headers | 972,646 | 11.5 s | 2.9 GB | 2.5 GB |
| Header chain, 16 headers | 1,945,062 | 23.1 s | 5.7 GB | 4.8 GB |

On Linux, peak memory grows in a straight line at about 2.9 KB per
constraint, about 15–20% above the MSI at every size. On the MSI, the rate
falls to 2.1 KB at 32 headers and 1.3 KB at 64. That drop may be Windows
trimming the working set, not lower demand. At the Linux rate, 32 headers
would need about 11.4 GB and 64 headers about 22 GB.

## Reading it for a 15.5 GB DDR4 laptop

**SPV payment.** Peak 4.7–5.3 GB, so it fits with a large margin. This is
the payment statement the SP1 route proves, as a BN254 Groth16 proof. BitVM
cannot verify it as it is: the circuit has 7 public inputs, and BitVM's
chunked verifier takes one (see `README.md`, "BitVM"). The SP1 route's
Groth16 step (`pay-wrap`) peaked at 19.1 GB host RSS and took 15:21 on the
8-vCPU VPS (`btc-wrap.time` in the VPS archive), so it does not fit that
laptop.

**Header chains.** The two machines agree up to 16 headers (4.8–5.7 GB),
which fits. Beyond that, the estimates depend on which figure is right:
- **32 headers:** 8.0 GB on the MSI, about 11.4 GB at the Linux rate. It
  probably fits, but with a small margin at the Linux rate.
- **64 headers:** 10.4 GB on the MSI, about 22 GB at the Linux rate. At the
  Linux rate it does not fit. The earlier ceiling of 64–70 headers came
  from the MSI's 64-header rate and is withdrawn until it is measured.

To settle it, run 32 and then 64 headers on the laptop under a hard memory
limit that the OS enforces, such as a Windows job object, not only under
`-CapGB`. Then record the peak committed memory as well as the working set.

Longer chains need recursion or folding, for example the Nova header-chain
proofs (1.4 GB flat), with Groth16 only on the final statement.

**Time on DDR4 with fewer cores.** These runs used 20 threads. Expect
proportionally longer times. Memory figures may not carry over between
Windows and Linux (see above).

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
