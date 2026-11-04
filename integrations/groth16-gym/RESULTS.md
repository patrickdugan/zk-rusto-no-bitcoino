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

## Hard memory limit: Acer (2026-11-04)

Intel i5-11400H with 12 threads and 23.8 GB RAM, Windows 11, MSVC build.
Each proof ran under `run-capped.ps1 -LimitGB 14`: a Windows job object
whose 14 GiB limit on committed memory the OS enforces. "Peak commit" is
the job's peak committed memory, which Windows cannot trim. The raw output
is `results/subhanallah-capped.jsonl`.

| Circuit | Constraints | Setup | Prove | Peak commit | Peak working set | MSI peak |
| --- | --- | --- | --- | --- | --- | --- |
| Header chain, 16 headers | 1,945,062 | 37 s | 29 s | 5.1 GiB | 4.9 GiB | 4.7 GiB |
| Header chain, 32 headers | 3,889,894 | 83 s | 144 s | 10.3 GiB | 9.9 GiB | 7.8 GiB |
| Header chain, 64 headers | 7,779,558 | — | — | stopped at the 14 GiB limit | — | 10.2 GiB |

Both completed runs verified their proof and rejected a wrong public input.
The 64-header run failed an allocation about 105 s in. At 32 headers,
building the constraint system alone took 8.3 GiB, so it most likely
failed during that step.

Committed memory is 2.8 KB per constraint at both 16 and 32 headers, in
line with the Linux VM. The MSI's lower 32- and 64-header figures were
working-set trimming, not lower demand. At 2.8 KB, 64 headers needs about
20.6 GiB.

## Reading it for a 15.5 GB DDR4 laptop

**SPV payment.** Peak 4.7–5.3 GB, so it fits with a large margin. This is
the payment statement the SP1 route proves, as a BN254 Groth16 proof. BitVM
cannot verify it as it is: the circuit has 7 public inputs, and BitVM's
chunked verifier takes one (see `README.md`, "BitVM"). The SP1 route's
Groth16 step (`pay-wrap`) peaked at 19.1 GB host RSS and took 15:21 on the
8-vCPU VPS (`btc-wrap.time` in the VPS archive), so it does not fit that
laptop.

**Header chains.** Measured under a hard limit on the Acer (above), at
2.8 KB of committed memory per constraint:
- **16 headers:** 5.1 GiB, so it fits.
- **32 headers:** 10.3 GiB. It fits if Windows and other programs leave
  about 10.5 GiB free.
- **64 headers:** about 20.6 GiB, so it does not fit. It also did not fit
  under a 14 GiB limit.
- **Ceiling, estimated:** at about 0.33 GiB per header (121,500
  constraints), 12–14 GiB of headroom allows about 36–42 headers per proof.
  This replaces the earlier estimate of 64–70 headers.

`run-capped.ps1` checks a single size on the laptop itself, for example
`-LimitGB 13 headers 40`. `run-gym.ps1 -CapGB` predicts from the working
set, so on Windows its predictions can be low.

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
