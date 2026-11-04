# Testnet4 SPV payment proofs: benchmarks (2026-11-04/05)

One real testnet4 payment, proven deep in the chain with the testnet4 Nova
circuit (min-difficulty and BIP94 rules, `--network testnet4`), at fold
widths k = 5 to 50. The payment was then verified by the gateway
(`zk.statement.verify`) against a live testnet4 node. Raw data is in
`results/testnet4/`.

## Setup

| | |
| --- | --- |
| Machine | Acer Nitro AN515-57: Intel i5-11400H (6 cores, 12 threads), 23.8 GB RAM, Windows 11, MSVC build with the halo2curves `asm` feature (the CPU has ADX) |
| Node | Bitcoin Core 32.1.0, testnet4, unpruned, synced to 158,949 |
| Payment | tx `5604bd9493e51721d8b38913f6edaa7b973a4991bf874a43b4c01db9ea4c4747`, output 0: 4,249,405,972 sats to P2WPKH (script SHA-256 `f9259fb7…7840`) |
| Block B | 100,008, `0000000000000000c3b3…9494`, a full-difficulty block (`0x1901c065`, 1,511 txs) between min-difficulty blocks |
| Checkpoint | 99,008, `00000000913000b0…c1ad`, chainwork `0x4c76a4af2fc07a98ff9` from Core's `getblockheader` |
| Proof A | checkpoint 99,008 → B 100,008: 1,000 headers |
| Proof B→tip | 100,008 → 158,948 (k = 10, 20), 158,928 (k = 40) or 158,908 (k = 50): about 58,900 headers. The tip must be a whole number of folds from B. |
| Inclusion | Core's `gettxoutproof`: 473 B MerkleBlock, plus the 215 B raw tx |
| Headers | 59,952 exported from the node with `scripts/export-node-headers.ps1`; each was checked against its block hash and its predecessor |
| Memory limit | Every phase ran in a Windows job object with an OS-enforced limit on committed memory. "Peak" is the job's peak commit. |

Proof A ends exactly where Core does: block 100,008's hash and chainwork
`0x516c61db08debad11f2`. Every B→tip proof starts from A's end state
`37d0c452…a243`. Every proof's folded output equals the native validator's
state (`outputs_match=true`).

## 1. k = 5 under a 1.5 GiB limit (solo)

200 headers, 100,701–100,900.

| Phase | Peak | Time |
| --- | --- | --- |
| Fold 40 × 5 + compress | 1,199 MiB | 76 s: 0.097 s per header, compress 42 s |
| Verify (saved key) | 551 MiB | 18 s |
| Verify (key rebuilt) | 731 MiB | 30 s |

## 2. Fold width sweep under a 13 GB limit (solo)

A few folds from 100,008, plus compression and a verify that loads the
saved key, as the gateway does. Fold steps get slower over the first few
steps and then settle. Section 3 shows them flat over a whole run.

| k | Constraints per step | Setup | Fold step (1st → last) | Compress | Prove peak | Key | Verify peak, time |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 5 | — | — | 0.5 s | 42 s | 1.2 GB | 138 MB | 0.6 GB, 18 s |
| 10 | 846k | 21 s | 0.9 s | 83 s | 2.3 GB | 258 MB | 1.0 GB, about 60 s (from section 3, on a shared CPU) |
| 20 | 1.68M | 40 s | 0.98 → 2.02 s | 176 s | 4.3 GB | 500 MB | 1.8 GB, 69 s |
| 40 | 3.34M | 84 s | 2.00 → 3.47 s | 363 s | 8.5 GB | 984 MB | 3.6 GB, 141 s |
| 50 | 4.17M | 89 s | 2.65 → 4.23 s | 369 s | 10.3 GB | 1.17 GB | 4.6 GB, 137 s |

The solo k = 10 figure is proof A (1,000 headers): 0.087–0.092 s per header.

## 3. Full payments, two lanes at once

Lane 1 ran k = 10 then k = 20; lane 2 ran k = 50 then k = 40, under a
20 GB limit. The lanes overlapped throughout, except the last ~22 minutes of
k = 40. Two provers together kept about 7 of 12 hardware threads busy.
Per-job times are therefore about 50% above solo.

| k | Prove A | Prove B→tip | Fold per header (B→tip) | Mean fold step, 1st / last quarter | Compress (B→tip) | Peak | Verify A + B→tip | NSP1 | Confirmations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | 403 s | 8,426 s (2 h 20 m) | 0.140 s | 1.48 / 1.36 s | 124 s | 2.3 GB | 60 + 58 s at 1.0 GB | 27,776 B | 58,941 |
| 20 | 461 s | 9,916 s (2 h 45 m) | 0.163 s | 3.29 / 3.14 s | 241 s | 4.3 GB | 115 + 112 s at 1.8 GB | 28,400 B | 58,941 |
| 40 | 765 s | 8,791 s (2 h 27 m) | 0.140 s | 5.05 / 5.32 s | 363 s | 8.6 GB | 155 + 138 s at 3.6 GB | 29,024 B | 58,921 |
| 50 | 855 s | 9,949 s (2 h 46 m) | 0.158 s | 7.83 / 7.84 s | 486 s | 10.4 GB | 252 + 232 s at 4.6 GB | 29,024 B | 58,901 |

All eight proofs verified, and each pair chained. Both proofs at a given k
share one verifier key, so each run kept a single copy. Per-step times are
in `results/testnet4/k*-Btip.steps.txt`.

The two lanes took 5 h 52 m in total for four payments (239,760 headers):
0.088 s per header across both lanes. Four payments at k = 10, one after
another, would take about 6.5 h (0.092 s per header plus compression). So
the second lane bought about 10%.

## 4. Gateway verification

`services/supernode-rpc` now takes `SUPERNODE_NOVA_NETWORK=testnet4`. The
k = 10 payment is the fixture `fixtures/testnet4/payment100008.nsp1`.

**Tests** (`tests/statements_gateway.rs`, real `btc-header-fold`, mock
Core; 295 s):

- `testnet4_nova_spv_payment_is_verified_and_bound_to_core` checks
  acceptance with the expected outpoint, the statement name, 58,941
  confirmations, the value and the script hash. It also checks that a
  reorganized tip is refused (-32050).
- `mainnet_policy_refuses_a_testnet4_payment` checks that a gateway
  configured for mainnet refuses the testnet4 proof, even when its operator
  pins the testnet4 key.

**Live:** the gateway executable ran against the testnet4 node (Direct
runner), with:
- the testnet4 k = 10 key `2495da9b…eabe`;
- checkpoint pin `39bc650e…eee2`.

The response is in `results/testnet4/gateway-live-k10-response.json`:

| Field | Value |
| --- | --- |
| `proof_verified` | true |
| `active_chain_at_lookup` | true: checkpoint, block and tip hashes and chainwork equal Core's |
| statement | `btc_nova_spv_payment_testnet4_v1` (parts `btc_header_chain_testnet4_v1`) |
| block / tip | 100,008 / 158,948, 58,941 confirmations |
| output | `5604bd94…4747:0`, 4,249,405,972 sats |
| `unspent_at_lookup` | false (spent long ago) |
| time | 120 s, mostly loading the 258 MB key twice on Windows |

## Takeaways

- **More memory does not prove faster on this CPU.** Folding costs about
  0.09 s per header solo at every k from 5 to 50. Larger k only adds
  compression time (42 s at k = 5, 486 s at k = 50), bigger keys and slower
  verification. k = 5 or 10 is the right setting here.
- **Folding time is flat over long runs.** The mean step time in the last
  quarter of 59,000 headers equals the first quarter's.
- **Two concurrent provers gain about 10%.** In a short sample, one prover
  kept about 6 of 12 hardware threads busy and two kept about 7, so the two
  mostly contend with each other.
- **Projection:** all 158,948 testnet4 headers from a checkpoint would take
  about 4 h solo at k = 10 in 2.3 GB, then a 2-minute compression. This is
  untested.

## Not covered

- **Authenticated checkpoints only.** No genesis start: the checkpoint is
  operator-pinned, with its chainwork from Core.
- **Direct runner only.** The separate-UID broker
  (`services/statement-verifier-broker`) still holds only the mainnet key,
  so it does not run the testnet4 tests.
- **No Linux timings.** The Linux CI runs the testnet4 gateway tests but
  does not time them.
