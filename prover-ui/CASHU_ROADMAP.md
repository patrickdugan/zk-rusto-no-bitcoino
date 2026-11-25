# Proof Grove Cashu roadmap

Snapshot dated November 25, 2026. An independent verifier checked the same protected V3 CDK issuance, Nova accounting proof and Bitcoin Core regtest payout. The holder received 24,750 sats after six blocks with the mint offline. The full SP1 settlement proof and funded BitVM3 verifier composition are still open. Completion ETA is unknown.

| Workstream | Verified or measured | Completion requirement |
| --- | --- | --- |
| PG-ZK-01 · Exact melt-funded proof | Stock Scarb accepted the fresh A100-generated STARK for the archived 24,000-sat reserve and 23,750-sat payout. A separate local audit checked the pinned program and profile, matched all 24 public words and rejected a mutation of each. An offline transaction audit checked the IDs, scripts, amounts, fee and holder signature. | Historical inclusion and relative timelock maturity require the original regtest blocks and an independent checkpoint. |
| PG-ZK-02 · Nova accounting | A separate verifier accepted compressed Nova fixture proofs. The authenticated journal exercises registration, issuance, split, swap, redemption and replay rejection. A fresh live regtest run verified the exact six-note CDK batch, its three-step Nova proof and the mined holder witness. The live observer reconciled the catalog to zero reserves and liabilities, rejected its stale tip after payout invalidation, and matched it again after block restoration. | Require independently observed chain context and available ledger witnesses for deployment. Define how to verify catalog completeness and distinguish protected liabilities from bearer notes issued outside the profile. |
| PG-ZK-03 · Claim-once redemption | CDK issued the V3 protected batch against a confirmed reserve, and an offline verifier checked DLEQ and reblinding. The cooperative and emergency branches spend one outpoint. Core confirmed a holder-only exit after six blocks and exercised conflicting spends, reorgs and beneficiary changes. | Extend protocol interoperability beyond the protected application profile. A transfer or split needs a usable funded reserve for each recipient. The historical melt-funded path depends on the mint accepting its initial melt. |
| PG-ZK-04 · BitVM3 settlement | The fixed Cashu settlement-record circuit measured 71,477 non-free gates. A funded one-byte Lamport assertion exercised the 49,500-sat challenger payout and the operator reclaim on regtest. Native M13 accepted four reference wraps and refused a valid C4 wrap under the Cashu statement. Native M14 refused six malformed claim inputs before generating garbling labels. | Resolve the captured SP1 recursion reduction failure, verify the complete Cashu wrap and bind it to the funded dispute. Full proof-level payout enforcement and malicious-setup controls remain open. |

## Work to close the prototype

1. Resume from the pinned SP1 checkpoints after diagnosing the four-child recursion reduction. The stock verifier accepted all four child proofs individually. The complete Cashu wrap is the input to the existing M13 and M14 gates.
2. Exercise a funded BitVM3 dispute against the complete verifier, with both honest reclaim and a rejected settlement paying their committed beneficiaries under the timeout rules.

The historical 23,750-sat STARK is independently verified. Historical Bitcoin inclusion and CSV maturity are a separate evidence gap. They require the original regtest blocks and a trusted active-chain checkpoint. A new protected regtest run has its own chain and transactions.

The fresh V3 regression took 211.28 seconds end to end. It generated one independently verified 11,504-byte Nova proof with SHA-256 `893d25000261b96997b1ffe3bd0846a9a0e57cd62366f1d626bbc517e1d57301`. The regtest payout transaction is `039fdc8817d9913007ae4328669d14040337df9e415c46bd755016e69b003708`.

## Compute and custody

The historical paired Cashu benchmark cost $0.2487. The measured A6000 SP1 resume replayed 750 core shards and produced 787 new core shards at 2.079 per second. It produced zero complete proofs. The remaining core and recursion task counts are unknown, so there is no proof or prototype ETA from that rate. On the RTX 3050, the archived Cairo smoke processed 33,554,428 Merkle nodes in 49.83 seconds across four stages. The Windows RAM guard stopped that run before stock Scarb verification.

The archived Shinigami kit includes native Merkle bridges for A100, RTX 3050/A6000, and RTX 5090. The exact-input A100 spot run produced one STARK in 316.33 seconds. CUDA hashed 805,306,331 Merkle nodes in 124.59 seconds, with 423 MiB peak sampled VRAM and zero observed swap I/O. The prover process peaked at 28.4 GiB resident memory and the worker cgroup peaked at 45.1 GiB. Hyperstack VM deletion was confirmed. The estimated cost ceiling is $0.163, with the invoiced charge pending. General-purpose Ark proving is suspended and the existing checkpoint archive is preserved.

The downloaded STARK has SHA-256 `701389f3f058d0d06ef4fa21402bf309ffcae54a1ee184bc27fb278c29a3dee7`. The compact verifier input derived from it has SHA-256 `d2340cf3c6f3c71f33268cc5b097e001ffbafb1ade96ab12ab3fa477ef1ef328`.

## Public evidence

- [November 23–24 campaign archive and session records](https://github.com/patrickdugan/Spiral/tree/57064314d97460a75a1b10c813b96b61640e26fd/codex-campaign-2026-11-23)
- [Pinned 23,750-sat fixture, Cairo execution receipt, and proving kit](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/6e8e89984ff91598bcdbf4efc0f343da34b9306b/fixtures/cashu-redemption-23750-sat)

The local `proof-grove-cashu-evidence-v31.zip` archive contains the portable V3 verifier and native M13/M14 evidence. Its SHA-256 is `990f35eafbf9c77195bb0a2438183d9ce0cb5f3adf2b41526d4666baa06f3cd7`.
