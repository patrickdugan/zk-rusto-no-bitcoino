# Proof Grove Cashu roadmap

Snapshot dated November 25, 2026. The protected prototype has independently checked CDK issuance and Nova accounting, plus a Bitcoin Core regtest payout with the mint offline. Completion ETA is unknown.

| Workstream | Verified or measured | Completion requirement |
| --- | --- | --- |
| PG-ZK-01 · Exact melt-funded proof | The archived case records a 24,000-sat reserve and a 23,750-sat payout after six blocks. The native Cairo replay matched 24 public words. An offline audit checked the transaction identifiers, reserve and payout scripts, amounts, fee and holder signature. The archived prover can now hash disk-backed Merkle trees on CUDA. | Generate a STARK accepted by stock Scarb, pin the program and profile, and reject mutations of all 24 public words. Original regtest blocks and a separately recorded checkpoint are required for historical inclusion and CSV maturity. |
| PG-ZK-02 · Nova accounting | A separate verifier accepted compressed Nova fixture proofs. The authenticated journal exercises reserve registration, issuance, split, swap, redemption and replay rejection. The protected V3 journal commits to the CDK issuance certificate and Bitcoin settlement record. | Require an independently observed chain and available ledger witnesses for admission and replay. Define completeness for the protected issuance ledger and how unreported bearer liabilities are treated. |
| PG-ZK-03 · Claim-once redemption | CDK issued the V3 protected batch against a confirmed reserve, and an offline verifier checked DLEQ and reblinding. The cooperative and emergency branches spend one outpoint. Core confirmed a holder-only exit after six blocks and exercised conflicting spends, reorgs and beneficiary changes. | Extend protocol interoperability beyond the protected application profile. A transfer or split needs a usable funded reserve for each recipient. The historical melt-funded path depends on the mint accepting its initial melt. |
| PG-ZK-04 · BitVM3 settlement | The fixed Cashu settlement-record circuit measured 71,477 non-free gates. Regtest exercised funded challenge and timeout paths for a one-byte dispute. The exact SP1 guest has a pinned program key and public output, and the A6000 runs retained core and recursion checkpoints. | Independently verify the complete SP1 settlement proof and compose it with the funded BitVM3 dispute. Exercise complete statement binding and actual payout enforcement under the collateral and timeout rules. |

## Compute and custody

The historical paired Cashu benchmark cost $0.2487. The measured A6000 SP1 resume proved 2.079 new core shards per second. It left the remaining shard count and recursion work unknown. On the RTX 3050, the archived Cairo smoke processed 33,554,428 Merkle nodes in 49.83 seconds across four stages. The Windows RAM guard stopped that run before stock Scarb verification.

The archived Shinigami kit includes native Merkle bridges for A100, RTX 3050/A6000, and RTX 5090. The exact-input A100 spot run has measured 402,653,181 Merkle nodes across three commitments in 84.09 seconds, with zero observed swap I/O. Its completed proof count and incurred cost are pending. General-purpose Ark proving is suspended and the existing checkpoint archive is preserved.

## Public evidence

- [November 23–24 campaign archive and session records](https://github.com/patrickdugan/Spiral/tree/57064314d97460a75a1b10c813b96b61640e26fd/codex-campaign-2026-11-23)
- [Pinned 23,750-sat fixture, Cairo execution receipt, and proving kit](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/6e8e89984ff91598bcdbf4efc0f343da34b9306b/fixtures/cashu-redemption-23750-sat)
