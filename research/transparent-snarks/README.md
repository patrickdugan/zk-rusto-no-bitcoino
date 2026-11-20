# Transparent recursive proofs

Research track opened 2026-11-05 for `patrickdugan/zk-rusto-no-bitcoino`.

**Decision: keep the entire selected proof pipeline free of trusted setup,
including its final compression.** Start with the existing Nova Pallas/Vesta
implementation and Spartan with IPA. This package adds a decision record,
a checked benchmark plan, and an implementation handoff. Prover measurements
for this package remain pending.

```text
bounded header batches
        -> Nova folding / Pedersen commitments over Pallas-Vesta
        -> Spartan compression / IPA
        -> native verifier pinned to the circuit and network
```

The first candidate already has code at
[`de607d3db17d400dd6c2923d357f1d4a7bf233c7`](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/de607d3db17d400dd6c2923d357f1d4a7bf233c7/integrations/nova-header-chain),
on the inspected `feat/testnet4-recursive-chain` branch. Both `src/main.rs` and
`src/bin/nova-chain.rs` select `PallasEngine`, `VestaEngine`, and
`RelaxedR1CSSNARK<..., ipa_pc::EvaluationEngine<...>>`. Its Cargo manifest pins
`nova-snark = "=0.76.0"`. The streaming executable supports durable
continuations and Spartan export. These are inspected source facts;
this package has not rerun their proof tests.

This folder is additive to `main`. It does not merge the feature branch or
change the Groth16 gym. The existing checkpoint preparation at
`prep/recursive-pruned-checkpoints-20261105` remains separate.

## Choices

| Candidate | Role in this track | Setup condition | Work still required |
| --- | --- | --- | --- |
| Nova + Spartan/IPA | First implementation and RAM baseline | Pedersen/IPA throughout, with transparent generator derivation | Reproduce proofs, measure compression separately, audit restart and statement binding |
| Zcash Halo2 with IPA | Alternative to evaluate after the Nova baseline | Pin the upstream IPA implementation and inspect the chosen recursion layer | Integrate a real recursive verifier and measure the same statement |
| Recursive FRI/STARK | Hash-based alternative, connected to the repository's Raito/STWO work | Keep recursion and final output within transparent protocols | Select a pinned implementation and measure its complete verifier/prover path |
| HyperNova with a transparent compressor | Later experiment for richer step circuits | Identify the concrete PCS and compressor before admitting the pipeline | Demonstrate a useful improvement over the existing Nova code |

Only the first candidate is admitted by the executable policy today.
The other rows are research candidates. A universal or updatable ceremony
still introduces a trusted-setup assumption, so KZG-based variants stay
outside this track. Groth16 remains an archival comparison in its existing
folder. Its verifier is not an allowed final wrapper here.

The API name `setup` can refer to public parameter generation or circuit
preprocessing. Review how parameters are derived and whether secret toxic
waste exists. The chosen IPA path permits publicly reproducible generators.
Public parameters and verifier keys can still occupy substantial memory.

## Run the offline checks

From the repository root, using Python 3.10 or newer:

```sh
python3 research/transparent-snarks/policy.py check research/transparent-snarks/plan.json
python3 research/transparent-snarks/policy.py matrix research/transparent-snarks/plan.json
python3 -m unittest discover -s research/transparent-snarks -p 'test_*.py' -v
```

`policy.py` checks the declared configuration. It rejects changed or extra
proof stages, unknown fields, and an unreviewed source revision. It binds
the declared network to its statement label and distinguishes a genesis
start from an authenticated checkpoint. The generated matrix contains
12 cases: 64, 128, and 1,024 headers at fold widths 1, 4, 8, and 16.

The memory target is **13 GiB**, with swap disabled, for the planned
15-16 GiB host experiment. This script creates a plan. OS enforcement and
measurement belong to the prover runner described in `BENCHMARK.md`.
A passing configuration check does not inspect the compiled binary or
establish cryptographic soundness.

## Proof and trust boundaries

A transparent setup removes the ceremony assumption. Verification still
needs a reviewed circuit and a correctly bound public statement. A
non-genesis checkpoint needs its own authentication policy. The default
plan starts from the network's genesis state; its fixture digest must be
filled before measurement.

Nova/IPA retains discrete-log assumptions. This track makes no
post-quantum claim for that pipeline. The live continuation contains
witness material; privacy claims require a separate review of the exact
compressed export. Header-chain proofs also leave transaction execution,
UTXO validity, and canonical-chain selection to their respective layers.

Native light-client verification is the first target. Bitcoin Script and
BitVM verification remain separate engineering milestones with their own
cost and security review. End-to-end transparency takes precedence over
reusing a pairing-based final verifier.

## Files

`BENCHMARK.md` defines the statement and measurement gates.
`HANDOFF.md` gives the next agent exact paths and commands.
`plan.json` is the checked input for `policy.py`.
`test_policy.py` exercises rejection cases; `VALIDATION.md` records this
package's local results. The CI workflow runs only these cheap checks.

## Primary sources

- [Nova upstream README](https://github.com/microsoft/Nova): Pedersen/IPA and Spartan compression; HyperKZG and Mercury require powers of tau. Upstream `main` is background reading; the repository's pinned crate remains the execution target.
- [Spartan upstream](https://github.com/microsoft/Spartan): transparent SNARK construction and discrete-log assumptions.
- [Zcash Halo2 IPA design](https://zcash.github.io/halo2/design/proving-system/inner-product.html) and [commitment construction](https://zcash.github.io/halo2/background/pc-ipa.html).
- [Stwo Cairo upstream](https://github.com/starkware-libs/stwo-cairo): transparent STARK and recursion context. The current README directs ongoing development to `starkware-libs/proving`; choose an exact revision before porting.
- [Pinned prover aliases](https://github.com/patrickdugan/zk-rusto-no-bitcoino/blob/de607d3db17d400dd6c2923d357f1d4a7bf233c7/integrations/nova-header-chain/src/main.rs) and [continuation/export executable](https://github.com/patrickdugan/zk-rusto-no-bitcoino/blob/de607d3db17d400dd6c2923d357f1d4a7bf233c7/integrations/nova-header-chain/src/bin/nova-chain.rs).

Sources inspected 2026-11-05. Performance figures from other machines are
not adopted as results of this package.
