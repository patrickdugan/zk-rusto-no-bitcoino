# IPA MSM feasibility: costed alternatives (M24 research gate)

Scope: non-interactive BitVM2 disproof verification of the retained Pallas/Vesta Nova/Spartan IPA terminal. This is a decision model rather than a new verifier, a Bitcoin consensus limit, or a proven IPA complexity bound. No proving, transaction construction or hosted Script tests were run.

## Reproducible source and units

The repo's [msm_projection.py](msm_projection.py) and [test_msm_projection.py](tests/test_msm_projection.py) count a Pippenger window-search heuristic over the two M22 grouped-complete-addition components measured in [GROUPED-CONVOLUTION.md](GROUPED-CONVOLUTION.md).

| Role | Generators | Window | Projected additions | Measured Script bytes/addition |
| --- | ---: | ---: | ---: | ---: |
| Pallas / primary | 524,288 | 15 | 10,027,280 | 61,523,789 |
| Vesta / secondary | 16,384 | 10 | 479,518 | 61,626,177 |

The product is **646,467,120,106,606 aggregate disproof Script bytes (~588 TiB)** across the catalogue of possible dispute scripts. This is distinct from publication of individual Bitcoin transaction scripts. The separate WOTS estimate charges 7,476 u32 words per operation at 200 signature bytes per word: **15,709,764,369,600 bytes (~14.29 TiB)** of hypothetical assertion signature material.

The constructor's 1,342,177,280-byte (1.25-GiB) forest policy is an experimental implementation budget, rather than a Bitcoin consensus limit. The baseline Script projection is 481,655.54 times that budget. Its break-even arithmetic permits **127.74 Script bytes per original point operation on average** with nothing left for the rest of the verifier. No general lower bound is implied.

## Alternative cost envelopes

The executable sensitivity analysis is in [ipa_design_space.py](ipa_design_space.py), tested in [test_ipa_design_space.py](tests/test_ipa_design_space.py). Invoke:

    python integrations/bitvm2-nova/ipa_design_space.py --comparison

The CLI also accepts --msm-operation-reduction, --script-cost-reduction, --additions-per-chunk and --boundary-words. Parameters denote *hypothetical* reductions. Operation counts and signature boundaries are rounded separately for both curves.

| Design/stress case | MSM catalogue Script bytes | Signature material bytes | Status |
| --- | ---: | ---: | --- |
| M22 x Pippenger baseline | 646,467,120,106,606 | 15,709,764,369,600 (full asserted-word estimate) | Existing cost projection; complete verifier unmeasured |
| Coarse groups of 64 additions with 36 signed u32 boundary words | 646,467,120,106,606 | 1,182,038,400 | Signature-only sensitivity, arithmetic unchanged |
| Groups of 256 additions with 36 boundary words | 646,467,120,106,606 | 295,531,200 | Signature-only sensitivity, sound ports unproven |
| 100x fewer MSM additions and 1,000x cheaper Script per operation, 64/group | 6,464,734,040 | 11,836,800 | Aggressive combined 100,000x hypothetical improvement still over budget |
| 500,000x cheaper Script per operation, unchanged count | 1,292,934,241 | 75,648,960,000 (one/group) | MSM alone fits; only 49,243,039 bytes (~47 MiB) spare |
| Transparent succinct wrapper of Nova verifier acceptance | unmeasured | unmeasured | Script verification, proof size, prover RAM and soundness gate remain |

The boundary-only estimate assumes exactly 36 signed words per chunk boundary: two nine-limb field coordinates per point, at two authenticated point states. It is an optimistic accounting toy, **not a soundness proof or a lower bound**. Real Pippenger bucket state, generator/key provenance, challenge origin, WOTS lifecycle, canonical encodings, chunk stitching, tree overhead, and malformed assertions may demand larger ports or other authentication. Sharing a wire is useful only when all its producers and consumers remain bound. Larger chunks may encounter interpreter, leaf, witness and transaction limits. Chunking itself leaves the arithmetic catalogue unchanged.

The MSM-operation scenario does not assert the availability of 100x fewer additions. Fixed-base tables must be authenticated and the IPA's challenge-product scalars are proof-dependent. New scheduling, arithmetic or precomputation should be measured against native IPA outputs, using complete Script components and matched accounting.

## Transparent wrapper candidate

Maintain the existing policy of **no trusted setup through the final layer**. The candidate proves that the native Nova/Spartan/IPA verifier accepts for a pinned statement, verifier/circuit identity, proof bytes, generator set and public inputs. Bitcoin would verify the outer transparent proof. A STARK/FRI-style wrapper with Script-native hash choices such as SHA-256 merits a pilot. No outer system or complete verifier is selected.

The outer prover still has to evaluate or arithmetize the large IPA MSM. Its RAM, time, proof bytes, soundness and Bitcoin Script verifier catalogue must be measured. The 16-GiB prover memory target is a separate gate. [Transparent SNARK research PR #16](https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/16) studies Nova/IPA final compression, whereas this gate studies proving the *Nova verifier* itself. They are different verification statements.

## Measured next experiments

1. Chunk-soundness microcases: compose one, two, four and eight point operations with authenticated shared boundaries. Count actual WOTS signatures, complete Script leaves, forest bytes, witnesses and runtime. Reject tampered hidden buckets, generators, challenge products, canonicality aliases, source swaps, truncated packets and bad linked states. Stop on any accepted forgery.
2. MSM arithmetic microcases: benchmark changed Pippenger windows, fixed-base tables, specialized add/double, sharing and any verifier-key preprocessing against both real retained proof-derived IPA terminals. Include table provenance and complete disproof costs in the same accounting.
3. Outer transparent pilot: verify a small independently falsifiable transparent proof in the intended Bitcoin Script executor, price SHA-256/Merkle openings and finite-field checks, then wrap a bounded native-verifier subtrace. Track 16-GiB prover peak RSS, proof security, honest/invalid cases and end-to-end key and public-input binding. No Groth16/KZG or setup fallback.

Passing any microcase adds a measured design point. A production gate still needs complete decoding, transcript, all algebra, authenticated proof/key origins, every invalid-execution dispute path and a spendable Bitcoin transaction graph.

[NEXT.md](NEXT.md) and [CLAUDE-HANDOFF.md](CLAUDE-HANDOFF.md) retain the M23 handoff. This branch changes no provers, header parameters or Bitcoin transaction code.
