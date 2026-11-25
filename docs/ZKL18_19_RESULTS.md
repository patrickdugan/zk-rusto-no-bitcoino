# ZKL-18 verified and ZKL-19 native preflight

## ZKL-18 retained evidence

Measured source a5c6acb571138342fb0090ef1303b46645b2ae87; hosted job [139098960257](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45583447979/job/139098960257) success. Five recursive and compressed Nova proofs, 92 typed rows, eight local rule kinds, nine malformed public compiler cases and four forged constraint assignments rejected. Raw constraints 11197/step; augmented primary/secondary 22575/10349; serialized proof 11096 B per case, VK 27235968 B. Peak RSS 259936 KiB, elapsed 78.65 s. Independent [Lean 4 replay](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45583447979/job/139098960754) accepted five closed definitions without axioms. The JSON retained alongside this note is parsed stdout. ZKL-18 is a hybrid with native semantic compilation; not a fully constrained typing checker.

## ZKL-19 local evidence

Unified circuit and fixed rule table commit fa125e191bfa094433ac395dc7bc69e6a2560989; source and dedicated CI commit 109ed7dba35bd7a58f1adf40be6162db9aeaf0f6. Frozen native fixture digest 3f859e7cb9808fe04208497f296e26b73ccd0387eb9b307327d200011eccb100; fixed rule table digest 7e98eaf808b2a80179b203d02f912d814dc939f3802ee6d672b14d473553febf. All 185 native rows across six cases and all 32 local rule cases pass recursive replay and 517 fixed linear conditions (per-rule selected equations). All 5371 substitutions of a prior reference by a different judgment in those same fixtures are rejected by the integer-equation evaluator. These are exact finite conformance checks, not Nova or universal soundness results.

The first five fixtures correspond to the same ZKL-18 closed typed endpoints and need 16/60/30/35/13 unified rows (154 in total). The sixth is an operation-coverage fixture with additional honest raw relation rows preceding a closed identity proof. It exercises the remaining selectors and is excluded from the five-case row comparison. Public host admission only checks syntax bounds, canonicality and backward pointers. The proposed circuit checks the actual semantics, rather than a public table of trusted inferences. Host must reconstruct the independently specified goal, arena and initial state; proof syntax is still public. No privacy claim, no general Lean kernel, no paid GPU.

## Fresh capacity diagnostics (native only)

`python scaling.py` after generating `unified-fixtures.json` via the retained native generator. 64 fresh roots each, seed ranges 22000..22063 (weakening), 23000..23063 (dependent application), 24000..24063 (conversion). All 192 generated proofs passed native replay and equation checks. The row counts are not an optimum or measured runtime.

| family | hybrid rows | unified rows | max rows | max objects | fit64 | fit128 | fit256 |
|---|---:|---:|---:|---:|---:|---:|---:|
| weakening | 2296 | 4260 | 153 | 60 | 36 | 57 | 64 |
| dependent_app | 4053 | 14829 | 442 | 199 | 6 | 11 | 38 |
| conversion | 3304 | 6217 | 200 | 81 | 20 | 43 | 64 |

Totals: 9653 hybrid and 25306 unified rows. 62/192 fit 64 slots; 111/192 fit 128; 166/192 fit 256; all fit 512. Increasing capacity is a prospective circuit shape change, not a measured cost. Dependent applications and repeated lifting/lookup are priorities for representation improvements. Compare only within a fixed semantics and circuit shape; ZKL-18 offloads work that ZKL-19 explicitly checks. Dedicated ZKL-19 workflow [45586064820](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45586064820) remains pending at handoff. No cryptographic measurements claimed until the hosted run completes.
