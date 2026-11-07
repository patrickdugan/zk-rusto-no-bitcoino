# Mythos work order: compactify the verification boundary

Owner: Patrick Dugan. Repository: `patrickdugan/zk-rusto-no-bitcoino`.
Workspace: `compact-skunk/`. Prepared 2026-11-07.

## Task

Develop a smaller, sound way to adjudicate the retained Nova/Spartan/IPA
verifier through non-interactive BitVM2. Produce an executable design point
with complete cost accounting. Mathematical redesign is welcome, including
additional transparent proof stages. Explore beyond tuning the current leaf
compiler, and keep each claimed improvement tied to an explicit relation.

Work toward a fixed verifier whose code and commitment structure can be
established before the disputed proof arrives. Permissionless challengers must
be able to refute an invalid claimed execution with the published data.

The proof pipeline must remain transparent through its final compression.
Preserve the current Bitcoin opcode model, including CAT-off execution. Record
bridge transaction/setup assumptions separately from cryptographic setup.
An interactive bisection game or garbled verifier belongs in an explicitly
labelled protocol-change lane. The primary lane retains BitVM2's existing
dispute structure. Keep BitVM3 and the separate garbled-verifier repository
untouched.

## Baseline to reproduce

Read `integrations/bitvm2-nova/msm_projection.py` at
`55e52156f800f0f39e4bc04ff76103c14633b273`, Git blob
`ed86b1b20ea37bac1e368e2aa4fbf72631e41852`. Run this folder's tests and source check.

| Quantity | Retained baseline |
| --- | ---: |
| Primary generators | 524,288 = 2^19 |
| Secondary generators | 16,384 = 2^14 |
| Projected Pippenger additions | 10,506,798 |
| Complete-add catalogue bytes, primary / secondary | 61,523,789 / 61,626,177 |
| Aggregate projected Script catalogue | 646,467,120,106,606 bytes |
| Projected full-word WOTS material | 15,709,764,369,600 bytes |
| Experimental forest budget | 1,342,177,280 bytes |

The catalogue spans possible disproof scripts. Transaction publication has its
own accounting. These operation counts come from one window-search heuristic,
and the per-addition costs come from M22. Their product supplies a baseline
against which to measure a new architecture. It supplies no universal lower
bound. The forest budget is a construction policy.

At the unchanged operation count, filling that budget allows about 127.744
catalogue bytes per point operation, with zero allowance for other components.
Use this as a diagnostic. Measure practical storage and construction costs if
a candidate proposes changing the forest policy.

PR #22's 36-word boundary scenarios leave Pippenger state unproved. This packet
counts actual dependencies for chosen tiny schedules; its default point encoding
uses 19 u32 words, including an infinity flag. Internal field constraints and
proof-dependent routing still require separate accounting.

## Mathematical target

The inspected IPA relation, with the repository's notation, is

    C + (r0*c) U + sum_j (u_j^2 L_j + u_j^-2 R_j)
      = a_hat * G_hat + (r0*a_hat*<b,s>) U,
    G_hat = sum_i s_i G_i.

For d challenges and MSB-first binary index b_0,...,b_(d-1),

    s_i = product_j u_j^(2*b_j-1)
        = alpha * product_j (u_j^2)^b_j,
    alpha = product_j u_j^-1.

Thus G_hat is a group-valued multilinear polynomial evaluated at u_j^2,
scaled by alpha. Investigate that structure. The coefficient tensor factorizes;
the fixed generator table still has to enter the authenticated computation.
Write the complete evaluation algorithm and count its group operations,
preprocessing, storage and authentication. Tests in `lab.py` verify this
identity over tiny additive fields; they establish only the identity.

A terminal-only proof must establish the same G_hat for the exact ordered
production generators and transcript-derived challenges. A full wrapper must
prove acceptance of the exact native verifier, with key/circuit identity and
public inputs fixed by the disputed statement. State explicitly whether an
auxiliary proof is zero-knowledge; validity alone does not establish that claim.

## Candidate work

Develop the four lanes in RESEARCH.md far enough to compare their costs. Select
one for a bounded implementation. Begin with a dependency census and an
independent soundness sketch. Use small real Pasta cases on hosted CPU before
scaling to the retained key. Keep a rejected candidate's counterexample or
cost obstruction so another agent can reproduce it.

A substantive first result may be a working authenticated supernode, a new
fixed-generator evaluation algorithm, or a transparent terminal certificate.
For each result, include a falsifiable claim and the adversarial test that
would invalidate it. An unmeasured wrapper estimate remains a proposal.

## Inputs already available

All paths below are relative to `integrations/bitvm2-nova/` at the baseline.

| Read | Purpose |
| --- | --- |
| `NEXT.md`, `CLAUDE-HANDOFF.md` | M23 state, measurement boundaries and current open joins |
| `ipa_algebra.py`, `ipa_statement.py`, `ipa_runtime.py` | Equality, ordered coefficients and proof-derived terminals |
| `bench_ipa_msm.py`, `NATIVE-CONFORMANCE.md` | Actual native-terminal harness and its scope |
| `GROUPED-CONVOLUTION.md`, `GROUPED-POINT-FOREST.md` | Measured complete arithmetic and shared openings |
| `AUTH-COST.md`, `WOTS-REGISTRY.md` | Authentication format and unique word identity |
| `PROOF-ADMISSION.md`, `PROOF-POINT-ORIGINS.md` | Proof parsing and point origins |
| `fixtures/nht4-genesis-0-2020-k5*` | Retained proof and trace/key/generator descriptors |

Native reference: branch `feat/testnet4-recursive-chain`, commit
`de607d3db17d400dd6c2923d357f1d4a7bf233c7`. Its known proof fixtures are listed in
`CLAUDE-HANDOFF.md`. Check availability and hashes before executing a benchmark.
The retained trace SHA-256 is
`394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8`.
The testnet4 k=5 key SHA-256 is
`1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24`.
Here k counts headers per fold. Preserve it for an existing continuation.

## Evidence required

Use `experiment-template.json`. Report catalogue bytes separately from the
largest spend, including witness and control-block weight. Count assertion
publication and setup material. Give cold and warm verifier times, prover time,
peak memory and precomputation amortization. Leave unavailable metrics null.
Record security parameters, every conditional assumption and the effective
soundness of the composed protocol.

A candidate must pass honest inputs and targeted invalid cases: a wrong
network/key, changed expected end state, reordered or substituted generators,
changed transcript challenges, a broken shared wire, hidden bucket corruption,
invalid curve/infinity encodings, noncanonical scalars, and malformed lengths
including truncation and trailing bytes. Include an equivocation attempt that
passes local arithmetic when adjacent chunks use different states. Attribute
any rejection to the layer that enforces it. A parser panic earns no rejection
credit.

For a wrapper, bind its circuit/version and generator ordering. Replay the same
outer proof against altered public inputs. Enforce transcript ordering and
bounded query schedules. For a fixed-base table, test one wrong entry and a
valid entry from another key. For state hashing, demonstrate that the bytes
hashed are the bytes consumed by arithmetic.

The full gate requires a composition argument: honest executions admit no
successful disproof; every invalid claimed execution admits an accessible
spendable disproof, including malformed assertions. The transaction graph,
timeouts and data availability are separate deliverables. State their status.

## Operating limits and handback

Keep preparation cheap and offline. Native/Script benchmarks belong in bounded
hosted jobs. Reuse existing proofs; keep new header proving and GPU jobs paused.
For a later approved prover pilot, plan around 16 GiB physical RAM with a 13 GiB
whole-job cap and swap disabled, then report the enforced limit. Respect other
workers and avoid parallel heavy jobs. Changes outside this folder need an
explicit reason; preserve all existing baseline implementations and caps.

Return `FINDINGS.md` with source commits, the tested relation, commands and
results. Provide the candidate code and adversarial fixtures under a named
experiment directory, an updated cost table, and the next test that determines
whether scaling is justified. Push with a checked current head. A failing
candidate should still leave reproducible research behind.
