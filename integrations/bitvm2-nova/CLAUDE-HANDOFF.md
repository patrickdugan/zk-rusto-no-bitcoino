# Nova SNARK / BitVM2 handoff after M23

> **Paused (2026-11-07, Patrick).** The BitVM2 route is unlikely to give a
> lean proof. The linear IPA MSM, the proof-byte assertions and the
> 4,296-constraint MSM term are the measured reasons. Work moves to
> exploring BitVM3. M23–M26a stay on main as measured baselines (see
> [STARK-ROUTE.md](STARK-ROUTE.md)). Do not resume M25c/M26b/M26c without
> a new go-ahead.

## M23 deliverable (Claude, 2026-11-07)

[PROOF-POINT-ORIGINS.md](PROOF-POINT-ORIGINS.md) is tested on implementation
commit `598d4b8fb9489b889399f03b1162c5c9883dc1cc`. Its measured run is
[42371873061](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42371873061)
on `a300b1f`. The later commits changed only the workflow: the bench parent's
CPU hard limit and the public annotations. All 78
retained compressed commitments are bound in Script, at their physical payload
BYTEs, to canonical `(infinity, x, y)` with `y^2 = x^3 + 5` and the sign bit
equal to the parity of y. Complete honest sources measure 887,723,899
(Pallas) / 727,322,403 (Vesta) Script bytes; both roles pass 382,408 calls.
Strict halo2curves decoding agrees with the leaf relation for every decoder
of every profile. All 24 earlier workflows pass the implementation commit.
Code lives in `proof_point_origins.py`, `bench_proof_point_origins.py`,
`point-origins-oracle/` and `bitvm2-nova-proof-point-origins.yml`. Logs and
artifacts need sign-in, so the workflow publishes its measurements as public
annotations.

**Decision before more component work.** The
[IPA MSM feasibility gate](NEXT.md#ipa-msm-feasibility-gate-projection)
prices the IPA terminal's generator MSM from measured M22 costs (code:
`msm_projection.py`). Over 524,288 + 16,384 generators it needs about 10.5
million point additions: about 588 TiB of Script and 1.57e13 bytes of
assertion signatures. Because BitVM2 signs every chunk boundary on-chain, the
transparent Spartan/IPA verifier cannot be completed for non-interactive
BitVM2 by backend optimization alone. The owner has to choose one of:
* a polylogarithmic transparent final compression;
* an interactive bisection dispute;
* relaxing the no-trusted-setup policy.

Components 3-5 below are worth building only under a route that removes the
linear MSM.

**Route chosen (2026-11-07): transparent STARK final compression.**
[STARK-ROUTE.md](STARK-ROUTE.md) has the argument, the measured M24 BLAKE3
cost (76,695 Script bytes per block; run 42377941685) and the milestone
order:
* M25: a size-targeted final layer of at most about 80 KB;
* M26: Script Merkle-path chunking;
* M27: the outer prover with a pinned affine key.

Proof-byte assertion (63.6 MB for the 1.27-MB SP1 proof) is now the binding
constraint.

## M22 deliverable

Start from tested main `6697b7ffb20dadc3c7e0639baabad8adefc3bbb5`
(implementation `0422b29bfb4f07d2c25f736295e335c7d655c7c8`).
[GROUPED-POINT-FOREST.md](GROUPED-POINT-FOREST.md) records the code, reproduction,
actual costs, checks, hashes and limits. The grouped complete point/one-bit
relation now works in actual eleven-component BitVM commitment forests.
Both roles and paired accounting pass: 668,076 native Script calls, 360,190
expected rejections. Complete costs are 824,415,257 / 824,501,399 Script bytes,
27,062,411 fewer per role. All 24 existing workflows pass the implementation
commit; fourteen Python and eighty-nine Rust tests pass per new role job.

Working components include authenticated WOTS word links, exact witness-length
guards, canonical field/point arithmetic, scalar-bit reconstruction, linked
rho/following-c transcript fragments, actual Taproot trees/forests, sumcheck
fragments and retained proof-payload scalar origins. Native retained-profile
transcript, matrix and IPA-terminal checks also exist. These components do not
yet form a complete Nova proof-acceptance/dispute verifier.

## Remaining components

1. **Whole-proof decoding and origins in Script.** Reuse the pinned native
   codec and extend the retained maximum-width scalar-payload source to bounded
   general NHT4/NHC1 trace coverage, variable widths,
   lengths/EOF and opaque commitments. Bind actual proof bytes and verifier-owned
   network, key, k, step count and initial/final public state. JSON receipts are
   observations; invoke the native verifier freshly for differential checks.
2. **Point encodings and key/proof origins.** M23 binds the proof's
   compressed commitment bytes to canonical coordinates. Still open:
   * connecting those coordinates to A/P ports and transcript inputs. Each
     needs the 65-byte affine encoding `x || y || [!infinity]`; the decoder
     already holds x's and y's BYTE words.
   * authenticating the generators and key material. Current A/P remain
     asserted ports.
3. **Complete Fiat-Shamir transcript in Script.** Compose the actual initialized
   Poseidon/Keccak protocol schedule, absorption, padding, squeeze and challenge
   reductions. The current graph links rho to one following sumcheck challenge;
   native retained replay is not a complete Script transcript.
4. **Complete Spartan equations.** Compose all required sumcheck rounds,
   terminals and authenticated matrix evaluations. Existing two-round/local
   arithmetic and native retained matrix checks are useful baselines.
5. **Scalar multiplication, MSM and IPA on both curves.** M22 supplies one
   `R=A+bP` step, not all 255 steps or an MSM. Lower the complete IPA equations,
   authenticate generator/key access, and connect every scalar/point origin.
   The retained k=5 native dimensions are 524,288 primary / 16,384 secondary
   generators and 19 / 14 IPA rounds; native terminal success is not Script IPA
   verification.
6. **Production assertion and complete dispute composition.** Replace test-only
   signing with the intended one-time-key lifecycle and externally owned
   assertion/root/context binding. Compose every boundary and establish a
   disproof path for every invalid execution, preserving canonical encodings,
   all anchors, opening identity and exact witness length. Existing honest/local
   roots and private faulty-fixture roots cannot supply production authority.
7. **Bitcoin transaction graph and end-to-end spends.** Add assertion UTXO,
   presigned transactions, challenge paths, timelocks, witness/weight accounting
   and spendable valid/invalid-proof tests. No such graph or deployment is
   delivered by M22.

## Next bounded task and stop conditions

M23 closed the commitment-decoding boundary. Settle the MSM gate first. If
the current route continues, the next bounded relations are:
* the 65-byte affine transcript encoding of the decoded commitments;
* the 556-byte header-to-`zn` binding (`public_state_to_zn_script_bound`).

Applying the grouped-AB transform to the decoders is the matching cost
experiment: their AB/PQ/column leaves are 95.8% of decoder bytes. Use the
existing real proofs; specify one closed source relation,
preserve the current implementation as baseline, test malformed/coherent
substitutions independently, then measure actual Script/forest effects under
the same caps. Require both roles and direct worker execution; no imported result
receipt may authorize acceptance. Stop and document a source/link mismatch,
accepted malformed authentication, unexpected interpreter/process failure or
resource-cap failure. Never count a panic as successful rejection or lift a cap
silently. Preserve empty, truncated, prepended and appended witness cases.

The size feasibility gate remains: the existing shared-prefix transcript
projection is 75,413,392,968 Script bytes (70.234 GiB), beyond the current
1.25-GiB/16-component experimental forest policy. It is an unmeasured projection,
not a theorem about Bitcoin or a lower bound on all implementations. Full MSM/IPA
size is also unresolved. Do not extrapolate the point savings into a completed
verifier or a dependable completion date.

## Existing real proof source

Use header-verifier branch `feat/testnet4-recursive-chain`, pinned
`de607d3db17d400dd6c2923d357f1d4a7bf233c7`, as the native baseline.
The earlier `feat/nova-testnet4` verifier accepts a testnet4 bundle relabelled NHC1
with a testnet4 key; the pinned baseline rejects a key with a different
`(network,k)`. Preserve that negative test.

Local materialized source (read `source-manifest.json` at its parent):
`C:\Users\patri\Documents\Codex\2026-11-05\task-4\proving-standalone-de607d3\integrations\nova-header-chain`.
Its `fixtures/testnet4/` contains real compressed proofs and receipts:
`genesis_0_158970_k5.nht4`, `genesis_0_2020_k5.nht4`,
`auth_100700_100900_k5.nht4`. The testnet4 k=5 key SHA-256 is
`1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24`;
genesis anchor state SHA-256 is
`9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c`.
`fixtures/nova100.nhc1` is the mainnet k=10 fixture; its key SHA-256 is
`e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698`.
These proofs require no new proving. Repository branch commands, logs and
SHA-256s are in `research/recursive-checkpoints/testnet4/README.md`.

The BitVM2 retained fixture and its replay/key/matrix/generator descriptors are
under `integrations/bitvm2-nova/fixtures/nht4-genesis-0-2020-k5*` in this checkout.
Read [NEXT.md](NEXT.md), [PROOF-PAYLOAD-ORIGINS.md](PROOF-PAYLOAD-ORIGINS.md),
[MATH-COMPOSITION.md](MATH-COMPOSITION.md), [PROOF-ADMISSION.md](PROOF-ADMISSION.md)
and the selected source modules before editing.

## Work boundaries

User authorizes direct pushes to main and parallel agents; recheck current heads
and active ownership first. No PR ceremony is required. Keep this transparent:
no trusted setup, including final compression. k denotes headers per shard/fold,
not a Halo2 exponent. The stated proving budget is 16 GiB, but existing proofs
already cover this next verification work. Do not launch new proving/GPU jobs
just to consume that budget. Keep local checks to parsing/math/schema, bounded
hash/compiler checks and formatting; run graph/native/Script work in the hosted
workflow unless the user changes that policy.

Do not alter header provers/k settings, BitVM3 or Claude/testnet4 work, security
or access settings, spend or transact. M19 point-auth-cost drafts and the dirty
local NEXT.md are private paused work: do not import, publish or retry them.
Read `git show HEAD:integrations/bitvm2-nova/NEXT.md` for the canonical published
roadmap rather than the private working copy. This handoff closes M23;
further feature work waits on the MSM-gate route decision.
