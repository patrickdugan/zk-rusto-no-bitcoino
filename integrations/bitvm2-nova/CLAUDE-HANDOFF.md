# Nova SNARK / BitVM2 handoff after M22

## Deliverable to keep

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
2. **Point encodings and key/proof origins.** Bind compressed point bytes and
   canonical decoding to actual graph coordinates. Connect A/P/commitments and
   generators to authenticated proof/key material. Current A/P are asserted
   ports; local curve correctness does not authenticate their origin.
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

Prefer closing a proof-byte/point-origin boundary using the existing real proofs
before adding more arithmetic optimizations. Specify one closed source relation,
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
roadmap rather than the private working copy. This handoff closes M22;
further feature work is deferred to the next owner.
