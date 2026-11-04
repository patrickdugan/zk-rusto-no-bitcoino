# Recursive checkpoint preparation

Prepared 2026-11-04 for a conditional operator session on **2026-11-05, Asia/Manila**.
Repository: `patrickdugan/zk-rusto-no-bitcoino`.

## What is staged

This additive patch supplies an offline evidence gate, synthetic tests, a proposed
continuation-file schema, and an implementation/deployment handoff. It leaves all
existing Rust backends, services, proof formats, and running experiments untouched.
Nothing here invokes a prover or authorizes deletion of Bitcoin data.

The pending recursive-sharding benches and SPV prototypes must finish before the
operator starts this workstream's resource-intensive experiments. The date alone
never clears that hold. No scheduled task or background execution is created.

## Source audit and branch choice

The audited integration baseline is `feat/statement-expected-output` at
`eb1bc5438cc9ad2830d19ef3e438e30e85ba3377`. `main` was still
`daf9a06153788de7b0e45bb324905632dcf83982` when read. The Nova and NSP1 integrations
already exist on the feature branch. Start the prep branch there; moving onto a
newer integration commit requires a fresh source and key-pin review.

| Existing work | Observed state | Handling |
| --- | --- | --- |
| PR #12, `groth16-gym-bitvm-inputs-and-memory` | Corrects working-set-based RAM estimates and BitVM public-input claims | Preserve corrected measurements; do not reuse the earlier 64-header-fit claim |
| PR #13, `feat/groth16-resumable-header-checkpoints` | Bounded Groth16 proof bundles with recovery; draft | Keep as a regression/reference path; these bundles have no recursive merge proof |
| `feat/statement-expected-output` | Nova Pallas/Vesta + IPA, Spartan compressed proofs, NHC1 and NSP1, expected-outpoint checks | Baseline for this preparation |
| PR #14, `feat/nova-testnet4` | Separate Testnet4 circuit/key; based on expected-output branch | Keep network/key separation; the mainnet gate excludes this mode |
| Pending recursive-sharding benches | Completion has not been established here | Required evidence before the next workstream runs |
| Pending SPV prototypes | Completion has not been established here | Required evidence before deployment review |

The PR #14 report measured a Testnet4 k=5 run at 1,199 MiB peak job commit
under a 1,536 MiB cap. This supports trying a small profile; it supplies no
mainnet performance guarantee. Its checkpoint used chainwork zero and was
explicitly unauthenticated. Do not promote that checkpoint to a trusted anchor.

See `source-lock.json` for immutable references and inspected blob identities.

## Architecture selected for the next experiment

Use the existing Nova header circuit as a fixed-width transition over its **17
field elements**: height, two hash limbs, chainwork, epoch nBits, epoch-start
timestamp, and the eleven timestamps needed for MTP.

A live continuation checkpoint must retain the recursive accumulator and enough
pinned context to continue `prove_step` after a process restart. Compression is a
separate export phase. Keep the original authenticated initial state throughout
continuation; a locally produced digest never creates a new trust anchor.

The audited CLI currently loads its headers into a map and builds a `Vec` of all
step circuits. It writes only the compressed proof and verification inputs under
`--compress --save`. The required streaming path and serialized live-accumulator
resume path are implementation tasks in `CLAUDE_HANDOFF.md`; this patch does not
claim they exist.

### Composition boundaries

Within one run, Nova accumulates successive transitions. For an independently
proved shard, the receiver must verify its proof and all boundary state fields.
The existing NSP1 path verifies two Nova proofs and binds their full-state
digests. That remains a multi-proof composition.

An arbitrary binary merge of independent Nova proofs needs its own verified
merge relation or compatible PCD construction. A matching endpoint hash, a
receipt hash chain, or a list of proofs does not implement that relation.
Keep the pending sharding experiment's exact proof semantics in its own report.

### Final Groth16 path

The current export is a Spartan/IPA proof over Pallas/Vesta. A future BN254
Groth16 export needs an explicitly implemented and measured compatibility path,
with all auxiliary commitment checks and public-input binding specified. Treat
Sonobe/CycleFold as a separate candidate port with independent circuit/key
review. Its published on-chain decider design includes KZG checks outside the
Groth16 circuit. Do not describe the Groth16 element alone as the entire decider.

Keep terminal export optional. Record its memory separately from folding,
including setup, key loading, serialization, and cold verification. No wrapper
or curve migration is included in this preparation patch.

## RAM profiles to measure

| Profile | Headers/fold | Hard process-tree cap | Purpose |
| --- | ---: | ---: | --- |
| `small-k1` | 1 | 1,536 MiB | Conservative fallback |
| `small-k5` | 5 | 1,536 MiB | First candidate after existing benches finish |
| `laptop-k10` | 10 | 8,192 MiB | Separate laptop comparison after operator selection |

These are proposed limits. They are not new benchmark results. A run must keep
the same fold width, circuit identity, and parameters for its entire accumulator.
Changing k creates a new parameter set and requires replay or an explicitly
proved bridge. The existing gateway's k=10 key pin must never be reused for k=5.

The two small profiles implement the previously discussed 1.5 GiB experiment.
The 8 GiB profile is separate and remains opt-in. Choose one profile per evidence
package; compare packages rather than mixing their peaks or verifier keys.

Use Linux cgroup v2 `memory.max` with `memory.swap.max=0` and `memory.peak`, or a
Windows Job Object with both job-wide and per-process committed-memory limits.
Include descendants. Windows working set, process polling, and a queue's RAM
reservation do not establish enforcement. Measure setup, folding, checkpoint
write, restoration, compression, cold verification, and warm verification.

After the existing benches finish, measure 1,000 and 10,000 headers for the chosen
profile. The offline gate uses a review tolerance of 128 MiB growth between those
fold runs. This is an experiment criterion, not an asymptotic theorem. Retain the
raw memory trace and audit bounded streaming independently.

## Trust and pruning scope

The current circuit proves a checkpoint-relative header statement. It includes
PoW, retarget handling, strict MTP, selected version rules, and accumulated work
under its documented target range. Its README excludes the wall-clock future-time
rule, canonical-chain selection, certain unused target encodings, and genesis
initialization below height eleven.

SPV proves transaction inclusion under the header statement. `gettxout` adds
Core's current unspentness observation. Full UTXO-state validity, scripts,
complete balances, historical data availability, and full Bitcoin consensus
remain outside this checkpoint pilot. A header certificate cannot authorize
pruning a UTXO-validation witness or bootstrapping an arbitrary UTXO snapshot.

Keep Core's own normal pruning policy unchanged. Preserve proof artefacts and
continuation witnesses until restart and rollback gates pass. An already-pruned
node needs historical witnesses from another source to prove discarded work.

## Offline checks now

From the repository root:

```sh
python3 -m unittest discover -s tools/research -p 'test_recursive_checkpoint_gate.py' -v
python3 tools/research/recursive_checkpoint_gate.py review \
  research/recursive-checkpoints/evidence.pending.json \
  --root research/recursive-checkpoints
```

The second command intentionally exits **2** with `BLOCKED`. No candidate pins,
finished dependency reports, or new benchmark measurements are supplied.
The manual-only workflow runs these lightweight checks without invoking Rust.

## Evidence contract

`evidence.pending.json` has the exact accepted top-level schema. Populate a copy
outside the source tree. Every `pass` check names retained local artefacts with
SHA-256 and size; each benchmark names its raw report. Candidate pins bind source
commit, binary, verifier key, lockfile, initial state, and anchor policy.

A benchmark record has this shape (illustrative values are **not measurements**):

```json
{
  "phase": "fold", "headers": 1000, "k": 5,
  "wall_seconds": 1.0, "peak_mib": 1.0, "hard_limit_mib": 1536,
  "containment": "cgroup-v2", "metric": "memory.peak", "swap_max_mib": 0,
  "process_tree_covered": true, "exit_code": 0, "artifact": "fold-1000-report"
}
```

Allowed phases are encoded in the gate. Windows records use `windows-job`,
`peak-job-commit`, and `swap_max_mib: null`. Artefacts are bounded to 32 MiB each;
large parameter files stay outside this log package and are independently pinned.
Never put credentials, private node configuration, or raw private witnesses in it.

Exit 0 means `EVIDENCE_COMPLETE_OPERATOR_REVIEW_REQUIRED`; exit 2 means an explicit
hold; exit 3 means malformed or inconsistent input. The tool checks retained
bytes and declared evidence consistency. It does not authenticate who produced
a report or execute cryptographic verification. Use an immutable, operator-owned
evidence directory. Even a complete report outputs `deploy_authorized: false`
and `prune_authorized: false`.

The last decision belongs to the operator after reviewing genuine verifier
outputs, source ancestry, the resource guard, and a separate canary/rollback run.

## Sources

- Baseline code and statement protocol:
  https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/eb1bc5438cc9ad2830d19ef3e438e30e85ba3377
- Memory and public-input correction: https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/12
- Groth16 bundle checkpoints: https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/13
- Testnet4 mode and measured job-cap results: https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/14
- Nova's documented compression/curve choices: https://github.com/microsoft/Nova
- Sonobe's on-chain decider design: https://sonobe.pse.dev/design/nova-decider-onchain.html

External documents inform the candidate design only. Any imported implementation
must be pinned and audited independently; no new external dependency is added.
