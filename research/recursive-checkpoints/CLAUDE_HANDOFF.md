# Operator/Claude handoff: recursive pruned-node checkpoint pilot

Work in `patrickdugan/zk-rusto-no-bitcoino`. Target session: **November 5, 2026,
Asia/Manila**, after the recursive-sharding benches and SPV prototypes finish.
This handoff does not schedule or authorize an automatic deployment.

## Stage the additive preparation patch

The inspected baseline is `feat/statement-expected-output` at
`eb1bc5438cc9ad2830d19ef3e438e30e85ba3377`. Read `AGENTS.md` and the source lock.
Use a separate worktree; leave the active benchmark checkout and its output
files untouched. Suggested branch: `prep/recursive-pruned-checkpoints-20261105`.

```sh
git fetch origin feat/statement-expected-output
git worktree add -b prep/recursive-pruned-checkpoints-20261105 \
  ../zk-recursive-checkpoint-prep eb1bc5438cc9ad2830d19ef3e438e30e85ba3377
cd ../zk-recursive-checkpoint-prep
git apply --check /absolute/path/recursive-checkpoint-prep.patch
git apply /absolute/path/recursive-checkpoint-prep.patch
python3 -m unittest discover -s tools/research -p 'test_recursive_checkpoint_gate.py' -v
```

If a newer feature head contains the completed experiments, inspect its delta
and parameter changes first, then deliberately update/version the source lock
and gate. Avoid an automatic rebase onto unknown circuit changes. Do not merge
PR #12, #13, or #14 merely to stage these new files.

## Hold before launching new work

Collect the final recursive-sharding report and final SPV-prototype report.
Record commit and binary hashes, real proof paths, full public statements,
verifier output, cap implementation, phase peaks, and rejection-test logs.
A running job or an assistant summary cannot satisfy completion.

Inspect the exact sharding claim: verified bundle, sequential IVC, or a genuine
recursive merge proof. Preserve that label. The SPV report must identify the
network and expected-output policy. Keep Testnet4 and mainnet artefacts separate.
Run the preparation gate. Its initial all-pending result is expected to block.

## Implement a continuation-capable streaming prover

Reuse `integrations/nova-header-chain`; add an optional binary/module there.
Keep the existing CLI, NHC1/NSP1 formats, gateway receipts, and production service
configuration unchanged during the pilot. No Raito verifier authority transfers
to this backend.

1. Replace whole-history `BTreeMap`/`Vec<HeaderStep>` retention in the new path
   with a bounded header reader. Keep a small batch and the consensus state.
   Reject missing/duplicate heights, wrong widths, overflow, and truncated input.
   Pin the consumed input prefix and the authenticated starting state.
2. Persist the live `RecursiveSNARK`, fixed public parameters, original z0,
   verified current zn, and exact completed-step count. Specify serialization
   and size limits. Test the `new`/first-`prove_step` behavior of pinned Nova
   0.76.0 so a resumed run neither repeats nor skips its first transition.
3. Follow `continuation.schema.json` for the proposed sidecar manifest. Canonical
   field decoding, count/range checks, and full-state equality belong in Rust.
   The JSON schema alone proves nothing. Check source/circuit/parameter/key/network
   identities before loading a bounded payload, then verify the accumulator
   against original z0 and the saved step count before accepting a continuation.
4. Implement crash-safe publication with immutable generation directories.
   Write bounded temporary payload/manifest, flush durable files, verify, rename
   to a unique generation name, and publish the latest pointer atomically.
   Test the target OS/filesystem's durability semantics. Keep the previous
   verified generation until the new one is fully durable.
5. Save a periodic verified continuation without compressing each time. Provide
   separate commands for resume, verify-continuation, and compressed export.
   Keep `--k` immutable across a continuation chain. Fresh k or keys need a new
   chain/replay, unless a separately proven bridge exists.
6. Save benchmark output for checkpoint serialization and restore. Enforce the
   cap over children and filesystem buffers charged by the OS guard. Raw live
   accumulators can contain witness material; use private permissions and avoid
   claiming they are zero knowledge.

Recommended new CLI names are **proposals**, not existing commands:
`checkpoint-run`, `checkpoint-resume`, `checkpoint-verify`, `checkpoint-export`.
Do not invoke them until implemented and built. Existing commands are listed in
`commands.md`.

## Required tests and experiments

Use k=1 as fallback and k=5 as the first small-profile candidate, subject to the
finished benchmarks. Both use a 1,536 MiB hard cap. The optional k=10 laptop
comparison uses 8,192 MiB. Obtain the correct mainnet verifier key for each k;
the gateway's existing k=10 pin is not the k=5 pin.

Start with unit/negative tests, then small genuine proofs. Once those pass,
measure 1,000 and 10,000 headers including a real retarget boundary. Keep all
phase peaks. Include setup, fold, write, restore, compress, verify-cold, and
verify-warm. A compression failure must leave the last verified continuation
recoverable. Never turn on swap or relax the cap silently to obtain a pass.

A split/restart run must have the same verified terminal state and header count
as the uninterrupted reference. Byte equality of randomized proofs is unnecessary.
Kill after a committed checkpoint, during payload writing, and during latest-pointer
publication. Verify the surviving generation before continuing.

Reject corrupted payloads, forged step counts, wrong z0, wrong full state,
changed k, swapped parameters, wrong key, cross-network relabeling, missing or
reordered batches, and a fork sharing only the claimed height. Bind all 17 state
elements, including the MTP/retarget context and accumulated work. Retarget and
MTP checks must agree with the pinned native reference, with equality-to-MTP
rejected. A native reference is a differential check, not independent proof
soundness evidence.

For the SPV canary, verify actual NHC1 proof(s) using the pinned executable,
then use the existing NSP1 expected-output route. Test wrong txid/vout, changed
script/value expectations, stale block, full-state join mismatch, tampered
inclusion path, and Core reorg response. Record Core-attested unspentness as
its own observation. Empty/two-proof variants must preserve the same statement
and confirmation convention defined by the existing gateway.

The existing compressed Nova output remains the terminal artefact for this
pilot. A Pallas/Vesta-to-BN254 Groth16 bridge, a Sonobe port, and recursive binary
shard merges each require separate implementation and measurement. Full UTXO
transition proofs and witness deletion remain outside this deployment.

## Evidence and conditional rollout

Populate a copy of `evidence.pending.json`, using genuine retained reports.
Run `recursive_checkpoint_gate.py review` on an immutable evidence directory.
An exit-0 review still requires manual approval and actual verifier acceptance.
The tool is an evidence consistency helper, never a receipt issuer.

After dependency completion and all applicable gates, deploy only the experimental
checkpoint path under its OS cap. Use a separate output directory, pinned binary
and key, and an authenticated checkpoint. Begin with a read-only canary against
Core. Keep the existing RPC route and data-retention policy intact.

Stop on any boundary mismatch, cap violation, failed genuine verification, or
missing anchor. Roll back by stopping the experimental process and returning to
the previous verified generation. Recheck the active-chain view before reuse;
rollback does not make a stale fork current. Preserve failure evidence.

Return exact source commit, tested commands, results, skipped work, measured
memory, and deployment state. Keep a draft PR until real proof, restart, resource,
and SPV canary tests are reviewed. Never report a full-consensus pruned-node
certificate from a header-only run.
