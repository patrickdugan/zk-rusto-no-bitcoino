# Implementation handoff: setup-free recursive header proofs

Work in `patrickdugan/zk-rusto-no-bitcoino`. Keep this track under
`research/transparent-snarks/`. Preserve existing benchmark checkouts and
outputs. Do not merge or rebase unrelated PRs or launch a full-chain run.

The selected pipeline is Nova over Pallas/Vesta with Pedersen commitments,
compressed through Spartan/IPA. Keep trusted setup forbidden through final
verification. A KZG or Groth16 wrapper would require a different research
track and explicit user approval.

## Start from the inspected code

The new research folder is based on main. The actual prover lives on a
separate feature branch at the pinned revision below. In a separate local
worktree, inspect AGENTS.md and any instructions relevant to modified paths:

```sh
git fetch origin feat/testnet4-recursive-chain
git worktree add --detach ../zk-transparent-baseline de607d3db17d400dd6c2923d357f1d4a7bf233c7
cd ../zk-transparent-baseline/integrations/nova-header-chain
```

Inspect `Cargo.toml`, `src/main.rs`, and `src/bin/nova-chain.rs`. Preserve
`nova-snark = "=0.76.0"` for the baseline. Both executables must retain
`PallasEngine`, `VestaEngine`, and the IPA `RelaxedR1CSSNARK` type aliases.
Review parameter derivation in the exact dependency source. Review any
portable-arithmetic vendor patch and retain its hash.

Run the crate's existing release tests after checking their cost. Commit a
lockfile on the implementation branch when needed, then build with
`cargo build --release --locked`. Record build provenance before measuring.
The research package's Python tests do not establish that Rust builds.

## Small pilot using existing commands

These commands are the inspected CLI. Supply an actual height-indexed
header file containing the genesis header at byte offset zero and a Core
reference TSV in the format consumed by `native-check`. Pin both fixture
digests. The prover reads 80-byte headers from the raw header file.

Run each expensive command under the verified OS limits in BENCHMARK.md.
Use a fresh output directory for every case. Never overwrite ongoing jobs.

```sh
./target/release/nova-chain native-check --network testnet4 --headers "$HEADERS" --core-ref "$CORE_REF" --to 64
./target/release/nova-chain run --network testnet4 --k 8 --headers "$HEADERS" --out "$RUN_DIR" --to 64 --every 4
./target/release/nova-chain verify-continuation --dir "$RUN_DIR"
./target/release/nova-chain export --dir "$RUN_DIR" --bundle "$RUN_DIR/final.nht4" --vk-out "$RUN_DIR/vk.bin"
./target/release/btc-header-fold verify-bundle "$RUN_DIR/final.nht4" --vk "$RUN_DIR/vk.bin"
```

The final command checks the proof with the supplied key. For acceptance,
independently pin the expected key and compare the returned statement and
public state to verifier-owned expectations. Giving a prover-selected key
to a generic verification command is insufficient authentication.

For a resumability case, start a separate run with `--max-steps 4`, then:

```sh
./target/release/nova-chain resume --dir "$RUN_DIR" --headers "$HEADERS" --to 64 --every 4
```

Use the existing `NOVA_CHAIN_CRASH=<phase>:<n>` hooks in dedicated scratch
runs. Recheck each hook's exact generation/step numbering in source before
using it. Keep continuation files private to the prover; they contain
witness material. A changed fixture must be detected before resuming.

## Deliverables

Add an OS-limited measurement runner in the research folder, with real
prover and independent verifier results. Write tests for wrong public
inputs and cold restart. Keep the source-pinned plan updated through an
explicit reviewed change to policy.py and plan.json together.

Capture compression peak memory and the full continuation footprint.
After the small pilot and pending sharding/SPV checks pass, run the checked
12-case matrix. Save raw logs and a machine-readable result ledger with
unavailable or failed measurements clearly marked. Report the actual
statement proved and any remaining circuit restrictions.

Use the result to decide whether a Halo2/IPA or recursive FRI experiment
merits implementation. HyperNova can enter after the exact transparent
compressor and expected circuit benefit have been specified. Avoid adding
new cryptographic machinery before measuring the code already present.
