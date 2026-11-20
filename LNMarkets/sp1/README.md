# Optional local SP1 prover

This directory prepares an SP1 6.9.0 proof of the relation in
[`../statement`](../statement). The guest calls the same bounded verifier used
by `lnm-native` and commits its exact, fixed public journal. Start with synthetic
fixtures and review the statement in [`../PROTOCOL.md`](../PROTOCOL.md).

**Proving status: no LNMarkets SP1 proof has been produced.** An ordinary host
`cargo check` validates Rust compilation for the host architecture. Building the
RISC-V ELF, executing it, and measuring a real proof remain separate steps.
Current test evidence belongs in [`../VALIDATION.md`](../VALIDATION.md).

## What this guest establishes

The proof binds both parties' BIP340 signatures on a batch authorization to the
checked oracle attestation, accepted contract commitments, the exact unsigned
batch transaction, and the sequential nullifier-root transition. These roots
track consumed batch authorizations. A consumer supplies the expected journal
from its own approved context and compares every byte, including its prior root,
venue, network, batch identifier, evaluation height, and expiry.

Original DLC plan and recovery digests remain opaque commitments in this
prototype. Bitcoin funding provenance, adaptor-signature validity, CET/refund
paths, actual Taproot witness signatures, and transaction relay require further
work. A proof of this relation cannot make an unsigned transaction spendable.
Fresh transaction signatures and a working unilateral recovery protocol remain
requirements for a custody upgrade. See the protocol document for the full
statement and its boundaries.

The public journal exposes batch metadata and aggregate totals. Hiding private
rows through a ZK proof still permits inference from small or recognizable
batches. Contract salts and local handling of witnesses are part of that privacy
model.

## Components and pins

| Path | Role |
| --- | --- |
| `program/` | Isolated guest, `sp1-zkvm = 6.9.0`, shared relation with native CLI disabled |
| `host/` | External-ELF execution and real proof verification; explicit local CPU Groth16 command |
| `host/`, optional `resumable` feature | Thin CPU binary that reuses the existing `nb3-prover` library under the reviewed host lockfile |
| `../scripts/local_prover.py` | Read-only plans by default, local commands only after `--run` |
| `../../integrations/bitvm3-nova/prover/` | Existing resumable CPU compressed prover, invoked by the runner |

The newly authored relation and guest use the repository's MIT license. The
host package declares **GPL-3.0-only**, matching its optional `nb3-prover`
dependency. A full copy is in [`host/LICENSE`](host/LICENSE). This component
scope leaves the native relation and guest under MIT.

Both standalone crates carry lockfiles. Pinning only `sp1-sdk = 6.9.0` permits
newer compatible transitive SP1 packages during a fresh resolution. These
lockfiles retain **6.9.0 for the entire SP1/slop family**, and the runner checks
that invariant before a build. Use `--locked` and review any future update as a
new program version. The initial locks derive from the repository's existing
M16 SP1 6.9.0 locks, with the workspace packages updated for this integration.

The guest initially uses upstream `k256 0.13.4` and `sha2 0.10.9`. Its signature
and hashing costs have not been measured in SP1. Adding compatible accelerator
patches is a later optimization and changes the ELF and program key. Existing
Shinigami/Nova measurements concern different guests.

The host requires an approved ELF SHA-256, an independently pinned program key,
and the exact expected journal plus its SHA-256. A program key read from a proof
bundle would permit a different program to define its own statement, so the
verifier derives the key from the pinned external ELF and checks the caller's
key pin. The key digest encoding matches the existing M16 interface: eight
`hash_u32()` values, each serialized little endian, then hex encoded. SP1's
`bytes32()` value is also recorded for other integrations.

`describe-program` emits **candidate pins for review**. Copying its output into
a trusted configuration needs source/build provenance review. Similarly, a
native demo journal is suitable for a synthetic run; a service's live verifier
must choose its expected prior root and settlement context independently.
Acceptance requires an atomic state update outside this CLI so competing batches
cannot consume the same prior root.

## Prepare now

From the repository root, inspect the available tools without creating files or
starting a build:

```sh
python3 LNMarkets/scripts/local_prover.py --dry-run
python3 -m unittest discover -s LNMarkets/scripts -p 'test_*.py' -v
```

Generate a synthetic witness with native verification:

```sh
umask 077
cargo run --locked --release --manifest-path LNMarkets/statement/Cargo.toml \
  --bin lnm-native -- demo --rows 1 --out LNMarkets/.local/native-1
cargo run --locked --release --manifest-path LNMarkets/statement/Cargo.toml \
  --bin lnm-native -- verify \
  --witness LNMarkets/.local/native-1/witness.bin \
  --journal LNMarkets/.local/native-1/journal.bin
```

The native result is an unproved relation check. Increase the row count only
after a one-row guest execution provides a useful cost measurement.

Python 3.11 or newer is required for the lockfile preflight. The runner reports
missing software in its plan and exits successfully in dry-run mode, allowing
preparation on a machine without SP1. An explicit `--run` exits with an error
when a prerequisite, pin, or file check fails.

## Build later

Install the SP1 **6.9.0** toolchain using the official installation instructions
and inspect `cargo prove --version`. The runner does not install or download a
toolchain on the user's behalf. Building dependencies and obtaining SP1's
wrapping artifacts can require network access. Witnesses stay on the local CPU
path; the SDK's network feature is disabled.
The host's SP1 dependencies require the Protocol Buffers compiler (`protoc`)
during compilation. Install it locally or provide its path through `PROTOC`;
`prost-build` stops with an error when it is missing.

First inspect, then explicitly run:

```sh
python3 LNMarkets/scripts/local_prover.py build --dry-run
python3 LNMarkets/scripts/local_prover.py build --run
```

This invokes `cargo prove build --locked` in `sp1/program/`, copies its ELF to
`LNMarkets/.local/prover/elf/lnm-batch.elf`, and builds the host in release mode.
There is no `build.rs` that silently compiles the guest. Guest build paths and
toolchain versions can affect the ELF and verification key, so preserve the
reviewed build environment and record the actual hashes.

Inspect the resulting candidate pins:

```sh
python3 LNMarkets/scripts/local_prover.py describe --run \
  --elf LNMarkets/.local/prover/elf/lnm-batch.elf
```

The file `LNMarkets/.local/prover/program-candidate.json` records both hashes.
Review the native journal with `lnm-native inspect --journal PATH` and compute
its SHA-256 using `sha256sum PATH`. Store the approved values outside the proof
bundle. The variables below are placeholders for that configuration:

```sh
LNM_ELF_SHA256=REPLACE_WITH_REVIEWED_ELF_SHA256
LNM_PROGRAM_VK=REPLACE_WITH_REVIEWED_PROGRAM_KEY_DIGEST
LNM_JOURNAL_SHA256=REPLACE_WITH_EXPECTED_JOURNAL_SHA256
```

The runner rejects those placeholder strings until they contain valid pins.

## Execute before proving

```sh
python3 LNMarkets/scripts/local_prover.py execute --run \
  --elf LNMarkets/.local/prover/elf/lnm-batch.elf \
  --witness LNMarkets/.local/native-1/witness.bin \
  --journal LNMarkets/.local/native-1/journal.bin \
  --elf-sha256 "$LNM_ELF_SHA256" \
  --program-vk "$LNM_PROGRAM_VK" \
  --journal-sha256 "$LNM_JOURNAL_SHA256"
```

The host checks the native relation, executes the guest with a single
`SP1Stdin::write_vec` frame, requires exit code zero, and compares the entire
committed journal with the expected bytes. Its report records ELF and program
key pins, witness and journal digests, instruction/syscall counts, and timings.
It labels this result `executed_unproved`. The relation limits the witness to
512 KiB and bounds its own row counts and arrays. The guest checks the frame cap
after `read_vec`; the host checks it before allocation into SP1 input.

Every operation writes new evidence files. Existing files cause an error; choose
a new `--work-dir` for a new execution, or use `verify` to inspect an existing
proof. Store real witness material outside Git. The default ignored
`LNMarkets/.local/` path contains all transient proof work, and the runner uses
private directory/file permissions on Unix.

## Resumable compressed stage

Build the wrapper around the existing CPU runner when ready:

```sh
cargo build --locked --release \
  --manifest-path LNMarkets/sp1/host/Cargo.toml \
  --features resumable --bin lnm-nb3-prove
```

The wrapper delegates to `nb3_prover::cli::main_with(Cpu)`. Its dependencies use
the same host lockfile, retaining SP1 6.9.0 throughout. The LNMarkets host remains
the final verifier with the approved program key.

```sh
python3 LNMarkets/scripts/local_prover.py compressed --dry-run \
  --elf LNMarkets/.local/prover/elf/lnm-batch.elf \
  --witness LNMarkets/.local/native-1/witness.bin \
  --journal LNMarkets/.local/native-1/journal.bin \
  --elf-sha256 "$LNM_ELF_SHA256" \
  --program-vk "$LNM_PROGRAM_VK" \
  --journal-sha256 "$LNM_JOURNAL_SHA256"
```

When ready to spend local CPU time, replace `--dry-run` with `--run`. The plan
contains a pinned host execution, `nb3-prove prove` with one proving permit,
and host cryptographic verification of the completed compressed proof. It passes
the expected public-journal digest to the resumable prover. Checkpoints live in
`compressed-checkpoints/`; rerunning the same command resumes its completed
tasks after an interruption. The existing prover checks that the input, ELF,
and proving configuration match its saved run. A completed proof is preserved;
use the verification action instead of starting it again.

**SP1 compressed STARK proofs do not provide zero knowledge.** Keep this stage
and its checkpoints private. A verified compressed report uses the explicit
status `compressed_proof_verified_not_zk`. No privacy claim follows from a
small proof or from hashing a witness.

## Explicit Groth16 proof

The host also exposes SP1's genuine Groth16 wrapper through a local CPU prover:

```sh
python3 LNMarkets/scripts/local_prover.py groth16 --dry-run \
  --elf LNMarkets/.local/prover/elf/lnm-batch.elf \
  --witness LNMarkets/.local/native-1/witness.bin \
  --journal LNMarkets/.local/native-1/journal.bin \
  --elf-sha256 "$LNM_ELF_SHA256" \
  --program-vk "$LNM_PROGRAM_VK" \
  --journal-sha256 "$LNM_JOURNAL_SHA256"
```

Replace `--dry-run` with `--run` for a deliberate full proof. The host's direct
command also requires `--allow-cpu-proving`. This path calls
`ProverClient::builder().cpu()` and `.prove(...).groth16()`, verifies the returned
proof with the real SP1 verifier and pinned public inputs, and only then saves
the proof bundle and report. An empty mock Groth16 encoding is rejected.

This command starts from the original witness and reruns the proof pipeline.
Importing an `nb3-prove` compressed checkpoint into the Groth16 wrapper is future
work. It has no resumability guarantee and no measured LNMarkets runtime or RAM
requirement yet. Begin with one row on a machine prepared for SP1's CPU proving
and wrapping requirements. The SDK may need its pinned circuit artifacts and a
working gnark/Docker wrapping environment, depending on the SP1 build. Consult
the versioned SDK and official setup instructions before a long run.

The host rejects development circuit mode and records `sp1_circuit_mode:
release`. SP1's `SP1_CIRCUIT_MODE=dev` changes the Groth16 verification artifacts,
so the runner rejects that ambient setting and explicitly pins release mode
for every subprocess.
The runner clears SP1's witness/trace dump environment controls. Direct host
invocations reject `SP1_DUMP`, `SP1_RECORD_WRITE_DIR`,
`SP1_RECORD_MAX_ARITY_INPUT`, and `SP1_RECORD_SHRINK_INPUT` so private material
cannot be redirected by an ambient debug setting.

Groth16 supplies SP1's ZK wrapper under its trusted-setup and soundness
assumptions. This source scaffold has produced **no Groth16 proof**. A report can
set `zero_knowledge_proof_verified: true` only after an actual Groth16 proof
passes cryptographic verification and the exact expected journal comparison.
It records the local backend, elapsed times, serialized proof SHA-256 and size,
and Groth16 wire-proof size. Fixed journal bytes are counted separately from the
cryptographic proof. No compression ratio is claimed before measurement.

## Verify with public information

A verifier needs the reviewed ELF and pins, expected journal, and proof bundle.
It does not need the private witness:

```sh
python3 LNMarkets/scripts/local_prover.py verify --run --mode groth16 \
  --elf LNMarkets/.local/prover/elf/lnm-batch.elf \
  --journal LNMarkets/.local/native-1/journal.bin \
  --proof LNMarkets/.local/prover/groth16-proof.bin \
  --elf-sha256 "$LNM_ELF_SHA256" \
  --program-vk "$LNM_PROGRAM_VK" \
  --journal-sha256 "$LNM_JOURNAL_SHA256"
```

Use `--mode compressed` for an existing compressed proof and retain its privacy
qualification. The verifier bounds proof input to 64 MiB, rejects trailing
bincode data and unexpected proof modes, requires a successful exit status
through SP1 verification, and compares the committed journal byte for byte.
Successful cryptographic verification does not update an exchange database or
declare a Bitcoin UTXO spent.

## Versioned API and security references

- [SP1 6.9.0 SDK feature flags](https://github.com/succinctlabs/sp1/blob/v6.9.0/crates/sdk/Cargo.toml): network support is optional.
- [SP1 6.9.0 LightProver](https://github.com/succinctlabs/sp1/blob/v6.9.0/crates/sdk/src/light/mod.rs): real proof verification and execution without proving.
- [SP1 6.9.0 prove request](https://github.com/succinctlabs/sp1/blob/v6.9.0/crates/sdk/src/prover/prove.rs): explicit Groth16 proof mode.
- [SP1 6.9.0 proof format](https://github.com/succinctlabs/sp1/blob/v6.9.0/crates/sdk/src/proof.rs): saved bundle and wire-proof encoding.
- [SP1 security model](https://docs.succinct.xyz/docs/sp1/security/security-model): individual STARK proofs lack zero knowledge; Groth16/PLONK wrappers provide it with their setup assumptions.
- [SP1 installation](https://docs.succinct.xyz/docs/sp1/getting-started/install): toolchain preparation; select the pinned release for this integration.
