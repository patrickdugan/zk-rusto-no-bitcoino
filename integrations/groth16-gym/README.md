# groth16-gym

BN254 Groth16 circuits for two Bitcoin statements. The bench measures what
fits in a laptop's memory. The proofs are arkworks 0.5 (`ark-groth16`)
proofs on BN254, the curve and proof type of BitVM's chunked Groth16
verifier. They do not fit that verifier as they are: each circuit exposes
7 public inputs, and the verifier takes one (see "BitVM" below).

| Circuit | What it proves | Public inputs |
| --- | --- | --- |
| `spv` | one output of a transaction is in a block (see below) | block hash, txid, value, script SHA-256 |
| `headers N` | N consecutive headers in one difficulty epoch (see below) | start prev-hash, end hash, nBits, target |

**`spv` checks:**
- txid = SHA256d(tx);
- the txid's Merkle branch reaches the header's merkle root;
- the block hash = SHA256d(header);
- the output's value and script hash are read from the hashed tx bytes.

**`headers N` checks** (all N headers):
- each header links to the previous hash;
- each header carries the epoch's nBits;
- each header's SHA256d is at most the target.

Each 32-byte value is two field elements, as described in `src/lib.rs`.

Fixtures are real mainnet data:
- **Payment:** tx `fd2fdd44…daa6`, output 0, 2,010,000 sats, in block 959,984 (13-level Merkle branch).
- **Headers:** 959,617–959,994, a single epoch.

## Run

Windows (PowerShell, Rust via rustup):

```
powershell -ExecutionPolicy Bypass -File run-gym.ps1 -CapGB 12
```

Linux or WSL:

```
./run-gym.sh 12
```

**What the run does:**
1. Builds the gym.
2. Proves and verifies `spv`.
3. Proves `headers 1, 2, 4, …`, stopping before the next doubling's predicted peak memory passes the cap.

**Output:**
- Each run is its own process and prints one JSON line: constraints, setup/prove/verify time, proof/vk/pk sizes, peak RSS, `verified`, and `rejects_wrong_input`.
- Lines are appended to `results/<host>-<date>.jsonl`.

`cargo test --release` runs the tamper tests (about 2 minutes). Each statement field and each witness part (tx, Merkle sibling or direction, header) is altered, and the circuit must reject it.

The gym is its own Cargo workspace, and no CI workflow builds or tests it. Run `cargo test --release` here before relying on a change.

**Peak memory differs by OS.** On Linux, `peak_rss_mb` is `VmHWM`. On Windows it is `PeakWorkingSetSize`, which Windows can trim under pressure, so it can read lower than the memory the process actually committed. Compare Windows and Linux figures with that in mind.

**Hard limit (Windows).** `run-capped.ps1` runs one proof in a job object whose limit on committed memory the OS enforces, and it records the peak committed memory:

```
powershell -ExecutionPolicy Bypass -File run-capped.ps1 -LimitGB 13 headers 36
```

Build first with `run-gym.ps1` or `cargo build --release`. Each run appends a line to `results/<host>-capped.jsonl`. If the proof needs more than the limit, an allocation fails and the line has `"completed":false`.

## BitVM

BitVM's chunked verifier (BitVM/BitVM `c620dbf`, `bitvm/src/chunk/api.rs`) has `NUM_PUBS = 1` and `PublicInputs = [ark_bn254::Fr; NUM_PUBS]`. Script generation asserts `vk.gamma_abc_g1.len() == NUM_PUBS + 1` (`api_compiletime_utils.rs`), so a verifying key with more public inputs is refused.

Both circuits here expose 7 field elements:
- **`spv`:** block hash (2), txid (2), value (1) and script SHA-256 (2).
- **`headers N`:** start prev-hash (2), end hash (2), nBits (1) and target (2).

To go through BitVM, a circuit has to expose one public input that commits to the statement, such as a hash of the seven values computed in the circuit, and the verifier recomputes that hash natively. That adds the hash's constraints to every circuit. Neither the change nor its cost is measured here.

## Limits

**Trusted setup.** `circuit_specific_setup` runs with a seeded RNG, so the
toxic waste is known. These keys are for measurement only. A real
deployment needs either:
- a ceremony for the circuit, or
- proving inside a zkVM whose Groth16 setup already exists (SP1, RISC0).

**Transaction layout.** The SPV circuit is specialized to one transaction
layout: its length and every count and length byte are circuit constants,
so the parse that locates the output is forced. Another layout means
another circuit and keys. Lengths of 64 bytes are refused, because such a
transaction is ambiguous with an inner Merkle node.

**Headers.** The circuit checks no retargets, median-time-past or version
rules; ranges stay inside one epoch. The verifier must check natively that
`target` is the decoding of `nBits`.
