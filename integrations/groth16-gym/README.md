# groth16-gym

BN254 Groth16 circuits for two Bitcoin statements. The bench measures what
fits in a laptop's memory. The proofs are arkworks 0.5 (`ark-groth16`)
proofs, the format BitVM's chunked Groth16 verifier consumes.

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
