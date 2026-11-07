# nb3-prover: resumable SP1 proving on one machine

`nb3-prove` produces SP1 6.9 compressed proofs for programs too long to prove in one sitting on
a single machine, without SP1's prover network. A BitVM deployment cannot depend on a hosted
prover: the operator has to be able to produce the proof it posts. This tool is how this repo
proves guest A (the complete Nova verifier, 72.3 × 10^9 instructions) on a laptop.

It is SP1's own prover (controller, executor, shard provers, recursion), assembled differently:

- **Artifacts on disk.** SP1's local node keeps every artifact (execution chunks, shard records,
  shard proofs, recursion proofs) in a `HashMap` in RAM, so a long run's memory grows with its
  length. [`DiskArtifactClient`](src/store.rs) keeps each artifact in a file. Resident memory is
  then what the provers hold for the shard in flight.
- **Memoized tasks.** Every finished shard task and recursion task is recorded under a key derived
  from what it proves ([`memo.rs`](src/memo.rs)). Rerunning the same command after a crash, a
  reboot or a kill replays the finished tasks and proves only the rest.
- **One task at a time.** SP1's worker pools default to several shards in flight. The tool sets
  each pool to one (unless the environment already sets it, or `--sp1-worker-defaults` is given),
  and `--permits` bounds concurrent provers (default 1).
- **Shard size is a parameter.** `--element-threshold` and `--height-threshold` set SP1's shard
  size, and with it the peak memory per shard.

The output is SP1's `SP1ProofWithPublicValues`, verified before it is written. M13's
`m13 shrink-wrap` takes it unchanged.

The node takes its provers from a [`Backend`](src/backend.rs). `nb3-prove` uses SP1's CPU
provers; [`nb3-prove-gpu`](../prover-gpu/README.md) runs the same node, command line and run
directories on SP1's CUDA provers, sized for GPUs below SP1's 24 GB floor. A run directory can be
resumed with either.

## Usage

```
nb3-prove prove --elf ELF --input FILE [--input FILE ...] --run-dir DIR --out PROOF.bin \
    [--element-threshold N] [--height-threshold N] [--shard-size N] \
    [--trace-chunk-threshold N] [--trace-chunk-slots N] [--permits N] \
    [--expect-public-sha256 HEX] [--sp1-worker-defaults]
nb3-prove status --run-dir DIR
```

- Each `--input` is written to the guest's stdin with `SP1Stdin::write_vec`, in order.
- `--expect-public-sha256` executes the guest first and refuses to prove unless it exits with code 0
  and commits public values with that SHA-256.
- `DIR/run.json` pins the run: ELF and input digests, every sharding option, and the proof nonce.
  A later run in the same directory must present the same ELF, inputs and options, or it is
  refused.
- `DIR/memo/` holds the finished tasks, `DIR/progress.jsonl` one line per task (proved or
  replayed, with its proving time), `DIR/result.json` the summary once the proof is verified.
- `status` summarizes a run directory, finished or not.

## How resuming works

SP1's controller names artifacts with fresh random ids, so nothing about a task's ids carries over
between processes. Tasks are keyed by content instead:

| Task | Key |
| --- | --- |
| `ProveShard` (core, memory or precompile shard, including its lift into a recursion proof) | run digest, the shard's trace record; for a precompile shard, the contents of the event chunks it points at |
| `RecursionReduce` (folding proofs in the compress tree) | run digest, the completion flag and shard ranges, the contents of the proofs folded |

The run digest is the SHA-256 of `run.json`. A rerun executes the program again and produces the
same shard records, so every shard task is found in the memo. Replaying a core shard re-uploads
the deferred precompile events it produced under their recorded ids and completes its
deferred-marker task, as the live prover does.

The compress tree pairs proofs in the order they arrive. A recursion task is found in the memo
when the rerun folds the same proofs. Otherwise it is proved again. A memo entry is replayed only
into a task whose key, and so whose inputs, are identical. SP1's proof bytes are not reproducible
across runs, so a recursion task folding a shard proved again (not replayed) is proved again too.
Everything replayed stays replayed.

## Measured (control-C guest, 4 testnet4 headers, 512,784 instructions)

Run in WSL on this laptop (Ryzen AI 9 365), one prover permit, SP1's default shard size, sharing
the CPU with guest builds:

| Run | Shard tasks | Recursion tasks | Proving | Result |
| --- | --- | --- | --- | --- |
| first | 1 proved, 1 not recorded (see below) | 1 proved | 1,366 s, peak RSS 12.0 GiB | verified; statement `cd9beb30…`, program key `4686663f…` (M13's pins) |
| rerun, same directory | 1 replayed, 1 proved | 1 proved | 619 s | verified; same statement and key |

The first run lost one core shard's deferred chunks to the trash sweep, which then judged age by
write time. The sweep now uses the deletion time and keeps everything deleted after the oldest
in-flight shard started; `tests/units.rs` reproduces the case.

Deleted artifacts move to `DIR/artifacts/trash` and are removed after ten minutes. A shard's
deferred chunks can be consumed by the controller before the shard reports completion, and the
memo reads them from the trash.

## Build

```
cd nova-bitvm3/prover
cargo build --release
cargo test --release --test units
```

SP1 6.9.0 from crates.io; the Rust toolchain SP1 6.9 requires. Proving runs on the CPU.
