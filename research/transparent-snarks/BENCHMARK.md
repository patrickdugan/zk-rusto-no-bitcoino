# Benchmark contract

Status: preparation only. No proving job or deployment is authorized by
running the Python checker. Preserve existing recursive-sharding and SPV
jobs, then use their verified outcomes to decide when to launch this track.

## Statement held constant

For the selected network and circuit version, prove a sequence of header
transitions from a verifier-approved start state to an explicitly expected
end state. With N headers and width k, N must equal k times the fold count.
Padding needs an explicit constrained no-op rule if it is introduced later.

The current source's state carries height, previous hash, cumulative work,
epoch difficulty/timestamp context, and recent timestamps. The network is
selected through a distinct circuit and key. Reuse its reviewed rules and
Bitcoin Core differential fixtures; keep testnet4's BIP94 behavior separate
from mainnet. Public-input and circuit-identity binding must survive export.

Check PoW and linkage, contextual difficulty, median-time-past, and work
accumulation. The exact acceptance range of the existing circuit must be
recorded alongside results, including any unsupported target encodings.
Future-time policy requires an external time source. A valid header segment
does not establish full block execution or choose the canonical chain.

A fresh verifier must check the expected initial state, network, circuit/key
identity, step count, and expected final state. A native receipt or hash
manifest supplies metadata; cryptographic verification remains mandatory.
An external checkpoint's digest identifies its bytes. Authentication of
those bytes requires a separate policy and cannot be inferred from the hash.

## Matrix and units

The default plan is testnet4 from genesis, widths 1/4/8/16, and lengths
64/128/1024 headers. Run each case independently using identical fixture
bytes. The early-genesis matrix is a resource pilot. Add separate fixtures
crossing a difficulty boundary and exercising min-difficulty exceptions.
The pilot alone cannot validate those branches of consensus logic.

Use `headers`, `fold_steps`, `constraints`, and `trace_rows` as separate
quantities. The previously discussed 64-row result must be matched to its
actual workload before using it as a baseline. Existing Groth16 results
may prove a narrower statement, so retain their original scope and host
provenance. No new ceremony-dependent benchmark is required by this plan.

## Measure each expensive phase

Record wall time and memory for public-parameter construction, witness
preparation, folding, durable save/reload, compression, and verification.
A fresh process gives a phase-specific high-water mark; a monotonically
increasing process high-water mark cannot be attributed to a later phase.
For the full pipeline, retain the maximum actually observed, including the
cold verifier and generator construction.

Report these artifact sizes separately:

- compressed proof payload and complete public proof bundle;
- continuation accumulator, including witness data;
- verifier parameters and any persistent cache;
- peak temporary disk and final retained disk.

The proof's small payload alone cannot describe the checkpoint's storage
or verification memory. Record both cold and warm verification.

## Enforce the RAM target outside Python

Target `memory.max = 13958643712` bytes and `memory.swap.max = 0` in a
verified cgroup v2 scope. Include child processes in that scope. Save the
actual limit files and `memory.peak` plus `memory.events`; abort the run
when the requested limits cannot be applied. Record process RSS separately
from cgroup accounting, which can include charged file cache.

On WSL2, record the VM limit and Windows host pressure as well. On native
Windows, require an equivalent enforced process-tree limit and working-set
measurement before using the result for the bounded-memory claim. Missing
`/proc` data must be reported as unavailable, never as zero-byte usage.
The 13 GiB target is a plan for a 15-16 GiB host; reserve host resources and
confirm available memory before launching a case.

Pre-build binaries outside measured cases. Save the exact source revision,
Cargo.lock hash, vendor-patch hashes, enabled features, Rust version,
binary hashes, CPU, OS, thread count, and fixture digest. Include the
verifier/key digest, public statement, and plan digest in the result record.
An SDK name or `trusted_setup=false` flag cannot replace dependency review.

## Acceptance gates

1. Reproduce a real proof and verify it in a fresh process using verifier-approved public inputs. Validate the final state against Bitcoin Core reference data.
2. Reject changed network, checkpoint, end-state, step count, proof bytes, and a deliberately invalid header. Test parser bounds and truncated bundles.
3. Interrupt ingest, fold, checkpoint payload, manifest, and publication. Resume from a verified durable generation and compare the resulting public state to an uninterrupted run. Randomized compressed proof bytes need not match.
4. Include compression and cold verification within the enforced RAM experiment. Record OOM kills and incomplete runs as failures. Fit a proposed RAM scaling law only after repeated measurements across width and length.
5. Trace every commitment and compression layer back to the pinned implementation. A new KZG, Groth16, or other ceremony-dependent stage fails this track's policy, even when it is only the final wrapper.
6. Keep deployability separate from the measurements. Testnet4 results stay labeled testnet4; Script/BitVM integration requires another verifier design and review.

## Comparing a second transparent backend

Admit Halo2/IPA or a recursive FRI stack only after selecting concrete
source revisions and writing a new policy profile with tests. Require the
same public statement and security target, then account for setup-free
parameter generation, recursion, final compression, and verifier costs.
Any change in constraint coverage gets a separate result row. A HyperNova
experiment additionally needs a demonstrated advantage for this workload
and a specified transparent compression path.
