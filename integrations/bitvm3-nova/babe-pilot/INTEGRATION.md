# Complete trace composition and funded dispute integration

## Implemented paths

| Path | Implementation and exercised boundary |
| --- | --- |
| Complete Boolean verifier | `TraceProgram` captures the actual `CircuitContext` program. Every input and gate has a scheduled check, and every required output must be true. `trace_protocol` sends a complete small NOT verifier through the universal local checker and a real Nova/Spartan soldering certificate. |
| Existing M14 verifier | The optional adapter calls `m14_e2e::full::final_verifier` with pinned proof shape, verification key and full expected statement. Its regression enters that function using the repository's real C4 fixture and checks refusal at a 100-gate cap. The full large trace has not been generated in this experiment. |
| Recovery | `DurableGarblerSession` rebuilds its deterministic garbler from a private saved seed, verifies the exact saved public artifact and restores its nonce and release guards. An independent head arbitrates durable updates. |
| Dynamic funded choice | The indexed profile authenticates all sixteen operator-owned openings before funding. The operator pre-signs each challenge connector; the challenger pre-signs its exact response. A later selection spends the common assertion output into the selected label script. |
| Bitcoin execution | The Core harness funds and mines the assertion timeout, withholding, honest payout and authenticated refutation paths. The inputs come from real Nova sessions recovered in new processes after challenge confirmation. |

The standalone size samples in `RESULTS.json` retain their original evidence scope. Their dummy outpoints and signatures have not become mined transactions. The funded run records its own transaction identifiers, signatures, policy decisions and mined spends.

## Coverage and adjacency

The compiler records an immutable program with canonical single-assignment wire indices. It starts with the two Boolean constants and the complete canonical proof input. Each gate record contains its truth table and the indices of both operands and its result. This includes XOR and the other free gate families. Required terminal outputs add accepting checks to the schedule.

If the program has `I` initial wires, `G` gates and `O` required outputs, it has `W = I + G` committed wire values and exactly `C = W + O` scheduled checks. A source pin records the verifier version. The parameter pin covers the reference shape and key, while the statement pin covers the entire expected public statement. The compiled instruction root binds the precise Boolean computation, including transitive gadget behavior.

Every producer and consumer opens the same indexed value commitment. A partition boundary carries a reference to that shared wire. An operator cannot assign a separate boundary value to a consumer while keeping both openings valid against one root.

For any committed trace, the first wire that differs from the independently defined computation must fail its input check or its gate check. If every wire agrees but a required verifier output is false, the terminal check fails. This establishes coverage of rejection when the program pin and complete trace publication are available. A challenger opening must authenticate the instruction and all used operand values before the Boolean circuit can produce a refutation.

The local relation is:

\[
\mathrm{refute}=\mathrm{authenticated\ instruction\ and\ values}
\land\neg\mathrm{scheduled\ relation}.
\]

The `AvailableTrace` capability requires the complete proof bytes and canonical packed input and wire vectors. It rejects missing bytes, changed roots and nonzero unused packing bits. This establishes availability to the checking process. Maintaining public access for the entire challenge window remains an operational duty.

`TraceProgram::compile` returns an error when an input, gate, pending wire or output limit is exceeded. It publishes no partial program pin. The M14 adapter preserves this behavior and does not turn a native verifier's answer into a proof of the full Boolean computation.

## Durable state and crash behavior

The journal contains four fixed-size records: initial session pins, the first nonce, the exact finalized setup digest and the first release reservation. SHA-256 chains the records. A journal file is bounded to 964 bytes, owned by the effective user and mode 0600. Its parent must be mode 0700. Directory-relative operations reject symlinks, unsafe file types and extra hard links. An exclusive OS lock covers the live handle, and each append is fsynced before returning.

An authority outside the session's rollback domain holds the accepted head. Every transition must win a durable compare-and-set before this wrapper returns openings, a proof or labels. `HeadAnchor` permits a remote authority implementation. The reference `LocalHeadAnchor` uses another locked journal whose final valid head is trusted. Independently protecting that directory is part of the deployment contract. Rolling back both stores defeats this protection.

Recovery accepts the exact trusted head or one complete successor. In the latter case it validates the seed against Commit1, checks any required artifact bytes and advances the authoritative head before resuming. Older histories, forks, two unanchored successors and torn records fail closed. A torn record requires intervention from the authority; automatic truncation would erase an uncertain reservation.

The finalized proof artifact is immutable and created by an atomic no-replace publication. Recovery reloads those exact bytes. A crash between publication and the finalization record can reuse the saved artifact. Compression is randomized, so substituting a newly generated proof for an already finalized artifact would violate its digest pin.

The release reservation commits both the input digest and the authorization digest. Authorization covers the catalogue, complete graph policy, funding outpoint and selected challenge transaction. An exact retry can return the same labels after restart. Changing the input or redirecting the release to another graph is rejected. A failed authority update poisons the live handle until it is reopened and reconciled.

Tests cover a real process exit and cross-process locking, every byte truncation and single-byte corruption of the bounded journal, invalid rehashed transitions, concurrent immutable file publication, stale heads, symlink substitution and malformed authority updates. Recovery tests share a real Nova certificate and interrupt execution on both sides of the finalization and release CAS operations.

## Funding and challenge order

Before funding, the parties independently verify the public setup and all sixteen committed indexed openings. The catalogue digest binds the session, circuit, Commit1, nonce and the full ordered inputs. It retains arithmetic faults so a faulty committed row remains challengeable.

The graph configuration also binds role keys, payout scripts, each fee and every CSV delay. Both parties must verify the complete presigned catalogue. The operator supplies a `SIGHASH_ALL` signature for each challenge transaction. The challenger signs each exact response transaction. The immutable pre-funding graph reservation lives beside the trusted authority head and includes the funding outpoint.

After the assertion output confirms, the challenger chooses one connector. Its output contains the hashlocks for that row's selected bits. The response leaf requires both signatures and every selected label. The challenger's signature binds the response to the committed disprove/payout output. Keeping the operator key therefore does not permit signing a different response destination.

The release process rebuilds the expected graph from its trusted reservation and verifies the entire catalogue against the real setup certificate. A configured Bitcoin Core adapter independently reads the exact selected transaction, its active confirming block and its unspent response output. The adapter checks a stable chain tip across those reads. Caller-supplied confirmation fields alone grant no release.

The response output offers an authenticated retained-instance refutation branch to the challenger and a delayed operator payout. If the operator withholds labels, the selected challenge output has a challenger CSV branch. If no challenge is selected, the original assertion output has its operator timeout.

The Core harness checks each CSV spend one block before maturity and at its first valid height. It also submits incorrect labels, a fresh operator signature over a redirected response, invalid refutation preimages, competing challenge transactions and repeated spends. The receipt distinguishes host signature checks, Core policy decisions and actual mined transactions.

## Resource and trust limits

The complete-trace response in the small NOT test contains 3,092 input bits, including Merkle paths. The funded catalogue currently uses the separate 128-bit indexed relation. The graph constructor supports at most sixteen choices and 480 label wires in one response input. A complete M14 deployment needs a selector that reaches every scheduled check and a transaction construction for larger authenticated openings. The 3,832-wire serialization sample does not supply that construction.

The M14 adapter currently stores the program and Merkle trees in memory. Raising a gate limit preserves the relation but also raises its resource demand. Full-scale M14 compilation and publication require a storage strategy and a measured budget beyond this run. The optional CI test confirms entry into the complete existing verifier and refusal of an undersized budget. It provides no full-scale trace timing or artifact-size result.

The executable cut-and-choose parameters remain `N=7, M=3`. The conditional probability for retaining an exactly three-instance malicious set while opening only honest instances is `1/35` under the assumptions in `SPECIFICATION.md`. This test configuration provides no production security claim.

Core runs with valueless regtest coins and disabled external networking. The harness simulates both signing roles in one process, and the reference release adapter supports regtest. Reorganization recovery and independently deployed adversarial role processes are outside the executed evidence. A reorganization cannot authorize a conflicting label vector through the durable release guard, but the guard alone does not guarantee bond recovery on the replacement chain.

An application still needs to bind its accepted transition to the precise DLC outcome or CET and the successor UTXO rights. These changes supply authenticated computation and dispute plumbing for that work. They establish no transferability rule for a DLC by themselves and make no prediction about a 58-hour application proving job.

## Reproduction

The default release suite includes the generic complete-trace certificate, durable recovery and indexed protocol tests:

```bash
cargo +1.90.0 test --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml -- --test-threads=1 --nocapture
cargo +1.90.0 test --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --features m14-trace --test trace_m14_adapter -- --nocapture
```

The BABE workflow documents the exact funded sequence. Before proving, it builds Bitcoin Core 31.1 from the official release commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, which is the commit identified by the signed `v31.1` tag. The source checkout, build profile and executable paths are checked; receipts record the source tree, compiler version, exact build arguments, CMake cache hash and both executable hashes. This path trusts the CI build environment. Its hashes identify that build and provide no independent proof that a compiler used the recorded source.

The runner also accepts `--core-archive` for the official Linux release. That path requires the pinned archive SHA-256 and checks both executables against its members. The original local funded run used this archive path. CI uses the pinned source build because the official binary download host repeatedly refused its connections. Receipt provenance identifies the mode used.

After preparing Core, the workflow initializes fresh sessions with `babe-session-fixtures init` and invokes `scripts/run-regtest.py`. The runner binds the graph before broadcasting funding and calls the release adapter only after selecting and confirming a challenge. Public receipts and transaction hex are uploaded; master seeds, private role keys and node cookies stay in temporary private directories.
