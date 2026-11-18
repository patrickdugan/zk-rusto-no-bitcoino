# `babe-pilot`: transparent Nova soldering research

This CPU pilot studies input-label soldering with `nova-snark = 0.76.0`, the Pallas/Vesta cycle, and Spartan with IPA commitments. Its inspiration is Babylon's January 2026 [BABE research paper](https://docs.babylonlabs.io/papers/BABE_Research_Paper_Jan_2026.pdf). BABE is used as the paper's name; this repository assigns it no expanded acronym.

The experiment opens four of seven committed garblings, retains three, and proves that one base label vector can be translated into the other retained instances. It now includes a compiler that covers a complete Boolean verifier, durable session recovery, an authenticated catalogue of sixteen challenges, and a funded Bitcoin Core regtest. [INTEGRATION.md](INTEGRATION.md) records the boundaries between those components.

Current measurements use protocol `RBZK-BABE-NOVA-PILOT-AUTHENTICATED-V2`, results schema `2`, and a source manifest recorded in `RESULTS.json`.

## Documents

- [SPECIFICATION.md](SPECIFICATION.md) defines the implemented relations, role boundaries, and remaining protocol work.
- [REPORT.md](REPORT.md) records measurement scope and separates the original experiment from the hardened relation.
- [PREREGISTRATION.md](PREREGISTRATION.md) preserves the original hypotheses and includes a subsequent audit addendum.
- [RESULTS.json](RESULTS.json) contains the benchmark output for the source version and evidence scope identified in that file.
- [INTEGRATION.md](INTEGRATION.md) describes complete trace checks, recovery, pre-funding graph reservations and the Core exercise.

## Modules and evidence

| Module | Implemented responsibility |
| --- | --- |
| `src/dispute_circuit.rs` | A 16-slot arithmetic dispute predicate over Mersenne-31, plus a separate 255-bit Pallas addition predicate. Each hashes the full operator-owned opening and returns `authenticated && !valid`. |
| `src/soldering.rs` | A Nova `CompressedSNARK` certificate linking base SHA-256 label hashlocks to the retained instances' blinded Poseidon label commitments. |
| `src/protocol.rs`, `src/program.rs` | A generic authenticated dispute program, pinned prechallenge verification, deterministic seed openings and evaluation through a verified setup capability. |
| `src/trace.rs` | Capture every input, gate and terminal check of an independently compiled Boolean verifier, authenticate shared wire values, and produce a local refutation. Optional `m14-trace` calls the existing complete M14 verifier. |
| `src/journal.rs`, `src/durable.rs` | Locked and fsynced reservations, exact setup reuse, an independent CAS head, recovery after interrupted updates, and one authorized label release. |
| `src/challenge.rs`, `src/transaction_graph.rs` | Authenticate all sixteen indexed openings, pre-sign both parties' connectors, select a challenge after funding, and authorize release from a confirmed unspent output. |
| `src/bitcoin_script.rs` | Taproot leaf and transaction constructors. The assertion leaf selects the label hash for each independently agreed challenge bit at construction. Transaction size and witness-shape measurements concern serialized fixtures. |
| `tests/pilot_adversarial.rs` | Integration and mutation checks covering the implemented setup, certificate, release, and evaluation boundaries. |
| `src/bin/babe-pilot-bench.rs` | CPU measurements with relation and artifact scope recorded in `RESULTS.json`. |
| `scripts/run-regtest.py` | Fund and mine assertion timeout, withheld response, honest payout and authenticated refutation paths on isolated Bitcoin Core, using real Nova session labels. |

The seven-instance configuration is a test parameter: the idealized probability that all three retained instances are corrupt while all opened instances pass is `1 / 35` for a fixed malicious set of size three. A production parameter choice needs a complete security analysis and an authenticated commitment-before-randomness protocol.

The funded exercise uses the sixteen-slot, 128-bit indexed relation. The complete-trace certificate test uses a small Boolean NOT verifier with a 3,092-bit authenticated response. M14's adapter compiles the existing complete verifier and rejects an explicit resource cap without returning a partial claim. A full M14 trace run and a scalable funded selector for all its checks remain open. Application settlement and the DLC-to-successor-UTXO rule require their own integration.

## Reproduce on CPU

```bash
cargo +1.90.0 fmt --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml -- --check
cargo +1.90.0 clippy --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --all-targets -- -D warnings
cargo +1.90.0 test --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml -- --test-threads=1 --nocapture
cargo +1.90.0 run --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --bin babe-pilot-bench
cargo +1.90.0 test --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --features m14-trace --test trace_m14_adapter
```

The default suite includes real CPU proving for the complete-trace certificate and recovery tests. The BABE CI workflow also creates fresh private sessions, verifies the pinned Bitcoin Core archive and mines the funded graph. Private session files stay outside uploaded artifacts. The preregistration's original runtime targets remain historical predictions.
