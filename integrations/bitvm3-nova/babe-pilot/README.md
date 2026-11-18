# `babe-pilot`: transparent Nova soldering research

This CPU pilot studies input-label soldering with `nova-snark = 0.76.0`, the Pallas/Vesta cycle, and Spartan with IPA commitments. Its inspiration is Babylon's January 2026 [BABE research paper](https://docs.babylonlabs.io/papers/BABE_Research_Paper_Jan_2026.pdf). BABE is used as the paper's name; this repository assigns it no expanded acronym.

The implemented experiment opens four of seven committed garblings, retains three, and proves that one base label vector can be translated into the other retained instances. A corrected local dispute predicate authenticates the operator's complete committed arithmetic tuple before it can produce a refutation. The larger Pallas addition gadget is a separate local experiment.

Current measurements use protocol `RBZK-BABE-NOVA-PILOT-AUTHENTICATED-V2`, results schema `2`, and a source manifest recorded in `RESULTS.json`.

## Documents

- [SPECIFICATION.md](SPECIFICATION.md) defines the implemented relations, role boundaries, and remaining protocol work.
- [REPORT.md](REPORT.md) records measurement scope and separates the original experiment from the hardened relation.
- [PREREGISTRATION.md](PREREGISTRATION.md) preserves the original hypotheses and includes a subsequent audit addendum.
- [RESULTS.json](RESULTS.json) contains the benchmark output for the source version and evidence scope identified in that file.

## Modules and evidence

| Module | Implemented responsibility |
| --- | --- |
| `src/dispute_circuit.rs` | A 16-slot arithmetic dispute predicate over Mersenne-31, plus a separate 255-bit Pallas addition predicate. Each hashes the full operator-owned opening and returns `authenticated && !valid`. |
| `src/soldering.rs` | A Nova `CompressedSNARK` certificate linking base SHA-256 label hashlocks to the retained instances' blinded Poseidon label commitments. |
| `src/protocol.rs` | Prechallenge commitment checking against a caller-supplied pin, deterministic seed openings, certificate verification, and evaluation through a verified public-setup capability. The garbler's nonce and label-release guards live in memory. |
| `src/bitcoin_script.rs` | Taproot leaf and transaction constructors. The assertion leaf selects the label hash for each independently agreed challenge bit at construction. Transaction size and witness-shape measurements concern serialized fixtures. |
| `tests/pilot_adversarial.rs` | Integration and mutation checks covering the implemented setup, certificate, release, and evaluation boundaries. |
| `src/bin/babe-pilot-bench.rs` | CPU measurements with relation and artifact scope recorded in `RESULTS.json`. |

The seven-instance configuration is a test parameter: the idealized probability that all three retained instances are corrupt while all opened instances pass is `1 / 35` for a fixed malicious set of size three. A production parameter choice needs a complete security analysis and an authenticated commitment-before-randomness protocol.

Bitcoin consensus execution, a funded transaction graph, dynamic challenge selection, and application settlement remain separate integration work. The local circuit establishes one committed step's status. A complete Nova verifier or application trace also requires endpoint binding, authenticated adjacency, coverage of its checks, and data availability for challenges.

## Reproduce on CPU

```bash
cargo +1.90.0 fmt --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml -- --check
cargo +1.90.0 clippy --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --all-targets -- -D warnings
cargo +1.90.0 test --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml -- --test-threads=1 --nocapture
cargo +1.90.0 run --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --bin babe-pilot-bench
```

The benchmark performs real CPU proving. Its output records measured time; the preregistration's original runtime targets remain historical predictions.
