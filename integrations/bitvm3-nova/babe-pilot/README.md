# `babe-pilot`: BABE-Inspired Transparent Nova/Spartan Soldering Pilot

Experimental CPU-scale adaptation of Babylon's January 2026 **BABE** (*Bitcoin-Authenticated Bytecode Execution*) garbled-verification architecture to a **100% transparent Nova + Spartan/IPA stack** (`nova-snark = 0.76.0` over the Pallas/Vesta cycle, zero trusted setup).

## Documents in This Crate

- [`PREREGISTRATION.md`](PREREGISTRATION.md): Preregistered experimental protocol (`RBZK-BABE-NOVA-PILOT-2026-11`), hypotheses `H1`–`H4`, fixed CPU CI parameters, and adversarial acceptance matrix (committed prior to Phase 4 benchmarking).
- [`SPECIFICATION.md`](SPECIFICATION.md): Formal relations ($\mathcal{R}_{\text{C\&C}}$, $\mathcal{R}_{\text{solder}}$, $\mathcal{R}_{\text{ped-chunk}}$), Unsoldering Algebra Soundness Lemma, `CompressedSNARK` vs `DirectSNARK` zero-knowledge requirement, malicious-garbler defense analysis (including the Hybrid Base-SHA256 + Soldered-Poseidon fix closing the $1/N$ base-equivocation gap), and Bitcoin Taproot spending enforcement.
- [`REPORT.md`](REPORT.md): Phase 4 empirical architecture comparison against committed `M14` (`785,442,492` gates, `12.57 GB`/circuit), `FC03` (`7,285,647`-gate 1-bit `BindingStep`), and optional Groth16 (`BABE` paper).
- [`RESULTS.json`](RESULTS.json): Machine-readable benchmark output produced by `babe-pilot-bench`.

## Crate Layout

- [`src/soldering.rs`](src/soldering.rs): Zero-knowledge Nova IVC + Spartan/IPA (`CompressedSNARK`) soldering relation $\mathcal{R}_{\text{solder}}$, verifying in-circuit `SHA-256` hashlocks on base retained instance $b = \min(\mathcal{R})$ and blinded Poseidon wire commitments on all $M - 1$ soldered retained instances $j \in \mathcal{R} \setminus \{b\}$.
- [`src/protocol.rs`](src/protocol.rs): Two-phase `(N = 7, M = 3)` Cut-and-Choose setup (`Commit_1` $\rightarrow$ challenger `nonce` $\rightarrow$ `N - M` deterministic 256-bit ChaCha20 seed openings + `SolderingCertificate`), single-use active base label delivery, isolated stateless evaluator unsoldering, and 1-of-`M` fault-tolerant dispute resolution with withholding recovery.
- [`src/dispute_circuit.rs`](src/dispute_circuit.rs):
  - `eval_indexed_dispute_circuit` (`W = 128` wires, `39,378` non-free gates): 16-slot SHA-256 authenticated trace-chunk check with witness-assisted Mersenne-31 modular arithmetic.
  - `eval_pasta_window_ec_step` (`W = 3,832` wires): Full 255-bit Pallas/Vesta `w = 4`-bit windowed witness-assisted complete affine point-addition + SHA-256 chunk authentication (`4x` shorter Pedersen binding trace than 1-bit `FC03`).
- [`src/bitcoin_script.rs`](src/bitcoin_script.rs): Real `bitcoin` v0.32 Taproot `CheckLampSigsMatch` (`AssertLabelsTx`), `WithholdingTimeoutTx`, balanced `(M + 1)`-leaf `DisproveTx` (`1-of-M` refute preimage locks), and `OperatorPayoutTx` builders and `vsize`/`WU` standardness analyzers.
- [`tests/pilot_adversarial.rs`](tests/pilot_adversarial.rs): End-to-end honest/dishonest evaluation, commitment/delta mutation rejection, `session_id`/`circuit_id`/`nonce` replay rejection, `M - 1` corrupted retained-instance malicious-garbler slashing, and withholding/malformed-artifact tests.
- [`src/bin/babe-pilot-bench.rs`](src/bin/babe-pilot-bench.rs): Deterministic CPU release benchmark runner generating `RESULTS.json`.

## Reproduce on CPU (No GPU Required)

```bash
# Lint & format checks
cargo +1.90.0 fmt --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml -- --check
cargo +1.90.0 clippy --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --all-targets -- -D warnings

# Run all unit, integration, and adversarial tests
cargo +1.90.0 test --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml -- --test-threads=1 --nocapture

# Regenerate RESULTS.json
cargo +1.90.0 run --release --locked --manifest-path integrations/bitvm3-nova/babe-pilot/Cargo.toml --bin babe-pilot-bench
```
