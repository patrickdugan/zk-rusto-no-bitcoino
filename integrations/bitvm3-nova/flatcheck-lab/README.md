# FlatCheck / FlatMerkle laboratory (BitVM3)

Experimental sidecar for [Sergio Demian Lerner, *FlatMerkle: Logarithmic-Space Inclusion Proofs over a Single Linear Hash Stream* (2026)](https://github.com/SergioDemianLerner/FlatMerkle). It lives in **zk-rusto-no-bitcoino**, beside the BitVM3 Nova integration.

| Part | What it is |
| --- | --- |
| [`flatmerkle.py`](flatmerkle.py), [`test_flatmerkle.py`](test_flatmerkle.py) | The PR #23 reference: Lerner's linear SHA-256 stream and one-index openings. |
| [`fc03/`](fc03/) | **FC03**: authenticated refutations of a Nova relaxed-R1CS instance (Rust). |
| [`fc03_ref.py`](fc03_ref.py), [`test_fc03_differential.py`](test_fc03_differential.py) | Independent Python adjudicator replaying the frozen FC03 vectors. |
| [`fixtures/fc03_vectors.json`](fixtures/fc03_vectors.json) | 172 adversarial cases (claims, challenges, responses, expected verdicts), deterministic from fixed seeds. |
| [`results/`](results/) | Measured outputs: benchmark, circuits, real-shape statistics, regtest dispute. |
| [`FC03_REPORT.md`](FC03_REPORT.md), [`FC03_RESULTS.json`](FC03_RESULTS.json) | Technical report and machine-readable results with outstanding security gates. |

## FC03 in one paragraph

An operator claims a Nova running instance U = (comm_W, comm_E, u, X) is satisfied, and commits FlatMerkle roots to its witness W, error vector E and two Pedersen binding traces. A challenger names one local check: a relaxed-R1CS row `(Az)_i (Bz)_i = u (Cz)_i + E_i`, one double-and-add step of the Pedersen MSM that binds the roots to comm_W / comm_E, a trace endpoint, or the public fold U = fold(U1, U2, comm_T). The operator answers with FlatMerkle openings; a fixed garbled circuit decides the row or step; the refute label of that circuit unlocks a hash-locked Bitcoin leaf. Row checks alone are not sound: for any W', the error E' = A z' ∘ B z' − u C z' satisfies every row, and the test suite shows exactly that pair opening correctly under fresh FlatMerkle roots. Only the binding trace (ending at Nova's comm_W) exposes it.

## Run

```sh
cd integrations/bitvm3-nova/flatcheck-lab
python3 -m unittest discover -p 'test_*.py' -v                       # FlatMerkle + FC03 Python differential
cargo +1.90.0 test --release --manifest-path fc03/Cargo.toml -- --test-threads=2 --nocapture
cargo +1.90.0 run --release --manifest-path fc03/Cargo.toml --bin fc03 -- bench results/fc03_bench.json
cargo +1.90.0 run --release --manifest-path fc03/Cargo.toml --bin fc03 -- circuits results/fc03_circuits.json results/fc03_realshape.json
cargo +1.90.0 run --release --manifest-path fc03/Cargo.toml --bin fc03 -- regtest BITCOIND BITCOIN-CLI DATADIR results/fc03_regtest.json
cargo +1.90.0 run --release --manifest-path fc03/realshape/Cargo.toml   # real HeaderStep shape statistics (rebuilds the 42 MB vk)
```

On Windows use `RUSTUP_TOOLCHAIN=1.90.0-x86_64-pc-windows-msvc` and a `CARGO_TARGET_DIR` outside OneDrive. `FC03_WRITE_VECTORS=1` regenerates the vector file; the test fails if the committed file differs from the suite. No test runs Nova or SP1 proving: the fixture folds a four-row relation with Nova 0.76's own NIFS in milliseconds. The regtest harness refuses any node whose `getblockchaininfo.chain` is not `regtest`.

CI: [`.github/workflows/flatmerkle-bitvm3-reference.yml`](../../../.github/workflows/flatmerkle-bitvm3-reference.yml) runs the Python tests, the Rust native and circuit tests, and the regtest dispute against the SHA-256-pinned Bitcoin Core 31.1 tarball.

## Scope and provenance

This is a reference experiment with no production cryptographic review. The FC02 bundle, patch and audit named in the FC03 brief were not present on the machine that built FC03 (searched: Downloads, OneDrive, `D:`, WSL), so FC02's reported counts (32 Python tests, 80 oracle comparisons, 2,240 local-check comparisons) are neither reproduced nor relied on; FC03 starts from PR #23's head `5e9095d`. An earlier chat described a larger S2 FlatCheck lab in `garbled-snark-verifier`; none of its numbers are used here.
