# Production-source conformance boundary

This milestone adds the actual Nova 0.76.0 non-EVM transcript algorithm,
strict NHC1/NHT4 container binding, bounded Spartan sumcheck checks, and one
Boolean Keccak permutation round for the transparent Nova SNARK route. The
intended final compression remains Spartan/IPA over Pallas/Vesta, with no
Groth16/KZG wrapper or trusted setup. These components do not yet compose a
complete Bitcoin verifier.

The existing arithmetic compilers remain the baseline. Existing header
provers, their RAM-targeted `k` settings, BitVM3, and separate testnet4 work are
outside this change. All fixture generation and local tests described here
avoid proving, GPU work, local Rust compilation and parameter reconstruction.

## Authoritative implementation

The header backend depends on the **published `nova-snark = "=0.76.0"` crate**.
Its archive SHA-256 is
`c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31`,
and its recorded VCS commit is
`98576efa884072bfe69bfad8f275a3a5cd8754e5`.
The earlier Nova Git revision used for IPA algebra inspection is historical
reference evidence; it does not identify this header dependency.

Primary source references at that release's VCS commit:

- [Keccak transcript](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/provider/keccak.rs),
  [group representations](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/provider/traits.rs),
  and [Pedersen commitments](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/provider/pedersen.rs).
- [Sumcheck verification](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/sumcheck.rs),
  [compressed univariates](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/polys/univariate.rs),
  [multilinear/sparse polynomials](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/polys/multilinear.rs),
  and [Spartan verification](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/spartan/snark.rs).
- [Pinned header backend](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/de607d3db17d400dd6c2923d357f1d4a7bf233c7/integrations/nova-header-chain).
  Its revision, circuit/key identity and Nova version are explicit policy fields.

`nova-oracle/Cargo.toml` uses the exact released Nova crate and pinned header
revision. Hosted evidence must retain the resolved Cargo lockfile and dependency
tree as well as the source revision. A historical fixture receipt or source pin
alone does not establish successful current-head execution.

## Implemented components

`production_transcript.py` implements the release's Keccak transcript using
`Cryptodome.Hash.keccak`, pinned by `transcript-requirements.txt`. Keccak-256
and SHA3-256 use different padding. The implementation preserves upstream
labels, byte concatenation, round counter, 64-byte state, buffered absorption,
domain separation, scalar reduction and bit extraction. Pallas uses scalar
field Q and Vesta scalar field P. Scalar vectors have no added length prefix;
raw affine points and Pedersen commitments have distinct representations.
Canonical scalars, finite on-curve affine points, snapshot shape, buffer bounds
and counter overflow are checked. Snapshot replay is supported; the engine
must be supplied independently because it is absent from upstream's snapshot.

The `transcript` Rust binary calls the actual released transcript and actual
upstream object representations. It compares challenges, state, buffer and
restore behavior after events. It does not substitute a locally ported Rust
transcript. Generic conformance events do not establish that a caller absorbed
every object required by an entire Nova proof.

`nht4.py` binds exact container/proof lengths and digests to verifier-owned
expectations, alongside network, `k`, step count, 17 canonical initial-state
scalars and their header-specific widths, checkpoint origin, key identity,
header revision, Nova version and expected output-state digest. It rejects
unsupported encodings, duplicate JSON fields and surplus/truncated bytes.
The container itself carries no independent proof-length field or verification
key. Production must authenticate the expected policy outside this parser.
Python framing acceptance explicitly reports **zero Nova proofs verified**.

The retained fixture is the pinned backend's genuine testnet4 genesis-to-2020
proof: `k=5`, 404 steps, 13,220 container bytes and 12,664 compressed-proof bytes.
Its expected policy and provenance accompany it in `fixtures/`. The native
`nht4` binary strictly decodes the inner bincode proof with an EOF requirement
and exact canonical reserialization,
reconstructs the pinned public verifier parameters, checks key identity, calls
the actual `CompressedSNARK::verify`, and binds the returned final state. It
also checks 14 adversarial variants, including canonical sumcheck-coefficient
tampering and two identity-sign-alias regressions. Public parameter reconstruction involves no secret setup or proof
generation, but may consume substantial resources and runs only hosted.
Arbitrary malicious inner-proof shapes have not received exhaustive panic
analysis; the pinned native harness is not an unrestricted network verifier.

`spartan_checks.py` restores the omitted linear coefficient from the running
claim, checks verifier-owned round and degree expectations, absorbs compressed
coefficients under `b'p'`, squeezes under `b'c'`, and evaluates each round. It
preserves encoded degree even when the highest coefficient is zero. Batch
initial claims include upstream's `2**(max_rounds-instance_rounds)` padding.
Supported bounds are at most 32 rounds, 64 batch instances and quadratic/cubic
degree expectations. Empty rows and unsafe batch/sparse dimensions are rejected
before source operations that would otherwise panic.

Separate terminal helpers implement the outer, inner and batched evaluation
equations. A sumcheck fold is not proof verification without a separately bound
initial claim and terminal equation. The functional API leaves its input
transcript unchanged and returns the advanced transcript on success.
The `sumcheck` Rust binary calls actual public upstream `SumcheckProof::verify`
and `verify_batch`, coefficient decompression, equality and sparse evaluation.
It distinguishes admission rejection, actual upstream rejection and terminal
claim mismatch. It never catches a panic as successful rejection.

`bench_spartan.py --native-report ...` additionally extracts coefficients from
the six primary/secondary outer/inner/batch sumchecks exported after genuine
native proof verification. Scalar JSON uses halo2curves 0.9's canonical LE32
hex representation. The resulting corpus is folded with **synthetic initial
claims and transcript states**. This exercises real coefficient encodings and
shapes; it is not that proof's full Fiat-Shamir replay. The report SHA-256 is
recorded in the expanded corpus.

`keccak_trace.py` includes a bounded word-level Keccak-256 reference and a
typed Boolean Script graph for exactly one selected Keccak-f[1600] round.
Lane index is `x+5*y`; bytes and bits within lanes are little endian. Source
constants and intermediate vectors are pinned in `keccak-sources.json` to
XKCP commit `5585d0213203c0c5b2dfdf3b34f5da9275abc3e7`. Small XOR/AND/NOT
predicates use enabled Script operations. Native whole-hash tests compare the
reference with the mature Keccak package; the Script graph remains one round.

## Evidence available for this change

Local targeted execution passed 42 tests in approximately one second: seven
transcript, 12 NHT4, seven Spartan, 14 Keccak and two Boolean-kernel tests.
Coverage includes independent field calculations, mature Keccak comparisons,
official intermediate vectors, malformed canonical encodings, dimensions,
counter overflow, altered coefficients/terminal claims, authenticated openings,
and empty, truncated, prepended and appended witnesses. These local checks do
not establish independent Rust execution.
The complete local Python suite also passed all 112 tests in 115.411 seconds.

Generated corpora and their current expected counts:

| Corpus | Cases | Acceptance/rejection expectation |
| --- | ---: | --- |
| Transcript | 76 | 34 accepted, 42 rejected; 530 generated events |
| NHT4 framing | 23 | One retained fixture, 22 rejected containers/policies |
| Synthetic Spartan | 48 | 26 accepted folds, 16 admission, four upstream and two terminal rejections |
| Expanded Spartan | 60 | Six genuine coefficient corpora and six tamper cases added; requires native report |
| One-round Keccak Script | 230 | 200 expected rejections; 12 selected registry checks generated separately |

The synthetic Spartan corpus contains 188 accepted rounds and 10 terminal
equation comparisons across both Pasta roles. The expanded corpus is generated
only after the retained proof's native verification succeeds. Require a successful
current-head job and its evidence artifacts before claiming native conformance.

Main `f428c32` compiled all three native binaries. Its
[native run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42116860045)
then failed a malformed-point admission case: halo2curves accepts `(0,0)` as its
identity sentinel even when the transport marks a finite point. The oracle now
checks actual group identity and rejects that noncanonical finite encoding.
Both-curve regressions cover raw affine and commitment encodings. This failed
run did not execute NHT4 verification and supplies no proof-verification evidence.

The same commit's
[Keccak run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42116860078)
passed all 230 independent Script vectors (200 rejections), and three WOTS
sessions executed 24 vectors (12 rejections). WOTS leaves reached 4,975 bytes,
35 stack items and 600 witness bytes. This samples four predicate shapes; it
does not measure the full signature-inclusive round catalogue.

Main `7b2e262` then passed the complete
[native workflow](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42118077893):
76 transcript cases (34 accepts, 42 rejections; 496 successful event comparisons),
48 synthetic Spartan cases and the 60-case expanded genuine coefficient corpus.
The latter made 44 actual upstream verifier calls and checked 289 accepted rounds
and ten terminal equations. This still uses synthetic transcript states for
the exported genuine coefficients.

The retained NHT4 proof passed actual `CompressedSNARK::verify`, matched its
verifier-key and output-state pins, and returned height 2020. All 22 rejected
framing cases and 13 native negative checks passed in that run, including actual
Pallas/Vesta identity-sign aliases rejected by canonical roundtrip. Parameter/key
reconstruction took 32.947 s, proof verification 1.559 s and the process 34.64 s
wall time, with 626,160 KiB peak RSS and zero swaps under the 3 GiB/600 s cap.
The [evidence artifact](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42118077893/artifacts/13456622998)
retains the lockfile, dependency/feature records, inputs and detailed results.
Metrics here come from completed job logs; the ZIP was not downloaded locally.

Review after that run found the retained-fixture gate was checked before key
reconstruction but after inner decoding. `decode_retained` now requires it before
bincode admission too. A fourteenth native negative first admits a coherent
outer frame with a non-retained malformed inner proof, then requires the exact
scope error before decoding. That additional ordering regression requires the
corresponding current-head hosted run; the earlier 13-check run does not cover it.

Current fixed-claim round measurements:

| Graph | Leaves | Baseline Script bytes | Compact-v1 Script bytes |
| --- | ---: | ---: | ---: |
| Quadratic sumcheck round, either engine | 590 | 2,558,213 | 2,187,953 |
| Cubic sumcheck round, either engine | 875 | 3,834,241 | 3,278,851 |
| Keccak permutation round 23 | 9,605 | 1,770,264 | Not measured |

These totals sum actual serialized disproof leaf bodies, including fixed-claim
opening hashes, program/claim tags, anchors where applicable and exact witness
length guards. They exclude transaction framing, control blocks and assertion
signatures. Sumcheck inputs/challenges are constants in the standalone round
fixture. Keccak's largest measured fixed-claim leaf is 194 bytes; generating
its selected corpus took about 0.50 seconds and 44.2 MB peak working set without
an enforced local memory ceiling. These are fixture costs, not complete proof,
signature-inclusive WOTS or bridge transaction costs. Existing full arithmetic
baseline/comparison measurements remain in `M2-CI-NOTES.md`, `M2-COMPACT.md`
and `WOTS-REGISTRY.md`.

## Reproduce reference checks

Python 3.10+ and the pinned mature hash dependency are required for the new
tests. The following reference work is lightweight and generates no proofs:

```sh
cd integrations/bitvm2-nova
python -m pip install -r transcript-requirements.txt
python -m unittest discover -s tests -v
python bench_transcript.py --cases results/native-transcript-inputs.json
python bench_nht4.py
python bench_spartan.py results/native-spartan-inputs.json
python bench_keccak.py --out results --round 23
```

Run the following only on a suitable hosted runner under the workflow's time
and memory limits. The native workflow caps retained-proof reconstruction and
verification at 3 GiB address space and ten minutes. Do not launch these Rust builds or public-parameter
reconstruction on the RAM-constrained host. Keep the two oracle workspaces'
lockfiles and dependency trees with their outputs:

```sh
cargo generate-lockfile --manifest-path nova-oracle/Cargo.toml
cargo tree --locked --manifest-path nova-oracle/Cargo.toml > results/native-cargo-tree.txt
cargo build --release --locked --jobs 2 --manifest-path nova-oracle/Cargo.toml --bins
nova-oracle/target/release/transcript results/native-transcript-inputs.json > results/native-transcript-execution.json
nova-oracle/target/release/sumcheck results/native-spartan-inputs.json > results/native-spartan-execution.json
timeout --signal=KILL 600s prlimit --as=3221225472 --cpu=600 -- \
  nova-oracle/target/release/nht4 results/nht4-inputs.json > results/native-nht4-execution.json
python bench_spartan.py results/native-spartan-expanded-inputs.json --native-report results/native-nht4-execution.json
nova-oracle/target/release/sumcheck results/native-spartan-expanded-inputs.json > results/native-spartan-expanded-execution.json

cargo generate-lockfile --manifest-path m2-oracle/Cargo.toml
cargo build --locked --manifest-path m2-oracle/Cargo.toml
m2-oracle/target/debug/bitvm2-nova-m2-oracle --scripts results/keccak-engine-vectors.jsonl
cargo generate-lockfile --manifest-path rust-oracle/Cargo.toml
cargo build --locked --manifest-path rust-oracle/Cargo.toml --bin registry
rust-oracle/target/debug/registry results/keccak-registry-inputs.json results/keccak-registry-engine-vectors.jsonl
```

An upstream interpreter panic is a failed run. It must never count toward an
expected rejection. Exact witness length is checked before indexed opening
access. Independent Script evidence must retain enabled stack limits, canonical
encoding checks, disabled OP_CAT and forbidden OP_SUCCESS behavior.

## Remaining production boundary

The production path still requires a complete authenticated composition:

- Enforce the verifier-owned dimensions and bounded parsing conditions in
  [ARBITRARY-PROOF-PREFLIGHT.md](ARBITRARY-PROOF-PREFLIGHT.md) before removing the
  retained-fixture gate. Nova's outer hash/NIFS stages also require Poseidon;
  the Keccak transcript implementation covers the Spartan/IPA transcript only.
- Replay the entire compressed Nova/Spartan verifier transcript from the real
  proof and verifier key, with exact labels, object order and both curve roles;
  bind external network/circuit/key/`k`/step/state expectations to that execution.
- Bind sumcheck initial claims, round shapes, matrix evaluations and terminal
  claims to actual instances and IPA openings. Complete production IPA
  verification, generator derivation/access and its real dimension/RAM ledger.
- Compose all 24 Keccak rounds with shared authenticated boundaries, correct
  absorption, padding, squeeze and Nova transcript framing. Equal wire names
  in independently committed round programs do not authenticate their linkage.
- Connect decoded proof data and native transcript challenges to disputable
  Script computation. Constant-anchored arithmetic fixtures do not supply this
  connection.
- Finish production WOTS key lifecycle and assertion binding, a complete
  shared-wire dispute graph, malformed-state/data-availability coverage and
  authenticated Bitcoin commitments/transactions. Build and check presigned
  paths, control blocks, signatures, timelocks, witnesses and transaction weight.
- Demonstrate end to end that an invalid proof has a spendable disproof path
  and a valid proof cannot be refuted. No complete-verifier, deployment or
  funds-safety result follows from this milestone.

No proving job, GPU run, transaction, bridge transfer or deployment is part of
these checks. The transparent no-trusted-setup requirement includes the final
compression stage and remains in force.
