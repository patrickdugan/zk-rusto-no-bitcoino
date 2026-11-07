# M14: the M13 final verifier as a fixed garbled circuit

M13 left a native verifier of the SP1 wrap layer under BLAKE3 ([`../m13/verify`](../m13/verify)) and a
garbled price derived from operation counts of one verification. M14 builds that verifier as a
Boolean circuit with a fixed shape, keeping every check `verify_final` makes (wrap key pin, STARK,
exit code 0, completeness, guest key, recursion key root, committed statement digest).

Order of work:
1. field arithmetic (KoalaBear, its degree-4 extension, challenge sampling);
2. hashing (BLAKE3 of fixed-length inputs, the Fiat-Shamir transcript, Merkle paths);
3. SP1's verifier logic for the wrap shape (jagged PCS, BaseFold, zerocheck and LogUp-GKR
   sumchecks), the statement and pin checks;
4. the whole circuit run on the committed proof and on mutated proofs, against `m13-verify`.

Steps 1 and 2 are in [`circuit/`](circuit). Steps 3 and 4 are in [`e2e/`](e2e): the complete final
verifier, run on real proofs in plain execution and garbled (see
[The complete final verifier](#the-complete-final-verifier)).

## The complete final verifier

[`e2e/src`](e2e/src) builds `verify_final` with transcript v2 as one circuit with one output wire.
Each stage follows sp1-hypercube 6.9.0's `verify_shard` and the verifiers it calls:
- **Preamble** ([`verifier.rs`](e2e/src/verifier.rs)): the pinned wrap key's transcript bytes, the
  187 public values, the main commitment, the shape. The constant bytes come from SP1's own
  `observe_into` code run on a recording challenger.
- **LogUp-GKR**:
  - grinding check;
  - the output claims (nonzero denominators, Σ n/d = 0);
  - 20 layer sumchecks;
  - interaction fingerprints from the chip openings.
- **Zerocheck**:
  - the 21-round sumcheck;
  - each of the 9 wrap-machine chips' AIR constraints, evaluated from SP1's own `eval` through a
    symbolic builder. p3-uni-stark 0.4.3-succinct's builder labels preprocessed columns
    `Entry::Main`; `SymBuilder` labels them correctly.
- **Jagged PCS** ([`pcs.rs`](e2e/src/pcs.rs)):
  - the modified-commitment checks;
  - the 27-round sumcheck;
  - the 56-round jagged-evaluation sumcheck, with its branching program and 122 constant prefix
    sums.
- **Stacked PCS and BaseFold**:
  - the batch claim and the 21 BaseFold rounds;
  - 94 queries, each with 2 component Merkle openings (depth 24) and 21 FRI rounds with
    openings.
  - x⁻¹ is computed as (g⁻¹)^rev(i), so FRI folding needs no field inversion.
- **Statement** ([`full.rs`](e2e/src/full.rs)): exit code 0, complete, and the guest key digest,
  recursion key root and committed-values digest equal to the pinned statement.
  - The wrap key is a circuit constant.
  - Every input field element is range-checked (< p).

The shape (chips, heights, column counts, path depths) comes from the pinned proof and is fixed.
Every proof value is an input. Values the native verifier recomputes and compares (sumcheck points
and claims, LogUp evaluation point) are derived instead of read.

| Measured on the committed proof (c4, transcript v2) | |
| --- | ---: |
| Non-free gates (= ciphertexts) | **785,442,492** |
| Ciphertext per circuit at 16 bytes per gate | 12.6 GB |
| Input bits (52,203 field elements, extension elements and digests) | 8,635,080 |
| Plain execution, whole circuit (one thread, Windows) | 143 s |

Against the estimates:
- M13 priced this verifier at 1.21–1.97 × 10^9 gates from operation counts.
- The built circuit is 785 M: 2.5× below M13's upper tier.
- That is 14× below the upstream garbled Groth16 verifier (1.12 × 10^10).
- It is 43× below M12's Poseidon2 figure.

**Checks** ([`e2e/tests`](e2e/tests)):
- `stages`: SP1 accepts the real proof natively, by its own `verify_logup_gkr` and
  `verify_zerocheck`. The circuit's stages accept it too.
  - Every byte the circuit transcript observes equals SP1's recorded transcript.
  - Per chip, the circuit's constraint evaluation and padded-row adjustment equal SP1's
    `eval_constraints` and `compute_padded_row_adjustment`.
  - A changed opening is rejected.
- `full`: `m13_verify::verify_final` accepts the committed proof, and so does the circuit. The
  circuit rejects:
  - a flipped Merkle path bit;
  - a changed public value;
  - a changed FRI row value;
  - a non-canonical field encoding (x + p);
  - the right proof under another pinned statement.
- `full` (local, `M14_SECOND_PROOF_DIR`): a second guest's real proof (same wrap key and shape,
  different values) is accepted by the circuit built from the committed proof's shape, under its
  own statement.
- `garbled`: the whole circuit garbled and evaluated.
  - The garbler (AES half-gates, the repo's `GarbleMode`) streams its 785,442,492 ciphertexts
    through a bounded channel to an evaluator running concurrently.
  - The evaluator holds only the input labels of the proof's 8,635,080 bits.
  - For the real proof, its output label is the garbler's label for accept; for a proof with one
    flipped bit, the label for reject.
  - Each garble-plus-evaluate run takes 209 s here.

A diagnostic check list (`final_verifier_parts`) found one bug while this was built: SP1 folds
each BaseFold message as m₀ + β·m₁, not by interpolation. The fix is in the history.

### Guest A (the Nova verifier)

The circuit does not depend on the guest. The wrap program, key and proof shape are the same for
every guest, and the second-proof test confirms it on another guest's proof. A final proof of
guest A, the complete Nova verifier from M12, goes through this exact circuit with A's two pins:
- guest key `5df3760f…f46b`;
- statement digest `d3b478b0…2fa0`.

Both are in [`../m13/pins.json`](../m13/pins.json).

**Not produced: guest A's compressed proof.** It was run here on 2026-11-07, with SP1 6.9.0's
CPU prover, a 12 GiB RAM cap and 1.12 M-instruction shards (`ELEMENT_THRESHOLD=2^26`,
`HEIGHT_THRESHOLD=2^20`):
- execution checks passed (exit code 0, statement `d3b478b0…`);
- steady proving was one shard every 165–189 s;
- guest A executes 72.3 × 10^9 instructions, which is about 64,600 shards, or about 131 days on
  this machine. The run was stopped.

The GPU here (RTX 5080 Laptop, 16 GB) runs a training job, and SP1's CUDA prover needs about
24 GB. The proof needs a 24 GB+ GPU, the prover network, or a much larger CPU host.

With the compressed proof in hand:
1. `run_full_a.sh` produces it (or reuse an existing compressed proof);
2. `m13 shrink-wrap` / `wrap-only-v2` wraps it;
3. `full::Known::new(proof, statement)` with A's statement verifies it.

## What is built

[`circuit/src`](circuit/src):
- `field.rs`: canonical-input check, add, sub, neg, double, halve, multiply (M12's Karatsuba
  product and Barrett reduction), constant multiply, inverse (SP1's addition chain), powers,
  equality, select, wide reduction, and constant-base powers by an index given as bits.
- `ext.rs`: SP1's `BinomialExtensionField<KoalaBear, 4>` (X^4 = 3). Multiplication reduces lazily:
  the 16 integer products are summed per coefficient (wrapped terms times 3) and reduced once.
  Also square (10 products), Frobenius maps, and inverse as in p3's `frobenius_inv`.
- `sample.rs`: fixed-cost challenge sampling (see below).
- `hash.rs`: BLAKE3 of any fixed length (chunks, flags, counters, parent tree), M13's byte
  transcript, Merkle leaf and node hashing, path roots and digest equality.
- `sumcheck.rs`: `slop_sumcheck::partially_verify_sumcheck_proof`.
  - It checks p_0(0) + p_0(1) against the claim, then p_{i-1}(α_{i-1}) = p_i(0) + p_i(1) for
    each later round.
  - It observes each polynomial, then samples the next α (v2).
  - The proof's point and final evaluation are derived, not taken as input. SP1 builds the
    point with each α inserted at the front, and a proof whose copies differ is one the native
    verifier rejects. The derived copies save their input labels.

A multiplication whose operand is a compile-time constant takes the constant path automatically,
so the circuit's gate count reflects which operands are actually constant.

## Checks

[`circuit/tests/gadgets.rs`](circuit/tests/gadgets.rs), 12 tests:
- **Against SP1's own types** (`p3-koala-bear 0.4.3-succinct`, `BinomialExtensionField<KoalaBear, 4>`):
  - every base and extension gadget on edge values (0, 1, p - 1, (p ± 1)/2, 2^24, 2^30, the
    extension's d-th root) and random inputs;
  - inverse of 0 returns 0, where the native inverse returns `None`; callers that must reject 0
    test `is_zero`.
- **Against the `blake3` crate:** BLAKE3 of 0 to 5,000 bytes (1 to 5 chunks).
- **Against M13's transcript:** a native copy of `Blake3Transcript` runs an 11-step
  observe/sample script, including a 1,100-byte absorb and a 33-byte squeeze across a re-hash.
- **Against real verifications:** `m13-verify` with `M13_TRANSCRIPT_TRACE` records every byte
  its transcript observes and samples while verifying the c4 final proof. The recordings are in
  [`circuit/fixtures/c4-v1-transcript.bin`](circuit/fixtures) and `c4-v2-transcript.bin`:
  - v1: 39,568 bytes observed, 8,836 sampled;
  - v2: 39,568 bytes observed, 17,124 sampled.

  Given the observed bytes, the circuit transcript produces every sampled byte of both. This
  exact transcript of the final verifier costs 11,198,078 gates under v2 (10,916,094 under v1).
- **Against the real zerocheck:** `m13-verify dump-zerocheck-v2` writes the c4 v2 proof's
  zerocheck sumcheck to
  [`circuit/fixtures/c4-v2-zerocheck.json`](circuit/fixtures/c4-v2-zerocheck.json): 21 rounds of
  degree-4 polynomials.
  - SP1's extension type confirms the rounds natively.
  - The circuit accepts them and returns SP1's final evaluation, both plainly and garbled.
  - A changed coefficient or claim is rejected.
- **Merkle paths:**
  - roots match a native BLAKE3 tree;
  - a flipped sibling bit or a wrong root is rejected.
- **Barrett domain:**
  - M12's reduction circuit keeps 31 bits of the quotient, so it is exact for x < p·2^31;
  - the native model is swept on 16.8 M values below p²;
  - the circuit is checked at the p² and 2^61 boundaries and fails at 2^62 - 1;
  - every caller passes less than p², which is why wide values split at bit 61.
- **Garbled evaluation:** each case below is garbled, then evaluated with the input labels of real
  values, and every output label must be the garbler's label for the native result bit:
  - extension multiplication;
  - base inverse;
  - the sampler;
  - the canonical check on a non-canonical input;
  - the full transcript script;
  - the real zerocheck sumcheck.
- **Gate counts:** taken in ExecuteMode and as GarbleMode ciphertexts (the two must agree), and
  required to equal [`circuit/RESULTS.json`](circuit/RESULTS.json).
  - The agreement check found one disagreement: adding a constant 0 built an AND of a carry and
    its own negation. ExecuteMode counted it; the garbler emitted no ciphertext for it.
  - `add` now returns the operand for + 0. It also uses `double` for x + x (61 gates against 94,
    and no AND with one wire as both inputs). Every count agrees.

## Measured gate counts

Non-free (AND-class) gates; XOR and NOT are free.

| Gadget | Gates | M13 price assumption |
| --- | ---: | ---: |
| base multiply / square | 2,068 | 2,068 |
| base add / sub / neg | 94 / 91 / 90 | 94 |
| base constant multiply: ×3, ×11, ×2^24, ×d-th root, ×two-adic generator (2^24) | 159, 328, 365, 611, 1,057 | 159 / 328 / 2,068 |
| base inverse (36 multiplications) | 74,448 | counted as multiplications |
| canonical-input check | 30 | not priced |
| extension multiply (lazy reduction) | 30,115 | 34,693 (16 reduced products) |
| extension square | 19,524 | — |
| extension × base | 8,272 | — |
| extension Frobenius | 1,402 | — |
| extension inverse | 154,736 | — |
| index power g^idx, 24-bit index | 21,891 | — |
| challenge, base field (8 bytes mod p) | 464 | — |
| challenge, extension | 1,856 | — |
| BLAKE3, one 64-byte block (Merkle node, 16-element leaf) | 10,281 | 10,410 |
| BLAKE3, 1,025 bytes (18 compressions) | 183,385 | 187,380 |
| **Transcript of the c4 final verification, v2** (1,177 compressions) | **11,198,078** | 12,252,570 (1,177 × 10,410) |
| Transcript of the c4 final verification, v1 (1,144 compressions) | 10,916,094 | 11,909,040 |
| Sumcheck rounds, zerocheck shape (21 rounds, degree 4; transcript excluded) | 2,600,555 | — |

## Decisions

**Circuit input encoding.** SP1's KoalaBear deserializer does not range-check in release builds:
`from_canonical_u32` only debug-asserts, then reduces mod p. The native verifier therefore accepts
any 32-bit word and uses its residue.

The circuit takes each field element of the proof as 31 bits and rejects values ≥ p
(`is_canonical`, 30 gates). For every proof the native verifier accepts, the canonical encoding of
its field values is accepted by the circuit, and the reverse also holds. The circuit accepts
exactly the same field values, with one encoding each.

**Fixed-cost challenge sampling (transcript v2).** SP1's `SerializingChallenger32` samples by
rejection: it takes 4 bytes, keeps 31 bits, and retries while the value is ≥ p (about 1 in 128).
Each rejection shifts the byte position of every later challenge. A circuit would need a
variable-offset selector for every later sample. M13's price instead covered this with observed
runs plus a margin.

v2 takes 8 bytes per base-field challenge and reduces the little-endian u64 mod p (464 gates).
- Every challenge consumes a fixed number of bytes, so the transcript's shape is fixed.
- No residue has probability above (1 + p/2^64)/p. Any event over the challenges therefore has
  at most (1 + 2^-33) times its uniform probability, so each Fiat-Shamir soundness term grows by
  that factor.
- Query indices (`sample_bits`) stay as they are: 4 bytes masked to the low bits, which is uniform.
- v2 uses its own transcript domain (`hash::DOMAIN_V2`).

**The prover side of v2 is in M13's code.**
- `ctx::Blake3ChallengerV2` and `Blake3KoalaBearV2` are SP1 `IopCtx` types.
- SP1's CPU prover proved the c4 shrink proof's wrap layer under them (`m13 wrap-only-v2`).
  The output is [`../m13/fixtures/c4-wrap-blake3-v2.bin`](../m13/fixtures/c4-wrap-blake3-v2.bin):
  same key, statement and size as v1, proved in 55 s.
- `m13-verify verify-v2` accepts it.
- Flipped bytes and altered public values are refused, and v1 and v2 proofs are each refused by
  the other verifier. These checks are in `m13/verify/tests/final_verifier.rs`.
- One v2 verification spends 1,177 transcript compressions in 537 squeezes
  ([`../m13/results/verify-counts-c4-v2.json`](../m13/results/verify-counts-c4-v2.json)), against
  1,144 in 504 for v1.

Two checks tie the circuit to v2:
- the circuit's sampler is checked against v2's native formula (`ctx::sample_base_v2`);
- the circuit transcript reproduces the recorded v2 verification byte for byte (above).

Which sampled bytes become which field challenge is fixed by the verifier logic (step 3).

**Constant multiplications.** M13's operation counter classified a multiplication as
"small-constant" from its runtime operand values. In the circuit, only compile-time constants are
cheap. Until step 3 shows which operands are constants, the reference price is M13's upper tier
(1.97 × 10^9 gates), plus the items M13 left unpriced.

## Reproduce

Windows (MSVC):

```powershell
$env:RUSTUP_TOOLCHAIN='1.90.0-x86_64-pc-windows-msvc'
cargo test --release --locked --manifest-path nova-bitvm3/m14/circuit/Cargo.toml -- --test-threads=2 --nocapture
```

Linux: the same `cargo +1.90.0 test ...` command; CI runs it in [`nova-m14.yml`](../../.github/workflows/nova-m14.yml).
`M14_WRITE_RESULTS=1` rewrites `RESULTS.json`.
