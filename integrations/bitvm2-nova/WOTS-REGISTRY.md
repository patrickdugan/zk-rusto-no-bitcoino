# Program-wide WOTS assertion registry

This milestone follows PR #20 at `3be58ce06510c9408e03f2f9f1d73db29e51aabd`.
It replaces per-leaf key choices with one immutable ordered registry for every
wire in a verifier-owned arithmetic program. M2, compact-v1 and the v1 WOTS
leaf remain separate baselines. Header provers and their RAM-targeted `k`,
BitVM3 and Claude/testnet4 work are unchanged.

## Registry and catalogue binding

`wots_graph.py` builds the complete catalogue from the original `Program`.
It includes every original constraint, one canonicality predicate for every
declared field, and a validity predicate for any otherwise unused small word.
The catalogue digest commits program/context/field-role/operation identity,
all ordered wire names and bounds, all ordered predicate kinds/arguments/wire
occurrences, and the exact expanded predicate bodies. Assignment values are
absent. Predicate bodies are deduplicated by SHA-256 in the fixture format.

`rust-oracle/src/registry.rs` verifies the catalogue, bounds and body hashes,
rejects unsupported shapes/opcodes, and binds one unique WOTS4 public key to
each global wire. Its constructor requires caller-owned expected catalogue
and registry IDs. Never source these expectations from the assertion's own
declared hashes. Swapped keys, duplicate keys, missing/surplus keys, altered
catalogues, wire reordering, changed bounds and missing validity leaves cannot
retain the expected registry identity.

Every compiled leaf includes the complete registry identity and its ordinal
and direction. Changing a key outside the selected leaf therefore changes that
leaf's compiled identity too. The surrounding Bitcoin transaction/Taproot
adapter must authenticate the expected leaf commitment; it is not implemented
here. A digest supplied by a claimant does not authenticate itself.

An assertion has exactly one WOTS signature per global wire. `Registry::witness`
selects those existing signatures for a leaf. The test signer signs every wire
once and never signs a second value with the same key. Repeated uses of one
signature for the same wire/message do not create a second signing operation.
Different wires may not share a key. Production persistent key lifecycle and
cross-session reuse prevention remain unimplemented.

Duplicate occurrences within one predicate are authenticated once and expanded
back into the original ordered operands. This supports additions such as
`y+y` without introducing two separately asserted values for `y`. The complete
255-step multiplication uses the same registry slots and signature bytes for
every adjacent accumulator and the final output equality. Bit reconstruction,
zero anchors and final equality remain original constraints in the catalogue.

## Malformed signed values

The exact initial witness count is checked before upstream WOTS stack access.
Each WOTS element must be 20 bytes; upstream verification authenticates the
message and checksum. All required signatures are verified before signed-word
validity can select a disproof result. Forged or missing openings abort; they
are never inverted into a successful disproof.

Each recovered four-byte message is checked for the 29-bit limit before numeric
assembly. The registered word bound is checked as well. Invalid signed words
produce a false predicate result and remain disputable without overflowing a
four-byte ScriptNum. All field words receive explicit field-validity leaves.
Their borrow comparisons return false for equality with or values above the
modulus, instead of aborting in an arithmetic kernel's canonicality guard.

This extra coverage matters for the multiplier. A completely coherent trace
of multiplication by the noncanonical integer `p` can satisfy every original
bit reconstruction and modular arithmetic equation. Its new `input/b`
canonicality leaf refutes it. The fixtures demonstrate this case with all
original native predicates true and independent Script execution of the
selected original predicates and canonicality disproof.

For a registry with all validity and original predicates true, the signatures
identify one bounded, canonical assignment shared across all occurrences,
assuming WOTS one-time signing discipline and hash security. The M2 arithmetic
argument then applies to that assignment. This conditional argument has not
been formally verified or audited. Missing assertion data, key distribution,
timeouts and transaction-level dispute completeness need the production
protocol; rejecting a missing opening locally does not implement those paths.

## Coverage and accounting

| Catalogue, either Pasta field/curve | Global words | Original constraints | Extra field-validity leaves | Total authenticated leaves |
| --- | ---: | ---: | ---: | ---: |
| Multiplication | 2,586 | 274 | 259 | 533 |
| Complete point addition | 33,588 | 3,616 | 3,363 | 6,979 |

The hosted harness compiles and counts every disproof leaf once for both
complete catalogues, using actual upstream WOTS public keys. It records ordered
leaf-stream hashes, largest leaf sizes and raw key/signature payload sizes.
These sums include WOTS checks and the newly explicit field-validity leaves.
They exclude transaction framing, control blocks and the remaining assertion
protocol. They are not directly comparable with the old arithmetic-only leaf
count as an optimization, and are not fee estimates.

Both complete 533-leaf multiplication catalogues execute in both predicate
directions. Both point catalogues execute every distinct predicate/alias shape
(25 each, including decoder-bound variants), plus the failed leaves for a wrong
but canonical point result.
Every point leaf is compiled and measured, but not every point leaf is executed
with WOTS in this bounded suite. Existing M2 tests continue executing every
fixed-claim point leaf and independent curve comparisons.

The native harness checks all 510 adjacent/final multiplication signature links
across both fields. Adversarial cases cover a broken middle link, wrong bits,
nonzero anchor, false result, coherent wrong/noncanonical multipliers, signed
oversize words, wrong canonical point results, signature corruption/substitution,
all witness-length variants and catalogue/key/role/context substitutions.
Native malformed-JSON, index/shape and forbidden-opcode checks fail closed.

`bench_registry.py` now produces a bounded JSON input with 49 signing sessions,
including Boolean truth tables and invalid signed bits, 18,676,730 bytes, SHA-256
`887a9d2ff810be2c937fe123ccfa79b730550f88f83cad9caf0655d2aadbc5f5`.
Local generation took 1.951 s and peaked at 87,867,392 bytes of Windows working
set (about 83.8 MiB); this was not an enforced memory ceiling. No Rust build,
Nova proving job, GPU run or heavy test runs on the local PC.

The hosted `BitVM2 Nova global registry checks` workflow uses BitVM WOTS at
`c620dbfaacebdf778e765a6681985350389973b1` and the interpreter at
`ba96bc2bd76774c9d1b011461cb79d983c2c43a1`. Actual initial witnesses, minimal
encodings/IF, the 1,000-item stack limit and disabled OP_CAT are enforced.
OP_SUCCESS is forbidden. Interpreter panics are fatal, never rejection evidence.
Read the completed current-head workflow and its evidence artifact before
claiming independent execution or measured signature-inclusive costs.

The first main-branch registry run
([42109257674](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42109257674))
compiled successfully but failed its complete run: the catalogue guard wrongly
required every `gate_equal` selector to have bound five. Curve membership uses
a Boolean infinity flag with bound two. The guard now accepts the declared
Boolean or five-way selector, requiring gate cases to fit that bound; the WOTS
decoder still enforces the exact registered bound. A regression records both
selector roles. That failed run is not complete-execution acceptance evidence.

Main `7708a99` subsequently passed the complete registry run
([42110490602](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42110490602)):
2,484 vectors, 1,304 expected rejections, 56 native rejections and all 510 shared
accumulator/final links. Complete authenticated multiplication sums to
16,798,073 disproof Script bytes (533 leaves); each point catalogue sums to
219,498,908 bytes (6,979 leaves). Largest leaves are 49,538 and 79,381 bytes,
respectively. The corpus reached 485 stack items and 9,600 witness bytes.
These costs are much larger than the fixed-claim arithmetic baseline.

The sampler now distinguishes decoder-bound variants as well as predicate/alias
bodies (25 point shapes instead of 23). Registry construction also lazily caches
each immutable wire's compiled WOTS/decoder block to avoid repeated upstream
compilation. This increases bounded verifier-generation memory and changes no
leaf bytes; the harness checks all four complete leaf-stream hashes and byte
totals against the uncached `7708a99` run. Main `6a87b90` passed
[42113034117](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42113034117):
2,492 vectors including 1,308 rejections, all 25 shapes per point catalogue and
exact byte preservation. Runtime fell from 428.713 to 169.809 seconds on the
respective hosted runners; this is an observed run comparison, not a controlled
hardware benchmark. The expanded Boolean corpus passed on main `f428c32`
([42116859987](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42116859987)):
49 cases, 2,538 Script vectors, 1,331 expected rejections, 56 native rejections,
all 510 links and all four unchanged complete leaf-stream hashes and byte totals.

```sh
cd integrations/bitvm2-nova
python -m unittest discover -s tests -v
python bench_registry.py
# On a suitable hosted runner, without proving:
cargo generate-lockfile --manifest-path rust-oracle/Cargo.toml
cargo run --locked --manifest-path rust-oracle/Cargo.toml --bin registry -- \
  results/registry-inputs.json results/registry-engine-vectors.jsonl
```

This completes an arithmetic assertion-registry boundary only when those checks
pass. Production key lifecycle, authenticated Bitcoin commitments/transactions,
data-availability disputes, whole-proof Nova/Spartan transcript binding and
complete authenticated IPA verification remain future work. The bounded
transcript, NHT4 and sumcheck components in
[NATIVE-CONFORMANCE.md](NATIVE-CONFORMANCE.md) do not close those gaps. No complete Nova proof or
deployability result is established, and no transaction is broadcast. The
transparent Nova -> Spartan/IPA pipeline still has no Groth16/KZG wrapper or
trusted setup, including final compression.
