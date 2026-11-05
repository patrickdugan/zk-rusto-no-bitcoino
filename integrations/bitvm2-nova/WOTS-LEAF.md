# WOTS-authenticated multiplication leaf

This bounded milestone follows M2.1 at `39b15c6b595af31e31001d9dc04c6375d20c2cc1`.
It connects one multiplication bit-step to real upstream BitVM Winternitz
signatures. It does not complete production Nova verification or BitVM2's
assertion/transaction graph. Existing M2 and compact compilers remain unchanged.

## Implemented boundary

`wots_leaf.py` derives a verifier-owned template from an existing `Program` and
one `mul_bit` ordinal. It admits exactly 28 distinct named wires, with their
original nine-limb field layouts and Boolean bit bound. Its template commits
the full program digest, context, field role, operation ID, ordinal, wire order,
bounds, compiler and predicate body. No assignment values enter the template.

`rust-oracle/src/wots.rs` uses upstream `Wots4::compact_checksig_verify` from
BitVM revision `c620dbfaacebdf778e765a6681985350389973b1`. It does not reimplement
the Winternitz hash chains or checksum. Each named word has its own WOTS public
key, and the ordered public keys are committed with the template identity.
Construction requires the expected template and key identities supplied by the
verifier. Do not take these expectations from an untrusted assertion's own
declared IDs. Duplicate keys within a leaf are rejected.

Four-byte messages encode unsigned words in little endian, with 10 compact
signature elements per word. A witness is ordered by wire, then by upstream's
signature digit order. The compiler consumes wires in reverse stack order.
Recovered words and validity flags are held on the altstack while subsequent
signatures are checked, then restored in the arithmetic kernel's original
little-endian limb order.

Every leaf starts with an exact `OP_DEPTH` guard for 280 signature elements,
before any upstream signature access. Upstream checks each element's 20-byte
length and its signature/checksum. Compact witnesses contain no claimant-
provided ScriptNum digit encodings. Script reconstructs the authenticated
message and creates the minimal numeric words itself.

## Invalid openings versus invalid signed values

A forged, swapped, incorrectly sized or missing signature aborts. It cannot
disprove an honest assertion. In contrast, an authenticated but inadmissible
value must be disputable:

- The high nibble is checked before numeric reassembly. Values requiring more
  than 29 bits take a false-validity branch without overflowing a four-byte
  ScriptNum. The bit must also be below two.
- All 28 signatures are verified before these validity flags can select a
  false predicate result. A malformed value cannot mask a forged signature.
- A borrow comparison checks all three complete field values against the
  selected Pasta modulus. Equality with the modulus and larger values return
  false, instead of aborting in a canonicality VERIFY.
- For admissible values the original compact multiplication predicate checks
  `(2*t + bit*a) mod p = output`. Its existing range and canonicality checks
  remain in the body as well.
- Only the final correctness Boolean is inverted for a disproof. Authentication
  failures are never inverted into successful disproofs.

The decoder's largest assembled word is `2^29-1`; the canonicality borrow
intermediates stay in `[-2^29,2^29-1]`. All arithmetic therefore retains the
four-byte numeric bound. Unsupported shapes fail closed. This API currently
supports one multiplication step, not every trace predicate.

## Checks and evidence

`bench_wots.py` generates 56 deterministic cases for both Pasta moduli. They
include correct and false arithmetic, zero and reduction boundaries, invalid
bits, signed noncanonical inputs/outputs and signed words through `0xffffffff`.
The input file is 504,920 bytes, SHA-256
`afcedc4d0dbd35ba506e4a22673babe8292fe1c4fbc998c8f821fd2e01aa94f9`.

The Rust `wots` executable creates a fresh TEST-ONLY key for every case and
wire and signs exactly one message per key. It compiles the leaf before
signing, then checks that signing did not change the script. It executes both
predicate directions, corrupts every signature element including checksum
chains, exercises empty/truncated/prepended/appended witnesses, substitutes
wire signatures and identities, and combines malformed values with forgery.
These public deterministic test keys must never be used live.

Execution uses actual initial witness stacks through upstream interpreter
revision `ba96bc2bd76774c9d1b011461cb79d983c2c43a1`, minimal encodings, minimal IF,
the 1,000-item stack limit, explicitly disabled OP_CAT and an opcode allowlist.
Panics are fatal. Nothing catches a panic or counts it as a successful rejection.

The hosted `BitVM2 Nova WOTS leaf checks` workflow builds this isolated oracle,
streams the executed vectors to JSONL, and records script/witness/stack costs,
dependency resolution, source revision and outcome in its evidence artifact.
The existing primitive and full-graph workflows retain their original vectors.
Do not infer independent success from fixture generation or Python tests; read
the completed current-head workflow and PR evidence.

```sh
cd integrations/bitvm2-nova
python -m unittest discover -s tests -v
python bench_wots.py
# Build on a suitable CI runner; no Nova proving job is needed.
cargo generate-lockfile --manifest-path rust-oracle/Cargo.toml
cargo run --locked --manifest-path rust-oracle/Cargo.toml --bin wots -- \
  results/wots-inputs.json results/wots-engine-vectors.jsonl
```

The local PC performs only lightweight Python checks and formatting. Rust
compilation and authenticated execution run on hosted CI. The BitVM library
dependency includes other upstream backends; this adapter calls only its WOTS
signature code and introduces no Groth16/KZG proof stage or trusted setup.

## Remaining boundaries and stop conditions

This milestone is accepted only after current-head hosted execution confirms
both predicate directions, every tested forgery/length rejection, authenticated
malformed-value disproofs, identity substitutions, and recorded resource costs.
A panic, mismatched expectation, source/fixture discrepancy or disabled stack
limit is a failure, not a partial acceptance.

A global shared-wire assertion/key registry still needs integration before
these leaves replace the complete M2 fixed-claim graph. The same named wire
must use the same authenticated assertion across every occurrence. One-time
keys must never sign two different messages; signing transactions, key
distribution and lifecycle enforcement are not implemented here. External
authentication of the verifier-owned template/key roots remains an application
obligation. No complete malformed-assertion coverage for all graph predicates
is claimed from this one supported leaf shape.

Actual Nova/Spartan transcripts, NHT4 decoding, full IPA verification, Taproot
commitments, Bitcoin transaction graphs and release dependency locking remain
future work. No complete Nova proof, deposit/withdrawal path or deployability
claim follows from this adapter. There are no broadcasts, merged PRs, services
or new security/access settings. Header provers, their RAM-targeted `k`, BitVM3
and the separate Claude/testnet4 work remain unchanged.
