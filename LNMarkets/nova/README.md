# LNMarkets on BitVM3/Nova

The primary LNMarkets proof architecture is **Nova 0.76 folding in BitVM3**, matching
[integrations/bitvm3-nova](../../integrations/bitvm3-nova/README.md).
The old standalone SP1 guest and Groth16 harness are retained under
[../sp1](../sp1/README.md) as a non-default experiment. They are separate from
this architecture.

## The first folding step

The verified batch certificate comes from
[../statement](../statement/src/lib.rs). Its native verifier checks the actual
BIP340 summary and batch-consent co-signatures, the indexed outcome and
two-of-three oracle signatures, the original UTXORef Taproot funding template,
the SHA-256 sparse nullifier transition, and the exact unsigned Bitcoin batch.

For each row, a new Nova step receives an **opaque SHA-256 digest of the signed
transcript**, the funding outpoint limbs, outcome index, collateral and payouts.
Inside R1CS, the step enforces satoshi conservation and 51-bit ranges, advances
cumulative totals and absorbs those inputs into M18's existing Pallas Poseidon
sponge. Eight field elements carry the state across steps:

```
z[0] = step count
z[1] = total collateral
z[2] = total payouts including anchor
z[3] = total fee
z[4] = Poseidon chain of private signed-row digests and economics
z[5] = native journal SHA-256 low 128 bits
z[6] = native journal SHA-256 high 128 bits
z[7] = epoch
```

The initial Poseidon root includes the same journal digest and epoch. The fold
is checked against a separately calculated native final state.

**Security boundary:** This first R1CS step treats the signed-row SHA-256
digest as an opaque witness, so a prover could invent another digest. An R1CS
proof alone does *not* prove either party's BIP340 signature, an oracle
attestation, full original DLC signature verification, a Merkle SHA256 path, or
Bitcoin spendability. The native exporter currently validates those claims
before trace construction; a malicious exporter is an explicit threat.
An independent BitVM3 verifier needs these claims constrained in the Nova
circuit or verified through a separately pinned proof with exact shared inputs.
Do not accept the fold as a funded-execution authorization.

## Why this is the BitVM3 route

- **Nova is the repeated prover:** one contract contributes a state-transition
  step. The node folds through 1, 2, 8 or 32 contracts rather than running
  a single SP1 guest over the entire private batch.
- **M18** is the pinned model for Pallas/Vesta, Poseidon and UTXO map folding.
  Its chain/window result is a distinct proof requiring a binding to the same
  funding outpoints and observed Bitcoin tip.
- **M17 Shinigami** currently handles legacy/P2SH/witness-v0 script execution
  and leaves Taproot/script-path signature semantics for a separate extension.
  Treat witness-v0 proof costs as unrelated to Taproot costs.
- **BitVM3 final verification:** M12–M15 currently put the Nova verifier in an
  SP1 guest and pass its wrapped final proof through the garbled M14 verifier.
  That architecture can still use SP1 for proof shrinkage. The LNMarkets
  *application* is a Nova fold, with its own verifier key and public state,
  not a standalone SP1/Groth16 DLC application proof.

The existing 276-byte journal is a native statement. Its SHA256 is carried in
the folding state and must be pinned independently by the receiver. A final
BitVM3 composite proof must verify both the Nova output and the native
statement's missing cryptographic checks against exact shared commitments.

## Run

From the repository root:

```sh
cargo test --manifest-path LNMarkets/nova/Cargo.toml --lib
cargo run --release --manifest-path LNMarkets/nova/Cargo.toml --bin lnm-nova -- trace 2
cargo run --release --manifest-path LNMarkets/nova/Cargo.toml --bin lnm-nova -- prove 1
cargo run --release --manifest-path LNMarkets/nova/Cargo.toml --bin lnm-nova -- prove 2 --compressed
```

The native test is an R1CS conformance check. Only `prove` calls Nova's
RecursiveSNARK prover and verifier. `--compressed` additionally creates and
verifies a Spartan/IPA CompressedSNARK. All fixtures have public test keys,
synthetic outpoints and zero live Bitcoin exposure.

## Security work in sequence

1. Commit exact signed-row bytes to the field digest *inside the circuit*
   (or bind the digest to a reviewed external SHA-256/BIP340 proof) and verify
   real co-signatures and indexed oracle authorization. Compare cost against
   M17's deferred-claims approach with its trust requirements written out.
2. Move the consumed-outpoint nonmembership/update relation into the Nova step
   under the M18 Poseidon map, with a proof of exact input identity. Bridge
   any legacy SHA256 nullifier root through explicit constraints.
3. Extend the Shinigami/M17 circuit to the actual UTXORef Taproot script path,
   BIP341 sighashes, adaptor completion, CSV refund and fresh batch signatures.
4. Bind M18's funding UTXO proof to the LNMarkets state and the M16 proven
   Bitcoin chain tip. Add real signed transaction and spend-acceptance tests.
5. Prove the folded trace, compress and route its *pinned Nova verifier* through
   the established M12–M15 BitVM3 garbled verifier. Measure privacy, wire
   bytes, verifier gates, prover memory, time, and confirmation latency.

The proof cannot authorize new signatures, bypass the original DLC refund
path, or turn two off-chain promises into a Bitcoin covenant. Every external
consent and chain claim remains a separately enforced acceptance condition.

This crate is GPL-3.0-only, matching its M18 dependency; the standalone
LNMarkets statement remains MIT.
