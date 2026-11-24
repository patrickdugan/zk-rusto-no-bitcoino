# PRAXIS-01 — witness-encryption feasibility for Bitcoin

Status: research preflight, no funds, no real witness encryption. Source:
Tse, Vanjani and Vesely, [Praxis: Practical Witness Encryption for NP](https://eprint.iacr.org/2026/2971), ePrint 2026/2971 (approved 2026-11-23).
The abstract was retrieved; the full paper and Lean artifacts were unavailable at registration.
Treat the claimed extraction theorem, concrete parameter selection and implementation as unaudited.

## Existing integration

At main commit ddc0164c8a2a17f5cc346713ab9ed2083760db8d, ../groth16-gym exports
proof.bin, vk.bin, public_inputs.bin via `cargo run --release -- spv --out /tmp/praxis-fixture`.
It uses arkworks 0.5, compressed BN254 objects; fixture proof 128 bytes, VK 488 bytes.
Its benchmark SPV relation proves transaction inclusion in a supplied header and a fixed-layout
output's value and script hash. It does not establish canonical chain selection, sufficient
confirmations, or a settlement policy. Its seeded setup has known toxic waste.
M16 in ../bitvm3-nova provides the candidate recursive header/SPV route; M18 adds windowed
UTXO commitments. The existing BLAKE3/garbled verifier stays unchanged.

This crate verifies the gym's exported proof against externally pinned SHA-256 hashes
of the exact VK and public-input bytes. Strict bounded canonical decoding and proof
verification are an interface preflight only. It contains no encrypted secret, no
decryption oracle, and no claimed witness encryption.

## Settlement relation

Let a canonical fixed-width context C bind version, network genesis, funding outpoint,
contract ID, epoch, predecessor state root, target state root, authenticated chain checkpoint,
withdrawal/nullifier, payout script hash, amount, fee policy, exact BIP341 sighash (or other
explicit signature digest), and verifier/program version. Specify each width, byte order,
domain tag and circuit-to-field mapping before use. A SHA256 digest of C can be exposed as
two 128-bit limbs; the circuit must enforce the digest of the actual checked transition.
Use independently pinned VK and public inputs x. A valid Groth16 proof pi for (VK,x) is
the witness to the Praxis predicate. An off-chain manifest or AEAD associated data alone
cannot make an unrelated proof authorize a particular withdrawal.

R(C,w) must enforce source consensus/finality assumptions, authenticated state roots,
conservation of collateral, recipient and payout binding, nullifier and epoch rules,
and exact destination authorization. For an SPV-only fixture, intentionally mark these
features absent. An existential statement permitting an old or irrelevant payment is unsafe.
If the wrapper's public inputs commit to an SP1 journal, constrain the journal, program
identity, chain checkpoint and all fields above inside the wrapped proof.

## Candidate release protocol (future, regtest only)

1. Freeze an exact SIGHASH_ALL/DEFAULT transaction template (including inputs, prevouts,
   amounts, recipients, change, locktime and sequence). Specify a compatible CPFP plan and
   a competing timelocked refund or dispute path; document its race semantics.
2. In a controlled test ceremony, produce a signature for that transaction. Encrypt only
   a fresh symmetric key to (VK,x) with actual Praxis; AEAD-encrypt the signature with
   domain-separated authenticated context. A proof holder can recover the signature and
   broadcast the committed transaction. Verify Bitcoin consensus acceptance independently.
3. Before funding, publish and validate the ciphertext availability commitment and
   demonstrate correctness of the encryption by a method justified by the construction.
   A hash commits to bytes, not their correctness. Malformed encryption can strand funds.
4. Model retained signing keys, retained plaintext signatures, corrupt encryptors,
   compromised Groth16 setup, withheld ciphertext, proof withholding, reorgs, early proof
   publication, competing exits and fee starvation. A single encryptor knows the message;
   secure erasure is an extra trust assumption. Threshold signing alone does not solve
   signature retention by a combiner. Investigate MPC that emits only encrypted
   authorization and prove composition, or keep explicit signer trust. Do not claim
   operator-free or keyless security without resolving this.

Any authorized proof holder can decrypt: privacy, exclusive withdrawal rights and
anti-front-running must come from the transaction and underlying relation. Never encrypt
a reusable spending key. A plaintext signature remains usable after its proof is stale
until the outpoint is spent or Bitcoin script/transaction rules invalidate it.
No broadcast to mainnet; no customer collateral.

## Work orders and stop gates

| ID | Work | Gate |
| --- | --- | --- |
| 01A | Verify canonical exported BN254 artifacts | Positive fixture; reject wrong input, wrong key hash, wrong proof, trailing bytes, oversize |
| 01B | Retrieve exact paper revision and Lean source; review construction | Pin SHA256, algorithms, extraction assumptions, parameter estimator and test vectors; no implementation from abstract alone |
| 01C | Implement scalar reference encryption/decryption | Known-answer vectors, valid and invalid witnesses, malformed ciphertext, independently reviewed parameters |
| 01D | Stream ciphertext and benchmark Fq/Fq2/pairing and search kernels | Separate operation counts, wall time, peak RSS/VRAM, disk read/write, throughput and failure probability; compare CPU and GPU |
| 01E | Regtest single payout plus competing refund | Exact proof and transaction binding; wrong epoch/network/recipient/amount rejected; Bitcoin Core accepts authorized spend |
| 01F | Recursive wrapper and batch economics | M16/M18 public-journal binding; reorg, withholding and retained-signature threat analysis; compare existing BitVM3 path |

At 100-bit paper parameters: 7.88 GiB ciphertext, 2^34.2 Fq multiplications to
encrypt, expected 2^33 to decrypt. At fixed statement size, search scaling is
2^((lambda-100)/4). Do not extrapolate total encryption or ciphertext size
without the parameter table; do not assume BN254 can achieve 128-bit security.
The quoted figures are paper claims, not measurements on our devices. Prefer
streaming from NVMe with bounded host/VRAM buffers; instrument bandwidth and
arithmetic separately. Compare marginal cost per settlement with direct BitVM3,
and distinguish circuit reuse from ciphertext reuse (a ciphertext is statement-specific
unless a stronger construction proves otherwise).

## Run

```sh
cargo test --manifest-path integrations/praxis-we/Cargo.toml
python3 integrations/praxis-we/budget.py
cd integrations/groth16-gym
cargo run --release -- spv --out /tmp/praxis-fixture
```

Pin the expected artifact digests from an authenticated independent registration;
for a local fixture only, derive them with sha256sum. A digest supplied by the
same untrusted party as its bytes is not an authorization policy.

```sh
cargo run --release --manifest-path ../praxis-we/Cargo.toml -- \
  /tmp/praxis-fixture EXPECTED_VK_SHA256 EXPECTED_INPUTS_SHA256
```

The fixture checks are intentionally not a deployment security claim. Real
Praxis encryption/decryption remains blocked at 01B.
