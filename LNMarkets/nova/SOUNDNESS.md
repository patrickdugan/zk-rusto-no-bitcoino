# Nova v2 statement and review record

This record describes `lnmarkets/sha256-transcript-accounting/v2`. The Pallas
batch circuit and the separate Secq BIP340 experiment prove different claims.
Their proofs have not been composed into a DLC authorization proof.

## Pallas relation

The receiver supplies an independently retained initial state, final state and
step count. It checks the exact 276-byte journal, reconstructs the initial
Poseidon commitment and verifies that the final accounting agrees with that
journal. An accepted batch contains 1–32 steps.

Each step establishes these relations:

- The count advances by exactly one. The input count fits five bits, which
  prevents a step after the thirty-second row.
- Each row amount fits 51 bits. Trader, maker and anchor amounts sum to the
  payout; payout plus fee equals collateral. Input and output cumulative
  amounts fit 56 bits.
- The SHA-256 result comes from a fixed 600-byte transcript. The 46-byte prefix
  is a circuit constant. Nova's existing SHA gadget supplies the standard IV,
  padding and length encoding, so the prover supplies only the payload bits.
- Transcript bytes and the existing accounting allocations have exact integer
  equality. The funding txid halves are 128-bit values; the vout and selected
  outcome index are 32-bit values. The same allocations enter Poseidon.
- The Poseidon domain is constrained to its literal value. The previous
  commitment, signed-row digest, outpoint, selected outcome and all amounts
  determine the next commitment.
- Journal hash halves and epoch carry through unchanged, with 128-bit and
  64-bit bounds respectively.

The 51-bit bound permits values above Bitcoin's MAX_MONEY. The native verifier
applies that tighter monetary rule. A valid proof of this circuit alone does
not add that rule or authenticate a journal hash supplied by the prover.

## Signed transcript layout

All offsets are byte offsets in the 600-byte encoding. Numeric fields are
little-endian. Each SHA output half is interpreted as a little-endian 128-bit
integer when converted to a Pallas field element.

| Bytes | Value | Circuit treatment |
| --- | --- | --- |
| 0–45 | `UTXORef/LNMarkets/Nova/validated-signed-row/v1` | Literal constant |
| 46–77 | Summary digest | Committed message digest |
| 78–109 | Batch consent digest | Committed message digest |
| 110–237 | Two summary signatures | Committed bytes |
| 238–365 | Two batch consent signatures | Committed bytes |
| 366–430 | First oracle index and signature | Committed bytes |
| 431–495 | Second oracle index and signature | Committed bytes |
| 496–499 | Selected outcome index | Equal to the Poseidon input |
| 500–531 | Outcome message | Committed bytes |
| 532–563 | Trader, maker, anchor and fee amounts | Equal to the accounting inputs |
| 564–595 | Funding txid in display order | Equal to the Poseidon outpoint |
| 596–599 | Funding vout | Equal to the Poseidon outpoint |

The hash now proves knowledge of this transcript. Signature bytes with a valid
hash can still contain invalid signatures. The summary and consent digests
also remain opaque message commitments in this circuit. Proving authorization
requires deriving those messages from the committed summary and context,
selecting the proper signer keys, and proving all signature equations.

## Problems found in the earlier fold

The first circuit at `c7d24a3a55fe06a63f4ad5d2cfea915434954816` allocated the
count increment and domain as witnesses without constraining them to their
intended constants. It also allocated fresh copies of the economic values for
the Poseidon input. An adversarial assignment could separate the values hashed
from the values conserved in the accounting equations.

The v2 circuit uses a literal `+1` coefficient, constrains the domain and
reuses the same allocated economic variables in both places. It also adds
explicit encoding and cumulative-state bounds. These changes alter the
circuit shape and verifier key. The earlier 10,816-byte proof measurements
remain historical performance observations of a superseded relation; they
cannot establish the security or cost of v2.

`tests/soundness.rs` records R1CS assignments and substitutes forged internal
values into the original constraints. The cases include recomputing an entire
Poseidon witness under another domain or payout, replacing SHA intermediates
while retaining a stale digest, and changing count and encoding assignments.
This reaches the constraints directly instead of relying on Rust input types
or the honest witness builder to reject the attack.

## Proof files and verifier identity

`prepare` creates receiver expectations from a natively verified witness and
the current circuit. `prove --compressed --out` saves a compressed proof,
journal, manifest and public measurement report. The private batch and the
recursive proof state stay out of that bundle.

The expected statement pins the exact initial/final states, row count, journal
hash, relation version and verifier-key identity. The proof's own hash appears
in the manifest to catch file corruption; it does not establish statement
authority. Copying a prover's expectations into a trusted location does not
make them independently accepted expectations.

The receiver reconstructs public parameters and the compressed verifier key
from its compiled circuit. It hashes the deterministic bincode serialization
through a bounded writer and compares that identity with the retained pin.
The full Spartan verifier key contains R1CS matrices, so exporting it would
add substantial data to a small proof. It is rebuilt locally instead.

JSON rejects unknown fields and noncanonical field encodings. Files have
explicit byte limits, new outputs preserve existing paths, and binary proof
decoding rejects trailing bytes. Nova 0.76 contains verifier paths that panic
on malformed internal vector lengths. The local entry point catches an
unwind from decoding or verification and returns an error. The persisted
artifact regression modifies a real proof to exercise those paths. This
protects the local Result boundary; resource exhaustion and an aborting
runtime require process-level isolation for any public verifier service.

## Separate BIP340 experiment

`bip340.rs` uses Nova's existing secp256k1 ECC gadgets over the Secq scalar
field. It verifies one signature over a 32-byte message, constrains canonical
encodings and point parity, and commits to the exact key, message and signature
bytes with SHA-256. Its three-field state permits exactly one step.

This experiment demonstrates a reusable signature relation. The claimant
supplies the public key. Proving that the key is an authorized DLC party or
oracle needs a further relation that opens the summary, derives each message
and connects the signature proof to the Pallas batch's exact ordered rows.
Pallas and Secq Poseidon commitments are distinct field objects. Any composite
verifier must prove equality through common byte commitments or a constrained
bridge, with separate pinned verifier identities.

## Remaining application claims

The Pallas batch does not verify outcome membership, nullifier paths, accepted
book membership, exact Bitcoin transaction construction, original DLC adaptor
completion, Taproot spending or a funding UTXO's chain status. The existing
native verifier checks several of these application conditions, while Bitcoin
spendability and funding require their own evidence. M17 Taproot support and
the M12–M15 application verifier remain future work.
