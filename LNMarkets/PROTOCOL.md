> **Prover architecture (2026-11-20):** The native co-signed batch statement here now feeds the **LNMarkets Nova step** in [nova/](nova/README.md) through the existing BitVM3-Nova machinery. The previous standalone SP1 application harness remains historical only. The first R1CS step treats co-signature digests as opaque private inputs; an end-to-end proof will require signature/merkle verification in-circuit or a verified proof composition with exact common commitments.

# Batch proposal statement v1

## Scope and trust boundary

The statement proves that the submitted, agreed set of bilateral records
authorizes a deterministic settlement proposal under a pinned application
context. Its public result is a journal. A sound proof of the reviewed guest
binds that journal to a successful execution of `verify_batch_bytes`.

The relying venue chooses the accepted-contract root from authenticated
trade records and retains that root before verifying a proposal. This step
establishes which maker identity and trader contracts the venue recognizes.
A prover can create its own keys and synthetic records, so proof validity
alone cannot establish membership in the venue's actual book.

The selected set is complete relative to the retained root and row count.
Venue-wide liabilities, price discovery, solvency and trade volume require
additional statements and independently established inputs.

The v1 domain is fixed to
`UTXORef/LNMarkets/bitcoin-regtest/lnmarkets/v1/`. Production chain IDs,
venue identities and protocol upgrades need separately specified domains,
reviewed code and newly pinned program keys.

## Private input

`LNMBAT01` introduces the canonical binary witness. Integer fields use
little-endian encoding. Hashes and fixed byte strings retain their encoded
order; funding txids use display order in the summary and reverse order in
Bitcoin transaction serialization. The parser bounds the total input and
all row/path counts, checks fixed-size fields and rejects trailing bytes.

| Part | Contents |
| --- | --- |
| Batch context | Epoch, batch ID, evaluation height, expiry height, accepted-contract root, old/new authorization roots, exact unsigned transaction SHA-256 and row count |
| DLC summary | 32-byte salt, contract ID, plan/recovery digests, funding outpoint/value/script, trader/maker keys, payout/anchor scripts, three sorted oracle keys, event ID, payout root/count, maturity, refund height and CSV |
| Summary signatures | Trader and maker BIP340 signatures over the domain-separated summary digest |
| Selected outcome | Canonical index, 32-byte outcome message, trader/maker/anchor payouts and fee, plus its Merkle path |
| Oracle evidence | Two distinct sorted oracle indices and BIP340 signatures over the event, maturity, outcome count, selected index and message |
| Batch consent | Trader and maker signatures over the entire batch context and this summary digest |
| Nullifier evidence | Exactly 256 sibling hashes for the row's nonmembership/update against the current intermediate root |

`plan_digest` and `recovery_digest` bind the new signatures to retained
package references. The guest does not open those packages. Each wallet
must validate the complete original DLC and its retained pins before
signing a summary. That workflow includes the payout table, adaptor
signatures, oracle announcement, fully signed refund and exact funded
outpoint. Importing a digest into this format adds no validation of its
preimage.

Fixture salts are deterministic. A real exporter must obtain fresh random
32-byte salts and protect the witness. A nonzero check inside a circuit
establishes no entropy guarantee.

## Cryptographic checks

Application commitments use SHA-256 tagged hashing. Tags include the fixed
protocol domain and a purpose label. The code uses `k256` BIP340
`verify_raw` on each 32-byte message digest. The generic message-verification
trait would apply another hash and define a different signing protocol.

Each row requires six signatures: two on the summary, two oracle
attestations and two fresh batch consents. Parties have distinct valid
x-only curve keys. Oracle keys are distinct and sorted. The payout root
commits to indexed leaves containing the contract ID, event, outcome count,
message and exact amounts. Path length derives from the signed outcome
count; indices outside the real table are rejected even when the Merkle
tree uses padding.

The oracle signs the table size and index as well as the outcome message. This prevents
moving a signature to another indexed leaf that happens to reuse the same
message. The application attestation envelope is new. Adopting it requires
oracle integration or a separately verified translation from the original
DLC oracle evidence. The guest verifies the selected branch and signatures;
economic correctness of the full table and truth of the observed price
remain wallet/oracle responsibilities.

The funding script uses UTXORef's public NUMS construction, sorted party
keys, a two-key CET script and a CSV refund script. TapLeaf, TapBranch and
TapTweak follow BIP341, including rejection of a tweak outside the scalar
field and the point at infinity. Deriving the output establishes that its
bytes match the template. A chain observer still has to establish that the
claimed funding outpoint exists with that value and remains spendable.

## Exact transaction proposal

Rows appear in strictly increasing `(display_txid, vout)` order. A duplicate
outpoint or contract ID is rejected. For every row:

```
trader_sats + maker_sats + anchor_sats + fee_sats = collateral_sats
```

Arithmetic uses checked integers bounded by Bitcoin's money range. This
first model requires positive, non-dust P2TR payouts and anchors, with a
bounded positive fee. Zero-payout/liquidation cases require a future format
revision; they are outside v1's supported fixture family.

The exact unsigned transaction uses version 2, empty input scriptSigs,
sequence `0xfffffffd` for every input and the maximum row maturity as
`nLockTime`. Identical payout scripts aggregate across rows and outputs are
ordered by their complete script bytes. All input references and outputs
are serialized before hashing. The journal contains both SHA-256 of those
bytes and the display-order Bitcoin txid obtained from double SHA-256.

Batch signatures bind the complete context, including the agreed accepted
set, exact transaction, state transition and validity window. These are
application signatures. Existing DLC CET signatures have their own BIP341
transaction binding; the actual combined transaction needs fresh Bitcoin
signatures for its inputs. There is no signature substitution or proof
opcode in the current Taproot leaves.

An expiry limits application acceptance when the venue compares it with
its trusted chain view. Bitcoin `nLockTime` supplies a lower bound. It does
not enforce this application's expiry, and a fully signed transaction may
remain valid later. Wallets must account for this when releasing real
Bitcoin witnesses.

## Consumed-authorization tree

The nullifier key is the domain-separated hash of the funding txid and
vout. Salts, contract IDs and epochs never enter that key. Changing those
fields cannot make the same outpoint fresh under the same trusted state.

The tree is a full 256-level binary sparse Merkle tree. Empty and used
leaves have separate hash tags; a used leaf commits its key. Key bits are
read most-significant first from root to leaf. Siblings are supplied from
leaf to root. For every row the verifier reconstructs the current root
using an empty leaf, then reconstructs the next root using the used leaf.
The next row continues from that root. The final root must equal the
co-signed `new_nullifier_root`.

This tree records consumed batch authorizations. Bitcoin UTXO status comes
from a separate chain observer. An accepted proof can precede signing or
broadcast, and either can fail. Version 1 leaves an accepted outpoint
consumed for future batches; its original unilateral recovery remains
available. A production venue needs durable reservations and an explicit
abort/cancellation protocol before retrying such a contract in a later
batch. Quietly resetting the root would reopen accepted authorizations.

## Public journal

The journal is exactly 276 bytes. `codec.rs` is the canonical encoder.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | `LNMJNL01` |
| 8 | 32 | Statement domain digest |
| 40 | 8 | Epoch |
| 48 | 32 | Batch ID |
| 80 | 4 | Evaluation height |
| 84 | 4 | Valid-until height |
| 88 | 4 | Row count |
| 92 | 32 | Accepted-contract root |
| 124 | 32 | Old nullifier root |
| 156 | 32 | New nullifier root |
| 188 | 32 | Unsigned transaction SHA-256 |
| 220 | 32 | Bitcoin txid in display order |
| 252 | 8 | Total collateral in sats |
| 260 | 8 | Total payouts including anchors in sats |
| 268 | 8 | Total committed fees in sats |

The selected-set root covers every supplied summary in canonical order.
External proof verification must preserve the exact journal bytes. A JSON
report, native hash receipt, guest execution result or successful parser
call supplies no cryptographic proof of execution.

## Receiver procedure

1. Authenticate and retain the selected batch manifest, wallet identities,
   expected epoch, old authorization root, transaction commitment and
   height window through the venue's existing acceptance process.
2. Obtain the funding and current-chain view independently. Check the
   chosen evaluation height and that acceptance occurs within the signed
   window. Record the chain identity and observation policy externally.
3. Verify the proof against the reviewed guest's verification key and
   chosen proof mode. The local host also checks the supplied ELF digest
   and expected journal digest, then compares the exact public bytes.
4. Call `verify_expected_journal` using retained `JournalPins`. They must
   come from the acceptance process. Copying fresh pins from a submitted
   proof would let its author choose the accepted context.
5. In one durable transaction, compare the expected epoch and old root
   with current state, record the accepted batch and advance to the new
   root. Enforce an idempotency key. Two valid competing proofs for one old
   root must never both advance that state.
6. Request the separate Bitcoin signatures and validate the assembled
   transaction through Bitcoin Core. Track broadcast, confirmations,
   failed signing and reorgs in distinct states. Retain per-contract
   recovery until the settlement is confirmed under the agreed policy.

The prototype provides the relation and verifier host, with synthetic
inputs for reproduction. It does not implement this venue database,
identity service, signer service or chain observer.

## Future composition

A Taproot execution proof must bind the same exact transaction bytes,
prevout amounts/scripts and spend witnesses used by the application
statement. A funding/chain proof must establish the corresponding outpoints
against an externally accepted chain commitment. A recursive composition
would verify both pinned verifiers and equality of those commitments.

The existing M17 Shinigami-style Nova relation leaves Taproot outside its
scope. The older UTXORef virtual-CET corpus has recorded proofs for its
limited arithmetic predicate. Its linear digest mixing and auxiliary
signature flags supply no substitute for the BIP340 and SHA-256 membership
checks implemented here. Source links and the precise evidence boundary
appear in [SOURCES.md](SOURCES.md).
