# PNS-PIPE-01 — localized fraud authorization for Nova

Date: 2026-11-24. Research only. Based on PR #32 at
17a52602f813af62623422d2c63c67488f541169. Separate from the positive
direct Nova-to-Praxis relation in PR #32 and the Praxis primitive in PR #31.
Do not merge as a production bridge, spend funds, or claim a deployed WE.

Sources: Bitcoin PIPEs v2, https://www.allocinit.xyz/uploads/pipesv2.pdf,
sections 1.1, 4 and 6 (pp. 3, 12, 18–19); BIP340 and BIP341; the pinned
Nova verifier/Boolean compiler work in integrations/praxis-nova/bqs/.
The PIPE construction in the paper releases a signing key and fixes the
witness hash at setup. Our proposal instead conditions release of specific
signature scalars on an authenticated local fault in a committed trace.
This is a different protocol with separate security obligations.
The paper's committee and honest-challenger assumptions are not removed.

## 1. Local fraud relation

Let V be a fixed deterministic Boolean verifier with the exact proof,
statement and VK inputs bound to constants by pin rows. It has a finite
acyclic gate graph with one definition for every noninput wire. Its two
constant wires are pinned to 1 and 0; final acceptance is pinned to 1.
Every row is an ordered (a,b,z,truth-table) constraint. A pin is a constant
truth table. Every value is a bit. For the native witness/proof binding,
a committee independently checks the typed encoding, pinned proof bytes,
keys, statement, graph, public pins and output pin before activation.

The instance is (S, R_rows, R_trace, nr, nw): session, two Merkle roots and
exact counts of real rows and wires. The fixed 32-byte row record holds
three LE u64 indices, one 4-bit truth table and zero reserved bits.
Trace pages pack 256 wire bits in 32 bytes, little endian within bytes.
Leaf hashes are Keccak256(tag || S || data); interior hashes are
Keccak256((tag+1) || S || left || right), with row tag 16, trace tag 32.
Trees pad to a power of two using zero records/pages. Index ranges
exclude padding. The path position itself binds the leaf index.
S in the current fixture binds network, preassigned bond outpoint,
epoch, verifier, statement, proof, policy, and exact disprove sighash.

A fraud witness contains one row index, one row record and its Merkle
path, and three pages with their Merkle paths. The indices in the
authenticated row determine the page positions and bit selections;
there are no independent witness-supplied wire indices. The predicate
checks all four paths, exact lengths, row and wire bounds, reserved bits,
and whether z differs from the truth table at a,b. Roots, counts and S
are circuit constants. A BQS can encode the entire predicate directly
using the existing Keccak and Boolean gate compiler, no SNARK wrapper.

### Conditional theorem / proof obligation

For a fixed independently authenticated complete Boolean circuit and
complete published bit trace, under collision resistance of the
domain-separated Merkle hash:

- Completeness: if the trace violates any row, its actual authenticated
  row and wire pages witness the local fault. If no row is violated,
  induction over the acyclic netlist plus all input and output pins
  implies acceptance of the fixed typed input.
- Soundness: given an honest accepting trace, every valid path and
  bounded index authenticates its actual row/page. A local fault witness
  for that trace requires a hash collision or a false local relation.

This is a conditional argument, not a mechanized proof or WE security
theorem. An incorrect trace for a valid proof can be challenged; the
protocol enforces consistency of the asserted execution. An invalid
proof with an honestly evaluated false result violates the output pin;
forging the result violates an internal gate.

Current tests use a small complete DAG, a three-page sparse fixture,
and a registered native Nova Pasta-addition component. They do not
establish a complete Nova verifier. The existing optimized IPA BQS uses
wide sparse linear forms; an entire dense row is not one Boolean gate.
For that implementation derive a deterministic bounded fan-in micro-op
trace (including modular carry, canonicality, bitness, all coefficient
and accumulator bindings) or a fixed Boolean netlist. Authenticate
every micro-op, pin all proof inputs and acceptance, show the local-fault
theorem for the actual trace, and measure its real size. Do not treat
the optimized group's 6.75B variable estimate as a count of Boolean gates.

## 2. Results and cost

Executed JS: exhaustive 128 traces, one passing and 127 authenticated
faults; 21 negative controls (row/page substitution, wrong roots,
padding, path mutation and every context field); two official Keccak
known-answer vectors. Native Rust implements the same local relation
using the pinned PNS BQS compiler, independent sha3 Keccak, two
cross-page fixtures and an actual Nova Pasta addition kernel.
Native CI and independent exact source-count comparison are registered.
Do not claim native execution until CI passes.

Four paths use one hash each for the leaves and one per level.
Each 65-byte leaf or 97-byte node fits one Keccak rate block.
The pinned Boolean source costs 193,174 gates per such hash (no
constant folding). Source-level relation counts (CI verifies them
against the same circuit's actual gate expansion):

| real rows and trace slots | Keccak permutations | witness bytes | Boolean unknowns | BQS equations |
|---|---:|---:|---:|---:|
| 3 rows, 520 slots | 12 | 392 | 2,335,435 | 2,332,300 |
| 2^20 each | 60 | 1,928 | 11,669,227 | 11,653,804 |
| 2^33 each | 112 | 3,592 | 21,780,835 | 21,752,100 |

These are local predicate counts, not the cost of a complete trace,
WE encryption/decryption, setup verification or Bitcoin settlement.
At 2^33 slots, the packed trace alone is 1 GiB; explicit 32-byte row
records for 2^33 rows are 256 GiB before Merkle metadata. A fixed
program may be regenerated, but verification, availability and Merkle
tree building are real costs. Consider streaming trees, multiproofs,
page-size tradeoffs, constant folding and a reviewed algebraic hash.
No 7.88 GiB Praxis extrapolation or security claim: the paper's
parameters are for a different relation. In particular, even this
local Keccak relation is much larger than that reference circuit.
Derive concrete admissible QAP and rank-gap/MSIS parameters afresh.

## 3. Exact transaction signature release

Do not encrypt the unrestricted pooled funding key. The test-only
signature_shares.js uses three public deterministic secp256k1 secret
and nonce shares. Aggregate x-only key Q and nonce R are normalized
to even y; challenge e = tagged_SHA256(R_x || Q_x || BIP341 sighash)
mod n. Each share s_i = k_i + e*x_i mod n obeys s_i G = R_i + e P_i.
Summing gives an ordinary 64-byte BIP340 signature. The SIGHASH_DEFAULT
fixture commits a single input and all outputs, no annex. It passes two
official BIP340 vectors, three share equations and 14 negatives, including
missing/duplicate shares, wrong session, changed share, outpoint, prevout
value/script, recipient, output amount/fee, extra output, sequence,
locktime and version.

This demonstrates algebra and transaction binding only. The fixture
is intentionally public and variable-time; no secure DKG/MPC, MuSig2,
FROST, WE, ciphertext well-formedness proof or real Bitcoin node.
For deployment use a reviewed distributed Schnorr signing protocol,
authenticated roster, proof of possession/key aggregation, fresh one-use
nonce commitments, parity/tweak accounting, transcript binding and
secure erasure. Each participant must generate and encrypt its own
partial scalar; no coordinator may receive plaintext shares. Ciphertext
verification must bind the encrypted scalar to the public share equation
and the same independently fixed release instance. A proof of correct
encryption cannot show that the creator forgot secrets. Specify
one-honest-signer safety and n-of-n setup availability (and/or separately
reviewed threshold variant), malicious ciphertext and withholding
controls. Any correctness proof system used in this program must stay
within the Nova-only requirement. No second SNARK wrapper.

## 4. Setup and dispute timing — fail closed

Important: the current preassigned-bond-outpoint context is an isolated
algebra test; it is not a Bitcoin dispute protocol. If the challenge
window starts at a later assertion, a relative timelock measured from
an old funding output is unsafe. Use a newly confirmed assertion/dispute
output for the challenge clock, or a separately proven anchor mechanism.

The fresh-output design needs an acyclic two-stage context:
1. Establish a unique case ID, network, prior funding outpoint, epoch,
   authenticated PNS1/VK and proof, and a fixed policy including destinations,
   timeouts and allowed fees. Use these for the trace-domain digest T;
   exclude the future assertion txid and disprove sighash here.
2. Commit row/trace roots under T. Independently validate the netlist and
   proof/input bindings, and make all trace, program and proof data
   available. Build an assertion transaction committing T/roots and
   creating a fresh dispute output; compute its stable SegWit txid.
3. Derive the exact competing disprove and optimistic/reimbursement
   transactions spending that same output, the latter with the chosen
   relative delay. Freeze the final WE instance X=(T,roots,counts,
   assertion outpoint,exact disprove sighash,policy). This avoids the
   circular dependence of root -> assert txid -> sighash -> root.
   The tested fixture instead uses an already fixed outpoint and sighash.
   The final X format and signing ceremony are the next work order.
4. Produce and verify all WE ciphertexts and signature-share consistency,
   register the exact optimistic transaction and authenticated manifest,
   confirm availability and pre-sign paths as required. Only then allow
   assertion broadcast. Bind the manifest to the on-chain assertion
   without introducing circular txid dependence. A known fault before
   assertion may release disprove shares early, but only for the exact
   dispute spend. Never hand out a general funding key.
5. On assertion confirmation start the challenge clock. An honest watcher
   reconstructs the verifier trace, obtains the authenticated fault and
   decrypts the shares, checks the signature and broadcasts the exact
   disprove transaction. The optimistic spend must be invalid until its
   delay expires. Both spends conflict on the same outpoint. Account
   for decryption latency, storage loss, fees, reorgs and censorship.
   Missing data is not itself an NP witness of a false row. Fail setup
   closed on unavailable data, keep an explicit availability assumption
   during the challenge, and separately design availability remedies.

No root-reusable ciphertext is assumed. The root must exist before
encryption. Fixed destination may require watcher payment outside the
disprove transaction, and fixed signatures limit fee bumps; analyze
safe CPFP or pre-agreed fee ladders. The setup committee and challenge
period remain. This proposal does not yet establish keyless custody or
remove required backing principal.

## 5. Matched capital accounting

costs.js also simulates a deterministic 30-day cohort: 120 withdrawals/day,
100,000 sats advanced per withdrawal, batches of 24, 2.4M sats incremental
bond per batch, 10% annual opportunity rate, one-hour final confirmation,
and all lockup tails included. Custody principal is separate. Existing
route is assumed precomputed; local setup is illustratively two hours.
At identical seven-day challenge windows, the latter adds 4.57 sats
of opportunity cost per withdrawal. A hypothetical one-day challenge
would leave 324.20 sats/withdrawal for incremental costs relative to
the seven-day baseline. A shorter window is not earned by this
experiment, nor shown safe. Actual WE/setup/fees/availability costs
are unknown. No measured capital saving.

## 6. Next gated work (PNS-PIPE-02)

First obtain CI receipt, repair failures and compare native local BQS
counts. Add an independently compiled real verifier trace, initially
a small complete Nova compressed-verification fixture or a labeled
subcomponent until that full verifier exists. Extend local predicates
to the actual sparse limb/micro-op relation, with an independently
checked compiler and trace/proof pins. Benchmark streaming availability
and alternative hash costs. Then implement the acyclic assertion
context and genuine regtest funding/dispute/refund race (without
WE initially); test timing, wrong outpoint, reorg and signature reuse.
Only after reviewing concrete Praxis parameters and secure setup do
actual WE. Never use a mock gate as evidence of cryptographic release.
Compare against existing BitVM3 under matched assumptions.

Reproduce:
    node integrations/pns-pipe/trace_fraud.js
    node integrations/pns-pipe/signature_shares.js
    node integrations/pns-pipe/costs.js
    cargo run --release --manifest-path integrations/pns-pipe/Cargo.toml
