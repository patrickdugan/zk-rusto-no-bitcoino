# PNS-PIPE-02 — sparse arithmetic fraud and fresh assertion

2026-11-24. Nova-only research. No real witness encryption, complete Nova trace,
secure signing ceremony, or proof-conditioned settlement. Parent PNS-PIPE-01
remains the Boolean/Keccak control. Its initial CI run 45410840138 was cancelled
during branch updates; do not report a native Rust pass until the current run
finishes.

## 1. Exact sparse-row normalization

The actual optimized Nova verifier emits BQS rows of the form
sum A_i(w) B_i(w) = C(w) over BN254 Fr, with Boolean unknowns w and w0=1.
The old one-Boolean-gate predicate cannot directly check such a row.
micro_fraud.js deterministically expands the rows into a bounded-fan-in
field-operation program, keeping one global slot namespace. Every original
slot is required to be a bit, constants w0=1 and w1=0 are pinned, and
independently selected proof/public input bits are separately pinned.

Four opcodes, with 64-byte fixed records (one-hot opcode byte, seven reserved
zero bytes, LE u64 a,b,z, canonical LE 32-byte Fr coefficient c):
BIT: z*z-z=0; PIN: z-c=0; MAC: z-a-c*b=0; MUL: z-a*b=0.
All residuals are in Fr. Use only verifier-owned coefficients and indices.
Each source linear form is accumulated from w1=0 by MAC; compute each product
with MUL; sum products, subtract C and PIN the result to zero. Every derived
output has exactly one definition and refers to earlier slots. Original
auxiliary witness bits may vary, but a fixed source program and input pins
determine the derived operation sequence. The full compiler and pins must be
authenticated before assertion activation. Prove source row/operation equivalence
by induction: all operation checks pass iff the source Boolean assignment
satisfies its original rows and pins and the derived field values equal the
accumulators. An unsatisfied row in a correctly computed trace yields a
nonzero final PIN residual. Altering a derived value to hide that residual
must break a defining operation. This is an exact algebraic argument and
fixture regression, not a mechanized compiler correctness proof.

## 2. Algebraic Merkle relation

Pinned circomlibjs numerical constants, commit
48b3ab37013c5ed21e9ff8a80a5b010795c97094, poseidon_constants.json blob
d15d818dd7b260243d240f3f794f69f5d77ed562. Source:
https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/poseidon_reference.js
and upstream test/poseidon.js. t=3 (8 full, 57 partial) and t=5
(8 full, 60 partial), exponent 5, BN254 Fr. This research mode uses the
session-dependent initial state Keccak256(domain || session || tag) reduced
modulo Fr. Tags 40/41 for row leaf/node and 42/43 for trace leaf/node.
Row leaves hash four exact 128-bit LE chunks with t=5, trace leaves hash
a canonical Fr value and zero with t=3, nodes hash two ordered field
children with t=3. Pad each tree with zero records/values, reject padded
indices. The semantic trace is a vector of field elements; independently
reject noncanonical serialized field words when registering data.
An auxiliary 254-bit representation of an internal field value may have
a different integer representative modulo Fr: this does not change the
field hash or the predicate. Canonical coefficients and byte-exact row
records are separately enforced. No unchecked quotient or host accept bit.

The BQS relation opens a row and three operand values at the row's own
indices. It checks range, Merkle paths, reserved bits, one-hot opcode and
canonical coefficient. It computes all four residuals, selects by opcode,
and enforces r*inv=1 with a Boolean-encoded field inverse. Thus an honest
zero residual cannot satisfy the local fraud predicate. The hash circuit
uses exact Fr multiplication rows (each S-box x^5 = three products) and
linear MDS maps, materializing every eighth round to bound coefficient
density. The arithmetic rows are checked during trace generation.
Standalone hash tests agree with three pinned upstream known-answer vectors.
The full independently exported relation replay and formal soundness audit
are next gates. In particular, audit collision resistance and domain
separation of this custom tree construction with the pinned permutation;
one field digest has roughly 127-bit generic birthday collision resistance,
which is not a concrete Praxis security estimate.

Executed receipts (results/micro-fraud.json):
- t=3 hash: 67,818 incremental Boolean unknowns, 268 rows including one
  final test pin; t=5: 86,360 unknowns, 341 rows including test pin.
- 16-op/11-slot committed fixture, 20 hash permutations: 1,386,157
  unknowns, 5,454 equations, 4,938 quadratic rows, Fmax=4, about 9.59M
  linear-form terms, max 5,844 terms in one row. Honest zero residual
  rejected solely at the inverse equation; fault accepted; same size.
  Seven native path/context/honest controls rejected. This does not test
  all seven mutations at the BQS level.
- Both actual Pallas/Vesta standalone sparse multiplication fixtures:
  49 source rows, 2,625 slots including constants, 12,481 micro-ops and
  12,430 field trace slots (397,760 trace bytes, 798,784 program bytes).
  All honest micro-ops pass. Changing one original bit leaves the program
  identical and violates two rows. Merkle construction for the full
  multiplication fixture is not yet benchmarked; the authenticated
  BQS test is the small 16-op fixture.

Important: the micro-op lowering can expand the trace considerably.
The former 6.75B variable estimate is for incomplete Nova group BQS, not
a micro-op count. Do not treat the numbers as equivalent. Stream actual
trace and program construction, consider mixed packed-bit/field leaves,
block linear accumulations and multiproofs, measure actual trace/DA costs
and coefficient density. Compare matched hash schedules and relation
shape; do not extrapolate a Praxis ciphertext size from the hash counts.

## 3. Acyclic fresh assertion

fresh_assertion.py defines a separate v2 SHA256 context:
T = H(domain || genesis || prior funding txid/vout || case ID || epoch ||
verifier || statement || proof || policy).
A = H(anchor domain || T || row root || trace root || exact counts).
The assertion transaction commits A in an OP_RETURN and creates a fresh
dispute output. A SegWit txid excludes the witness, so its outpoint can be
fixed before signing the competing spends.
X = H(release domain || T || A || assertion txid/vout ||
disprove BIP341 sighash || optimistic BIP341 sighash || height delay).
No future outpoint or sighash feeds T or A. For the algebraic tree encode
roots canonically as 32-byte LE Fr values. The test uses dummy roots;
connecting actual micro-op roots to the native assertion is still a gate.
Freeze the exact public WE relation and X, authenticate all ciphertexts,
their signature-share consistency, data availability and the approved
transactions in a signed off-chain manifest. Ciphertexts depend on X
and cannot be included in the assertion txid's own commitment without a
cycle. Independently authenticate the manifest and prevent the assertion
funding spend from being broadcast until the setup is approved (e.g.
at least one honest required funding signer checks every gate).
Only start the dispute clock on confirmation of the fresh output.

Local Python compile and context self-test executed: 9 trace-domain,
5 anchor/txid and 7 release-ID substitutions rejected; the frozen
anchor and txid remain unchanged by future release fields. CI compares
the JSON receipt. Native Bitcoin Core binaries absent in the current
environment, so --regtest was not executed. It uses a new isolated
datadir, wallet test keys, dummy trace roots and no network peers.
The test pre-signs both exact spends, verifies the fresh output is not
eligible for the six-block delayed path, demonstrates that an older
funding output already meets the delay, exercises the earliest mempool
height and competing spends, and explicitly tests the retained-key
bypass. The script is a transaction plumbing test. A Taproot key-path
output still permits a signer retaining its key to authorize another
transaction. Actual design must enforce the appropriate script/CSV
branch and/or analyzed one-honest-signer preauthorization/erasure.
Review reorg, fee/CPFP and availability failure paths. No mainnet.

## 4. Continuation

Read CLAUDE_PIPE03.md. Preserve PR #32's positive direct verifier route.
No extra proof system or trusted acceptance bit. Require a complete
independently pinned verifier trace, independently replayable local BQS,
a genuine secure signature release design, and fresh Praxis concrete
parameter analysis. Hold full-size ciphertext generation until those
gates pass. No claim of shorter safe challenge windows or capital savings.

Reproduce:
    node integrations/pns-pipe/micro_fraud.js
    python3 integrations/pns-pipe/fresh_assertion.py
    # Only with trusted bitcoind/bitcoin-cli already installed:
    python3 integrations/pns-pipe/fresh_assertion.py --regtest


## 7. Script-enforced delay preflight (PNS-PIPE-02B)

The earlier fresh assertion regtest harness uses wallet-owned key-path
outputs. A delayed presigned child by itself is not a consensus-enforced
restriction on other spends authorized by a retained key. The new
taproot_csv.js fixture instead constructs a two-leaf BIP341 Taproot output
using the published NUMS internal point (SHA256 of the uncompressed
secp256k1 generator, lifted to the even-y point). Its unknown discrete log
is an assumption. The leaves are:

    <fault x-only pubkey> CHECKSIG
    6 CHECKSEQUENCEVERIFY DROP <optimistic x-only pubkey> CHECKSIG

The delay is a six-block test parameter only, not a safe production window.
BIP341 leaf/branch hashes, tweak, parity and control paths match a
published wallet test vector. The BIP340 signing routine matches official
vector 0. Script-path SIGHASH_DEFAULT uses BIP342 ext_flag=1, no annex,
one input, key_version=0 and codesep_pos=0xffffffff. Both leaf signatures
commit to exact transaction fields. Sixteen negative checks executed:
candidate height below maturity, reconfirmation resets clock, re-signing
with the retained optimistic key under zero/short/disabled/time-type
sequence or version 1, wrong control blocks/leaf/parity, key-path vs
script-path digest, altered recipient, amount/fee or outpoint. The
restricted offline model accepts at candidate height assertion+6.
This is a semantic fixture for the two scripts, not a full interpreter or
consensus test. It uses publicly known TEST secrets, no actual UTXO and
no secure DKG, FROST or WE.

Explicit counterexamples: a retained fault key can authorize arbitrary
fault-branch spends immediately; a retained optimistic key can redirect
after CSV. The NUMS internal key and CSV do not provide a covenant, and
cannot establish signature erasure or proof-conditioned release. The
fault branch must be controlled by a properly reviewed multi-party setup
with the necessary honest-party assumption. The optimistic branch needs
a similarly justified exact-transaction preauthorization if arbitrary
post-delay spending is unacceptable. No funds.

Source: BIP341 https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki,
BIP342 https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki,
BIP341 wallet test vectors https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
(blob 11261b00ba24afb90b62109505d9ca5ddd773b3b).
Run node integrations/pns-pipe/taproot_csv.js; expected receipt:
results/taproot-csv.json. The current container has neither bitcoind nor
bitcoin-cli; official download was blocked by DNS. The existing regtest
harness remains unexecuted. Next: fund this script path only on an isolated
regtest node, serialize actual script-path spends, use testmempoolaccept
and block confirmation at earliest eligible height, reorg and competing
spend tests, independently verify BIP342 sighash, demonstrate retained-key
counterexamples, and bind actual trace roots and X to the real outputs.
CI replays offline fixtures; no native node claim.
