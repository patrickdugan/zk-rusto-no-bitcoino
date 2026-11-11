# M18: a windowed UTXO map folded in Nova, and balance proofs against it

M16 proves that a payment exists: an output was created in a block with k confirmations on the
proven mainnet chain. It cannot prove that the output is still unspent, because Bitcoin headers
commit to each block's transactions, not to the UTXO set. A balance (the sum of a script's
unspent outputs) needs both.

M18 folds, in Nova, an assume-valid pass over the blocks of a window H..T:
- re-hash every transaction (no witness) and rebuild each block's Merkle root;
- check that root against the block's header, and link the headers H..T;
- keep a map of every output created in the window, marking an output spent when a later input
  spends it.

It does not check scripts, signatures, amounts or any other consensus rule ("assume-valid"): the
headers are proven-work headers, and validity is inherited from the chain's acceptance, as in
Core's assumevalid. A balance proof is a set of map entries, created in H..T and unspent at T,
checked against the folded map's root. T is tied to the NHC1 header-chain proof by its hash.

## Why a window, and the cost

Re-hashing the block bodies with SHA-256 is the dominant cost and cannot be avoided: it is what
binds the transactions to the proven headers.
- The NHC1 header fold (`btc-header-fold`, the circuit behind the mainnet chain proof) measured
  82,809 R1CS constraints per header: three SHA-256 compressions plus checks. One compression
  alone measures 25,840 constraints (Nova 0.76 frontend gadget, constant IV).
- Mainnet blocks 975,067..975,072 carry 810,812 bytes of non-witness transaction data on average
  (1.56 MB raw), 15,357 compressions for the transaction bodies, so 3.97 × 10^8 constraints of
  SHA-256 per block before the txid finish, the Merkle merges, parsing and map updates.

A fold from genesis would take years, so the map covers a window, and a balance covers outputs
created inside it. The per-step and per-block figures are in Status.

## The map

An indexed Merkle tree (a sorted linked list in a fixed-depth Merkle tree, as used for nullifier
sets), depth D = 20 (1,048,576 leaves, about 80 mainnet blocks of outputs), over the scalar field
of Pallas, hashed with Poseidon:
- key `k` = the low 248 bits of `Poseidon(txid_lo, txid_hi, vout)` (txid in internal byte order as
  two 16-byte little-endian limbs). Keys are below 2^248, so an order comparison is a 249-bit
  decomposition;
- leaf `(k, next_k, next_index, value, script_fp, spent)`, hashed as a 6-input Poseidon. Leaf 0 is
  a sentinel with every field 0; `next_k = 0` marks the last leaf; an empty slot is the leaf hash 0;
- `script_fp` is a fingerprint of the output script: Horner evaluation at `r_s` of the sequence
  (script length, byte 0, byte 1, ...), starting from 0, where
  `r_s = Poseidon(1, hash(H−1)_lo, hash(H−1)_hi, hash(T)_lo, hash(T)_hi)` over the 16-byte
  little-endian limbs of the internal-order hashes. The block hashes fix every script in the
  window before `r_s` exists, so two window scripts collide with probability at most
  (length)/|F|, and so does a window script with a script fixed before `r_s` was known (a
  verifier's own address). The fingerprint is linear in the script bytes, so it does not bind a
  script picked after `r_s` is public: from about 34 free bytes on, lattice reduction finds a
  second byte string with a given fingerprint. A balance claim therefore carries the output's
  transaction (non-witness serialization); the verifier hashes it to the txid that keys the
  leaf and reads the script and value from it (`native::verify_output`), so the script is bound
  by SHA-256d, and the leaf's value and `script_fp` must agree with it.

Operations, one per event:
- **create** (an output): a non-membership proof for k (the low leaf has `key < k < next_key`),
  then the low leaf is updated and the new leaf appended;
- **spend, in window** (an input whose outpoint is in the map): a membership proof, then
  `spent = 1`; a leaf already spent cannot be spent again;
- **spend, before window** (an input spending an output created before H): a non-membership proof
  for k. Nothing changes.

A Utreexo forest supports add and delete but not proofs of absence. Absence is what makes the
window sound: a prover who called an in-window spend "before window" would keep a spent output in
the map, and the non-membership proof refuses that.

Every output is created, OP_RETURN included (an unspendable output adds its own value, zero in
practice). The coinbase input is an ordinary input event with the null outpoint; its
non-membership always holds, since no transaction has txid 0. A duplicate txid (the two BIP30
pairs before height 91,880) fails non-membership, so a window cannot cover those blocks.

## The step circuit

One uniform Nova step (plain Nova, not SuperNova), so the verification path is the one NHC1 uses.
The state has 72 elements; M12's guest A fixes the arity at 17 (`m12/native/src/bundle.rs`), so
verifying M18 inside SP1 needs guest A generalised over the arity. The Nova verifier code itself
is unchanged.

The native step machine (`src/machine.rs`, `step(&State, &StepWitness)`) is the source of truth.
The circuit (`src/circuit.rs`, `M18Step`) enforces exactly the relations `step` checks, and its
`z` is `State::to_vec`.

A step has two slots that run side by side: one SHA-256 compression (the producer) and one map
leaf update (the consumer). Per block the window needs 25,000 to 43,032 compressions and 23,231
to 36,224 leaf updates, so a block takes about max(compressions, leaf updates) steps.

### State and witness

`z` in order: producer (`phase`, `fresh`, SHA register `sha` (2), previous block hash `prev` (2),
`height`, `n`, frontier (16 × 2), `carry` (2), `mlevel`, `lastf`), parser (`ps`, `rem`, `acc`,
`vmul`, `n_in`, `n_out`, `out_idx`, `pl`, `ph`, `val`, `sfp`, `tx_len`, `lenacc`), producer
fingerprint `fp`, consumer (`root`, `leaf_count`, `fc`, `gc`, `open`, `tx` (2), `pending`,
`pend`), constants and result (`h0` (2), `r_s`, `r`, `sealed`). A verifier of the proof recomputes
z0 with `State::initial` (empty map, `leaf_count = 1`, every fingerprint and flag 0, `h0 = prev =
hash(H−1)`, and the window's `r_s`, `r`) and requires `sealed = 1` in the output.

Two forms of a 32-byte hash appear. The SHA register, the frontier and `carry` hold the halves
form: `lo` is the big-endian integer of bytes 0..16 (the SHA-256 state words, high word first), so
the register can be absorbed back as a message or chaining value. `prev`, `h0`, the `tx`
register and the txid in events hold the limb form (little-endian limbs of the internal byte
order), the form the map key hashes. The two are different weightings of the same 256 bits, so a
compression output yields both for the price of two constraints each.

The witness of a step: `idle`, the 64 message bytes `block`, `last` (at TXID), `end` (at HDR3),
the consumer's `close`, `open` (with the txid limbs), `op`, three event fields, the old leaf, the
index and the D siblings.

### Producer: one compression per step, chosen by a phase

| phase | message block | chaining value in | after |
|---|---|---|---|
| BODY | 64 witness bytes of the current transaction's padded non-witness serialization, run through the parser | IV if the transaction is fresh, else the SHA register | BODY, or TXID when the parser reaches DONE |
| TXID | SHA register (32 bytes) ‖ padding for 32 bytes | IV | add the txid to the frontier at level 0 |
| MERGE1 | frontier slot L ‖ carry | IV | MERGE2; slot L is consumed (n −= 2^L) |
| MERGE2 | padding for 64 bytes (constant) | SHA register | MERGE3 |
| MERGE3 | SHA register ‖ padding for 32 bytes | IV | add the result to the frontier at level L + 1 |
| HDR1 | header bytes 0..63 (witness) | IV | HDR2 |
| HDR2 | header bytes 64..79 ‖ padding for 80 bytes | SHA register | HDR3 |
| HDR3 | SHA register ‖ padding for 32 bytes | IV | next block's BODY, or DONE |
| DONE | ignored | ignored | DONE |

The message of a phase other than BODY, HDR1 and the first 16 bytes of HDR2 is derived from the
state, and the circuit checks the witness block against it bit by bit. Every active step sets the
SHA register to the compression output.

A witness flag `idle` makes a step leave the whole producer state unchanged (the compression runs
on ignored input); the prover uses it when a block has more leaf updates than compressions.

The Merkle tree is built as a binary counter over a frontier of 16 slots (a block has fewer than
2^16 transactions): `n` counts the leaves added in this block, slot j is occupied when bit j of n
is 1. "Add node X at level L": if bit L of n is 0, slot L := X and n += 2^L; otherwise carry := X
and the next phase is MERGE1 at level L (left = slot L, right = carry). After a node is placed:
- if the transaction just finished was not the block's last (a witness flag set at TXID, kept in
  `lastf`), go to BODY;
- if it was the last and n is a power of two, slot log2(n) is the Merkle root: copy it to the
  carry register and go to HDR1;
- otherwise duplicate: j := the lowest set bit of n, carry := slot j, go to MERGE1 at level j
  (merging slot j with itself, Bitcoin's odd-node rule).

A node placed at level 16 is refused, and so is a merge of an empty slot.

The header phases check: header bytes 4..35 equal the previous block hash (state), header bytes
36..67 equal the root (carry register; bytes 36..63 in HDR1, 64..67 in HDR2). HDR3 sets the
previous block hash to the new block hash, height += 1, n := 0 and `fresh`, and
- requires the consumer to be in step with the producer after this step's consumer work: no open
  transaction, no pending create, and `Fc = Fp`. The consumer may apply its last close and
  nothing else in this step; it cannot start the next block's events (they are not in `Fp`);
- with the witness flag `end`, seals the window: it checks
  `r_s = Poseidon(1, h0_lo, h0_hi, hash(T)_lo, hash(T)_hi)` and `r = Poseidon(2, r_s, Gc)`, sets
  `sealed = 1` and moves to DONE.

A consumer of the proof requires `sealed = 1`. After the seal a step changes nothing: the
consumer's `close`, `open` and ops must be empty once `sealed = 1`, and the producer is in DONE.
(Without this rule a prover could keep folding after the seal and move the root the proof
reports.)

A 64-byte transaction is refused (the parser checks the length): its txid would equal an inner
Merkle node, letting a prover collapse a subtree into one fake transaction and hide its spends.
The duplicated-last-transaction mutation (CVE-2012-2459) gives the same root, but a repeated
transaction re-creates its outputs and fails non-membership.

### The parser

A state machine over the bytes of BODY steps, carried between steps. States (21): VER (4 bytes),
INCNT_FIRST, INCNT_REST, PTXLO (16), PTXHI (16), PVOUT (4), SSLEN_FIRST, SSLEN_REST, SS,
SEQ (4), OUTCNT_FIRST, OUTCNT_REST, VALUE (8), SPKLEN_FIRST, SPKLEN_REST, SPK, LOCK (4), PAD80,
PADZ, LEN, DONE. Registers: `rem` (bytes left in the field), `acc` and `vmul` (little-endian
accumulation: `acc += byte · vmul`, `vmul *= 256`), `n_in` and `n_out` (inputs and outputs left),
`out_idx`, `pl` and `ph` (the outpoint's txid limbs), `val`, `sfp`, `tx_len`, `lenacc`. A fresh
parser starts in VER with `rem = 4`. In a step that is not an active BODY step the parser sits
in a sink state that has no transitions, so it neither moves nor refuses.
- Compact sizes: a first byte below 0xfd is the value; 0xfd and 0xfe read 2 and 4 more bytes;
  0xff is refused. Input and output counts of 0 are refused. A byte after DONE is refused.
- At the last PVOUT byte the input event (1, pl, ph, pv) is complete, `pv` being the accumulated
  4 bytes. At the last SPK byte, or at the end of SPKLEN when the script is empty, the output
  event (2, out_idx, val, sfp) is complete; `sfp` starts at the script length and absorbs each
  script byte (`sfp·r_s + b`). Each SEQ end decrements `n_in`; each completed output
  decrements `n_out` and increments `out_idx`.
- After LOCK: PAD80 (the byte must be 0x80, and `rem := 8`), then PADZ (zero bytes). At block
  position 56 a PADZ state switches to LEN, which reads the 8-byte big-endian bit length at
  positions 56..63 and checks it equals 8·tx_len; then DONE. `tx_len` = 64 is refused. `tx_len`
  counts the bytes of VER..LOCK.

The parser reads bytes; it does not require canonical compact sizes. A block with a non-canonical
size is not a valid block, so the chain's proven work excludes it.

### Events: two fingerprints and a hash chain

Both sides fold the same sequence of field elements, four per event, by Horner's rule at a
challenge `r` (`F := ((((F·r + x1)·r + x2)·r + x3)·r + x4`, from 0). Per transaction: each input as
(1, prev_lo, prev_hi, prev_vout), each output as (2, out_idx, value, script_fp), then
(3, txid_lo, txid_hi, 0): the txid event is padded with a 0. The producer folds `Fp` as the
parser completes events (any number per 64-byte block) and the txid limbs at TXID; the consumer
folds `Fc` as it applies them. Every event starts with a nonzero tag, so equal fingerprints
mean equal sequences except with probability (sequence length)/|F|, provided `r` is fixed after
the consumer's sequence. The consumer also hashes its sequence into `Gc`, pinned as
`Gc := Poseidon(Gc, x1, x2, x3, x4)` from 0 (one 5-input Poseidon per event), and the seal checks
`r = Poseidon(2, r_s, Gc)`. The prover computes the trace natively first, derives `r_s` and
`r` (`Gc` does not depend on `r`: the event sequence comes first), and puts both in z0.

The consumer creates an output under the txid its `open` witness names and folds that same txid
at `close`, and the producer folds the txid it hashed, so equal fingerprints bind every key to the
real txid.

### Consumer: one leaf update per step

Per step the witness gives `close`, `open` (with a txid) and an op in {NONE, SPEND_IN,
SPEND_PRE, CREATE_LOW, CREATE_NEW}, applied in that order:
- `close` (requires an open transaction and no pending create) folds (3, txid) into Fc and Gc;
- `open` sets the current txid (requires none open);
- the op updates one leaf: old leaf and new leaf with one path (D index bits, D siblings), the old
  root must equal the state root and the new root replaces it. An event op requires an open
  transaction and no pending create.
  - SPEND_IN: old.k = k (k from the input event), old.spent = 0, new = old with spent = 1;
  - SPEND_PRE: old.k < k and (old.next_k = 0 or k < old.next_k); new = old;
  - CREATE_LOW: the same non-membership on old; new = old with next_k = k and
    next_index = leaf_count; the hash of the new leaf (k, old.next_k, old.next_index, value,
    script_fp, 0) waits in `pend`;
  - CREATE_NEW: requires `pending`; the old slot is empty (hash 0) at index leaf_count; the new
    leaf hash is `pend`; leaf_count += 1;
  - NONE: new = old.
  SPEND_IN, SPEND_PRE and CREATE_LOW fold their event into Fc and Gc; for outputs
  k = key(current txid, out_idx). A step can carry two events: the close of one transaction and
  the first event of the next.

The fold's public output (in zn): H, the height after T, hash(H−1), hash(T), the map root, the
leaf count, `r_s`, and `sealed`.

### The trace

`run_window` generates the witnesses of a window (blocks and hash(H−1)) and runs `step` on each.
It derives `r_s` and `r`, then schedules the two slots greedily: the producer takes the next
phase every step; the consumer pops its queue (open a transaction, spends, creates as LOW and
NEW, close) packing a close, an open and one op into a step. At HDR3 the producer waits (idle)
until the consumer's queue holds at most the final close, so a block takes
max(compressions, leaf updates) steps plus a few.

## Segmented folding and the verifier

One process folds at 1.4 to 2.2 s per step on the laptop whatever its thread count (the step is
MSM-bound and the machine is shared), so a window is split into segments folded side by side.
Every field of the state is in z, so a segment can start at any step: segment i+1's z0 is
segment i's zn. Commands (`src/segment.rs`, `src/main.rs`, `scripts/fold-window.sh`):
- `m18 trace <data> <first> <last> <segment-steps> <work> [m16-public.bin]`: runs the window
  natively, writes each segment's witnesses (`seg-i.wit`, fixed 1,066-byte records), z0 and
  expected zn, `manifest.json`, and with the M16 statement `balance.json` (the PAY1 output and
  every window output paying its script, each with its transaction and membership path);
- `m18 params <work>`: the public parameters, once, shared by every segment (`pp.bin`);
- `m18 check-trace <work> <m16-public.bin>`: the post-proof checks below on the traced states;
- `m18 fold-seg <work> <i> <every>`: folds segment i, checkpointing the RecursiveSNARK every
  `every` steps (bincode, written by rename) and resuming from the checkpoint after an
  interruption; verifies the RecursiveSNARK against the traced zn;
- `m18 compress-seg <work> <i>`: the segment's CompressedSNARK, verified;
- `m18 verify-window <work> [m16-public.bin] [--vk-sha256=<hex>]`: the verifier.

The verifier accepts a window when:
1. the verifier key is rebuilt from `M18Step` (or is a `vk.bin` whose SHA-256 the caller pins);
2. every segment's CompressedSNARK verifies with its z0;
3. the first z0 equals the window's initial state recomputed from hash(H−1) and H, every field
   compared, `r_s` and `r` excepted (the seal fixes them);
4. each segment's z0 equals the previous segment's zn;
5. the last zn is sealed, with `h0`, `r_s` and `r` unchanged since z0.

With the M16 statement (its wrap proof checked separately by `m13-verify`), it also requires the
statement to be mainnet (NHC1), hash(T) to equal the statement's tip hash (zn[1], zn[2], the same
limb encoding) and T to equal its tip height, and then checks each balance entry: the transaction
hashes to the txid of the leaf's key, the output's script is the PAY1 script (SHA-256), the
leaf's value and `script_fp` agree with the output, the membership path verifies with an index
below 2^20, no outpoint counts twice, and the PAY1 output is unspent with the PAY1 value.

## Status

Built (2026-11-11). The first window is mainnet 975,067..975,072, the six blocks under M16's
payment (txid `a652ab0c…0045`, output 0, 940,000 sats). All six headers match the six headers
inside the M16 payment input.

- `src/native.rs`: block parsing (segwit stripped to the non-witness serialization), txid, Merkle
  root with odd-node duplication, header links, the depth-20 indexed Merkle tree over Poseidon
  (M17's sponge), `script_fp`, create / spend-in-window / spend-before-window with proof
  generation and checking, double spends and false "before window" claims refused, balance
  queries; the coinbase input is an ordinary before-window spend.
- `src/machine.rs`: the state, the witness, `step`, the byte parser, the trace generator.
- `src/circuit.rs`: `M18Step`, the Nova step circuit, 51,404 constraints per step.
- `src/cost.rs`: the map operations as standalone gadgets (the circuit reuses `key_of`,
  `lt_bit`, `path_root`, the Poseidon sponge and the SHA-256 state packing) and the cost-model
  step.

Reproduce: `scripts/cargo.sh test --release` (25 tests, one ignored), `... test --release --lib -- --ignored`
(the full window, needs the raw blocks), then `m18 run`, `m18 cost`, `m18 fold-window` and
`m18 fold`. Raw blocks come from mempool.space into a data directory (not committed) and are
pinned by `fixtures/blocks.json` (heights, hashes, sizes, SHA-256); `fold-window` takes
`<dir> <first> <last> <out.json>` with `<h>.raw` for each height and `<first−1>.hash`.

Window 975,067..975,072 through the step machine (`full_window_975067_975072`, 2026-11-11, 224,790
steps, 2,127 s native). Every HDR3 produces its block hash, every header links, the window seals,
the folded root equals the native map's root, and each block takes max(compressions, leaf updates)
steps (one more when leaf updates lead, for the final close):

| block | steps | compressions | leaf updates | idle steps |
|---|---|---|---|---|
| 975,067 | 41,336 | 41,336 | 35,235 | 0 |
| 975,068 | 43,032 | 43,032 | 36,224 | 0 |
| 975,069 | 42,534 | 42,534 | 35,518 | 0 |
| 975,070 | 41,411 | 41,411 | 34,738 | 0 |
| 975,071 | 25,000 | 25,000 | 23,231 | 0 |
| 975,072 | 31,477 | 29,726 | 31,476 | 1,751 |

The producer leads in five blocks, so the consumer idles; in the last block the consumer leads
and the producer idles through 1,751 steps before HDR3.

Native window run (`results/native-975067-975072.json`, `m18 run`, every proof checked, 2,537 s):
32,693 transactions, 4,864,871 non-witness bytes, 92,141 padded SHA-256 blocks for the bodies, 47,238
inputs (the 6 coinbase inputs included), 74,592 outputs. Events: 74,592 creates, 26,447 in-window
spends, 20,791 before-window spends (6 of them the coinbase null outpoint). 32,729 Merkle merges.
Final map: 74,593 leaves, root `7e18b083…2d1c` (little-endian hex in the results file), the root the
step machine reaches. The depth and the script fingerprint changed the root from the earlier
`9d4dbc82…d220`.

Balance at 975,072. Output `a652ab0c…0045:0` (940,000 sats) is in the map at leaf 8 and unspent;
its membership proof verifies against the final root and its value equals the PAY1 value. It is
the only window output paying its script (`00148e04…ea96`, SHA-256 matches PAY1), so the balance
of that script at 975,072 is 940,000 sats, with a verified balance proof (the script is matched by
`script_fp` at the window's `r_s`).

Constraints (`results/constraints.json`, Nova 0.76 TestConstraintSystem, D = 20):

| unit | constraints |
|---|---|
| M18 step circuit (arity 72) | 51,404 |
| SHA-256 compression | 25,840 |
| Poseidon sponge, 2 / 3 / 6 inputs | 313 / 313 / 625 |
| map create (standalone gadget) | 28,220 |
| map spend in window | 14,447 |
| map spend before window (non-membership) | 8,042 |

End to end on mainnet blocks 170 and 171 (`m18 fold-window <dir> 170 171 <out>`,
`results/fold-window-170-171.json`; block 169's hash and the two raw blocks, 490 and 215 bytes,
from mempool.space): 23 steps (block 170: 16 steps, 16 compressions, 8 leaf updates; block 171: 7
steps, 7 compressions, 3 leaf updates). All 23 steps fold in a RecursiveSNARK that
verifies and ends sealed with the native root `5fde007a…8a1f` (little-endian hex, 5 leaves); the
CompressedSNARK (Spartan over IPA, the types of the earlier fold benchmark) proves and verifies.
Timings, Nova 0.76 on Pallas and Vesta, 4 threads, the laptop's WSL shared with other jobs (load
average 12 to 19):

| stage | seconds |
|---|---|
| public parameters | 53.0 |
| fold, per step (steady) | 2.23 (1.2 to 3.8) |
| fold, 23 steps | 49.7 |
| recursive verify | 2.50 |
| compressed setup | 20.9 |
| compressed prove | 109.5 |
| compressed verify | 2.67 |
| compressed proof | 13,800 bytes |

At 51,404 constraints per step the measured rate is 2.23 s per step on the loaded machine, below
the 3.05 s per step the earlier model gave for its 251,160-constraint uniform step. A block now
takes 37,465 steps on average, not the model's 20,304 (a create is two leaf updates, and the
compressions set the pace), so the window of 224,790 steps comes to about 139 hours of folding
in one process, against the model's 103 hours. It is folded in segments instead (below).

Segmented, blocks 170 and 171 (`results/segmented-170-171.json`): `m18 trace` with 10-step
segments (10, 10, 3 steps), one `pp.bin` (72,704,152 bytes, digest `2a19124c…3101`, primary
70,617 constraints with the Nova augmentation, secondary 10,349), each segment folded by its own
`fold-seg` process and verified against the traced zn, then compressed (13,800 bytes each,
34 to 91 s of proving). `verify-window` accepts the three proofs and the chaining with the
verifier key rebuilt from the circuit (SHA-256 `a259c50c…1939`, equal to the `vk.bin` the
prover wrote) and ends at root `5fde007a…8a1f`, the single-process root. Refused: a z0 with one
byte changed (segment 2 does not start where segment 1 ended), and a wrong `--vk-sha256` pin.
Resume: segment 1 killed after its step-3 checkpoint restarted at step 3 and reached the traced
zn, and its CompressedSNARK verifies.

Window 975,067..975,072, traced, folded and verified (`results/trace-975067-975072.json`,
`results/segmented-975067-975072.json`): 224,790 steps in 8 segments of 28,099 steps (the last
28,097), 29.95 MB of witnesses each, traced in 1,743 s natively. The 8 `fold-seg` processes
(2 threads each, `scripts/fold-window.sh`, checkpoint every 250 steps, shared `pp.bin` digest
`2a19124c…3101`) finished in 35,615 to 35,839 s (9.96 h wall, 1.27 s per step per segment,
6.27 steps/s aggregate), each `zn` matching the trace (`recursive_verify` 0.30 to 0.69 s), and
each segment compressed to a 13,800-byte Spartan-IPA proof (setup 1.61 to 3.41 s, prove 5.94 to
10.27 s, verify 0.13 to 0.32 s; 110,400 bytes across the 8 proofs). `m18 verify-window
--from-circuit` rebuilds the verifier key from the circuit in 3.61 s (`a259c50c…1939`), verifies
all 8 CompressedSNARKs, segment chaining, initial state for hash(975,066) at height 975,067,
sealing at root `7e18b083…2d1c` (74,593 leaves, `r_s` `efec1a32…5b10`), equality of hash(T) and
T = 975,072 with the M16 statement `cae6068f…c869`, and the PAY1 output `a652ab0c…0045:0` from
its transaction and membership path (`results/balance-975067-975072.json`, leaf 8: unspent,
940,000 sats, the only window output paying its script) in 1.47 s.

The earlier bench step (c compressions plus one create at depth 32, `m18 fold`,
`results/fold-timing*.json`, `results/cost-model.json`, `scripts/cost_model.py`) stays as the
reference for the cost model that preceded this circuit.
