# Offline Taproot commitment to actual registry Scripts

`rust-oracle/src/taproot_commitment.rs` constructs a reproducible Taproot root and
one selected Script membership proof from an immutable admitted `Registry`.
Every leaf is the actual `registry.script(ordinal, true)` disproof Script. This
adds an offline commitment boundary; it does not execute a Bitcoin transaction,
sign anything, create a secret key, bind an assertion UTXO or implement the
remaining Bitcoin transaction graph. Production WOTS lifecycle, actual assertion
binding and a complete Script Nova verifier remain separate work.

## Existing identities and compiled bytes

`Registry::new` already requires independently expected catalogue and registry
IDs. `GraphSpec::identity()` binds the program digest, context, field role,
operation, ordered named wires/bounds and ordered leaf kinds, arguments, wires
and predicate-body digests. Its registry ID additionally binds the ordered WOTS
public keys. Each compiled Script includes a domain-separated dropped literal
tag hashing registry ID, ordinal and `disprove=true`.

The Taproot layer uses those existing bytes directly, including the exact
witness-length guard, WOTS recovery code, canonicality predicates and leaf tag.
It changes neither `Registry::script` nor witness handling. TapLeaf hashing uses
the mature `TapNodeHash::from_script(..., LeafVersion::TapScript)` API, including
the BIP341 leaf version and CompactSize Script length. It does not substitute a
bare SHA-256, body hash, registry label or externally supplied leaf-hash list.

TapBranch hashing sorts child hashes. Swapping siblings can preserve a subtree
root, so a root is not claimed to authenticate a left/right index by itself.
Ordinal binding comes from the compiled tag and exact recompilation from the
admitted registry. Changing catalogue order changes its identity and therefore
the compiled tags, even when individual predicates are otherwise identical.

## Complete balanced tree and bounded state

For leaf count `N`, let `h=floor(log2(N))` and `deep=2*(N-2^h)`. In increasing
ordinal/DFS order, the first `deep` leaves have depth `h+1`, and the remainder
have depth `h`. This is the versioned `complete-left-filled-dfs/v1` schedule.
There are exactly N real leaves, with no duplicated or dummy padding leaves.
Examples are `[0]` for N=1, `[2,2,1]` for N=3, and `[3,3,2,2,2]` for N=5.

The factory hashes every compiled leaf. It passes only the selected Script to
`TaprootBuilder::add_leaf`; all others use `add_hidden_node` with their actual
TapLeaf hashes. The mature hidden-node representation retains no Script leaves.
The completed builder must contain exactly one retained Script and its proof.
An ordinary all-Script builder is used only as a tiny test reference.

Tree overhead is O(log N), plus one retained selected Script and one transient
compilation buffer. Extracting the selected Script through the public spend-info
map briefly copies that one bounded Script. Existing Registry graph/keys,
predicate bodies and per-wire `OnceLock` decoder caches remain additional memory;
this is not a claim that the entire process uses O(log N) memory. The roughly
88 MB aggregate candidate point catalogue is never retained as a Script vector.

The module accepts 1..=30,000 leaves, rejects an invalid ordinal before compiling,
preserves the 100,000-byte individual leaf limit, and checks the running sum
before overflow with a 256 MiB cumulative compiled-Script cap. The 30,000-leaf
bound implies at most depth 15 and a 513-byte control block. For the existing
6,151-leaf point catalogue, depths are 12/13, implying 417/449-byte control blocks.
The maximum is an arithmetic bound. The selected current-catalogue lengths were
also measured in the hosted execution below.

The compiled-byte sum counts every actual disproof Script once. The stream SHA
uses the existing registry ledger format: each Script's u32 LE byte length,
followed by those exact bytes, in catalogue ordinal order. Control bytes, witness
framing, assertion signatures and transactions are outside that sum. Runtime and
process memory for this construction are recorded below. No full catalogue
compilation or Rust build was run on the local host.

## Fixed public NUMS internal key

The internal key is the BIP341 NUMS x coordinate:

```
50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
```

BIP341 derives it as SHA-256 of the standard uncompressed secp256k1 generator
encoding. The corresponding point has no known discrete logarithm; preventing a
key-path bypass relies on the usual discrete-log assumption, not a secret chosen
by this adapter or a trusted setup ceremony. Fixed NUMS exposes that policy rather
than adding BIP341's optional privacy-blinding scalar. The code uses a
verification-only secp256k1 context and public-key operations exclusively.

The constant was checked against the
[primary BIP341 construction guidance](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs)
and a lightweight SHA-256 calculation. A no-secret unit test asserts that same
derivation. No signing secret is generated, imported or used.

## Factory and verification API

`TaprootCommitment::new(&registry, ordinal)` returns an immutable object exposing
the selected Script, control block/bytes, Merkle root, output key, leaf count,
ordinal, registry/catalogue IDs, compiled-byte sum and compiled stream SHA.

`commitment.verify_member(&registry, expected_root, expected_output_key, ordinal)`
checks object identity and calls the public byte-opening verifier:

```
verify_opening(&registry, expected_root, expected_output_key,
               ordinal, script, control_bytes)
```

The expected root, output key and identities used to admit `Registry` must come
from the verifier's own authenticated context, not be accepted from an untrusted
opening. The opening verifier requires:

- exact equality with the freshly recompiled selected disproof Script;
- the expected complete-tree depth and exact canonical control-block encoding;
- `LeafVersion::TapScript`, fixed NUMS internal key and expected output parity;
- the root reconstructed from the actual Script and branch equal to the external
  expected root;
- the recomputed output key equal to the external expected key;
- successful mature `ControlBlock::verify_taproot_commitment` verification.

The upstream convenience APIs use `expect` for a tweak outside the scalar range
or an invalid output point. Before invoking them, this adapter parses the actual
TapTweak bytes using fallible `Scalar::from_be_bytes` and calls the fallible
`XOnlyPublicKey::add_tweak` on the exact same root/key. It applies that preflight
both before creating spend information and before verifying an external opening.
No panic is caught or treated as successful rejection.

Membership does not demonstrate predicate execution, valid assertion signatures,
or that a Bitcoin output exists with this output key. A self-reported root or
successful offline receipt cannot supply those missing authorities.

## Validation and source compatibility

Five no-secret unit-test groups cover every selected ordinal for small trees
N=1..17 against the ordinary all-Script builder's roots, output keys and serialized
control blocks; malformed Script/branch/parity/internal-key/version/length/ordinal
inputs; wrong external roots/keys; changed context/program/field/catalogue;
size/arithmetic caps; NUMS provenance and fallible tweak errors; and TapBranch
commutativity without a false ordering claim. Their synthetic fixed public WOTS
bytes and dummy predicate exercise commitment admission only, not arithmetic or
signing correctness. Actual hosted execution passed as recorded below.

The implementation uses APIs available in the existing `bitcoin = "0.32.5"`
compatible dependency range. Relevant primary implementation files are
[`bitcoin/src/taproot/mod.rs`](https://github.com/rust-bitcoin/rust-bitcoin/blob/bitcoin-0.32.5/bitcoin/src/taproot/mod.rs),
`bitcoin/src/taproot/merkle_branch.rs`, and `bitcoin/src/crypto/key.rs`. The resolved
version and generated Cargo.lock from the actual hosted run are part of its
evidence; this stage does not change dependency or source pins. The recorded
hosted run resolved `bitcoin 0.32.102` within that compatible range.

## Measured hosted execution

Code commit `5a82788780bf9b4c3f17777cf5367ad1edd0250e` passed all seven
workflows. The
[global-registry job](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42152203691/job/127677852673)
executed five library test groups, including all **153 selected openings** for
N=1..17 against the ordinary all-Script builder, and two binary test groups.
It then constructed all eight complete candidate trees and rejected all
**108 negative cases**: thirteen opening-mutation categories across eight
openings, plus four invalid constructor ordinals. A panic would fail the job;
it is never counted as rejection.

| Catalogue | Real leaves | Aggregate disproof Script bytes | Control bytes at ordinal 0 / last |
| --- | ---: | ---: | ---: |
| Pallas multiplication | 489 | 6,993,315 | 321 / 289 |
| Vesta multiplication | 489 | 7,001,191 | 321 / 289 |
| Pallas point addition | 6,151 | 88,586,200 | 449 / 417 |
| Vesta point addition | 6,151 | 88,688,588 | 449 / 417 |

Every tree construction hashed every actual disproof Script. The four distinct
catalogues total **191,269,294 Script bytes**; compiling each twice, for selected
ordinals 0 and last, processed **382,538,588 bytes**. Each selection produced the
same full-catalogue root and output key. All four candidate stream-byte/hash
goldens matched, while the preceding baseline registry run independently retained
the four original goldens. The Script sums exclude control blocks, transaction
framing and assertion signatures; they are not transaction weights or fees.

The complete Taproot binary took **44.503489095 seconds** and `/usr/bin/time`
recorded **69,420 KiB (71,086,080 bytes) peak RSS**, under the 512 MiB address-space
and 300-second CPU/wall caps. It derived **16,220 deterministic TEST-ONLY WOTS
public keys**, matching the existing registry fixture derivation, and created
zero assertion signatures. Each Registry was reused for its two selections:
ordinal 0 populated its per-wire decoder caches, so the last-ordinal construction
was warm. This is not a cold-independent runtime comparison between selections.

The same job passed the unchanged baseline **49 cases / 2,538 Script vectors /
1,331 rejections**, and candidate **44 cases / 3,778 vectors / 1,987 rejections**.
Existing empty, truncated, prepended and appended witness regressions remain in
those executions. Maximum stack/witness metrics stayed **485 stack items,
480 witness items and 9,600 witness payload bytes**. The separate M2 job retained
74 independent curve cases, 10,884 baseline Script vectors and 19,216 compact
vectors; the Python suite passed 210 tests. The identical-accounting footprint
comparison, including the fixed-claim size regression, remains in
[M2-CONVOLUTION.md](M2-CONVOLUTION.md).

Artifacts contain the small `taproot-registry-execution.json` ledger, its file
digest, timing, unit-test output and resolved lockfile. Roots in that ledger are
observations from this offline test, not independently authenticated production
assertion roots. `taproot_roots_independently_pinned`, Script execution, WOTS
witness verification, assertion UTXO/transaction binding and complete-verifier
flags all remain false. Transactions broadcast and complete Nova proofs verified
by this command are zero. The existing registry execution supplies separate
arithmetic evidence; membership alone does not establish it.
