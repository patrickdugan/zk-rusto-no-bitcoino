# Framed LO endpoint and scalar reduction

This separate hosted composition connects the first 256 output bits of one
streamed Keccak permutation to the LO ports of the digest-reduction graph.
It also anchors the fixed framing, Keccak padding and zero capacity bits at the
permutation input. HI remains an external claimed digest. This is a bounded
graph and opening-link conformance experiment, not a complete hash, transcript,
Nova SNARK or production BitVM2 verifier.

## Fixed retained transcript profile

The profile follows the retained primary transcript's event 103: label `r`,
counter 59, LO branch selector zero. The single-block message has 111 bytes:

| Byte positions | Meaning | Source status |
| --- | --- | --- |
| 0 | `w` | fixed |
| 1-32 | eval_W little-endian bytes | external input |
| 33-36 | `NoDS` | fixed |
| 37-44 | counter 59 as little-endian u64 | fixed |
| 45-108 | previous 64-byte transcript state | external input |
| 109 | `r` | fixed |
| 110 | LO branch selector zero | fixed |
| 111 | Keccak delimiter `0x01` | fixed |
| 112-134 | zero padding | fixed |
| 135 | final padding `0x80` | fixed |
| 136-199 | zero capacity | fixed |

Every hash starts from zero before absorbing this block. The previous
transcript state is message data, not the initial sponge state. The 104 fixed
bytes produce 832 Boolean const anchors. The other 768 input bits remain
external. Their fixed lengths do not establish eval_W canonicality, proof-byte
origin or previous-state transcript validity. All corresponding authority flags
remain false.

## Shared identities and unchanged limits

The thirteen live components are the existing twelve streamed permutation
pairs and a fresh endpoint tail. The tail preserves every digest-reduction
constraint and its canonical result field. It appends 832 frame anchors, moving
the digest child's field-validity leaf from 372 to 1204. Its measured census is
1,787 words and 1,205 authenticated leaves.

Exactly 256 tail LO bit identities map to `state/24/l0..3/b0..63`. Exactly 832
anchor identities map to the matching fixed `state/0` bits. All other tail
identities have a separate namespace; the 256 HI bits never alias a permutation
port. Each shared occurrence must use the same bound, value, public key,
signature and actual opening bytes. The initial fixed-input entries survive the
stream until the tail is processed. Shared values are reused, never re-signed.

The complete composition has 231,715 leaves and 232,809 distinct
global words. It uses the unchanged sixteen-component, local 256-MiB compiled
catalogue and global `5 << 28` Script limits. Context fixes topology and maps
before test keys, registry identities, Scripts and Taproot roots are derived.
Only live typed commitments enter the forest; raw root or JSON receipt inputs
cannot establish membership or source authority.

## Adversarial execution boundary

The hosted experiment covers three separately signed cases:

- Honest framing, permutation, LO linkage and reduction.
- A coherent wrong final LO bit with a fully rewitnessed reduction. The last
  permutation output producer must refute it while the tail remains coherent.
- A wrong delimiter bit at input byte 111, followed by a complete honest
  permutation and reduction from that altered block. Only the matching frame
  anchor, tail ordinal 492, should refute it.

All tail leaves execute in correctness and disproof modes. Every permutation
leaf is compiled and its Boolean reference relation checked; selected
authenticated permutation shapes execute through the upstream interpreter.
The selected actual disproof also needs hierarchical offline membership.
Malformed witness lengths, signature forgeries, cross-wire substitutions and
altered ordered maps remain separate failures. Interpreter panics are fatal
worker failures and never successful rejections.

A coherently changed external eval_W/prior-state message may satisfy this
graph. That is expected while those sources remain unbound. Test keys and
fresh offline roots do not supply production WOTS lifecycle or assertion UTXOs.
The complete HI hash, actual proof parsing and transcript composition, remaining
Spartan/IPA Script verification and Bitcoin transaction graph remain open.
The existing real k=10/k=20 proving profiles remain separate and unchanged.

## Executed hosted evidence

The [endpoint workflow](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42212773426)
passed on source commit `c8931419b74dafbcf006a70331e00b547b1729b8`.
All 20 endpoint tests ran on hosted Linux, including the seven real graph tests
that skip locally. All thirteen workflows passed on that source commit,
including the primitive workflow's 335 Python tests. The
initial worker build needed explicit `u64` sum types; no native execution or
successful rejection was claimed from that failed build.

Every scenario compiled all 231,715 actual leaves into a live thirteen-component
forest with the same byte total:

| Complete catalogue | Leaves | Authenticated disproof Script bytes |
| --- | ---: | ---: |
| Twelve existing Boolean permutation pairs | 230,510 | 1,083,207,078 |
| Digest reduction plus framing tail | 1,205 | 4,723,663 |
| Full framed LO composition | 231,715 | 1,087,930,741 |

The tail consists of the 3,321,743-byte Pallas-scalar digest reduction plus
**1,401,920 bytes for 832 framing anchors**, exactly 1,685 bytes per anchor.
The complete source boundary adds 4,723,663 Script bytes to the standalone
permutation. This is measured boundary overhead, not a footprint reduction.
New contexts and test keys change compiled streams and roots; the permutation's
byte total reproduces the existing structure's accounting.

Script totals exclude transaction framing, control blocks and assertion
signatures. The total remains below the unchanged `5 << 28` per-forest budget;
three separately signed test scenarios are not one combined assertion forest.
Two full Boolean permutations alone would exceed that budget and require more
than sixteen current pair components. This experiment authenticates only LO.

The native worker checked every Boolean reference predicate, compiled every
leaf, and executed **8,952 Script vectors**, including **4,833 expected
rejections**. Of these, 714 were malformed/authentication guard vectors over
four Boolean layouts and thirteen targeted tail layouts per scenario; this is
not exhaustive malformed testing of every public coefficient/body shape.
All 1,205 tail leaves executed in both modes for each of the three scenarios,
plus selected authenticated permutation shapes. Six additional selected-leaf
executions checked the actual hierarchical opening paths. Interpreter panics
remain fatal failures, not successful rejections.

For each scenario the worker created 232,809 test signatures once per distinct
global word and reused 18,688 entries: 17,600 inter-pair states, 832 retained
initial framing entries and 256 final LO entries. It compared 832 actual input
opening links, 256 actual LO opening links, 128 byte-adapter links and 64 carry
links in the endpoint, in addition to the existing 38,400 internal-pair and
35,200 inter-pair opening links. Twelve source-cache mutations per scenario
changed name, bound, value, key, signature or actual opening at each source
type; all were rejected. Thirty-nine forest-opening negatives covered altered
Scripts/branches/controls, identities, selection and component order.

The honest scenario had no false predicate. The coherent-output scenario had
exactly one false predicate, component 11 leaf 17,608, while the entire tail
remained coherent. The wrong-padding scenario had exactly one false predicate,
component 12 leaf 492, despite fully recomputing the permutation and reduction.
Their actual selected disproofs passed hierarchical membership, with global
control blocks of 577 and 449 bytes respectively. Fresh roots are not
independently pinned production roots. Swapping two components preserved the
sorted Taproot root but failed the ordered manifest check, demonstrating why
root equality alone does not establish the requested component order.

Maximum compiled leaf size was 18,509 bytes and maximum stack size 95 items.
Maximum observed vector input was 91 witness items, including malformed-length
tests, with 1,800 payload bytes. Native execution took 151.983151966 seconds;
total generation plus execution took 207.575729962 seconds. Parent peak RSS was
85,651,456 bytes; the outer `time -v` recorded 189,616 KiB (194,166,784 bytes).
These are one optimized hosted conformance run's measurements, not Bitcoin
spend costs or proving performance. No proving or transaction jobs ran here.

Topology SHA-256:
`92ff11cbf2386c9d3963a25588f236511e0bf05eb4686240e92fba1e2e30fdb4`.
Exact generated manifest SHA-256:
`c4e706e04722217fe0ad0a0826e6442a61732e839a9b8c32869aa17a0bed762e`.
The selected vector stream was hashed without writing a raw vector file:
83,427,173 bytes, SHA-256
`1691c56b35d5504b310ebc199edfd3063a8fd9db341d41d03b4d6c628c7ccbda`.
All full-hash, complete-permutation-in-Script, transcript, proof and production
authority flags remain false.
