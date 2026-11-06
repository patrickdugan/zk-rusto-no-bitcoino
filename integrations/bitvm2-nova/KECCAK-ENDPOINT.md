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
the digest child's field-validity leaf from 372 to 1204. Its expected census is
1,787 words and 1,205 authenticated leaves.

Exactly 256 tail LO bit identities map to `state/24/l0..3/b0..63`. Exactly 832
anchor identities map to the matching fixed `state/0` bits. All other tail
identities have a separate namespace; the 256 HI bits never alias a permutation
port. Each shared occurrence must use the same bound, value, public key,
signature and actual opening bytes. The initial fixed-input entries survive the
stream until the tail is processed. Shared values are reused, never re-signed.

The complete composition has an expected 231,715 leaves and 232,809 distinct
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

Script totals exclude transaction framing, control blocks and assertion
signatures. This source boundary adds obligations; actual hosted costs and
coverage are recorded only after native execution.
