# Linked rho and following sumcheck challenge

This bounded experiment links the framed rho challenge to the immediately
following batch-sumcheck challenge in each retained Nova verifier transcript.
The previous [rho composition](BYTE-RHO.md), all existing backends, exact witness
guards and resource caps remain the baseline. Hosted conformance passed for this
two-challenge relation; proof/transcript origins and full verification remain
separate obligations.

The pinned trace is `fixtures/nht4-genesis-0-2020-k5.trace.json`, SHA-256
`394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8`.
Primary events 103/104/105 use rho counter 59 and next counter 60; secondary
events 78/79/80 use counters 44 and 45. The two absorbed compressed quadratic
coefficients are `c0,c2`. The chain derives its previous raw transcript state
from the actual rho digest producers, rather than accept a new independent
64-byte state or feed back the reduced scalar.

## Exact two-block message

| Message bytes | Contents |
| --- | --- |
| 0 | `p` |
| 1-32 | canonical coefficient `c0`, little-endian |
| 33-64 | canonical coefficient `c2`, little-endian |
| 65-68 | `NoDS` |
| 69-76 | next public u64 counter, little-endian |
| 77-140 | actual rho `LO_digest || HI_digest`, 64 bytes |
| 141 | `c` |
| 142 | selector, LO=0 and HI=1 |

The common prefix permutation consumes exactly the first 136 message bytes and
zero initial capacity. This full rate block has no delimiter or terminal pad.
The 59/5 split of the previous raw state puts its first 59 bytes in that prefix
and its last five in the next rate block.

The second rate block is the last five raw bytes, `c`, the selector, delimiter
`0x01`, 127 zero bytes and final `0x80`. It is XORed into the actual prefix
permutation output rate. All 64 capacity bytes forward that output unchanged;
they must not be reset to zero at either final branch.

Eight suffix transforms are identical across branches and are computed once:
five dynamic BYTE XORs and three constant XORs for `c`, delimiter and final pad.
One further XOR introduces HI's selector at byte 6. LO forwards the prefix byte
there. This gives nine predicates and 23 local words. Final HI/LO input states
share exactly 199 structural identities. Their prefix intersections are 191
and 192 words, respectively. Equal values never select aliases.

## Source and authenticated boundaries

The nine ordered components are rho HI, rho LO, rho tail, canonical coefficient
and prefix-frame source, shared prefix permutation, suffix absorption, final
HI permutation, final LO permutation and the unchanged uniform reducer. All
five full permutations retain their original 29,245 leaves and 29,445 words.

The coefficient/frame component has 187 words and 111 leaves. It preserves the
existing 32 scalar-to-BYTE encoding constraints, adds 77 fixed prefix anchors,
and retains both canonical-field guards at leaves 109/110. The final reducer
retains its complete 379-word, 245-leaf relation and all original quotient,
reconstruction, overflow and carry guards.

The source census is 147,043 leaves, 148,401 local declarations, 147,355 unique
global words and 1,046 declaration reuses. All aliases come from explicit source
interfaces. A fresh immutable global key/signature pool admits that exact census
before signing; the old rho pool's count gate is unchanged. Compact parent maps
pin normative mappings and actual interfaces without serializing every private
word a second time. Native validation must independently rebuild those maps and
count every actual declaration.

The source identity precedes keys, complete component trees and the global
forest. Graphs and registries are streamed one at a time. Five isolated
permutations give a 757,162,580-byte linear Script subtotal; actual bridges,
tails and membership paths now have the separate measurements below. Nine
components can reach the unchanged depth-19 budget exactly. The isolated
permutation subtotal is not a verifier lower bound.

## Conformance scope

Both retained roles have one fully executed honest chain. Coherent rho-HI-byte31
and prefix-output-capacity-byte136 faults are separate targeted chain cases;
downstream witnesses are regenerated from the claimed producers. Every main
case still validates all references, source identities, mappings, complete
compiled trees and actual opening caches. Full and targeted execution must be
reported separately.

Twenty separately reported small probes test coefficient-modulus encodings,
prefix counter/NoDS/tag/zero-capacity anchors, and absorption XOR, selector,
delimiter and final padding. These use fresh probe-domain keys and live local
trees. They do not replace main-pool signatures or establish a global main-forest
claim for a private probe.

Empty, truncated, prepended and appended witnesses, forged openings and exact
length checks remain required. Interpreter panics or failed process execution
are failures, never evidence of successful rejection. Full graph construction
and actual Script execution run only in the bounded hosted job. Existing
256-MiB component, 1.25-GiB global, 16-component, depth-19, 512-MiB native,
8-MiB raw-map and 128-MiB compact-record caps remain unchanged; a failed budget
must be reported or optimized rather than bypassed.

## Measured hosted result

Tested source `15807d4d0f6f4283ff467a437bcff4f9b1f2872d` passed
[run 42266024221](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42266024221),
job `128058023885`. All 19 source workflows passed. The dedicated job passed
14 Python tests in 74.923 seconds under 256 MiB, then 9 registry, 5 forest and
35 worker unit tests. M2 ran 438 tests in 542.632 seconds: 437 passed and one
explicit opt-in test skipped; that chain test passed in the dedicated job. Initial
source `e763fb0` failed three Rust API call sites before native execution; the
tested fix changed only those call sites, with no arithmetic, guard or cap change.

| Component | Pallas scalar Script bytes | Vesta scalar Script bytes |
| --- | ---: | ---: |
| Five unchanged full permutations, sum | 757,162,580 | 757,162,580 |
| Original rho tail | 2,494,673 | 2,486,550 |
| Canonical coefficients and prefix frame | 410,169 | 410,169 |
| Shared suffix absorption | 42,357 | 42,357 |
| Following uniform reducer | 2,143,759 | 2,135,636 |
| Complete forest | 762,253,538 | 762,237,292 |

Each full permutation still measures 151,432,516 bytes. All three main profiles
in a role have the same complete cost. Each live local tree matches the whole
measured component stream, and the live forest sums all nine components. Raw
Script accounting is identical to the prior rho boundary and excludes transaction
framing, control blocks and assertion signature payloads.

This extension adds 456,893,833 bytes for Pallas and 456,885,710 for Vesta relative
to rho alone: it proves additional source boundaries. No complete unshared or
Boolean two-challenge baseline was measured, so no whole-verifier savings ratio
is established. Sharing the first block removes a structural permutation copy;
the remaining full-transcript projection in [NEXT.md](NEXT.md) is still far
above the current global budget.

Actual Script execution passed 623,600 calls with 324,792 expected rejections:

- 594,756 normal main calls: two full 147,043-leaf honest cases and four
  targeted 823-leaf coherent cases, each in both C/D modes.
- 2,808 normal private-probe calls: all 1,404 small probe leaves in both modes.
- 25,984 exact-length, forged-opening and cross-wire guards, all rejecting.
- 52 selected-tree C/D rechecks, 12 global and 40 private local calls.

The coherent rho fault fails only its byte31 Chi producer, ordinal 29,072; the
coherent prefix-capacity fault fails only ordinal 29,177. Their downstream
relations are re-witnessed and remain true. Private modulus probes refute guards
109/110; frame probes refute exactly their const anchors and suffix probes their
actual XOR/mask leaves. No upstream panic is accepted as a rejection.

Every main case checks 2,142 cross-component, 46 canonical-encoding and 46,000
internal-round opening comparisons. Across six cases these total 12,852, 276
and 276,000, respectively. The main pools create 884,130 signatures and reuse
6,276 component declarations. The twenty probes create 2,428 separate signature
entries and twenty separate local trees. Main metadata rejection counts are
216 admission, 12 map, 18 source, 96 cache and 13 forest controls per case;
each private tree also rejects all twelve local mutation classes. These native
metadata checks are separate from Script call/rejection totals.

Global selected controls measure 353 bytes for honest final-field validity,
609 for the rho fault and 577 for the prefix fault. Private controls measure
225/257/161/129 bytes according to the selected local leaf. Roots come from
actual compiled live components; no externally pinned production assertion root
is established. Maximum observed Script size is 18,509 bytes, stack occupancy
95 items and witness size 91 items / 1,800 payload bytes, including guard cases.

Native execution took 430.324464439 seconds; the complete parent benchmark took
673.726217626 seconds. Parent peak RSS is 128,827,392 bytes. External
`/usr/bin/time` reported 383,072 KiB (392,265,728 bytes) for the benchmark
command. These are distinct observations, with no simultaneous sum or standalone
native-RSS claim. All original address-space, CPU, wall, component, depth, map
and record limits passed. The compact stream is 116,408,076 bytes under the
128-MiB cap, SHA-256
`86831cfc2ebb92e6ba19b4bb77ac6c3e60e56715b376dbc0e4f1e3870557e43b`.
Records are hashed only after actual engine outcomes match; no raw vector file
or detached success receipt substitutes for execution.

Artifact `13528321168` includes raw metadata, reports, logs and the dependency
lock. Its downloaded ZIP and both JSON files were independently hash-checked;
artifact report/stdout and direct job stdout are semantically identical, and
the native input pin matches the raw manifest SHA.

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| ZIP | 124,653 | `6bb58c543410051113310dcdb98444c9b81c61da51a93da637fb271950f242a2` |
| `byte-rho-chain-conformance.json` | 138,264 | `5f86772dc2b0fed7db3af0c0a25a6f719ea9b49af980ffd04573b3d725718b88` |
| `byte-rho-chain-manifest.json` | 307,694 | `8b4367fda65ce71f6c12df9e5139452eff0777560476f8694c82c00a801ba0c4` |

This closes one raw-state producer boundary and coefficient canonicality for
the retained two-challenge relation. Initial eval_W/proof origins, the earlier
prior-state transcript, coefficient proof spans, generic multiblock transcript
processing, full Spartan sumcheck equations, Script NHT4/point decoding and
generator origins, authenticated curve/scalar multiplication and IPA/MSM,
production assertion authority and the Bitcoin transaction graph remain separate
obligations. No new
proving, trusted setup, GPU work or transaction is needed for this experiment.
