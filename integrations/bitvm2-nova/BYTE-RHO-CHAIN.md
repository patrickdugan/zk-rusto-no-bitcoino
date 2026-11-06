# Linked rho and following sumcheck challenge

This bounded experiment links the framed rho challenge to the immediately
following batch-sumcheck challenge in each retained Nova verifier transcript.
The previous [rho composition](BYTE-RHO.md), all existing backends, exact witness
guards and resource caps remain the baseline. Whole-composition costs and hosted
conformance are pending; the source alone is not a complete transcript verifier.

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
tails, complete streams, membership paths, memory and record costs still need
measurement. Nine components can reach the unchanged depth-19 budget exactly.
These are analytical checks, not a measured fit or a verifier lower bound.

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

This closes one raw-state producer boundary and coefficient canonicality when
hosted conformance passes. Initial eval_W/proof origins, the earlier prior-state
transcript, coefficient proof spans, generic multiblock transcript processing,
authenticated curve/scalar multiplication and IPA/MSM, production assertion
authority and the Bitcoin transaction graph remain separate obligations. No new
proving, trusted setup, GPU work or transaction is needed for this experiment.
