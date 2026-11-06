# Both framed BYTE hashes and rho reduction

This bounded hosted experiment connects both single-block Keccak branches for
the retained rho challenge to the unchanged uniform 512-bit field reducer. It
uses three components ordered HI, LO and tail. Both complete permutation
catalogues remain unchanged, with fresh source identities and explicit global
maps. It does not accept a Nova proof or establish complete transcript,
production assertion or Bitcoin transaction binding.

## Exact framing and shared origins

The 111-byte preimage is the same in both branches except for its last byte:

| State byte positions | Contents |
| --- | --- |
| 0 | `w` |
| 1-32 | external eval_W, 32 bytes little-endian |
| 33-36 | `NoDS` |
| 37-44 | the same public u64 counter, little-endian |
| 45-108 | external prior transcript value, 64 bytes |
| 109 | `r` |
| 110 | selector: LO=0, HI=1 |
| 111 | Keccak delimiter `0x01` |
| 112-134 | zero padding |
| 135 | final padding byte `0x80` |
| 136-199 | zero sponge capacity |

The prior 64-byte transcript value is message data. Both branches start from a
zero sponge; HI does not use counter+1 or consume LO's resulting state. The
retained primary/Pallas event uses counter 59; the secondary/Vesta event uses
44. The sealed factory takes the public counter explicitly before construction.

All 96 dynamic message BYTE ports have common global identities across the
branches: 32 eval_W bytes and 64 prior-state bytes. Every other branch word,
including all 104 fixed input bytes, has a private branch namespace. Equal
values never select aliases. Host binding requires a canonical scalar encoding
for eval_W, but this is explicitly not Script proof-origin or scalar-canonicality
evidence. Prior-transcript provenance also remains open.

## Source quotient and preserved reduction

The three component images have exact pairwise intersections:

- HI/LO: the 96 dynamic message bytes.
- HI/tail: 104 HI frame bytes and 32 HI digest bytes.
- LO/tail: 104 LO frame bytes and 32 LO digest bytes.
- Triple intersection: empty.

The analytical census is 58,943 leaves and 59,109 unique global words. Each
full permutation has 29,245 leaves and 29,445 words. The tail has 453 leaves
and 587 words, all below the existing component caps. No oversized Program or
flattened 58,943-leaf GraphSpec is constructed.

The tail preserves all 245 leaves of a fresh original uniform reducer through
an explicit projection. Its ordinary leaves remain 0-243; its canonical-field
leaf moves from 244 to 452, after 208 new whole-BYTE const anchors. Predicate
bodies, formal alias partitions and field identities remain exact.

The first 32 reducer inputs share the actual LO output bytes; the next 32 share
HI output bytes. Neither digest nor its bytes are reversed:

`X = int.from_bytes(LO_digest || HI_digest, "little")`.

Reduction remains modulo Q for Pallas scalar and P for Vesta scalar. All nine
canonical result limbs, cross-byte reconstruction, unsigned 258-bit quotient,
33 quotient bytes, top-high-zero guard, 65 columns including overflow, both carry
anchors and the anchored BYTE-one remain unchanged.

The 208 actual frame-anchor openings each link to both initial C-parity and
Theta consumer openings, giving 416 comparisons. Sixty-four natural Chi/Iota
digest producer openings link to the original reducer unit adapters. Each
shared external origin has four actual consumer occurrences across the two
branches; it still has no authenticated upstream proof/transcript producer.
Both permutations also retain their 23 internal state joins each.

## Hosted checks and bounded claims

Source identities precede a scenario-global key catalogue, registries, Scripts
and the global forest. A single global word has one key/value/signature entry;
independent component seeds cannot silently replace shared origins. Full
components and their admitted registries are streamed one at a time, with small
actual opening caches retained for cross-component links.

The eight-case corpus distinguishes full from targeted execution. Both roles
have honest and coherent bad-HI-digest cases executing all three components in
both modes. Bad-LO-framing cases execute the full tail and LO source consumers
125 and 351. Canonical wrong-result cases execute the tail only, with no HI/LO
leaf executions. Every case still checks
all native word references, arithmetic truths, source maps, opening links,
complete component compilation and forest construction. The result must report
the selected scope rather than claim all leaves ran in every case.

The native checks cover fresh source/program identities, fields and exact maps;
both whole-byte frame and digest links; shared message entries; live forest
membership/disproofs; and malformed authentication and exact witness-length
guards. Empty, truncated, prepended and appended witnesses remain regression
cases. Interpreter panics are fatal failures, never successful rejection.

The existing 256-MiB local Script, 1.25-GiB global Script, 16-component,
depth-19, 512-MiB native address-space and 128-MiB compact-record caps remain.
Case, map, compact manifest and result files keep their bounded limits. The
record budget includes full/targeted, guard and selected-tree calls; no cap is
increased or bypassed by splitting workers. No proving or GPU work runs here.

## Measured hosted result

Source commit `ece1e54e6afe9554aef7eca22b58ac438fce5583` passed the
[hosted composition run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42250750468),
job `128004860359`. The 17 Python tests passed in 197.761 seconds under the
unchanged 256-MiB address-space cap. Nine registry tests, five forest tests and
all 19 new native tests passed before actual Script execution.
All 18 workflows for this source commit passed; the complete M2 Python suite
passed 424 tests in 650.487 seconds.

| Scalar role | HI bytes | LO bytes | Tail bytes | Complete forest Script bytes |
| --- | ---: | ---: | ---: | ---: |
| Pallas | 151,432,516 | 151,432,516 | 2,494,673 | 305,359,705 |
| Vesta | 151,432,516 | 151,432,516 | 2,486,550 | 305,351,582 |

Every profile in a role has the same complete measured cost. Each live component
tree's count and stream hash match its complete independently measured Script
stream; each live forest sums all three components. The same raw-Script
accounting as the isolated permutation is used. It excludes transaction framing,
control blocks and assertion signature payloads. This experiment does not supply
a conversion-complete Boolean full-rho baseline or establish a full-verifier
savings ratio.

Actual execution passed 487,176 Script calls, including 249,580 expected
rejections. These are 475,176 ordinary C/D calls, 11,984 malformed-authentication
and witness-length guard calls, and 16 selected-forest C/D rechecks. Four groups
execute the complete statement; four execute the targeted subsets described
above. All 471,544 case/predicate pairs received independent native truth checks;
this is coverage, separate from the Script call count or the number of repeated
native truth evaluations. The canonical wrong-result cases fail exactly the first
reducer column, ordinal 85; the controlled HI digest fault fails ordinal 29,241,
and the controlled LO delimiter fault fails tail anchor 363.

Across eight groups, the worker checked 147,200 internal state producer/consumer
openings, 3,072 shared-message consumer occurrences, 3,328 frame-anchor links and
512 digest-to-reducer links. It created 472,872 scenario-global signatures and
reused 2,944 component declarations. The 576 native-admission, 64 map, 96 source,
240 cache and 104 forest negative controls are non-Script checks and are not
added to the Script rejection count.

Selected global controls are 321 bytes for the honest tail field-valid leaf,
545 for the bad HI producer, and 353 for either tail counterexample. All 13
forest mutation classes reject in every group. These roots are freshly built
from actual compiled components; they are not externally pinned production
assertion roots. Maximum observed Script size is 18,509 bytes, stack occupancy
95 items, and witness size 91 items / 1,800 payload bytes.

Native execution took 255.362551059 seconds; the complete parent benchmark took
368.894601329 seconds. Parent-reported peak RSS is 114,028,544 bytes. External
`/usr/bin/time` reported 288,308 KiB (295,227,392 bytes) for the benchmark command.
These are distinct observations, not a simultaneous sum or a direct native-only
peak. The unchanged native 512-MiB address-space, CPU, forest and record caps
passed. The 102,652,964-byte compact execution stream stays below its original
128-MiB cap and has SHA-256
`048a8711ecf30669af9a79e10a6f378d090b64ec80d6ebfa84b88c36c2caa8c7`.
It commits records only after actual engine outcomes match; no raw vector file
or proof-verification receipt is substituted for execution.

Artifact `13520308353` contains the report, raw manifest, timing/test logs and
resolved dependency lock:

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| ZIP | 46,714 | `9a6cecf8e9bfd82b2a53aa554b8813fabff2f21dd920a1d0044b9e3210d5559c` |
| `byte-rho-conformance.json` | 50,803 | `b563594c5b1d953ce4174a770b4fbaf8dcc2b6d9eb0ed50ebdbbdfbb248fb7e7` |
| `byte-rho-manifest.json` | 154,254 | `0af2f8dd11942bd8e99614694851d46480e6b7ec6391f523217cddebeb61ca3a` |

The downloaded ZIP, report and manifest were hash-checked locally. Native
compilation, graph construction and Script execution ran on hosted Linux; this
milestone performed no local proving, GPU or native graph job.

This is a framed rho-hash/reduction relation given external message origins.
Script eval_W canonicality and proof-span provenance, full prior-state
transcript provenance, generic multiblock transcript processing, downstream
challenge ports, IPA/MSM verification and production assertion authority remain
separate obligations.
