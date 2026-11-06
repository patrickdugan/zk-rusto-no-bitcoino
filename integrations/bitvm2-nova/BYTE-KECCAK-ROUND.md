# Opt-in byte Keccak round with producer-linked outputs

This hosted experiment implements exactly one Keccak-f[1600] round with the
existing byte-v1 predicates. It retains the Boolean round as a separate
baseline. One-round correctness does not establish a composed permutation,
hash, transcript, Nova SNARK or production BitVM2 verifier.

## Routing and terminal producers

The input has 200 BYTE words ordered by lane `x+5*y`, then little-endian byte
index 0-7. Theta, Rho, Pi, Chi and Iota follow the existing 64-bit word reference.
For a lane rotation `s=8*q+r`, output byte j uses a at `(j-q) mod 8` and b at
`(j-q-1) mod 8`; a nonzero r uses `byte_rol(a,b,out;r)`. Byte-aligned rotations
only route existing references. Pi sends source lane x+5*y to
`y+5*((2*x+3*y) mod 5)`. No routing depends on assignment values.

Chi produces fresh output words. A nonzero Iota round-constant byte replaces
the corresponding lane-zero Chi terminal with a fresh public-mask output.
All 200 final words are distinct, disjoint from inputs, and never consumed by a
later gate in this round. Every post-input word has exactly one preceding
producer. The sealed source map identifies each terminal's actual producer
ordinal and operand occurrence; outputs are not the last 200 allocated words.

The Program operation identity includes the explicit round index after the
caller prefix. Round constants alone are insufficient: rounds 5/22 and 6/20
repeat constants. The sealed manifest records both operation identities and
binds the round-specific source maps. Numeric openings for equal values remain
equal; expected Program/catalogue identity admission and registry-specific WOTS
keys provide their respective domain boundaries. This does not supply the
future production assertion binding.

This avoids an output-copy layer and its zero wire in the new byte backend.
The existing Boolean backend's zero anchor and 1,600 output-copy gates remain
unchanged. BYTE boundaries use distinct `byte-state` identities so they cannot
silently share a key with the older bound-two state words.

The byte schedule has 160 column-parity XORs, 40 Theta rotations and 40 D XORs,
200 Theta application XORs, 176 Rho joins and 600 Chi gates. Iota adds one mask
gate for each nonzero little-endian round-constant byte n. Thus one round has
`1216+n` leaves and `1416+n` words, with n from 1 to 4. These source counts do
not imply a measured multi-round cost.

## Complete Boolean BYTE-port baseline

The comparison uses the same 200 external input bytes and 200 external output
bytes. A fresh legacy Boolean round retains every original word, predicate,
body, zero anchor and output copy. A separate bounded child connects each BYTE
port through one BASE auxiliary and eight existing boundary bits, using the
unchanged MSB-first `bits(8)` and `conv_reconstruct(8)` predicates.

The children share exactly 3,200 input/output bit words. The parent appends 400
BYTE words, 400 auxiliaries and 800 bridge leaves. Its complete catalogue has
`10401+popcount(RC)` leaves and `12001+popcount(RC)` words. This exceeds the
10,000-constraint Program limit, so the sealed factory composes GraphSpecs
instead. Both child Programs retain their existing limits, as does the
30,000-leaf graph bound. Imported Programs, maps and result receipts are not
constructors for either sealed round factory.

There are 3,200 distinct bridge bit words. The 1,600 input bits each feed two
legacy consumers; the 1,600 output bits come from their existing output-copy
producers. The native checks therefore compare 4,800 actual bit openings and
400 auxiliary openings per baseline. The output BYTE source is operand 1 of
its reconstruction leaf. Value equality alone does not establish these links.

This is an isolated same-BYTE-port round comparison. A full Boolean permutation
keeps its intermediate boundaries as bits and would not pay these BYTE bridges
at every round. Per-round ratios must not be multiplied into a whole-permutation
savings claim; complete composition and joins require separate measurements.

## Output-consumer probe and adversarial cases

A separate diagnostic registry copies all 200 source outputs with public-mask
zero predicates. It reuses the exact source output public keys, values,
signatures and actual producer openings, then introduces fresh copy outputs.
The probe's Script cost is reported separately from the round cost.

The hosted corpus has 64 source/probe pairs: all 24 byte rounds in both scalar
roles, four coherent wrong-output cases, four signed oversized-input cases and
eight complete Boolean baselines. Wrong Iota and Chi terminal bytes must refute
only their actual producer while their copy probes remain coherent. A valid
signature over an out-of-domain u32 is handled through the existing decoder
flag, not mistaken for a canonical byte. Authentication forgeries and empty,
truncated, prepended or appended witnesses must still abort both modes.

All source and probe leaves execute in correctness and disproof modes through
the upstream interpreter. Expected outcomes, native word-level round reference,
SSA, producer maps, source identities and all preserved child projections are
checked independently. Native panics are fatal failures, never successful
rejections.

Full raw vectors would be unnecessarily large. The worker instead hashes
bounded compact execution records containing exact Script/witness digests,
identities, modes and outcomes. The existing 128-MiB record cap is separate from
the ordered compiled Script byte sums; it does not cap or stand for the amount
of Script processed. Fresh case snapshots and the manifest are hashed before
the direct configured resource-capped worker runs. No external result receipt
is loaded as verification authority.

## Measured hosted result

Source commit `d17bdcb7659cb6d625988b9c1784e3c6893fe673` passed the dedicated
[hosted run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42224687519).
Every leaf of all 64 sources and all 64 probes executed in both correctness and
disproof modes. The four directly compared rounds measured the following
ordered disproof Script byte sums; both scalar roles gave exactly these costs.

| Round | BYTE source leaves | BYTE source bytes | Complete Boolean BYTE-port source leaves | Complete Boolean source bytes |
| --- | ---: | ---: | ---: | ---: |
| 0 | 1,217 | 6,304,498 | 10,402 | 52,487,418 |
| 1 | 1,218 | 6,307,869 | 10,404 | 52,494,084 |
| 2 | 1,219 | 6,311,270 | 10,406 | 52,500,750 |
| 23 | 1,220 | 6,314,561 | 10,405 | 52,497,417 |

These isolated BYTE-port round sources are about 88% smaller than the complete
Boolean baselines. Each separate 200-leaf output-consumer probe costs 665,600
bytes for either backend. Across all 24 independently executed honest BYTE
rounds, source costs range from 6,304,413 to 6,314,678 bytes. This is not a
measurement of connected rounds or a full permutation. In particular, the
Boolean full permutation does not convert every intermediate boundary to bytes.
Script accounting excludes transaction framing, control blocks and assertion
signature payloads.

The run executed 151,472 source leaves and 12,800 probe leaves: 164,272
predicates in each mode. Another 10,752 malformed/authentication guard vectors
bring the total to **339,296 Script executions, with 175,024 expected
rejections**. Empty, truncated, prepended and appended witnesses remained
rejections in both modes; interpreter panics were fatal failures. The separate
native admission checks rejected 3,072 mutations across source and probe
catalogues, 512 port mutations and 768 signature-cache mutations; these are not
additional Script executions.

All 12,800 output producer/consumer opening comparisons matched actual source
openings and reused signatures. The eight Boolean baselines also checked
38,400 bit opening occurrences (25,600 input and 12,800 output), plus 3,200
auxiliary links. Wrong round-0 Iota output bytes refuted only source leaf 1,216;
wrong round-23 Chi output bytes refuted only leaf 1,024. Signed oversized input
words refuted exactly their two consumers, leaves 0 and 240. These outcomes held
in both scalar roles while all corresponding probe predicates remained true.

The worker created 188,272 fresh signature entries and reused 12,800 source
output entries. Maximum observed Script size was 14,882 bytes, stack size 95
items, witness size 91 items and witness payload 1,800 bytes. Native execution
took 131.973 seconds; total parent time was 143.111 seconds. External
`time -v` recorded 85,756 KiB peak RSS, while the parent's own peak was
47,833,088 bytes; these are distinct observations, not an aggregate memory
measurement. The existing resource caps, old kernels and baseline guards were
unchanged. The dedicated job passed 24 Python tests, nine registry Rust tests
and six worker Rust tests. All 15 workflows passed on the source commit; the M2
workflow's complete Python suite passed 375 tests.

The first hosted attempt at `489989a` failed before native execution: it exposed
the repeated-constant Program identity gap above, and a test incorrectly
rejected the valid `claimed_output=None` default. The correction preserves
all-round Program uniqueness and explicitly tests both repeated-constant pairs,
foreign expected identity admission and the honest default. No measurements
from the failed attempt count as successful evidence.

The [CI artifact](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42224687519/artifacts/13505037697)
contains the report, manifest, dependency lock, test logs and resource logs.
Its downloaded ZIP was independently checked against the GitHub artifact
digest, and its report matched the job's stdout report.

- Artifact ZIP: 114,184 bytes; SHA-256 `96e6144159564a4ec98588cda06075d109782a2884a7a9d28cddf9f978499226`.
- Report: 145,627 bytes; SHA-256 `1998742a20c67b3940e15edfe5f0740bc5162128569826393f66b1973ea48e98`.
- Input manifest: 127,384 bytes; SHA-256 `bd2aae010b096ff1b94c796656835540e4581c947a7d8914d9584ca51dc259f1`.
- Actual compact execution-record stream: 83,568,880 bytes; SHA-256 `af5aa95cc36e87af5fdd601c303de9de31a5c04321c84825b1b058b5e4c8601d`.

The compact stream is hashed during execution, not uploaded as a raw vector
file. Its digest and length do not represent a full verifier, proof or
transaction artifact. Test keys only were used; no setup, proving, GPU job or
transaction broadcast occurred in this round measurement.

## Remaining composition boundary

The subsequent [four-round BYTE component](BYTE-KECCAK-BLOCK.md) preserves
the child predicate bodies and exact global BYTE identities, merges exactly
200 words at each adjacent boundary, and compares all 1,200 actual opening
occurrences across the three joins while reusing 600 boundary signatures.
Producer locations come from the sealed maps, never a final-word suffix.
The parent has fresh catalogue/registry identities and its own measured Script
costs. Equal values or independent one-round receipts cannot establish these
joins; its separate hosted evidence covers them.

Existing full-permutation and framed-LO Boolean evidence, header provers and
real k-sized proving profiles remain separate. A complete byte permutation,
both hash branches, proof-derived message origins, full
verifier composition and production assertions/transactions remain future work.
