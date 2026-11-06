# Opt-in four-round BYTE Keccak component

This separate hosted experiment composes exactly four consecutive BYTE Keccak
rounds into one GraphSpec and one authenticated registry. The one-round BYTE
implementation and all Boolean baselines remain unchanged. A four-round
component does not establish a complete permutation, hash, transcript, Nova
SNARK or production BitVM2 verifier.

## Exact state joins and parent identity

The sealed factory builds four fresh child plans for absolute rounds r through
r+3, where r is an integer from 0 through 20. Every word remains BYTE-bound.
Each child map is injective. Adjacent child images intersect at exactly their
200 ordered state words; nonadjacent images are disjoint. No internal wire
aliases another child because it happens to hold the same value.

The parent preserves every child predicate body and formal alias partition.
Four BYTE rounds fit within the unchanged 10,000-constraint Program limit, so
the parent has an actual BYTE Program and its normal Program digest. Its
operation identity includes the absolute round range. A separate
domain-separated, value-free source manifest covers the parent and child
identities, maps and ordered producer/consumer locations. These identities
precede the parent key catalogue, authentication wrappers and any resulting
commitment. Imported maps, Programs, receipts or roots are not factory authority.

Each middle byte has one actual producer and two next-round consumers: a
column-parity XOR and its Theta application XOR. The three joins therefore
require 1,200 producer-to-consumer opening comparisons. A single parent word
entry supplies the actual key, value, bound and signature to both child views;
600 middle entries are reused. Equal values alone are not evidence of a link.

Chi and Iota outputs are scattered through the child catalogue. Producer
locations must come from the sealed maps and actual leaf operand occurrences.
The first three child output sets become internal consumed boundaries; only
the last child's 200 outputs are parent terminals. No output-copy or zero-anchor
layer is added.

## Hosted execution and diagnostic cases

The bounded corpus covers the six aligned four-round ranges in both scalar
roles, coherent corruption of each of the three middle states at both Chi and
Iota outputs, corrupted final Chi/Iota outputs and signed oversized input
words. Later rounds are regenerated from each claimed middle state. The
corrupted state's actual producer must refute while downstream computation
remains consistent.

The native worker independently checks round routing, constants, topology,
maps, exact child projections, identities and references. It executes every
parent leaf in correctness and disproof modes through the upstream interpreter,
then checks actual middle producer/consumer openings. Authentication forgeries
and empty, truncated, prepended or appended witnesses must abort both modes.
Interpreter panics are fatal failures, never successful rejection evidence.

Parent Script costs are measured directly. The benchmark does not infer a
new savings ratio from independent one-round results, and it does not flatten
four Boolean rounds into a catalogue exceeding the existing leaf cap. Source
Script sums exclude transaction framing, control blocks and assertion signature
payloads. Compact execution-record hashes are diagnostic evidence, not proofs.

The existing Program, graph, Script, file, record-stream and process limits
remain in force. Construction and execution stay on the hosted runner; local
checks are limited to pure routing, guards, syntax and synthetic transport.
## Measured hosted result

Source commit `7d2b53dbc25286700f33387637feacd90f0b6f09` passed the dedicated
[hosted run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42229474862)
on its first attempt. Every parent leaf of every case executed in both modes.
The six honest aligned ranges measured the following disproof Script sums;
both scalar roles gave exactly these costs.

| Rounds | Parent leaves | Unique words | Parent Script bytes |
| --- | ---: | ---: | ---: |
| 0-3 | 4,873 | 5,073 | 25,234,673 |
| 4-7 | 4,875 | 5,075 | 25,241,779 |
| 8-11 | 4,871 | 5,071 | 25,228,060 |
| 12-15 | 4,875 | 5,075 | 25,241,834 |
| 16-19 | 4,874 | 5,074 | 25,238,009 |
| 20-23 | 4,877 | 5,077 | 25,248,161 |

These are measured four-round parent costs. The six independent registries
have not been composed into a full permutation, and this run does not measure
an isolated-child savings ratio or a complete permutation footprint.

The 32 cases contain 155,974 parent leaves. Both modes account for 311,948
ordinary executions; another 6,300 malformed/authentication vectors produce
**318,248 Script executions, with 162,274 expected rejections**. All 19,200
middle-word cache entries reused their original parent key/value/bound/signature
and actual producer opening, with **38,400 actual producer/consumer opening
comparisons**. The worker created 162,374 fresh signature entries. Projected
child declarations total 181,574 word occurrences; their difference is exactly
the 19,200 shared entries, which are not additional signatures.

Each coherent middle/final corruption refuted only the selected original
producer. All later child predicates remained consistent with the claimed
state. The two signed oversized-input profiles in both roles refuted exactly
parent leaves 0 and 240. Empty, truncated, prepended and appended witnesses
aborted both modes, and interpreter panics remained fatal. Separate admission
checks rejected 768 catalogue/API mutations, 256 map mutations, 384 source
mutations and 576 cache mutations; these are not additional Script executions.

Maximum observed Script size was 5,663 bytes, stack size 35 items, witness size
31 items and witness payload 600 bytes. Native execution took 154.590 seconds;
the parent took 178.158 seconds. External `time -v` recorded 59,604 KiB peak
RSS; the parent's own observation was 46,702,592 bytes. These are separate
observations, not a combined-memory measurement. Resource caps were unchanged.

All 16 workflows passed on the source commit. The dedicated job passed 16
Python tests, nine registry Rust tests and eight worker Rust tests. The complete
M2 Python suite passed 391 tests. No actual full graph, native worker, proving
job or GPU job ran on the local PC for this component.

The [CI artifact](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42229474862/artifacts/13507472594)
contains reports, dependency lock, test logs and resource logs. Its downloaded
ZIP matched GitHub's digest, and its raw report matched the job stdout report.

- Artifact ZIP: 83,643 bytes; SHA-256 `ff9e6a59160bf6551fb3a6a2dcdace4395d3c9ba0521c0103e70409e27511600`.
- Report: 111,951 bytes; SHA-256 `5b7531f588602a048bca1ab3a5c0c90026ad252f0a7916945ec7e23a2da5ac54`.
- Input manifest: 215,340 bytes; SHA-256 `db700c18f893e888c08d471989990d6e8a90b3188fbc7c302a7281d53947d0c2`.
- Actual compact execution-record stream: 80,313,846 bytes; SHA-256 `34a2ce0ca62b25a954a1383382f1f87de395297606a6e4f40890425c5e3cd6f7`.

The compact stream was hashed during execution and was not uploaded as a raw
vector file. Test keys only were used. No setup, proving, GPU job or transaction
broadcast occurred in this component measurement. Full-permutation, hash,
transcript, proof and production verification flags remain false.

## Remaining boundary

The subsequent [full BYTE permutation](BYTE-KECCAK-PERMUTATION.md) flattens six
sealed blocks into a 29,245-leaf, 29,445-word GraphSpec without raising the
30,000-leaf cap or creating an oversized Program. Its separate manifest identity
and source binding cover all 23 states, 4,600 shared words and 9,200 actual
opening comparisons. It directly measures the full Script cost, memory and
tree/disproof checks; the four-round sums alone do not supply that evidence.
Both hash branches still need absorption,
padding, squeeze and proof-derived message origins. Full transcript and IPA
Script verification, production assertion authority and Bitcoin transactions
remain separate obligations. Existing real sharded proving profiles and header
provers are unchanged.
