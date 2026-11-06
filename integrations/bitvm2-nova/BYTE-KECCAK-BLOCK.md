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
Actual hosted costs, checks and resource observations will be recorded after
the run succeeds.

## Remaining boundary

A complete BYTE permutation using these components would connect six blocks,
bind all five inter-component states, and check full permutation references
and actual global commitment/disproof paths. Both hash branches also need absorption,
padding, squeeze and proof-derived message origins. Full transcript and IPA
Script verification, production assertion authority and Bitcoin transactions
remain separate obligations. Existing real sharded proving profiles and header
provers are unchanged.
