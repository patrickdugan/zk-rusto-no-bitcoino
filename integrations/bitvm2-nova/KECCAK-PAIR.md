# Two adjacent Keccak rounds under one registry

`keccak_pair.build_keccak_pair` freshly constructs two adjacent existing Boolean
round programs, then combines their complete catalogues into one immutable
`GraphSpec`. The default slice is Keccak-f[1600] rounds 0 and 1. It closes one
internal shared-state boundary; it is not a full permutation, hash, sponge,
Nova transcript, proof verifier or production assertion adapter.

No cryptographic round implementation, default compiler or source pin changes.
The standalone round builder and its previous evidence remain intact. Full pair
construction/binding are Linux/GitHub guarded before allocation; local tests use
only tiny synthetic children. Actual full-pair graphs, WOTS signing and native
execution remain hosted work.

## Exact boundary quotient

Round 0 has 9,602 leaves / 11,202 words; round 1 has 9,604 / 11,204. Sharing
exactly 1,600 ordered middle bits gives **19,206 leaves / 20,806 global words**.
All words have bound two and there are no Fr field declarations. A parent
`Program` is never created: each child retains the 10,000-constraint cap, while
the merged catalogue stays within 30,000 leaves / 100,000 words.

Global endpoint names are `boundary/{input,middle,output}/l{lane}/b{bit}`,
lane-major `lane=x+5*y`, least-significant bit first. Other words are namespaced
`child/0/<original>` or `child/1/<original>`. Even equal-valued zero constants
remain separate words. Only each first-round output and its same-position
second-round input share a global slot/key.

The factory checks:

- every child word is mapped once and its map is injective;
- the maps intersect at exactly the 1,600 declared ordered ports, with no other
  shared words, missing slots, reordered bits or changed bounds;
- all declared child/composite words have a leaf validity/use path;
- every leaf preserves ordered occurrences and its repeated-wire partition;
- regenerating alias expansion plus predicate yields exactly the original body
  bytes and digest;
- every original leaf is retained, and merged bodies have no extra/duplicate
  records or same-digest/different-byte collision;
- input and output endpoint sets remain separate from the middle boundary.

Injectivity matters because the existing alias-expansion body depends on repeated
wire positions. Numerical global indices can change, but collapsing two distinct
child words would change that body and invalidate its statement.

## Sealed topology and assignment binding

The public factory accepts only first-round index, caller-owned context, field
role and operation ID. It builds both children internally. There is no child
JSON/program/receipt/map input that can authorize a pair.

`spec.program_sha256` is explicitly a domain-separated, versioned **composite
manifest hash**, not an oversized `Program.digest()`. The manifest commits the
consecutive rounds, context/role/operation, child Program/catalogue IDs, namespace
rules and complete word/leaf/endpoint maps. The expected GraphSpec ID comes from
this live factory before its JSON is transported to the native oracle. Manifest
and source-map getters return copies; the spec is immutable.

`pair.bind(initial_state, claimed_middle=None, claimed_output=None)` freshly
builds assignments and verifies unchanged child shapes. It rejects conflicting
values mapped to the same global word. A coherently wrong middle uses that same
corrupted state as the consumer's input and recomputes the second round, while
the first producer still has a false output gate. No detached copy can hide the
boundary mismatch.

The default producer output leaves are 8,002..9,601 and the consumer round starts
at 9,602. Each middle bit is consumed once in column parity and once in theta:
1,600 shared words imply 3,200 producer-to-consumer opening comparisons. These
are source-derived counts until executed hosted evidence is recorded below.

## Bounded native checks

The hosted benchmark emits five fresh TEST-ONLY signing sessions: honest pair,
coherently wrong middle, wrong final output, signed Boolean value 2 and signed
u32 maximum. JSON input is streamed with a five-case / 32 MiB cap. The honest
selection executes every distinct authenticated shape plus a small spread of
producer/consumer endpoints; it does not execute 1,600 endpoints solely to count
them. The Rust helper independently checks **all** ordered shared slots and their
actual WOTS opening chunks.

Every honest disproof leaf is compiled and measured. Complete offline Taproot
trees are built for the honest catalogue and coherent malicious catalogue, with
the actual producer disproof executed and checked for membership. Separate
signing sessions preserve one message per test key. Existing empty, truncated,
prepended and appended witness regressions, forgeries, cross-wire signatures,
and catalogue/context/role/key substitutions are retained.

Boolean catalogues have no `field_valid` leaf. The native substitution test now
removes an actual Boolean predicate in that case, instead of mistaking a no-op
removal for an accepted mutation. Existing arithmetic catalogues still exercise
their original field-validity removal. No Script bytes or witness behavior
change for earlier catalogues.

The workload retains 100,000 bytes per Script and 256 MiB aggregate compiled
Script bytes per tree, with hosted 512 MiB / 300 CPU seconds / 300 wall seconds.
Python full-pair tests/generation have separate 256 MiB / 180-second caps. A cap
failure would be reported as a bounded negative result, never evidence of
rejection or deployability. Interpreter panics fail the run.

This stage also tightens the previous retained benchmark's private summary
formatter to require its already-recorded `native_proofs_verified=0` and
`container_framing_checked_by_this_call=false`. Its API/output and mathematical
checks remain unchanged; three tiny formatter tests pass.

## Remaining boundaries

Twelve pairs still leave eleven inter-pair state boundaries. Full absorption,
Keccak-256 suffix/padding, all 24 rounds, squeeze and Nova's two-digest scalar
challenge framing/reduction are not supplied by this pair. A flat 24-round union
would exceed the current caps, so it is neither built nor claimed.

Commitment order remains acyclic: external context -> topology -> keys/registry
-> compiled Script leaves -> Taproot root/output -> future assertion transaction.
The resulting registry/Taproot root is not fed back into its own input context.

One global WOTS key per shared word supplies a consistent fixture opening, but
does not alone stop its secret-key holder signing conflicting values. Production
single-assertion/signature binding and the Bitcoin transaction graph remain
required. Full hash/transcript/proof/production flags stay false. Aggregate Script
totals exclude control blocks, assertion signatures and transaction framing.

## Executed hosted evidence

Code commit `f85621920ca8598d2397f4d516353eee5293b501` passed all nine workflows,
including the complete **258-test Python suite**. The
[linked-pair job](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42163639381/job/127714885585)
passed 14 dedicated tests in 22.176 seconds, including the four actual full-pair
tests that were skipped locally. It then executed five signed sessions,
**116 Script vectors / 86 expected rejections**, and **27 native catalogue,
registry, signature-count and ordinal rejections**.

| Measurement | Actual value |
| --- | ---: |
| Complete catalogue words / leaves | 20,806 / 19,206 |
| Aggregate disproof Script bytes | 90,256,702 |
| Largest disproof Script | 4,975 bytes |
| Honest leaves selected for engine execution | 24 |
| Shared words / producer-consumer opening comparisons | 1,600 / 3,200 |
| Selected producer control block | 481 bytes |
| Global public-key / signature payload per session | 4,161,200 bytes each |
| TEST-ONLY signatures across five sessions | 104,030 |
| Peak stack / witness items | 35 / 31 |
| Maximum witness payload | 600 bytes |

Every leaf was compiled and measured; 24 selected honest leaves exercised all
authenticated shapes and sampled endpoints. The complete 1,600-word linkage was
checked separately through actual shared signature chunks. Peak witness counts
include malformed length regressions; a normal three-slot gate has 30 signature
items. These totals exclude transaction framing, control blocks and assertion
signatures from the Script sum, and are not transaction weights or fees.

The coherent wrong-middle session re-witnessed the consumer from a flipped first
middle bit. Only producer ordinal **8002** was false; its actual signed Script
disproof succeeded and passed membership in the complete malicious catalogue
tree. Both honest and malicious complete trees were built, with matching byte
totals and separate test keys/roots. Neither root is production assertion
authority.

The honest catalogue ID is
`8ab3993cb532afa83c95c955c27db66ace1a9d6120435e69c5275af3b9718261`.
Its leaf-stream SHA-256, using u32 LE Script lengths followed by exact Script
bytes in ordinal order, is
`9584830c6944aa783df73159999cc3bba5a1081657cc2f76dd89c10c2516553d`.

The signed run took **133.105726144 seconds** and `/usr/bin/time` recorded
**201,456 KiB (206,290,944 bytes) peak RSS**, within the stated hosted cap.
Python generation took **3.642235014 seconds**, with **68,841,472 bytes peak RSS**.
Its five-case corpus was **18,688,602 bytes**, SHA-256
`db0799faa0c65aabdd53a0607b83db2f0496764efe01c68dc7fe5957264bf478`.
No full pair, WOTS signing, native build or graph execution ran on the local PC.

The earlier arithmetic, sumcheck and retained mathematical composition workflows
also passed unchanged. No interpreter panic or cap failure was counted as a
successful rejection. Full permutation/hash/transcript/proof and production
binding flags remain false; twelve pairs do not yet constitute an authenticated
24-round graph.
