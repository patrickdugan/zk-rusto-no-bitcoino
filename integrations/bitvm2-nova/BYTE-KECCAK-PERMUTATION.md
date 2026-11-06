# Opt-in full BYTE Keccak permutation

This hosted experiment joins all 24 Keccak-f[1600] rounds in one GraphSpec and
one authenticated registry. It constructs a permutation relation between
external 200-byte input and output states. Sponge framing, a complete hash,
proof-derived message origins, Nova transcript/IPA verification, production
assertions and Bitcoin transactions remain separate obligations.

## One bounded catalogue

The factory regenerates six aligned sealed four-round blocks and projects each
into the parent. Their exact quotient has 29,245 leaves and 29,445 BYTE words,
within the existing 30,000-leaf and 100,000-word GraphSpec limits. A Program with
29,245 constraints would violate its 10,000-constraint limit and is not created.

The parent program identity is explicitly a versioned, domain-separated
manifest hash. The manifest commits to the child program/source/catalogue
identities, exact mapping hashes and admitted predicate catalogue before the
parent GraphSpec is built. A separate source hash then binds the final parent
catalogue. Parent source, registry, key, Script or tree identities cannot feed
back into the earlier program manifest. Caller context precedes all of them.

Complete raw source maps are bounded separately from compact manifests. The
one-MiB run-manifest/result limits and 32-MiB case-file limit remain unchanged.
No imported Program, map, root or execution receipt admits a sealed permutation.
Factory construction and binding regenerate one block at a time and retain
small immutable descriptors, rather than six full child bindings.

## All 23 authenticated state boundaries

Adjacent blocks share exactly their 200 ordered endpoint words; nonadjacent
block images are disjoint. The five inter-block states add 1,000 shared word
entries and 2,000 producer/consumer coordinates to the 18 joins preserved inside
the blocks. All 23 boundaries therefore contain 4,600 shared state words and
9,200 actual producer-to-consumer opening comparisons.

Every word remains BYTE-bound. All child predicate bodies and formal alias
partitions remain exact. Producer locations use the actual scattered Chi/Iota
outputs and their formal occurrences, not a final-word suffix. Each next-round
input byte has both its C-parity and Theta consumers. Only the final state-24
words are terminal; there are no new output copies, zero anchors or aliases
created from equal values.

Binding accepts exactly 200 immutable input bytes, an optional immutable tuple
of 23 intermediate state claims and an optional final claim. Each later block
is freshly witnessed from the actual selected previous state. The independent
honest reference always starts from the original input and ignores diagnostic
overrides. Conflicting shared assignments reject.

## Hosted conformance boundary

The bounded native corpus has eight full parents: both scalar roles, each with
an honest case, a coherent state-4 Iota corruption, a final Chi corruption and
a signed oversized input word. State 4's Iota corruption targets byte 1 because
round 3's constant byte 0 is zero. The source factory tests separately cover
Chi and Iota claims at every inter-block boundary.

The native worker independently derives child projections, actual small-child
Program digests, full manifest identities, source hashes, routing, constants,
SSA, complete maps and word-level references. Every parent leaf executes in
correctness and disproof modes. Middle state entries reuse actual parent keys,
values, bounds and signatures; every actual producer opening is compared with
both next-round consumer openings. Authentication forgeries and empty,
truncated, prepended or appended witnesses must abort both modes. Interpreter
panics are fatal failures.

Full component Taproot construction runs on the hosted runner using the existing
streaming complete-left-filled constructor. Selected membership and disproof
checks retain only the selected Script/path, with the existing per-leaf,
component-tree and depth checks. This is Script execution plus component
commitment evidence, not a funded or presigned
Bitcoin transaction or production assertion authority.

The full parent must fit the existing 256-MiB compiled Script budget and the
512-MiB native address-space cap. CPU, wall-time, file, witness, stack and
128-MiB compact execution-record limits remain unchanged. Compact records retain
case/leaf identity, mode, Script hash, witness hash and expected outcome only
after actual execution. No raw-vector file or external acceptance receipt is
used as verification authority.

Actual full-parent Script costs, opening counts, tree paths, execution totals
and resource observations will be recorded after the hosted run succeeds.
Independent four-round sums are not a full-permutation measurement. Script
accounting excludes transaction framing, control blocks and assertion signature
payloads.
