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

## Measured full-parent result

Source commit `69e329d380a0a2dbd426002f46afd2f552456046` passed the dedicated
[hosted run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42236982737).
Every one of the eight complete parents measured **151,432,516 disproof Script
bytes**, with 29,245 leaves and 29,445 unique words. Both scalar roles gave
exactly this cost. This directly measures the joined parent and all 23 round
boundaries; it is not inferred from four-round sums.

The result is 117,002,940 bytes below the unchanged 268,435,456-byte component
Script limit. Individual Scripts remained at most 5,663 bytes. Accounting
excludes transaction framing, control blocks and assertion signature payloads.
The older Boolean permutation remains the bit-port baseline; a conversion-
complete full Boolean BYTE-port baseline was not measured here. No full
Boolean-to-BYTE savings ratio is claimed.

All 233,960 parent predicates executed in both modes: 467,920 ordinary calls.
Another 2,576 malformed/authentication vectors and 16 selected-tree C/D rechecks
give **470,512 Script executions, with 236,544 expected rejections**. These
include ordinary opposite-mode false outcomes, not only malformed inputs.

Every parent checked 4,600 cached state entries against 9,200 actual consumer
openings. Corpus totals are **36,800 cached entries and 73,600 opening
comparisons**: 28,800/57,600 inside blocks and 8,000/16,000 across blocks.
There were 235,560 fresh signature entries, one per unique parent word.
Projected declarations total 243,560 block-word and 272,360 round-word
occurrences; shared occurrences are not additional signatures.

Both scalar roles gave the exact diagnostic failures:

- Coherent state-4 Iota byte-1 changes refuted only full leaf 4,870, round 3's
  local producer 1,216; every later round was consistently re-witnessed.
- Final Chi byte-8 changes refuted only full leaf 29,049, round 23's local
  producer 1,024.
- Signed oversized initial words refuted exactly round-0 leaves 0 and 240.
- Honest cases had no false predicates in any of their 24 round partitions.

Empty, truncated, prepended and appended witnesses remained aborts in both
modes. Native panics remained fatal failures. Separate checks rejected 192
catalogue/API mutations, 64 map mutations, 96 source mutations, 144 cache
mutations and 96 tree mutations; these are not additional Script executions.

## Actual complete component trees

All eight trees contain the entire 29,245-leaf disproof catalogue. Their
measured byte sums and ordered Script stream hashes match the live parent
registries exactly. The selected C/D rechecks are included in the totals above.

Honest and final-Chi cases select leaf 29,049 with a 481-byte control block.
Middle-Iota cases select leaf 4,870 and oversized cases select leaf 0, each
with a 513-byte control block. Both tree depths are exercised. Honest selected
correctness succeeds and disproof fails; the six malformed-assertion cases
give the opposite outcomes at their selected refuting leaf.

Each live opening rejects 12 mutations: altered Script, truncated/appended
control, Merkle branch, catalogue, internal key, leaf version, ordinal, output
key, parity, registry and root. These are component membership checks against
freshly constructed roots. They are not independently pinned production
assertions, funded transactions or presigned challenge paths.

## Resources, CI and evidence

Native execution took 284.463 seconds; the parent took 348.014 seconds.
External `time -v` recorded 293,728 KiB peak RSS (300,777,472 bytes); the
parent's own observation was 110,010,368 bytes. These are separate observations,
not a sum or simultaneous-process measurement. The native run passed under
its unchanged 512-MiB address-space, CPU and wall-time caps. Maximum stack
size was 35 items, witness size 31 items and witness payload 600 bytes.

The dedicated job passed 16 Python tests under the unchanged 256-MiB test cap,
nine registry Rust tests, five component-Taproot Rust tests and eight worker
Rust tests. The complete M2 Python suite passed 407 tests. Sixteen source
workflows passed at `69e329d`; the remaining byte-kernel job hit its existing
180-second timeout because broad discovery included the new full-graph tests.
Workflow-only commit `bcb8c9df0975aaaab5d4548f0db8cc7ea702680d` restricted that
job to its original two kernel files and all 16 kernel tests without changing
time or memory caps. Both workflows triggered by that commit passed.
Dedicated graph jobs and complete discovery retain full graph coverage.

The initial `1b12d06` attempt failed before native compilation or execution.
A test MagicMock retained child Programs in its argument history and exhausted
the test cap. The fix uses a non-retaining direct counter, preserves the
per-conversion 10,000-constraint guard and adds a tiny weak-reference regression.
The successful hosted rerun establishes fit after that correction. Failed
attempts contribute no successful execution evidence.

The [CI artifact](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42236982737/artifacts/13512788415)
contains the report, compact input manifest, dependency lock, test logs and
resource logs. Its downloaded ZIP matched GitHub's digest; its raw report
matched the job's stdout report.

- Artifact ZIP: 37,544 bytes; SHA-256 `3c7a99278449ece07212dff4865d8155f7aaeadc06f3c1f093481c66822789cc`.
- Report: 76,030 bytes; SHA-256 `74e4964ee871bd611ce607b7f45627e59c1fd4b93c34a5f67a3bc867a6a92b12`.
- Input manifest: 52,378 bytes; SHA-256 `6ede528f3116e9f24be75381a9d4fae6a23e45c5ad5ef0b5624b4f52d0244293`.
- Actual compact record stream: 97,349,024 bytes; SHA-256 `eb26632f2f64d004bb9cd18823b286026c55810980cea28c86034ba9069b2c32`.

The record stream stays below the unchanged 128-MiB cap and is hashed during
execution, not uploaded as a raw-vector file. Test keys only were used; no
setup, proving, GPU job or transaction broadcast occurred in this experiment.
The full-24-round Script-conformance flag is true. Generic full-hash,
transcript, proof, production-verifier and independently pinned-root flags
remain false.

## Next hash boundary

The next bounded composition supplies independently framed LO/HI permutations
to the unchanged uniform 512-bit reducer. It must explicitly share the same
96 message-byte origins, retain 104 branch-private framing/padding/capacity
BYTE anchors per branch, and link the 64 actual digest bytes to the reducer
in the original little-endian order. A three-component route keeps both full
children unchanged and appends a separate reduction/framing tail. Its whole
cost, memory, source links and forest/disproof evidence require their own
measurements. Exact proof/message origins and complete transcript/IPA binding
remain separate from that bounded hash experiment.
