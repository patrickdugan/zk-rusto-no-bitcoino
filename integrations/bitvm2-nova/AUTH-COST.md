# Full-width WOTS verification-format cost experiment

This isolated experiment compares the existing CompactWots4/Bruteforce
verification format with mature full-width Wots4/Listpick verification for BYTE
ports. Implementation and source review are in progress; hosted execution and
measured costs are pending. The completed [scalar-source relation](RETAINED-SCALAR-SOURCES.md)
and every old worker remain unchanged baselines. No savings, complete verifier
or Bitcoin deployment result is claimed by the new code before execution.

## Identical signed messages and explicit packet modes

Both formats retain the same four-byte unsigned message, ten hash-chain
signature elements and 200-byte public key. All eight message digits and two
checksum digits remain authenticated. One full Wots4 signature is generated per
actual source word/value, then converted into both witness views. This preserves
actual signed 256 and u32::MAX diagnostics rather than shortening their message
domain or casting their values to bytes.

| Declared word bound | Baseline packet | Candidate packet |
| --- | --- | --- |
| 256 | Compact full-u32: ten hash elements | Hinted full-u32: ten hash/hint pairs |
| Other supported bounds | Compact full-u32: ten hash elements | Same compact full-u32 packet |

Mode selection is verifier-owned and depends on the declared bound, never the
claimed value. The candidate uses a new registry/leaf identity with explicit mode
and packet width. Source mathematical programs and predicate bodies are unchanged.
All seeds/public keys, key shapes and collisions are checked before the first
signature. Separate case domains prevent a test key being signed for different
case values; the two format views intentionally reuse the same one-message
signature within each comparison.

A hinted packet has twenty stack items; a compact packet has ten. Offsets and
exact witness lengths are prefix sums over actual unique words, not formal
operand positions. Repeated aliases must not add a second packet. Actual opening
capture/cache checks bind mode, packet boundaries, key, full unsigned value,
bound and actual authenticated chunks. Full-signature comparison proves common
conversion provenance; unused host-side hint bytes in a compact packet are not
Script-authenticated data.

## Canonical hints and isolated executor

The pinned [upstream Wots4 API](https://raw.githubusercontent.com/BitVM/BitVM/c620dbfaacebdf778e765a6681985350389973b1/bitvm/src/signatures/public.rs)
and [Winternitz verifier](https://raw.githubusercontent.com/BitVM/BitVM/c620dbfaacebdf778e765a6681985350389973b1/bitvm/src/signatures/winternitz.rs)
provide both full-width views. This experiment changes the verifier adapter,
not the hash-chain/checksum cryptography.

Every hinted digit must be empty for zero or exactly one byte in 1-15. The
211-byte preflight checks all ten positions and preserves the original packet.
It runs before upstream OP_MIN clipping. Rejecting only malformed native
metadata would be insufficient: adversarial raw packets must reject in actual
Script. The leaf's exact total-depth guard precedes all indexed reads.

The frozen executor does not allow OP_MIN (0xa3). A separate isolated executor
adds only that standard opcode and retains the same interpreter, transaction
fixture, minimal-IF settings, CAT-off policy and all limits. The original executor
is unchanged. Actual stack statistics use the pinned executor's combined
main/alt-stack counter; explicit packet admission and measured peaks are both
required. A 64-formal-word cap alone does not admit 64 hinted unique words.

All authentication for every unique slot must finish before the semantic
invalid-value branch. An authentic signed out-of-bound value may yield
correctness=false/disproof=true. A forged hash, hint, checksum or packet must fail
both modes, including when a different word is legitimately out of bounds.
Upstream assert/unwrap raw-witness conversion helpers are never used to classify
adversarial packets; panics and process failures are failures, not rejections.

## Closed source corpus

There are 22 source cases: nine mixed profiles per role and two bindings of one
unchanged BYTE round per role. Supported roles are pallas_scalar and vesta_scalar.
All files, parameters and recipes are closed and independently reconstructed
before signing. No external receipt, caller-provided source map or value-selected
mode can become a source authority.

The mixed program declares a BYTE `a`, radix-2^29 `aux`, and bound-2^18 `sq`.
It checks `conv_reconstruct(aux,a;8)` and `conv_ab(a,a,sq;1)`, preserving the
repeated product alias. Each leaf uses two unique words: twenty witness items
in the baseline and thirty in the candidate. The same BYTE key/signature is
reused at every actual occurrence across both leaves.

| Profile | a | aux | sq |
| --- | ---: | ---: | ---: |
| a0 | 0 | 0 | 0 |
| a1 | 1 | 1 | 1 |
| a9 | 9 | 9 | 81 |
| a255 | 255 | 255 | 65,025 |
| bad-aux | 9 | 8 | 81 |
| bad-square | 9 | 9 | 80 |
| a256 | 256 | 256 | 65,536 |
| a-max | 4,294,967,295 | 0 | 0 |
| auth-order | 9 | 4,294,967,295 | 4,294,967,295 |

The a256 case isolates the BYTE range failure while both arithmetic equations
remain true. Neither a256 nor a-max is truncated or reduced into a canonical
BYTE. Authentication attacks exercise both relative slot orders: forged hinted
`a` beside authentic invalid wide words, and forged compact wide words beside an
authentic invalid BYTE.

The one-round source has 1,417 words, 1,217 leaves and eleven authenticated
layouts. It reuses the unchanged round-0 program. Inputs are synthetic bytes
`(17*i+counter)&255` for i=0..199, with counters 59/44 solely distinguishing the two
role fixtures. These are cost fixtures, not real Nova transcript states.
The honest binding uses the fresh reference assignment. The producer-fault
binding flips bit zero of the first actual produced word (word 200), retaining
all other values, so producer and immediate consumer leaves 0 and 1 are false.
It is not coherent downstream re-witnessing.

The sealed factory validates actual child/program/spec/maps/source digests before
replaying immutable SSA for each closed binding. Hosted source tests construct
exactly two full round graphs, one per role. The native checker independently
rebuilds topology, values, truth, identities and maps; cached metadata is not a
substitute. Twenty-six bounded compiler-body pins cover both roles and exact
alias shapes. Their provenance pins the existing compiler; it is not an
independent compiler-semantics proof.

## Authentication attacks and measurement gates

Both adapters execute all normal leaves and retain the standard empty,
truncated, prepended, appended, forged and cross-wired witness regressions.
Candidate tests cover every hinted digit with ten genuinely malformed encodings,
first/last signature-hash mutations and wrong-format packet replay. Valid empty
zero is not mislabeled as a negative test.

Special tests include the 15-to-16 data-hint clamp alias in signed u32::MAX and
the checksum digit 15 in message 9 (checksum 0x6f). A checksum-isolating mutation
advances a message hint/hash-chain position consistently, leaving all ten
individual public-key endpoints valid while making the checksum inconsistent.
It must fail both modes with otherwise valid operands and with the authentic
invalid wide operands of auth-order. The attack is derived under each case's
own key/signature, not borrowed from a different case.

Before any graphs/keys, closed accounting bounds 71,392 calls at 220 record bytes
each: 15,706,240 bytes, under the unchanged 134,217,728-byte hard limit. Normal
accounting is 4,904 leaves across both adapters and both modes, 19,616 calls.
The current source-derived full prediction is 54,888 calls with 45,080 expected
rejections; these are not measured results. Actual census must match after direct
execution. Compact per-leaf rows retain ordinal, C/D Script sizes, witness items
and payload bytes within the unchanged one-MiB summary cap.

The hosted job retains 256-MiB Python-test and 512-MiB execution address-space
limits, bounded CPU/wall time, two build threads, 100,000 Script bytes, 1,000
combined stack items and 520 bytes per stack element. Sources and configured
binary are hashed before/after; all four integration manifests/locks and compiler
inputs are included as observations, not a binary/source-equivalence attestation.
Artifacts contain reports, text and lockfiles, without keys, seeds, proof binaries
or raw execution streams. Local checks are limited to syntax/format, pure closed
recipes and bounded body hashing; no local full graphs, native builds, signing,
Script execution or proving are required.

This cost-only experiment measures actual authenticated leaf scripts, their
complete disproof streams and actual opening comparisons. It constructs no new
Taproot forest and makes no candidate membership/production-binding claim. All
such flags remain false, with zero tree calls. Applying the adapter to larger
compositions requires actual tree integration and another review.

Report Script, witness and stack costs separately under identical before/after
accounting. Do not infer a runtime improvement from hosted timing noise, or whole
permutation/verifier fit from one round. Stop on any accepted forgery, source or
opening mismatch, unexpected abort, panic, cap failure or honest negative result.
Full proof decoding, scalar/MSM/IPA, the complete Nova/Spartan transcript/equations,
production assertion binding and the Bitcoin transaction graph remain open.
