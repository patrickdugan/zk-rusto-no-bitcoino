# Retained proof-payload scalar-origin experiment

Implementation is in progress in a separate legacy-only worker. Source and pure
benchmark tests pass; hosted graphs, native execution, actual openings and Script
costs remain pending. The reviewed [design note](PROOF-PAYLOAD-ORIGINS-PLAN.md)
defines the restricted statement and its remaining proof-verifier obligations.
This does not resume the unpublished point-authentication cost candidate.

## Retained profile and source relation

The source uses the 12,664-byte payload of the existing 13,220-byte NHT4 fixture.
It excludes the 556-byte public header. Three components comprise the payload
tape and canonical encoders for 169 Pallas/Q and 119 Vesta/P scalars. Physical
container-offset IDs share each of the 9,216 scalar BYTEs exactly with its actual
encoding input; scalar limb and split-auxiliary identities remain role-specific.

The tape has 1,383 Program constant constraints and 11,281 deterministic
`word_valid` GraphSpec leaves, preserving the separate 10,000 Program-constraint
and 30,000 GraphSpec-leaf caps. The encoder batches add 2,704/1,904 arithmetic
constraints and 169/119 field guards. The source totals 17,560 leaves, 28,504
local words and 19,288 global words. A complete material pass has 35,128 opening
occurrences, including 9,216 cross-component BYTE comparisons and 6,624 internal
limb/auxiliary repeats. These remain source-derived counts until hosted checks.

All 119 prefix values are fixed for this retained maximum-width serialization
profile. General admission allows different widths at 101 of those prefixes;
the new experiment does not replace that decoder. The final 17 `zn` scalars
also require 431 high-zero BYTEs beyond field canonicality. The 78 compressed
commitments remain opaque BYTEs.

## Closed coverage and preserved authentication

Fourteen closed cases include one complete honest source and thirteen targeted
cases. They cover canonical eval_W changes in both roles, each role's modulus
and modulus+1, a `zn[0]` width failure, shorter outer-row prefix claims, opaque
commitment changes in both roles, and actual signed BYTE 256/u32::MAX. A target
selects every false/abort leaf plus controls and affected occurrences, with a
128-leaf cap across all three components. Coherent canonical and opaque-point
changes can pass this local relation; that does not establish proof acceptance.

The actual frozen compact registry/interpreter is used. Each case preflights
the entire 19,288-word global seed/public-key set before its first signature.
Source/catalogue/packet admission for all cases precedes key generation. Actual
captures must bind the physical source, key, bound, unsigned value and signature
chunks, with immutable shared openings and aliases. Full four-byte messages and
all checksum digits remain; raw out-of-bound diagnostics are never cast to BYTE.

Standard guards retain empty, truncated, prepended, appended, changed-hash and
foreign-key witnesses on honest layouts and actual targeted leaves. Exact
witness depth precedes indexed reads. Panics, worker failures and timeouts are
failures, never successful rejection evidence. No new WOTS algorithm, hinted
adapter or checksum-forwarding implementation is introduced by this feature.

## Before-execution budgets

One honest source requires 35,120 C/D executions. The conservative corpus bound
is 66,842 calls including targeted checks, standard guards and a 1,024-call
reserve. At the independently sized 218-byte record maximum this is
14,571,556 bytes, below the unchanged 134,217,728-byte record cap. Guard IDs must
remain bounded owned ASCII for that serialization bound.

At most 19,224 lossless three-integer cost rows use 403,704 bytes; the metadata
reserve is 300,000 bytes, totaling 703,704 below the one-MiB summary cap. Every
row compiles both scripts and checks D=C+1. Full or selected ordering determines
the ordinal. Actual counters and both derived/hard bounds must reconcile.

This larger tape has a new bounded 450,000-node pre-parse limit, with independent
419,000-node tape and 179,488-node scalar-component upper bounds. Actual encoded
counts are checked before writes and natively before allocation/key work. Old
parsers are unchanged. Existing byte/depth/string limits and Script, component,
stack, element, memory, CPU and wall limits remain in place.

Local checks are restricted to pure parsing/math/schema, syntax/format and bounded
compiler hashing. All graph, key, native and Script work runs in the dedicated
hosted workflow. No new proving job or GPU work is needed. Evidence artifacts
contain reports, manifest hashes, logs and lockfiles, without raw cases, proofs,
keys, witness streams or executables.

## Explicit unverified boundaries

The experiment does not build a tree or establish membership. Whole-blob SHA-256,
authenticated EOF, public-header-to-`zn` equality, point decompression, production
assertions and Bitcoin transaction/dispute construction remain false/unverified.
`public_state_to_zn_script_bound` is explicitly false; a canonical, width-valid
height change may still pass the local source relation.

A decoded reference and matching metadata hashes are not Nova proof verification
or Script blob authentication. Scalar encoding does not establish transcript or
IPA/MSM equations. Commitment transcript subobjects require affine encodings and
the compound folded/derandomized instances described in the design note; raw
32-byte compressed proof points are not interchangeable with those inputs.

Stop on an accepted malformed opening, origin/alias mismatch, unexpected abort,
panic, cap failure or any attempt to present this retained profile as general
proof acceptance. Actual runtime, cost and resource fit are still unmeasured.
