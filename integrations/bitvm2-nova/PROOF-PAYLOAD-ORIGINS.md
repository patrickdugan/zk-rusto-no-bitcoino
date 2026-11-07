# Retained proof-payload scalar-origin experiment

The isolated legacy-only worker passed hosted conformance on
`aa221e66bbb7e18316000aaff5a44b871769c1dc`
([run 42340933774](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42340933774)).
It executed 51,978 Script calls, including 33,402 expected rejections. The one
complete honest payload/scalar source measures 61,598,099 disproof Script bytes.
The reviewed [design note](PROOF-PAYLOAD-ORIGINS-PLAN.md) defines the restricted
statement and remaining proof-verifier obligations. This does not resume the
unpublished point-authentication cost candidate or verify a Nova proof.

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
limb/auxiliary repeats. Hosted source admission and actual opening captures
confirm these counts in every one of the fourteen cases.

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
proof acceptance. The measurements below establish only this closed experiment's
execution and resource fit.

## Measured hosted result

| Complete honest component | Words | Leaves | Disproof Script bytes |
| --- | ---: | ---: | ---: |
| Payload BYTE tape | 12,664 | 12,664 | 21,240,083 |
| 169 Pallas/Q scalar encoders | 9,295 | 2,873 | 23,682,308 |
| 119 Vesta/P scalar encoders | 6,545 | 2,023 | 16,675,708 |
| Total | 28,504 local / 19,288 global | 17,560 | 61,598,099 |

These are aggregate disproof Script bytes. Assertion signatures, witness bytes,
control blocks and transaction framing are excluded. There is no matched new
optimization in this milestone and no claimed reduction from another source's
total. The unchanged legacy implementation remains the baseline. All 18,576
measured cost rows compile C and D and check D=C+1.

The honest source executes all 17,560 leaves in both C/D modes. The thirteen
other cases execute 1,016 selected leaves in total, 50-92 per case, including
every false predicate, affected scalar/byte occurrence and fixed controls.
Their individual costs are targeted costs and cannot be presented as complete
source totals. All 14 cases perform the complete opening-material pass, even
where Script execution is targeted. The native worker creates and uses 270,032
test-only full signatures across those cases.

Normal execution has 37,152 calls and 18,576 expected rejections. Standard
witness/authentication guards add 14,826 calls, all expected rejections, giving
51,978/33,402 overall. Native admission separately rejects 378 malformed inputs;
those are not added to Script counts. There are eleven proper disproof checks
of false predicates and zero abort leaves in this corpus. Empty, truncated,
prepended, appended, changed-hash and foreign-key witnesses remain covered;
no panic, timeout or process failure receives rejection credit.

Canonical coherent eval_W changes and opaque commitment changes have no false
local predicates. The four scalar modulus/modulus+1 cases fail the appropriate
canonical field guard. The width case fails tape ordinal 952; the shorter-row
claims fail tape ordinals 48 and 560. Actual signed BYTE 256 and u32::MAX each
fail both tape ordinal 5,639 and Pallas encoder ordinal 1,767. An independent
pure unsigned reconstruction checks these exact selections and outcomes without
building local graphs or running a native/Script worker.

Normal global peaks are 14,912 Script bytes, 95 combined-stack items, 90 witness
items and 1,800 witness payload bytes. Guard-inclusive peaks are respectively
14,912/95/91/1,800. The honest guard-layout census is 9/17/17. Every observed
limit fits the unchanged policies; no Taproot tree or forest is constructed or
verified by this experiment.

Native execution takes 50.033655561 seconds. The Python parent's elapsed time
is 66.303097696 seconds and its reported peak RSS is 52,752,384 bytes. GNU time's
outer-command observation is separately 66.45 seconds and 159,156 KiB maximum
RSS; these are different process/resource scopes. The execution record is
9,776,957 bytes, below both its 14,571,556-byte derived bound and unchanged
134,217,728-byte hard cap. The complete canonical report is 366,446 bytes below
the 703,704-byte derived bound and unchanged 1,048,576-byte cap.

## Tests and evidence reconciliation

The dedicated hosted workflow passes all 18 Python tests (6.200 seconds), all
19 Rust tests (0.01 seconds), compiler body pins and rustfmt. The broad primitive
workflow also passes: 497 Python tests collected, 485 passed and 12 explicitly
skipped, in 723.496 seconds. All 23 workflows for the tested code commit
`aa221e66bbb7e18316000aaff5a44b871769c1dc` passed. Two earlier attempts
stopped before Script execution: the first exposed an ambiguous Rust loop index,
fixed to usize; the second exposed a snapshot assumption about an absent optional
requirements.txt, fixed without inventing a dependency input. Mandatory transcript
requirements, all five crate sources/manifests/locks, recursive compiled inputs,
and all source/work/resource limits remain enforced. Neither failed attempt is
counted as completed worker/Script conformance, measured costs or successful
Script rejection evidence.

The root and independent reviewer reconcile all 42 component ledgers, exact
metric folds, cost rows, raw-domain cases, coverage and false scope flags. The
strict validator accepts the actual observation and rejects 24 contradictory
mutations of that observation. Canonical report JSON equals parsed artifact
stdout; root separately reconciles exact direct-job stdout bytes to artifact
stdout. Group descriptors remain transported identity observations checked
against manifest/source pins, rather than a new independent graph rebuild.

The snapshot has 162 files / 4,362,342 bytes: 157 exact Git blobs at the tested
commit plus five matching generated lockfiles. Recursive literal Rust inputs
are included. Worker bytes/hash are a configured executable observation, not
binary/source equivalence attestation.

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Artifact 13560764874 ZIP | 105,722 | `956365d9e38a7cc27e0cd357043da88ed8fc8b8932ec3156db00fb777efc212a` |
| Canonical conformance report | 366,446 | `c1291be4bb0bd4191258bff667a34cd1fe2a77bda9efaad13e4ea8347bcc2b19` |
| Direct/artifact stdout | 428,485 | `f7f654c92aa12a3bda346c7b350914e9928b64628d26f8811ea791d5f25f0575` |
| Input manifest | 3,047 | `08efd47a33010debde4b2efeba3e18feb1aa6719f4494d5568e0f8fd1c6a2b20` |
| Compact execution record | 9,776,957 | `17ba52e5ffecb52f3380f190af33ff637dd9e727de9dfb7020041e982e28b83c` |
| Configured worker observation | 3,503,400 | `6f9642f089917007644820c200caf0072f82ceb20b84f49febd01a7e79ff2397` |

The canonical snapshot file-list SHA-256 is
`93763fae3f6e1b70249d1e7acdecc808d004212b75cdecf38233a49e42c341d0`.
The native record is hashed by the direct worker and not exported. The artifact
contains reports, manifest hashes, dependency locks and logs; it excludes raw
case inputs, proofs, key material, witness streams and executables. There are
zero proving, GPU, setup, transaction-broadcast, native-proof-verification and
tree calls. Whole-proof authentication and verification remain open as stated
above.
