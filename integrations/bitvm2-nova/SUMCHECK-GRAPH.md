# Two proof-derived outer sumcheck rounds

`sumcheck_graph.py` lowers outer Spartan rounds 0 and 1 for both retained-proof
roles into separate globally authenticated arithmetic graphs. It is a bounded
composition step toward the transparent Nova SNARK verifier. The previous
constant-anchored `spartan_checks.round_trace` and default arithmetic builders
remain unchanged. No trusted setup or final compression backend is added.

## Statement and shared state

Published Nova 0.76.0 starts each outer sumcheck with claim zero and uses cubic
rounds. The primary role uses Pallas scalar Q; the secondary uses Vesta scalar P.
The compressed row contains ascending coefficients `[c0,c2,c3]`, omitting `c1`.
For each round, the graph reconstructs

```
c1 = prior - 2*c0 - c2 - c3 (mod q)
next = c0 + r*(c1 + r*(c2 + r*c3)) (mod q)
```

The first equation gives `P(0)+P(1)=prior`. Six existing byte-convolution products
implement the two cubic evaluations. Only `initial/claim` is a protocol constant:
nine zero limb anchors. Twelve internal convolution endpoint anchors at 8192
are also retained. Coefficients and challenges are canonical field ports.

The first evaluated result is checked against `round/0/next`. That exact nine-wire
tuple is the second round's prior claim, including its use in reconstruction of
`round/1/c1`. It is never replaced by another zero, a constant copy or an
independently signed field. Each canonical scalar has one declared field-validity
path. Equal-valued source fields remain distinct named wires.

Both constructed programs have 3,737 words, 2,877 original constraints, 31
canonical fields and 384 convolution columns. The authenticated adapter appends
31 field-validity leaves, for 2,908 leaves per role. These are graph counts;
signature-inclusive Script costs require actual hosted native execution.

## Proof and transcript provenance

`build_outer_sumcheck_graphs(decoded, expected, bindings, native_trace, *,
expected_trace_sha256, poseidon_parameters)` accepts admitted proof data and
typed, independently pinned metadata. It performs fresh strict
`replay_production` internally, then selects the first two actual compressed
outer rows and ordered `r_x` challenges. It accepts no replay receipt, claimed
success flag, arbitrary context, source override or claimed-output override.

The immutable factory objects expose the program and round/port descriptions;
assignment and provenance getters return copies. The graph context commits the
complete expected policy, published crate digest, proof/key/dimensions, key
bindings, native trace, Poseidon parameters, role/field/phase and exact source
paths. Coefficient descriptors retain the admitted inner-proof and NHT4 byte
offsets. Challenge descriptors retain the `p` absorption and following `c`
squeeze event, after all 19 primary or 14 secondary tau squeezes. Absorption
contains exactly 96 coefficient bytes, without `c1` or Vec framing.

Primary executable sources are Nova 0.76.0 `src/spartan/snark.rs:259-286`,
`src/spartan/sumcheck.rs:87-125` and
`src/spartan/polys/univariate.rs:137-194`, under the published crate digest
already pinned in `SOURCES.json` and `proof_codec.py`. Source inspection and a
separate small field calculation checked all four actual round rows against the
retained native capture.

## Explicit open input boundary

The graph proves the polynomial relation **given its source ports**. A context
hash and source path do not constrain a signed coefficient or challenge to equal
the value decoded from proof bytes or computed by Fiat-Shamir in Bitcoin Script.
Tests deliberately re-witness a coherent coefficient/challenge substitution:
the same-context arithmetic graph can still pass. This is an honest negative
result about the current input boundary, not proof acceptance.

With source ports fixed, changing the first next claim while coherently
re-witnessing the entire second round leaves the first producer equality false.
The shared authenticated claim cannot detach at the boundary. The hosted corpus
exercises this stronger attack as well as a wrong final result, isolated source
changes, a nonzero initial anchor, noncanonical p/p+1 fields and oversized signed
limbs. Existing exact witness guards are retained.

The benchmark distinguishes a false predicate from an aborted predicate.
Addition's canonical-input checks use `VERIFY`, so an input equal to p aborts
both correctness and disproof modes; a noncanonical output with canonical inputs
is an ordinary false equality. The original modular native relation assumes
canonical admission and cannot classify those malformed inputs by itself. The
first hosted corpus exposed that reference mismatch. The corrected reference
records such aborting arithmetic leaves as inapplicable to a Boolean-mode check,
while retaining p/p+1 cases and their explicit `field_valid` disproofs. Validly
signed oversized words remain disputable through the registry decoder's validity
flag; forged signatures instead fail authentication in both modes. No Script or
witness guard changes are made for these distinctions.

`source_ports_script_bound`, challenge/proof-parser Script binding, complete
proof verification and complete BitVM2 verification remain false. Full proof-byte
decoding, exact hash/sponge and transcript composition, remaining sumcheck rounds
and terminals, curve scalar multiplication/MSM lowering, production assertions
and the transaction graph remain separate work.

## Bounded independent execution

`bench_sumcheck_graph.py` reads independently pinned small fixtures directly and
calls the sealed factory; it accepts no native or replay result receipt. Its
hosted-only resource guard precedes fixture reads and corpus construction. It
streams at most 32 cases / 32 MiB, atomically replacing output only after a
complete successful write. The current corpus has two complete measured graphs
and eighteen adversarial cases, each with a separate deterministic TEST-ONLY
WOTS signing session.

The existing Rust registry oracle measures every honest disproof leaf and
executes every distinct authenticated predicate/alias shape, all initial anchors
and all shared claim uses. A scoped adapter checks nine shared WOTS word openings
and 378 adjacent convolution carries per role, malformed witness lengths,
signature forgeries, cross-wire signatures and catalogue/field/context/key
substitutions. Interpreter panics fail execution; they never count as rejection.

The same adapter builds complete offline Taproot commitments for both honest
graphs, comparing the full Script byte sum/hash against the measured ledger.
For each coherently wrong shared claim it also commits the malicious TEST-ONLY
registry, executes the producer disproof and verifies membership of that exact
Script. Honest and adversarial sessions use fresh keys; no WOTS key signs two
different messages. Roots remain test observations, not production assertion
UTXO authority. No Bitcoin transaction, signing service or broadcast is created.

Small Python tests cover actual source rows, canonicality and both coherent
boundary studies. Exhaustive all-leaf Script execution is guarded for hosted CI.
Native execution and complete-catalogue cost measurement run only on hosted
runners under 512 MiB / 300 CPU seconds / 300 wall seconds; Python corpus work
has separate 256 MiB / 180-second caps. No native build, bulk generator/matrix
access, large MSM, proving or GPU job runs on the local PC.

## Executed hosted evidence

Code commit `abd2d29afe0c872dcd0b98cf9c109d78864700d0` passed all eight workflows.
The [linked-sumcheck job](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42156333714/job/127691262909)
passed 17 dedicated Python tests, then executed **20 signed cases / 1,204 Script
vectors / 728 expected rejections**, plus **54 native catalogue/registry
substitution rejections**. It generated one signature per wire per fresh test
session, totaling **74,740 TEST-ONLY signatures**. The complete Python suite
passed 227 tests; existing M2, WOTS, Keccak and all original catalogue goldens
also passed on this code commit.

| Role | Words | Authenticated leaves | Executed honest leaf shapes/boundaries | Aggregate disproof Script bytes |
| --- | ---: | ---: | ---: | ---: |
| Primary / Pallas scalar Q | 3,737 | 2,908 | 83 | 42,398,317 |
| Secondary / Vesta scalar P | 3,737 | 2,908 | 83 | 42,351,061 |

Every leaf was compiled and measured. The 83 selected honest leaves per role
cover all **71 distinct authenticated shapes**, aliases, initial anchors and
shared-claim uses; they are not a claim that every leaf was executed through
WOTS. The separate Python test executed every original arithmetic leaf. Script
totals include exact witness guards and word recovery, and exclude transaction
framing, control blocks and assertion signatures. These are fragment costs,
not complete-verifier weights or fees.

Native execution checked **18 shared claim-word openings** and **756 adjacent
convolution carry links**. The producer equality is ordinal **1442** and its
round1 linear-coefficient consumer is ordinal **1446**, in both catalogues.
Both coherent shared-claim attacks passed the remaining second-round checks and
produced an actual successful disproof at the first producer. The disproof
Scripts also passed membership against the complete corresponding malicious
test-registry Taproot roots. The two honest catalogues and two malicious
catalogues each had a complete tree construction; all selected controls were
**417 bytes**. Malicious and honest roots differ because their signing sessions
use separate keys, while catalogue IDs and Script byte totals stay identical.

The honest leaf-stream SHA-256 values (u32 LE length followed by exact Script
bytes, in ordinal order) are:

- Primary: `9c9204bed01b53d57031550b18300f06154e103a64009f9c80fda6d0dec87230`.
- Secondary: `8acbc352e9d63382438144505adec557ba3d2866f5e8bb2f88c8fcf5a19fb163`.

The signed native run took **82.475601447 seconds**, with **69,976 KiB
(71,655,424 bytes) peak RSS**. Its largest Script was **46,617 bytes**, with
**275 peak stack items**, **270 witness items** and **5,400 witness payload
bytes**. Python generation took **3.100032728 seconds** and **37,748,736 bytes
peak RSS**, emitting **17,896,802 bytes** for the 20-case bounded corpus. Its
SHA-256 is `516c6a093b4b0158f393600cfd5b610bd913019c31dd3014561ce3185044e16e`.

All p/p+1 cases retained explicit field-validity refutations. Their diagnostics
record arithmetic ordinals 9 and 1441 as canonical-input `VERIFY` aborts, excluded
from the Boolean-mode checks; no abort or interpreter panic was counted as a
successful disproof. Signed oversized-word cases also passed their disproofs.

All complete-verifier, proof-source Script binding, Fiat-Shamir Script binding,
production root/UTXO/transaction binding flags remain false. The successful
coherent source-substitution study remains an explicit limitation. These tests
establish the linked arithmetic fragment and selected authenticated disproofs;
they do not establish a spendable Bitcoin transaction or complete Nova verifier.
