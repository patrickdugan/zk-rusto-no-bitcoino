# Opt-in byte-convolution multiplication

`convolution.py` supplies an alternative integer multiplication argument for
both Pasta fields. The original Horner builder and the `m2`/`compact-v1`
compilers remain the default and retain their golden leaf streams. Select the
new builder explicitly, or call
`point_add_trace(..., multiplication_backend='convolution-v1')`.

This is an arithmetic/WOTS catalogue experiment. It does not implement the
complete Nova verifier, a production assertion protocol or Bitcoin transactions.
The independent production Poseidon milestone is recorded separately in
[POSEIDON.md](nova-oracle/POSEIDON.md).

## Integer argument and Script bounds

The three field values a,b,c retain their original nine radix-2^29 limbs and
canonical field declarations. Each is linked to 32 little-endian bytes through
seven crossing-byte splits and nine limb reconstruction equations. The final
limb reconstructs only 24 bits; bits256..260 cannot hide above the byte array.
The original canonical-field check also excludes bit255 and values at/above p.
Splitting a crossing byte before shifting avoids four-byte ScriptNum overflow.
Byte decompositions are reused by wire identity, including true same-wire
squaring; equal witness values never choose an alias or topology.

The quotient q is an unsigned 32-byte **integer**, not a declared field value.
Inline AB blocks contain at most four byte products. Public p-byte times
q-byte blocks contain at most eight terms, skipping only public zero modulus
bytes. Each of the 64 radix-256 columns checks

```
AB_i + e_i + 255*8192 = c_i + PQ_i + 256*e_(i+1)
```

Here c_i is zero above byte31, e_i is range-checked below16384, and both endpoint
carries are anchored to8192. Setting t_i=e_i-8192 gives
`AB_i+t_i=c_i+PQ_i+256*t_(i+1)`. Multiply by256^i and sum all64 equations:
interior carries cancel, and the anchored endpoints give `a*b=c+p*q` over
integers. Canonical c is consequently the unique field product. Removing either
anchor invalidates that argument; an explicit test makes all64 columns of
`1*1=2` pass with a forged initial carry and refutes its anchor.

AB blocks are bounded below2^18, PQ blocks below2^19, and encoded carries below
2^14. Even the admitted maximum column shapes stay below2^23; reconstructed
limbs stay below2^29. All numeric opcode operands remain four-byte ScriptNums.
Byte products use eight derived Boolean decisions and enabled additions,
comparisons and conditionals. No multiplication opcode, OP_CAT or OP_SUCCESS
is introduced. Public shape validation precedes caching, including nested
Boolean/integer argument aliases.

## Authentication and accounting

The standalone fixed-claim adapter has a distinct compiler domain and preserves
the exact witness-depth guard before indexed openings, per-wire hashes and
field/context/program/claim identity. The WOTS adapter reuses the existing
global key registry, bounded word recovery, canonical field leaves, alias
expansion and authenticated catalogue identity. One key/signature belongs to
each named global wire. Shared carry slots and their signature blocks are
checked across all63 adjacent column pairs. Production one-time key lifecycle,
assertion binding and transaction commitments remain separate work.

| Graph | Words | Arithmetic constraints | Canonical fields | WOTS leaves |
| --- | ---: | ---: | ---: | ---: |
| Convolution multiplication | 634 | 486 | 3 | 489 |
| Complete convolution point addition | 7,476 | 6,116 | 35 | 6,151 |
| Original Horner multiplication | 2,586 | 274 | 259 | 533 |
| Complete original point addition | 33,588 | 3,616 | 3,363 | 6,979 |

The standalone compiler is an honest negative against compact-v1:

| Graph | Original m2 bytes | compact-v1 bytes | Convolution bytes | Extra over compact |
| --- | ---: | ---: | ---: | ---: |
| Pallas multiplication | 1,268,152 | 1,083,022 | 1,193,846 | 110,824 |
| Vesta multiplication | 1,268,152 | 1,083,022 | 1,201,722 | 118,700 |
| Pallas complete point addition | 16,554,753 | 14,148,063 | 15,345,751 | 1,197,688 |
| Vesta complete point addition | 16,554,753 | 14,148,063 | 15,448,139 | 1,300,076 |

Fewer global signed words alone do not establish a WOTS Script saving. Native
WOTS costs must come from the actual hosted compiler/interpreter ledger, not
extrapolation from this census. The generator measured all four original golden
leaf streams unchanged in3.465seconds at54.1MB peak working set, without an
enforced local memory cap. It generated44 bounded registry sessions in a
17,326,299-byte input, SHA-256
`e9e7b5594ed9799a448048908789ecec3736530b71aff04c26e6ae5efaade59a`.

`bench_convolution.py` measures every fixed-claim disproof leaf once on the same
M2 inputs, operation IDs and contexts, retaining all four original golden leaf
stream hashes. Its point ledger includes every multiplication and dispatch
branch. The existing global-registry workflow separately compiles/measures every
WOTS leaf of both complete point graphs and both multiplications, then compares
the candidate with the baseline executed in that same job. Every multiplication
leaf is executed; point execution covers each distinct authenticated predicate,
alias layout and decoder-bound shape:97 samples per curve, including11 alias
shapes. It does not execute every point leaf.

Artifacts `convolution-fixed-ledger.json`, `convolution-registry-execution.json`
and `convolution-wots-comparison.json` record actual totals, largest leaves,
length-prefixed stream hashes, signatures, coverage and comparisons. All totals
include exact witness guards and the respective opening/word-recovery code.
They exclude transaction framing, control blocks and assertion signatures.
These are aggregate Script bytes, not transaction weights or fees.

## Executed WOTS comparison

Source commit `c3de2fc08bc391e39f5a33bcfe019e49e732f5ad` passed all seven
workflows. [Registry run42138502256](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42138502256)
compiled and measured both catalogues in the same job with the same pinned
interpreter, input claims and accounting:

| Graph | Baseline Script bytes | Convolution Script bytes | Reduction |
| --- | ---: | ---: | ---: |
| Pallas multiplication | 16,798,073 | 6,993,315 | 58.37% |
| Vesta multiplication | 16,798,073 | 7,001,191 | 58.32% |
| Pallas complete point addition | 219,498,908 | 88,586,200 | 59.64% |
| Vesta complete point addition | 219,498,908 | 88,688,588 | 59.59% |

The largest multiplication leaf falls from49,538 to22,639 bytes. The largest
point leaf remains79,381 bytes. Across the executed candidate corpus, peak
combined stack remains485 items; maximum witness remains480 items/9,600 bytes.
The enabled stack limit remains1,000. Neither a maximum-leaf nor a maximum-stack
improvement is claimed for the complete point graph.

The candidate passed3,778 Script vectors including1,987 expected rejections,
54 native catalogue/API rejections, four native shape tests and126 shared carry
links. Its44 signing sessions generated55,264 test signatures once per global
wire and took108.504seconds under the512MiB/300second process cap. The unchanged
baseline passed2,538 vectors including1,331 rejections,56 native rejections and
510 accumulator/final links; all four baseline Script stream hashes matched.
The separate M2 job passed172 Python tests,74 independent halo2curves cases,
10,884 original Script vectors with1,630 rejections and19,216 compact vectors
with9,958 rejections. No upstream interpreter panic counted as a rejection.

The `bitvm2-nova-global-registry-evidence` artifact contains both complete
native ledgers, the comparison JSON, length-prefixed leaf hashes, vector hashes,
dependency lockfile and resource records. The native numbers above include
repeated WOTS recovery in every leaf, but still exclude transaction framing,
control blocks and assertion signatures. The fixed-claim regression above
remains real: this optimization benefits the authenticated catalogue and does
not replace the smaller compact-v1 fixed-claim default.

## Verification boundary

Tests cover independent integer products, arbitrary unsigned quotients,
coherent wrong products, both carry anchors, all original261 bits, crossing
splits, top-bit reconstruction, same-wire squaring, complete point dispatch,
false point claims, field canonicality, opening/identity substitutions and
empty/truncated/prepended/appended witnesses. Native catalogue tests reject
malformed shapes and wrong formal-slot bounds. The hosted WOTS run additionally
checks forged and moved signature digits and all shared carry links. Upstream
interpreter panics fail the run; they never count as successful rejection.

Local work is bounded Python and source/format checking. All Rust builds,
signature generation and native Script execution stay on hosted runners.
The convolution native process is capped at512MiB and300seconds. No proving,
GPU job, trusted setup, transaction, deployment or header-prover change is part
of this milestone. Matrix evaluation, the complete IPA generator MSM, full hash
Script composition and production Bitcoin assertion/transaction binding remain
unfinished.
