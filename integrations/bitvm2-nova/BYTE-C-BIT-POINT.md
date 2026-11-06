# Challenge bit and conditional point relation

This bounded extension links the actual next sumcheck challenge from
[the nine-component rho/c chain](BYTE-RHO-CHAIN.md) to one conditional point
relation, `E=A+P; R=A if b=0 else E`. It retains the existing chain as the
baseline and adds separate scalar-bit and point components. Hosted evidence
for this extension is pending. This document's counts are source-derived;
they are not a new measured Script cost or a complete verifier result.

## Exact source boundary

The scalar bridge consumes the nine actual Uniform result limbs, using the
same global identities, bounds, signatures and actual opening coordinates.
Nine unchanged `bits` predicates reconstruct all 255 output bits with widths
`29,29,29,29,29,29,29,29,23`. The input limbs retain their full radix-2^29
bounds, so unused high bits cannot disappear during a byte conversion. The
bridge declares no independent canonical field: the original upstream Uniform
`field_valid` leaf 244 remains mandatory. Public bit indices are little endian;
formal `bits` operands are most significant first within each limb.

The verifier fixes the selected index 0-254 in the fresh source identity. Only
that bound-2 bit crosses from scalar role to the corresponding curve base
role: `pallas_scalar -> pallas_base`, `vesta_scalar -> vesta_base`. Equal Pasta
moduli across the curve cycle never determine this semantic mapping. The
selected bit has five actual point predicate occurrences.

The point component includes the complete unchanged convolution addition
`E=A+P`, even when `b=0`. It appends three Boolean infinity-selection predicates,
four gated coordinate comparisons, one infinity-form predicate, and two
canonical result-coordinate guards. The original 6,116 arithmetic predicates,
35 canonical fields, aliases and body bytes are explicitly projected. Its
original canonical guards move after the eight new arithmetic predicates.
Result coordinates are authenticated asserted ports, not new SSA producers.

| Source | Local words | Leaves |
| --- | ---: | ---: |
| Unchanged rho/c chain | 148,401 | 147,043 |
| Scalar bits | 264 | 9 |
| Complete addition and selector | 7,498 | 6,161 |
| Eleven-component source | 156,163 | 153,213 |

Exactly nine upstream limbs and one selected bit are additionally shared. The
fresh fixed-count key profile therefore has 155,107 unique global words and
1,056 declaration reuses. The old nine-component profile and all old helpers
remain unchanged. New native code is isolated in `point-oracle`, reusing the
existing Script library and pinning Halo2curves 0.9.0 for the independent curve
oracle. Native group-decoding rejection is distinct from actual Script disproof.
The new native checker also requires a static body-hash table from the unchanged
verifier-owned predicate compiler, keyed by base role, public arguments and
formal alias partition. This pins the baseline compiler outputs; it does not
claim an independent reimplementation of that compiler. A first-observed body
hash or a caller-supplied catalogue is insufficient for this check.

## Closed adversarial corpus

Both retained transcript roles have three main profiles: honest, coherent
changed selected bit, and coherent `c+p, q-1` scalar alias. Two honest profiles
execute all leaves. Four coherent profiles use explicitly reported targeted
execution, while their full sources, assignments, measurements, key pools and
trees still require validation.

The scalar alias is a deliberate canonicality attack. It retains
`X = (c+p) + p*(q-1)` and, for these retained inputs, stays below 2^255 while
flipping bit zero. All byte decompositions, quotient products, carries, bits
and the selected point are re-witnessed. All integer and bit predicates can
remain true; the authenticated original canonical guard must reject. The
closed constructor accepts neither an imported graph/assignment nor an
arbitrary alternative. A separate 634-word/254-leaf private probe merges fresh
Uniform and bit children; its sole canonical guard moves from 244 to 253.

Private probes are separately keyed and measured: the existing twenty
frame/absorb cases, twelve point-edge cases, two scalar-alias cases, and
eighteen selected point negatives. The twelve Script edge probes use bits
`0,1,0,1,0,1` on each curve's six point pairs. A tiny independent Jacobian
oracle covers both bits on all pairs, 24 cases; that is not a claim that all
24 have full Script execution. Selected negatives cover invalid unused `P`,
wrong `E`, wrong selected result/flag, nonzero infinity coordinates, an
auxiliary flip, signed invalid bit 2, and coordinate encodings `p,p+1`.

Raw native predicates classify ordinary true/false values separately from
numeric-domain aborts. Every executed ordinary leaf must have a defined
verdict. Noncanonical coordinate tests select actual field-validity disproofs;
an unselected arithmetic abort or a native point decoder error cannot count
as a successful Script rejection. The signed bit-2 fixture uses only its
explicit private invalid-message profile. No private key/signature becomes
authority for the main forest.

## Verification and stop conditions

The dedicated hosted job must pass fresh source/map/program/catalogue binding,
canonicality, field-role identity, opening joins, complete catalogue and tree
cost accounting, independent Halo2 group checks and actual WOTS Script tests.
It retains empty, truncated, prepended and appended witness regressions, exact
witness-length guards, forged openings and cross-wire negatives. Interpreter
panics, process failures and unexpected aborts fail the job.

All existing limits remain: 100,000-byte leaf Script, 1,000 stack/witness items,
520-byte elements, 256-MiB component Script, 1.25-GiB global Script, sixteen
components, depth nineteen, 8-MiB maps and 128-MiB compact records. Python
conformance uses 256 MiB/480 seconds; native execution uses 512 MiB with the
existing CPU and wall limits. New guard/tree string identifiers have a stricter
32-byte bound; old 64-byte identifiers are unchanged. The closed record upper
bound is 132,472,024 bytes, below 134,217,728. Actual bytes must also be measured.
Any failed bound must be corrected or documented, never raised to force a pass.

No local full graphs, native builds, key generation, Script execution or
proving are required for this milestone. Existing local transparent proofs
remain available; no proof binaries are published by this change.

## Remaining verifier work

This source relation does not implement scalar multiplication, MSM, full IPA,
the surrounding sumcheck equation, a complete Nova/Spartan transcript, proof
byte/span/length/EOF admission, NHT4 Script decoding, compressed-point origins,
generator/key origins, production assertion binding or a Bitcoin transaction
graph. `A` and `P` are external ports. Those gaps prevent any complete verifier
or deployment claim.

The full-transcript size projection in [NEXT.md](NEXT.md) remains a design
constraint. Adding this boundary after measurement would establish additional coverage;
it would not establish full-verifier savings or Bitcoin practicality.
