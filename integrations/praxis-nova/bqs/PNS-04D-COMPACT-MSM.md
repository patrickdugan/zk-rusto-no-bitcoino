# PNS-04D — compact group arithmetic and fixed-base IPA MSM

2026-11-24. Nova 0.76 Pallas/Vesta, Spartan/IPA. CPU research only.
No alternative proof system. No whole-verifier or witness-encryption claim.

## Verified prior boundary

CI run 45381516633 on adc360ba completed both jobs successfully:
https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45381516633
The native settlement fold had 4,996 step constraints, three payouts,
10,912 compressed proof bytes, 18,984,584 verification-key bytes, 0.263 s
fold, 4.076 s compression, 0.099 s native verify (CI host). Actual native
IPA, transcript export and joint group relation succeeded on both Pasta
curves; wrong a_hat and challenge mutations rejected. The measured one-round
IPA transcript prefix alone has 3,929,941 Pallas or 3,932,263 Vesta
Boolean unknowns. The old standalone Boolean multiplication count
was also confirmed exactly (1,003,490 / 1,002,332 unknowns).

## Compact group law

The new compactAdd retains the five fixed-shape branch cases of PNS-04C:
left identity, right identity, inverse, ordinary, doubling. For canonical
admitted inputs, identical x coordinates imply equal or opposite y.
The inverse branch requires equal x and excludes equal nonzero y;
the doubling branch requires equal x and equal nonzero y. Other finite
pairs require distinct x. Equality indicators use the sum of squares of
eight radix-2^32 limb differences. This nonnegative integer is < 2^67;
a Boolean nz and a bounded slack force exact equality/non-equality.
One-hot branch flags and conditional output-coordinate pins enforce
the exceptional cases. A finite regular output has canonical coordinates.

For regular pairs, use a canonical slope lambda and directly constrain
four modular polynomial residuals (only the indicated branch activates
each residual):
* ordinary: lambda*(x_Q-x_P)-(y_Q-y_P)=0 mod p;
* doubling: 2*lambda*y_P-3*x_P^2=0 mod p;
* regular: lambda^2-x_P-x_Q-x_R=0 mod p;
* regular: lambda*(x_P-x_R)-y_P-y_R=0 mod p.

Each polynomial is encoded with three radix-2^86 limbs. Allocate a
258-bit biased signed quotient k (bias 2^257), a 255-bit residue r,
and five signed 94-bit carries. Six convolution columns constrain the
integer identity f=p*k+r, with zero initial and terminal carry.
The Boolean branch flag conditionally forces every residue bit to zero
via a bit-sum row. Inactive residue values need no canonicality, since
only the active branch's congruence matters. Absolute product coefficient
weight <=5 and linear weight <=3. For any binary assignment the
column residual is bounded by
18*(2^86)^2 + 5*(2^86) + (2^86+1)*2^93,
strictly below the BN254 scalar modulus. Thus modular BQS satisfaction
implies exact integer column equations and telescoping gives the
stated congruence. Nonzero denominators ensure unique slopes. Output
membership follows inductively from the complete affine group law;
external points must still be admitted. No host-computed acceptance bit.

## Fixed-base specialization

For pinned constant generators G, generate table [0,G,...,(2^w-1)G]
as verifier-owned constants. No witnessed table entries. A Boolean
one-hot selector per window matches the actual digit bits. Coordinate
limbs and the infinity flag are linear combinations of constant table
values. The resulting coordinate bits are canonical and on-curve
by exact selection, so they need no second range witness.
Window widths 4,6,8 were executed. For w=8 each window allocates
256 selectors + 511 coordinate/flag bits + 5,639 add unknowns,
i.e. 6,406 new unknowns and 149 equations. The fixed-base Horner
variant shares doublings across all terms; shifted tables trade
more constants for eliminating those doublings. Variable L/R bases
retain witnessed group-addition precomputation and checked digit lookup.

| Component | Prior | Compact |
|---|---:|---:|
| Complete affine addition unknowns | 14,297 | 5,639 |
| Addition equations | 494 | 133 |
| One-round synthetic IPA unknowns | 9,645,610 | 3,117,520 |
| Synthetic IPA equations | 333,154 | 75,026 |
| Synthetic IPA additions | 647 | 506 |

The synthetic full-width fixture uses known related test generators and
chosen challenges. Positive and incorrect-a_hat negative have identical
shape and counts; all 17 failing rows in the negative occur at the
terminal group equality. See results/ipa-compact-fullwidth.json.
Component checks: 22 positives, 18 negatives, both Pasta curves.
All were directly executed. Native transcript-bound compact replay
is registered in CI, pending this checkpoint.

Two-term fixed MSM, full-width scalars, shifted constants:
4-bit: 789,248 variables, 18,560 rows, 2,048 table entries.
6-bit: 534,404 variables, 12,642 rows, 5,504 entries.
8-bit: 409,984 variables, 9,536 rows, 16,384 entries.
The unshifted 8-bit variant has 1,808,456 variables in this tiny case
because it pays 248 shared doublings for only two generators; it uses
512 entries. This overhead amortizes for large n.
Counts include lookup variables and group-law rows but exclude initial
scalar allocations. Row linear-form term counts are in compact-msm.json.

## Native key shape and feasibility gate

src/key_shape.rs inventories the actual native compressed verifier-key
layout, including both Spartan padded dimensions and actual generator
vector lengths, by a typed bincode mirror with bytewise roundtrip.
This is local fixture metadata extraction, not untrusted input parsing.
The padded batch evaluation domain is max(padded_cons,padded_vars),
as the native Spartan batch evaluation pads W and E to the larger
length. Confirm actual IPA round lengths during end-to-end extraction.
CI runs this for the existing PNS-01 settlement and the tiny
SquarePlusFive (2 -> 9 -> 86), and emits price_key_shapes.py receipts.
The inventory has not yet executed at this checkpoint.

For fixed n+1 bases, 8-bit unshifted scheduling allocates
204,992*(n+1) + 248*5,639 Boolean unknowns for the fixed group/lookup
portion. The variable group portion costs 5,639*(78*(2*ell)+252)
+ 1,051*64*(2*ell), ell=log2(n), and two final compact additions.
These exact schedule counts omit scalar coefficients, input admission,
transcript, Spartan and Nova folding. Example n=32768 alone has
6.72 billion fixed-group unknowns, even after compact encoding.
It is an illustrative domain size, not an actual key measurement.
Do not extrapolate 7.88 GiB Praxis figures from a smaller Groth16
relation to this direct Nova verifier.

## Reproduce and continue

    node integrations/praxis-nova/bqs/compact_msm_test.js
    node integrations/praxis-nova/bqs/ipa_compact_fullwidth.js
    cargo run --release --manifest-path integrations/praxis-nova/Cargo.toml -- --square-shape /tmp/pns
    node integrations/praxis-nova/bqs/ipa_joint.js /tmp/ipa-transcripts/Pallas --compact

PNS-04E: inspect actual key-shape and native compact joint CI receipts.
Optimize constant lookup row widths and Keccak-wide reduction
(the latter still uses the old Boolean reduction). Investigate
algebraic verified fixed-base window decompositions with fewer
per-generator operations and their constant/coefficient storage.
The linear-size IPA MSM is still the fundamental scale problem.
Do not pretend a host MSM, a claimed digest, or random unchecked
batch relation verifies the commitment. Continue the native Spartan
outer/inner and batch/matrix binding program in parallel.
Keep Pallas/Vesta and Nova-only. No full-size Praxis ciphertext or
proof-authorized Bitcoin settlement before feasibility and soundness gates.
