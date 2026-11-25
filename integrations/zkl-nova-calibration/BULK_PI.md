# ZKL-20: bulk lifting with raw context lookup

Separate circuit/profile from ZKL-19. The public canonical syntax arena and authenticated log remain. RawLookup(ctx,i,A) retrieves the unshifted binder type from its defining prefix. The zero case checks the binder of an extension; the successor case checks a prior RawLookup in the parent with i-1. Var typing checks WF(ctx), RawLookup(ctx,i,A), and Lift(A,0,i+1,T). Lift(t,k,d,u) has explicit unsigned 16-bit cutoff and distance, with the same d propagated through all recursive premises. Under a binder the body cutoff increases by one; its domain cutoff is unchanged. In the above-cutoff variable case the output index equals input+d. Substitution under a binder requires exactly d=1, not an arbitrary shift. No field wraparound can satisfy a false bounded addition: operands and results are canonical small integers. Zero and maximum legal distance are tested; an inert sort must also reject an out-of-range d.

Proof of bulk equivalence (design-level): by induction on terms, L(k,a+b)=L(k,b) composed with L(k,a) for nonnegative a,b; for a variable below k both preserve it, while one at/above k remains at/above k. Sort is unchanged. Pi/Lam use the same cutoff in the domain and cutoff+1 in the body; App uses the same cutoff in both branches. Hence bulk lifting is repeated unit lifting whenever intermediate and final indices fit the bounds. Raw lookup identifies the stored binder by induction over backward parent traversal; lifting by i+1 recovers the previous lookup relation. This is not a mechanized Lean metatheorem or universal circuit audit.

## Native paired diagnostics

All 192 reused ZKL-19 public diagnostic roots replay with both relations, all new selected equations checked. 64 each, same seeds 22000..22063 / 23000..23063 / 24000..24063. No causal or statistical generalization claim, no learned policy. Counts are certificate sizes, not minimal derivation lengths.

| family | old rows | bulk rows | better/equal/worse roots | fit64 | fit128 | fit256 | fit512 | max bulk rows |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| weakening | 4260 | 4231 | 23/15/26 | 36 | 58 | 64 | 64 | 148 |
| dependent_app | 14829 | 11678 | 58/0/6 | 6 | 18 | 45 | 64 | 318 |
| conversion | 6217 | 6226 | 17/15/32 | 20 | 43 | 64 | 64 | 196 |
| total | 25306 | 22135 | 98/30/64 | 62 | 119 | 173 | 192 | 318 |

Six fixed fixtures: 189 rows, all 32 selectors, 5,153 different-signature predecessor replacements rejected by native integer equations. 4,096 direct vs repeated-shift comparisons, 42 false-distance mutations rejected, native zero/max boundary checks pass. 507 static linear equations in the new program; the circuit additionally constrains the lift/replacement field to 16 bits. Small fixture total increases 185->189 due to memoization and new lookup signatures. Public object total on the paired roots decreases 11315->9701.

## Circuit measurements pending

Depth 6 covers the six small fixtures. Depth 9 covers one preselected stress example from the already inspected dependent family: seed 23004, 112 objects and 270 rows. Fixed shape per process, with independently generated Nova public parameters per depth. The CI regenerates all fixture and program digests, tests every honest row and actual recursive/compressed proof verification. It tests coherent wrong references, false distances, malformed arena and state-binding attacks. No cost or proving time is claimed before CI passes. Only the 25,945 raw constraints per step for the measured ZKL-19 depth-six profile are known at registration. Larger capacity is its own cost profile. No claim of witness privacy, arbitrary Lean theoremhood or production security. No paid GPU compute.

ZKL-19 measured receipt: https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45586627039/job/139109768491 (six proofs, 185 rows, 25,945 raw constraints/step, 11,472-byte compressed proofs, 31 forged constraint witnesses rejected). Preserve this baseline.
