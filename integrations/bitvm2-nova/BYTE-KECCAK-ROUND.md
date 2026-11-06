# Opt-in byte Keccak round with producer-linked outputs

This hosted experiment implements exactly one Keccak-f[1600] round with the
existing byte-v1 predicates. It retains the Boolean round as a separate
baseline. One-round correctness does not establish a composed permutation,
hash, transcript, Nova SNARK or production BitVM2 verifier.

## Routing and terminal producers

The input has 200 BYTE words ordered by lane `x+5*y`, then little-endian byte
index 0-7. Theta, Rho, Pi, Chi and Iota follow the existing 64-bit word reference.
For a lane rotation `s=8*q+r`, output byte j uses a at `(j-q) mod 8` and b at
`(j-q-1) mod 8`; a nonzero r uses `byte_rol(a,b,out;r)`. Byte-aligned rotations
only route existing references. Pi sends source lane x+5*y to
`y+5*((2*x+3*y) mod 5)`. No routing depends on assignment values.

Chi produces fresh output words. A nonzero Iota round-constant byte replaces
the corresponding lane-zero Chi terminal with a fresh public-mask output.
All 200 final words are distinct, disjoint from inputs, and never consumed by a
later gate in this round. Every post-input word has exactly one preceding
producer. The sealed source map identifies each terminal's actual producer
ordinal and operand occurrence; outputs are not the last 200 allocated words.

The Program operation identity includes the explicit round index after the
caller prefix. Round constants alone are insufficient: rounds 5/22 and 6/20
repeat constants. The sealed manifest records both operation identities and
binds the round-specific source maps. Numeric openings for equal values remain
equal; expected Program/catalogue identity admission and registry-specific WOTS
keys provide their respective domain boundaries. This does not supply the
future production assertion binding.

This avoids an output-copy layer and its zero wire in the new byte backend.
The existing Boolean backend's zero anchor and 1,600 output-copy gates remain
unchanged. BYTE boundaries use distinct `byte-state` identities so they cannot
silently share a key with the older bound-two state words.

The byte schedule has 160 column-parity XORs, 40 Theta rotations and 40 D XORs,
200 Theta application XORs, 176 Rho joins and 600 Chi gates. Iota adds one mask
gate for each nonzero little-endian round-constant byte n. Thus one round has
`1216+n` leaves and `1416+n` words, with n from 1 to 4. These source counts do
not imply a measured multi-round cost.

## Complete Boolean BYTE-port baseline

The comparison uses the same 200 external input bytes and 200 external output
bytes. A fresh legacy Boolean round retains every original word, predicate,
body, zero anchor and output copy. A separate bounded child connects each BYTE
port through one BASE auxiliary and eight existing boundary bits, using the
unchanged MSB-first `bits(8)` and `conv_reconstruct(8)` predicates.

The children share exactly 3,200 input/output bit words. The parent appends 400
BYTE words, 400 auxiliaries and 800 bridge leaves. Its complete catalogue has
`10401+popcount(RC)` leaves and `12001+popcount(RC)` words. This exceeds the
10,000-constraint Program limit, so the sealed factory composes GraphSpecs
instead. Both child Programs retain their existing limits, as does the
30,000-leaf graph bound. Imported Programs, maps and result receipts are not
constructors for either sealed round factory.

There are 3,200 distinct bridge bit words. The 1,600 input bits each feed two
legacy consumers; the 1,600 output bits come from their existing output-copy
producers. The native checks therefore compare 4,800 actual bit openings and
400 auxiliary openings per baseline. The output BYTE source is operand 1 of
its reconstruction leaf. Value equality alone does not establish these links.

This is an isolated same-BYTE-port round comparison. A full Boolean permutation
keeps its intermediate boundaries as bits and would not pay these BYTE bridges
at every round. Per-round ratios must not be multiplied into a whole-permutation
savings claim; complete composition and joins require separate measurements.

## Output-consumer probe and adversarial cases

A separate diagnostic registry copies all 200 source outputs with public-mask
zero predicates. It reuses the exact source output public keys, values,
signatures and actual producer openings, then introduces fresh copy outputs.
The probe's Script cost is reported separately from the round cost.

The hosted corpus has 64 source/probe pairs: all 24 byte rounds in both scalar
roles, four coherent wrong-output cases, four signed oversized-input cases and
eight complete Boolean baselines. Wrong Iota and Chi terminal bytes must refute
only their actual producer while their copy probes remain coherent. A valid
signature over an out-of-domain u32 is handled through the existing decoder
flag, not mistaken for a canonical byte. Authentication forgeries and empty,
truncated, prepended or appended witnesses must still abort both modes.

All source and probe leaves execute in correctness and disproof modes through
the upstream interpreter. Expected outcomes, native word-level round reference,
SSA, producer maps, source identities and all preserved child projections are
checked independently. Native panics are fatal failures, never successful
rejections.

Full raw vectors would be unnecessarily large. The worker instead hashes
bounded compact execution records containing exact Script/witness digests,
identities, modes and outcomes. The existing 128-MiB record cap is separate from
the ordered compiled Script byte sums; it does not cap or stand for the amount
of Script processed. Fresh case snapshots and the manifest are hashed before
the direct configured resource-capped worker runs. No external result receipt
is loaded as verification authority.

Actual hosted costs and execution counts are recorded after the run succeeds.
Script accounting excludes transaction framing, control blocks and assertion
signature payloads. Existing full-permutation and framed-LO Boolean evidence,
header provers and real k-sized proving profiles remain separate. Four-round
blocks, a complete byte permutation, both hash branches, proof-derived message
origins, full verifier composition and production assertions/transactions remain
future work.
