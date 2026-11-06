# Unsigned 512-bit Pasta reduction argument

This optional arithmetic graph supplies the wider reduction needed after Nova's
two Keccak squeeze branches. It takes externally supplied bytes; it does not bind
them to a hash, proof or transcript. The existing multiplication builder,
32-byte quotient, Script predicates, compiler defaults and goldens are unchanged.

## Integer statement and bounds

For 64 unsigned little-endian bytes representing X, the new factory constructs
`X = c + p*q`, where c is a canonical Pasta field value and q is an unsigned
integer below `2^258`. The quotient has 33 BYTE-bound words. Its last byte is
split into low two/high six bits, with high anchored to zero. q is never declared
as a field element; honest maximum-input quotients exceed p.

Sixty-four `conv_ab` adapters multiply each input byte by a shared BYTE-bound
constant one. Existing `conv_pq` blocks compute public modulus-byte products in
groups of at most eight. Sixty-five `conv_column` equations cover input columns
0–63 and an explicit zero overflow column 64. The canonical result keeps its
nine radix-`2^29` limbs, linked to 32 bytes by the unchanged crossing splits and
reconstruction equations. The WOTS adapter appends its explicit field-validity
leaf. Both encoded carry endpoints are anchored to 8,192.

Writing `t_i = encoded_carry_i - 8192`, each column proves
`X_i + t_i = c_i + PQ_i + 256*t_(i+1)`.
Multiplying by `256^i` and summing telescopes to the exact integer statement.
Canonical c then makes it the unique remainder. For either modulus, let S be
the sum of its 32 public bytes. Every PQ column is at most `255*S`; the independent
floor-carry recurrence stays in `[-(S+1),0]`. Here S is 1,417 or 1,597, so encoded
carries stay within their unchanged 14-bit bounds. Every admitted column
intermediate is below `2^23`; reconstructed limbs stay below `2^29`. Numeric
operands therefore fit four-byte ScriptNums. There are no new opcodes or OP_CAT.

The analytical topology is 379 words, 244 constraints, one canonical field and
245 WOTS leaves. It contains 64 input adapters, 94 public-product blocks, 65
columns and 66 carry words. Actual hosted verification and accounting are required
before treating these counts as measured evidence.

## Independent checks and boundary attacks

The factory is sealed, has a fixed topology independent of witness values, and
exposes ordered input, quotient, result and carry ports through immutable copies.
No graph, replay receipt or imported port map can construct it. Full graph/Script
work is guarded to hosted GitHub Linux before allocation. Local checks use small
integer recurrences only.

Independent tests cover both moduli, zero, modulus boundaries, maximum X,
deterministic random inputs, false claims, encodings and source identity. The
retained primary squeeze event 103 supplies a real 257-bit quotient case;
the maximum-input boundary needs 258 bits. A separate bounded Rust oracle calls
the existing pinned halo2curves 0.9.0 `FromUniformBytes<64>` implementation,
checks actual Fp/Fq modulus identities and compares canonical little-endian
results. Its strict JSON parser rejects duplicate/unknown fields, malformed hex,
roles and oversized corpora. It performs no setup, proving or MSM.

The signed-assignment adversarial fixtures include:

- X=0, c=1, q=0, signed initial carry 1. Every column can hold while the initial
  carry anchor refutes the claim.
- X=0, c=`2^512 mod p`, q=`floor(2^512/p)`. The first 64 columns hold with signed
  carry64=-1; carry65=0 keeps the final anchor true. Only overflow column64
  refutes this assignment. Removing that column disconnects the final anchor.
- A shared unit of zero with c=q=0 erases a nonzero input from all columns. The
  explicit constant-one leaf refutes this assignment.
- X=p, c=p, q=0. All integer equations and encodings can hold; the field-validity
  leaf must refute the noncanonical result.

The final carry65 anchor is preserved as an explicit boundary. With all 65
columns, initial carry zero and the specified bounds, it is algebraically
implied: `X-c-p*q = 2^520*t65`, while the left side has magnitude below `2^514`.
No final-anchor-alone counterexample is claimed. This redundancy does not justify
removing the overflow equation or any authenticated link.

The hosted WOTS harness signs each global word once and checks all 64 shared
carry openings per measured role. Exact witness-length guards and empty,
truncated, prepended and appended witness cases remain enabled, along with
forgery, cross-wire and native catalogue identity checks. Interpreter panics fail
the job and never count as successful rejection. Every leaf of both measured
catalogues executes in both correctness and disproof mode and is measured using
the same serialized Script-only accounting as earlier milestones.

## Remaining scope

Script sizes exclude signatures, control blocks and transaction framing. A
standalone reduction has a different statement from field multiplication; its
size must not be described as a multiplication optimization. Hosted conformance
reports identify executed fixtures, not trusted proof-acceptance receipts.

Both Keccak branch outputs, exact Nova framing/padding, prior transcript state,
proof-byte origins and downstream challenge use still need authenticated Script
links. The complete Nova/Spartan/IPA Script verifier, production assertion/key
lifecycle and Bitcoin transaction graph remain unfinished. Hash, transcript,
proof and production verification flags remain false.
