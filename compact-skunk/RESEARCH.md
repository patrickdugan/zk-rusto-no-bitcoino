# Research lanes and source leads

These are proposed experiments. The only executed work in this packet is the
offline arithmetic and toy graph suite recorded in RESULTS.md.

## Concurrent M24 work to reuse

Main advanced during preparation to
[`8dcfd2f`](https://github.com/patrickdugan/zk-rusto-no-bitcoino/commit/8dcfd2fc2b796f2ec16a64afe091d731c0191be5).
It adds `integrations/bitvm2-nova/stark-hash-oracle/` and
`.github/workflows/bitvm2-nova-stark-hash.yml`, using pinned upstream BLAKE3 and
SHA-256 Script implementations. Inspect its hosted output before using costs.
Its scope is hash execution against reference digests; Merkle authentication,
proof verification and statement binding still need separate checks. Reuse
this harness for lanes A, C and D. Preserve that worker and its resource caps.
The arithmetic baseline in this packet remains pinned to M23.

## A. Authenticated cuts and larger predicates

Build one complete point operation as a supernode, then compose 2, 4 and 8.
Carry internal arithmetic locally where Script limits allow. Compute the exact
set of values consumed across every cut and authenticate each shared identity.
Measure both unique signed words and the maximum witness for a selected chunk.
Bucket arrays, selectors and exceptional curve cases belong in this accounting.
The bucket census in `lab.py` gives a starting representation.

Investigate hashing a live state or authenticating sparse memory accesses.
Price each hash or opening and show how producer/consumer equality is enforced.
A signed root needs a protocol that binds the accessed data to that root.
Price data publication and refusal-to-open behavior. Chunks must remain
challengeable from a fixed program when the proof changes.

`OP_SHA256` consumes one stack item. For a Merkle or state hash, explain the
binding of each supplied preimage component under CAT-off execution. A claimed
concatenation supplied by a witness needs its own check. Algebraic hashing and
Script-level hashing offer comparison points. Record their actual cost.

## B. Structured and fixed-generator MSM

Use the group-valued multilinear identity in MYTHOS.md. Compare a direct MSM
with recursive tensor contraction and any public preprocessing scheme. Count
scalar multiplications separately from additions; replacing many additions
with fewer full-width multiplications changes the cost model.

The scalar coefficient vector has tensor rank one. A useful additional
factorization of the generator table must be demonstrated over the actual
ordered key and charged for storage and validation. Never manufacture known
discrete-log relations among Pedersen generators to make the experiment cheap.
Such a substitution changes the commitment's binding assumptions.

Other concrete probes include fixed-base window tables, signed-digit schedules,
shared challenge powers, and specialized mixed/projective arithmetic. Maintain
complete handling of zero, equality, inverses and infinity. Prove an exceptional
case unreachable from authenticated inputs before removing its check. Price
canonicality and any inverse/quotient witness. Include table construction and
cold key loading in the measurement.

A generic sumcheck or a compressed checksum of coefficients leaves an endpoint
relation to verify. Write that endpoint before claiming the large MSM has been
removed. A host-computed terminal point needs authentication just like every
other claimed intermediate.

## C. Transparent proof of the terminal relation

Retain the existing Nova proof. Add a transparent certificate for
`G_hat = sum_i s_i G_i` on both curves, binding the coefficient source and key.
The outer prover performs the expensive terminal work. Its verification becomes
a candidate replacement for the disputed MSM.

First implement a small actual Pasta instance with key-swap and challenge-swap
tests. Use a mature proof backend. Measure non-native field arithmetic and all
hash/query work. Then establish a bounded route from that instance to the
retained dimensions. Preserve a pinned public statement and security parameters.

This lane leaves the rest of the verifier to compose. The baseline NEXT.md
projects 75,413,392,968 bytes for a shared-prefix Keccak transcript, before a
complete verifier is assembled. Include that residual cost in comparisons.

## D. Transparent proof of full verifier acceptance

Wrap the pinned native Nova verifier, or design a replacement final compression
whose equivalence to the original statement is established. The latter changes
the proof pipeline and needs new proofs; an outer verifier proof can reuse an
existing header proof. Keep those costs separate.

Investigate hash-based polynomial commitments with a mature implementation.
Pin the exact transcript, arithmetization and verifier version. Compare a small
terminal wrapper with a full-verifier wrapper under matched security. Fiat-Shamir
hashes, Merkle authentication and all constraint evaluation belong in the
Bitcoin cost table, including a bounded schedule for proof-dependent queries.

A proof-specific compiled script is useful as a local oracle. Production needs
a program that remains bound to the agreed verifier across proofs. Show how a
program fixed during setup accepts varying proof data and rejects malformed
or overlong query schedules.

## Source leads checked on 2026-11-07

Use exact revisions when importing code. Review licenses first. The sources
below supply research leads; this packet has not built their proof backends.

**Existing project.** [M23 baseline](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/55e52156f800f0f39e4bc04ff76103c14633b273/integrations/bitvm2-nova)
and [PR #22](https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/22).
The branch tip for the sensitivity study was
`697c0b69bd56a706706df79e7e54618f8acb4d58` when prepared.

**BitVM2.** The authors' [protocol description](https://bitvm.org/bitvm2)
explains intermediate assertions and the single faulty-step disproof.
[BitVM's implementation](https://github.com/BitVM/BitVM) contains chunking and
Winternitz machinery. Pin it before reuse. Its bridge setup assumptions require
a separate account from a transparent proof system's setup.

**Bitcoin limits.** [BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
retains the 1,000-item combined stack limit and 520-byte element limit.
Transaction weight and relay policy require full serialized-spend accounting.
The 1.25 GiB constructor policy belongs to this project's experiment.

**WHIR.** [Arnon, Chiesa, Fenzi and Yogev, 2024/1586](https://eprint.iacr.org/2024/1586)
provide a hash-based route for polynomial commitments and succinct arguments.
Native verifier speed alone gives no Script byte count. Record the selected
soundness regime and query/grinding parameters.

**A concrete reuse candidate with a version trap.**
[`GOATNetwork/bitcoin-stark-verifier`](https://github.com/GOATNetwork/bitcoin-stark-verifier)
was previously under AppliedPQC. Its
[current README at e33bcd0](https://github.com/GOATNetwork/bitcoin-stark-verifier/blob/e33bcd096858d2a12792b0d6914eed460f321f89/README.md)
describes a garbled binary-field WHIR verifier and points to the earlier
[Script implementation at d45e453](https://github.com/GOATNetwork/bitcoin-stark-verifier/tree/d45e45386315c4ce927e099c97f51eed48bdc877).
Audit that earlier revision for the primary BitVM2 lane. The current route
belongs in the protocol-change lane. Its README reports unfinished input
soldering and transaction composition; it also reports about 40-bit
cut-and-choose security for one configuration. Track that separately from
proof soundness. Reproduce any measurements before adopting them.

**Resource allocation.** Inspect and reuse suitable libraries as required by
root AGENTS.md. Run cheap source and model checks here. Stage any actual
native/Script experiment in hosted CI with a named resource budget. Keep the
existing header prover and BitVM3 work isolated.
