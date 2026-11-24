# PNS-04: direct Nova verification relation for Praxis

## Decision

Nova 0.76.0, Pallas/Vesta, Spartan/IPA compression, using the existing M16/M18 and PNS-01 native code. No external proof wrapper. Reference: src/nova_verify.rs. The actual Praxis circuit is unfinished; this document registers the gates.

Let x be an independently registered canonical PNS1 statement and the exact Nova verifying key VK fixed as constants. Let pi be a compressed Nova proof. Define R_x(pi, a) = 1 iff the native verification computation accepts and yields the fixed terminal state, and every auxiliary value a is consistent with that computation. For a composite statement, also check header and UTXO segment verification, state equality and policy constraints as described in README. The statement must fix all these predicates before encryption. The witness is the bit encoding of pi plus deterministic/constrained verifier trace, not a host assertion of acceptance.

## Compilation plan

1. Freeze a minimal SquarePlusFive fixture from ../bitvm3-nova/src/bin/nova_reference.rs, then PNS-01 with fixed key, step count and state arity. Pin Nova source/lockfile and exact verification path, including primary and secondary Spartan proofs. Inventory proof coordinates, canonical Pasta field encodings, lengths, group identity representations, transcript and challenge ordering, subgroup/point checks, and all branches. Bincode is for transport; use a fixed typed field/point vector as the circuit witness. Prove or differentially test the translation and enforce all canonicality required by the typed predicate.
2. Audit and reuse Boolean Pasta kernels and M1–M11 transcript, sumcheck, Spartan and R1CS conformance work in ../bitvm3-nova. The complete native Nova verifier has not yet been emitted as a verified fixed Boolean circuit. Existing M14 garbles a different final verifier, so do not reuse its gate count as a Nova circuit estimate. Specialize VK and statement constants; choose bounds for all lengths. Deterministic native trace generation is only an assignment generator.
3. Lower each Boolean wire to a Boolean unknown (the Praxis relation enforces bitness). With constant wire w0=1, encode AND as xy=z; XOR as 2xy=x+y-z; NOT as 0=x+z-1; COPY as 0=x-z. Require accept=1. A fixed acyclic netlist plus these equations has a unique consistent gate assignment per input. Test truth tables, wrong output, nonbit assignments and disconnected acceptance. For costs, count XORs too: free-XOR pricing in garbling does not apply to BQS.
4. For field-native optimization, build shared canonical limb variables for both Pasta moduli over BN254 Fr. Modular add/mul, inversion with nonzero checks, curve addition with exceptional branches, MSM, transcript, sumcheck, IPA and both Spartan verifiers must constrain every intermediate. Exact bounded signed carries prevent modular wrap; no unverified inverse, lookup or reduced scalar. Compare optimized BQS to Boolean reference and actual Nova verifier. Keep both verifier engines pinned; BN254 is Praxis's field, not a migration of existing Nova state or M18 Poseidon roots.
5. Validate accepting and rejecting traces against pinned native verification: proof mutation, mismatched VK, wrong statement, wrong step count, altered output, out-of-range coordinates, identity/exceptional points, transcript challenge mutations, wrong sumcheck claims, final IPA mismatch. Require both directions: every satisfying assignment decodes to a proof accepted by native verification, and every accepted proof has a satisfying assignment. For a fixture, independent randomized re-proofs must satisfy the same fixed statement.
6. Measure N Boolean variables, number of equations, maximum products per equation, QAP domain D, form dimensions and compression counts. Derive and audit fresh MSIS and rank-gap parameters and concrete reductions; paper Table 4 and fixed Lean correctness/extraction theorems do not certify new sizes. Stream and benchmark the actual Nova-specific encryption/decryption only after those gates. If direct encoding is too large, optimize verifier shape and compare against BitVM3; do not introduce a new proof system.

## Resource gates

CPU only initially. Start with the tiny native proof and field/transcript kernels. Require exact native differential receipt and BQS shape/count receipt before large QAP allocations. Publish relation hashes and wire order. No 7.88 GiB or laptop-time claim for Nova-specific WE. No real collateral. Bitcoin release still requires authenticated ciphertext availability, exact presigned transaction and a signing ceremony that addresses plaintext signature retention.

## Implemented backend

See [PNS-04A/B](bqs/README.md) for the direct CircuitContext-to-BQS lowering, exact optimized Pasta limb arithmetic results, and registered native Spartan/transcript differential. The complete native compressed Nova verifier is still the acceptance target.

PNS-04C's native IPA and shared-slot BQS CI passed (45381516633). See [PNS-04D](bqs/PNS-04D-COMPACT-MSM.md) for the optimized complete group law and fixed-base MSM, measured synthetic opening reduction, and actual key-domain pricing gate. Remain Nova-only.
