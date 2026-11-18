# Specification: authenticated local disputes and Nova soldering

Current protocol identifier: `RBZK-BABE-NOVA-PILOT-AUTHENTICATED-V2`.

## 1. Scope and proof configuration

This crate implements a bounded research experiment inspired by Babylon's January 2026 [BABE paper](https://docs.babylonlabs.io/papers/BABE_Research_Paper_Jan_2026.pdf). The default protocol uses a 16-slot Mersenne-31 predicate with 128 input bits, seven generated garblings, four seed openings, and three retained instances. `DisputeProgram` also carries the universal local checker for an independently compiled complete Boolean verifier. A separate 3,832-bit Pallas addition gadget measures and tests a larger local relation.

The soldering certificate uses `nova-snark = 0.76.0`, `PallasEngine`/`VestaEngine`, `CompressedSNARK`, and Spartan's `RelaxedR1CSSNARK` with `ipa_pc::EvaluationEngine`. The selected commitment backend derives transparent parameters. This configuration still relies on its cryptographic assumptions, correct library implementation, authenticated verification parameters, and the program described below.

Nova supplies the certificate's zero-knowledge argument. Poseidon commitments with seed-derived blindings provide computational hiding under the chosen hash and PRG assumptions. The code derives 253-bit blinding values from a domain-separated ChaCha20 stream; it establishes no statistical or information-theoretic hiding theorem. `RecursiveSNARK` remains prover state. The released artifact is `CompressedSNARK`; a different compressor would need its own zero-knowledge analysis.

The standalone benchmark measures Bitcoin serialization and witness shape. The integrated harness exercises a separate funded sixteen-choice graph against Bitcoin Core, with real Nova session labels and durable release after confirmation. Complete trace composition and its scale limits are described in [INTEGRATION.md](INTEGRATION.md).

## 2. Ownership of the claim and challenge data

The operator fixes the claim specification before garbling and before receiving the cut-and-choose nonce. The challenger selects an opening of that committed claim. Every arithmetic auxiliary which could change the local result belongs to the committed operator trace.

For a local opening `t`, define

\[
\operatorname{refute}(t)
=\operatorname{authenticated}(t)
\land\neg\operatorname{validTransition}(t).
\]

An opening that fails authentication yields no refutation. This prevents a challenger from changing a quotient or coordinate and turning its own altered witness into evidence against the operator. A committed invalid tuple yields a refutation when its opening is available.

The output bit zero means that this opening supplies no authenticated refutation. It leaves the status of other steps and the global application claim outside this local result. The API names this result `InstanceVerdict::NoRefutation` and, for the local resolution, `DisputeResolution::NoAuthenticatedRefutation`.

### 2.1 Mersenne-31 indexed relation

Let `p = 2^31 - 1`. The fixed `IndexedDisputeSpec` contains `claim_id`, 16 generators `g[i]`, and 16 full 32-byte SHA-256 step commitments. Its `circuit_id` hashes that specification under the versioned domain in `src/dispute_circuit.rs`.

The opening contains a four-bit slot index and four 31-bit integers:

\[
t=(i,s_{\rm in},a,s_{\rm out},q).
\]

The commitment hashes the domain `babe-pilot/step/v2\0`, the complete claim identifier, slot index, selected generator, and all four integers in their fixed little-endian encodings. The circuit compares all 256 digest bits.

For an authenticated opening, validity requires canonical field elements and the integer equality

\[
((s_{\rm in}+g[i])\bmod p)\,a
=q\,p+s_{\rm out}.
\]

The quotient is part of the commitment. Its encoding and the multiplication check use bounded integers. A representation which would truncate a supplied value is rejected before encoding.

`commit_step` constructs a different operator statement for tests or setup. The verifier must continue using its independently agreed specification after setup; replacing that specification would select a different claim.

### 2.2 Pallas window relation

The larger gadget uses the Pallas base field and the fixed point `G = (-1, 2)`. For window index `c`, its deterministic lookup table contains

\[
T_c[u]=u\,2^{4c}G,\qquad 0\le u<16.
\]

The final window of a 255-bit scalar restricts the selector to its remaining three bits. The configuration binds the curve and generator convention, claim identifier, step index, window index, and complete table. This is a fixed-generator local experiment; importing Nova's actual Pedersen generators requires further work.

The operator opening includes the window value, input/output infinity flags and full coordinates, inverse and slope, intermediate products, every modular quotient, and the 32-byte auxiliary field named `sibling_hash`. That field is opaque committed data in this relation. A Merkle-path verification rule would require additional structure and checks.

The step hash uses `babe-pilot/pasta-step/v2\0`, the 32-byte context digest, byte encodings of the window and two infinity flags, all 14 field-sized values as 32-byte little-endian integers, and the 32-byte auxiliary field. The values are `x1`, `y1`, `x3`, `y3`, `inv`, `lambda`, `x1_sq`, `lam_sq`, `lam_dx3`, and `q0` through `q4`. The full digest is compared with `expected_step_hash`.

Arithmetic validity checks the canonical coordinate/auxiliary encodings, on-curve endpoints and canonical infinity encoding `(true,0,0)`, the selected table entry, and the complete addition cases. In slope branches, witness-assisted products must satisfy their integer quotient equalities. Identity and inverse branches keep the auxiliary fields committed and canonical while leaving their unused slope equations inactive. The same `authenticated && !valid` output rule applies.

The gadget commits one complete step. A full Pedersen computation also needs authenticated links between successive accumulators, the actual generator schedule and scalar decomposition, and binding to the intended final commitment.

## 3. Garbling and label commitments

Each generated instance `k` uses a 256-bit seed and the pinned `garbled-snark-verifier` dependency's seeded garbling constructor. Input labels and the global offset are 128-bit values:

\[
L_{k,i,1}=L_{k,i,0}\oplus\Delta_k,
\qquad \Delta_k\ne0.
\]

The manifest binds the fixed circuit specification, session identifier, input width, and each instance header. A header includes public garbling salt and constant labels, ciphertext count and SHA-256 digest, label-commitment roots, and separate SHA-256 hashes for the two output labels.

The base instance exposes raw label hashlock pairs

\[
h_{b,i,\beta}=\operatorname{SHA256}
(\operatorname{LE16}(L_{b,i,\beta})).
\]

`compute_base_tap_root` folds the complete paired hashlocks into a Poseidon accumulator initialized with the session, circuit identifier, and instance index. The soldered instances use blinded Poseidon label commitments which include their instance index, wire index and bit value; their accumulator initialization also binds the session and circuit identifier.

Raw SHA-256 label hashlocks support Bitcoin's existing `OP_SHA256`. Their association with a session, wire and selected challenge bit comes from the pinned setup and the constructed spending script.

## 4. Soldering relation

Let `R` be the retained set, `b = min(R)`, and `J = R \ {b}`. The pilot has two soldered instances. For each `j` in `J`, the public certificate publishes

\[
S_{j,i}=L_{j,i,0}\oplus L_{b,i,0},
\qquad
\Gamma_j=\Delta_j\oplus\Delta_b.
\]

The private witness contains the base false labels, secret offset material, and soldered-label blindings. The Nova step processes two wires. Its public state carries a context binding tag, wire cursor, base hashlock accumulator, the soldered commitment accumulators, and a delta accumulator.

For each wire, the circuit reconstructs both base labels from their Boolean decompositions, computes both raw 16-byte SHA-256 hashes, and updates the base accumulator. It then derives the soldered label pairs by XOR, opens their Poseidon commitments, and updates each target accumulator. Public translations and offset translations enter the delta accumulator. The verifier recomputes the initial state and expected terminal roots from the independently pinned setup, and checks the exact step count and terminal cursor.

This directly connects the SHA-256 labels used at the base to the label pairs used in the soldered instances. The certificate establishes input-label consistency. The retained gate tables are covered by cut-and-choose and the assumptions in the next section.

### Evaluation identity

For a selected bit `x_i`, a base active label translates as

\[
\begin{aligned}
L_{b,i,x_i}\oplus S_{j,i}\oplus x_i\Gamma_j
&=(L_{b,i,0}\oplus x_i\Delta_b)
\oplus(L_{j,i,0}\oplus L_{b,i,0})
\oplus x_i(\Delta_j\oplus\Delta_b)\\
&=L_{j,i,0}\oplus x_i\Delta_j
=L_{j,i,x_i}.
\end{aligned}
\]

Its use depends on the authentic selected base label, the verified certificate, and the correct committed circuit for any instance relied upon for adjudication.

## 5. Protocol order and API boundary

1. The participants agree the session and complete claim specification. The garbler creates all seven headers and publishes `PreChallengeManifest`. The challenger records its `commit1_digest` independently.
2. After that pin is fixed, the challenger supplies a fresh unpredictable nonce. The partition derives from the pinned digest and nonce using the implementation's deterministic sampling. Four indices are opened; the three retained indices are sorted to select the base.
3. The garbler's first finalization attempt reserves the nonce before proving. Another nonce is rejected. `DurableGarblerSession` persists this reservation and advances an independent authority before producing openings or a proof. Successful finalization returns the opened seeds, retained ciphertext streams, base hashlocks and soldering certificate.
4. `verify_public_setup` receives the independently expected commitment digest along with the expected session, specification and nonce. It checks the manifest pin, regenerates every opened instance, checks retained stream counts/digests, reconstructs the base root, and verifies the Nova certificate. Success returns an immutable `VerifiedPublicSetup` capability.
5. The garbler releases a base active-label vector only after successful finalization and for its fixed nonce. The release guard binds the agreed input digest; conflicting requests fail. Retained evaluation and dispute resolution require the verified capability.
6. The evaluator checks each delivered label against the selected base hashlock and translates it into every retained instance. A matching refutation output returns `AuthenticatedRefutation` with that instance's committed output preimage. Unrecognized outputs remain evaluation failures; an all-corrupt result yields an error.

The independent `expected_commit1` argument supplies a pin comparison. Its caller must establish that the pin was obtained before the nonce. Recomputing it from the candidate after seeing the nonce would leave that ordering unestablished.

The low-level garbler retains process guards. `DurableGarblerSession` adds a locked, fsynced journal and an independent compare-and-set head, with exact saved-artifact recovery. Its release reservation binds the complete input and the selected funded transaction. Recovery accepts one complete pending transition after validating its saved artifacts. A torn journal fails closed; rollback of both the session and its authority remains outside the guarantee.

A missing or invalid label delivery returns `AwaitingWithholdingTimeout` in the protocol model. Exercising its CSV branch requires an actual funded outpoint and observed deadline maturity. The host function has no chain clock or consensus execution authority.

## 6. Conditional cut-and-choose probability

Assume a fixed malicious set `B` with `b_bad = |B|`, an authenticated prechallenge commitment, one independent uniformly sampled retained subset of size `M`, correct opening verification, and sound commitments and certificates.

For `b_bad <= M`, the probability that every bad instance avoids opening is

\[
\Pr[B\subseteq R]
=\frac{\binom{N-b_{\rm bad}}{M-b_{\rm bad}}}{\binom{N}{M}}.
\]

When the protocol can use any honest retained instance to refute an authenticated invalid opening, the event that all retained instances are bad and all opened instances pass requires `b_bad = M`. That event has probability

\[
\binom{N}{M}^{-1}.
\]

For this pilot, `N=7`, `M=3` gives `1/35`, approximately `2^-5.129`. The arithmetic factor for `N=115`, `M=39` is approximately `2^-102.585`. The latter is a combinatorial event probability under the stated assumptions. A complete protocol bound must also account for cryptographic failures, challenge generation, retries and grinding, publication and deadline behavior, and the security of the transaction graph. This crate claims no inherited production security level from the paper's parameter choices.

A caller who permits multiple post-nonce candidate commitments changes the experiment. Fresh independently pinned sessions and a bounded retry policy are necessary for any claimed aggregate bound.

## 7. Bitcoin label binding and transaction evidence

The assertion constructor receives the independently authenticated expected input bits. For wire `i`, the script contains only the hashlock for `h[b,i,expected_bit[i]]`. Its witness supplies the active label. The witness cannot select the opposite hashlock through a free bit selector.

The output's Taproot commitment binds that exact selected vector. `transaction_graph` supplies a bounded presigned catalogue, and `challenge` authenticates every indexed opening before funding. Selection after funding spends the common assertion output into the chosen label script. The release CLI checks a graph reservation saved in the trusted authority directory before funding and independently observes the confirmed selected transaction. The standalone constructors retain their size-measurement role.

The funded graph's response output provides a hashlock branch for each retained refutation output and a delayed operator branch. The selected challenge output has a withholding branch with CSV. Its response leaf requires both role signatures; the challenger's exact SIGHASH_ALL signature fixes the destination even when the operator retains its signing key. The Core harness mines the positive paths and checks malformed witnesses, redirects, competing spends and CSV boundaries.

The garbler knows both output labels. A sound custody protocol must account for who can use a refutation preimage, which party controls each signature, and how branches bind to the same claim and collateral.

## 8. Required composition before application custody

| Boundary | Remaining obligation |
| --- | --- |
| Full verifier or application trace | The compiler covers every Boolean input, gate and required output with shared wire commitments. Full M14 trace generation, storage and measured cost remain open. |
| Source data | Complete trace publication and all sixteen indexed openings are checked. Keep them available for the full challenge window and bind application settlement state. |
| Bitcoin transaction graph | The funded indexed profile covers its sixteen choices and deadlines. Larger trace openings need coordinated chunk transactions and a scalable selector. Adversarial deployment across independent role processes and reorganization recovery remain open. |
| Persistence | Durable reservations and crash recovery are implemented. Deploy the CAS authority outside the session rollback domain and provide recovery for a torn authority record. |
| Proof and garbling costs | Measure the corrected relation and complete protocol under matching security and coverage assumptions. |
| DLC integration | Bind the same accepted application transition to the concrete CET, guardian or BitVM spend path and successor settlement rights. |

A smaller local circuit changes the cost of its particular relation. An end-to-end comparison with M14, FC03 or the BABE Groth16 verifier requires a common statement and complete enforcement costs. This specification makes no full-verifier speedup or production proving-time prediction.
