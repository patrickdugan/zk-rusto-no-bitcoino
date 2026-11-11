# FC03: authenticated Nova refutations, FlatMerkle versus Merkle, a garbled row check and a regtest dispute

Status: reference implementation for review. Soundness of the local checks is tested on a Nova-folded
four-row relation over both Pasta engines; the Bitcoin path is enforced by tapscript on regtest under
three stated trust assumptions. Machine-readable numbers: [`FC03_RESULTS.json`](FC03_RESULTS.json),
[`results/`](results/).

## 1. Starting point

- Branch `feat/flatmerkle-bitvm3-checks` at PR #23's head `5e9095d` (Python FlatMerkle reference, 4 tests,
  reproduced passing).
- The FC02 bundle, patch and audit were not on this machine (Downloads, OneDrive, `D:` and WSL were
  searched). FC02 was therefore neither applied nor reproduced, and no FC02 number is used.
- Existing code reused: Nova 0.76.0 (folding, Pedersen, Poseidon RO), M12's verifier-key mirror and
  SHA-256 compression gadget (`m12/gates`), garbled-snark-verifier `8fa7efe` (gate context, bigint
  gadgets, `GarbleMode`/`EvaluateMode`, AES-CCR half-gates hasher).

## 2. What must be authenticated to the proof being challenged

From Nova 0.76's source:

| Object | Relation |
| --- | --- |
| Witness W, blind r_W | `comm_W = MSM(ck.ck[..|W|], W) + r_W · H` (`provider/pedersen.rs::commit`) |
| Error E, blind r_E | `comm_E = MSM(ck.ck[..|E|], E) + r_E · H` |
| Relaxed relation | `A z ∘ B z = u · C z + E` with `z = W ‖ u ‖ X` (`r1cs::is_sat_relaxed`) |
| Folding instance | `U = U1 + r·U2`: `comm_W = comm_W1 + r comm_W2`, `comm_E = comm_E1 + r comm_T`, `u = u1 + r`, `X = X1 + r X2` (`r1cs::RelaxedR1CSInstance::fold`) |
| Transcript | `r = Poseidon(pp_digest, U2.comm_W, U2.X, comm_T)` squeezed to 128 bits (`nova::nifs::NIFS::verify`) |

A FlatMerkle root over a W' the operator invents says nothing about Nova's comm_W. For any W', the
vector `E' = A z' ∘ B z' − u C z'` satisfies every row. Test `forged_witness_error_pair_is_caught_by_binding_only`
builds such a pair on both engines:
- every row challenge holds;
- the FlatMerkle openings verify;
- Nova's own `is_sat_relaxed` passes the R1CS equations and fails only with "Invalid commitments".

**What detects the substitution** is the Pedersen binding, which FC03 decomposes into local checks:
- scalars `s_0..s_{n-1} = v` and `s_n = r_v`, generators `G_0..G_{n-1}` from the key and `G_n = H`;
- transition t (j = t / 256, b = t mod 256): `acc' = acc + bit_b(s_j)·P`; `P' = 2P` (b < 255), `G_{j+1}` (b = 255, j < n), O (j = n);
- start state `(O, G_0)`; after (n+1)·256 transitions, acc must equal comm_v.

What the challenger's search found:
- With an honest trace of (W', r_W), the first refutable check is `BindingEnd{W}`.
- With the last state overwritten by Nova's comm_W, it is `BindingStep{W, 1279}`.
- With Nova's own trace committed next to W' values, it is the first bit where W'_j and W_j differ.

## 3. Protocol objects (`fc03/src/protocol.rs`)

Every identifier is SHA-256 over `frame("FLATCHECK/FC03/v1") ‖ frame(kind) ‖ (frame(tag) ‖ frame(value))*`,
`frame(x) = u32_be(len x) ‖ x`. Field elements are 32-byte little-endian canonical; points are
`inf ‖ x ‖ y` (65 bytes, identity `01 ‖ 0^64`).

- `TrustedConfig` (pinned by the contract):
  - field id, network, shape digest;
  - FlatMerkle root of the row records;
  - dimensions and per-matrix slot widths K;
  - leaf counts of every tree;
  - commitment-key root over (G_0..G_{n-1}, H);
  - pp digest and RO identifier.
- `FlatCheckClaim`:
  - version, config digest, field byte, session id;
  - replay domain (network, contract id);
  - statement digest, and folding digest (U1, U2, comm_T);
  - instance (comm_W, comm_E, u, X);
  - roots of W‖r_W, E‖r_E and both binding traces.
- `FlatCheckChallenge`: claim id, kind (`Row`, `BindingStart`, `BindingStep`, `BindingEnd`, `Claim`), index, challenger key, nonce, replay domain.
- `FlatCheckResponse`: echoes the challenge id and carries FlatMerkle openings of exactly the operands
  the predicate reads. Every record names its field, tag and index, so position is authenticated twice:
  by the path and by the item.

Verdict rule (identical in Rust, Python and both circuits):
- `ChallengeInvalid` if the challenge names another claim, another replay domain, version ≠ 1, or an
  out-of-range index. This is never a refutation.
- Otherwise the claim is refuted unless all of these hold:
  - the predicate's claim fields are pinned and canonical;
  - the response is present and answers this challenge;
  - every operand opens;
  - the predicate holds.

## 4. Adversarial suite and differential results

`fc03/src/cases.rs`, 172 cases: 84 per engine plus 2 cross-engine cases in each direction. Each case records the expected verdict next to the actual one.

| Group | What it covers |
| --- | --- |
| honest | each row; binding start and end of W and E; 10 binding steps per vector, including bit-255 generator hand-offs and the blinding scalar's last step; public fold |
| malformed-encoding | u = modulus, X = 2^256 − 1, a committed W/E value ≥ p, a non-canonical row coefficient, a trace coordinate = base modulus, infinity flag 2 |
| wrong-row | a response for another row; row-2 data relabelled as row 1; row = num_cons; an E opening of another row; a W opening at the wrong column |
| switched-field | claim field byte switched; W items tagged with the other field; each engine's honest claim under the other engine's configuration |
| altered-public | X0 + 1 and u + 1 (rows and fold); pp digest; comm_T + G; comm_W + G (fold and binding end); comm_W off the curve |
| forged-opening | flipped reveal byte; changed item value; E opened from the W tree; trace state from the E trace; substituted generator; opening from another commitment |
| repeated-operand | W0 read twice by row 3, honestly and with the second read changed |
| replay | a challenge of another claim; another contract; another network; version 2; a response to an earlier challenge |
| witness-substitution | W2 + 1; E0 + 1; the forged (W', E') pair over rows, fold, binding ends, patched end, Nova-trace variant |
| withheld / binding-start | missing responses; acc_0 ≠ O; generator 1 offered as G_0 |

| Check | Result |
| --- | --- |
| Native adjudicator vs expected verdicts | 172 / 172 |
| Honest local checks, exhaustive (every row and binding step, both engines) | 5,128 hold |
| Python reference vs vectors | 160 / 160 matched. 12 Claim-kind cases need Nova's Poseidon and are compared natively only |
| Circuit vs native, Row and BindingStep cases | 120 / 120, 0 mismatches. The other 52 are withheld, Start, End or Claim kinds, which these two circuits do not decide |
| Garbled honest vs refuted (row and step, both engines) | evaluator obtains the accept label for honest cases and the refute label for refuted ones, 8 / 8 |

## 5. FlatMerkle versus Merkle (`results/fc03_bench.json`)

The same FC03 64-byte records go into both schemes. Merkle is `leaf = SHA256(00 ‖ item)`,
`node = SHA256(01 ‖ L ‖ R)`. Timings are medians on this laptop.

| n | build µs F / M | build compressions F / M | opening bytes F / M | verify compressions F / M | shared-operand multiproof bytes F / M (7 reads, 5 distinct) | peak heap F / M |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 3.9 / 8.2 | 31 / 62 | 228 / 196 | 8 / 10 | 656 / 564 | 3,296 / 1,218 |
| 64 | 19.0 / 32.8 | 127 / 254 | 292 / 260 | 12 / 14 | 848 / 756 | 19,312 / 4,386 |
| 256 | 160.7 / 129.9 | 511 / 1,022 | 356 / 324 | 16 / 18 | 1,040 / 948 | 77,104 / 16,736 |
| 1024 | 655.9 / 501.1 | 2,047 / 4,094 | 420 / 388 | 20 / 22 | 1,232 / 1,140 | 308,272 / 66,018 |

What the numbers show:
- FlatMerkle builds in half the compressions (2n − 1 versus 4n − 2) and verifies in two fewer.
- Each FlatMerkle opening is 32 bytes larger, because it carries the sibling item rather than a hash.
- Peak heap is higher here because the reference keeps every checkpoint state in maps.
- Proof substitution (each opening at three other indices, and openings from a second tree) is
  rejected in every attempt for both schemes: 64, 256, 1,024 and 4,096 attempts.

**Malformed streams.**
- Corrupting one MID checkpoint leaves an ordinary SHA-256 digest.
- Every later checkpoint the verifier recomputes then disagrees with the stream. A whole suffix becomes unopenable: corrupting MID blocks 2, 17 and 20 of n = 16 strands items 0–15, 8–15 and 12–15 respectively.
- Earlier items still open, and no item opens to another value.
- An honest rebuild from the items detects the malformation. A challenge on an unopenable item ends in the response timeout.

**Binding to a Bitcoin transaction (measured on regtest).**
- Both roots are 32 bytes in the claim, whose id rides in an OP_RETURN.
- Two different Core 31.1 relay limits apply, and they are easy to conflate:
  - each initial tapscript witness stack item is capped at 80 bytes (`MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`); larger items give `bad-witness-nonstandard`;
  - OP_RETURN data was raised in Core 30: `-datacarriersize` defaults to 100,000 bytes in 31.1, summed over multiple outputs.
- The same row-3 response on each carrier:

  | Payload and carrier | Relay | vsize / weight |
  | --- | --- | ---: |
  | FlatMerkle openings, 2,044 bytes, witness in 80-byte pushes | standard | 649 / 2,596 |
  | Merkle openings, 1,756 bytes, witness in 80-byte pushes | standard | 576 / 2,302 |
  | FlatMerkle, witness in 520-byte pushes | `bad-witness-nonstandard` (consensus-valid, mined with `generateblock`) | 643 / 2,571 |
  | FlatMerkle, one OP_RETURN output | standard | 2,197 / 8,785 |
  | FlatMerkle, envelope in the leaf script (`OP_FALSE OP_IF <520-byte pushes> OP_ENDIF`) | standard | 644 / 2,574 |

- OP_RETURN relays the payload but costs 3.4 × the weight of the witness carrier: output bytes weigh 4 WU each, witness bytes 1 WU. Script also cannot read output data. Splitting into 80-byte pushes costs 6 vB more than 520-byte pushes.
- The envelope is the cheapest standard carrier. Its pushes live in the revealed script, not on the initial stack, so the 80-byte stack-item policy never applies, which is the same route inscriptions take around it. The catch is that the script is fixed when the output is created, so the payload must be known then. The dispute uses this: a row's response is a function of the operator's committed data, so it is baked into the response leaf at setup.
- Because a FlatMerkle digest is plain SHA-256 of the stream, `OP_SHA256 <root> OP_EQUALVERIFY` checks a whole commitment when the stream fits one stack item (n = 4, 384 bytes). This is consensus-valid (234 vB, mined with `generateblock`) but not relayed, because of the 80-byte tapscript item limit. The larger OP_RETURN limit does not help here: OP_SHA256 needs the stream on the stack.
- For n ≥ 8, and for any Merkle root, Script would need OP_CAT.

## 6. The dispute circuits (`fc03/src/circuit/`, `results/fc03_circuits.json`)

Each circuit is fixed per trusted configuration: one row circuit, and one binding-step circuit per vector.
Inputs are the on-chain claim id, the claim values, the challenge and the response; there is one output, "refute".

The circuit performs, in order:
1. Recomputes the claim id and the challenge id (in-circuit SHA-256 over the exact `Enc` layout).
2. Checks the context and the pinned config digest and field byte.
3. Verifies every FlatMerkle opening with data-dependent directions; reveals are fed in level order.
4. Parses records strictly.
5. Checks canonicality (`v < p`).
6. Evaluates the relation with 255-bit Montgomery arithmetic. This ports garbled-snark-verifier's `montgomery_reduce` to R = 2^255, since both Pasta moduli exceed 2^254.
7. For the step circuit, evaluates RCB complete addition over the commitment group's base field.

Measured gadget costs: Montgomery multiply 82,012–82,316 non-free gates, modular add 765, and a
FlatMerkle verification of 2,048 leaves 500,390.

| Circuit | Non-free gates (= ciphertexts) | Ciphertext bytes | Input bits | Garble + evaluate | × fewer than baseline |
| --- | ---: | ---: | ---: | ---: | ---: |
| Row, toy, Pallas | 2,683,971 | 42.9 MB | 21,864 | 0.75–0.95 s | 292.6 |
| Row, toy, Vesta | 2,680,871 | 42.9 MB | 21,864 | 0.94–0.95 s | 293.0 |
| Binding step, toy, Pallas | 4,666,776 | 74.7 MB | 19,168 | 1.56–1.75 s | 168.3 |
| Binding step, toy, Vesta | 4,665,516 | 74.6 MB | 19,168 | 1.60–1.76 s | 168.3 |
| Binding step, real HeaderStep sizes (2^26-leaf trace) | 7,285,647 (exact) | 116.6 MB | — | — | 107.8 |
| Row, real sizes, p99 width (53 operand slots) | 50,177,670 (model) | 0.80 GB | — | — | 15.7 |
| Row, real sizes, widest row (929 + 84 + 256 slots) | 1,150,138,072 (model) | 18.4 GB | — | — | 0.68 |

Notes on the table:
- **Baseline.** M14's complete final verifier of the Nova proof (SP1 wrap, BLAKE3 transcript v2) is one garbled circuit of 785,442,492 gates (`../m14/README.md`).
- **Real sizes.** Read from the pinned testnet4 k = 1 key (`results/fc03_realshape.json`, vk `6894f490…`):
  - 131,072 rows and variables;
  - max non-zeros per row A/B/C = 929 / 84 / 256;
  - row total non-zeros p50 3, p99 53, max 1,169.
- **The model.** The row circuit is `2,235,317 + 904,573 × slots`. This is fitted to exact builds at 32, 56 and 88 slots, with a maximum residual of 2,659 gates.
- **Why the widest row is modelled, not built.** Building it in ExecuteMode exceeded 20 GB on this 15.5 GB host and was stopped.
- **Count conventions.** ExecuteMode counts a few `AND(x, NOT x)` gates that the garbler folds (Vesta row: 11, Pallas step: 36); the table gives the garbler's ciphertexts.

**Against the tenfold target:**
- Met for binding steps at real size (108×) and for rows up to about 85 operand slots.
- Missed for one fixed-width row circuit over the real shape: a circuit sized for the widest row is 1.46 × the full verifier.
- Two designs would close it (neither built): width classes, where each row goes to a circuit sized for its own width, or a term-accumulator trace, where each local check reads one matrix entry.

## 7. Bitcoin regtest dispute (`fc03/src/regtest.rs`, `results/fc03_regtest.json`)

Bitcoin Core 31.1 regtest, 2 sat/vB, bond 200,000 sat. Every output is Taproot with a NUMS internal key, spent by script path only.

| Output | Leaves |
| --- | --- |
| claim C | `<6> CSV DROP <op> CHECKSIG`; per row i: `<i> DROP <op> CHECKSIGVERIFY <ch> CHECKSIG` |
| challenge X_i (operator pre-signed tx, OP_RETURN challenge id) | `OP_FALSE OP_IF <row i response, 520-byte pushes> OP_ENDIF <ch> CHECKSIGVERIFY <op> CHECKSIG`; `<6> CSV DROP <ch> CHECKSIG` |
| response R_i (challenger pre-signed tx) | `SHA256 <H(refute label_i)> EQUALVERIFY <ch> CHECKSIG`; `<6> CSV DROP <op> CHECKSIG` |

| Transaction | vsize | weight | fee (sat) |
| --- | ---: | ---: | ---: |
| claim (bond + OP_RETURN claim id) | 197 | 788 | 396 |
| unchallenged payout after D1 | 145 | 580 | 290 |
| challenge | 213–221 | 850–882 | 426–442 |
| response (2,044-byte payload revealed from the envelope leaf) | 677 | 2,705 | 1,354 |
| disprove (refute-label preimage) | 150 | 597 | 300 |
| operator payout after D3 / withheld-response payout after D2 | 137 | 548 | 274 |

All 19 checks match the expected accept/reject outcome:

| Scenario | Outcome |
| --- | --- |
| Premature payouts on all three CSV leaves | `non-BIP68-final` |
| A response revealing any envelope other than the committed one | `Witness program hash mismatch` |
| Honest claim, row 2 | The challenger reads the response back from the confirmed witness and evaluates the garbled circuit. It obtains the accept label; disprove with it fails `OP_EQUALVERIFY`, and the operator is paid after 6 blocks |
| Dishonest claim (W2 + 1) | The challenger's search locates row 3. The response opens correctly, and evaluation yields the refute label: disprove accepted. The same with the operator's key fails "Invalid Schnorr signature"; the operator's later payout fails `bad-txns-inputs-missingorspent` |
| Withheld response | The challenger is paid after D2 = 6 blocks |
| Corrupted challenger signature, an operator pre-signature from another row's leaf, a challenge pre-signed for another claim | All "Invalid Schnorr signature" |

**Enforced by Bitcoin:**
- who may challenge, and for which row;
- the challenge id;
- the exact response payload, fixed in the envelope at setup;
- the response deadline;
- that only the holder of that circuit instance's refute label can disprove;
- the operator's payout after an unrefuted response.

**Not enforced: T1–T3 below.**

## 8. Work outside the garbled circuits and trust assumptions

- **T1 garbling.** The operator garbles; nothing checks that the tables are the pinned circuit's (needs cut-and-choose or a proof of correct garbling).
- **T2 input labels.** Labels for the on-chain bits are handed over off-chain.
  - Because openings are binding, a label set that yields "accept" must encode the committed data.
  - But labels withheld after a confirmed response leave the challenger without a refute label, and the operator is paid after D3.
- **T3 pre-signed graph.** Operator and challenger pre-signatures stand in for a covenant. They must exist before the bond is locked.
- **Native only.** `Claim` (public fold recomputation with Nova's Poseidon), `BindingStart` and `BindingEnd` are decided by the native adjudicator, with no circuit.
- **Off-chain search.** The challenger's search (`locate_fault`) runs off-chain over data the operator must publish.

## 9. Outstanding security gates

1. **G-LABEL**: bind circuit input labels to the on-chain claim, challenge and response (BitVM3 label commitments or WOTS-derived labels), so withholding is punishable.
2. **G-INDEX**: real shapes need 131,072 row challenges and 2 × (2^17 + 1) × 256 ≈ 67.1M binding-step challenges. The regtest graph has one leaf, one garbled instance and one envelope-baked response per row (4 rows). One circuit per kind with an on-chain-bound index input is required; envelope responses would then need a commit-reveal step, since a leaf cannot hold every possible response.
3. **G-WIDE-ROWS**: the fixed row circuit at the real widest row is 1.15 × 10^9 gates. Width classes or a term-accumulator trace are needed.
4. **G-FOLD**: the public fold check (Poseidon over 2 points and the X vector, 128-bit scalar multiplications) has no circuit.
5. **G-ENDPOINTS**: `BindingStart`/`BindingEnd` circuits are not built (small: one or two openings and a 65-byte comparison).
6. **G-NOVA-FULL**: FC03 covers one relaxed instance and its last fold. A full Nova refutation also covers the secondary relaxed instance, the fresh secondary instance, and the IVC hash binding `X = H(pp, i, z0, zi, U_other)` across both curves.
7. **G-REAL-WITNESS**: no row of the real HeaderStep folded witness (7.2 MB RecursiveSNARK, not committed) was challenged. The real-shape circuits are counted at real sizes with synthetic values.
8. **G-DA**: availability of the committed W, E and traces is assumed, not enforced.
9. **T1** (garbling correctness) and **T3** (pre-signed graph) as above.

## 10. Next concrete blocker

G-LABEL together with G-INDEX: one garbled row (or step) circuit whose challenge-index and response
input labels are fixed by the on-chain transactions. Until then each challengeable check needs its own
pre-signed leaf and garbled instance. That is affordable for the 4-row fixture, but not for the 131,072 rows and
67.1M binding steps of the real HeaderStep instance.
