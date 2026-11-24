# Claude handoff: PNS-PIPE-03

Repository https://github.com/patrickdugan/zk-rusto-no-bitcoino
Draft PR https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/33
Branch research/pns-pipe-01-local-fraud (child of PR #32).
Read integrations/pns-pipe/README.md, PNS-PIPE-02.md, micro_fraud.js,
poseidon-params.json, fresh_assertion.py, taproot_csv.js and receipts. Check actual head and CI.
Read Bitcoin PIPEs v2 https://www.allocinit.xyz/uploads/pipesv2.pdf and
Praxis https://eprint.iacr.org/2026/2971; preserve the Nova-only constraint.
PR #32 direct verifier/IPA research remains an independent positive route.

Goal: a mathematically sound optimistic Bitcoin dispute protocol using a
localized fault in a committed native Nova verifier trace as the Praxis
witness, with an exact presigned transaction release. Nova 0.76, Pasta,
Spartan/IPA only. No Groth16, SP1, STARK, external proof wrapper, or mock
witness encryption. Do not introduce a new trust model without explicit
review. No real funds or paid compute.

1. Reproduce CI, repair failures, and audit the two existing local predicates.
   Prove the bit-gate and sparse Fr micro-op local-fault theorems with fixed
   canonical input pins, opcode/range/canonicality checks, exact coefficient
   and accumulator semantics, final acceptance, and authenticated netlist.
   Every satisfying full trace must imply acceptance by the actual pinned
   native verifier; every invalid trace must have a localized witness.
   Reject wrong statement, key, proof, shape, substituted rows, padding,
   Merkle siblings, index aliases, inverse=0/zero residual, and bit aliases.
   Audit custom Poseidon tree domain separation and security. Freeze the
   public relation independently and export/replay equations using a separate
   checker. Verify same-instance malicious witnesses, not just honest vs
   different invalid roots.

2. Connect the real verifier trace, starting with the genuine arity-one
   SquarePlusFive Nova proof 2 -> 9 -> 86. Reuse PR #32's exact native
   transcript, sumcheck, IPA and limb components; complete both Spartan
   verifiers, matrix evaluation, batch, folding and public-state binding.
   If a complete verifier remains unavailable, explicitly label each
   subcomponent. Never accept a host-computed success bit. Use actual source
   rows and independently derived public pins; neither proof nor trace
   producer may choose the verifier. Stream the program and trace, measure
   bit/field slots, operations, bytes, tree construction, peak RSS, DA,
   witness size, N, equations, Fmax and coefficient density. Compare Keccak,
   pinned Poseidon, mixed packed-bit/field leaves and bounded accumulator
   blocks. Existing actual multiplication: 49 rows -> 12,481 micro-ops.
   Existing small Poseidon local relation: 1,386,157 bits, 5,454 equations,
   9.59M linear terms. Do not mistake this for the complete verifier size.

3. Run the isolated fresh_assertion.py --regtest harness using a verified
   Bitcoin Core installation. Validate six-block BIP68 timing at the exact
   earliest height, old-funding-clock adversary, conflict, txid and BIP341
   binding, reorg/reconfirmation and fee escalation. Integrate real trace
   roots with the acyclic T -> A -> assertion txid -> X context. Extend the executed offline NUMS two-leaf Taproot/CSV fixture (16 negative
   controls, BIP341 wallet and BIP340 signing vectors) to real script-path
   consensus tests. Compare key-path preauthorization. Preserve separate
   fault and optimistic keys; demonstrate that retained fault authority
   bypasses WE and retained optimistic authority can redirect after CSV.
   The local runtime lacked Bitcoin Core and DNS blocked the download.
   Explicitly show retained-key bypass in the test baseline. Require an
   authenticated committee setup manifest before assertion broadcast and
   availability for the full window. Missing data is not a local fault.
   No shortening challenge times merely because the witness is small.

4. Specify and prototype a reviewed distributed Schnorr signing ceremony,
   individually encrypted exact-transaction partial signatures. Bind nonce
   commitments, key aggregation/PoP, parity/tweaks, roster, transaction
   sighash, X, ciphertext correctness and the public partial equations.
   Never give a combiner the complete plaintext authorization before
   release. Analyze malicious ciphertexts, one-honest-signer assumptions,
   retained shares/keys, withholding, replay, copied witnesses and fees.
   Correct-encryption proofs cannot establish deletion. Any proof system
   must remain Nova-only. No real WE until its security and parameter gates.

5. Derive concrete Praxis parameters from actual local BQS (including
   coefficient density, QAP, ring ties and MSIS/extraction reductions).
   Audit the false-instance security needed for honest accepting traces,
   and liveness for invalid committed traces. Compare actual costs to
   positive Nova-to-Praxis and existing BitVM3 under identical assumptions.
   Separate custody principal, incremental bond and advance capital,
   setup, data availability, fees, decryption, disputes and monitoring.
   If local WE is still infeasible, report a quantitative no-go. No blind
   7.88 GiB estimate, no full-size ciphertext or mainnet.

Commit derivations, independently executable tests, exact receipts, CI
URLs, and a continuation ledger on PR #33 or a child branch. Continue
as far as possible in one session; do not merge without verification.
Clearly mark executed versus pending, proved versus conjectural.

Latest additional gate: run the two-leaf NUMS Taproot script-path fixture on
an isolated Bitcoin Core node. Verify BIP342 actual spends and six-block
CSV maturity, reorg and redirection counterexamples. The 16 offline controls
passed, but consensus tests remain pending. No production delay is selected.
