# Praxis / Nova settlement pilot (PNS-01)

Status: research, no funds. Prepared 2026-11-24 on main 01698bdb590ff38c3d3077dc5cba534a63ef5580, separately from PR #31 (Praxis algebra). The CPU workflow measures the real Nova fold and compressed proof. SP1 guest source is prepared but its VK pin is intentionally UNSET. No full SP1 proof, Groth16 wrapper, witness encryption, or Bitcoin spend has been demonstrated by this branch.

## Architecture

Existing M16 is not just a prospective verifier: it checked the genesis-anchored Bitcoin mainnet header chain and a confirmed SPV payment via Nova 0.76.0, SP1 6.9.0, the BLAKE3 wrap and M14 garbled verification. M18 folds an assume-valid UTXO window with Pallas Poseidon and 72 field elements. Reuse those verified computations; M18 is not full consensus validation or a global UTXO commitment. For M18 verify all segments from canonical empty-window z0, match each boundary, require sealed, link H-1 and T to the selected chain, and constrain output membership and its SHA256d transaction/script binding.

The shared application statement should be derived by verifying M16, M18 (if required), and the new settlement fold in one pinned SP1 program, with a policy-selected checkpoint/chainwork and exact Bitcoin transaction checks. Keep the existing BLAKE3 wrap for BitVM3. For Praxis, instead produce SP1's standard BN254 Groth16 proof of the same guest and public values, with the honest setup/key provenance required by Praxis. M13's 2026-11-24 public-values digest fix is mandatory: recompute the digest inside the checked wrapper relation, bind exit code, program key, recursion key root, completeness and committed public values. Do not use the earlier vulnerable M13 final verifier. SP1's BN254 wrap and its Groth16 public inputs must be audited against the exact pinned SDK/verifier, not guessed or substituted with the M13 BLAKE3 proof format. The Groth16 proof is the Praxis witness, not the native Nova proof.

## PNS-01 step relation

Use one fixed shape with depth 8 (256 claim slots) and Pallas/Vesta, sharing the M18 Poseidon sponge. Each step verifies one authorized indexed claim and debits a running budget. A scope digest denotes the chain/network, contract, epoch and authoritative predecessor state. This scope must be constructed from policy and authenticated state outside the fold. Avoid a circular commitment: do not put the claims tree root or the final payout accumulator in the scope. The separate context digest binds those values, the funding outpoint, transaction digest, fee, policy/version and checkpoint.

State z has 11 field elements, in order:

| i | field | rule |
|---|---|---|
| 0–1 | scope digest | two 128-bit little-endian limbs of raw 32 bytes |
| 2 | authorized claims root | Pallas field, canonical LE bytes |
| 3–4 | context digest | two 128-bit little-endian limbs of raw 32 bytes |
| 5 | expected payout count | 1..256 |
| 6 | initial net available sats | 0..MAX_MONEY; fee already reserved |
| 7 | processed count | 0 at initialization, +1 per step |
| 8 | next allowed claim index | 0 initially, index+1 after each step |
| 9 | remaining budget | starts equal to z6, decreases by exact amount |
| 10 | payout accumulator | Poseidon(1004,scope0,scope1) initially |

Claim leaf = Poseidon(1001,scope0,scope1,index,script_hash0,script_hash1,amount). Empty leaf = Poseidon(1005). Node = Poseidon(1002,left,right). The witness supplies an 8-bit index, script SHA256, positive amount, and eight sibling field elements. The same index bits select path orientation. Authenticate membership in z2. Enforce index >= z8 via an 8-bit gap, count remaining via an 8-bit difference, amount >0 and remaining - amount via 51-bit differences. Inputs and outputs are range-constrained so field wrap cannot fake negative balances. MAX_MONEY = 2.1e15. There is no witness-dependent circuit shape or conditional synthesis. Append Poseidon(1003,old_acc,index,script_hash0,script_hash1,amount). Every index occurs at most once per fold.

The claim root is an **authenticated application liability registry**, not the M18 Bitcoin UTXO root. A tree supplied solely by a prover would let it authorize arbitrary recipients. The upstream ledger must establish correct liability, authorization, unique claim IDs and cross-epoch nullifier rules, and bind the funding balance and root to the previous accepted state. Strict increasing indices alone cannot establish global nullifier uniqueness. No general user exit/reorg policy has been proved.

At final verification reconstruct initial z0 from independently registered policy and expected outputs, verify exactly count Nova steps, match all invariant fields, require zn[7]=count, zn[8]=expected_last_index+1, zn[9]=exact change, zn[10]=expected accumulator. Count, amount, fee and change must reconcile with the Bitcoin prevout(s). Transaction parsing must match every committed output (including duplicates/order and change), and independently recompute BIP341 sighash over exact prevouts, amounts, scripts, sequences, outputs, version, locktime and flags. Restrict initial pilot to one funding input, all-output SIGHASH_DEFAULT and no annex. Independent policy must authorize change address and timelocked refund path. Do not treat a hash supplied by an untrusted prover as checking a transaction.

## Stable release journal PNS1

440 bytes, exact order (offsets half-open):
- [0,4) magic PNS1; [4,8) count LE u32;
- [8,360) all 11 canonical LE 32-byte initial state elements;
- [360,392) expected payout accumulator, canonical field;
- [392,400) expected change LE u64;
- [400,408) last index+1 LE u64;
- [408,440) SHA256 of the pinned Nova compressed verification key.

The native exporter also writes PNV1 with actual proof hash for diagnostics. **Never encrypt against PNV1.** The release statement must be computable when the ciphertext is prepared, before the proof exists. The test SP1 adapter uses PNS1 as its exact public values and verifies the fold against a compile-time pin. It checks every terminal field, the initial accumulator, canonical field representations, count, bounds and key bytes. It does not yet enforce M16/M18 or transaction/policy authentication; therefore pinning a PNS1 journal alone is a fold test, not deployment authorization. Final guest should have a distinct domain/version/ELF and VK pin after the additional checks. Guest currently uses compressed VK; adapt M15's raw affine conversion and pin compressed/raw key pair after measuring cycles. Never accept a VK or expected guest digest chosen by the prover. Nova 0.76 bincode cross-type deserialization must be tested (the verification-only circuit marker does not synthesize).

## Reproduce

```sh
cargo test --release --manifest-path integrations/praxis-nova/Cargo.toml -- --nocapture
RAYON_NUM_THREADS=2 cargo run --release --manifest-path integrations/praxis-nova/Cargo.toml -- /tmp/praxis-nova-pilot
```

Three deterministic test payouts (1200,800,500 sats) at indices 3,17,245 from a 3000-sat net budget, leaving 500. Reject altered amount, script, index, sibling, scope, root, range, noncanonical remaining, zero amount, overdraw, duplicate and descending index, exhausted count, wrong final accumulator/change/count/context. Verify real recursive and compressed proof against native trace, reject wrong z0 and step count. Export proof, vk, z0, zn, diagnostic journal, stable statement and receipt. CI uses two CPU threads and captures exact constraint count, wall time, proof bytes, key bytes and peak RSS. No Silico or GPU allocation.

## Handoff (Carbon / Neon)

PNS-02: obtain CPU receipt; pin the generated VK hash only for test guest; build SP1 6.9.0 guest via existing M16 build approach. Execute it on the archived proof, key and PNS1, and check exact byte equality of committed values. Reject substituted VK, z0, terminal fields, count, malformed proof, trailing bytes. Measure cycles, peak RAM; use M15 raw affine pin pair if decompression dominates. Do not start a full proof until guest execution and all mutations pass.

PNS-03: add M16/M18 verification and a fixed authoritative context construction to the guest, with output list/sighash checks and nullifier/epoch rules. Compile and pin the program. Test proof replay, chain tip and reorg substitutions, alternate recipients, fee/change, wrong liability root, wrong network and outpoint. Establish selection of chain by independently authenticated checkpoint/work, not mere existence of a valid-work fork. Preserve M13 public-values digest negative controls, including values replaced before proving.

PNS-04: use existing SP1 compressed proof pipeline and generate standard Groth16 wrap using pinned SP1 6.9.0 SDK and its shipped wrap artifacts. Verify independently against the exact native BN254 public inputs and official VK; export canonical proof/VK/public inputs, preserving encoding semantics. Audit any truncation or field reduction of public-value digest, program-key binding, public-input vector, setup assumptions and subgroup validation. Reuse verified outputs for PR #31 only after its actual Groth16-to-BQS verifier compiler and production Enc/Dec are available. Pin the fixed statement and keys first; two separate randomized proofs for one fixed statement must both satisfy the relation. Reject other guest/statement combinations. No fallback to a trusted host verifier as a circuit witness.

PNS-05: compare shared off-chain circuit plus BLAKE3 garbled route versus shared off-chain circuit plus Groth16/Praxis release. The off-chain fold is common work; measure incremental proof wrapping, per-condition ciphertext, availability, capital lockup and signature-provisioning trust. Before any regtest proof-conditioned spend, integrate independently audited signing/release ceremony and authenticated encryption. This branch changes neither M13/M14 verifier nor any existing on-chain path.
