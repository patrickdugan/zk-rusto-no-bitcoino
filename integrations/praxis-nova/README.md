# Praxis / Nova settlement pilot (PNS-01)

Status: research, no funds. Prepared 2026-11-24 on main 01698bdb590ff38c3d3077dc5cba534a63ef5580. Nova is the sole proof system for this branch. The CPU workflow exercises a native recursive fold and Spartan/IPA compressed proof. Praxis witness-encryption integration is a separate direct verifier-compilation research task; no witness encryption or Bitcoin spend has been demonstrated.

## Architecture

Existing M16 is not just a prospective verifier: it checked the genesis-anchored Bitcoin mainnet header chain and a confirmed SPV payment via Nova 0.76.0, SP1 6.9.0, the BLAKE3 wrap and M14 garbled verification. M18 folds an assume-valid UTXO window with Pallas Poseidon and 72 field elements. Reuse those verified computations; M18 is not full consensus validation or a global UTXO commitment. For M18 verify all segments from canonical empty-window z0, match each boundary, require sealed, link H-1 and T to the selected chain, and constrain output membership and its SHA256d transaction/script binding.

The new route is Nova-only. Compose authenticated native Nova proofs for headers, the windowed UTXO map if required, and settlement. Freeze PNS1 (and a distinct future composite statement) before proving. The release relation directly checks compressed Nova proof(s) under pinned verification keys and expected start/end states. No SP1 guest, STARK wrapper, Groth16 wrapper, or additional proof system is required or planned for this branch. Existing BitVM3 M13/M14 remains unchanged.

Praxis is a general NP witness-encryption construction. Its published concrete parameters specialize to a Groth16 verifier; they do not transfer to the native Nova verifier. For a Nova-only route, compile the actual native Nova verification predicate directly into a Boolean quadratic system over the scalar field of the Praxis pairing groups. The compressed Nova proof and constrained verification auxiliaries are the witness. Praxis still needs its own pairing arithmetic and security assumptions; Nova itself does not implement witness encryption. See DIRECT_NOVA_BQS.md. If direct encoding is infeasible, report that result rather than introducing another proof system.

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

The native exporter also writes PNV1 with actual proof hash for diagnostics. **Never encrypt against PNV1.** The stable release predicate uses the PNS1 statement, fixed independently before proof generation. The native oracle checks both an externally pinned PNS1 digest and a separately pinned VK digest, rejects noncanonical encodings and wrong terminal values, verifies the compressed Nova proof, and checks the initial and final boundary. The trusted registration of statement and key is essential; a hash supplied by the prover is insufficient. The native oracle is a differential reference, not the BQS encoding and not authorization on Bitcoin. Generic bincode decoding is not a hardened hostile-input parser.

## Reproduce

```sh
cargo test --release --manifest-path integrations/praxis-nova/Cargo.toml -- --nocapture
RAYON_NUM_THREADS=2 cargo run --release --manifest-path integrations/praxis-nova/Cargo.toml -- /tmp/praxis-nova-pilot
```

To verify an exported fixture independently, run:

```sh
cargo run --release --manifest-path integrations/praxis-nova/Cargo.toml -- --verify /tmp/praxis-nova-pilot EXPECTED_PNS1_SHA256 EXPECTED_VK_SHA256
```

Three deterministic test payouts (1200,800,500 sats) at indices 3,17,245 from a 3000-sat net budget, leaving 500. Reject altered amount, script, index, sibling, scope, root, range, noncanonical remaining, zero amount, overdraw, duplicate and descending index, exhausted count, wrong final accumulator/change/count/context. Verify real recursive and compressed proof against native trace, reject wrong z0 and step count. Export proof, vk, z0, zn, diagnostic journal, stable statement and receipt. CI uses two CPU threads and captures exact constraint count, wall time, proof bytes, key bytes and peak RSS. No Silico or GPU allocation.

## Handoff (Carbon / Neon)

PNS-02: complete CPU receipt and exercise native pinned artifact verification. Export both the fixed statement and compressed proof. Verify independent re-proofs, incorrect keys, wrong initial/terminal state, count, malformed proof, trailing bytes, and noncanonical encodings.

PNS-03: compose M16/M18 native Nova verification and authoritative context, exact Bitcoin transaction checks, liability authentication and cross-epoch nullifier rules. Pin each Nova key and bounded segment count; chain every verified state; require M18 sealed, tie both window endpoints to selected headers, enforce finality and checkpoint policy. Do not rely on a host-provided boolean or digest as proof of these checks.

PNS-04: compile the native compressed Nova verifier into BQS directly using the work order in DIRECT_NOVA_BQS.md. Start with an arity-one native proof and reuse Pasta arithmetic and transcript kernels from bitvm3-nova M1–M11. Audit exact semantics and pin the compiler, proof shape, keys, statement and variable ordering. Measure actual counts and derive admissible Praxis parameters. No second proof system.

PNS-05: once direct BQS and real witness encryption pass their independent gates, compare the common Nova computation plus direct witness-conditioned release against the existing BitVM3 path. Account for storage, decryption, signing trust, ciphertext availability and refund races. Regtest only, no funds.
