# M17: Bitcoin Script on Nova (Shinigami's engine as a folding step)

M17 proves that a transaction input's scripts execute successfully under Bitcoin Core's rules. It
covers legacy scripts, P2SH and witness v0, and folds one machine step per Nova step on the same
curve cycle as the header chain (Pallas/Vesta, IPA). The semantics are those of the Shinigami fork
(`patrickdugan/shinigami`, branch `taproot-provable`), whose Cairo engine passes Bitcoin Core's
script vectors. The same vectors, built by that fork's `vectors.py`, test every layer here.

Shinigami proves a Cairo execution with a STARK. Nova's 0.76 has no non-uniform folding, so the
engine became one fixed step circuit with a small machine behind it:

| Piece | What it does |
| --- | --- |
| [`compile.rs`](src/compile.rs) | Turns Core's VerifyScript for one input (scriptSig, scriptPubKey, P2SH redeem script, witness program) into a linear program. Everything Core decides from the scripts and flags alone is decided here: script and push sizes, disabled opcodes, OP_VERIF, parse failures, CONST_SCRIPTCODE, SIGPUSHONLY, witness program shapes, P2SH-witness malleation, MINIMALIF and NOP/CLTV/CSV flag handling. |
| [`isa.rs`](src/isa.rs) | 75 instructions (Bitcoin opcodes plus pseudo instructions for the orchestration between scripts) and 14 phase codes for multi-step operations. Each dispatch code has a control row: pops, pushes and their sources, functional units, register updates, claim. |
| [`engine.rs`](src/engine.rs) | The native machine: Core semantics on real bytes. Each step emits the circuit's witness and the next state vector. |
| [`circuit.rs`](src/circuit.rs) | The step circuit, 6,808 constraints. |
| [`sigcheck.rs`](src/sigcheck.rs) | Core's signature rules: legacy and BIP143 sighash, FindAndDelete, DER/low-S/hashtype/pubkey encodings, NULLFAIL, NULLDUMMY, the CHECKMULTISIG loop, CLTV and CSV. |

## The machine

State (19 field elements):
- the commitment of the remaining program;
- the main, alt, temporary and saved stacks, each as a Poseidon hash chain with its depth;
- Core's condition stack (size, position of the first false);
- the opcode count, the claim accumulator, the script id, the CODESEPARATOR offset;
- a phase, a counter and two holding registers for multi-step operations.

Stack elements are single field elements:
- an element of up to 30 bytes packs its length and bytes, so the circuit can read numbers, sizes
  and truth values back by bit decomposition;
- a longer element is 2^249 plus a 248-bit Poseidon digest of its bytes.

What one step does:
1. Opens the current instruction against the program commitment.
2. Decodes its dispatch code one-hot.
3. Pops up to six elements; each pop is a hash preimage check.
4. Runs the functional units: three CScriptNum decoders with the minimal-encoding rule, four
   comparators, a minimal number encoder, castbool and length on the top element, element
   equality.
5. Pushes up to six results.
6. Updates the condition stack exactly as Core's ConditionStack does.
7. Checks the opcode limit (201) and the stack limit (1,000).

PICK, ROLL and CHECKMULTISIG run over several steps through the temporary stack and the holding
registers.

### Claims

Some checks are deferred to a claim checker:
- signature checks (CHECKSIG, CHECKMULTISIG with its whole loop);
- hash opcodes;
- CLTV and CSV;
- castbool and size of elements longer than 30 bytes.

Each deferred check appends a claim to a Poseidon accumulator in the state.

The checker:
1. Compiles the spend itself, which gives z0.
2. Verifies the folded proof.
3. Requires that the final state has consumed the program and has no operation in progress.
4. Checks every claim against Core's rules.
5. Recomputes the accumulator from the claim payloads alone.

The circuit never computes a signature hash or a SHA-256. In the BitVM3 pipeline the checker
would run inside the SP1 guest next to the Nova verifier, where secp256k1 and SHA-256 have
precompiles. That guest is not built yet.

## Results

All runs below were on the laptop, in WSL, while the mainnet header fold (M16) held 20 CPU
threads. Times are therefore contended.

### Native engine against Core

Bitcoin Core's `script_tests.json` and `script_assets_test.json` give 4,995 checks.
- 2,756 checks are legacy, P2SH or witness v0 (including the script_assets entries checked
  without the Taproot flag). The engine agrees with Core on all 2,756 and disagrees on none
  (`nova-script vectors`).
- 2,239 are Taproot spends, which this milestone does not cover.

### Step circuit against the engine

`nova-script circuit` checks every step of every valid case through the circuit:
- the step must be satisfied;
- its output must equal the engine's next state.

For every invalid case that fails at a machine step, it feeds the failing step's witness to the
circuit. That step must be refused, unless the failure came from a claim check.

| Outcome | Count |
| --- | ---: |
| Valid cases | 1,808 |
| Valid-case steps, each satisfied with the engine's exact next state | 29,121 |
| Invalid: the circuit refused the failing step | 819 |
| Invalid: rejected by a claim check (signature encoding, NULLFAIL, locktime) | 72 |
| Invalid: rejected by the compiler (static rules) | 57 |
| Taproot, skipped | 2,239 |

All 2,756 non-Taproot checks are accounted for, with no failure. The run took 3,330 s with
19 MB peak memory.

### Nova proofs

`nova-script prove` folds each case. Then it verifies as the checker: z0 recomputed from the
compiled program, the final state, and the claims. It also verifies once more with the step count
off by one, which must fail.

| Case | Script | Steps | Claims | Prove | Verify |
| --- | --- | ---: | ---: | ---: | ---: |
| script_tests/1055 | P2PKH | 10 | 1 | 8.0 s | 0.75 s |
| script_tests/1059 | P2SH multisig | 31 | 2 | 25.8 s | 0.65 s |
| script_tests/1135 | P2WPKH | 21 | 2 | 17.4 s | 0.71 s |
| script_tests/1134 | P2WSH | 17 | 2 | 14.2 s | 0.75 s |
| script_tests/1137 | P2SH(P2WPKH) | 30 | 3 | 29.5 s | 0.78 s |
| script_tests/1136 | P2SH(P2WSH) | 26 | 3 | 25.8 s | 0.87 s |
| script_tests/74 | `0 ROLL` | 18 | 0 | 16.9 s | 0.68 s |
| script_tests/216 | DUP HASH160 SWAP SHA256 RIPEMD160 EQUAL | 13 | 3 | 13.1 s | 0.63 s |
| script_tests/224 | NOP1 CLTV CSV NOP4–10 (flags off) | 19 | 0 | 16.7 s | 0.75 s |
| script_tests/417 | 2-key CHECKMULTISIG, no signatures | 20 | 1 | 16.9 s | 0.83 s |

- Setup took 14.2 s.
- Folding ran at 0.8 to 1.0 s per step with 4 threads.
- The step count off by one was refused in all ten cases.

Compressed with Spartan over IPA (`nova-script compress`), script_tests/1059 (P2SH multisig,
31 steps):

| Setup | Prove | Proof size | Verify | Peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| 2.5 s | 34.0 s | 11,480 bytes | 0.84 s | 197 MB |

### Tampering

`nova-script mutate` changes one witness field per step. It ran on 12 valid cases (the ten above,
plus `0 PICK` and WITHIN).
- Fields every step reads (the instruction opening, the commitments under the pops, every popped
  element) must leave the step unsatisfied.
- Fields only some rows read (W, the alt-stack and temporary-stack values) must either be refused
  or change the committed state.

Result: 1,955 tampered steps, 1,264 unsatisfied. Every change to a read field was refused.

## Not covered

- Taproot and tapscript: key-path spends, OP_CHECKSIGADD, OP_SUCCESS, the validation weight
  budget.
- The checker inside SP1. The claim checker exists natively (`engine::verify_claims`), and the
  SP1 guest that would run it beside the Nova verifier is the next milestone.
- Compressed proofs inside the existing guest-A pipeline: this circuit has its own verifier key.

## Run

```
python3 scripts/export_vectors.py SHINIGAMI_DIR script_tests.json script_assets_test.json cases.jsonl
bash scripts/cargo.sh build --release        # WSL; syncs into /root/nb3/m17
nova-script vectors  cases.jsonl
nova-script circuit  cases.jsonl
nova-script prove    cases.jsonl script_tests/1055 ...
nova-script mutate   cases.jsonl script_tests/1055 ...
nova-script compress cases.jsonl script_tests/1059
```

`sigcheck.rs` has its own unit tests (15, all passing): the block-170 P2PK spend, BIP143's
P2WPKH and P2SH-P2WPKH examples, FindAndDelete, DER edge cases, SIGHASH_SINGLE out of range,
multisig NULLFAIL/NULLDUMMY, CLTV and CSV.
