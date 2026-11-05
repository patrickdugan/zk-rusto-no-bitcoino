# M2.1: opt-in multiplication Script compaction

This milestone reduces the fixed-claim disproof Script footprint on top of PR
#18, commit `474299439e178da7b965d6c3716bdb8320e082d3`. It preserves the M2
graph and default compiler. It does not implement a complete Nova verifier.

## Change and arithmetic argument

`bound.script(ordinal, compiler='compact-v1')` selects the experimental compiler;
`compiler='m2'` remains the default. `bound.execute` takes the same option.
Only `mul_bit` predicate bodies change. A separate compiler domain is included
in each compact leaf's identity tag. Program/claim identities and wire openings
are unchanged; caller-owned `require_identity` checks remain necessary.

`compact.py` replaces the repeated lexicographic comparisons of the two field
inputs with radix-2^29 subtraction-borrow comparisons. First, every input and
output limb still receives the original range check. Subtracting a modulus
limb and the preceding borrow gives `t_i = x_i - p_i - borrow_i`, in
`[-2^29, 2^29-1]`. The next borrow is `t_i < 0`, a Script Boolean. The final
borrow is one exactly when `x < p`; Script verifies it. Thus equality with the
modulus and values above it still abort before computing a predicate result.
Every numeric opcode operand stays within the original four-byte ScriptNum
bound. Both Pasta moduli use the same argument.

The builder also emits `OP_DUP` for `0 OP_PICK`, `OP_OVER` for `1 OP_PICK`, and
`OP_2DROP` for pairs of discarded stack items. These have the same successful
stack effects. No disabled or experimental opcode is introduced. The Python
interpreter and independent Rust allowlist add exactly those three enabled
opcodes; OP_CAT remains disabled and OP_SUCCESS remains forbidden.

The arithmetic itself retains both original modular additions for
`(2*t + bit*a) mod p`, Boolean validation, canonical comparisons, and output
equality. Every leaf retains the exact `OP_DEPTH ... OP_EQUALVERIFY` guard
before indexed opening access, each per-wire SHA-256 check, ordinal, predicate
direction, and verifier-owned field/role/program/context/claim identity.
Bit reconstruction, nine initial zero-word anchors, all 255 transitions, and
final product equality are unchanged. Both complete point graphs retain all
13 multiplications and every point-validity and dispatch constraint.

## Measured ledger

`bench_compact.py` uses the exact M2 benchmark inputs, operation IDs and context
and sums the actual disproof bytes of **every leaf once** for both compilers.
Its report includes a SHA-256 over length-prefixed leaves in ordinal order.
The guard-inclusive baseline is checked against M2-CI-NOTES.md, not M2.md's
historical pre-guard table. Both Pallas and Vesta give these sizes:

| Operation | Leaves, both compilers | M2 Script bytes | compact-v1 Script bytes | Saving |
| --- | ---: | ---: | ---: | ---: |
| Field multiplication | 274 | 1,268,152 | 1,083,022 | 185,130 (14.60%) |
| Complete affine point addition | 3,616 | 16,554,753 | 14,148,063 | 2,406,690 (14.54%) |

The bare bit-step kernel falls from 3,818 to 3,092 bytes. The largest bound
disproof leaf falls from 4,904 to 4,178 bytes. The saving is 726 bytes per
bit-step, times 255 steps per multiplication and 13 products per point graph.
These aggregate sizes exclude transaction framing, control blocks, assertion
signatures, and the rest of the BitVM2 transaction graph. They are not fees.

There is **no reduction in leaf count, witness items/payload, or maximum stack**.
Peak stack remains 215 items. The compact reference bit-step executes 2,410
instructions; this is not upstream's unavailable Tapscript opcode count.
The complete point graph still exceeds 14 MB of aggregate Script. This result
does not establish practical bridge economics or deployability.

Local generation took 10.526 s and peaked at 43,294,720 bytes of Windows working
set (about 41.3 MiB). Working set can be trimmed by the OS. This was not an
OS-enforced ceiling or a proof-generation benchmark. Scripts are streamed,
with one complete admitted trace retained at a time; no prover was launched.

## Validation and reproduction

The new tests compare both compilers with independent integer expectations
on edge and deterministic random cases. They execute every compact point leaf
on both curves, and refute altered bits, each accumulator including the zero
anchor, final results, and coherent traces using the wrong multiplier.
Changed openings, false point/slope claims, role/context/program substitutions,
noncanonical fields, nonminimal/oversized/negative limbs, invalid bits, and
empty/truncated/prepended/appended witnesses are covered. The original witness
arity regression test is retained unchanged. Golden default leaf hashes were
captured directly from the `4742994` source.

The new generator emits 19,216 Script vectors with 9,958 expected rejections.
Expectations for raw arithmetic use Python integers, not the trace predicate;
tampered-bit and accumulator failure locations follow the fixed graph layout.
Fixture: 148,984,550 bytes, SHA-256
`b960829e50cc9bc8ff9c50c9b5ec4148c2a90e0e9b5dc4605acdd6dc2baa147b`.
The existing hosted M2 workflow retains the 10,884 baseline Script vectors and
74 independent halo2curves cases, and runs the new corpus separately through
the same pinned upstream interpreter. Actual initial witnesses, minimal
encodings, the 1,000-item stack limit and disabled OP_CAT remain enforced.
Interpreter panics are fatal: they are not caught or counted as rejections.

```sh
cd integrations/bitvm2-nova
python -m unittest discover -s tests -v
python bench_compact.py
# On a runner suitable for the small independent oracle build:
cargo generate-lockfile --manifest-path m2-oracle/Cargo.toml
cargo run --locked --manifest-path m2-oracle/Cargo.toml -- --scripts results/compact-engine-vectors.jsonl
```

`results/compact-local-evidence.json`, `results/compact-local-tests.txt`, and
`results/compact-baseline-comparison.json` record local outcomes. Hosted results
must be read from the completed current-head workflow; generating fixtures or
passing the Python reference is not independent Script execution. The local
Windows host was not used for a Rust build or any large proving/GPU job.

## Scope and next boundary

This remains an admitted, fixed-claim research compiler. Native admission does
not provide complete on-chain dispute coverage for malformed dynamic assertions.
Production assertion binding, actual Nova/Spartan transcripts, NHT4 decoding,
complete IPA verification, Taproot/Bitcoin transaction graphs, and release
dependency locking remain future work. No complete Nova proof was verified,
no transaction was broadcast, and no merge or deployment was performed.
The intended path stays Nova/Pallas-Vesta -> Spartan/IPA, with no trusted setup
including final compression. Existing header provers and RAM-targeted `k`,
BitVM3, and the separate Claude/testnet4 work are untouched.

Before further size projection, consider a reviewed liveness-aware stack
compiler or wider multiplication steps with complete authenticated bit
reconstruction. Measure their full graph cost against this opt-in baseline and
retain the same adversarial corpus. Do not remove range/canonical checks or
authenticated openings just to shrink the ledger.
