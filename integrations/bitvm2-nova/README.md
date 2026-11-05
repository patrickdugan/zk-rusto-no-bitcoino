# BitVM2 Nova/IPA backend

This starts a transparent Nova verifier backend for BitVM2. M1 emits real
Bitcoin Tapscript for arithmetic over both Pasta fields and checks the IPA
verification equality in a separate native reference. The complete Nova
verifier and bridge transaction graph remain unimplemented. BitVM3 is outside
this package. Existing header provers and the default Rust crate are unchanged.

Later milestones add complete point arithmetic, compact predicates and the
[global WOTS registry](WOTS-REGISTRY.md). The production transcript, retained
NHT4/native Nova checks, Spartan folds and one Keccak Script round are described
in [NATIVE-CONFORMANCE.md](NATIVE-CONFORMANCE.md). These are components of the
transparent Nova SNARK verifier; complete authenticated verification and the
Bitcoin transaction graph remain unfinished.

## What runs

`script.py` emits enabled Bitcoin opcodes for modular addition and the
multiplication transition `t_next = (2*t + bit*a) mod p`. It uses nine
little-endian 29-bit limbs. Script computes carries itself. There are no
unconstrained carry hints, OP_MUL, OP_CAT, or OP_SUCCESS instructions.

The native multiplication iterator streams 255 MSB-first transitions. Tests
execute every transition for both fields and compare the final value with
Python's independent big-integer multiplication. This establishes the local
arithmetic kernel. The eventual trace adapter must authenticate the link
between adjacent transitions and the bits of the multiplier.

A fixed-claim disproof fixture commits every opened word with SHA-256 and
includes a context digest in the leaf. Its final predicate is the inverse of
the arithmetic equality. For admitted inputs, an honest claim cannot be
refuted by changing an opening; a wrong output has a successful disproof.
These fixture-specific commitments must be replaced or integrated with the
operator's authenticated assertion mechanism before deployment. There is no
BitVM2 WOTS or transaction-graph adapter in M1.

`ipa_algebra.py` implements the equality from the inspected Nova IPA source:

```
C + (r0*c)U + sum_j(u_j^2 L_j + u_j^-2 R_j)
    = a_hat * sum_i(s_i G_i) + (r0*a_hat*<b,s>)U
```

It checks this on Pallas and Vesta, including point and scalar validation.
The coefficients `s_i` are generated in upstream order with logarithmic
auxiliary storage. Tests construct small IPA fixtures and alter every round.
The fixture transcript and generator derivation are explicitly TEST-ONLY.
`verify_equation` accepts externally supplied challenges and therefore verifies
only algebra. It cannot authenticate a Nova proof. Production Fiat-Shamir,
Nova generator derivation, Spartan sumchecks and compressed-proof decoding
must be connected to the pinned upstream implementation.

## Run

Python 3.10+ and the pinned mature Keccak dependency run the local references:

```sh
cd integrations/bitvm2-nova
python -m pip install -r transcript-requirements.txt
python -m unittest discover -s tests -v
python bench.py
```

For independent execution, Rust builds the upstream BitVM interpreter at the
revision in `rust-oracle/Cargo.toml`:

```sh
cargo generate-lockfile --manifest-path rust-oracle/Cargo.toml
cargo run --locked --manifest-path rust-oracle/Cargo.toml -- results/engine-vectors.json
```

The CI job runs this differential check with the 1,000-item stack limit
turned on. It preserves the resolved Cargo.lock and dependency tree as
artifacts. The upstream BitVM revision is pinned; transitive git dependencies
are captured by that run's lockfile. Commit an audited lockfile before relying
on reproducible release builds.

## Measured primitive sizes

Local run: November 5, 2026. `results/kernel-bench.json` records exact script
hashes and the Python environment. `results/local-tests.txt` records 25 tests.
The Rust interpreter's results must be read separately from CI artifacts.

| Kernel, either field | Bare Script | Fixed-claim disproof | Witness items | Reference peak stack |
| --- | ---: | ---: | ---: | ---: |
| Modular addition | 2,494 bytes | 3,538 bytes | 27 | 177 |
| Multiply bit-step | 3,818 bytes | 4,900 bytes | 28 | 215 |

The fixed-claim sizes include per-word hash checks and the context tag. They
exclude transaction framing, control blocks and dynamic assertion signatures.
These figures describe primitive scripts; they do not estimate bridge fees or
the size of a complete Nova dispute graph. Python timings are interpreter
measurements and cannot stand in for Bitcoin Script or header-proving speed.

## RAM budget and k

The existing Nova prover's `k` controls the number of headers in its step
circuit. Keep it fixed for a continuation, as the existing implementation
requires. This backend preserves that architecture. M1's multiplication trace
is an iterator, so it can be consumed with bounded buffering. Chunk/buffer
size in the verifier backend is a separate knob from the prover's `k`.

The inspected IPA verifier computes `ck_hat = commit(ck, s)` over `n`
generators. Its verification work depends on that dimension even when proof
bytes grow logarithmically. Obtain `n` from the actual pinned verifier key.
A small compressed proof does not determine the total Script budget. M1
streams coefficient generation; the supplied generator and b vectors still
occupy their caller's memory. A disk-backed generator source is future work.

## Trust and scope

No ceremony or secret setup randomness is used here. The intended full route
remains Pallas/Vesta Nova with Spartan/IPA and no Groth16/KZG wrapper. Avoiding
a ceremony does not establish the soundness of this new implementation.
No funds should rely on it. No Bitcoin transactions are broadcast by the tests.

The compiler's inputs must be admitted canonical ScriptNums, with canonical
input field elements and a Boolean multiplier bit. Malformed encodings abort
execution. A production protocol needs a completeness argument covering
malformed assertions, so an operator cannot escape a dispute by committing
an inadmissible state. The reference interpreter is stricter than a full
consensus implementation in some encoding policies and fails closed on all
opcodes outside its subset. The Rust differential check covers emitted
fixtures, not every possible witness or transaction policy.

`NEXT.md` gives the next implementation boundary and the arithmetic argument.
