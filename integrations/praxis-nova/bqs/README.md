# PNS-04A/B: direct native Nova verifier BQS backend

Scope: CPU research, no funds. This extends PR #32's Nova-only path.
Nova 0.76.0, Pallas/Vesta, Spartan/IPA. No other proof system.

## A. Pinned circuit backend

Source: garbled-snark-verifier rev 8fa7efe495ea1bd4675f9c8bbd29f0b6e8bee051, modules
src/nova.rs, src/nova/transcript.rs, src/nova/sumcheck.rs,
src/nova/sumcheck/chain.rs. The backend implements the actual CircuitContext
trait, inlines every named child with a single wire namespace, validates
acyclic single-definition topology and compiles all gate types. No garbling
or free-XOR assumption.

For gate truth table f, define D=f(0,0), L=f(1,0)-D, R=f(0,1)-D,
M=f(1,1)-D-L-R. Encode M*a*b = z-L*a-R*b-D*w0. BQS imposes bitness
of every variable, w0=1. Wire FALSE maps to w1 with constraint w1=0;
TRUE maps to w0. The final accept gate is pinned to 1. Public input bits
are independently pinned where specified. For bounded binary assignments
the integer residual has magnitude at most 8, so zero in BN254 Fr is
equivalent to integer zero. Gate-level assignment uniqueness follows
by induction along the acyclic graph. Native GateType evaluates the
assignment; the separate quadratic residual checker accepts or rejects
it. Truth polynomial test covers all 16 possible truth tables and all
8 input/output combinations, including gates absent in the fork.

Optional compact export: 16 bytes per row, u32 LE input a,b and output z,
then signed i8 D,L,R,M. Headerless rows.bin accompanied by manifest.json
and assignment.bin (one byte per slot). Rows first, then pin rows.
Manifest includes ordered input slots, variable count, row counts and SHA256
of domain tag PNS-BQS-GATES/v1 followed by NUL, slot count, input count,
gate/pin counts (u64 LE), ordered u32 LE input slots and row bytes.
This is an interchange format; bitness and w0=1 are part of the relation.

Native CI fixtures: modular add/multiply for each Pasta field, degree 2
and degree 3 Spartan rounds for each field with challenges computed by the
actual Keccak transcript kernel, and a two-round quadratic Spartan chain.
Native Nova SumcheckProof::verify is the positive oracle. Negative controls
include noncanonical values, changed coefficients, changed next claim,
nonbit witness, altered intermediate, false acceptance, transcript reset
before round 2, and changed suffix challenge. The isolated round pins
initial and final claims; the chain pins context and initial claim and
checks actual computed final and suffix. Full Spartan polynomial evaluation,
matrix/IPA openings and Nova proof/state composition remain to be connected.

## B. Optimized shared limb reference (executed)

Use 8 radix-2^32 limbs for each canonical 255-bit Pasta scalar.
Canonicality: x + slack = p - 1, 255-bit slack and 7 binary carries.
Multiply using a*b = r + k*p, canonical a,b,r,k, 16 convolution columns,
15 signed 37-bit carries, exact bounded local residuals. Max absolute
column residual bound 590295810294281142287 < BN254 Fr modulus.
No wrap; multiply equations telescope to integer equality. Quotient and
remainder are unique for canonical inputs. Addition/subtraction uses a
one-bit modular correction and bounded signed carries. Wide transcript
reduction uses a 258-bit quotient and 512-bit dividend constrained to the
actual digest wires when integrated. This reference tests arithmetic only;
no free challenge is admissible in the final verifier.

Executed JS result: 304 positives, 402 negative controls, 128 truth-table
assignments. Both Pasta fields have identical optimized counts:

| kernel | Boolean unknowns | BQS equations |
|---|---:|---:|
| standalone multiplication | 2623 | 48 |
| incremental multiplication (inputs already canonical) | 1589 | 32 |
| incremental addition | 532 | 16 |
| incremental wide reduction (digest bits allocated) | 1330 | 24 |
| quadratic sumcheck arithmetic only | 7906 | 192 |
| cubic sumcheck arithmetic only | 11076 | 264 |

Max eight products per multiplication equation. The counts exclude implicit
bitness, and sumcheck excludes Keccak. From the pinned Boolean source,
canonical C=768+popcount(p), add A=2816+popcount(p), double
D=1536+popcount(p), radix-4 select S=1792, admit=3C+2.
Standalone add has admit+A+768+1 gates. Multiply has
admit+D+A+S+127*(2D+S+A)+768+1 gates. Compiler measures every gate; source
counts are asserted during the native run:

| Field | add gates | mul gates | standalone mul unknowns incl input and false slot |
|---|---:|---:|---:|
| Pallas base | 6079 | 1002721 | 1003490 |
| Vesta base | 6067 | 1001563 | 1002332 |

The limb relation has about 382x fewer Boolean unknowns for standalone
multiplication. This is a comparison of relation encodings, not measured
encryption/proving speed or whole verifier size.

## Reproduce

From repository root:
```sh
node integrations/praxis-nova/bqs/limb_reference.js
cargo test --release --manifest-path integrations/praxis-nova/bqs/Cargo.toml
cargo run --release --manifest-path integrations/praxis-nova/bqs/Cargo.toml
# Optional (large unoptimized files):
cargo run --release --manifest-path integrations/praxis-nova/bqs/Cargo.toml -- /tmp/pns-bqs-rows
```

CI runs both references and records native counts and peak RSS. JS receipt
was executed in this research turn; Rust compile and native differential
remain pending until CI. No claim of full verifier encoding.

## Next gate PNS-04C

Use the BQS backend for outer/inner Spartan transition, batched sumcheck
and R1CS evaluation kernels. Audit the two Spartan/IPA commitment
opening checks and Nova folding transcript and bind the real arity-one
SquarePlusFive compressed proof end-to-end. Replace Boolean field multiply
and wide reduction with shared limb equations only after differential tests.
Pin verifier key and public statement; enforce exact point/canonical scalar
encodings, transcript byte scheduling, group operations and final acceptance.
Compare accepting and rejecting traces against actual Nova 0.76 verification.
Only then derive Nova-specific Praxis QAP dimensions and security parameters.
