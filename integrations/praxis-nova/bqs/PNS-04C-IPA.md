# PNS-04C — direct Nova IPA opening relation

2026-11-24. Nova-only. This is one isolated evaluation opening, not the full
compressed Nova verifier or a witness-encryption deployment.

## Native source and exact equation

Source inspected: https://github.com/microsoft/Nova/blob/01b1e2d662a847ed7029770ecbaf6687398899dd/src/provider/ipa_pc.rs
(the corresponding Cargo.toml declares 0.76.0; our crate resolves =0.76.0).
Source blob c77b3c0cde7780ed7db0590c497cfc55666af9f1. Pin actual Cargo.lock
and registry source checksum before a production claim. The Rust fixture
uses the native public EvaluationEngineTrait prove/verify API, both Pasta
engines, lengths 2,4,8 and two deterministic input variants. The private
L_vec,R_vec,a_hat fields are accessed by a bincode layout mirror with
bytewise roundtrip and native verification. The mirror is fixture
transport, not an accepted circuit deserializer.

For x in the scalar field^ell and b_j = eq(x,j), the native protocol first
absorbs the complete evaluation context in its caller. It then uses
dom_sep("IPA"), absorb("U", commitment || evaluation), squeeze("r") = rho,
and for each round absorb("L", L_i), absorb("R", R_i), squeeze("r") = r_i.
Pasta commitment transcript encoding is x-coordinate || y-coordinate ||
one infinity byte, 65 bytes. The instance itself omits the point x:
the caller must bind the point to the existing transcript (the isolated
test prefix does so explicitly). Native challenges must be nonzero
where inverted. Preserve the continuation of that transcript.

Let H be the single IPA generator before scaling by rho, and G_j the
first 2^ell generators of the pinned commitment key. Define
s_j = product over i of (r_i when bit i of j, MSB first, is 1; otherwise
r_i^-1). Then native verification is equivalent to

C + sum_i(r_i^2 L_i + r_i^-2 R_i) + rho*(y-a_hat*b_hat)*H
  - sum_j a_hat*s_j*G_j = identity.

Here b_hat = dot(eq(x),s) = product_i((1-x_i)*r_i^-1+x_i*r_i).
The tensor factorization avoids building a second length-2^ell vector
of equality weights. The scalar-weight recurrence starts with
w_0 = -a_hat*product_i(r_i^-1), then
w_j = w_(j-2^h)*r_(ell-1-h)^2 for h=floor(log2(j)).
It avoids computing a_hat*s_j separately for every j. Verify both
identities against the native scalar oracle. The fixed-generator MSM
still has length 2^ell, which is the principal scaling obstacle.

## Direct BQS implementation

- ipa_native.rs generates real native IPA openings, reconstructs the
  native transcript and fused equation, checks the suffix challenge,
  tensor recurrence and factored evaluation, and rejects eight mutations.
- ipa_transcript.rs lowers the pinned BitVM3 Keccak transcript gates to BQS
  and exports ordered variable slot IDs for the exact typed proof and
  challenge fields. For the isolated n=2 fixture, context, commitment,
  evaluation point and claimed evaluation are public pins; L/R/a_hat are
  witness bits. Raw transcript absorption is deliberately paired with the
  scalar/point admission constraints in the suffix.
- ipa_bqs.js implements canonical Pasta limbs, signed carries, zero
  tests, modular inverse equations, complete affine point addition,
  one-hot 4-bit table selection, windowed MSM and scalar folding. It
  verifies sparse quadratic rows over BN254 Fr as the assignment is
  generated. All variables are Boolean, w0=1, w1=0. A global bit store
  preserves the IDs. Points have canonical x,y plus one infinity bit,
  with (0,0,1) the only identity encoding. External points are checked
  for membership; Pasta cofactor one means on-curve suffices. Intermediate
  group operations are justified inductively by the full group law.
- ipa_joint.js checks the exported gate rows and shape hash, imports
  their actual slot IDs into the same Boolean namespace, constrains typed
  encodings and reserved bits, and appends the full scalar/curve equation.
  It does not copy Fiat-Shamir challenges into independently allocated
  witness scalars. The scalar part binds inverse, tensor weights and
  folded evaluation; the group part enforces the final identity.
  Fixed generators are verifier-owned constants, derived from the native
  test key for the fixture. In deployment use independent key pins.
  Changed challenge and fixed commitment bits must fail prefix rows;
  changing a_hat alone must pass the prefix and fail the final equality.
  Optional --emit writes suffix sparse JSONL rows (ab list of pairs of
  linear forms, c right-hand linear form; each term [slot, decimal
  coefficient]) and the full bit assignment. The prefix rows and
  interface map are separately hashed. Full compiler/row stream review,
  including shape invariance and independent export replay, is a later
  gate. The streaming check is not itself a cryptographic proof.

## Arithmetic argument for group addition

Inputs are canonical admitted points. A one-hot vector selects exactly
one of: left identity, right identity with finite left, inverse finite
pair, distinct-x finite pair, same-point doubling. Enforce the branch's
conditions using modular differences and zero tests, with zero iff the
sum of the canonical coordinate bits is zero. Regular branches require
nonzero denominator and lambda*den=num, followed by
x_R=lambda^2-x_P-x_Q and y_R=lambda*(x_P-x_R)-y_P.
Exceptional branches set the slope to zero and constrain the exact
identity or input point. These cases cover the group operation on
canonical short-Weierstrass Pasta points and establish closure. The
coordinates and flags are constrained even for exceptional inputs.
Every branch has identical BQS shape, independent of the selected
branch in the trace. The modular integer bounds are as in PNS-04B.
The one-hot window lookup uses at most sixteen products in each
coordinate-limb equation.

## Executed receipts

| Component | Result |
|---|---:|
| Pallas/Vesta group and scalar regression | 18 positives, 26 negatives |
| One affine addition, incremental | 14,297 Boolean unknowns, 494 equations |
| Two-term 8-bit MSM | 576,084 unknowns, 20,406 equations |
| Three-round IPA scalar folding | 50,299 unknowns, 1,072 equations |
| One-round synthetic full-width opening | 9,645,610 unknowns, 333,154 equations |
| Wrong a_hat, same synthetic opening | 17 failed rows, all at final identity |

The synthetic full-width opening uses related public generators and
chosen full-width challenges, not a native or Fiat-Shamir-bound proof.
It exercises 647 group additions, 147,697 quadratic equations, and a
maximum of 16 products per equation. Positive and negative have the
same counts. The native IPA and joint actual transcript fixture gates
are registered in CI and must pass before any claim of native opening
compilation. PNS-01's CPU proof run 45379085463 has completed successfully.

## Scaling and next decision

For ell rounds, n=2^ell, k=n+2*ell+1 MSM terms, the baseline 4-bit
Straus schedule uses 14*k precompute additions, 64*(4+k) scan additions,
and one final addition of C, i.e. 78*k+257. At n=2 this is 647.
At n=32768 it is 2,558,579 group additions; at the current per-add
encoding that alone contributes about 36.6 billion Boolean unknowns.
This is a shape cost extrapolation for the present baseline, not a
measured full verifier or Praxis ciphertext estimate. The toy full-width
opening already has roughly 24.6 times the paper's 391,693 Boolean
unknowns for its optimized Groth16 instantiation, so the paper's 7.88 GiB
numbers cannot be applied to this route. Measure actual Nova key lengths
before pricing the verifier.

PNS-04D priority:
1. Inspect actual primary/secondary compressed Nova verification keys and
   extract their padded evaluation-domain sizes. Price both complete IPA
   openings, not merely log-round count.
2. Specialize fixed generators and exploit fixed-base tables; compare
   witnessed group-law batch checks and alternative constrained MSM
   algorithms. Keep sound deterministic checks. No random unchecked
   host MSM, no extra proof system, no trusted accept bit. Profile
   every bit and equation. Explore Nova-native verifier variants only
   as separately registered relations with matching key/statement pins.
3. Integrate outer/inner and batched Spartan sumcheck plus R1CS evaluation
   and both IPA checks; wire Nova folding transcript and state binding.
   Verify real arity-one compressed Nova proof with a single connected
   BQS assignment; reject adversarial re-proofs and key/state mutations.
4. Re-derive admissible Praxis parameters only after the complete
   relation and optimization pass. Stop if the direct route is
   prohibitively large. No full ciphertext or GPU run on these counts.

## Reproduce

```sh
node integrations/praxis-nova/bqs/ipa_bqs.js
node integrations/praxis-nova/bqs/ipa_synthetic_fullwidth.js
cargo run --release --manifest-path integrations/praxis-nova/bqs/Cargo.toml --bin ipa_native -- /tmp/ipa-native.json
cargo run --release --manifest-path integrations/praxis-nova/bqs/Cargo.toml --bin ipa_transcript -- /tmp/ipa-native.json /tmp/ipa-transcripts
node integrations/praxis-nova/bqs/ipa_joint.js /tmp/ipa-transcripts/Pallas
node integrations/praxis-nova/bqs/ipa_joint.js /tmp/ipa-transcripts/Vesta
node integrations/praxis-nova/bqs/ipa_joint.js /tmp/ipa-transcripts/Pallas --negative
```
