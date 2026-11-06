# Hosted IPA terminal relation boundary

This component executes the missing generator MSM of the retained Nova0.76.0
IPA statement using the released mature CPU group implementation. It is a
mathematical terminal checker invoked directly by trusted code. It is not a
general proof verifier, an imported receipt, or a Bitcoin Script verifier.

## Actual generators

The generator projection was authenticated and independently hashed in hosted
run42147838335, job127663527790, source `6eaa9741a57c66ce8e806e5a5e7ce0c9220299cc`.
Both original-key vectors total17,301,520 bytes, with524,288 Pallas and16,384
Vesta points. All two file/four section hashes and count prefixes matched.
Native export took0.138seconds; independent hashing took0.038seconds at27.9MB
peak RSS. The1505-byte canonical collection is independently pinned by
`db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4`.
The payloads remain ephemeral on the hosted runner; they are neither downloaded
nor retained in artifacts. This establishes the ordered projection, not an MSM.

## Statement and execution binding

`build_ipa_statements` takes an admitted proof and separately pinned key, trace,
Poseidon and generator metadata. It invokes strict production replay itself;
it never accepts a caller's replay JSON as authority. Factory-only immutable
requests bind the proof/bundle/end-state, release/header/network/k/steps,
key/dimension/trace/Poseidon/generator identities, joint commitment/evaluation,
batch point, initial challenge, ordered L/R points and folding challenges,
`a_hat`, and the independently reconstructed residual.

`execute_ipa_statement` directly runs a trusted configured `ipa_msm` executable.
The proof cannot select that configuration. The wrapper snapshots authenticated
metadata, writes exact canonical request bytes, and passes their SHA256 out of
band as a separate argument. It validates the actual exit and bounded typed
output against that sealed request and checks the returned residual, scaling
and factorized b-hat. No public JSON-import path can construct an execution or
set an executed/relation flag. The compiled helper and local process execution
remain trusted dependencies, as with a verification library; an environment
variable is only resource protection.

The native checker independently loads U0 from the original pinned tiny scalar
key, authenticates each generator byte consumed into immutable affine values,
checks exact count/order/EOF and canonical point roundtrips, and rejects the
upstream x=0/sign=1 identity alias. Generator points must be finite. Scalar
weights use the engine's scalar field; point encodings use its base field.
Initial challenge r0 and a_hat may be zero, while folding challenges must not.

For the joint commitment C and evaluation c, it recomputes

```
P = C + r0*c*U0 + sum(u_j^2*L_j) + sum(u_j^-2*R_j)
b_hat = product((1-x_j)/u_j + x_j*u_j)
residual = P - r0*a_hat*b_hat*U0
```

It compares that residual with Python's reconstruction, regenerates every
MSB-first tensor weight s_i, and checks `residual == a_hat*MSM(s_i,G_i)` using
the public `DlogGroupExt::vartime_multiscalar_mul` CPU API. No new curve/MSM
algorithm, random setup, label-default substitution or GPU path is introduced.
The commitment-key h values have zero coefficients and do not enter this IPA.

## Scope and resource limits

The two roles execute sequentially. Each child has512MiB address-space,
300CPU-second,360wall-second and32KiB stdout/stderr file limits. Requests are
at most32KiB, collections at most64KiB, and generator streams at most32MiB.
The full CLI requires hosted GitHub Linux before any payload I/O. Local tests
use tiny fixtures or explicit test-only process mocks; no real generator vector,
Native build, GPU, setup or large MSM runs locally. Panics, nonzero exits,
timeouts, malformed output and resource exhaustion fail the operation.

Only `ipa_native_msm_executed` and `ipa_native_relation_checked` can become true
after actual direct execution and all bindings pass. The independent Python
MSM, complete IPA/general proof and Bitcoin Script flags remain false. A native
JSON receipt supplied by someone else is not proof authority. The real positive
and native unit checks require the corresponding current-head hosted evidence.
Production WOTS assertions, full Script/hash composition, arbitrary-proof
verification and Bitcoin transaction binding remain separate work.
