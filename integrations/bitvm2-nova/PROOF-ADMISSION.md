# Bounded compressed-proof admission

The inner codec targets the published Nova 0.76.0 non-EVM Pallas/Vesta
`CompressedSNARK` fixed-integer little-endian bincode layout. Admission checks
structure and canonical encodings. It does not verify a proof, authenticate a
Bitcoin claim, or establish complete dispute coverage.

`VerifierDimensions.from_json` requires an expected descriptor SHA-256 supplied
independently by the verifier, alongside its `ExpectedBundle` policy. A correct
verifier-key hash written inside an editable descriptor is insufficient. The
production fixture profile must be obtained from the actual reconstructed key
after its complete SHA-256 pin passes, then pinned separately. Test-only
profiles exercise the parser and are never promoted from proof row counts to
trusted key metadata.

The retained k=5 descriptor was exported after actual key reconstruction in
[run 42121264330](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42121264330)
at `44219a5`. Its exact 808 canonical JSON bytes are pinned by SHA-256
`de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc`.
The adjacent fixture provenance records that source. Both curve shapes have
two public inputs and one scalar generator; their trusted dimensions are:

| Role | Constraints | Variables | IPA generators | IPA rounds |
| --- | ---: | ---: | ---: | ---: |
| Pallas primary | 524,288 | 524,288 | 524,288 | 19 |
| Vesta secondary | 16,384 | 16,384 | 16,384 | 14 |

The selective export read seven numbers and four generator lengths, visited no
generator elements and materialized no additional full key. Those statistics
describe metadata extraction; native parameter reconstruction still generates
and holds the actual public parameters and key. The descriptor does not supply
complete IPA generator access or a proof-verification RAM bound for other `k`.

`decode_proof` first walks the bounded layout without curve work. It checks
every vector length against verifier-owned dimensions, checks remaining bytes
before iterating, and requires exact EOF. The second pass checks canonical
scalars, header output widths and compressed points in their declared curve.
It accepts canonical identity commitments and rejects the alternate identity
sign encoding accepted by the underlying group decoder. The admitted object
keeps immutable source data; its decoded-value accessor returns a copy.
Re-encoding preserves upstream field order and compressed polynomial widths.

The independent hosted `admission` binary uses its own bounded structural
cursor before calling actual upstream bincode/curve/scalar deserialization.
On acceptance it compares the entire upstream serde value, every structural
span and the canonical byte roundtrip with the Python result. It does not call
native proof verification, setup or proving for arbitrary malformed inputs.
An upstream panic is a failed run and never rejection evidence. Its pinned
descriptor and expected policy are separate inputs, never per-case claims.

The hosted workflow obtains its genuine proof and key metadata from the
retained NHT4 native verification run. It then generates bounded shape,
length, encoding and alias mutations. Admission-only acceptance of a modified
canonical proof is expected: cryptographic verification is a separate step.
The retained-fixture gate in the actual native verifier remains in place.

The local reference suite passed all 125 tests in 104.830 seconds. Its new
13 tests cover every inner-proof truncation, every length prefix, scalar and
point canonicality, all 17 output widths, descriptor pin/identity forgery and
duplicate/deep JSON transport. Independent review matched all 485 spans, tested
78 identity-sign aliases and 78 canonical point replacements, and exercised
256 random bit mutations. Shape-valid changes remain explicitly unverified.

Direct local generation with the pinned profile produces 213 differential
cases: nine structural admissions and 204 rejections, covering all 119 length
prefixes and 24 logical classes. The corpus JSON is 8,194,808 bytes; the CLI
adds one LF, giving 8,194,809 bytes within its 8 MiB budget.
This structural-only measurement took 0.133 seconds and 47,841,280 bytes
peak working set without an enforced local memory ceiling. It consumed no
native report and supplies no new proof-verification evidence.

The admission process is intended to run under a 256 MiB address-space cap,
60 CPU seconds and 90 seconds of wall time. All Rust work remains hosted; local
reference checks do not generate parameters or proofs. Current-head CI and
its artifacts must pass before claiming native differential conformance.

Complete Nova/Poseidon and Spartan/IPA transcript binding, generator access,
authenticated Script hash composition, production WOTS assertions and the
Bitcoin transaction/dispute graph remain unfinished. The transparent
Spartan/IPA compression route keeps the no-trusted-setup requirement.
