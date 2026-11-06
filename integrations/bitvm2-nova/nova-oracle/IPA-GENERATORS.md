# Actual ordered IPA vector-generator export

This stage adds an explicit optional native export of the two actual ordered
`ck_v.ck` vectors from the authenticated retained Nova verifier key. It does not
compute an MSM, verify the missing independent IPA equation, or produce a
proof-authorizing receipt. Independent IPA, Bitcoin Script and complete-verifier
claims remain future work. Bulk generator files stay on the hosted runner; no
key reconstruction, export or MSM runs on the RAM-constrained local host.

The replay oracle first admits the exact retained bundle and proof, reconstructs
the transparent key and checks the existing whole-VK SHA-256. It verifies the
independent dimension descriptor before any optional export. The exporter also
requires the independently pinned descriptor digest
`de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc`.
Its actual per-role `ck_v_generators` counts must equal the known retained
`ipa_dimension` values, 524,288 for Pallas and 16,384 for Vesta. Proof-owned
dimensions and regenerated default generators are not substitutes for this key.

## Supported projection and encoding

The only selected upstream paths are:

- `vk_primary.vk_ee.ck_v.ck`;
- `vk_secondary.vk_ee.ck_v.ck`.

The selective serializer tracks eight unique route fields and requires all of
them. Missing, duplicate or unexpected selected types fail the export. Matrix
shapes, RO constants, `ck_s`, blinding `h` and unrelated key fields are skipped
without serializing their values. At each selected vector, the exporter borrows
the actual original value and calls `bincode::serialize_into`; it neither clones
the generator vector nor materializes the full key or serialized vector in a Vec.

The mature affine serde implementation uses `halo2curves 0.9.0` compressed Pasta
points: 32-byte canonical little-endian x coordinate with y parity in bit 255.
Canonical identity is all-zero bytes. The legacy `bincode 1.3.3` format is exactly
an unsigned 64-bit little-endian Vec length followed by those 32-byte records.
This is the supported compressed serde encoding, **not** raw Montgomery affine
memory or the 65-byte commitment transcript representation. No Debug parsing,
unchecked raw-point decoding, unsafe cast or private-layout access is used.

Two no-key toy vectors, one for each actual affine curve type, include a generator
and identity and compare original bincode serde against independently assembled
`u64LE count || GroupEncoding::to_bytes()` records. Other tests cover split count
headers, exact sizes/caps, short writes and injected I/O failures, selected paths,
overwrite prevention, descriptor identity and hosted path containment. These tests
require hosted compilation/execution; they were not run locally.

## Optional hosted invocation and bounds

```
replay RETAINED.nht4 EXPECTED.json PINNED_DIMENSIONS.json \
  --ipa-output results/native-ipa-generators
```

The existing `--matrix-output` option may be combined with `--ipa-output` in
either order. Unknown, duplicate, incomplete and overlapping output options fail
before input reads, proof decoding or key reconstruction. Omitting `--ipa-output`
performs no generator export and leaves its four report fields null.

The destination must be a new relative child beneath the existing working
directory's `results` tree. Absolute paths and non-normal components, including
`..`, are rejected. The existing parent is canonicalized and must remain within
both the canonical results root and the canonical current workspace. Existing
targets are rejected; all output files use `create_new`.

The exporter preflights both complete lengths, with 32 MiB per-file and 32 MiB
total caps. A 64 KiB outer buffer coalesces the original serializer's small
writes. The inner writer checks the actual count prefix, exact expected length
and cap, and hashes only successfully accepted underlying writes. Flush, write,
format and selection errors fail the oracle. No panic is caught or classified as
a successful proof rejection.

| Role | Fixed filename | Count | Expected serialized bytes |
| --- | --- | ---: | ---: |
| primary / Pallas | `primary-generators.bin` | 524,288 | 16,777,224 |
| secondary / Vesta | `secondary-generators.bin` | 16,384 | 524,296 |
| Total | | 540,672 | 17,301,520 |

These lengths are calculated from independently authenticated counts and the
toy-tested format. Actual file hashes, successful export and measured resource
costs remain unknown until the new hosted stage completes.

After both files complete, `collection.json` is written as compact sorted-key
ASCII JSON without a newline. The directory contains exactly these two binary
files and the collection. An error can leave partial files or a partial
collection but returns no successful report; such a directory must not be reused
as a completed export.

## Collection contract and authority

The collection schema is `bitvm2-nova-ipa-generators/v1`. Top-level fields are
`schema`, `nova_version`, `nova_crate_sha256`, `header_revision`, `network`, `k`,
`verifier_key_sha256`, `verifier_dimensions_sha256`, `encoding`, `total_bytes`,
and ordered `files` (primary, then secondary). `encoding` is
`bincode-1.3.3-legacy-fixed-little-endian`.

Each file record contains exactly `role`, `engine`, `base_field_role`,
`scalar_field_role`, `filename`, `count`, `bytes`, `sha256`, and ordered `segments`:

| Section | Offset | Bytes | Hash covers |
| --- | ---: | ---: | --- |
| `count` | 0 | 8 | complete u64 LE Vec prefix |
| `points` | 8 | `32*count` | all original ordered compressed point records |

Each segment record is `{name, offset, bytes, sha256}`. The whole-file hash covers
both sections together. Primary points have base-field role `pallas_base` and
scalar-field role `pallas_scalar`; secondary uses `vesta_base` and `vesta_scalar`.
Pallas base is Pasta Fp and scalar Fq; Vesta base is Fq and scalar Fp.

The native report adds `ipa_generators`, `ipa_generators_sha256`,
`ipa_generator_export`, and `ipa_generator_export_seconds`. The collection digest
is over the exact canonical bytes written to `collection.json`. Export statistics
record two selected vectors, byte totals, skips, fixed caps and the bounded
buffer, with full-key/vector materialization false. Actual skip counts are
execution evidence only after hosted confirmation.

An embedded VK digest or a self-reported collection hash does not authenticate
edited point files. Consumers need a separate caller-owned collection SHA pinned
after the actual hosted export and independent integrity check. A future reader
must authenticate the exact immutable point-record bytes consumed for arithmetic
against the section hash, check the prefix and exact EOF, and perform canonical
curve/field decoding. Hashing and later rereading unchecked bytes is insufficient.
In particular, the released decoder can accept an `x=0, sign=1` identity alias;
preserve canonical re-encoding checks and any explicit finite-generator policy.

## Executed export and remaining IPA boundary

Hosted run42147838335 at `6eaa9741a57c66ce8e806e5a5e7ce0c9220299cc` passed31
replay tests, exported17,301,520 bytes, and independently matched both file hashes,
four section hashes and both count prefixes. Export took0.138seconds; independent
hashing took0.038seconds at27.9MB peak RSS. The canonical1505-byte collection is
now independently pinned by
`db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4`.
No raw generator payload was downloaded or retained in artifacts. The first
build had stopped before export on a report-macro recursion limit; splitting
the unchanged44 fields into bounded groups resolved it.

`provider/ipa_pc.rs` derives source-ordered tensor weights from replayed folding
challenges, computes the vector-generator MSM and compares the complete terminal
equation. The current independent replay reconstructs scalar weights, the joint
opening, proof L/R contributions and residual, but this export stage does not
evaluate the missing large MSM. [IPA-TERMINAL.md](IPA-TERMINAL.md) describes the
bounded direct-process checker using public `DlogGroupExt::vartime_multiscalar_mul`.
Its source and tiny transport tests are implemented; actual native unit/MSM
execution requires corresponding hosted evidence. A native JSON receipt alone
remains insufficient proof authority. Resource use must be measured rather than
inferred from file size.

The authoritative Nova source is release `0.76.0`, crate SHA-256
`c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31`.
Relevant exact source paths are `src/nova/mod.rs` (outer private verifier key),
`src/spartan/snark.rs` (private `vk_ee`), `src/provider/ipa_pc.rs` (distinct
`ck_v`/`ck_s` and IPA equation), `src/provider/pedersen.rs` (ordered private Vec,
public `generators()` accessor), and `src/provider/traits.rs` (public MSM trait).
The affine serde/flag semantics are in `halo2curves 0.9.0`
`src/derive/curve.rs`, `src/serde.rs`, and `src/pasta/pallas.rs`/`vesta.rs`.
