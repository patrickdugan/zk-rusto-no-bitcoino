# Authenticated matrix length profile

The default oracle exports **metadata only** for the six CSR matrices in the
retained Nova verifier key. An explicit `--matrix-output NEW_DIR` option enables
bounded native serialization to ephemeral hosted files. Neither mode validates
CSR contents, evaluates matrix polynomials or closes the independent
matrix-verification flag. No matrix payload is downloaded or evaluated on the
RAM-constrained host.

The native replay oracle first reconstructs the original transparent key, streams
its complete SHA-256 and checks the existing pinned identity. It also checks the
independently pinned dimension descriptor. Only then does `matrix_profile.rs`
inspect the supported serde paths `vk_primary.S` and `vk_secondary.S`.

The profile binds Nova version/crate identity, header revision, testnet4, `k=5`,
the original complete VK SHA and the dimension-descriptor SHA. Its own canonical
SHA uses sorted object keys and compact ASCII JSON without a newline. An embedded
VK digest does not authenticate an arbitrary edited profile; future consumers
must independently pin the profile digest obtained from the authenticated export.

## What is inspected

For each curve, the exporter reads actual `S.num_cons`, `S.num_vars`, `S.num_io`,
then for each of `S.A`, `S.B`, `S.C` reads:

- `data.len()`;
- `indices.len()`;
- `indptr.len()`;
- the declared `cols` integer.

Each selected vector stops serialization at its known-length callback, before
visiting its first element. A private serde control-flow marker is caught only
at that selected vector field. Other errors fail the export; no panic is caught
or classified as proof rejection. Matrix coefficients, column indices and pointer
values are not serialized. Other key subtrees are skipped entirely. The report
records 12 numeric fields and 18 vector lengths for all six matrices, plus skip
and no-payload statistics. Hosted run `42140056093`, job `127637849653`, passed
20 replay tests and the actual authenticated-key export. The canonical 1,376-byte
profile has SHA-256
`7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921`.

Logical dimensions must remain positive powers of two, at most `2^24`, with
two public IO elements and at least eight variables. Pointer-vector lengths must
be known and lie in `1..=2^24+1`; coefficient/index length metadata is bounded by
`2^49`, the largest logical dense grid permitted by those dimension limits.
This mathematical metadata ceiling is **not** an authorization or resource budget
for a later payload export. The exporter additionally requires:

- `data_len == indices_len`;
- `csr_rows = indptr_len - 1 <= logical num_cons`;
- `cols <= 2 * logical num_vars`, with checked arithmetic;
- stored-entry count no greater than `csr_rows * cols`.

The last check is a metadata density ceiling, not an ordering check. The public
`SparseMatrix::new` constructor requires strictly increasing columns, but the
actual frontend constructs CSR rows directly from its linear-combination
iterator. That iterator emits public-input terms before auxiliary terms, so a
mixed row can legitimately descend from the public-input half to witness
columns. Consumers must preserve those entries and the native polynomial-sum
semantics rather than imposing global within-row sorting. Explicitly stored zero
coefficients are not inspected or removed.

## Stored shape and polynomial domain differ

The polynomial domain has `num_cons` rows and `2*num_vars` columns. The extra
column-index bit selects the witness or public-input half of the assignment.
The actual CSR `cols` can instead describe the occupied assignment prefix,
typically `num_vars + num_io + 1`. It must not be assumed equal to `2*num_vars`.

Likewise, `R1CSShape::pad()` has a `num_vars == m` shortcut that changes logical
constraint count while cloning existing CSR matrices. Stored pointer rows can
therefore be fewer than logical rows; missing trailing rows are zero. The other
padding branch extends pointer rows and shifts public-input columns. The profile
preserves both stored CSR rows/columns and logical evaluation dimensions instead
of forcing equalities that the mature code does not require.

The independently authenticated retained dimensions already establish:

| Curve | Logical constraints | Logical variables | Evaluation column domain |
| --- | ---: | ---: | ---: |
| Pallas | 524,288 | 524,288 | 1,048,576 |
| Vesta | 16,384 | 16,384 | 32,768 |

The actual hosted census, independently pinned in
`../fixtures/nht4-genesis-0-2020-k5.matrix-profile.json`, established:

| Curve | Matrix | Stored rows | Declared columns | Stored entries |
| --- | --- | ---: | ---: | ---: |
| Pallas | A | 524,288 | 524,291 | 1,153,172 |
| Pallas | B | 524,288 | 524,291 | 527,234 |
| Pallas | C | 524,288 | 524,291 | 860,569 |
| Vesta | A | 16,384 | 16,387 | 72,548 |
| Vesta | B | 16,384 | 16,387 | 44,127 |
| Vesta | C | 16,384 | 16,387 | 9,812 |

The six matrices contain 2,667,462 stored entries. These are key-derived counts,
not values inferred from proof round counts. The lengths imply 119,674,848 raw
serialized bytes for the optional format below, with maximum file size
50,321,224 bytes. Actual file hashes and successful payload export still require
the new hosted execution; these size calculations are not export evidence.

## Source and public APIs

The authoritative source is the authenticated `nova-snark 0.76.0` archive,
SHA-256 `c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31`.
Relevant paths at recorded VCS revision
`98576efa884072bfe69bfad8f275a3a5cd8754e5` are:

- `src/nova/mod.rs`: private outer `vk_primary`/`vk_secondary` fields.
- `src/spartan/snark.rs`: private Spartan `S` field; actual matrix evaluation
  closure in complete verification.
- `src/r1cs/mod.rs`: shape dimensions, public `A()`/`B()`/`C()` getters and padding.
- `src/r1cs/sparse.rs`: public CSR fields and serde order
  `data`, `indices`, `indptr`, `cols`; public `iter()` and `get_row_unchecked()`.
- `src/frontend/r1cs.rs` and `src/frontend/lc.rs`: actual CSR row construction
  and input-before-auxiliary linear-combination iteration.
- `src/spartan/polys/eq.rs`: equality-polynomial index convention.

Typed public shape/matrix APIs exist, but the complete verifier key has no public
getter exposing its private Spartan shape. Selective serde is the supported
bridge here; no Debug parsing, unsafe cast or private memory-layout access is
used. CSR iterators index data under structural assumptions and should not be
called on an unvalidated arbitrary deserialized matrix.

## Explicit optional hosted payload export

`replay RETAINED.nht4 EXPECTED.json PINNED_DIMENSIONS.json --matrix-output NEW_DIR`
first authenticates the complete original VK, the independent dimensions and the
actual profile digest above. The output directory must be a relative child under
the existing working-directory `results` tree, such as `results/native-matrices`.
Absolute paths, `..`, non-normal components and existing targets are rejected;
the existing parent is canonicalized and must remain inside both the canonical
results root and the current workspace. `matrix_stream.rs` selects only
`vk_primary.S.A/B/C` and
`vk_secondary.S.A/B/C`, borrows each actual field and calls the original
`bincode 1.3.3` legacy fixed-integer, little-endian serializer. It never clones a
matrix or the full key and never creates a serialized payload Vec. An outer
64 KiB buffer coalesces small scalar writes; the inner writer checks exact sizes
and headers and hashes only bytes successfully accepted by the underlying file.
Flush, write, selection and format errors fail the export and the oracle; no
panic is caught or classified as a successful proof rejection.

All six expected file lengths are checked before creating the directory. Each
file is limited to 64 MiB and their sum to 160 MiB. Files use `create_new`, with
these fixed names and order:

1. `primary-A.csr.bin`, `primary-B.csr.bin`, `primary-C.csr.bin`;
2. `secondary-A.csr.bin`, `secondary-B.csr.bin`, `secondary-C.csr.bin`.

Each file has four contiguous, separately SHA-256-hashed sections:

| Section | Encoding | Length in bytes |
| --- | --- | ---: |
| `data` | u64 LE entry count, then original 32-byte LE field encodings | `8 + 32*data_len` |
| `indices` | u64 LE count, then u64 LE column indices | `8 + 8*indices_len` |
| `indptr` | u64 LE count, then u64 LE pointers | `8 + 8*indptr_len` |
| `cols` | original u64 LE declared column count | `8` |

Thus each complete file has `32 + 40*data_len + 8*indptr_len` bytes. Vec length
prefixes are **included** in their section hashes. The writer checks every
prefix and the final `cols` word against the authenticated profile, including
headers split across writes. Small no-key tests compare the original public
`SparseMatrix` serializer against independently assembled field/usize bytes;
other tests exercise malformed headers, extra/truncated data, caps, short writes,
injected I/O errors, selected paths and overwrite prevention. Hosted compilation
and execution remain required; these tests were not run locally.

After all six files complete, `collection.json` contains sorted compact ASCII
JSON without a newline. Its schema is `bitvm2-nova-matrix-collection/v1`, binding
the release/crate/header/network/k, complete VK, dimensions and actual profile
identities. Its ordered `files` records include role, engine, scalar-field role,
matrix, fixed filename, logical dimensions, CSR counts, exact byte length,
whole-file SHA and ordered `segments` records `{name, offset, bytes, sha256}`.
The oracle reports `matrix_collection`, `matrix_collection_sha256`,
`matrix_payload_export`, and `matrix_payload_export_seconds`; all four are null
when the option is absent. An error can leave incomplete files or a partial
manifest in the new directory, and returns no successful report. Such a
directory must not be reused as a completed export.

The collection digest must be pinned independently after successful hosted
export and integrity checks. A self-reported digest or embedded VK label does
not authenticate edited files. A future evaluator uses three independent file
cursors because coefficients, indices and pointers occupy separate sections.
It must hash the **same bytes consumed for arithmetic** against the pinned
section digests, so hashing a file and then rereading unchecked data is
insufficient. A whole-file digest is an additional transport check. Keep bulk
files on the hosted runner; retain the small collection, hashes, timings and
evaluation evidence instead of downloading or uploading bulk files by default.

## Export evidence and independent real-proof replay

The optional exporter at `eb082648d19c2f33a38404b1e699415ab5d3875d` passed
[native run42143751249](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42143751249),
including25 replay-bin tests. It wrote119,674,848 bytes across six files in
0.6657seconds without duplicating matrices in memory. The independent hosted
checker matched all six file hashes,24 section hashes and24 headers/footers in
0.1797seconds at28.8MB peak RSS. Export integrity does not establish polynomial
or proof validity. No raw matrix file was downloaded or retained in artifacts.

The5672-byte canonical collection is now independently pinned in
`fixtures/nht4-genesis-0-2020-k5.matrix-collection.json` by
`fb7dc2a6a27d366a742a97928dffa2209dfdb961f27190164e51494e7a6746e0`.
Adjacent provenance records the authenticated source, completed job and
independent integrity evidence. The full original VK, dimensions, key bindings,
trace and Poseidon parameter pins remain unchanged.

`matrix_reference.py` implements the bounded independent reader and polynomial
evaluation. Twelve small tests cover both fields, ordinary and duplicate row
entries, implicit zeros, malformed CSR data, exact arithmetic-section hashes,
evaluation-point binding and zero assignment evaluation. Its default equality
table budget is only1MiB. No real payload or large table was used locally.
`replay_production` optionally accepts that typed, separately pinned collection
and a matrix directory. It reconstructs r_x, the full r_y, rho and eval_Z from
the proof-bound transcript, computes all A/B/C evaluations and checks both inner
terminal equations directly, including eval_Z=0. Results bind immutable points,
roles and collection identities. Missing matrix parameters retain the earlier
partial replay with a false matrix flag. Independent proof, IPA generator MSM
and Script flags remain false in both modes.

The real positive still requires the corresponding hosted execution. The CLI
accepts `--matrix-dir results/native-matrices` only in the hosted environment,
using an explicit64MiB equality-table budget and512MiB/300CPU-second/360wall-second
process limits. Local code/tests use the1MiB default and no actual payloads.
The separate export-conformance CLI reports all matrix/proof/Script flags false.

Before using contents, validate initial/monotone/bounded pointer values, terminal
pointer equality with entry count, equal data/index counts, canonical field
coefficients and index bounds. Neither metadata nor opaque native serialization
establishes any of these content properties for a consumer.

For real proof challenges, independent Python should compute
`sum(value * eq(r_x,row) * eq(r_y,col))` for each matrix. Use the full `r_y`, not
the witness-only suffix; its first coordinate is the most significant index bit.
Primary coefficients belong to Pallas **scalar Q**, secondary to Vesta **scalar P**.
The resulting A/B/C evaluations can bind the actual inner-sumcheck terminal
equation. Streaming rows and caching only a bounded column-weight table is a
candidate strategy; resource use and practical caps remain to be measured on a
hosted runner. No timing, memory, transaction-size or deployability claim follows
from this export stage.
