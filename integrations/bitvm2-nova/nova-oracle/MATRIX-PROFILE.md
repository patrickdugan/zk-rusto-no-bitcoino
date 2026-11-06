# Authenticated matrix length profile

This stage exports **metadata only** for the six CSR matrices in the retained
Nova verifier key. It does not export any matrix elements, validate CSR contents,
evaluate matrix polynomials or close the independent matrix-verification flag.
No matrix payload is downloaded or evaluated on the RAM-constrained host.

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
and no-payload statistics. These counts require successful current-head CI before
being treated as execution evidence.

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

The last check is consistent with matrices constructed by the pinned
`SparseMatrix::new`, which requires strictly increasing column indices in each
row. It does not demonstrate that ordering for the actual contents. Explicitly
stored zero coefficients are not inspected or removed.

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

Actual stored rows, declared columns and entry counts are deliberately left to
the hosted metadata export. They are not inferred from proof round counts or
from the logical dimensions above.

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
- `src/spartan/polys/eq.rs`: equality-polynomial index convention.

Typed public shape/matrix APIs exist, but the complete verifier key has no public
getter exposing its private Spartan shape. Selective serde is the supported
bridge here; no Debug parsing, unsafe cast or private memory-layout access is
used. CSR iterators index data under structural assumptions and should not be
called on an unvalidated arbitrary deserialized matrix.

## Possible later hosted stage

First read the actual census and choose explicit entry/disk/time/memory limits.
Then, if within those limits, stream authenticated CSR sections or canonical
row/column/coefficient records to **ephemeral hosted files**, with a separately
pinned manifest of counts and hashes. Do not put large matrices in local fixtures
or upload large payloads by default; retain small metadata, hashes, timings and
evaluation evidence instead.

A streaming implementation can preserve the original serde vector order in
three file sections, avoiding a full JSON matrix or another complete key copy.
Before using contents, validate initial/monotone/bounded pointer values, terminal
pointer equality with entry count, equal data/index counts, canonical field
coefficients and index bounds. Length-only metadata cannot establish any of these
content properties.

For real proof challenges, independent Python should compute
`sum(value * eq(r_x,row) * eq(r_y,col))` for each matrix. Use the full `r_y`, not
the witness-only suffix; its first coordinate is the most significant index bit.
Primary coefficients belong to Pallas **scalar Q**, secondary to Vesta **scalar P**.
The resulting A/B/C evaluations can bind the actual inner-sumcheck terminal
equation. Streaming rows and caching only a bounded column-weight table is a
candidate strategy; resource use and practical caps remain to be measured on a
hosted runner. No timing, memory, transaction-size or deployability claim follows
from this metadata stage.
