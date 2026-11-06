# Independent production Poseidon replay

This is the source map and verification boundary for replacing the native-only
Poseidon stage in the retained Nova replay. The actual-key parameter export,
native conformance oracle and independent Python replay have the source-specific
hosted evidence recorded below. These checks validate this retained Poseidon
stage. They do not complete matrix evaluation, the IPA generator MSM or Bitcoin
Script proof verification.

## Authoritative implementation and parameter binding

Nova 0.76.0 vendors its Neptune-derived implementation under
`src/frontend/gadgets/poseidon/`. There is no separately versioned Neptune crate
in this path. Use the published Nova archive SHA-256
`c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31`,
VCS revision `98576efa884072bfe69bfad8f275a3a5cd8754e5`.
`src/provider/poseidon.rs` supplies the actual Nova RO wrapper.

The retained verifier key includes private `ro_consts_primary` and
`ro_consts_secondary` fields. Their `wide` and `narrow` members give four
profiles: Pallas base P and Vesta base Q, each in Wide and Narrow mode.
Authenticate the whole original VK before exporting these profiles, then pin
the exported parameter document independently of trace/proof data. A copied
VK label or a parameter document's printed digest is not authority.

| Mode | Arity/rate | Total permutation width | Capacity elements |
| --- | ---: | ---: | ---: |
| Wide | 24 | 25 | 1 |
| Narrow | 5 | 6 | 1 |

The production verifier currently uses Wide. Narrow is a distinct supported
backend mode and needs its own vectors; it cannot share a Wide parameter set.
Both profiles use `Strength::Standard` and `HashType::Sponge`.

The public serde representation of `PoseidonConstants` exposes optimized
constants, not its private raw round constants or explicit domain-tag field.
A sufficient minimal profile contains:

- `.mds.m`, the ordinary dense MDS matrix;
- `.crc`, compressed round constants;
- `.psm`, the pre-sparse matrix;
- `.sm`, per-partial-round sparse matrices, each with `w_hat` and `v_rest`;
- `.rf`, `.rp`, `.s` and `.ht`.

Do not recover private constants by parsing `Debug` output. The optimized
representation is sufficient to implement the permutation independently.
The native conformance oracle must compare its public default constants to
the independently pinned actual-key profile before hashing case inputs.
This prevents an internally consistent test using substitute parameters.

Before indexing, validate the exact typed schema, role/modulus/mode identity,
width, even positive full-round count, bounded partial-round count, and canonical
field encodings. Dense matrices are t by t, sparse matrix count is rp, every
`w_hat` has t elements, every `v_rest` has t-1 elements, and CRC count is
`rf*t + rp`. Enforce byte/count/time budgets and reject duplicate JSON fields.
Do not pass malformed untrusted parameter objects to upstream routines whose
internal assumptions can panic.

## Optimized permutation

Let t be the width, rf the full-round count, rp the partial-round count, and
hf=rf/2. State element zero is the capacity element. S-box exponent is five.
The exact static schedule is:

1. Add the first t compressed constants to every state element.
2. Execute hf full rounds. Each raises all t elements to power five, adds the
   next t post-round constants, then applies that round's mixing matrix.
3. Execute rp partial rounds. Each raises only element zero to power five,
   adds the next single post-round constant there, then applies sparse mixing.
4. Execute hf-1 full rounds with t post-round constants each.
5. Execute the final full round with no post-round key, then mix.

Every operation is in the profile's declared prime field. All CRC entries must
be consumed exactly. Use the following mixing orientation; the special
pre-sparse matrix is generally not symmetric:

| Zero-based round r | Mixing |
| --- | --- |
| r = hf-1 | `y[j] = sum_i x[i] * psm[i][j]` (row state times matrix). |
| hf <= r < hf+rp | Sparse matrix `sm[r-hf]`. |
| All other rounds | `y[j] = sum_i mds[j][i] * x[i]` (matrix times column state). |

Sparse mixing uses the old complete state:

```
y[0] = sum_i w_hat[i] * x[i]
y[j] = x[j] + x[0] * v_rest[j-1]       for j > 0
```

The generated ordinary MDS is symmetric, which can hide a transposition bug.
That symmetry does not justify transposing the pre-sparse operation. Reusing
the native implementation through an FFI/subprocess is useful reference
evidence but does not supply an independent Python permutation.

## Sponge framing and I/O tag

The native provider creates a fresh Simplex sponge for each call with the
operation pattern `[Absorb(n), Squeeze(1)]` and no optional domain separator
(therefore zero). `HashType::Sponge` has domain tag zero, but `start` replaces
capacity element zero with the I/O-pattern tag.

The I/O tag has its own 128-bit wrapping arithmetic. Set B=2^128-159. For each
nonempty coalesced operation, multiply the running power by B and add
`power * op_value`, all modulo 2^128. Absorb(n) has value n+2^31; Squeeze(k)
has value k. Finally process the u32 domain separator, including zero, with
one more power of B. Adjacent operations of the same kind coalesce; zero-count
operations are skipped when their run is finalized. Thus for the production
pattern and zero separator:

```
n > 0: tag = (B * (n + 2^31) + B^2) mod 2^128
n = 0: tag = B
```

This is modulo 2^128, not modulo the prime B and not modulo the Pasta field.
The resulting u128 is embedded little-endian in a field representation with
the upper 16 bytes zero. It fits both Pasta fields. The following independent
tag calculations also reproduce the vendored `api.rs` test goldens for
`[Absorb(2), Squeeze(2)]`, domain separators zero and one:

| Input count n | Production tag, 16 little-endian bytes | Wide permutations | Narrow permutations |
| --- | --- | ---: | ---: |
| 0 | `61ffffffffffffffffffffffffffffff` | 1 | 1 |
| 1 | `22620080b0ffffffffffffffffffffff` | 1 | 1 |
| 23 | `78540080b0ffffffffffffffffffffff` | 1 | 5 |
| 24 | `d9530080b0ffffffffffffffffffffff` | 1 | 5 |
| 25 | `3a530080b0ffffffffffffffffffffff` | 2 | 5 |
| 48 | `f1440080b0ffffffffffffffffffffff` | 2 | 10 |
| 52 | `75420080b0ffffffffffffffffffffff` | 3 | 11 |

Counts passed to native `SpongeOp` must be bounded below 2^31 before calling
the API; its high bit is reserved for the operation tag. Serialize large tags
as canonical bytes or strings rather than assuming a JSON Value supports u128.

## Absorption, finalization and repeated RO squeezes

Initialize `[tag, 0, ..., 0]`. Rate offset i corresponds to state element i+1.
Add each input to that state element. When the rate is full, permute before
absorbing the next input, reset the absorb position, and continue adding to
the retained state.

`HashType::Sponge` padding is a **no-op**. Do not append a one, add another
suffix, or zero unused rate positions after an intermediate permutation.
Those positions still contain state from the preceding permutation.
The first squeeze forces a final permutation, including an empty input or an
exact rate multiple. Its first output is state element one, not element zero.
The permutation count for n inputs and one output is
`max(1, ceil(n/rate))`. API `finish` clears the lower sponge without another
permutation.

The provider's outer RO is a separate state machine. Each `PoseidonRO::squeeze`
constructs a fresh lower sponge over its current vector, retains only the full
untruncated field hash as its new outer state vector, and returns the requested
low bits. If `start_with_one` is true, it adds bit `num_bits-1` when absent,
using base-field arithmetic; the retained full hash does not change. For the
production 128/250-bit ranges this equals an integer bitwise OR. At 255 bits,
forcing the bit can wrap modulo the field, so a generic oracle must model
that arithmetic or reject that unsupported request before calling native code.
Zero bits with a forced bit must never reach the upstream indexing operation.
Production calls use 250 or 128 bits and false. Subsequent absorbs append to the full hash. For example,
after absorbing `[2,5]` and squeezing, then absorbing 8, the next fresh sponge
receives `[full_hash,8]`. It does not continue the previous lower permutation
state or consume only the previous truncated challenge.

## Independent evidence and closure condition

Use both fields and both modes. Boundary lengths should include
0, 1, 4, 5, 6, 23, 24, 25, 47, 48, 49 and 52, with zero, counter,
alternating zero/p-1, and sparse first/last patterns. Include a multi-squeeze
outer-RO case, canonical field failures and input-budget failures. These
cover the empty-run tag, Narrow and Wide block boundaries, additive retained
state, final permutation, output index and full-hash chaining.

The retained real proof supplies five additional exact input sequences, of
lengths 52, 20, 9, 34 and 34. Reconstruct their inputs from the proof, trusted
key and external state, compute each complete field hash independently, and
compare both full captured after-state and returned truncation. A captured full
hash must be an expected output, never an input determining the independent
answer. The prior diagnostic mutation of an unused high hash bit must reject
under this stronger computation even when a test explicitly replaces its
capture pin.

Only after those checks and hosted differential execution pass may the retained
replay's Poseidon-independent flag become true. Matrix evaluation, the IPA
generator MSM, complete Script composition, production assertions and Bitcoin
transactions remain separate obligations. Keep their flags false until their
own implementations and evidence exist.

All native compilation and parameter/default generation stays on bounded
hosted runners. Local source review, tag arithmetic and bounded Python checks
generate no proofs and run no large generator MSM. No debug-parameter parsing,
trusted setup, wrapper proof system, transaction or deployment is introduced.

## Captured parameter evidence

Source commit `8628502b7779e8b7035f00cf600e09d19e4e1022` produced the
actual-key export in hosted run
[42133918717](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42133918717),
job `127617122076`, artifact `13464802953`. The downloaded 925,585-byte ZIP
independently hashes to
`e7729a4435424c65c89a7336b64098133fd81bbb591af4f0de6b6c814ec16115`.
Its raw `native-replay-8628502.json` report hashes to
`5ebeffaf03c70fc162d46fa8d2763160be8937bb9934350886cbb7dcfce7dead`.

The fixture `../fixtures/nht4-genesis-0-2020-k5.poseidon.json` is exactly the
report's parameter object encoded as sorted compact ASCII JSON without a
trailing line feed: 702,325 bytes, SHA-256
`b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67`.
This was checked against the downloaded report, separately from the adjacent
provenance document. The report retains the expected full VK SHA, dimension
SHA, proof SHA and end-state SHA, and reports one successful native proof
verification, one deterministic setup call and zero proving jobs.

For each of the two fields, Wide has rf=8, rp=59, width=25, CRC count=259 and
59 sparse matrices; Narrow has rf=8, rp=56, width=6, CRC count=104 and 56 sparse
matrices. The selective exporter reports 10,384 scalar fields, 11,230 JSON
nodes, 32 selected leaves and 27 skipped fields. It materializes neither the
full key nor inverse MDS caches.

A separate local source-derived dense-matrix implementation expanded each
sparse matrix, transposed the PSM explicitly, and recomputed the I/O tag with
a separate wrapping-arithmetic loop. It matched the optimized Python reference
and all five full hashes in the genuine native trace, including each returned
128/250-bit truncation:

| Engine/session | Absorbed elements | Full field hash, canonical little-endian hex |
| --- | ---: | --- |
| Pallas/0 | 20 | `3190d4acd76dd70a9aa1bd75de02168b9ed54a543d724e16cdf9cdab8db98e3d` |
| Pallas/1 | 34 | `be1973a7b79cd8436deb176768dcda1bac6dfa0de957c2b44a8f758c18e43d1c` |
| Vesta/0 | 52 | `5d39013a50b33e3baa53e2283f6cda052299b73a7bdc5a23a60e03298bc3f332` |
| Vesta/1 | 9 | `f3aa4be40afb920b3b42865bbaefa26190b01ad18a3e75b90e15674f12f86327` |
| Vesta/2 | 34 | `08c6d4d740f382c3b6bc0d308920bfee72c3830e911d362bc36bdce416fd8636` |

This local check is bounded arithmetic comparison against the retained
real-proof trace. The separate hosted differential result is recorded next;
neither check supplies independent matrix evaluation, generator MSM, Script
execution or complete proof verification.

## Completed hosted differential and replay evidence

The Poseidon stage at source commit
`666202061796afed10bf75c36debadb1b558446f` passed hosted run
[42136357424](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42136357424).
The original native Poseidon implementation checked all 254 corpus cases:
200 accepted sessions, 54 admission rejections and 776 squeeze comparisons.
Every squeeze compared the Python full hash, an original native shadow hash,
the observed live post-squeeze full state and the returned challenge. The
corpus exercised 192 forced-255-bit field reductions and both fields/modes,
including empty input and the documented block boundaries. Native execution
took about 0.57 seconds and 17,400 KiB peak RSS. No arbitrary serialized
constants were deserialized into the native RO, and no panic counted as a
rejection.

The stronger retained production Python replay also passed in that hosted
run, taking about 0.705 seconds and 30 MB peak RSS. It independently computes
the five complete Poseidon hashes from proof/key/state-derived inputs, then
checks native snapshots and truncations. Its independent-Poseidon flag is
true. Removing the authenticated parameters requires an explicit diagnostic
opt-in and leaves that flag false; re-pinned high-hash-bit mutations reject
under the independent path. Matrix, IPA generator MSM, standalone proof and
Bitcoin Script verification flags remain false. These commands generate no
proofs or transactions.

Primary sources: [provider RO](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/provider/poseidon.rs),
[permutation](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/frontend/gadgets/poseidon/poseidon_inner.rs),
[sponge API and tag](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/frontend/gadgets/poseidon/sponge/api.rs),
[native sponge adapter](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/frontend/gadgets/poseidon/sponge/vanilla.rs),
[parameter serde](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/frontend/gadgets/poseidon/serde_impl.rs),
and [hash types](https://github.com/microsoft/Nova/blob/98576efa884072bfe69bfad8f275a3a5cd8754e5/src/frontend/gadgets/poseidon/hash_type.rs).
