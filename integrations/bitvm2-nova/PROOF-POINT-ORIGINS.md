# Retained compressed-commitment decoding (M23)

M17 signed every BYTE of the retained 12,664-byte Nova proof payload and
decoded its 288 scalars, but left its 78 compressed commitments opaque. M23
binds each of those 32-byte encodings, at its physical container offsets, to
asserted canonical affine coordinates `(infinity, x, y)` using only frozen
legacy predicates. It closes the "point decompression" origin listed as open
by [PROOF-PAYLOAD-ORIGINS.md](PROOF-PAYLOAD-ORIGINS.md); it does not say which
point a commitment ought to be.

Code: [proof_point_origins.py](proof_point_origins.py) (factory and pure value
model), [bench_proof_point_origins.py](bench_proof_point_origins.py) (hosted
driver), [point-origins-oracle](point-origins-oracle) (direct native worker)
and the `bitvm2-nova-proof-point-origins` workflow.

## Encoding and relation

The retained proof uses halo2curves 0.9 Pasta compressed points: the 32 bytes
are `x` little-endian with the sign of `y` (its low bit) in bit 255, and the
identity is 32 zero bytes. Pallas commitments have coordinates modulo `P`
(`pallas_base`); Vesta commitments modulo `Q` (`vesta_base`).

For one commitment with asserted BYTEs `b[0..32]`, the decoder asserts the
flag `infinity`, the canonical fields `x` and `y`, and checks:

| Predicate | Statement |
| --- | --- |
| `conv_split(7)` on `b[31]` | `b[31] = lo + 128*sign`, `lo < 128`, `sign` Boolean |
| `conv_split(7)` on `x31` | the x digit `x31 = lo` (high part is the constant 0) |
| 7 splits + 9 reconstructions | `x` limbs are exactly `b[0..31] ‖ x31` |
| `field_valid(x)`, `field_valid(y)` | both coordinates are canonical |
| `point_form` | `infinity => x = y = 0` |
| 3 convolution products, `add`, `gate_equal(0)` | `not infinity => y^2 = x^3 + 5` |
| `conv_split(1)` on y's BYTE 0 | the low bit of `y` equals `sign` |

Every predicate kind, argument and alias pattern is one of the frozen legacy
shapes already pinned in `point-oracle/src/body_pins.rs`; no new compiler or
body is introduced. The x digits are the proof BYTE words themselves, so the
product `x*x` reads the signed payload positions directly.

**Uniqueness.** 5 is a quadratic non-residue modulo both `P` and `Q`, so no
finite point has `x = 0`. Both curves have prime (odd) order, so no finite
point has `y = 0`, and the two roots of `y^2 = x^3 + 5` have opposite low
bits. Hence:

* if `infinity = 1`, `point_form` forces `x = y = 0`, the parity split forces
  `sign = 0`, and the bytes must all be zero;
* if `infinity = 0`, `x` is fixed by the bytes and `y` is the unique root with
  the asserted parity.

Each 32-byte string therefore has at most one satisfying `(infinity, x, y)`.
It has one exactly when the encoding is canonical:
`to_bytes(from_bytes(b)) == b`. A noncanonical `x`, an `x` with no curve
point, or the upstream `x = 0 / sign = 1` identity alias leaves every
assertion with a false leaf, so the claim is disprovable. Rejecting the alias
matches the repository's strict codec and reference admission. Bare
halo2curves `from_bytes` accepts that alias, and honest Nova serialization
never emits it.

## Source and caps

Each curve role is one source: the unchanged M17 BYTE tape (12,664 leaves)
followed by decoder components of at most seven decoders. Each decoder has
1,696 words, 1,400 Program constraints and 6 canonical-field leaves. A
component adds 10 shared constant words and leaves (`5` as a field, and the
zero high part). Seven decoders give 9,810 constraints, under the unchanged
10,000-constraint Program cap.

| Role | Decoders | Components | Words | Leaves | Shared tape BYTEs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pallas | 43 | 1 tape + 7 | 85,662 | 73,199 | 1,376 |
| Vesta | 35 | 1 tape + 5 | 72,074 | 61,929 | 1,120 |

Decoder encoding BYTEs reuse the tape's physical identities
`proof/container-byte/{556+offset}`. They therefore share its WOTS key,
signature and opening, which the worker checks per actual opening. Both role
sources stay within the 16-component policy. The unchanged per-leaf
100,000-byte, per-component 256-MiB, aggregate 1.25-GiB, 1,000-item stack,
128-MiB record and 1-MiB summary caps all apply. The worker runs under the
same 512-MiB address-space cap as M22. Its CPU budget is 2,280 seconds,
stated in the workflow, for this larger closed corpus.

## Closed profiles

Twelve profiles run per role. The honest source executes every leaf in both
correctness and disproof modes. Each targeted profile changes one decoder. It
executes that decoder's complete 1,406 leaves, every false leaf anywhere, the
tape leaves of every changed BYTE, and fixed controls, capped at 2,048 leaves.

| Profile | Claim | Expected local result |
| --- | --- | --- |
| `honest` | reference bytes, strict decodings | all leaves true |
| `coherent-negate` | encoding and coordinates of `-P` | all true (another valid point) |
| `coherent-identity` | zero bytes, identity | all true (another valid point) |
| `sign-flip` | sign bit flipped, honest coordinates | parity split false |
| `wrong-root` | honest bytes, `y' = p - y` | parity split false |
| `x-noncanonical` | `x + p` encoded, coherent limbs | `field_valid(x)` false |
| `off-curve` | next `x` with `x^3+5` a non-residue | `gate_equal` false |
| `identity-alias` | `x = 0, sign = 1`, identity claim | parity split false |
| `identity-finite-flag` | zero bytes, finite flag | `gate_equal` false |
| `infinity-lie` | honest bytes, infinity flag set | `point_form` false |
| `byte-256`, `byte-max` | signed BYTE 256 / `u32::MAX` | every leaf reading it, plus the tape leaf |

Coherent substitutions passing is the stated limit of this relation: binding
bytes to a valid point does not establish that the point is the prover's
commitment. That needs the transcript, folding and IPA/MSM equations.

## Independent checks

The Python factory builds every component with the frozen
`ConvolutionTraceBuilder`. It checks that its pure value model equals the
builder's own honest assignment. The native worker then re-derives:

* the retained layout;
* the tape;
* every decoder's word and predicate schedule, against the legacy body pins;
* the raw-u32 assignment of each profile, from closed recipes;
* every leaf's truth, the selection, the program and catalogue identities;
* the aggregate source hash.

All of this happens before any key is generated. For every decoder of every
profile, it requires strict halo2curves decoding (`from_bytes` plus the
canonical round trip) to agree with the complete leaf relation. Panics,
worker failures and timeouts are failures, never rejection evidence. The
empty, truncated, prepended, appended, changed-hash and foreign-key witness
guards run on every authenticated layout of the honest source and on the
targeted leaves. No receipt is an input.

## Measured hosted result

Both role jobs and the cross-role accounting job passed on
`a300b1fe4cb921235d54114c0ba8d75289497532`
([run 42371873061](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/42371873061),
10m56s). The same code also passed run 42370911294 on `08d44a4`. The
integration code is unchanged since implementation commit
`598d4b8fb9489b889399f03b1162c5c9883dc1cc`, on which all 24 existing
workflows and Rust CI passed. The two failed earlier M23 runs stopped before
any worker started:
* `598d4b8`: the bench parent's 1,200-second CPU hard limit was below the
  worker's 2,280-second `prlimit`, which `prlimit` refused (EPERM);
* `16303e9`: the same cause, after stderr was added as an annotation.

Neither counts as conformance or rejection evidence.

Complete honest sources (aggregate disproof Script bytes; assertion
signatures, witnesses, control blocks and transaction framing excluded):

| Role | Tape | Per decoder | Decoders | Complete source |
| --- | ---: | ---: | ---: | ---: |
| Pallas | 21,240,083 | 20,145,610 | 866,261,230 (43) | 887,723,899 |
| Vesta | 21,240,083 | 20,169,238 | 705,923,330 (35) | 727,322,403 |

Every decoder of a role costs exactly the same (fixed topology), and each
component adds 31,798 bytes of shared constants. The tape re-measures at
M17's 21,240,083 bytes. Both role sources fit the unchanged 1.25-GiB
aggregate cap. The 78 decoders together measure 1,572,184,560 bytes, so one
source containing both roles would not fit, which is why the roles are
separate sources.

| Predicate kind (Pallas honest) | Leaves | Script bytes | Largest leaf |
| --- | ---: | ---: | ---: |
| `conv_ab` | 36,120 | 575,521,460 | 17,858 |
| `conv_pq` | 11,868 | 135,231,087 | 18,291 |
| `conv_column` | 8,256 | 118,936,710 | 22,639 |
| `conv_reconstruct` | 1,935 | 19,320,115 | 11,218 |
| `word_valid` (tape) | 11,281 | 18,906,956 | 1,676 |
| `conv_split` | 1,634 | 8,256,860 | 5,119 |
| `field_valid` | 265 | 3,951,680 | 14,912 |
| `const` | 1,711 | 2,887,091 | 1,689 |
| `add` | 43 | 2,004,531 | 46,617 |
| `point_form` | 43 | 1,356,048 | 31,536 |
| `gate_equal` | 43 | 1,351,361 | 31,427 |

The three convolution products dominate. Their `conv_ab`, `conv_pq` and
`conv_column` leaves alone are 829,689,257 bytes, 95.8% of the decoder
bytes. The M21 grouped-AB transform is the existing candidate for reducing
them; it was not applied here, so this legacy measurement is the baseline.

| Role | Script calls | Expected rejections | Normal calls | Peak Script / stack / witness items / payload |
| --- | ---: | ---: | ---: | --- |
| Pallas | 203,836 | 114,770 | 178,132 | 46,617 / 275 / 271 / 5,400 |
| Vesta | 178,572 | 100,808 | 155,528 | 46,617 / 275 / 271 / 5,400 |

Normal-execution peaks are 46,617 / 275 / 270 / 5,400 in both roles.
Standard guards ran on all 9 tape and 83 per-component decoder layouts of
each honest source, and on the targeted leaves. The closed pre-key call
budgets were 328,670 and 291,794. Compact execution records were 38,192,252
and 33,461,102 bytes, under the 128-MiB cap.

Per targeted profile, Pallas first (Vesta in parentheses where it differs):

| Profile | Measured leaves | False leaves | Rejected decoders |
| --- | ---: | ---: | ---: |
| `coherent-negate` | 1,433 (1,431) | 0 | 0 |
| `coherent-identity` | 1,464 (1,460) | 0 | 0 |
| `sign-flip` | 1,433 (1,431) | 1 | 1 |
| `wrong-root` | 1,432 (1,430) | 1 | 1 |
| `x-noncanonical` | 1,446 (1,443) | 1 | 1 |
| `off-curve` | 1,433 (1,430) | 1 | 1 |
| `identity-alias` | 1,464 (1,460) | 1 | 1 |
| `identity-finite-flag` | 1,464 (1,460) | 1 | 1 |
| `infinity-lie` | 1,432 (1,430) | 1 | 1 |
| `byte-256`, `byte-max` | 1,433 (1,430) | 94 | 1 |

In every case the single rejected decoder is the targeted one. In every
profile, strict halo2curves decoding agreed with the complete leaf relation
for all 43 / 35 decoders.

| Role | Global words | Local words | Opening occurrences | Signatures (12 cases) |
| --- | ---: | ---: | ---: | ---: |
| Pallas | 84,286 | 85,662 | 460,986 | 1,011,432 |
| Vesta | 70,954 | 72,074 | 377,564 | 851,448 |

Native worker wall times were 375.0 s (Pallas) and 258.4 s (Vesta). GNU
time measured the whole bench step at 7:31.31 elapsed with 409,088 KiB
maximum RSS (Pallas), and 5:11.55 with 353,696 KiB (Vesta), under the
512-MiB address-space cap. Both role jobs passed 10 Python tests (one
expected guard skip) and 16 Rust tests.

| Evidence | SHA-256 |
| --- | --- |
| Pallas report | `f3f89af94c698bd0d751640c0cf0711db0dd7e8f7a000da54d3db7864b827972` |
| Pallas input manifest | `65f8fd21ebb4a1bb18b54dc1431e4738778f04bfd67e1bbc4a9bf498e542aea6` |
| Vesta report | `70e6be7ad62189158c9dd5b14b2e5a7f3c79b2bd8264fa62c835bf0d02857a64` |
| Vesta input manifest | `8acefb21c0fddd71dcc1bada70fb88e238a65e8ccfa13904d4a5d6169b1d5768` |
| Accounting | `aba63be3777f9bbd1e9190638eeb40b9d93e1830e8d9b748fced3d24c2f9af67` |
| Source snapshot (159 files) | `69b464aa0adba79378f92184dbb53b7b036aaeea6509d50a680c7bed07194c81` |
| Worker executable (3,628,264 bytes) | `f87cc7b5ba4df31d996a8884cb7a474ba4b8ef651da84f5d7e37a23a2673efd4` |

Workflow logs and artifacts require sign-in. The measured values above are
published as public run annotations by the workflow's final step. There
were zero proving, GPU, setup, tree and broadcast calls.

## Explicit unverified boundaries

* Which point each commitment should be: transcript absorption, NIFS folding,
  derandomization and the IPA/MSM equations remain open.
* The 65-byte affine transcript encoding of these commitments is not yet
  exported to a transcript source.
* There is no whole-blob SHA-256, EOF, header-to-`zn` binding, production
  assertion, Taproot tree or Bitcoin transaction graph.

None of this is Nova proof verification.
