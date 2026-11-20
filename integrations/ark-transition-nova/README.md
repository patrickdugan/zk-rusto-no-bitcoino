# ark-transition-nova

A Nova (nova-snark 0.76, Pallas/Vesta, Spartan over IPA compression) proof that an Ark transaction
graph, as emitted by the bitcoin-rs `ark-nm2` tool, satisfies:

1. per transaction, sum(inputs) = sum(outputs) + fee;
2. every fee is in [0, fee_bound_sat];
3. every value and fee is a 64-bit integer;
4. no spend_id appears twice across the whole graph (single-use spend identities);
5. the proof is bound to one 32-byte `statement_digest` and one record list (Poseidon chain R1).

## What is not proven

- That the records correspond to real transactions: the records-to-transactions binding is checked
  natively by the bitcoin-rs tool, not in the circuit.
- No SHA-256 and no signature checking in the circuit; Bitcoin consensus validity is not proven.
- spend_id and commit are compared on their first 31 bytes (see mapping). A spend_id whose 31-byte
  prefix is all zero is refused.

## Circuit

One item per step; kind selected by four boolean flags (sum = 1); a kind's constraints are products with
its flag, so unselected kinds constrain nothing. Constraints per step: **1050** (measured).

State (17 Pallas scalars): `dig_hi, dig_lo, fee_bound, gamma, acc, sum_in, sum_out, sum_fee, r1, p1, r2, p2,
last, n_in1, n_in2, n_tx, phase`.

- INPUT (phase 0): 64-bit value; `acc += v`, `sum_in += v`; `r1 = H(r1,1,spend,v)`; `p1 *= gamma - spend`; `n_in1 += 1`.
- OUTPUT (phase 0): 64-bit value; `acc -= v`, `sum_out += v`; `r1 = H(r1,2,v,commit)`.
- CLOSE (phase 0): 64-bit fee; `fee_bound - fee` is 64-bit; `acc == fee`; `acc = 0`; `sum_fee += fee`; `n_tx += 1`; `r1 = H(r1,3,fee,0)`.
- SORTED: `phase = 1`; `spend - last - 1` is a 248-bit integer (strictly increasing, so no duplicates); `last = spend`; `r2 = H(r2,spend)`; `p2 *= gamma - spend`; `n_in2 += 1`.

Record steps require phase 0 and SORTED sets phase 1, so the phase never returns to 0. The prover appends
one SORTED step per input, in ascending spend order. `num_steps = items + inputs`.

z0 = `[dig_hi, dig_lo, fee_bound, gamma, 0,0,0,0, R0, 1, R0, 1, 0,0,0,0, 0]`, `R0 = H(DOMAIN, dig_hi, dig_lo, fee_bound)`.
H is Poseidon (neptune-style sponge, 128-bit strength, absorb n, squeeze 1), identical natively and in circuit.

Field mapping:
- `DOMAIN` = first 31 bytes of SHA-256("ArkTransitionV1/nova"), big-endian; `DOMAIN_GAMMA` the same for "ArkTransitionV1/nova/gamma".
- `spend_id`, `commit`: first 31 bytes of the 32-byte value, big-endian, as a 248-bit element.
- `statement_digest`: hi = bytes[0..16], lo = bytes[16..32], big-endian 128-bit limbs.
- field elements in JSON: 64 hex chars, 32 bytes big-endian.

### Fiat-Shamir argument

The prover computes the final record chain `r1` and sorted chain `r2` natively (neither depends on gamma),
then sets `gamma = H(DOMAIN_GAMMA, r1, r2)` and puts it in z0. The verifier rechecks `gamma == H(DOMAIN_GAMMA, zn.r1, zn.r2)`.
gamma is therefore a hash of both lists, fixed before the grand products `p1`, `p2` are computed. `p1 == p2` at that
gamma means the multiset of input spend_ids equals the sorted list, except with negligible probability (Schwartz-Zippel
over a 255-bit field); the sorted list is strictly increasing, so the inputs are distinct.

## Verifier

After the compressed SNARK verifies for z0 -> zn over `steps`: z0 recomputed from statement, fee_bound and gamma;
`phase == 1`, `acc == 0`, `n_in1 == n_in2`, `p1 == p2`, gamma check; `zn.sum_in/sum_out/sum_fee/n_tx/n_in1` equal
the `expect` block; `zn.r1` equals the chain recomputed from the items (full mode, `--witness`) or the expected r1
(succinct mode, `--expect`; with neither flag, the fields of public.json are the reference, which checks
self-consistency only). The verifier key is rebuilt from the circuit shape and its SHA-256 compared with `vk_digest`.
The proof must also re-serialize to exactly its own bytes.

## Commands

```
scripts/cargo.sh test --release          # rsyncs into /root/ark-nova (WSL), CARGO_TARGET_DIR=/root/ark-nova/target
scripts/cargo.sh build --release
ark-nova prove  --witness fixtures/ark4-sample.json --out DIR
ark-nova verify --public DIR/public.json --proof DIR/proof.bin [--witness W.json | --expect E.json]
ark-nova mutate --witness fixtures/ark4-sample.json --out DIR
ark-nova bench  --sizes 4,16,64,256 [--witnesses A.json,B.json] --out results/bench.json
```

`--expect` takes `{statement_digest, fee_bound_sat, r1, expect:{...}}`.

## Measured (WSL2, RAYON_NUM_THREADS=8, 1050 constraints/step, setup 3.66 s, vk 22ad3282...dfcdad)

Synthetic Ark graphs (commitment tx with N boarding inputs + 1 liquidity input; binary tree of N-1 txs, 1-in/2-out) and
the real bitcoin-rs `nested` graphs. Proof size is 11,104 bytes at every size. Peak RSS is the process high-water mark
(VmHWM), cumulative across the run.

| graph | steps | fold s | compress s | verify s (succinct / full) | peak RSS MiB |
|---|---|---|---|---|---|
| synthetic 4 | 28 | 5.96 | 6.05 | 0.21 / 0.18 | 149 |
| synthetic 16 | 112 | 24.35 | 5.62 | 0.15 / 0.20 | 170 |
| synthetic 64 | 448 | 113.01 | 5.57 | 0.21 / 0.23 | 175 |
| synthetic 256 | 1792 | 464.02 | 6.25 | 0.18 / 0.26 | 176 |
| ark-nm2 nested-4 | 28 | 6.38 | 7.73 | 0.23 / 0.21 | 178 |
| ark-nm2 nested-16 | 112 | 28.49 | 6.11 | 0.17 / 0.17 | 178 |
| ark-nm2 nested-64 | 448 | 100.21 | 5.69 | 0.18 / 0.21 | 185 |

Folding is about 0.26 s per step; compression and verification are independent of size. All rows accepted in both
modes. Raw rows: `results/bench.json`.

## Negative controls

`results/ark4-mutations.json`: on `fixtures/ark4-sample.json` (4 users, 28 steps, 8 inputs, fees 800 sat) the baseline
is accepted and all 22 mutations are rejected: output value changed, duplicated spend_id, fee above bound (each refused
by the native precheck and, with the precheck bypassed, by the circuit); other statement digest; public.json rewritten
for another statement; truncated, extended and bit-flipped proofs; flipped zn fields; proof of one witness with the
public.json of another; altered steps, vk_digest, schema, expect block and gamma.

`cargo test --release`: 10 unit tests pass (native chain equals circuit chain, each kind matches the engine, unsorted
and duplicate SORTED, value >= 2^64, fee above bound, nonzero acc at CLOSE, records after phase 1, unknown kind, synthetic
graph validity).
