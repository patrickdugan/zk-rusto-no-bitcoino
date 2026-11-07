# Real Bitcoin-header Nova proofs (testnet4, k=20) and verifier inventory

These are M11 step A inputs (`../../M11_WORK_ORDER.md`): two genuine compressed
Nova 0.76.0 proofs of testnet4 headers and an exact operation inventory of
their verifier key. No garbled verification is claimed here.

## Proofs

| File | Statement | Bundle SHA-256 | Proof SHA-256 |
| --- | --- | --- | --- |
| `k20-testnet4-0-40.nht4` | headers 1–40 from the genesis anchor | `376e3801…ddffce` | `62cf7c1c…3d64` |
| `k20-testnet4-40-80.nht4` | headers 41–80 from shard 0's end state | `a92d3527…31d9` | `2bb4ca79…175c` |

**Bundle layout:** NHT4 = magic `NHT4` | steps u32 LE (2) | k u32 LE (20) |
z0 (17 × 32-byte canonical Pallas scalars) | compressed proof (13,288 bytes,
bincode 1.x legacy encoding).

**Anchor and joins:**
- Shard 0's z0 is the testnet4 genesis anchor state, SHA-256
  `9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c`.
- Shard 1's z0 equals shard 0's proven end state.

**Final state:**
- height 80, hash `00000000f2d5675990f22987f0fa75cebcf1ae9d18cdc16b817fce54c390ebc2`;
- chainwork `0x5100510051`;
- state SHA-256 `df3824edb9c5222256710a35504730bade2fe558de0a6e9090b0966c8a677991`.

**Provenance:**
- Produced by the Codex run `proving-k20-two-shards-16g-parallel` from
  `patrickdugan/zk-rusto-no-bitcoino` at
  `de607d3db17d400dd6c2923d357f1d4a7bf233c7`.
  - `nova-chain.exe` SHA-256 `01075ba2…539f`;
  - `btc-header-fold.exe` SHA-256 `ad531c22…be40`.
- Headers: that repo's `fixtures/testnet4/headers_0_4100.bin`, SHA-256
  `c6806aaa…a2ee`, checked against Bitcoin Core 31.1.
- The run record, with host paths removed, is `k20-codex-run-verified.json`.

## Verifier key (not in git)

The key is 500,333,512 bytes with SHA-256
`9e94b9083b5be30e796e974218804214b7106284c071eeec9b15945735321727` (bincode
1.x legacy encoding). It is too large for git.

**Regenerating it.** At the source revision above:

```
btc-header-fold vk-export 20 OUT --network testnet4
```

Keys for k=5 and k=10 rebuilt deterministically across Windows and Linux.
**The k=20 rebuild has not been checked against this digest.**

## Inventory (`k20-testnet4-verifier-inventory.json`)

`tests/real_header_verifier_inventory.rs` reads the key with Nova's own serde
types. It mirrors only the crate-private wrappers, and uses bincode with
`reject_trailing_bytes`, so the decode accounts for every byte.

Counts follow the installed 0.76.0 `spartan/snark.rs` `multi_evaluate` and
`provider/ipa_pc.rs` verify code:

| | Primary (Pallas) | Secondary (Vesta) |
| --- | ---: | ---: |
| Constraints / variables, as padded in the key | 2,097,152 / 2,097,152 | 16,384 / 16,384 |
| Nonzeros: A / B / C | 4,159,082 / 1,851,659 / 3,398,554 | 72,548 / 44,127 / 9,812 |
| Equality-table multiplications | 6,291,456 | 49,152 |
| Per-nonzero multiplications (2 per nonzero) | 18,818,590 | 252,974 |
| IPA opening length n (rounds) | 2,097,152 (21) | 16,384 (14) |
| IPA `s`-vector multiplications | 2,097,151 | 16,383 |
| IPA MSM terms | 2,097,152 | 16,384 |

**Totals:** 27,525,706 field multiplications and 2,113,536 MSM terms.
**Not counted:**
- the NIFS Poseidon hashes and fold scalar multiplications;
- the logarithmic sumcheck, transcript and IPA L/R work.

## Priced with `cost_envelope.py` (conditional proxies, not lower bounds)

| Scenario | Non-free gates | Ciphertext per instance |
| --- | ---: | ---: |
| 27,525,706 checked Pasta multiplication predicates (360,963 each) | 9,935,761,414,878 | about 159 TB |
| Sensitivity: 12 checked point additions × 2,113,536 MSM terms | about 1.10 × 10^14 | about 1.76 PB |

## Tests (skip unless the key path is set)

```
NOVA_REAL_VK=<key> NOVA_REAL_BUNDLES="fixtures/bitcoin-header/k20-testnet4-0-40.nht4;fixtures/bitcoin-header/k20-testnet4-40-80.nht4" \
  cargo +1.90.0 test --release --manifest-path nova-bitvm3/Cargo.toml --features native-reference \
  --test real_header_proof_native --test real_header_verifier_inventory -- --nocapture --test-threads=1
```

**`real_header_proof_native`** verifies both bundles natively. Measured on
Windows:
- key decode: 75 s;
- verification: 6.3 s and 1.5 s.

It requires each of these to be rejected:
- a wrong step count;
- altered checkpoint chainwork;
- an altered checkpoint hash;
- four flipped proof bytes;
- a truncated proof.

**`real_header_verifier_inventory`** regenerates the inventory, with key
decode in 112 s.
