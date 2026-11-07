# M12 fixtures

| File | Bytes | SHA-256 | What it is |
| --- | ---: | --- | --- |
| `testnet4-headers-0-80.bin` | 6,480 | `86c91459b1d6622b39e4511b10374b4359fb5675ec24717b5778d17dd974df9f` | Testnet4 headers 0–80, raw 80 bytes each |
| `testnet4-k1-0-4.nht4` | 12,596 | `ffa1fdbc8a7ef712941434db51c2c780232f5a2190f225bca640ab5a4d6c5f3c` | Real compressed Nova proof: k=1, 4 steps, genesis → height 4 |
| `testnet4-k1-0-4.statement.json` | — | — | The statement the native verifier accepts for it |

## Headers

The header file is the first 6,480 bytes of `fixtures/testnet4/headers_0_4100.bin` in
`patrickdugan/zk-rusto-no-bitcoino` at `de607d3` (whole-file SHA-256 `c6806aaa…a2ee`).
That file was checked against a Bitcoin Core 31.1 dump. Height 4's hash
`000000008f5794caa45c418a0184303e848e9d6756e4d77234c9aada983b4265` and chainwork `0x500050005`
match `core_ref_0_4100.tsv` in the same commit.

## The k=1 proof

`m12 prove testnet4 1 4 testnet4-headers-0-80.bin OUT` produced the proof (`../native/src/bin/m12.rs`).
It folds from the consensus genesis state; the z0 SHA-256 is the genesis anchor
`9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c`.

| Item | Value |
| --- | --- |
| Primary constraints / variables | 97,409 / 97,267 (padded to 2^17) |
| Secondary constraints / variables | 10,349 / 10,331 (padded to 2^14) |
| Compressed proof | 12,040 bytes, SHA-256 `66c903b0…d7e4` |
| Verifier key | 42,270,392 bytes, SHA-256 `6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a` |
| Folded witness (RecursiveSNARK) | 7,223,800 bytes; not committed |

Nova's blinding is random, so the proof bytes do not reproduce from the same
command. The verifier key does. It is a deterministic function of the circuit shape.
Three independent exports gave the same SHA-256:
- `m12 vk-export testnet4 1`;
- the M12 prove run;
- `btc-header-fold.exe vk-export 1 --network testnet4`, binary `ad531c22…be40` from `de607d3`.

The tests rebuild the key in-process from the circuit shape. They then compare it to the pin in
`../native/src/pins.rs` and verify the bundle, so CI runs real Nova verification without a
key file.
