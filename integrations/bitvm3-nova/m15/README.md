# M15: guest A with raw-encoded commitment keys

Guest A (M12) spent 51.6 × 10^9 of its 72.3 × 10^9 SP1 instructions decoding the Nova verifier
key. The key carries 147,464 commitment-key points compressed, and decoding each one takes a
field square root. M15 makes three changes:

- [`keyconv`](keyconv) re-encodes a pinned key with uncompressed affine points (x, y). It decodes
  them with an on-curve check instead of a square root. `m15-keyconv to-raw KEY.vk RAW.vk`
  checks the conversion both ways before writing anything: RAW.vk decodes and re-encodes
  compressed to exactly KEY.vk's bytes.
- [`vendor/halo2curves`](vendor/halo2curves) is halo2curves 0.9.0 with a global switch
  (`raw-affine-serde-switch`) that changes how points serialize. [`vendor/halo2derive`](vendor/halo2derive)
  routes field multiplication through SP1's `uint256_mulmod` precompile (Montgomery form: x·y mod
  p, then ·R⁻¹).
- SHA3 (Nova's key digest) goes through SP1's Keccak precompile, via the sp1-patches tag
  `patch-sha3-0.10.8-sp1-6.2.0`. The lockfile pins sha3 0.10.8:
  `cargo update -p sha3@0.10.9 --precise 0.10.8`.

The switch must be on only while the key decodes. Nova's verifier recomputes the key's digest by
serializing the key, and that digest is over the compressed encoding keygen used. With the switch
always on, the guest panicked at 10.5 × 10^9 instructions.

The [`guest`](guest) checks the raw key against a raw digest pinned next to the compressed one.
It then commits the compressed digest, so its statement is byte-identical to M12's for the same
key and bundle.

## Measured

Guest A's testnet4 bundle (`/mnt/d/m14-a/bundle.nht4`, k = 1), SP1 6.9.0 execute (`nb3-prove
execute`), WSL2:

| | Instructions | Execute | Peak RSS | Statement |
| --- | --- | --- | --- | --- |
| M12 guest A, compressed key | 72.3 × 10^9 | | | `d3b478b0…` |
| M15 guest, raw key (ELF `03b9b45f…`) | 21,157,221,342 | 371.7 s | 4.6 GB | `d3b478b0…` (same) |

The M15 run made 307,285 `KECCAK_PERMUTE` syscalls.

Raw keys:

| Key | Compressed SHA-256 | Raw SHA-256 | Raw bytes | Conversion |
| --- | --- | --- | --- | --- |
| testnet4, k = 1 | `6894f490…c12a` | `63f91f1e…d20e` | 46,989,240 | 20.6 s |
| mainnet, k = 1 | `6aa50d09…da1d` | `4e815db8…7615` | 46,916,520 | 5.2 s |

M16's guest uses this encoding (see [`../m16`](../m16)).
