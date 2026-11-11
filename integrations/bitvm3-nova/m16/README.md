# M16: mainnet chain state and an SPV payment in one SP1 guest

The [`sp1/program`](sp1/program) guest verifies a Nova proof of the Bitcoin mainnet header chain,
anchored at genesis. It then proves that a transaction output is in a block with n confirmations
under the proven tip.

Private inputs:
1. the k = 1 verifier key, raw-encoded ([M15](../m15));
2. the chain segments: `u32 m | m × (u32 len | NHC1 bundle)`. Segment i + 1 must start at segment
   i's end state (`z0 == zn`, canonical bytes);
3. the payment: `u32 n | headers B..T | u32 vout | u32 len | tx (no witness) | u32 depth |
   siblings | u32 index`.

The guest refuses unless every one of these holds:
- the key matches the pin for (network, k);
- Nova accepts every segment;
- the segments chain;
- header T hashes to the tip in zn;
- B..T link by previous-block hash;
- the transaction is not 64 bytes, parses completely with at least one input, and has output
  `vout`;
- its txid folds up the Merkle branch to header B's root.

The checks that don't need the tip run first, so a bad payment is refused in under a second.

Statement: guest A's 1,164-byte layout (magic | k | steps | z0 | zn | sha256(compressed vk) |
proofs digest), followed by a 128-byte payment record:

```
"PAY1" | segments | height_B | hash_B | confirmations | txid | vout | value | script length | sha256(script)
```

The genesis anchor is z0 in the statement, the same as in guest A.

Tools:
- [`sp1/script`](sp1/script) (`m16-nova-spv-script`): `elf`, `segments`, `execute`, `mutations`,
  `decode`, and `program-vk ELF` (the SP1 program key digest of an ELF file, setup only).
- [`fetch_mainnet.py`](fetch_mainnet.py): reads every header from a Bitcoin Core node (pruned is
  fine) and builds the payment input.
- [`scripts`](scripts): the WSL build and the two-shard mainnet fold.
- [`m16.elf`](m16.elf): the proven guest, 1,240,008 bytes, SHA-256 `bb7d51b0…4790`; its program
  key digest is `dfc68a5d…cb60` (`m16-nova-spv-script program-vk m16.elf`, 3 s).

### Rebuilding the ELF

The guest ELF depends on the absolute paths it is built at. `scripts/build.sh` builds as root at
`/root/nb3/m16/sp1`, with M15's vendored halo2curves at `/root/nb3/m15/vendor` and
`CARGO_HOME=/root/.cargo` (SP1 6.9.0, `cargo prove` b8387fa). Measured in WSL on 2026-11-11:

| Build | ELF SHA-256 | Bytes | Program key |
| --- | --- | ---: | --- |
| at the paths above, from this tree | `bb7d51b0…4790` (equal to `m16.elf`) | 1,240,008 | `dfc68a5d…cb60` |
| `/root/repro/w/…`, built twice | `0453cdca…d659` both times | 1,239,856 | `bd8a0210…bb61` |
| `/root/repro/w/…` with `codegen-units = 1`, built twice | `88a9f7ff…30b7` both times | 1,014,456 | `8413655b…1954` |

A build is deterministic at a fixed path, and any other checkout path gives a different ELF and a
different program key, although panic-location paths are remapped. The CI job
`bitvm3-nova-m16-elf.yml` in zk-rusto-no-bitcoino builds at the paths above and checks the ELF hash
and the program key.

## Test chain: block 170, two segments

Inputs:
- headers 0–800, folded as two segments (0–400 and 400–800);
- the payment is block 170's second transaction (`f4184fc5…`, 10 BTC, output 0, Merkle depth 1),
  with headers 170–800, so 631 confirmations.

With the raw-key guest (ELF `bb7d51b0…`):

| Run | Result |
| --- | --- |
| execute | 34,064,279,163 instructions, 873 s, 9.1 GB peak RSS; statement `67a9deb9…`, the same as the compressed-key build |
| compressed key in place of the raw key | refused |
| 13 mutations | all refused (3,569 s in total) |

The 13 mutations:
- tip nonce, payment block's Merkle root, transaction byte, vout out of range, index, trailing
  byte, Merkle sibling;
- tip header dropped, middle link broken;
- first segment's start height, first segment's proof byte;
- second segment's z0;
- segments swapped.

## Mainnet

Inputs:
- Bitcoin Core 31.1, a pruned node (`prune=550`, `listen=0`), synced headers to tip 975,072
  (`…6ff792`) in about 15 minutes.
- `fetch_mainnet.py` read the 975,073 headers back with 975,077 RPC calls in 5,322 s.
- `nova-chain native-check` agreed with Core on hash, chainwork, bits, time and median time at
  every height (535 s).

Payment:
- block 975,067 (`…55fe22`, 6,153 transactions), 6 confirmations;
- transaction `a652ab0c…0045`, output 0, 940,000 sats to P2WPKH, Merkle depth 13.
- The node, being pruned, refused `getblockfrompeer` for the block. The raw block came from
  mempool.space. That source needs no trust: its header matches the dumped header at that height,
  and the guest checks the Merkle branch against it.

| File | SHA-256 |
| --- | --- |
| headers.bin | `bc9d6ecb…21de` |
| block.bin | `41600bb8…aae8` |
| payment.bin | `6a50449f…d2a9` |

Fold, 2026-11-08 16:58 to 2026-11-10 07:09 UTC:
- two shards (0–487,536 and 487,536–975,072), 10 threads each, on a 20-thread laptop CPU, both
  exited 0;
- 137,435 s (38.2 h) wall time for the slower shard, about 345 MB RSS per process;
- with the machine to themselves the shards did 2,000 headers each in 370 to 413 s, about
  10 headers/s combined. For about a day the [M17](../m17) runs shared the CPU, and the average
  over the whole fold was 3.55 headers/s per shard;
- earlier benchmarks: 5.2 headers/s with one process, 10.4 with 2 × 10, 14.4 with 4 × 5, 16.3 with
  6 × 3.

Two shards trade CPU time against guest cost: each extra segment adds a Nova verification to the
guest. With raw keys that is about 13 × 10^9 instructions: 21.2 × 10^9 for one segment against
34.1 × 10^9 for two.

Export and guest execution (`nova-chain export`, `btc-header-fold verify-bundle`, then
`m16-nova-spv-script segments`, `execute`, `mutations`):

| Step | Result |
| --- | --- |
| export s0, s1 | 44.5 s and 31.1 s; 12,596-byte bundles `217334e1…e084` and `a7bb0ddf…7af02` |
| native verify of each bundle, compressed key `6aa50d09…da1d` | accepted, 7.8 s and 7.0 s |
| segments file | 25,204 bytes, `bdbd28e6…c878` |
| execute, raw key `4e815db8…7615`, ELF `bb7d51b0…` | 34,055,622,753 instructions, 1,283 s, 7.5 GB peak RSS |
| compressed key in place of the raw key | refused |
| the 13 mutations listed above | all refused (3,589 s in total) |

Where the instructions go: Nova verification 29.18 × 10^9, hashing the key 2.78 × 10^9, decoding
the key 2.04 × 10^9, decoding the proofs 52 × 10^6, the payment 259,390, the tip check 14,192.

Statement, 1,292 bytes, SHA-256 `cae6068f7ad8c4891cb3220702a88b0bc3df54013f45e65df11a9ced531bc869`:
- NHC1, k = 1, 975,072 steps, z0 at genesis;
- tip 975,072 (`…6ff792`), chainwork `0x156c4c3c54ad473bac5daf261`. Height, hash and chainwork
  equal Core's `getblockheader` at the tip;
- payment: block 975,067 (`…55fe22`), 6 confirmations, txid `a652ab0c…0045`, output 0,
  940,000 sats, 22-byte script `58432f41…7283`.

Proved, wrapped and garbled (2026-11-11):

| Step | Result |
| --- | --- |
| [`nb3-prove-gpu`](../prover-gpu/README.md), `--element-threshold 134217728` | compressed proof verified: 13,290 shard tasks, 4,430 recursion tasks; statement `cae6068f…c869`, program key `dfc68a5d…cb60` |
| `m13 shrink-wrap`, `m13 wrap-only-v2` | 1 min 52 s and 1 min 12 s; `m13-verify verify` and `verify-v2` accept; wrap key `d42c63e3…` and recursion key root `7487c217…` equal the pins |
| M14 circuit, plain | accepts (785,442,492 non-free gates, 96.8 s); rejects a flipped bit and guest A's statement |
| M14 circuit, garbled and evaluated | the evaluator obtains the accept label (167.1 s) |

The GPU run's last attempt took 1 h 54 min from its memo. Earlier attempts on 2026-11-10 were cut
short by a host memory guard and by the host drive filling (see the GPU prover's README). The
proofs and statement are in [`../m13/fixtures`](../m13/fixtures/README.md) (`m16-*`), the key in
[`../m13/pins.json`](../m13/pins.json), and the circuit runs in [M14](../m14/README.md#m16-on-mainnet).
