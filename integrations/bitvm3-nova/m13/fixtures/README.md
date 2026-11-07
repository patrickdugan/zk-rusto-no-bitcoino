# M13 fixtures

All produced on 2026-11-07 by `m13` (SP1 6.9.0, x86_64 WSL2) from public inputs.

| File | Bytes | SHA-256 | What |
| --- | ---: | --- | --- |
| `c4-compressed.bin` | 1,273,665 | `9e6f1ba3…52e7` | SP1 6.9.0 compressed proof of the control-C guest (`m12/sp1/program-direct`, ELF `2d49248d…9005`) over testnet4 heights 1–4 from the consensus genesis state (`m12/fixtures/testnet4-headers-0-80.bin`). Committed values: 1,096 bytes, magic \| n \| z0 \| zn; SHA-256 `cd9beb30…6567`. |
| `c4-wrap-blake3.bin` | 1,099,173 | `896105cf…42bb` | bincode `SP1WrapProof<Blake3KoalaBear, …>`: SP1's wrap program over SP1's shrink of `c4-compressed.bin`, proved with BLAKE3. 104-byte key + 1,099,069-byte proof. |
| `c4-wrap-blake3-v2.bin` | 1,099,173 | `b37cb7a6…8564` | The same shrink proof wrapped under transcript v2 (`Blake3KoalaBearV2`, fixed-cost challenges; M14). Same key and statement as `c4-wrap-blake3.bin`; `m13-verify verify-v2` checks it. |
| `c4-statement.json` | 408 | `b0675307…c386` | The statement `m13-verify` decodes and checks: pinned wrap key, guest key digest, recursion key-map root, committed-values digest, exit code 0, complete. |
| `shrink-shape.json` | 192 | `22978774…5ae1` | Chip heights of SP1's shrink program (fixed by SP1); `m13 check-wrap-program` rebuilds the wrap program from it. |

Reproduce the wrap from the compressed proof (3.5 min, 7 GiB RAM plus 3.5 GB swap here):

```
m13 shrink-wrap nova-bitvm3/m13/fixtures/c4-compressed.bin OUT
m13-verify verify OUT/wrap.bin nova-bitvm3/m13/fixtures/c4-statement.json
m13 wrap-only-v2 OUT          # transcript v2 from OUT/shrink.bin (1 min, same memory)
m13-verify verify-v2 OUT/wrap-v2.bin nova-bitvm3/m13/fixtures/c4-statement.json
```
