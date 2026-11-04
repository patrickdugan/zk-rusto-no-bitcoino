# Testnet4: genesis-anchored Nova header-chain proof under 1.5 GiB

Branch `feat/testnet4-recursive-chain`, based on PR #14 (`9ba7770`) and
importing PR #15's preparation contracts. The machine-readable status is in
`acceptance-ledger.json`. Raw outputs (stdout JSON, stderr, systemd unit
result with cgroup peak, GNU time) are in `logs/`.

## Result

The testnet4 header chain from its genesis block to height 158,970 (Core's
tip at dump time) is proven in one Nova continuation and compressed to a
13,220-byte proof.

- **Steps:** 31,794 folds of k=5 headers.
- **Memory:** every proving, export and verification step ran under an
  OS-enforced 1,536 MiB cap (cgroup v2 `memory.max`, swap 0; the cgroup also
  charges page cache from checkpoint writes).
- **Independent verification:** `btc-header-fold verify-bundle` verifies the
  proof on the VPS and on a Windows laptop, with the pinned key and with a
  rebuilt key.
- **Receipt:** it starts at the consensus genesis anchor and ends at Core's
  tip hash and chainwork.
- **Fixture:** the proof is
  `integrations/nova-header-chain/fixtures/testnet4/genesis_0_158970_k5.nht4`,
  and CI verifies it in `tests/testnet4_bundle.rs`.

| | Value |
| --- | --- |
| Start | height 0, `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`, chainwork `0x100010001` |
| End | height 158,970, `00000000037eaf09696c4d3deddcdc2a2bbb6c15c241afb31de3545d6849b6d1`, chainwork `0xf0ec105bc6803722073` (equal to Core) |
| Folds | 31,794 (k=5) |
| Fold time | 0.123 s/header; 5:07:37 wall for 29,794 folds from 10,000 (the earlier runs: 2,000 folds) |
| Peak, folding | cgroup 1,169 MiB; RSS 1,115 MiB |
| Durable generations | 87; verify before publish 0.76 s mean; serialize and publish 0.48 s mean (3.2 s max) |
| Continuation payload | 28,495,096 bytes (`accumulator.bin`), plus manifest |
| Cold verify of the continuation | 12.6 s parameter setup + 1.2 s restore and verify; cgroup 758 MiB |
| Compression (export) | 39 s Spartan prove; cgroup 1,444 MiB |
| Compressed proof | 13,220-byte NHT4 bundle, SHA-256 `f0bbf308a26875edce56bd2dde85ccd975159fb5d8f6a0bf3b47a3bcd93e0f8b`; proof SHA-256 `eca27d14ee3d83acfb5087017680027dc7f6d7435e7b3d78d8d07370bb5123ee` |
| Verification | 2.3 s with the key file (cgroup 470 MiB); 38 s including key rebuild (cgroup 713 MiB) |
| Verifier key | `1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24` (testnet4 k=5; same on Windows MSVC/asm and Linux no-asm) |
| Circuit identity | `730c0463ef01bce15b4429aae164217ded34ee8b70edd86821bc2be952a5d44e` (network, k, constraint and variable counts) |
| Public-parameter digest | `8df73bd3060cd6f15b8510cb6d97f98c01d6986a8ea5536095723dc9ff95dd01` |
| Start-state SHA-256 (genesis anchor) | `9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c` |
| End-state SHA-256 | `6cef2039cd645a732846aa92a59afca7a8ffc3387b988ee082837d0cd266b965` |

### Milestones

All runs are on the same machine and under the same cap.

| Run | Range | Folds | Fold s/header | Fold peak | Export peak | Verify | Start provenance |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PR #14 reproduction | 100,700 → 100,900 | 40 | 0.123 | 905 MiB | 1,499 MiB (RSS 1,412) | verified, 471 MiB | **Unproven start:** state derived natively from genesis; its chainwork `0x54596fd7758cafd453c` equals Core's |
| Genesis → first retarget | 0 → 2,020 | 404 | 0.124 | 935 MiB | 1.4 GiB (RSS 1,473 MiB) | verified, 470 MiB | **Genesis anchor** |
| Genesis → 10,000 | 0 → 10,000 | 2,000 | 0.155 (three jobs sharing CPU) | 1,106 MiB | 1,362 MiB | verified, 471 MiB | **Genesis anchor** |
| Genesis → tip | 0 → 158,970 | 31,794 | 0.123 | 1,169 MiB | 1,444 MiB | verified, 470 MiB / 713 MiB (key rebuild) | **Genesis anchor** |

Margin to the 1,536 MiB cap:

- **Folding, cold verification, verification:** at least 367 MiB.
- **Compression (export):** narrow; the worst case is 1,499 MiB cgroup.
  k=1 was not needed and was not measured.

## Phase A: authentication of the starting state

**Anchor.** The trust anchor is the testnet4 genesis block itself.
`State::genesis` builds the starting state from the consensus genesis header
(its fields come from Core's chainparams; a test checks that it hashes to the
genesis hash). Its chainwork is the genesis block's own work, and every later
unit of work is added inside the proof. No chainwork value is asserted from
outside.

**Median-time-past for early heights.** Core uses the median of the blocks
that exist; for n < 11 that is `sorted[n/2]`. The 11-slot window is padded
with alternating 0 and `u32::MAX` slots so that its median matches Core's at
every fill level. The window drains oldest first, which keeps the split
right. A unit test compares against Core's definition for random histories,
and the Core differential below covers the real heights.

**Differential reference.** `scripts/dump-core-headers.py` dumped all 158,971
headers from Bitcoin Core 31.1 (testnet4, pruned, synced; read-only RPC).
Each header must hash to Core's block id and link to its predecessor. Core's
per-height hash, chainwork, bits, time and median time were recorded.
`nova-chain native-check` then applies the native rules from the genesis
state and compares all five fields at every height:

- **0–158,970: all agree.**
- The range includes 78 retargets and 107,083 min-difficulty blocks.
- Its smallest boundary timewarp margin is 0 s: a period's first block exactly
  600 s before its predecessor, which Core accepts and so does the rule.
- Run: 1.6 s.
- Committed slice: `fixtures/testnet4/headers_0_4100.bin` and
  `core_ref_0_4100.tsv`.
- Dump digests: `core_dump_158970.json`.

**What this proves and what it does not:**
- The Core comparison is a differential check of the native mirror, not
  soundness evidence for the circuit.
- The circuit binds every header to the rules it encodes. The native rules
  agree with Core, and the circuit agrees with the native rules (outputs are
  compared at every published generation).

**The 100,700 run.** Its start is the state the native rules derive from
genesis over Core's headers. That start is **checked, not proven**, and is
labelled `native-from-genesis/.../unproven-checkpoint` in its manifest. The
genesis-anchored chain supersedes it.

**Typed, versioned checkpoint.** `continuation.schema.v2.json`, with the
manifest that `nova-chain` writes. It carries:
- all 17 state elements and their digests;
- network, k and anchor policy;
- circuit identity and public-parameter digest;
- the pinned verifier key;
- the input chain hash and parent manifest.

## Phase B: testnet4 rules across boundaries

**Audit result.** PR #14's rules match Core's testnet4 logic. The table names
the Core function each rule comes from.

| Rule | Core source | PR #14 implementation |
| --- | --- | --- |
| Min-difficulty | `GetNextWorkRequired` with `fPowAllowMinDifficultyBlocks` | strict `t > prev + 1200`; otherwise the epoch's nBits, which is what Core's walk-back yields |
| BIP94 retarget base | BIP94 `CalculateNextWorkRequired` | the first block of the period |
| BIP94 timewarp | `ContextualCheckBlockHeader` | `t >= prev - 600` at a boundary |
| Versions | signed comparison | version ≥ 4 from height 1 |

**Changes:** none. **Evidence:** the full-chain Core differential, the
existing edge tests (1200/1201 s, 600/601 s, retarget from a min-difficulty
predecessor, version 3), and the proofs, which cross 78 real retargets.

**Adversarial evidence on a real bundle:** `logs/adversarial/summary.tsv`.
Every case was rejected:
- **Bundle tampers:** forged chainwork, altered start height, altered start
  hash, altered MTP window, altered retarget-base epoch bits, altered step
  count, altered proof bytes, and the bundle verified against the mainnet
  circuit.
- **Continuation tampers:** corrupted payload, forged step count, wrong z0,
  wrong end state, changed k, relabelled network, swapped parameters.
- **Resume cases:** resume with a different k, a fork that shares only the
  height (block 100,850 altered: native PoW rejects it), and an omitted block
  (100,830 removed: `prev_link` rejects it).

**Found and fixed: relabelled bundle.** The first run of the suite found that
a testnet4 bundle relabelled `NHC1` and verified with `--vk` (the testnet4
key) **was accepted and produced a mainnet receipt**. `verify-bundle` now
refuses a key pinned to another (network, k)
(`logs/adversarial/adv-relabel-fixed.json`, `tests/testnet4_bundle.rs`).
With a rebuilt key it was already refused. The gateway pins the mainnet key
hash, which would also have refused it.

## Phase C: bounded RAM and resumable recursion

**Memory bounds.**
- Headers stream from a height-indexed file, one fold step at a time.
- The live `RecursiveSNARK`, z0 and the exact step count are persisted.
- The public parameters are rebuilt and pinned by digest.
- k and network cannot change across a continuation.

**Nova initial-step semantics (0.76).** `new(c0)` executes step 0, and the
first `prove_step` after it is a no-op that ignores its circuit. A
continuation is never published at `i = 0`. `src/tests.rs` pins this, and
also checks that a restored accumulator continues exactly, that a wrong step
count or z0 is refused, and that an omitted block does not verify.

**Publication protocol.**
1. Verify against the native state.
2. Write the payload and manifest in a `.tmp` generation, with fsync.
3. Rename, then fsync the parent.
4. Publish LATEST atomically.
5. Keep the previous generation.

**Resume.** A resumed run re-verifies the newest generation before appending
and falls back to an older one if it fails.

**Interruption tests** (`logs/interrupt/summary.tsv`). The process was
aborted at each of these points:
- witness ingestion;
- the proof update;
- a torn payload write, twice (generations 2 and 4);
- a torn manifest write;
- after the generation rename but before the LATEST update.

Every case resumed to the **same verified end state and step count** as the
uninterrupted reference (`bad079be…`, 20 steps). A torn LATEST payload falls
back to the previous verified generation.

**Phase timings and peaks** (in each run's JSON):
- setup;
- native anchor;
- per-generation verify-before-publish and serialize-and-publish;
- restore and verify;
- compress setup, prove and self-verify;
- independent verify.

## Phase E: SPV over testnet4, without SP1

**Identifiers.** `pack-spv` writes `NST4` for testnet4 NHT4 proofs; mainnet
`NSP1` is unchanged.

**Offline verifier.** `scripts/verify-nst4.py` checks:
1. both proofs with the pinned `btc-header-fold` and key;
2. that the first proof starts at the genesis anchor;
3. that the second proof starts at the first proof's end state;
4. the Merkle branch, including the CVE-2012-2459 duplicate shape and the
   64-byte guard;
5. the output;
6. Core's active chain, chainwork and `gettxout`.

The gateway's verification authority is not changed.

**Canary** (`logs/spv/`):
- **Payment:** tx `6ce83076f3228b1e177817af3d522c1e8f3a98f8c7d88fd7c16a01462515dde5`,
  output 0, 4,900,000,000 sats, in block 158,965, with 6 confirmations.
- **Proofs:** genesis → 158,965 (a fork of the tip continuation, extended),
  then 158,965 → 158,970.
- **Core:** the active chain and chainwork match, and Core reports the output
  unspent at lookup. That is Core's view, not proven.
- **Refusals:** wrong expected vout, txid or value; tampered Merkle node,
  transaction or second proof; a state-join mismatch; a non-genesis first
  proof.

**Groth16 compression: not attempted.** Compressing this proof into BN254
Groth16 needs one of two things:
- verifying a Pallas/Vesta IPA + Spartan proof inside a BN254 circuit, which
  means non-native field arithmetic and multi-scalar multiplications;
- re-folding over a BN254/Grumpkin cycle with a Groth16 decider.

The groth16-gym on `main` (`daf9a06`) measured 1.3–2.5 KB of proving memory
per constraint for SHA-heavy BN254 circuits. Any decider of a few million
constraints is therefore estimated above 1.5 GiB. This estimate is not
measured for a decider. Per the brief, the native compressed Nova proof is
the deliverable.

## Machine and build

| | Value |
| --- | --- |
| VPS | 8 vCPU "Intel Core Processor (Skylake, IBRS)" (no ADX exposed), 31 GiB RAM |
| OS | Ubuntu 26.04.1 LTS, kernel 7.0.0-38, cgroup v2 |
| Toolchain | rustc 1.99.1 |
| Nova | nova-snark 0.76.0, vendored without halo2curves asm (`scripts/vendor-nova-noasm.sh`) |

**Binary used for the tip run:**
- `nova-chain` SHA-256 `1341a869797939e240f6f738c341d589ca5bd85d5f7aacc34029deff59320dbf`
  (recorded in each manifest);
- built from the working tree committed as `d93940e`;
- manifests carry `source_commit: "wip"`.

**Binaries used for earlier runs:**
- The runs up to 10,000 used `84ec865e…`, built before the publish fix for
  orphaned generations.
- The final `btc-header-fold` that verified everything after the relabel fix
  is `c837fc41…`.

**Cap tooling.** `scripts/capped.sh` runs each step in a transient systemd
unit (`MemoryMax=1536M`, `MemorySwapMax=0`). PR #14's 200-header numbers came
from a Windows job object; these runs use the Linux cgroup.

## Reproduce

On a Linux machine with a synced testnet4 Core node and sudo for
`systemd-run`:

```
cd integrations/nova-header-chain
sh scripts/vendor-nova-noasm.sh          # only on CPUs without ADX
cargo build --release
python3 scripts/dump-core-headers.py --datadir ~/btc-testnet4 --port 48352 --out ~/tn4-data
target/release/nova-chain native-check --network testnet4 --headers ~/tn4-data/headers.bin --core-ref ~/tn4-data/core_ref.tsv
sh scripts/tn4-phase-d1.sh               # 200-header reproduction, genesis to 2,020
sh scripts/tn4-phase-d2.sh               # to 10,000, then to TIP (TIP=... env)
sh scripts/tn4-interrupt.sh
sh scripts/tn4-adversarial.sh ~/tn4-runs/c200.nht4 ~/tn4-runs/tn4-k5.vk ~/tn4-runs/c200
sh scripts/tn4-spv-canary.sh
```

To verify the whole-chain proof anywhere, without a node:

```
target/release/btc-header-fold verify-bundle fixtures/testnet4/genesis_0_158970_k5.nht4
```

That rebuilds the key; `--vk FILE` supplies it instead. Then check that
`checkpoint_state_sha256` equals the genesis anchor
`9c82dffe…de9c` (`nova-chain anchor --network testnet4`).

## Not claimed

- **Header-chain validity only.** No transaction or script validation, no
  UTXO set, no proof of unspentness, and no best-chain selection: compare
  chainwork with a node.
- **Future-time rule.** Not enforced; it needs a wall clock.
- **Keys are pinned candidates.** No ceremony applies to Nova, but the keys
  are not audited releases.
- **Not post-quantum.** Pallas/Vesta.
- **Not zero knowledge.** The continuation payload holds witness material
  and is not ZK.
- **Pilot deployment.** Gated on the recursive-sharding benchmark and
  SPV-prototype acceptance reports (PR #15's gate). No production service,
  Core node, pruning policy or gateway authority was changed.
