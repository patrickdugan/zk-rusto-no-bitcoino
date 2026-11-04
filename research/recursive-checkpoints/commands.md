# Commands and launch boundaries

## Now: offline preparation

```sh
python3 -m py_compile tools/research/recursive_checkpoint_gate.py tools/research/test_recursive_checkpoint_gate.py
python3 -m unittest discover -s tools/research -p 'test_recursive_checkpoint_gate.py' -v
python3 tools/research/recursive_checkpoint_gate.py template > /tmp/checkpoint-evidence.json
python3 tools/research/recursive_checkpoint_gate.py review /tmp/checkpoint-evidence.json --root /tmp
```

The review exits 2 because the evidence is pending. Use a private local evidence
directory on the operator machine. Windows can substitute its Python launcher
and an operator-owned directory for `/tmp`.

## Existing CLI syntax, for the later operator session

The following syntax was checked against `integrations/nova-header-chain/src/main.rs`
at the pinned baseline. These commands can use substantial resources. Their
presence here gives no permission to execute them before the dependency hold
clears. Run under the reviewed OS guard and inside the crate so relative fixture
paths resolve correctly.

```sh
# Existing short mainnet fixture, a new run (not a continuation).
btc-header-fold --start 1000 --k 5 --steps 20 --compress --save OUT
btc-header-fold pack OUT bundle.nhc1
btc-header-fold verify-bundle bundle.nhc1 --vk OUT/vk.bin

# Deterministic key generation is also a measured, capped phase.
btc-header-fold vk-export 5 nova_vk_k5.bin

# Existing SPV packaging, after both parts have been genuinely verified.
btc-header-fold pack-spv OUT.nsp1 VOUT TO_BLOCK.nhc1 TO_TIP.nhc1 MERKLEBLOCK_HEX TX_HEX
# TO_TIP can be '-' for the existing optional suffix convention.
```

Uppercase tokens denote local arguments. `--save` currently saves a compressed
export. It cannot resume a live recursive accumulator. The new continuation CLI
in the handoff is proposed work and has no runnable commands in this patch.

The 10,000-header run requires a suitable authenticated checkpoint and header
fixture extending across the selected interval. The early bundled fixture alone
cannot supply that range. Reuse the completed benches' validated input sources;
keep network fetching outside this preparation tool.

## Gate review after genuine results exist

```sh
python3 tools/research/recursive_checkpoint_gate.py review \
  /absolute/private/evidence/evidence.json --root /absolute/private/evidence
```

Exit 0: complete operator report, manual review still required.
Exit 2: outstanding or failed conditions.
Exit 3: malformed report, bad digest/path, or incompatible policy.

No command in the gate starts a node, sends an RPC, changes service state,
executes a proof backend, or deletes a checkpoint.
