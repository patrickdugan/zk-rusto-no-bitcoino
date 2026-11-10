# FlatCheck / FlatMerkle laboratory (BitVM3)

Experimental sidecar for [Sergio Demian Lerner, *FlatMerkle: Logarithmic-Space Inclusion Proofs over a Single Linear Hash Stream* (2026)](https://github.com/SergioDemianLerner/FlatMerkle). This work lives in **zk-rusto-no-bitcoino**, beside the existing independent BitVM3 Nova integration.

## What this branch implements

`flatmerkle.py` constructs the recursively laid-out, 64-byte-block FlatMerkle stream. Its commitment is the ordinary SHA-256 digest of the exact byte stream, using a transparent compression-function implementation to reconstruct intermediate states. It exposes one-index opening and verification with logarithmic compression work. Tests exercise SHA256's standard finalization, every index for 4–64 leaves, wrong-index substitution, altered data, altered sibling state, and wrong commitments.

Run without a prover or network dependency:

```sh
cd integrations/bitvm3-nova/flatcheck-lab
python3 -m unittest discover -p 'test_*.py' -v
```

This code is a **reference experiment**, and has not received production cryptographic review. It assumes a power-of-two number of 64-byte blocks (at least 4), and each supplied item is padded with zero bytes up to 64. Applications must specify exact canonical item encodings and ensure that padding does not create ambiguity.

## Intended application to this repo

A compressed Bitcoin header-chain/checkpoint verification claim has public inputs (checkpoint hash, chainwork conditions, chain policy and the proposed final state). A verifier may be lowered to a stable set of local constraints. A challenger that finds a violated constraint would require authenticated openings of precisely the wire or trace values read by that constraint, tied to a public fixed verifier descriptor.

Proposed public-boundary relation:

```
claim_id = SHA256(domain || pinned_verifier_id || network || checkpoint ||
                  claimed_tip || claimed_chainwork || proof_or_trace_commitment)
failed_check = chosen_check_id || authenticated_operands ||
               authenticated_fixed_descriptor || failed_relation_result
```

The exact transaction-level commitment, all length prefixes, hashes and endianness must be defined before connecting this to Bitcoin funds. A locally failing condition is only grounds to adjudicate a bonded claim if the values have been authenticated to that exact claim. An operator's missing response needs a separately enforceable deadline. Counterparty signatures, replay handling, canonical-chain authentication, and Bitcoin transactions are additional requirements.

### Follow-on gates (not implemented in this port)

1. Extract every required local check, including public outputs and canonicality, from a **pinned** Nova/SP1 or STWO verification graph; prove native equivalence on frozen positive and adversarial witnesses.
2. Partition witness values into bounded authenticated groups, with a single source for values shared between groups; bind each group to the proof and fixed verifier identity.
3. Implement both FlatMerkle and ordinary Merkle publication baselines, including malformed-byte-stream fraud evidence. Count all authenticated-read and fixed-descriptor gates rather than just the arithmetic operation.
4. Measure off-chain garbling, peak memory, proof/opening bytes, publication weight and Bitcoin regtest response/timeout spends; enforce real availability and bond economics before any settlement authority.

**Status/provenance:** This branch is an independently written, minimal primitive. A previous chat described a larger S2 FlatCheck lab and gate-count measurements in `garbled-snark-verifier`; that local checkout is unavailable in the current execution environment, so those numbers have **not** been copied, reproduced or presented as measurements in this repository. The two repositories may be connected with a pinned, reviewed artifact later. This branch does not run cloud Nova/SP1 proofs or modify existing proving paths.
