#!/usr/bin/env python3
"""Check the committed NHT4 fixture/inventory integrity, never proof validity."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "fixtures" / "bitcoin-header"
VK = "9e94b9083b5be30e796e974218804214b7106284c071eeec9b15945735321727"


def require(test: bool, why: str) -> None:
    if not test:
        raise ValueError(why)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_bundle(raw: bytes, receipt: dict) -> None:
    require(556 < len(raw) <= 1 << 20, "NHT4 bundle length")
    require(raw[:4] == b"NHT4", "NHT4 magic")
    require(int.from_bytes(raw[4:8], "little") == 2, "step count")
    require(int.from_bytes(raw[8:12], "little") == 20, "fold width")
    require(raw[12:556].hex() == receipt["initial_state_hex"], "checkpoint bytes")
    require(len(raw) == receipt["bundle_bytes"], "bundle byte count")
    require(digest(raw) == receipt["bundle_sha256"], "bundle checksum")
    require(len(raw[556:]) == receipt["proof_bytes"], "proof byte count")
    require(digest(raw[556:]) == receipt["proof_sha256"], "proof checksum")


def check_state(raw: bytes, rec: dict, prefix: str) -> None:
    require(len(raw) == 544, prefix + " length")
    require(digest(raw) == rec[prefix + "_state_sha256"], prefix + " digest")
    info = rec[prefix]
    require(int.from_bytes(raw[:32], "little") == info["height"], prefix + " height")
    require(int.from_bytes(raw[96:128], "little") == int(info["chainwork"], 16),
            prefix + " chainwork")
    tip = (raw[32:48] + raw[64:80])[::-1].hex()
    require(tip == info["tip_hash"], prefix + " tip")


def main() -> None:
    manifest = {}
    for row in (ROOT / "SHA256SUMS").read_text().splitlines():
        sha, filename = row.split(maxsplit=1)
        require(filename not in manifest, "duplicate manifest entry")
        manifest[filename] = sha
    expected_files = {"README.md", "k20-testnet4-0-40.nht4",
                      "k20-testnet4-40-80.nht4",
                      "k20-codex-run-verified.json",
                      "k20-testnet4-verifier-inventory.json"}
    require(set(manifest) == expected_files, "manifest file coverage")
    for name, checksum in manifest.items():
        require(digest((ROOT / name).read_bytes()) == checksum, "manifest hash: " + name)

    run = json.loads((ROOT / "k20-codex-run-verified.json").read_text())
    require((run["k"], run["shards"], run["to_height"]) == (20, 2, 80),
            "proving receipt dimensions")
    require(len(run["artifacts"]) == 2, "shard receipts")
    previous = None
    for i, entry in enumerate(run["artifacts"]):
        require(entry["index"] == i and entry["vk_sha256"] == VK, "shard/key order")
        rec = entry["native_receipt"]
        require(rec["verified"] is True and rec["network"] == "testnet4"
                and rec["statement"] == "btc_header_chain_testnet4_v1",
                "reported native result and network")
        require(rec["vk_sha256"] == VK, "native verifier identity")
        path = ROOT / f"k20-testnet4-{i*40}-{(i+1)*40}.nht4"
        b = path.read_bytes()
        verify_bundle(b, entry)
        first, last = bytes.fromhex(entry["initial_state_hex"]), bytes.fromhex(entry["end_state_hex"])
        check_state(first, rec, "checkpoint")
        check_state(last, rec, "end")
        require(previous is None or previous == first, "full checkpoint continuity")
        previous = last
        if i == 0:
            for pos in (0, 4, 8, 12, 556, len(b)-1):
                modified = bytearray(b)
                modified[pos] ^= 1
                try:
                    verify_bundle(modified, entry)
                except ValueError:
                    pass
                else:
                    raise ValueError(f"tampered fixture accepted at offset {pos}")
    require(digest(previous) == run["continuity"]["end_state_sha256"], "final state")

    inv = json.loads((ROOT / "k20-testnet4-verifier-inventory.json").read_text())
    require(inv["verifier_key_sha256"] == VK and inv["verifier_key_bytes"] == 500333512,
            "inventory key commitment")
    require(len(inv["engines"]) == 2, "two engines")
    muls = msm = 0
    for e in inv["engines"]:
        nnz = e["nnz"]
        n = e["ipa_opening_length_n"]
        ops = e["verify_ops"]
        require(nnz["total"] == sum(nnz[x] for x in "ABC"), "matrix nonzeros")
        require(ops["matrix_eval_breakdown"]["per_nonzero"] == 2*nnz["total"],
                "matrix products")
        require(ops["matrix_eval_breakdown"]["eq_tables"] == e["padded_rows"]+e["z_columns"],
                "equality products")
        require(ops["matrix_eval_field_muls"] == sum(ops["matrix_eval_breakdown"].values()),
                "matrix multiplication accounting")
        require(n == e["ipa_ck_v_generators"] == ops["ipa_msm_terms"], "IPA generators")
        require(ops["ipa_s_vector_field_muls"] == n-1, "IPA vector products")
        muls += ops["matrix_eval_field_muls"] + ops["ipa_s_vector_field_muls"]
        msm += n
    require((muls, msm) == (27525706, 2113536), "recorded cross-engine counts")
    require(muls == inv["linear_verifier_work"]["field_muls_in_matrix_eval_and_ipa_scalars"],
            "inventory multiplication sum")
    require(msm == inv["linear_verifier_work"]["msm_terms_total"], "inventory MSM sum")
    print(json.dumps({
        "scope": "fixture_integrity_and_operation_arithmetic_only",
        "cryptographic_proof_verified_here": False,
        "vk_export_k20_digest_reproduced_here": False,
        "bundles_checked": 2,
        "field_multiplications": muls,
        "msm_terms": msm,
        "proxy_gates": muls*360963,
        "proxy_ciphertext_bytes": muls*360963*16,
    }, indent=2))


if __name__ == "__main__":
    main()
