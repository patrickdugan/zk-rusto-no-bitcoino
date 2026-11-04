#!/usr/bin/env python3
"""Verify a sharded header-chain proof: consecutive NHC1/NHT4 bundles.

Accepts the set only if:
 1. every bundle verifies with the verifier executable (btc-header-fold
    verify-bundle; with --vk, against that key, which must be identical for
    all shards; without it, the key is rebuilt per bundle);
 2. every bundle is for --network;
 3. the first bundle starts at the network's genesis anchor (from
    `nova-chain anchor`), and
 4. each later bundle starts exactly at the previous bundle's proven end
    state (end_state_sha256 == next checkpoint_state_sha256) and height.
Prints one btc_header_chain_shards_v1 receipt covering genesis to the last
end; exit 1 on refusal. With --core-datadir/--core-port, also checks the
final end hash and chainwork against Core's active chain.

  verify-segments.py --network mainnet --verifier btc-header-fold[.exe] \
      --nova-chain nova-chain[.exe] [--vk VK] shard-000.bundle shard-001.bundle ...
"""
import argparse, base64, hashlib, json, os, subprocess, sys, urllib.request


def refuse(msg):
    print(json.dumps({"statement": "btc_header_chain_shards_v1", "verified": False, "error": msg}))
    sys.exit(1)


def last_json(out):
    for line in reversed(out.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            pass
    return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundles", nargs="+")
    ap.add_argument("--network", required=True, choices=["mainnet", "testnet4"])
    ap.add_argument("--verifier", required=True)
    ap.add_argument("--nova-chain", required=True)
    ap.add_argument("--vk")
    ap.add_argument("--core-datadir"); ap.add_argument("--core-port", type=int)
    a = ap.parse_args()

    anchor = last_json(subprocess.run([a.nova_chain, "anchor", "--network", a.network],
                                      capture_output=True, text=True).stdout)
    if "initial_state_sha256" not in anchor:
        refuse("could not compute the genesis anchor")
    statement = "btc_header_chain_testnet4_v1" if a.network == "testnet4" else "btc_header_chain_v1"
    receipts, vk_shas = [], set()
    for i, b in enumerate(sorted(a.bundles) if all("shard-" in x for x in a.bundles) else a.bundles):
        cmd = [a.verifier, "verify-bundle", b] + (["--vk", a.vk] if a.vk else [])
        out = subprocess.run(cmd, capture_output=True, text=True)
        r = last_json(out.stdout)
        if out.returncode != 0 or r.get("verified") is not True:
            refuse(f"{b}: rejected: {r.get('error')}")
        if r.get("statement") != statement:
            refuse(f"{b}: not a {a.network} header-chain proof")
        if i == 0:
            if r["checkpoint_state_sha256"] != anchor["initial_state_sha256"]:
                refuse(f"{b}: first shard does not start at the {a.network} genesis anchor")
        else:
            prev = receipts[-1]
            if r["checkpoint_state_sha256"] != prev["end_state_sha256"] or r["checkpoint"] != prev["end"]:
                refuse(f"{b}: does not start at the previous shard's proven end state")
        vk_shas.add(r["vk_sha256"])
        receipts.append(r)
        print(f"shard {i}: {r['checkpoint']['height']} -> {r['end']['height']} verified", file=sys.stderr)
    if len(vk_shas) != 1:
        refuse("shards were verified against different keys")
    first, last = receipts[0], receipts[-1]
    receipt = {"statement": "btc_header_chain_shards_v1", "network": a.network, "verified": True,
               "anchor": anchor["anchor_policy"], "start": first["checkpoint"], "end": last["end"],
               "end_state_sha256": last["end_state_sha256"], "headers": sum(r["headers"] for r in receipts),
               "shards": len(receipts), "vk_sha256": vk_shas.pop(),
               "proof_sha256": [r["proof_sha256"] for r in receipts]}
    if a.core_datadir:
        sub = "" if a.network == "mainnet" else "testnet4"
        cookie = open(os.path.join(os.path.expanduser(a.core_datadir), sub, ".cookie")).read().strip()
        auth = "Basic " + base64.b64encode(cookie.encode()).decode()

        def rpc(m, *p):
            req = urllib.request.Request(f"http://127.0.0.1:{a.core_port}", data=json.dumps(
                {"jsonrpc": "1.0", "id": 0, "method": m, "params": list(p)}).encode(),
                headers={"Authorization": auth, "Content-Type": "application/json"})
            return json.loads(urllib.request.urlopen(req, timeout=60).read())["result"]

        e = last["end"]
        if rpc("getblockhash", e["height"]) != e["tip_hash"]:
            refuse("the proven end is not on Core's active chain")
        if int(rpc("getblockheader", e["tip_hash"])["chainwork"], 16) != int(e["chainwork"], 16):
            refuse("the proven end chainwork differs from Core")
        receipt["active_chain_at_lookup"] = True
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
