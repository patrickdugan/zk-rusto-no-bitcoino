#!/usr/bin/env python3
"""Dump every header of a Bitcoin Core node's active chain, from genesis.

Writes, into OUT_DIR:
  headers.bin   80-byte raw headers, height-indexed (byte offset = height * 80)
  core_ref.tsv  height, hash, chainwork, bits, time, mediantime: Core's own
                values, used as the differential reference for the native
                validator and the circuit's state
  dump.json     node version, chain, tip and the SHA-256 of both files

Each raw header is checked to double-SHA-256 to Core's block hash and to link
to its predecessor. Read-only RPC (getblockhash, getblockheader, getnetworkinfo,
getblockchaininfo).

  dump-core-headers.py --datadir ~/btc-testnet4 --port 48352 --out ~/tn4-data [--to HEIGHT]
  dump-core-headers.py --chain main --datadir %APPDATA%\\Bitcoin --port 8332 --out mainnet-data
A pruned node is enough, but it must be synced: getblockhash only covers the
active chain, which a headers-only node has not built.
"""
import argparse, base64, hashlib, json, os, urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datadir", required=True)
    ap.add_argument("--chain", default="testnet4")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--to", type=int)
    ap.add_argument("--batch", type=int, default=1000)
    a = ap.parse_args()
    # Core keeps the mainnet cookie in the datadir itself, others in a subdirectory.
    sub = "" if a.chain in ("main", "mainnet") else a.chain
    cookie = open(os.path.join(os.path.expanduser(a.datadir), sub, ".cookie")).read().strip()
    auth = "Basic " + base64.b64encode(cookie.encode()).decode()

    def batch(calls):
        body = json.dumps([{"jsonrpc": "1.0", "id": i, "method": m, "params": p}
                           for i, (m, p) in enumerate(calls)]).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{a.port}", data=body,
                                     headers={"Authorization": auth, "Content-Type": "application/json"})
        res = sorted(json.loads(urllib.request.urlopen(req, timeout=300).read()), key=lambda r: r["id"])
        for r in res:
            if r.get("error"):
                raise RuntimeError(r["error"])
        return [r["result"] for r in res]

    info, net = batch([("getblockchaininfo", []), ("getnetworkinfo", [])])
    tip = info["blocks"] if a.to is None else a.to
    os.makedirs(os.path.expanduser(a.out), exist_ok=True)
    out = os.path.expanduser(a.out)
    hb, tsv = open(f"{out}/headers.bin.tmp", "wb"), open(f"{out}/core_ref.tsv.tmp", "w")
    tsv.write("height\thash\tchainwork\tbits\ttime\tmediantime\n")
    prev = None
    for lo in range(0, tip + 1, a.batch):
        hs = range(lo, min(tip, lo + a.batch - 1) + 1)
        hashes = batch([("getblockhash", [h]) for h in hs])
        raws = batch([("getblockheader", [x, False]) for x in hashes])
        meta = batch([("getblockheader", [x, True]) for x in hashes])
        for h, x, raw, m in zip(hs, hashes, raws, meta):
            b = bytes.fromhex(raw)
            assert len(b) == 80 and m["height"] == h
            assert hashlib.sha256(hashlib.sha256(b).digest()).digest()[::-1].hex() == x, h
            assert prev is None or b[4:36] == prev, h
            prev = hashlib.sha256(hashlib.sha256(b).digest()).digest()
            hb.write(b)
            tsv.write(f"{h}\t{x}\t{m['chainwork']}\t{m['bits']}\t{m['time']}\t{m['mediantime']}\n")
        print(f"{hs[-1]}/{tip}", flush=True)
    hb.close(); tsv.close()
    os.replace(f"{out}/headers.bin.tmp", f"{out}/headers.bin")
    os.replace(f"{out}/core_ref.tsv.tmp", f"{out}/core_ref.tsv")
    sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
    json.dump({"chain": info["chain"], "core_version": net["subversion"], "tip_height": tip,
               "tip_hash": hashes[-1], "tip_chainwork": meta[-1]["chainwork"],
               "headers_bin_sha256": sha(f"{out}/headers.bin"),
               "core_ref_tsv_sha256": sha(f"{out}/core_ref.tsv")},
              open(f"{out}/dump.json", "w"), indent=1)
    print(open(f"{out}/dump.json").read())


if __name__ == "__main__":
    main()
