#!/usr/bin/env python3
"""Mainnet inputs for M16 from a Bitcoin Core node: every header from genesis to a tip, and an
SPV payment in a block a few blocks below that tip.

Works on a pruned node in initial block download, where getblockhash only covers the
(short) active chain: headers are walked back from the best known header with getblockheader,
which covers every header the node has, and the payment's block is fetched from a peer with
getblockfrompeer. Read-only apart from that block fetch.

  fetch_mainnet.py --datadir D:\\btc-mainnet-hdr --out DIR [--confirmations 6] [--tip HEIGHT]

Writes into DIR:
  headers.bin    80-byte raw headers, height-indexed from genesis (nova-chain's input)
  core_ref.tsv   height, hash, chainwork, bits, time, mediantime (Core's values; nova-chain
                 native-check's reference)
  block.bin      the payment block, raw
  payment.bin    the M16 guest's payment input: u32 n | headers B..T | u32 vout | u32 len | tx
                 (no witness) | u32 depth | siblings | u32 index
  fetch.json     node version, tip, payment block, txid, output, and SHA-256 of every file
"""
import argparse, base64, hashlib, http.client, json, os, struct, time


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Rpc:
    def __init__(self, datadir, port):
        cookie = open(os.path.join(datadir, ".cookie")).read().strip()
        self.auth = "Basic " + base64.b64encode(cookie.encode()).decode()
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=600)
        self.n = 0

    def __call__(self, method, *params):
        self.n += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self.n, "method": method, "params": list(params)})
        self.conn.request("POST", "/", body, {"Authorization": self.auth, "Content-Type": "application/json"})
        r = json.loads(self.conn.getresponse().read())
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]


def raw_header(m):
    return (struct.pack("<i", m["version"]) + bytes.fromhex(m.get("previousblockhash", "00" * 32))[::-1]
            + bytes.fromhex(m["merkleroot"])[::-1] + struct.pack("<III", m["time"], int(m["bits"], 16), m["nonce"]))


def varint(b, i):
    x = b[i]
    if x < 0xfd:
        return x, i + 1
    n = {0xfd: 2, 0xfe: 4, 0xff: 8}[x]
    return int.from_bytes(b[i + 1:i + 1 + n], "little"), i + 1 + n


def ser_varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def parse_tx(b, i):
    """Returns (no-witness serialization, outputs [(value, script)], next offset)."""
    start = i
    ver = b[i:i + 4]; i += 4
    segwit = b[i] == 0 and b[i + 1] == 1
    if segwit:
        i += 2
    n_in, i = varint(b, i)
    ins = []
    for _ in range(n_in):
        j = i + 36
        l, j = varint(b, j)
        j += l + 4
        ins.append(b[i:j]); i = j
    n_out, i = varint(b, i)
    outs, out_bytes = [], []
    for _ in range(n_out):
        j = i
        value = int.from_bytes(b[i:i + 8], "little"); i += 8
        l, i = varint(b, i)
        outs.append((value, b[i:i + l])); i += l
        out_bytes.append(b[j:i])
    if segwit:
        for _ in range(n_in):
            items, i = varint(b, i)
            for _ in range(items):
                l, i = varint(b, i)
                i += l
    lock = b[i:i + 4]; i += 4
    legacy = ver + ser_varint(n_in) + b"".join(ins) + ser_varint(n_out) + b"".join(out_bytes) + lock
    if not segwit:
        assert legacy == b[start:i]
    return legacy, outs, i


def merkle_branch(txids, index):
    level, branch = list(txids), []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[index ^ 1])
        level = [sha256d(level[k] + level[k + 1]) for k in range(0, len(level), 2)]
        index //= 2
    return branch, level[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datadir", required=True)
    ap.add_argument("--port", type=int, default=8332)
    ap.add_argument("--out", required=True)
    ap.add_argument("--confirmations", type=int, default=6)
    ap.add_argument("--tip", type=int, help="tip height (default: the best header)")
    ap.add_argument("--reuse-headers", action="store_true", help="use DIR/headers.bin from an earlier run")
    ap.add_argument("--block-file", help="the payment block, raw, from any source")
    a = ap.parse_args()
    rpc = Rpc(a.datadir, a.port)
    os.makedirs(a.out, exist_ok=True)
    info, net = rpc("getblockchaininfo"), rpc("getnetworkinfo")
    assert info["chain"] == "main", info["chain"]
    if a.reuse_headers:
        hb = open(f"{a.out}/headers.bin", "rb").read()
        assert len(hb) % 80 == 0
        raws, prev = [hb[k:k + 80] for k in range(0, len(hb), 80)], bytes(32)
        for k, raw in enumerate(raws):
            assert raw[4:36] == prev, k
            prev = sha256d(raw)
        assert sha256d(raws[0])[::-1].hex() == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        tip, tip_hash = len(raws) - 1, prev[::-1].hex()
        tip_meta = rpc("getblockheader", tip_hash)
        print(f"reusing headers 0..{tip} ({tip_hash})", flush=True)
    else:
        best = max(rpc("getchaintips"), key=lambda t: t["height"])
        assert best["status"] in ("active", "headers-only", "valid-headers"), best
        tip_hash = best["hash"]
        while a.tip is not None and rpc("getblockheader", tip_hash)["height"] > a.tip:
            tip_hash = rpc("getblockheader", tip_hash)["previousblockhash"]
        tip_meta = rpc("getblockheader", tip_hash)
        tip = tip_meta["height"]
        print(f"tip {tip} {tip_hash}; walking back to genesis", flush=True)

        t0, metas, h = time.time(), [None] * (tip + 1), tip_hash
        for height in range(tip, -1, -1):
            m = rpc("getblockheader", h)
            assert m["height"] == height
            metas[height] = m
            h = m.get("previousblockhash")
            if height % 100_000 == 0:
                print(f"  {height} ({time.time() - t0:.0f} s)", flush=True)
        assert metas[0]["hash"] == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        raws = []
        with open(f"{a.out}/headers.bin.tmp", "wb") as hb, open(f"{a.out}/core_ref.tsv.tmp", "w") as tsv:
            tsv.write("height\thash\tchainwork\tbits\ttime\tmediantime\n")
            prev = b"\x00" * 32
            for m in metas:
                raw = raw_header(m)
                assert sha256d(raw)[::-1].hex() == m["hash"] and raw[4:36] == prev, m["height"]
                prev = sha256d(raw)
                hb.write(raw)
                raws.append(raw)
                tsv.write(f"{m['height']}\t{m['hash']}\t{m['chainwork']}\t{m['bits']}\t{m['time']}\t{m['mediantime']}\n")
        os.replace(f"{a.out}/headers.bin.tmp", f"{a.out}/headers.bin")
        os.replace(f"{a.out}/core_ref.tsv.tmp", f"{a.out}/core_ref.tsv")
        print(f"headers 0..{tip} written ({time.time() - t0:.0f} s, {rpc.n} RPC calls)", flush=True)

    b_height = tip - (a.confirmations - 1)
    b_hash = sha256d(raws[b_height])[::-1].hex()
    if a.block_file:
        block = open(a.block_file, "rb").read()
    else:
      try:
          block = bytes.fromhex(rpc("getblock", b_hash, 0))
      except RuntimeError:
          peers = [p["id"] for p in rpc("getpeerinfo") if not p.get("inbound")]
          for pid in peers:
              try:
                  rpc("getblockfrompeer", b_hash, pid)
                  break
              except RuntimeError as e:
                  print(f"  peer {pid}: {e}")
          for _ in range(120):
              try:
                  block = bytes.fromhex(rpc("getblock", b_hash, 0))
                  break
              except RuntimeError:
                  time.sleep(2)
          else:
              raise SystemExit("payment block not received")
    assert block[:80] == raws[b_height]
    open(f"{a.out}/block.bin", "wb").write(block)

    n_tx, i = varint(block, 80)
    txs = []
    for _ in range(n_tx):
        legacy, outs, i = parse_tx(block, i)
        txs.append((legacy, outs))
    assert i == len(block)
    txids = [sha256d(t[0]) for t in txs]
    # The first non-coinbase transaction (not 64 bytes) with a nonzero output to a
    # witness program (P2WPKH, P2WSH or P2TR): a typical recent payment.
    pick = None
    for idx in range(1, n_tx):
        legacy, outs = txs[idx]
        if len(legacy) == 64:
            continue
        for v, (value, script) in enumerate(outs):
            if value > 0 and len(script) in (22, 34) and script[0] in (0x00, 0x51):
                pick = (idx, v)
                break
        if pick:
            break
    assert pick, "no suitable payment in the block"
    idx, vout = pick
    branch, root = merkle_branch(txids, idx)
    assert root == block[36:68], "Merkle root mismatch"
    legacy, outs = txs[idx]
    headers = raws[b_height:tip + 1]
    pay = struct.pack("<I", len(headers)) + b"".join(headers) + struct.pack("<II", vout, len(legacy)) + legacy \
        + struct.pack("<I", len(branch)) + b"".join(branch) + struct.pack("<I", idx)
    open(f"{a.out}/payment.bin", "wb").write(pay)
    sha = lambda p: hashlib.sha256(open(f"{a.out}/{p}", "rb").read()).hexdigest()
    value, script = outs[vout]
    meta = {
        "chain": "main", "core_version": net["subversion"],
        "tip_height": tip, "tip_hash": tip_hash, "tip_chainwork": tip_meta["chainwork"],
        "payment": {
            "block_height": b_height, "block_hash": b_hash, "confirmations": len(headers),
            "block_tx_count": n_tx, "tx_index": idx, "txid": txids[idx][::-1].hex(), "vout": vout,
            "value_sats": value, "script_pubkey": script.hex(),
            "script_sha256": hashlib.sha256(script).hexdigest(), "merkle_depth": len(branch),
        },
        "files": {p: sha(p) for p in ("headers.bin", "core_ref.tsv", "block.bin", "payment.bin")},
    }
    json.dump(meta, open(f"{a.out}/fetch.json", "w"), indent=1)
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
