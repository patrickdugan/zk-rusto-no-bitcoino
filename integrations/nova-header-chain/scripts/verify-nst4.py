#!/usr/bin/env python3
"""Offline verifier for a testnet4 Nova+SPV payment bundle (NST4).

NST4 = b"NST4" | vout u32 | four u32-length-prefixed parts:
  NHT4 proof (genesis-anchored chain to block B) | NHT4 proof (B to tip, may
  be empty) | Core MerkleBlock (gettxoutproof) | raw transaction.

Checks, in order, and refuses on the first failure:
 1. each NHT4 proof verifies with the pinned verifier executable and key
    (btc-header-fold verify-bundle --vk), as testnet4;
 2. the first proof starts at the testnet4 genesis anchor state;
 3. the second proof's start state is exactly the first proof's end state;
 4. the MerkleBlock header hashes to the first proof's end hash (block B),
    its branch reaches the header's merkle root and binds exactly the tx's
    txid; 64-byte transactions are refused;
 5. the output exists; value and script SHA-256 come from the tx bytes;
 6. optional --expect-txid/--expect-vout/--expect-value/--expect-script-sha256;
 7. optional --core-datadir/--core-port: Core's active chain has the proven
    block and tip hashes at their heights with equal chainwork, and
    gettxout reports the output (recorded as unspent_at_lookup, Core's view).
Prints a btc_nova_spv_payment_testnet4_v1 receipt; exit 1 on refusal.
"""
import argparse, base64, hashlib, json, os, struct, subprocess, sys, tempfile, urllib.request

GENESIS_ANCHOR = "9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c"
TN4_K5_VK = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24"


def refuse(msg):
    print(json.dumps({"statement": "btc_nova_spv_payment_testnet4_v1", "verified": False, "error": msg}))
    sys.exit(1)


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(b, i):
    n = b[i]
    if n < 0xFD:
        return n, i + 1
    w = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + w], "little"), i + 1 + w


def split(b):
    if len(b) > 30 * 1024 or b[:4] != b"NST4":
        refuse("not an NST4 bundle")
    vout = struct.unpack("<I", b[4:8])[0]
    parts, i = [], 8
    for _ in range(4):
        if i + 4 > len(b):
            refuse("truncated bundle")
        n = struct.unpack("<I", b[i:i + 4])[0]
        if i + 4 + n > len(b):
            refuse("truncated bundle")
        parts.append(b[i + 4:i + 4 + n])
        i += 4 + n
    if i != len(b):
        refuse("trailing bytes")
    return vout, parts


def merkle_match(mb):
    """Parse a MerkleBlock; return (header, [matched txids], root ok)."""
    header = mb[:80]
    n_tx = struct.unpack("<I", mb[80:84])[0]
    nh, i = varint(mb, 84)
    hashes = [mb[i + 32 * k:i + 32 * k + 32] for k in range(nh)]
    i += 32 * nh
    nf, i = varint(mb, i)
    flags = mb[i:i + nf]
    if i + nf != len(mb):
        refuse("MerkleBlock has trailing bytes")
    bits = [(flags[j // 8] >> (j % 8)) & 1 for j in range(8 * nf)]
    width = lambda h: (n_tx + (1 << h) - 1) >> h
    height = 0
    while width(height) > 1:
        height += 1
    st = {"b": 0, "h": 0}
    matches = []

    def walk(h, pos):
        f = bits[st["b"]]; st["b"] += 1
        if h == 0 or not f:
            x = hashes[st["h"]]; st["h"] += 1
            if h == 0 and f:
                matches.append(x)
            return x
        l = walk(h - 1, 2 * pos)
        if 2 * pos + 1 < width(h - 1):
            r = walk(h - 1, 2 * pos + 1)
            if r == l:
                refuse("duplicated Merkle node (CVE-2012-2459 shape)")
        else:
            r = l
        return dsha(l + r)

    root = walk(height, 0)
    if st["h"] != len(hashes) or (st["b"] + 7) // 8 != len(flags):
        refuse("MerkleBlock does not consume all hashes and flags")
    return header, matches, root == header[36:68]


def tx_outputs(tx):
    """txid (internal order) and outputs of a raw tx, any serialization."""
    i = 4
    segwit = tx[4] == 0 and tx[5] == 1
    if segwit:
        i = 6
    n_in, i = varint(tx, i)
    for _ in range(n_in):
        i += 36
        n, i = varint(tx, i)
        i += n + 4
    n_out, i = varint(tx, i)
    outs, body_end = [], None
    for _ in range(n_out):
        value = struct.unpack("<Q", tx[i:i + 8])[0]
        n, j = varint(tx, i + 8)
        outs.append((value, tx[j:j + n]))
        i = j + n
    body_end = i
    if segwit:
        for _ in range(n_in):
            items, i = varint(tx, i)
            for _ in range(items):
                n, i = varint(tx, i)
                i += n
    if i + 4 != len(tx):
        refuse("transaction does not parse to its length")
    stripped = tx[:4] + (tx[6:body_end] if segwit else tx[4:body_end]) + tx[-4:]
    return dsha(stripped), len(stripped), outs


def verify_proof(exe, vk, part, tag):
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{tag}.nht4") as f:
        f.write(part)
    out = subprocess.run([exe, "verify-bundle", f.name, "--vk", vk], capture_output=True, text=True)
    os.unlink(f.name)
    try:
        r = json.loads(out.stdout.strip().splitlines()[-1])
    except Exception:
        refuse(f"{tag}: verifier produced no receipt")
    if out.returncode != 0 or r.get("verified") is not True or r.get("network") != "testnet4":
        refuse(f"{tag}: proof rejected: {r.get('error')}")
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--verifier", required=True, help="pinned btc-header-fold executable")
    ap.add_argument("--vk", required=True)
    ap.add_argument("--expect-txid"); ap.add_argument("--expect-vout", type=int)
    ap.add_argument("--expect-value", type=int); ap.add_argument("--expect-script-sha256")
    ap.add_argument("--core-datadir"); ap.add_argument("--core-port", type=int)
    a = ap.parse_args()

    vk_sha = hashlib.sha256(open(a.vk, "rb").read()).hexdigest()
    if vk_sha != TN4_K5_VK:
        refuse("verifier key is not the pinned testnet4 k=5 key")
    vout, (p_block, p_tip, mb, tx) = split(open(a.bundle, "rb").read())
    if p_block[:4] != b"NHT4" or (p_tip and p_tip[:4] != b"NHT4"):
        refuse("proofs must be testnet4 NHT4 bundles")
    r1 = verify_proof(a.verifier, a.vk, p_block, "to_block")
    if r1["checkpoint_state_sha256"] != GENESIS_ANCHOR:
        refuse("first proof does not start at the testnet4 genesis anchor")
    r2 = None
    if p_tip:
        r2 = verify_proof(a.verifier, a.vk, p_tip, "to_tip")
        if r2["checkpoint_state_sha256"] != r1["end_state_sha256"]:
            refuse("second proof does not continue the first proof's end state")
    header, matches, root_ok = merkle_match(mb)
    if dsha(header)[::-1].hex() != r1["end"]["tip_hash"]:
        refuse("MerkleBlock header is not the proven block")
    if not root_ok:
        refuse("Merkle branch does not reach the header's root")
    txid, stripped_len, outs = tx_outputs(tx)
    if stripped_len == 64:
        refuse("64-byte transactions are refused")
    if matches != [txid]:
        refuse("Merkle branch does not bind exactly this transaction")
    if vout >= len(outs):
        refuse("output index out of range")
    value, script = outs[vout]
    txid_d, script_sha = txid[::-1].hex(), hashlib.sha256(script).hexdigest()
    for want, got, name in [(a.expect_txid, txid_d, "txid"), (a.expect_vout, vout, "vout"),
                            (a.expect_value, value, "value"), (a.expect_script_sha256, script_sha, "script")]:
        if want is not None and want != got:
            refuse(f"expected {name} differs")
    tip = (r2 or r1)["end"]
    receipt = {"statement": "btc_nova_spv_payment_testnet4_v1", "network": "testnet4", "verified": True,
               "anchor": "genesis/testnet4", "vk_sha256": vk_sha,
               "block": r1["end"], "tip": tip, "confirmations": tip["height"] - r1["end"]["height"] + 1,
               "txid": txid_d, "vout": vout, "value_sats": value, "script_sha256": script_sha,
               "proof_sha256": [r1["proof_sha256"], r2 and r2["proof_sha256"]]}
    if a.core_datadir:
        cookie = open(os.path.join(os.path.expanduser(a.core_datadir), "testnet4", ".cookie")).read().strip()
        auth = "Basic " + base64.b64encode(cookie.encode()).decode()

        def rpc(m, *p):
            req = urllib.request.Request(f"http://127.0.0.1:{a.core_port}", data=json.dumps(
                {"jsonrpc": "1.0", "id": 0, "method": m, "params": list(p)}).encode(),
                headers={"Authorization": auth, "Content-Type": "application/json"})
            return json.loads(urllib.request.urlopen(req, timeout=60).read())["result"]

        for point in [r1["end"], tip]:
            if rpc("getblockhash", point["height"]) != point["tip_hash"]:
                refuse(f"height {point['height']}: proven hash is not on Core's active chain")
            if int(rpc("getblockheader", point["tip_hash"])["chainwork"], 16) != int(point["chainwork"], 16):
                refuse(f"height {point['height']}: proven chainwork differs from Core")
        o = rpc("gettxout", txid_d, vout, True)
        if o is not None and (round(o["value"] * 1e8) != value or
                              hashlib.sha256(bytes.fromhex(o["scriptPubKey"]["hex"])).hexdigest() != script_sha):
            refuse("Core's unspent output differs from the proven one")
        receipt.update({"active_chain_at_lookup": True, "unspent_at_lookup": o is not None,
                        "unspent_source": "bitcoin_core_gettxout_including_mempool"})
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
