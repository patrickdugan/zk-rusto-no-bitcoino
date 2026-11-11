"""Independent pure-Python reference of the FC03 adjudicator (stdlib only).

Mirrors the semantics of the Rust crate fc03 (checker order included) but is written
independently. The "Claim" challenge kind needs Nova's Poseidon random oracle; this module
performs every check up to the fold equations and then returns SKIPPED_POSEIDON.
"""
from hashlib import sha256

from flatmerkle import Opening, verify as fm_verify

PROTOCOL = b"FLATCHECK/FC03/v1"
VERSION = 1
CHALLENGE_INVALID = "challenge_invalid"
CLAIM_INVALID = "claim_invalid"
RESPONSE_MISSING = "response_missing"
RESPONSE_INVALID = "response_invalid"
HOLDS = "holds"
VIOLATED = "violated"
SKIPPED_POSEIDON = "skipped_poseidon"

PALLAS_BASE = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001  # Fp
PALLAS_SCALAR = 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001  # Fq
# field byte -> (R1CS scalar modulus, coordinate base modulus)
MODULI = {1: (PALLAS_SCALAR, PALLAS_BASE), 2: (PALLAS_BASE, PALLAS_SCALAR)}

TAG_W, TAG_E, TAG_ROW, TAG_GEN, TAG_TRACE_W, TAG_TRACE_E, TAG_PAD = b"W", b"E", b"R", b"G", b"w", b"e", b"Z"
ROW_DOMAIN = b"FC03/row/v1"
TRACE_DOMAIN = b"FC03/trace/v1"
GEN_DOMAIN = b"FC03/gen/v1"
TRACE_RECORD_LEN = 13 + 1 + 1 + 4 + 65 + 65
GEN_RECORD_LEN = 11 + 1 + 4 + 65
U32 = 0xFFFFFFFF


# ---------------------------------------------------------------- encoding
class Enc:
    def __init__(self, kind: str):
        self.b = bytearray()
        self._frame(PROTOCOL)
        self._frame(kind.encode())

    def _frame(self, x: bytes):
        self.b += len(x).to_bytes(4, "big") + x

    def field(self, tag: str, v: bytes):
        self._frame(tag.encode())
        self._frame(bytes(v))
        return self

    def u8(self, tag, v):
        return self.field(tag, bytes([v]))

    def u32(self, tag, v):
        return self.field(tag, (v & U32).to_bytes(4, "big"))

    def u64(self, tag, v):
        return self.field(tag, v.to_bytes(8, "big"))

    def digest(self) -> bytes:
        return sha256(bytes(self.b)).digest()


def h(x: str) -> bytes:
    return bytes.fromhex(x)


def item(fid: int, tag: bytes, index: int, payload: bytes) -> bytes:
    return b"FC03" + bytes([fid]) + tag + b"\0\0" + index.to_bytes(4, "big") + payload + b"\0" * 20


def parse_item(it: bytes):
    """-> (field_id, tag, index, payload) or None unless every fixed byte is canonical."""
    if len(it) != 64 or it[:4] != b"FC03" or it[6] or it[7] or any(it[44:]):
        return None
    return it[4], it[5:6], int.from_bytes(it[8:12], "big"), it[12:44]


# ---------------------------------------------------------------- ids
def replay_digest(r) -> bytes:
    return Enc("replay-domain").field("network", r["network"].encode()).field("contract_id", h(r["contract_id"])).digest()


def tc_digest(tc) -> bytes:
    e = Enc("trusted-config")
    e.u32("version", VERSION).u8("field", tc["field"]).field("network", tc["network"].encode())
    e.field("shape_digest", h(tc["shape_digest"])).field("matrix_root", h(tc["matrix_root"]))
    e.u32("matrix_leaves", tc["matrix_leaves"]).u32("num_cons", tc["num_cons"]).u32("num_vars", tc["num_vars"]).u32("num_io", tc["num_io"])
    e.u32("k_a", tc["k"][0]).u32("k_b", tc["k"][1]).u32("k_c", tc["k"][2])
    e.u32("w_leaves", tc["w_leaves"]).u32("e_leaves", tc["e_leaves"]).u32("ck_len", tc["ck_len"])
    e.field("ck_root", h(tc["ck_root"])).u32("ck_leaves", tc["ck_leaves"])
    e.u32("trace_w_leaves", tc["trace_w_leaves"]).u32("trace_e_leaves", tc["trace_e_leaves"])
    e.field("pp_digest", h(tc["pp_digest"])).field("ro", tc["ro"].encode())
    return e.digest()


def _put_relaxed(e: Enc, ri, p: str):
    e.field(p + ".comm_W", h(ri["comm_w"])).field(p + ".comm_E", h(ri["comm_e"])).field(p + ".u", h(ri["u"]))
    e.u32(p + ".num_x", len(ri["x"]))
    for x in ri["x"]:
        e.field(p + ".x", h(x))


def folding_digest(f) -> bytes:
    e = Enc("folding")
    _put_relaxed(e, f["u1"], "U1")
    e.field("U2.comm_W", h(f["u2"]["comm_w"])).u32("U2.num_x", len(f["u2"]["x"]))
    for x in f["u2"]["x"]:
        e.field("U2.x", h(x))
    e.field("comm_T", h(f["comm_t"]))
    return e.digest()


def statement_digest(s) -> bytes:
    return Enc("statement").field("pp_digest", h(s["pp_digest"])).u64("steps", s["steps"]).field("app_digest", h(s["app_digest"])).digest()


def claim_id(c) -> bytes:
    e = Enc("claim")
    e.u32("version", c["version"]).field("tc_digest", h(c["tc_digest"])).u8("field", c["field"]).field("session_id", h(c["session_id"]))
    e.field("replay", replay_digest(c["replay"])).field("statement", statement_digest(c["statement"])).field("folding", folding_digest(c["folding"]))
    _put_relaxed(e, c["instance"], "U")
    e.field("root_W", h(c["root_w"])).field("root_E", h(c["root_e"])).field("root_trace_W", h(c["root_trace_w"])).field("root_trace_E", h(c["root_trace_e"]))
    return e.digest()


def kind_parts(kind):
    if kind == "Claim":
        return "Claim", {}
    (name, body), = kind.items()
    return name, body


def kind_code(kind):
    """-> (kind byte, index, vec byte) for a serde-style challenge kind."""
    name, body = kind_parts(kind)
    vec = ord(body["vec"]) if "vec" in body else 0
    if name == "Claim":
        return 5, 0, 0
    if name == "Row":
        return 1, body["row"], 0
    if name == "BindingStart":
        return 2, 0, vec
    if name == "BindingStep":
        return 3, body["step"], vec
    if name == "BindingEnd":
        return 4, 0, vec
    raise ValueError(name)


def challenge_id(ch) -> bytes:
    k, idx, v = kind_code(ch["kind"])
    e = Enc("challenge")
    e.u32("version", ch["version"]).field("claim_id", h(ch["claim_id"])).u8("kind", k).u32("index", idx).u8("vec", v)
    e.field("challenger", h(ch["challenger"])).field("nonce", h(ch["nonce"])).field("replay", replay_digest(ch["replay"]))
    return e.digest()


# ---------------------------------------------------------------- config helpers
def n_vec(tc, v):
    return tc["num_vars"] if v == "W" else tc["num_cons"]


def trace_steps(tc, v):
    return ((n_vec(tc, v) + 1) * 256) & U32


def trace_leaves(tc, v):
    return tc["trace_w_leaves" if v == "W" else "trace_e_leaves"]


def vec_leaves(tc, v):
    return tc["w_leaves" if v == "W" else "e_leaves"]


def row_record_len(k):
    return len(ROW_DOMAIN) + 1 + 4 + sum(4 + 36 * x for x in k)


def gen_index(n, ck_len, j):
    return ck_len if j == n else j


# ---------------------------------------------------------------- field / curve
def fe(b: bytes, mod: int):
    v = int.from_bytes(b, "little")
    return v if v < mod else None


def aff(b: bytes, mod: int):
    """65-byte point -> (x, y, inf) or None if non-canonical."""
    x, y = fe(b[1:33], mod), fe(b[33:65], mod)
    if x is None or y is None:
        return None
    if b[0] == 0:
        return (x, y, False)
    if b[0] == 1 and x == 0 and y == 0:
        return (x, y, True)
    return None


def to_proj(a, p):
    x, y, inf = a
    return (0, 1, 0) if inf else (x, y, 1)


def rcb_add(P, Q, p):
    """Renes-Costello-Batina 2016 Alg. 7, a = 0, b3 = 15 (step-for-step)."""
    b3 = 15
    x1, y1, z1 = P
    x2, y2, z2 = Q
    t0 = x1 * x2 % p
    t1 = y1 * y2 % p
    t2 = z1 * z2 % p
    t3 = (x1 + y1) % p
    t4 = (x2 + y2) % p
    t3 = t3 * t4 % p
    t4 = (t0 + t1) % p
    t3 = (t3 - t4) % p
    t4 = (y1 + z1) % p
    x3 = (y2 + z2) % p
    t4 = t4 * x3 % p
    x3 = (t1 + t2) % p
    t4 = (t4 - x3) % p
    x3 = (x1 + z1) % p
    y3 = (x2 + z2) % p
    x3 = x3 * y3 % p
    y3 = (t0 + t2) % p
    y3 = (x3 - y3) % p
    x3 = (t0 + t0) % p
    t0 = (x3 + t0) % p
    t2 = b3 * t2 % p
    z3 = (t1 + t2) % p
    t1 = (t1 - t2) % p
    y3 = b3 * y3 % p
    x3 = t4 * y3 % p
    t2 = t3 * t1 % p
    x3 = (t2 - x3) % p
    y3 = y3 * t0 % p
    t1 = t1 * z3 % p
    y3 = (t1 + y3) % p
    t0 = t0 * t3 % p
    z3 = z3 * t4 % p
    z3 = (z3 + t0) % p
    return (x3, y3, z3)


def proj_eq_aff(P, a, p):
    x, y, inf = a
    if inf:
        return P[2] == 0
    return P[2] != 0 and P[0] == x * P[2] % p and P[1] == y * P[2] % p


def on_curve(x, y, p):
    return (y * y - x * x * x - 5) % p == 0


def point_ok(b: bytes, p: int) -> bool:
    """Strict decode used by the claim public check (canonical, on curve y^2 = x^3 + 5)."""
    if b[0] == 1:
        return not any(b[1:])
    if b[0] == 0:
        x, y = fe(b[1:33], p), fe(b[33:65], p)
        return x is not None and y is not None and on_curve(x, y, p)
    return False


# ---------------------------------------------------------------- records
def parse_row_record(b: bytes, fid: int, k, n_cols: int, mod: int):
    if len(b) != row_record_len(k) or b[:11] != ROW_DOMAIN or b[11] != fid:
        return None
    row = int.from_bytes(b[12:16], "big")
    off = 16
    nnz, slots = [0] * 3, [[], [], []]
    for m in range(3):
        nnz[m] = int.from_bytes(b[off:off + 4], "big")
        off += 4
        if nnz[m] > k[m]:
            return None
        for j in range(k[m]):
            c = int.from_bytes(b[off:off + 4], "big")
            v = fe(b[off + 4:off + 36], mod)
            if v is None:
                return None
            if j >= nnz[m] and (c != 0 or v != 0):
                return None
            if c >= n_cols:
                return None
            slots[m].append((c, v))
            off += 36
    return row, nnz, slots


def parse_trace_record(b: bytes, fid: int, v: str):
    if len(b) != TRACE_RECORD_LEN or b[:13] != TRACE_DOMAIN or b[13] != fid or b[14] != ord(v):
        return None
    return int.from_bytes(b[15:19], "big"), b[19:84], b[84:149]


def parse_gen_record(b: bytes, fid: int):
    if len(b) != GEN_RECORD_LEN or b[:11] != GEN_DOMAIN or b[11] != fid:
        return None
    return int.from_bytes(b[12:16], "big"), b[16:81]


# ---------------------------------------------------------------- openings
def _opening(o) -> Opening:
    return Opening(o["index"], (h(o["pair"][0]), h(o["pair"][1])), tuple(h(r) for r in o["reveals"]))


def open_value(fid, tg: bytes, leaves, root: bytes, index, o):
    op = _opening(o)
    it = op.pair[op.index & 1]
    v = parse_item(it)
    if v is None:
        return None
    f, t, i, payload = v
    if f != fid or t != tg or i != index:
        return None
    return payload if fm_verify(leaves, root, index, it, op) else None


def open_record(fid, tg: bytes, leaves, root: bytes, index, r) -> bool:
    rec = h(r["record"])
    it = item(fid, tg, index, sha256(rec).digest())
    op = _opening(r["open"])
    return op.pair[op.index & 1] == it and fm_verify(leaves, root, index, it, op)


def _tag_of(v: str, trace: bool) -> bytes:
    return (TAG_TRACE_W if v == "W" else TAG_TRACE_E) if trace else (TAG_W if v == "W" else TAG_E)


# ---------------------------------------------------------------- checks
def _decode_state(fid, v, t, rec: bytes, p):
    r = parse_trace_record(rec, fid, v)
    if r is None:
        return "trace record malformed"
    tt, a, pt = r
    if tt != t:
        return f"trace record says step {tt}, sits at {t}"
    a, pt = aff(a, p), aff(pt, p)
    if a is None:
        return "trace accumulator not canonical"
    if pt is None:
        return "trace point not canonical"
    return a, pt


def _row_check(tc, claim, row, r, q, p):
    fid = tc["field"]
    inst = claim["instance"]
    u = fe(h(inst["u"]), q)
    if u is None:
        return CLAIM_INVALID
    if len(inst["x"]) != tc["num_io"]:
        return CLAIM_INVALID
    x = []
    for xb in inst["x"]:
        v = fe(h(xb), q)
        if v is None:
            return CLAIM_INVALID
        x.append(v)
    k = tc["k"]
    n_cols = tc["num_vars"] + 1 + tc["num_io"]
    rr = h(r["row_record"])
    if len(rr) != row_record_len(k):
        return RESPONSE_INVALID
    if not open_record(fid, TAG_ROW, tc["matrix_leaves"], h(tc["matrix_root"]), row, {"record": r["row_record"], "open": r["row_open"]}):
        return RESPONSE_INVALID
    rec = parse_row_record(rr, fid, k, n_cols, q)
    if rec is None:
        return RESPONSE_INVALID
    rrow, nnz, slots = rec
    if rrow != row:
        return RESPONSE_INVALID
    if len(r["terms"]) != sum(k):
        return RESPONSE_INVALID
    seen = {}
    prod = [0, 0, 0]
    slot = 0
    for m in range(3):
        for j in range(k[m]):
            col, coef = slots[m][j]
            active = j < nnz[m]
            o = r["terms"][slot]
            slot += 1
            if not active:
                continue
            if col < tc["num_vars"]:
                vb = open_value(fid, TAG_W, tc["w_leaves"], h(claim["root_w"]), col, o)
                if vb is None:
                    return RESPONSE_INVALID
                v = fe(vb, q)
                if v is None:
                    return VIOLATED
                if col in seen and seen[col] != v:
                    return RESPONSE_INVALID
                seen.setdefault(col, v)
                z = v
            elif col == tc["num_vars"]:
                z = u
            else:
                z = x[col - tc["num_vars"] - 1]
            prod[m] = (prod[m] + coef * z) % q
    eb = open_value(fid, TAG_E, tc["e_leaves"], h(claim["root_e"]), row, r["e_open"])
    if eb is None:
        return RESPONSE_INVALID
    e = fe(eb, q)
    if e is None:
        return VIOLATED
    return HOLDS if prod[0] * prod[1] % q == (u * prod[2] + e) % q else VIOLATED


def _step_check(tc, claim, v, step, r, q, p):
    fid = tc["field"]
    leaves = trace_leaves(tc, v)
    root = h(claim["root_trace_w" if v == "W" else "root_trace_e"])
    j, b = step // 256, step % 256
    n = n_vec(tc, v)
    tt = _tag_of(v, True)
    if not open_record(fid, tt, leaves, root, step, r["cur"]):
        return RESPONSE_INVALID
    if not open_record(fid, tt, leaves, root, step + 1, r["next"]):
        return RESPONSE_INVALID
    sb = open_value(fid, _tag_of(v, False), vec_leaves(tc, v), h(claim["root_w" if v == "W" else "root_e"]), j, r["scalar"])
    if sb is None:
        return RESPONSE_INVALID
    need_gen = b == 255 and j < n
    gi = gen_index(n, tc["ck_len"], j + 1)
    if need_gen and not open_record(fid, TAG_GEN, tc["ck_leaves"], h(tc["ck_root"]), gi, r["gen"]):
        return RESPONSE_INVALID
    s1 = _decode_state(fid, v, step, h(r["cur"]["record"]), p)
    if isinstance(s1, str):
        return VIOLATED
    s2 = _decode_state(fid, v, step + 1, h(r["next"]["record"]), p)
    if isinstance(s2, str):
        return VIOLATED
    (acc, pt), (acc2, p2) = s1, s2
    s = fe(sb, q)
    if s is None:
        return VIOLATED
    bit = (s >> b) & 1
    pa, pp = to_proj(acc, p), to_proj(pt, p)
    exp_acc = rcb_add(pa, pp, p) if bit else pa
    ok_acc = proj_eq_aff(exp_acc, acc2, p)
    if b < 255:
        ok_p = proj_eq_aff(rcb_add(pp, pp, p), p2, p)
    elif j < n:
        gr = parse_gen_record(h(r["gen"]["record"]), fid)
        if gr is None:
            return RESPONSE_INVALID
        ga = aff(gr[1], p)
        if ga is None:
            return RESPONSE_INVALID
        ok_p = gr[0] == gi and ga == p2
    else:
        ok_p = p2[2]
    return HOLDS if ok_acc and ok_p else VIOLATED


def _start_check(tc, claim, v, r, q, p):
    fid = tc["field"]
    root = h(claim["root_trace_w" if v == "W" else "root_trace_e"])
    if not open_record(fid, _tag_of(v, True), trace_leaves(tc, v), root, 0, r["first"]):
        return RESPONSE_INVALID
    if not open_record(fid, TAG_GEN, tc["ck_leaves"], h(tc["ck_root"]), 0, r["gen0"]):
        return RESPONSE_INVALID
    s = _decode_state(fid, v, 0, h(r["first"]["record"]), p)
    if isinstance(s, str):
        return VIOLATED
    acc, pt = s
    gr = parse_gen_record(h(r["gen0"]["record"]), fid)
    if gr is None or gr[0] != 0:
        return RESPONSE_INVALID
    ga = aff(gr[1], p)
    return HOLDS if ga is not None and acc[2] and ga == pt else VIOLATED


def _end_check(tc, claim, v, r, q, p):
    fid = tc["field"]
    last = trace_steps(tc, v)
    comm = h(claim["instance"]["comm_w" if v == "W" else "comm_e"])
    ca = aff(comm, p)
    if ca is None:
        return CLAIM_INVALID
    root = h(claim["root_trace_w" if v == "W" else "root_trace_e"])
    if not open_record(fid, _tag_of(v, True), trace_leaves(tc, v), root, last, r["last"]):
        return RESPONSE_INVALID
    s = _decode_state(fid, v, last, h(r["last"]["record"]), p)
    if isinstance(s, str):
        return VIOLATED
    return HOLDS if s[0] == ca else VIOLATED


def _claim_public_check(tc, c, q, p):
    """Everything before the Poseidon fold equations. None = all passed so far."""
    if c["replay"]["network"] != tc["network"]:
        return VIOLATED
    if c["statement"]["pp_digest"] != tc["pp_digest"]:
        return VIOLATED
    f = c["folding"]
    for pb in (f["u1"]["comm_w"], f["u1"]["comm_e"], f["u2"]["comm_w"], f["comm_t"], c["instance"]["comm_w"], c["instance"]["comm_e"]):
        if not point_ok(h(pb), p):
            return VIOLATED
    for ub in (f["u1"]["u"], c["instance"]["u"]):
        if fe(h(ub), q) is None:
            return VIOLATED
    for xs in (f["u1"]["x"], f["u2"]["x"], c["instance"]["x"]):
        if len(xs) != tc["num_io"] or any(fe(h(x), q) is None for x in xs):
            return VIOLATED
    if fe(h(c["statement"]["pp_digest"]), q) is None:
        return VIOLATED
    return None


def adjudicate(tc, claim, challenge, response):
    """-> (code, refutes)."""
    code = _adjudicate(tc, claim, challenge, response)
    return code, code not in (CHALLENGE_INVALID, HOLDS)


def _adjudicate(tc, claim, ch, resp):
    # challenge validity
    if ch["version"] != VERSION or ch["claim_id"] != claim_id(claim).hex() or replay_digest(ch["replay"]) != replay_digest(claim["replay"]):
        return CHALLENGE_INVALID
    name, body = kind_parts(ch["kind"])
    if name == "Row" and body["row"] >= tc["num_cons"]:
        return CHALLENGE_INVALID
    if name == "BindingStep" and body["step"] >= trace_steps(tc, body["vec"]):
        return CHALLENGE_INVALID
    if claim["version"] != VERSION:
        return CLAIM_INVALID
    if h(claim["tc_digest"]) != tc_digest(tc):
        return CLAIM_INVALID
    if claim["field"] != tc["field"] or claim["field"] not in MODULI:
        return CLAIM_INVALID
    q, p = MODULI[tc["field"]]
    if name == "Claim":
        res = _claim_public_check(tc, claim, q, p)
        return res if res is not None else SKIPPED_POSEIDON
    if resp is None:
        return RESPONSE_MISSING
    (rname, rbody), = resp.items()
    if h(rbody["challenge_id"]) != challenge_id(ch):
        return RESPONSE_INVALID
    if name == "Row" and rname == "Row":
        return _row_check(tc, claim, body["row"], rbody, q, p)
    if name == "BindingStep" and rname == "Step":
        return _step_check(tc, claim, body["vec"], body["step"], rbody, q, p)
    if name == "BindingStart" and rname == "Start":
        return _start_check(tc, claim, body["vec"], rbody, q, p)
    if name == "BindingEnd" and rname == "End":
        return _end_check(tc, claim, body["vec"], rbody, q, p)
    return RESPONSE_INVALID
