"""Differential test: pure-Python FC03 reference vs frozen vectors from the Rust adjudicator."""
import json
import sys
import time
import unittest
from pathlib import Path

import fc03_ref as R

FIX = Path(__file__).parent / "fixtures" / "fc03_vectors.json"
DATA = json.loads(FIX.read_text())


class Differential(unittest.TestCase):
    def test_all_cases(self):
        t0 = time.time()
        cases = DATA["cases"]
        compared = matched = skipped = 0
        mism = []
        for c in cases:
            tc = DATA["configs"][c["tc_field"]]
            claim = DATA["claims"][c["claim_id"]]
            self.assertEqual(R.claim_id(claim).hex(), c["claim_id"], c["name"])
            code, refutes = R.adjudicate(tc, claim, c["challenge"], c["response"])
            if code == R.SKIPPED_POSEIDON:
                skipped += 1
                continue
            compared += 1
            exp = (c["expected"], c["expected_refutes"])
            if (code, refutes) == exp:
                matched += 1
            else:
                mism.append(f"{c['name']}: python={(code, refutes)} rust={exp}")
        print(f"FC03-PY cases={len(cases)} compared={compared} matched={matched} skipped_poseidon={skipped}", file=sys.stderr)
        self.assertLess(time.time() - t0, 60)
        self.assertFalse(mism, "mismatches:\n" + "\n".join(mism))

    def test_moduli_match_fixture(self):
        for name, fid in (("PallasScalar", 1), ("VestaScalar", 2)):
            q, p = R.MODULI[fid]
            self.assertEqual((q, p), (int(DATA["moduli"][name]["scalar"], 16), int(DATA["moduli"][name]["base"], 16)))

    def test_enc_framing(self):
        a = R.Enc("k").field("ab", b"c")
        b = R.Enc("k").field("a", b"bc")
        self.assertNotEqual(bytes(a.b), bytes(b.b))
        self.assertEqual(bytes(a.b)[:4], len(R.PROTOCOL).to_bytes(4, "big"))
        self.assertTrue(bytes(R.Enc("k").u32("x", 7).b).endswith(b"\x00\x00\x00\x04\x00\x00\x00\x07"))

    def test_item_strictness(self):
        it = R.item(1, b"W", 7, bytes([9]) * 32)
        self.assertEqual(R.parse_item(it), (1, b"W", 7, bytes([9]) * 32))
        for pos in (63, 6, 7, 44, 0):
            bad = bytearray(it)
            bad[pos] ^= 1
            self.assertIsNone(R.parse_item(bytes(bad)), pos)
        self.assertIsNone(R.parse_item(it[:63]))

    def test_rcb_doubling_matches_affine(self):
        for name, fid in (("PallasScalar", 1), ("VestaScalar", 2)):
            p = R.MODULI[fid][1]
            found = None
            for c in DATA["cases"]:
                if c["tc_field"] != name or not isinstance(c["response"], dict):
                    continue
                for body in c["response"].values():
                    for key in ("gen", "gen0"):
                        if key in body:
                            found = R.parse_gen_record(bytes.fromhex(body[key]["record"]), fid)
                            if found:
                                break
                    if found:
                        break
                if found:
                    break
            self.assertIsNotNone(found)
            x, y, inf = R.aff(found[1], p)
            self.assertFalse(inf)
            self.assertTrue(R.on_curve(x, y, p))
            lam = 3 * x * x * pow(2 * y, -1, p) % p
            x3 = (lam * lam - 2 * x) % p
            y3 = (lam * (x - x3) - y) % p
            P = R.to_proj((x, y, False), p)
            self.assertTrue(R.proj_eq_aff(R.rcb_add(P, P, p), (x3, y3, False), p))
            neg = (x, (-y) % p, 1)
            self.assertEqual(R.rcb_add(P, neg, p)[2], 0)
            self.assertTrue(R.proj_eq_aff(R.rcb_add(P, (0, 1, 0), p), (x, y, False), p))


if __name__ == "__main__":
    unittest.main()
