#!/usr/bin/env python3
"""Bitcoin Core's script vectors as JSON lines for `nova-script vectors`, reusing the case builder
of the Shinigami fork (scripts/core_vectors/vectors.py) with raw hex in place of Cairo felts.

    export_vectors.py SHINIGAMI_DIR script_tests.json script_assets_test.json OUT.jsonl
"""
import importlib.util
import json
import sys

shinigami, st_path, assets_path, out_path = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("vectors", f"{shinigami}/scripts/core_vectors/vectors.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def raw_args(transaction, prevouts, index, flags):
    return {"tx": transaction.hex(), "prevouts": [[a, s.hex()] for a, s in prevouts], "index": index, "flag_bits": flags}


v.case_args = raw_args
n = 0
with open(out_path, "w") as out:
    for case in list(v.script_tests(st_path)) + list(v.script_assets(assets_path)):
        case.update(case.pop("args"))
        out.write(json.dumps(case) + "\n")
        n += 1
print(f"wrote {n} cases to {out_path}")
