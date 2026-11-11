"""Add the Python reference's verdict to each row of results/fc03_cases.json (written by
`fc03 cases`), so every adversarial case carries expected / native / circuit / Python results.

    python3 fc03_case_table.py
"""
import json
import os
import sys

import fc03_ref as R

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    vec = json.load(open(os.path.join(HERE, "fixtures", "fc03_vectors.json")))
    path = os.path.join(HERE, "results", "fc03_cases.json")
    table = json.load(open(path))
    by_name = {c["name"]: c for c in vec["cases"]}
    disagree = 0
    for row in table["cases"]:
        c = by_name[row["name"]]
        claim = vec["claims"][c["claim_id"]]
        tc = vec["configs"][c["tc_field"]]
        code, refutes = R.adjudicate(tc, claim, c["challenge"], c["response"])
        row["python"] = code
        row["python_refutes"] = None if code == "skipped_poseidon" else refutes
        for k in ("native", "python"):
            if row[k] != "skipped_poseidon" and row[k] != row["expected"]:
                disagree += 1
        if row["circuit_refutes"] is not None and row["circuit_refutes"] != row["expected_refutes"]:
            disagree += 1
    with open(path, "w", newline="\n") as f:
        f.write(json.dumps(table, indent=2) + "\n")
    n = len(table["cases"])
    print(f"cases={n} circuit_decided={sum(r['circuit_refutes'] is not None for r in table['cases'])} "
          f"python_skipped={sum(r['python'] == 'skipped_poseidon' for r in table['cases'])} disagreements={disagree}")
    return 1 if disagree else 0


if __name__ == "__main__":
    sys.exit(main())
