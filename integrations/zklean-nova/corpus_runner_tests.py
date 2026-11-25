#!/usr/bin/env python3
"""Process/provenance regression tests; these are excluded from corpus metrics."""
from __future__ import annotations

import hashlib
import json
import os
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import corpus_collect
import corpus_owned_export


class CorpusRunnerTests(unittest.TestCase):
    def fake_compiler(self, root: Path) -> Path:
        compiler = root / "compiler"
        compiler.write_text(
            f"#!{sys.executable}\n"
            "import pathlib,sys\n"
            "if '--version' in sys.argv:\n"
            "    print('isolated runner test compiler')\n"
            "else:\n"
            "    output=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n"
            "    output.parent.mkdir(parents=True,exist_ok=True)\n"
            "    output.write_bytes(b'test object')\n"
        )
        compiler.chmod(0o755)
        return compiler

    def test_cached_fetch_checks_exact_git_blob(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b"cached source integrity test\n"
            repo = {"repository": "TestOwner/TestRepo", "commit": "0" * 40}
            item = {"path": "Example.lean", "kind": "lean_source", "bytes": len(data),
                    "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
            source = root / "sources" / repo["repository"] / item["path"]
            source.parent.mkdir(parents=True)
            source.write_bytes(data)
            good = corpus_collect.fetch_one(root, repo, item, 1024)
            self.assertEqual(good["fetch_status"], "verified")
            self.assertEqual(good["sha256"], corpus_collect.digest(data))
            source.write_bytes(data.replace(b"cached", b"forged"))
            bad = corpus_collect.fetch_one(root, repo, item, 1024)
            self.assertEqual(bad["fetch_status"], "fetch_failed")

    def test_changed_source_is_refused_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = self.fake_compiler(root)
            source = root / "Changed.lean"
            source.write_bytes(b"changed bytes\n")
            output = root / "objects" / "Changed.olean"
            entry = {"repository": "TestOwner/TestRepo", "path": "Changed.lean",
                     "fetch_status": "verified", "sha256": corpus_collect.digest(b"original bytes\n"),
                     "source_path": str(source), "object_path": str(output),
                     "project_root": str(root), "search_paths": [str(output.parent)]}
            result = corpus_collect.compile_one(entry, str(compiler), root, 10)
            self.assertNotEqual(result["build_status"], "compiled")
            self.assertFalse(output.exists())

    def test_fetch_inventory_exact_join_and_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payloads = {"Small.lean": b"small", "lean-toolchain": b"release", "Large.lean": b"x" * 33}
            items = [{"path": name, "kind": "project_metadata" if name == "lean-toolchain" else "lean_source",
                      "bytes": len(data), "git_blob_sha1": hashlib.sha1(
                          b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
                     for name, data in payloads.items()]
            repo = {"repository": "TestOwner/TestRepo", "commit": "0" * 40,
                    "visibility": "public", "files": items}
            manifest = {"selection": {"max_source_bytes": 8}, "repositories": [repo,
                {"repository": "TestOwner/EmptyRepo", "commit": "1" * 40,
                 "visibility": "public", "files": []},
                {"repository": "TestOwner/PrivateRepo", "visibility": "private", "files": []}]}
            for name in ("Small.lean", "lean-toolchain"):
                local = root / "sources" / repo["repository"] / name
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(payloads[name])
            rows = [corpus_collect.fetch_one(root, repo, item, 8) for item in items]
            result = corpus_collect.validate_fetch_inventory(manifest, rows, root)
            self.assertEqual(result["public_repositories"], 2)
            self.assertEqual(result["expected_files"], 3)
            self.assertEqual(result["expected_source_files"], 2)
            self.assertEqual(result["verified_files"], 2)
            self.assertEqual(result["verified_byte_checks"], 2)
            self.assertEqual(result["excluded_oversized_sources"], 1)
            self.assertTrue(result["all_fetchable_verified"])

            mutations = {"missing": copy.deepcopy(rows[:-1]), "duplicate": copy.deepcopy(rows + rows[:1])}
            extra = copy.deepcopy(rows[0])
            extra["path"] = "Unselected.lean"
            mutations["extra"] = copy.deepcopy(rows) + [extra]
            for field, value in (("commit", "2" * 40), ("kind", "project_metadata"),
                                 ("git_blob_sha1", "3" * 40), ("bytes", 6), ("bytes", True)):
                changed = copy.deepcopy(rows)
                changed[0][field] = value
                mutations[f"metadata_{field}_{value}"] = changed
            oversize = copy.deepcopy(rows)
            oversize[2]["fetch_status"] = "verified"
            mutations["oversized_admitted"] = oversize
            excluded = copy.deepcopy(rows)
            excluded[0]["fetch_status"] = "source_budget_exceeded"
            mutations["eligible_excluded"] = excluded
            for name, changed in mutations.items():
                with self.subTest(name=name), self.assertRaises(ValueError):
                    corpus_collect.validate_fetch_inventory(manifest, changed, root)

            failed = copy.deepcopy(rows)
            failed[0].update(fetch_status="fetch_failed", error="recorded network failure")
            failed[0].pop("sha256")
            failed[0].pop("local_path")
            failure_counts = corpus_collect.validate_fetch_inventory(manifest, failed, root)
            self.assertEqual(failure_counts["expected_files"], 3)
            self.assertEqual(failure_counts["fetch_failed_files"], 1)
            self.assertFalse(failure_counts["all_fetchable_verified"])
            (root / "sources" / repo["repository"] / "Small.lean").write_bytes(b"other")
            with self.assertRaises(ValueError):
                corpus_collect.validate_fetch_inventory(manifest, rows, root)

    def test_build_clears_objects_outside_the_new_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = self.fake_compiler(root)
            work = root / "work"
            work.mkdir()
            item = {"path": "Budget.lean", "kind": "lean_source", "bytes": 2,
                    "git_blob_sha1": "0" * 40}
            repo = {"repository": "TestOwner/TestRepo", "commit": "0" * 40,
                    "visibility": "public", "files": [item]}
            manifest = {"selection": {"max_source_bytes": 1, "per_file_timeout_seconds": 10},
                        "repositories": [repo]}
            manifest_file = root / "manifest.json"
            manifest_file.write_text(json.dumps(manifest))
            fetched = {**item, "repository": repo["repository"], "commit": repo["commit"],
                       "fetch_status": "source_budget_exceeded"}
            (work / "fetch_receipt.json").write_text(json.dumps({
                "manifest_sha256": corpus_collect.digest(manifest_file.read_bytes()), "files": [fetched]}))
            stale = work / "objects" / "TestOwner" / "TestRepo" / "StaleDependency.olean"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale object outside current selected files")
            run = subprocess.run([sys.executable, str(Path(corpus_collect.__file__).resolve()),
                                  "--phase", "build", "--manifest", str(manifest_file),
                                  "--work-dir", str(work), "--lean", str(compiler),
                                  "--build-workers", "1"], capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertFalse(stale.exists())
            receipt = json.loads((work / "build_receipt.json").read_text())
            self.assertEqual(receipt["source_file_denominator"], 1)
            self.assertEqual(receipt["files"][0]["build_status"], "source_budget_exceeded")

    def test_fast_process_cannot_skip_output_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [sys.executable, "-c",
                       "from pathlib import Path; Path('large.bin').write_bytes(b'x' * 1048576)"]
            result = corpus_owned_export.run_bounded(command, root, os.environ.copy(),
                        root / "process.log", 10, root, 1024)
            self.assertTrue(result["output_limit"], result)


if __name__ == "__main__":
    unittest.main()
