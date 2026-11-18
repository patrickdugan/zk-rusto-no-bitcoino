#!/usr/bin/env python3
"""Fast provenance rejection tests using temporary repositories and inert binaries."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("run-regtest.py")
SPEC = importlib.util.spec_from_file_location("core_provenance_runner", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class CoreProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="babe-core-provenance-")
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name).resolve() / "source"
        self.source.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Provenance Test")
        self.git("config", "user.email", "provenance@example.invalid")
        (self.source / ".gitignore").write_text("/build/\n*.ignored\n")
        (self.source / "CMakeLists.txt").write_text("# inert tracked source\n")
        self.git("add", ".")
        self.git("commit", "-qm", "temporary provenance fixture")
        self.git("remote", "add", "origin", runner.CORE_SOURCE_URL)
        self.commit = self.git("rev-parse", "HEAD").strip()
        # The production runner has no pin override argument or environment hook.
        pin = mock.patch.object(runner, "CORE_SOURCE_COMMIT", self.commit)
        pin.start()
        self.addCleanup(pin.stop)
        self.build = self.source / "build"
        self.binaries = self.build / "bin"
        self.binaries.mkdir(parents=True)
        for name in ("bitcoind", "bitcoin-cli"):
            binary = self.binaries / name
            binary.write_text(f"#!/bin/sh\nprintf '%s\\n' 'Bitcoin Core {name} version {runner.CORE_VERSION}'\n")
            binary.chmod(0o755)
        self.cache = {
            "CMAKE_HOME_DIRECTORY": str(self.source),
            "CMAKE_CACHEFILE_DIR": str(self.build),
            "CMAKE_CXX_COMPILER": "/usr/bin/c++",
            "CMAKE_C_FLAGS": "", "CMAKE_CXX_FLAGS": "",
            "CMAKE_C_FLAGS_RELEASE": "-O3 -DNDEBUG",
            **runner.CORE_BUILD_PROFILE,
        }
        self.info = {
            "schema": runner.CORE_BUILD_SCHEMA,
            "configure_argv": ["cmake", "-S", str(self.source), "-B", str(self.build)] +
                              [f"-D{key}={value}" for key, value in runner.CORE_BUILD_PROFILE.items()],
            "build_argv": ["cmake", "--build", str(self.build), "--target", "bitcoind", "bitcoin-cli", "--parallel", "4"],
            "compiler_version": "inert test compiler; no Core source compilation performed\n",
        }
        self.write_cache()
        self.write_info()
        self.args = types.SimpleNamespace(bitcoin_bin=self.binaries, core_source=self.source, core_archive=None)

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.source), *arguments],
                              capture_output=True, text=True, check=True, timeout=10).stdout

    def write_cache(self):
        (self.build / "CMakeCache.txt").write_text("".join(f"{key}:STRING={value}\n" for key, value in self.cache.items()))

    def write_info(self):
        (self.build / "build-info.json").write_text(json.dumps(self.info))

    def rejected(self, args=None, expected=None):
        with self.assertRaises((AssertionError, OSError, ValueError, subprocess.CalledProcessError)):
            runner.verify_core(args or self.args, expected=expected)

    def test_valid_source_receipt_has_exact_pins_and_artifact_hashes(self):
        receipt = runner.verify_core(self.args)
        self.assertEqual(receipt["evidence_kind"], "trusted-ci-source-build")
        self.assertEqual(receipt["source_commit"], self.commit)
        self.assertEqual(receipt["source_tree"], self.git("rev-parse", "HEAD^{tree}").strip())
        self.assertEqual(receipt["source_git_url"], runner.CORE_SOURCE_URL)
        self.assertEqual(receipt["tracked_source_files"], 2)
        self.assertEqual(receipt["bitcoind_sha256"], runner.digest(self.binaries / "bitcoind"))
        self.assertEqual(receipt["bitcoin_cli_sha256"], runner.digest(self.binaries / "bitcoin-cli"))
        self.assertEqual(receipt["cmake_cache_sha256"], runner.digest(self.build / "CMakeCache.txt"))
        self.assertEqual(receipt["build_info_sha256"], runner.digest(self.build / "build-info.json"))
        self.assertIn("do not prove", receipt["trust_basis"])
        self.assertEqual(runner.verify_core(self.args, expected=receipt), receipt)

    def test_wrong_commit_and_origin_fail_before_executing_a_binary(self):
        binary = self.binaries / "bitcoind"
        marker = self.build / "executed"
        binary.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        with mock.patch.object(runner, "CORE_SOURCE_COMMIT", "0" * 40):
            self.rejected()
        self.git("remote", "set-url", "origin", "https://example.invalid/bitcoin.git")
        self.rejected()
        self.assertFalse(marker.exists())

    def test_dirty_tracked_or_staged_source_is_rejected(self):
        (self.source / "CMakeLists.txt").write_text("changed tracked source\n")
        self.rejected()
        self.git("add", "CMakeLists.txt")
        self.rejected()

    def test_assume_unchanged_cannot_hide_changed_source_bytes(self):
        self.git("update-index", "--assume-unchanged", "CMakeLists.txt")
        (self.source / "CMakeLists.txt").write_text("hidden source change\n")
        self.assertEqual(self.git("status", "--porcelain=v1", "--untracked-files=no"), "")
        self.rejected()

    def test_untracked_and_ignored_files_outside_build_are_rejected(self):
        for name in ("extra.cpp", "extra.ignored"):
            with self.subTest(name=name):
                path = self.source / name
                path.write_text("unexpected source\n")
                self.rejected()
                path.unlink()
        runner.verify_core(self.args)

    def test_binary_directory_file_type_and_execute_mode_are_checked(self):
        args = copy.copy(self.args)
        args.bitcoin_bin = self.source
        self.rejected(args)
        binary = self.binaries / "bitcoind"
        binary.chmod(0o644)
        self.rejected()
        binary.unlink()
        binary.symlink_to(self.binaries / "bitcoin-cli")
        self.rejected()

    def test_build_directory_symlinks_are_rejected(self):
        moved = self.source.parent / "another-build"
        self.build.rename(moved)
        self.build.symlink_to(moved, target_is_directory=True)
        self.rejected()

    def test_cache_paths_profile_and_active_debug_flags_are_checked(self):
        original = dict(self.cache)
        for key, value in (("CMAKE_HOME_DIRECTORY", "/another/source"),
                           ("CMAKE_BUILD_TYPE", "Debug"), ("ENABLE_WALLET", "OFF"),
                           ("ENABLE_IPC", "ON"), ("CMAKE_CXX_FLAGS", "-g"),
                           ("CMAKE_CXX_FLAGS_RELEASE", "-O2 -DNDEBUG -g")):
            with self.subTest(key=key):
                self.cache = {**original, key:value}
                self.write_cache()
                self.rejected()

    def test_malformed_or_ambiguous_build_metadata_is_rejected(self):
        original = copy.deepcopy(self.info)
        mutations = (
            lambda info: info.update(schema="unknown"),
            lambda info: info.update(configure_argv="cmake shell text"),
            lambda info: info["configure_argv"].extend(["-DENABLE_WALLET=ON"]),
            lambda info: info["configure_argv"].__setitem__(2, "/another/source"),
            lambda info: info["build_argv"].__setitem__(5, "all"),
            lambda info: info["build_argv"].__setitem__(7, "0"),
            lambda info: info.update(compiler_version=""),
        )
        for index, change in enumerate(mutations):
            with self.subTest(mutation=index):
                self.info = copy.deepcopy(original)
                change(self.info)
                self.write_info()
                self.rejected()
        (self.build / "build-info.json").write_text('{"schema":"a","schema":"b"}')
        self.rejected()
        (self.build / "build-info.json").write_bytes(b" " * (256 * 1024 + 1))
        self.rejected()

    def test_postflight_rejects_each_changed_executable_before_execution(self):
        before = runner.verify_core(self.args)
        for name in ("bitcoind", "bitcoin-cli"):
            binary = self.binaries / name
            original = binary.read_bytes()
            marker = self.build / (name + ".executed")
            binary.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
            self.rejected(expected=before)
            self.assertFalse(marker.exists())
            binary.write_bytes(original)

    def test_postflight_rejects_changed_source_cache_and_build_description(self):
        before = runner.verify_core(self.args)
        self.info["compiler_version"] = "a different reported compiler"
        self.write_info()
        self.rejected(expected=before)
        self.info["compiler_version"] = before["compiler_version"]
        self.write_info()
        with (self.build / "CMakeCache.txt").open("a") as cache:
            cache.write("# changed cache bytes\n")
        self.rejected(expected=before)
        self.write_cache()
        (self.source / "CMakeLists.txt").write_text("changed after preflight\n")
        self.rejected(expected=before)

    def test_archive_mode_keeps_the_release_hash_and_both_member_checks(self):
        archive = self.source.parent / "core.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name in ("bitcoind", "bitcoin-cli"):
                payload = (self.binaries / name).read_bytes()
                member = tarfile.TarInfo("bitcoin-31.1/bin/" + name)
                member.size = len(payload)
                output.addfile(member, io.BytesIO(payload))
        args = types.SimpleNamespace(bitcoin_bin=self.binaries, core_source=None, core_archive=archive)
        with mock.patch.object(runner, "CORE_ARCHIVE_SHA256", runner.digest(archive)):
            receipt = runner.verify_core(args)
            self.assertEqual(receipt["evidence_kind"], "official-release-archive")
            (self.binaries / "bitcoin-cli").write_bytes(b"changed release member")
            self.rejected(args)
            with archive.open("ab") as output:
                output.write(b"changed archive")
            self.rejected(args)

    def test_provenance_modes_are_mutually_exclusive(self):
        args = copy.copy(self.args)
        args.core_archive = self.source / "unused.tar.gz"
        self.rejected(args)
        args.core_source = args.core_archive = None
        self.rejected(args)
        parsed = subprocess.run([sys.executable, str(SCRIPT), "--bitcoin-bin", ".",
                                 "--core-source", ".", "--core-archive", "unused.tar.gz"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(parsed.returncode, 2)
        self.assertIn("not allowed with", parsed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
