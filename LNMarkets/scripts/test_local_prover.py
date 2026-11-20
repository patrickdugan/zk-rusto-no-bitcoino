"""Cheap runner boundary tests. These never require SP1 or run a prover."""

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("local_prover", Path(__file__).with_name("local_prover.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class LocalProverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.elf = self.root / "guest.elf"
        self.elf.write_bytes(b"\x7fELFsynthetic-test-only")
        self.witness = self.root / "witness.bin"
        self.witness.write_bytes(b"synthetic-test-only")
        self.journal = self.root / "journal.bin"
        self.journal.write_bytes(b"synthetic-journal")
        self.host = self.root / "host"
        self.host.write_text("#!/bin/sh\nexit 99\n")
        self.host.chmod(0o700)
        self.work = self.root / "outputs"

    def args(self, action="execute"):
        return [
            action, "--work-dir", str(self.work), "--host", str(self.host),
            "--elf", str(self.elf), "--witness", str(self.witness), "--journal", str(self.journal),
            "--elf-sha256", hashlib.sha256(self.elf.read_bytes()).hexdigest(),
            "--program-vk", "ab" * 32,
            "--journal-sha256", hashlib.sha256(self.journal.read_bytes()).hexdigest(),
        ]

    def quiet_main(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return runner.main(args)

    def test_default_and_dry_run_never_spawn_or_write(self):
        with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("spawned")):
            self.assertEqual(self.quiet_main([]), 0)
            self.assertEqual(self.quiet_main(self.args("groth16") + ["--dry-run"]), 0)
        self.assertFalse(self.work.exists())

    def test_explicit_action_without_run_is_read_only(self):
        with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("spawned")):
            self.assertEqual(self.quiet_main(self.args()), 0)
        self.assertFalse(self.work.exists())

    def test_wrong_elf_or_journal_pin_blocks_before_spawn(self):
        for flag in ("--elf-sha256", "--journal-sha256"):
            args = self.args()
            args[args.index(flag) + 1] = "00" * 32
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("spawned")):
                self.assertEqual(self.quiet_main(args + ["--run"]), 2)
        self.assertFalse(self.work.exists())

    def test_missing_or_malformed_program_pin_blocks(self):
        args = self.args()
        args[args.index("--program-vk") + 1] = "true"
        plan = runner.make_plan(runner.parser().parse_args(args))
        self.assertFalse(plan["ready"])
        self.assertTrue(any("32 hex bytes" in b for b in plan["blockers"]))

    def test_witness_cap_checked_before_spawn(self):
        with self.witness.open("wb") as file:
            file.truncate(runner.MAX_WITNESS_BYTES + 1)
        with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("spawned")):
            self.assertEqual(self.quiet_main(self.args() + ["--run"]), 2)

    def test_outputs_are_preserved(self):
        self.work.mkdir()
        output = self.work / "execution.json"
        output.write_text("previous evidence")
        plan = runner.make_plan(runner.parser().parse_args(self.args()))
        self.assertFalse(plan["ready"])
        self.assertEqual(output.read_text(), "previous evidence")

    def test_compressed_plan_uses_pinned_preexecute_then_real_verify(self):
        args = self.args("compressed") + ["--nb3-prove", str(self.host)]
        plan = runner.make_plan(runner.parser().parse_args(args))
        self.assertTrue(plan["ready"])
        self.assertEqual([c["argv"][1] for c in plan["commands"]], ["execute", "prove", "verify-proof"])
        self.assertIn("--expect-public-sha256", plan["commands"][1]["argv"])
        self.assertIn("--expect-program-vk", plan["commands"][2]["argv"])
        self.assertFalse(plan["zero_knowledge_proof_verified"])

    def test_verifier_needs_no_private_witness(self):
        args = self.args("verify")
        index = args.index("--witness")
        del args[index:index + 2]
        proof = self.root / "proof.bin"
        proof.write_bytes(b"synthetic-proof-for-plan-only")
        args += ["--proof", str(proof), "--mode", "groth16"]
        plan = runner.make_plan(runner.parser().parse_args(args))
        self.assertTrue(plan["ready"])
        self.assertNotIn("--witness", plan["commands"][0]["argv"])

    def test_lock_preflight_rejects_transitive_version_drift(self):
        lock = self.root / "Cargo.lock"
        lock.write_text('[[package]]\nname="sp1-sdk"\nversion="6.9.0"\n[[package]]\nname="sp1-prover"\nversion="6.10.0"\n')
        with self.assertRaisesRegex(ValueError, "dependency drift"):
            runner.check_sp1_lock(lock)
        lock.write_text('[[package]]\nname="sp1-sdk"\nversion="6.9.0"\n[[package]]\nname="sp1-prover"\nversion="6.9.0"\n')
        self.assertEqual(runner.check_sp1_lock(lock), 2)

    def test_development_circuit_mode_blocks_run(self):
        with mock.patch.dict(runner.os.environ, {"SP1_CIRCUIT_MODE": "dev"}):
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("spawned")):
                self.assertEqual(self.quiet_main(self.args("groth16") + ["--run"]), 2)
        self.assertFalse(self.work.exists())

    def test_subprocess_environment_clears_private_dump_controls(self):
        debug = {key: "test-only-debug-setting" for key in runner.PRIVATE_DUMP_ENV}
        with mock.patch.dict(runner.os.environ, debug):
            with mock.patch.object(runner.subprocess, "run") as spawn:
                self.assertEqual(self.quiet_main(self.args() + ["--run"]), 0)
        self.assertEqual(spawn.call_count, 1)
        environment = spawn.call_args.kwargs["env"]
        self.assertEqual(environment["SP1_CIRCUIT_MODE"], "release")
        self.assertEqual(environment["SP1_PROVER"], "cpu")
        for variable in runner.PRIVATE_DUMP_ENV:
            self.assertNotIn(variable, environment)


if __name__ == "__main__":
    unittest.main()
