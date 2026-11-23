"""Regressions for stale liveness and proof-receipt binding, without a prover."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("live_probe", Path(__file__).parents[1] / "src/live_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_stale_active_status_is_not_a_live_process(self):
        with patch.object(probe, "command", return_value="ActiveState=active\nMainPID=999999999\n"):
            job = probe.inspect_unit("old-proof.service", "/root/build/s3o/prove-clean")
        self.assertFalse(job["running"])
        self.assertIsNone(job["process"])

    def test_recognizes_only_live_nova_commands_and_deduplicates_configured_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            programs = {}

            def process(pid, exe, command, state="R"):
                proc = root / str(pid)
                proc.mkdir()
                programs[str(pid)] = "/var/tmp/bin/" + exe
                fields = ["0"] * 22
                fields[0], fields[11], fields[12], fields[19], fields[21] = state, "230", "70", "1234", "7"
                (proc / "stat").write_text(f"{pid} ({exe}) " + " ".join(fields))
                (proc / "cgroup").write_text("0::/system.slice/fixture.service\n")
                (proc / "cmdline").write_bytes(b"\0".join([exe.encode(), command, b"private-path", b""]))

            process(17, "shz", b"mnr04-route-prove")
            process(18, "shz", b"mnr04-route-prove", "Z")
            process(19, "shz", b"mnr04-oracle-external")
            process(20, "unrelated", b"mnr04-route-prove")
            process(21, "ark-prove-gpu", b"prove")
            with (
                patch.object(probe.os, "readlink", side_effect=lambda path: programs[path.parent.name]),
                patch.object(probe.os, "sysconf", side_effect={"SC_CLK_TCK": 100, "SC_PAGE_SIZE": 4096}.__getitem__, create=True),
            ):
                ark, nova = probe.scan_provers(root)
                self.assertEqual([entry["pid"] for entry in ark], [21])
                self.assertEqual([job["id"] for job in nova], ["mnr04:17:1234"])
                self.assertEqual(nova[0]["phase"], "Proving the routed settlement")
                self.assertEqual(nova[0]["cpu_seconds"], 3)
                self.assertEqual(nova[0]["ram_bytes"], 28672)
                self.assertNotIn("private-path", json.dumps(nova))
                self.assertEqual(probe.scan_provers(root, {"fixture.service"})[1], [])

    def test_output_presence_does_not_verify_and_mutation_revokes_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proof = root / "proof.json"
            proof.write_bytes(b"proof artifact")
            self.assertFalse(probe.receipt(root, "audit.json", "proof.json")["valid"])
            data = {"status":"independently_verified_with_negative_controls", "stark_verified":True,
                    "proof_sha256":hashlib.sha256(proof.read_bytes()).hexdigest(),
                    "negative_controls":[{"exit_code":1} for _ in range(15)]}
            audit = root / "audit.json"
            audit.write_text(json.dumps(data))
            self.assertTrue(probe.receipt(root, audit.name, proof.name)["valid"])
            proof.write_bytes(b"changed")
            self.assertFalse(probe.receipt(root, audit.name, proof.name)["valid"])
            proof.write_bytes(b"proof artifact")
            data["negative_controls"][0]["exit_code"] = -9
            audit.write_text(json.dumps(data))
            self.assertFalse(probe.receipt(root, audit.name, proof.name)["valid"])
            data["negative_controls"] = None
            audit.write_text(json.dumps(data))
            self.assertFalse(probe.receipt(root, audit.name, proof.name)["valid"])
            audit.write_text("{broken")
            self.assertFalse(probe.receipt(root, audit.name, proof.name)["valid"])


if __name__ == "__main__":
    unittest.main()
