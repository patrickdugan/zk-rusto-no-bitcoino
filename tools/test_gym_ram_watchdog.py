import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).with_name("gym_ram_watchdog.py")
PARENT = """import subprocess, sys
child = subprocess.Popen([sys.executable, '-c', sys.argv[1]])
print(child.wait(), flush=True)
"""
IDLE = "import time; buf = bytearray(64 * 1024**2); time.sleep(3)"
BUSY = "import time; buf = bytearray(64 * 1024**2); end = time.monotonic() + 2\nwhile time.monotonic() < end: pass"


@unittest.skipUnless(importlib.util.find_spec("psutil"), "requires psutil")
class WatchdogTests(unittest.TestCase):
    def exercise(self, worker, reserve, *flags):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--cpu-only", "--reserve-mib", str(reserve),
             "--worker-mib", "48", "--sample-seconds", ".10", "--idle-seconds", ".7",
             "--cpu-percent", "5", *flags, "--", sys.executable, "-c", PARENT, worker],
            text=True, capture_output=True, timeout=15,
        )

    def test_idle_pressure_reaps_child_and_fails_run(self):
        got = self.exercise(IDLE, 10**9)
        self.assertEqual(got.returncode, 86, got.stderr)
        self.assertEqual(json.loads(got.stderr.splitlines()[0])["action"], "terminate")
        self.assertNotEqual(got.stdout.strip(), "0")

    def test_cpu_active_survives_pressure(self):
        got = self.exercise(BUSY, 10**9)
        self.assertEqual((got.returncode, got.stdout.strip(), got.stderr), (0, "0", ""))

    def test_idle_survives_without_pressure(self):
        got = self.exercise(IDLE, 1)
        self.assertEqual((got.returncode, got.stdout.strip(), got.stderr), (0, "0", ""))

    def test_unrelated_process_survives_reap(self):
        sibling = subprocess.Popen([sys.executable, "-c",
                                    "import time; buf = bytearray(64 * 1024**2); time.sleep(15)"])
        try:
            got = self.exercise(IDLE, 10**9)
            self.assertEqual(got.returncode, 86, got.stderr)
            self.assertIsNone(sibling.poll())
        finally:
            if sibling.poll() is None:
                sibling.terminate()
            sibling.wait(timeout=5)

    def test_report_only_leaves_worker_alive(self):
        got = self.exercise(IDLE, 10**9, "--report-only")
        self.assertEqual((got.returncode, got.stdout.strip()), (0, "0"))
        self.assertEqual(json.loads(got.stderr.splitlines()[0])["action"], "would_terminate")


if __name__ == "__main__":
    unittest.main()
