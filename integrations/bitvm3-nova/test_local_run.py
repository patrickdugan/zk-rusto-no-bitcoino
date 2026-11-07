import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import local_run as run

class LocalRunnerTests(unittest.TestCase):
    def test_all_plan_covers_each_suite(self):
        name, build, execute = run.plans('all', Path('/tmp/out'))[0]
        self.assertEqual(name, 'all')
        self.assertIn('--no-run', build)
        self.assertNotIn('--no-run', execute)
        for target in ['curves', 'transcript', 'boolean_transcript', 'structured_transcript', 'sumcheck']:
            self.assertIn(target, build); self.assertIn(target, execute)
        self.assertIn('--test-threads=1', execute)
    def test_native_is_separate_and_build_only_plan_does_not_execute(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(run.main(['--suite', 'native', '--build-only', '--plan']), 0)
        plan = json.loads(buffer.getvalue())
        self.assertEqual(len(plan['commands']), 1)
        self.assertIn('build', plan['commands'][0]['argv'])
        self.assertFalse(plan['full_garbled_nova_verifier'])
    def test_success_failure_and_timeout_logs(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            for expression, status in [('print("ok")', 'passed'), ('raise SystemExit(7)', 'failed')]:
                record = run.run_logged([sys.executable, '-c', expression], root, os.environ.copy(), root / f'{status}.log', 5)
                self.assertEqual(record['status'], status)
                self.assertEqual(len(record['log_sha256']), 64)
            record = run.run_logged([sys.executable, '-c', 'import time; time.sleep(60)'], root,
                                    os.environ.copy(), root / 'timeout.log', 1)
            self.assertEqual(record['status'], 'timeout')
    def test_full_receipt_and_failed_build_stop(self):
        for fail_build in [False, True]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); lab = root / 'nova-bitvm3'; lab.mkdir()
                (lab / 'Cargo.toml').write_text('[package]\nname="fixture"\n')
                (lab / 'Cargo.lock').write_text('# fixture lock\n')
                output = root / 'run'
                names = []
                def fake(args, cwd, env, log, timeout):
                    names.append(log.name); log.write_text('fixture log\n')
                    return {'command': args, 'log': str(log), 'status': 'failed' if fail_build and 'build' in log.name else 'passed'}
                with patch.object(run, '__file__', str(lab / 'local_run.py')), \
                     patch.object(run.shutil, 'which', return_value=sys.executable), \
                     patch.object(run, 'optional_command', return_value='fixture'), \
                     patch.object(run, 'run_logged', side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
                    code = run.main(['--suite', 'all', '--output', str(output)])
                self.assertEqual(code, int(fail_build))
                receipt = json.loads((output / 'receipt.json').read_text())
                self.assertEqual(receipt['status'], 'failed' if fail_build else 'passed')
                self.assertFalse(receipt['hard_memory_limit_enforced'])
                self.assertIn('Cargo.lock', receipt['artifacts'])
                self.assertEqual('all_run.log' in names, not fail_build)
    def test_imported_lock_conflict_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lab = root / 'nova-bitvm3'; lab.mkdir()
            (lab / 'Cargo.toml').write_text('x'); (lab / 'Cargo.lock').write_text('old')
            other = root / 'ci.lock'; other.write_text('new')
            with patch.object(run, '__file__', str(lab / 'local_run.py')), \
                 patch.object(run.shutil, 'which', return_value=sys.executable), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run.main(['--lockfile', str(other), '--output', str(root / 'run')])
            self.assertEqual((lab / 'Cargo.lock').read_text(), 'old')
            self.assertFalse((root / 'run').exists())

if __name__ == '__main__': unittest.main(verbosity=2)
