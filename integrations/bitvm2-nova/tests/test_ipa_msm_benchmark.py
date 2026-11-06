"""Resource protection for the real IPA benchmark; no generator payload I/O."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import bench_ipa_msm


class IpaBenchmarkGuard(unittest.TestCase):
    def test_host_guard_precedes_all_report_and_generator_io(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(bench_ipa_msm, 'validate_native_report') as report:
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux only'):
                bench_ipa_msm.run(Path('not-read'), Path('not-read'), Path('not-run'))
            report.assert_not_called()


if __name__ == '__main__':
    unittest.main()
