"""Tiny retained benchmark guards/policy checks; no bulk math or native work."""
import ast
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import bench_retained_verifier as bench
from nht4 import load_expected_json


class RetainedBench(unittest.TestCase):
    def test_hosted_linux_guard_precedes_fixture_io_and_composition(self):
        for github,runner,platform in [('false','Linux','linux'),
                ('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                    patch.object(bench.sys,'platform',platform),\
                    patch.object(bench,'_load_inputs') as load,\
                    patch.object(bench,'_compose') as compose:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    bench.run(Path('not-read'),Path('not-read'),Path('not-run'))
                load.assert_not_called()
                compose.assert_not_called()
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux'},clear=True),\
                patch.object(bench.sys,'platform','linux'):
            bench._hosted_guard()  # Resource guard only; performs no I/O/math.

    def test_independent_literal_pins_match_existing_retained_metadata_consumers(self):
        def literals(filename,names):
            tree=ast.parse((bench.FIXTURES.parent/filename).read_text(encoding='utf-8'))
            return {target.id:ast.literal_eval(node.value)
                for node in tree.body if isinstance(node,ast.Assign)
                for target in node.targets if isinstance(target,ast.Name) and target.id in names}
        names={'DIMENSION_PIN','KEY_PIN','TRACE_PIN','POSEIDON_PIN',
               'MATRIX_PROFILE_PIN','MATRIX_COLLECTION_PIN'}
        pins=literals('bench_replay.py',names)
        self.assertEqual(set(pins),names)
        for name,value in pins.items():
            self.assertEqual(getattr(bench,name),value)
            self.assertEqual(len(value),64)
        self.assertEqual(bench.GENERATOR_PIN,literals('bench_ipa_msm.py',{'GENERATOR_PIN'})['GENERATOR_PIN'])
        self.assertEqual((bench.MATRIX_BYTES,bench.GENERATOR_BYTES,bench.GENERATORS),
                         (119674848,17301520,540672))

    def test_private_summary_formatter_rejects_contract_drift_and_authority_flags(self):
        # TEST-ONLY format fixture, not a sealed execution or evidence of math.
        expected=load_expected_json((bench.FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        policy=json.dumps(expected.json(),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        summary=dict(schema='bitvm2-nova-retained-math-verification/v1',
            retained_math_checks_composed=True,matrix_files_checked=6,
            matrix_inner_terminals_checked=2,ipa_native_msm_executions=2,generator_count=540672,
            matrix_bytes_checked=119674848,generator_payload_bytes=17301520,
            matrix_entries_checked=2667462,transactions_broadcast=0,native_proofs_verified=0,
            container_framing_checked_by_this_call=False,
            expected_policy_sha256=sha256(policy).hexdigest(),proof_sha256=expected.proof_sha256.hex(),
            bundle_sha256=expected.bundle_sha256.hex(),end_state_sha256=expected.end_state_sha256.hex(),
            verifier_key_sha256=expected.verifier_key_sha256.hex(),verifier_dimensions_sha256=bench.DIMENSION_PIN,
            key_bindings_sha256=bench.KEY_PIN,native_trace_sha256=bench.TRACE_PIN,
            poseidon_parameters_sha256=bench.POSEIDON_PIN,matrix_profile_sha256=bench.MATRIX_PROFILE_PIN,
            matrix_collection_sha256=bench.MATRIX_COLLECTION_PIN,generator_collection_sha256=bench.GENERATOR_PIN,
            roles=[{'role':'primary'},{'role':'secondary'}])
        summary.update({name:False for name in bench.FALSE_FLAGS})
        self.assertEqual(bench._checked_summary(summary,expected),summary)
        for name,value in [('retained_math_checks_composed',1),('matrix_files_checked',True),
                ('ipa_native_msm_executions',1),('generator_count',True),('matrix_bytes_checked',0),
                ('transactions_broadcast',False),('proof_verified',True),('complete_verifier',True),
                ('native_proofs_verified',True),('container_framing_checked_by_this_call',True),
                ('ipa_complete_verification',True),('native_trace_sha256','00'*32),
                ('expected_policy_sha256','00'*32),('roles',[{'role':'secondary'},{'role':'primary'}])]:
            changed=deepcopy(summary);changed[name]=value
            with self.assertRaises(ValueError):bench._checked_summary(changed,expected)
        for name in bench.FALSE_FLAGS:
            changed=deepcopy(summary);changed[name]=0
            with self.assertRaises(ValueError):bench._checked_summary(changed,expected)


if __name__=='__main__':
    unittest.main()
