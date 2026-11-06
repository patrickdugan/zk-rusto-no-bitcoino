"""Tiny transport/guard checks only; never build real retained sumcheck graphs."""
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import bench_sumcheck_graph as bench
from script import OPS, execute, num
from trace import TraceBuilder
from trace_kernels import compile_predicate
from wots_graph import GraphSpec


class SumcheckBench(unittest.TestCase):
    def setUp(self):
        owned = (bench.FIXTURES.parent/'results').resolve()
        owned.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(prefix='tiny-sumcheck-bench-test-',dir=owned)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.assertTrue(self.base.is_relative_to(owned))

    def test_hosted_guard_precedes_reads_and_real_graph_construction(self):
        with patch.dict(os.environ,{},clear=True),patch.object(bench,'_load_graphs') as load:
            with self.assertRaisesRegex(ValueError,'hosted'):
                bench.run(self.base/'not-created.json')
            load.assert_not_called()
        self.assertEqual(list(self.base.iterdir()),[])

    def test_streamed_exact_bytes_hash_and_atomic_budget_failure(self):
        path=self.base/'tiny.json'
        cases=[{'name':'a','words':[0]},{'name':'b','words':[1]}]
        info=bench._write_cases(iter(cases),path)
        raw=path.read_bytes()
        self.assertEqual(json.loads(raw),cases)
        self.assertEqual(info,dict(cases=2,input_bytes=len(raw),input_sha256=sha256(raw).hexdigest()))
        self.assertLess(len(raw),128)
        with patch.object(bench,'MAX_INPUT_BYTES',20):
            with self.assertRaisesRegex(ValueError,'32MiB'):bench._write_cases(iter(cases),path)
        self.assertEqual(path.read_bytes(),raw)
        self.assertFalse(path.with_name(path.name+'.partial').exists())
        with patch.object(bench,'MAX_CASES',1):
            with self.assertRaisesRegex(ValueError,'case bound'):bench._write_cases(iter(cases),path)
        self.assertEqual(path.read_bytes(),raw)

    def test_preexisting_partial_file_is_not_deleted(self):
        path=self.base/'tiny.json'
        partial=path.with_name(path.name+'.partial')
        partial.write_bytes(b'other-owner')
        with self.assertRaises(FileExistsError):bench._write_cases(iter([{'x':0}]),path)
        self.assertEqual(partial.read_bytes(),b'other-owner')
        self.assertFalse(path.exists())

    def test_canonical_field_and_unsigned_decoder_are_distinct_guards(self):
        builder=TraceBuilder('pallas_scalar','test/tiny-field',bytes(32))
        wires=builder.field('x',0)
        builder.check('equal',wires+wires)
        program,values=builder.finish()
        spec=GraphSpec.from_program(program)
        canonical=bench._field_ordinal(program,spec,wires)
        self.assertTrue(bench._truth(program,spec,values,0))
        self.assertTrue(bench._truth(program,spec,values,canonical))
        noncanonical=bench._set_field(values,wires,program.p)
        self.assertTrue(bench._truth(program,spec,noncanonical,0))
        self.assertFalse(bench._truth(program,spec,noncanonical,canonical))
        oversized=dict(values);oversized[wires[0]]=0xffffffff
        self.assertFalse(bench._truth(program,spec,oversized,0))
        self.assertFalse(bench._truth(program,spec,oversized,canonical))

    def test_add_noncanonical_input_aborts_both_modes_output_is_plain_false(self):
        for role in ('pallas_scalar','vesta_scalar'):
            builder=TraceBuilder(role,'test/tiny-add-domain',bytes(32))
            x=builder.field('x',0)
            y=builder.field('y',0)
            z=builder.field('z',0)
            builder.check('add',x+y+z)
            program,values=builder.finish()
            spec=GraphSpec.from_program(program)
            code=compile_predicate(program.p,'add')
            inverted=code+bytes([OPS['NOT']])
            witness=lambda changed:[num(changed[word]) for word in x+y+z]
            self.assertIs(bench._truth(program,spec,values,0),True)
            self.assertTrue(execute(code,witness(values)).success)
            for wires in (x,y):
                bad=bench._set_field(values,wires,program.p)
                # The modular relation alone is true. Actual Script has an
                # additional canonical INPUT VERIFY, so neither mode succeeds.
                self.assertTrue(program.constraints[0].native(bad,program.p))
                self.assertIsNone(bench._truth(program,spec,bad,0))
                for script in (code,inverted):
                    result=execute(script,witness(bad))
                    self.assertFalse(result.success)
                    self.assertEqual(result.error,'VERIFY')
                valid=bench._field_ordinal(program,spec,wires)
                self.assertIs(bench._truth(program,spec,bad,valid),False)
                body=bytes.fromhex(dict(spec.bodies)[spec.leaves[valid].body_sha256])
                field_disproof=execute(body+bytes([OPS['NOT']]),[num(bad[word]) for word in wires])
                self.assertTrue(field_disproof.success)
                self.assertIsNone(field_disproof.error)
            bad_output=bench._set_field(values,z,program.p)
            self.assertIs(bench._truth(program,spec,bad_output,0),False)
            comparison=execute(code,witness(bad_output))
            self.assertFalse(comparison.success)
            self.assertIsNone(comparison.error)
            self.assertTrue(execute(inverted,witness(bad_output)).success)


if __name__=='__main__':
    unittest.main()
