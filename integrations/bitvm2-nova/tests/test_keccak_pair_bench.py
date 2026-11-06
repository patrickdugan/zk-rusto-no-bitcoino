"""Tiny benchmark checks only; never construct or bind a full Keccak pair."""
from hashlib import sha256
import itertools
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import bench_keccak_pair as bench
from trace import TraceBuilder
from wots_graph import GraphSpec


class KeccakPairBench(unittest.TestCase):
    def setUp(self):
        owned=(bench.ROOT/'results').resolve()
        owned.mkdir(exist_ok=True)
        self.temp=TemporaryDirectory(prefix='tiny-keccak-pair-bench-',dir=owned)
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name).resolve()
        self.assertTrue(self.directory.is_relative_to(owned))

    def test_hosted_guard_precedes_io_and_full_pair_construction(self):
        for github,runner,platform in [('false','Linux','linux'),
                ('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                    patch.object(bench.sys,'platform',platform),\
                    patch.object(bench,'_load_pair') as load:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    bench.run(self.directory/'not-created.json')
                load.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()),[])

    def test_stream_hash_budgets_atomic_preservation_and_partial_ownership(self):
        path=self.directory/'toy.json'
        cases=[{'name':str(i)} for i in range(5)]
        result=bench._write_cases(iter(cases),path)
        raw=path.read_bytes()
        self.assertLess(len(raw),128)
        self.assertEqual(json.loads(raw),cases)
        self.assertEqual(result,dict(cases=5,input_bytes=len(raw),input_sha256=sha256(raw).hexdigest()))
        with patch.object(bench,'MAX_INPUT_BYTES',20):
            with self.assertRaisesRegex(ValueError,'32MiB'):bench._write_cases(iter(cases),path)
        self.assertEqual(path.read_bytes(),raw)
        with self.assertRaisesRegex(ValueError,'five-case'):bench._write_cases(iter(cases+[{'name':'six'}]),path)
        self.assertEqual(path.read_bytes(),raw)
        partial=path.with_name(path.name+'.partial')
        self.assertFalse(partial.exists())
        partial.write_bytes(b'other-owner')
        with self.assertRaises(FileExistsError):bench._write_cases(iter(cases),path)
        self.assertEqual(partial.read_bytes(),b'other-owner')

    def test_boolean_reference_includes_signed_word_decoder_bounds(self):
        for kind,width in [('bool_xor',3),('bool_and',3),('bool_not',2),('const',1)]:
            builder=TraceBuilder('pallas_scalar','test/tiny-pair-bool',bytes(32))
            wires=tuple(builder.small(f'w{i}',0,2) for i in range(width))
            builder.check(kind,wires,(0,) if kind=='const' else ())
            program,_=builder.finish()
            spec=GraphSpec.from_program(program)
            for bits in itertools.product((0,1),repeat=width):
                values=dict(zip(wires,bits,strict=True))
                self.assertEqual(bench._truth(spec,values,0),program.constraints[0].native(values,program.p))
            for malformed in (2,0xffffffff,True):
                values={word:0 for word in wires};values[wires[0]]=malformed
                self.assertIs(bench._truth(spec,values,0),False)

    def test_coherent_middle_word_reference_changes_final_state(self):
        initial=bench._initial_state()
        middle=bench.keccak_f1600_round(initial,0)
        changed=bench._flip_first(middle)
        self.assertEqual(changed[0]^middle[0],1)
        self.assertEqual(changed[1:],middle[1:])
        self.assertNotEqual(bench.keccak_f1600_round(changed,1),bench.keccak_f1600_round(middle,1))


if __name__=='__main__':
    unittest.main()
