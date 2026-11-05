import unittest
from script import P, Q, OPS, execute
from trace import multiplication_trace


class WitnessArity(unittest.TestCase):
    def test_exact_witness_count_guard(self):
        for role,p in [('pallas_base',P),('vesta_base',Q)]:
            program,values=multiplication_trace(role,p-19,p-73)
            bound=program.bind(values)
            for i in [0,8,9,18,273]:
                for disprove in (False,True):
                    code=bound.script(i,disprove=disprove)
                    self.assertEqual(code[0],OPS['DEPTH'])
                    ws=list(bound.witness(i))
                    for bad in [[],ws[:-1],ws+[b''],[b'']+ws]:
                        result=execute(code,bad)
                        self.assertFalse(result.success)
                        self.assertEqual(result.error,'EQUALVERIFY')


if __name__=='__main__':unittest.main()
