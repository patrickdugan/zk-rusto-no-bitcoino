"""Small scheduler checks; no source download, child process or proving."""
import unittest

from proving_shards import admit_memory_budget


class ProvingMemoryBudget(unittest.TestCase):
    def test_sixteen_gib_admits_two_six_gib_shards_with_fifteen_gib_available(self):
        result=admit_memory_budget(memory_mib=6144,parallel=2,export_parallel=2,
            total_memory_mib=16384,reserve_memory_mib=2048,available_bytes=15 << 30)
        self.assertEqual(result['maximum_concurrent_job_limit_bytes'],12 << 30)
        self.assertEqual(result['total_proving_memory_mib'],16384)

    def test_total_budget_and_live_capacity_are_independent_requirements(self):
        with self.assertRaisesRegex(ValueError,'total proving budget'):
            admit_memory_budget(memory_mib=6144,parallel=3,export_parallel=2,
                total_memory_mib=16384,reserve_memory_mib=2048,available_bytes=40 << 30)
        with self.assertRaisesRegex(ValueError,'available RAM'):
            admit_memory_budget(memory_mib=6144,parallel=2,export_parallel=2,
                total_memory_mib=16384,reserve_memory_mib=2048,available_bytes=13 << 30)

    def test_export_capacity_and_typed_limits_are_checked(self):
        with self.assertRaisesRegex(ValueError,'total proving budget'):
            admit_memory_budget(memory_mib=6144,parallel=1,export_parallel=3,
                total_memory_mib=16384,reserve_memory_mib=0,available_bytes=40 << 30)
        for changes in ({'parallel':True},{'memory_mib':0},{'reserve_memory_mib':-1},
                        {'available_bytes':True},{'total_memory_mib':1.5}):
            args=dict(memory_mib=6144,parallel=2,export_parallel=2,
                total_memory_mib=16384,reserve_memory_mib=2048,available_bytes=15 << 30)
            args.update(changes)
            with self.assertRaises(ValueError):
                admit_memory_budget(**args)


if __name__=='__main__':
    unittest.main()
