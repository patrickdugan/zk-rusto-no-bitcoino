"""Offline configuration tests. These do not execute a cryptographic backend."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import policy

PLAN = json.loads(Path(__file__).with_name("plan.json").read_text())


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.plan = deepcopy(PLAN)

    def rejected(self):
        with self.assertRaises(policy.PolicyError):
            policy.validate(self.plan)

    def test_default(self):
        policy.validate(self.plan)

    def test_groth16_wrapper(self):
        self.plan["stages"].append("groth16")
        self.rejected()

    def test_kzg_compressor(self):
        self.plan["stages"][-1] = "spartan-hyperkzg"
        self.rejected()

    def test_mercury_compressor(self):
        self.plan["stages"][-1] = "spartan-mercury"
        self.rejected()

    def test_fflonk_wrapper(self):
        self.plan["stages"].append("fflonk-kzg")
        self.rejected()

    def test_missing_compression(self):
        self.plan["stages"].pop()
        self.rejected()

    def test_empty_pipeline(self):
        self.plan["stages"] = []
        self.rejected()

    def test_changed_curve(self):
        self.plan["stages"][0] = "nova-bn254-hyperkzg"
        self.rejected()

    def test_stages_string(self):
        self.plan["stages"] = "nova-pallas-vesta-pedersen,spartan-ipa"
        self.rejected()

    def test_unknown_profile(self):
        self.plan["profile"] = "transparent-by-label"
        self.rejected()

    def test_trusted_setup_optout(self):
        self.plan["trusted_setup"] = "optional"
        self.rejected()

    def test_false_flag_cannot_override_stages(self):
        self.plan["stages"].append("groth16")
        self.plan["trusted_setup"] = False
        self.rejected()

    def test_quantum_claim(self):
        self.plan["post_quantum_claim"] = True
        self.rejected()

    def test_privacy_claim(self):
        self.plan["zero_knowledge_claim"] = True
        self.rejected()

    def test_integer_false_is_rejected(self):
        self.plan["zero_knowledge_claim"] = 0
        self.rejected()

    def test_unknown_root_field(self):
        self.plan["wrapper"] = "groth16"
        self.rejected()

    def test_missing_field(self):
        del self.plan["trusted_setup"]
        self.rejected()

    def test_changed_revision(self):
        self.plan["source"]["revision"] = "main"
        self.rejected()

    def test_changed_nova_version(self):
        self.plan["source"]["nova_snark_version"] = "0.77.0"
        self.rejected()

    def test_unknown_source_option(self):
        self.plan["source"]["kzg"] = True
        self.rejected()

    def test_wrong_network_statement(self):
        self.plan["workload"]["network"] = "mainnet"
        self.rejected()

    def test_mainnet_pair(self):
        self.plan["workload"].update(network="mainnet", statement="btc_header_chain_v1")
        policy.validate(self.plan)

    def test_nonstring_network(self):
        self.plan["workload"]["network"] = []
        self.rejected()

    def test_ambiguous_rows(self):
        self.plan["workload"]["unit"] = "rows"
        self.rejected()

    def test_genesis_at_nonzero_height(self):
        self.plan["workload"]["start_height"] = 1000
        self.rejected()

    def test_checkpoint_requires_digest(self):
        self.plan["workload"].update(anchor_mode="authenticated-checkpoint", start_height=1000)
        self.rejected()

    def test_checkpoint_is_explicit(self):
        self.plan["workload"].update(anchor_mode="authenticated-checkpoint", start_height=1000,
                                     checkpoint_state_sha256="a" * 64)
        self.assertTrue(policy.matrix(self.plan)["checkpoint_trust_required"])

    def test_bad_digest(self):
        self.plan["workload"]["fixture_sha256"] = "bad"
        self.rejected()

    def test_pinned_fixture(self):
        self.plan["workload"]["fixture_sha256"] = "a" * 64
        self.assertTrue(policy.matrix(self.plan)["fixture_pinned"])

    def test_bool_is_not_step_count(self):
        self.plan["workload"]["headers_per_step"] = [True]
        self.rejected()

    def test_zero_width(self):
        self.plan["workload"]["headers_per_step"] = [0]
        self.rejected()

    def test_duplicate_width(self):
        self.plan["workload"]["headers_per_step"] = [1, 1]
        self.rejected()

    def test_nondivisible(self):
        self.plan["workload"]["total_headers"] = [65]
        self.rejected()

    def test_height_overflow(self):
        self.plan["workload"].update(anchor_mode="authenticated-checkpoint", start_height=2**32 - 2,
                                     checkpoint_state_sha256="a" * 64)
        self.rejected()

    def test_over_memory_budget(self):
        self.plan["budget"]["memory_max_bytes"] += 1
        self.rejected()

    def test_swap_not_allowed(self):
        self.plan["budget"]["memory_swap_max_bytes"] = 1
        self.rejected()

    def test_unknown_budget_field(self):
        self.plan["budget"]["ignore_oom"] = True
        self.rejected()

    def test_matrix(self):
        result = policy.matrix(self.plan)
        self.assertEqual(len(result["cases"]), 12)
        self.assertFalse(result["proof_executed"])
        self.assertFalse(result["os_memory_limit_enforced"])
        for case in result["cases"]:
            self.assertEqual(case["fold_steps"] * case["headers_per_step"], case["total_headers"])
        self.assertEqual(result["plan_sha256"], policy.matrix(deepcopy(self.plan))["plan_sha256"])

    def test_hash_changes_with_workload(self):
        old = policy.matrix(self.plan)["plan_sha256"]
        self.plan["workload"]["total_headers"] = [64]
        self.assertNotEqual(old, policy.matrix(self.plan)["plan_sha256"])

    def bad_file(self, raw):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "plan.json"
            p.write_bytes(raw)
            with self.assertRaises(policy.PolicyError):
                policy.load_plan(p)

    def test_duplicate_json_key(self):
        self.bad_file(b'{"trusted_setup":"forbidden","trusted_setup":"allowed"}')

    def test_nonfinite_json(self):
        self.bad_file(b'{"number":NaN}')

    def test_oversize_json(self):
        self.bad_file(b" " * (policy.MAX_PLAN_BYTES + 1))

    def test_invalid_utf8(self):
        self.bad_file(b"\xff")

    def test_wrong_root_type(self):
        self.bad_file(b"[]")

    def test_cli(self):
        result = subprocess.run([sys.executable, str(Path(policy.__file__)), "check",
                                 str(Path(__file__).with_name("plan.json"))],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["scope"], "declared-plan-only")

    def test_cli_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([sys.executable, str(Path(policy.__file__)), "check",
                                     str(Path(d) / "absent.json")],
                                    capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stderr)["ok"])


if __name__ == "__main__":
    unittest.main()
