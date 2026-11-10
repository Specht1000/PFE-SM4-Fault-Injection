"""Validate paired comparison controls and early-stop budget reconstruction."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location("sm4_comparison", ROOT / "analysis" / "compare_sm4_attacks.py")
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class SM4ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        cls.correct = comparison.sm4.sm4_encrypt_block(cls.key, cls.key)
        cls.outputs = comparison.make_outputs(cls.key, cls.key)

    def test_known_mask_equivalence_and_unknown_bit_superset(self):
        faulty = self.outputs[31, 0, 1]
        known = comparison.piret_sm4.sm4_byte_candidates(self.correct, faulty, 0, 1)[0]
        giraud_known = comparison.giraud_sm4.sm4_candidates(self.correct, faulty, 1)[1]
        unknown = comparison.giraud_sm4.sm4_candidates(self.correct, faulty)[1]
        self.assertEqual(known, {0x90, 0x91})
        self.assertEqual(known, giraud_known)
        self.assertLess(known, unknown)
        self.assertEqual(len(unknown), 10)

    def test_budget_curve_matches_actual_restricted_runs(self):
        for model in comparison.MODELS:
            complete = comparison.recover(model, self.correct, self.outputs)

            for budget in (1, 2, 3, 8):
                with self.subTest(model=model, budget=budget):
                    inferred = comparison.budget_outcome(complete, budget)
                    actual = comparison.recover(model, self.correct, self.outputs, budget)
                    self.assertEqual(inferred["complete"], actual["complete"])
                    self.assertEqual(inferred["used"], actual["used"])

    def test_matched_bit_histories_are_identical(self):
        piret = comparison.recover("Piret-matched-bits", self.correct, self.outputs)
        giraud = comparison.recover("Giraud-known-bit", self.correct, self.outputs)
        self.assertTrue(piret["complete"])
        self.assertEqual(piret["master_key"], self.key)
        self.assertEqual(piret["history"], giraud["history"])


if __name__ == "__main__":
    unittest.main()
