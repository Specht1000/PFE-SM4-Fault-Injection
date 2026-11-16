"""Check last-round linear identities and the nonlinear counterexample."""
from pathlib import Path
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import prove_sm4_round31 as proof


class Round31ProofTests(unittest.TestCase):
    def test_public_vector_counterexample_and_correct_key_equation(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        data = proof.calculate(key, key)
        self.assertEqual(data["error"], 0x03000000)
        self.assertEqual(data["delta_b"], 0x2E000000)
        self.assertNotEqual(data["delta_b"], data["b_correct"])
        self.assertNotEqual(data["inverse_difference"], data["rk"] ^ data["error"])
        self.assertNotEqual(data["inverse_difference"] ^ data["q"], data["rk"])
        self.assertEqual(proof.inverse_sbox_word(data["b_faulty"]) ^ data["q"] ^ data["error"], data["rk"])

    def test_inverse_tau_and_equations_for_multiple_positions_and_keys(self):
        rng = random.Random(20261116)

        for index in range(4):
            key = rng.randbytes(16)
            plaintext = rng.randbytes(16)

            for mask in (1, 3, 0x80, 0xFF):
                data = proof.calculate(plaintext, key, index, mask)
                self.assertEqual(proof.inverse_sbox_word(proof.sm4.sbox(data["a_correct"])), data["a_correct"])
                self.assertEqual(data["delta_b"], data["b_correct"] ^ data["b_faulty"])


if __name__ == "__main__":
    unittest.main()
