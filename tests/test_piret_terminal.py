"""Check ciphertext-only recovery and the didactic terminal entry point."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import aes
import piret


class PiretTerminalTests(unittest.TestCase):
    def test_recovery_random_keys_all_positions(self):
        rng = random.Random(2003)
        for row in range(4):
            for column in range(4):
                key, block = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
                correct = piret.aes_target_encrypt(block, key)
                self.assertEqual(piret.trace_round8(block, key)[0], correct)
                masks = rng.sample(range(1, 256), 8)
                faulty = (piret.trace_round8(block, key, row, column, mask)[0] for mask in masks)
                last_key, used = piret.recover_last_key(correct, faulty)
                self.assertIsNotNone(last_key)
                self.assertLessEqual(used, 8)
                self.assertEqual(piret.reverse_key_schedule(last_key), key)

    def test_ambiguity_and_invalid_model(self):
        key, block = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)
        correct = piret.trace_round8(block, key)[0]
        faulty = piret.trace_round8(block, key, mask=1)[0]
        self.assertIsNone(piret.recover_last_key(correct, [faulty, faulty])[0])
        with self.assertRaises(ValueError):
            piret.recover_last_key(correct, [correct])
        with self.assertRaises(ValueError):
            piret.recover_last_key(b"short", [faulty])
        with self.assertRaises(ValueError):
            piret.reverse_key_schedule(b"short")

    def test_main_reads_changed_aes_configuration(self):
        key = "102132435465768798a9bacbdcedfe0f"
        output = io.StringIO()
        flags = aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS
        with patch.object(aes, "KEY", key), patch.object(aes, "PLAINTEXT", "ffeeddccbbaa99887766554433221100"), patch("builtins.input", return_value=""), redirect_stdout(output):
            status = piret.main(["--step", "--color", "never"])
        text = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("Recovered K0: " + key.upper(), text)
        self.assertIn("KEY RECOVERY: PASS", text)
        self.assertNotIn("\033[", text)
        self.assertEqual((aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS), flags)

    def test_cli_ambiguity_and_colors(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = piret.main(["--faults", "1", "--color", "always"])
        self.assertEqual(result, 2)
        self.assertIn("AMBIGUOUS", output.getvalue())
        self.assertIn("\033[", output.getvalue())
        self.assertNotIn("KEY RECOVERY: PASS", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
