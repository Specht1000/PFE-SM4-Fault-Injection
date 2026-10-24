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
    def test_legacy_round9_api_matches_shared_engine(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)
        with patch.object(piret, "FAULT_ROW", 2), patch.object(piret, "FAULT_COL", 3), patch.object(piret, "FAULT_VALUE", 0xA5):
            correct, clean, keys = piret.encrypt(plaintext, key)
            faulty, snapshots, _ = piret.encrypt(plaintext, key, inject_fault=True)
        traced, history = piret.encrypt_with_trace(plaintext, key, 2, 3, 0xA5, fault_round=9)
        self.assertEqual(faulty, traced)
        self.assertEqual(correct, piret.aes_target_encrypt(plaintext, key))
        self.assertEqual(set(snapshots), {"before_fault", "after_fault", "after_mixcolumns", "before_last_subbytes", "ciphertext"})
        predicted = piret.predicted_mixcolumns_difference(2, 0xA5)
        difference = piret.difference(clean["after_mixcolumns"], snapshots["after_mixcolumns"])
        self.assertEqual([difference[r][3] for r in range(4)], predicted)
        self.assertEqual(piret.reverse_last_round_difference(correct, faulty, keys[10]), piret.difference(clean["before_last_subbytes"], snapshots["before_last_subbytes"]))
        # An external edit of one legacy snapshot cannot corrupt another or the trace.
        original = history[-1][2]
        snapshots["before_fault"][0][0] ^= 1
        self.assertEqual(aes.state_to_bytes(snapshots["ciphertext"]), original)

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
        configuration = aes.KEY, aes.PLAINTEXT
        with patch.object(aes, "KEY", key), patch.object(aes, "PLAINTEXT", "ffeeddccbbaa99887766554433221100"), patch("builtins.input", return_value=""), redirect_stdout(output):
            status = piret.main(["--step", "--color", "never"])
        text = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("Recovered K0: " + key.upper(), text)
        self.assertIn("KEY RECOVERY: PASS", text)
        self.assertNotIn("\033[", text)
        self.assertEqual((aes.KEY, aes.PLAINTEXT), configuration)

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
