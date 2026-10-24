"""Verify the PDF models, one-command execution and red fault highlighting."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import run as demo


class CombinedTests(unittest.TestCase):
    def test_pdf_sm4_values(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        correct, trace = demo.sm4_encrypt(key, key)
        self.assertEqual(correct.hex(), "681edf34d206965e86b3e94f536e4246")
        self.assertEqual(trace[0]["a"], 0xF002C39E)
        self.assertEqual(trace[0]["b"], 0x18E992B1)
        self.assertEqual(trace[0]["linear"], 0x26D99622)
        self.assertEqual(trace[-1]["a"], 0x96FF9D45)
        expected = [(0x4f, 0x81), (0x71, 0x83), (0x79, 0x6f), (0x80, 0xc9)]
        recovered = bytearray()
        for byte in range(4):
            survivors = None
            for mask in (1, 2):
                faulty, _ = demo.sm4_encrypt(key, key, byte, mask)
                if byte == 0 and mask == 1:
                    self.assertEqual(faulty.hex(), "1b50e209d206965e86b3e94f536e4246")
                guesses, _, delta = demo.sm4_byte_candidates(correct, faulty, byte, mask)
                self.assertEqual((delta >> (24 - byte * 8)) & 255, expected[byte][mask-1])
                survivors = guesses if survivors is None else survivors & guesses
            self.assertEqual(len(survivors), 1)
            recovered.append(next(iter(survivors)))
        self.assertEqual(recovered.hex(), "9124a012")

    def test_random_sm4_candidates_and_inverse(self):
        rng = random.Random(20)
        for _ in range(20):
            value = rng.randrange(1 << 32)
            self.assertEqual(demo.inverse_linear(demo.sm4.linear(value)), value)
            key, block = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
            correct, _ = demo.sm4_encrypt(block, key)
            keys = demo.sm4.key_expansion(key)
            self.assertEqual(demo.reverse_sm4(keys[28:]), key)
            for byte in range(4):
                faulty, _ = demo.sm4_encrypt(block, key, byte, 1)
                guesses, _, _ = demo.sm4_byte_candidates(correct, faulty, byte, 1)
                self.assertIn((keys[31] >> (24 - byte * 8)) & 255, guesses)
        with self.assertRaises(ValueError):
            demo.reverse_sm4([1])

    def test_round9_aes_recovery(self):
        rng = random.Random(9)
        for _ in range(4):
            key, block = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
            correct = demo.piret.aes_target_encrypt(block, key)
            recovered = bytearray(16)
            for column in range(4):
                survivors = None
                for mask in range(1, 9):
                    faulty, _ = demo.piret.trace_round8(block, key, 2, column, mask, fault_round=9)
                    self.assertEqual(sum(a != b for a, b in zip(correct, faulty)), 4)
                    current = demo.piret.key_candidates(correct, faulty, column)
                    survivors = current if survivors is None else survivors & current
                    if len(survivors) == 1:
                        break
                self.assertEqual(len(survivors), 1)
                for position, byte in zip(demo.piret.output_positions(column), next(iter(survivors))):
                    recovered[position] = byte
            self.assertEqual(demo.piret.reverse_key_schedule(recovered), key)

    def test_single_command_and_colors(self):
        output = io.StringIO()
        with redirect_stdout(output), patch("builtins.input", return_value=""):
            self.assertEqual(demo.main(["--step", "--color", "always"]), 0)
        text = output.getvalue()
        self.assertIn("AES MASTER KEY:", text)
        self.assertIn("DFA RECOVERED rk31 = 9124A012", text)
        self.assertIn("No reference subkeys are supplied", text)
        self.assertIn("SM4 MASTER KEY: ", text)
        self.assertIn("\033[31m", text)
        terminal = demo.LessonTerminal("always")
        self.assertEqual(terminal.changed(b"\x00\x01", b"\x00\x02"), "00 \033[31m02\033[0m")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(demo.main(["--observations", "1", "--color", "never"]), 2)
        self.assertNotIn("\033[", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
