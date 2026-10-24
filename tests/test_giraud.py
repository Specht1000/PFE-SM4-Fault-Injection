"""Chapter-7 vectors, bit-fault models, ciphertext-only recovery and ambiguity."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import aes
import sm4
import giraud
import gui as lab
import run as simulator


class GiraudTests(unittest.TestCase):
    def test_terminal_main(self):
        output = io.StringIO()
        with redirect_stdout(output), patch("builtins.input", return_value=""):
            self.assertEqual(giraud.main(["--step", "--color", "never"]), 0)
        self.assertIn("Recovered master key: " + aes.KEY.upper(), output.getvalue())
        self.assertIn("Recovered rk31: 9124A012", output.getvalue())
        self.assertNotIn("\033[", output.getvalue())
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(giraud.main(["--algorithm", "aes", "--known-bit", "--color", "never"]), 0)
        self.assertIn("Bit known to solver: True", output.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(giraud.main(["--observations", "1", "--color", "never"]), 2)

    def test_pdf_aes_example_and_two_observations(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)
        correct, trace = lab.aes_giraud_encrypt(plaintext, key)
        self.assertEqual(trace["Before fault"][0], 0xBD)
        self.assertEqual(correct.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        first, _ = lab.aes_giraud_encrypt(plaintext, key, 0, 1)
        second, _ = lab.aes_giraud_encrypt(plaintext, key, 0, 2)
        self.assertEqual(first.hex(), "76c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(second.hex(), "1bc4e0d86a7b0430d8cdb78070b4c55a")
        for known in (False, True):
            a = giraud.aes_candidates(correct, first, 1 if known else None)[1]
            b = giraud.aes_candidates(correct, second, 2 if known else None)[1]
            self.assertEqual(a & b, {0x13})

    def test_pdf_sm4_example(self):
        key = bytes.fromhex(sm4.KEY)
        correct, _ = simulator.sm4_encrypt(key, key)
        first, _ = simulator.sm4_encrypt(key, key, 0, 1)
        self.assertEqual(first.hex(), "1b50e209d206965e86b3e94f536e4246")
        position, guesses, inputs, delta = giraud.sm4_candidates(correct, first, 1)
        self.assertEqual((position, inputs, delta), (0, {0x96, 0x97}, 0x4F000000))
        self.assertEqual(guesses, {0x91, 0x90})
        second, _ = simulator.sm4_encrypt(key, key, 0, 2)
        self.assertEqual(guesses & giraud.sm4_candidates(correct, second, 2)[1], {0x91})

    def test_all_aes_positions_and_known_bit_is_stronger(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)
        correct, _ = lab.aes_giraud_encrypt(plaintext, key)
        last_key = aes.state_to_bytes(aes.key_expansion(key)[10])
        for byte in range(16):
            for mask in giraud.SINGLE_BITS:
                faulty, _ = lab.aes_giraud_encrypt(plaintext, key, byte, mask)
                position, unknown = giraud.aes_candidates(correct, faulty)
                _, known = giraud.aes_candidates(correct, faulty, mask)
                expected = 4 * ((byte // 4 - byte % 4) % 4) + byte % 4
                self.assertEqual(position, expected)
                self.assertIn(last_key[position], known)
                self.assertLessEqual(known, unknown)

    def test_random_key_recovery_both_models(self):
        rng = random.Random(2004)
        for _ in range(8):
            key, plaintext = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
            for algorithm in ("AES-128", "SM4"):
                report = lab.giraud_lesson(algorithm, plaintext, key, row=2, column=3)
                self.assertTrue(report["verified"], report["remaining_candidates"])
                if algorithm == "AES-128":
                    self.assertEqual(report["recovered_key"], key.hex())
                else:
                    self.assertEqual(report["recovered_key"], key.hex())
                    self.assertEqual(report["recovered_subkey"], f"{sm4.key_expansion(key)[31]:08X}")
                    self.assertEqual(set(report["recovered_round_keys"]), {"28", "29", "30", "31"})
                    self.assertNotIn("reference_subkeys", report)

    def test_ambiguity_and_rejections(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)
        correct, _ = lab.aes_giraud_encrypt(plaintext, key)
        for mask in (0, 3, 255):
            with self.assertRaises(ValueError):
                lab.aes_giraud_encrypt(plaintext, key, 0, mask)
        with self.assertRaises(ValueError):
            giraud.aes_candidates(correct, correct)
        with self.assertRaises(ValueError):
            giraud.masks_for(1, 9)
        for algorithm in ("AES-128", "SM4"):
            result = lab.giraud_lesson(algorithm, plaintext, key, maximum=1)
            self.assertFalse(result["verified"])
            self.assertIsNone(result["recovered_key"])
        first, _ = lab.aes_giraud_encrypt(plaintext, key, 0, 1)
        second, _ = lab.aes_giraud_encrypt(plaintext, key, 0, 2)
        position, survivors = giraud.recover_byte("AES-128", [(correct, first), (correct, second)])
        self.assertEqual((position, survivors), (0, {0x13}))
        other, _ = lab.aes_giraud_encrypt(plaintext, key, 1, 1)
        with self.assertRaises(ValueError):
            giraud.recover_byte("AES-128", [(correct, first), (correct, other)])
        with self.assertRaises(ValueError):
            giraud.intersect_candidates({1}, {2})
        self.assertEqual(giraud.recover_byte("SM4", []), (None, None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
