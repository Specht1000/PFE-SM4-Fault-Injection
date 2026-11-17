"""Regression checks for the round-input SM4 DFA; standard library only."""
import contextlib
import io
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import piret_sm4
import sm4


class InputFaultTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes.fromhex(sm4.KEY)
        self.plaintext = bytes.fromhex(sm4.PLAINTEXT)

    def test_official_vector_and_observable_input_fault(self):
        correct, _ = piret_sm4.sm4_fault_encrypt(self.plaintext, self.key)
        faulty, trace = piret_sm4.sm4_fault_encrypt(self.plaintext, self.key, 0, 3)
        self.assertEqual(correct.hex().upper(), "681EDF34D206965E86B3E94F536E4246")
        self.assertEqual(faulty.hex().upper(), "FE30678CD206965E86B3E94F506E4246")
        self.assertEqual(trace[31]["before"][1] ^ trace[31]["state"][1], 0x03000000)
        candidates, _, delta = piret_sm4.sm4_byte_candidates(correct, faulty, 0, 3)
        self.assertEqual(candidates, {0x91, 0x92})
        self.assertEqual(delta, 0x2E000000)

    def test_every_input_word_byte_and_tail_round(self):
        rng = random.Random(2026)

        for sample in range(3):
            key = rng.getrandbits(128).to_bytes(16, "big")
            plaintext = rng.getrandbits(128).to_bytes(16, "big")
            correct = sm4.sm4_encrypt_block(plaintext, key)
            schedule = sm4.key_expansion(key)

            for word in (1, 2, 3):
                for number in range(28, 32):
                    later_keys = {}

                    for later in range(number + 1, 32):
                        later_keys[later] = schedule[later]

                    clean_view = piret_sm4.peel_sm4(correct, number, later_keys)

                    for byte in range(4):
                        mask = rng.randrange(1, 256)
                        faulty, trace = piret_sm4.sm4_fault_encrypt(plaintext, key, byte, mask, number, word)
                        faulty_view = piret_sm4.peel_sm4(faulty, number, later_keys)
                        candidates, _, delta = piret_sm4.sm4_byte_candidates(clean_view, faulty_view, byte, mask)
                        actual = (schedule[number] >> (24 - 8 * byte)) & 255
                        self.assertIn(actual, candidates)
                        self.assertEqual(sm4.linear(delta), struct.unpack(">4I", clean_view)[0] ^ struct.unpack(">4I", faulty_view)[0])

    def test_complete_recovery_random_keys_each_input_word(self):
        rng = random.Random(17)

        for word in (1, 2, 3):
            key = rng.getrandbits(128).to_bytes(16, "big")
            plaintext = rng.getrandbits(128).to_bytes(16, "big")
            correct = sm4.sm4_encrypt_block(plaintext, key)

            def oracle(number, byte, mask):
                ciphertext, _ = piret_sm4.sm4_fault_encrypt(plaintext, key, byte, mask, number, word)
                return ciphertext

            result = piret_sm4.recover_sm4_master_key(correct, oracle)
            self.assertTrue(result["complete"])
            self.assertEqual(result["master_key"], key)
            self.assertEqual(sm4.sm4_decrypt_block(correct, result["master_key"]), plaintext)

    def test_one_observation_is_reported_as_ambiguous(self):
        correct = sm4.sm4_encrypt_block(self.plaintext, self.key)

        def oracle(number, byte, mask):
            ciphertext, _ = piret_sm4.sm4_fault_encrypt(self.plaintext, self.key, byte, mask, number)
            return ciphertext

        result = piret_sm4.recover_sm4_master_key(correct, oracle, masks=(3,))
        self.assertFalse(result["complete"])
        self.assertIsNone(result["master_key"])

    def test_invalid_pass_through_fault_is_rejected(self):
        correct = sm4.sm4_encrypt_block(self.plaintext, self.key)

        with self.assertRaises(ValueError):
            piret_sm4.sm4_byte_candidates(correct, correct, 0, 3)

        with self.assertRaises(ValueError):
            piret_sm4.sm4_fault_encrypt(self.plaintext, self.key, 0, 3, word=0)

    def test_html_contains_all_guesses_and_overwrites_previous_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.html"
            path.write_text("OLD CONTENT", encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                status = piret_sm4.main(["--log", str(path), "--color", "never"])

            self.assertEqual(status, 0)
            report = path.read_text(encoding="utf-8")
            self.assertNotIn("OLD CONTENT", report)
            self.assertIn('class="red"', report)
            self.assertEqual(report.count("k=00:"), 32)
            self.assertEqual(report.count("k=FF:"), 32)
            self.assertIn("Recovered master key: 0123456789ABCDEFFEDCBA9876543210", report)
            self.assertTrue(path.with_suffix(".txt").exists())


if __name__ == "__main__":
    unittest.main()
