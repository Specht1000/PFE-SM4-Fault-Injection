"""Tests for the Giraud single-bit DFA on AES-128."""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import giraud  # noqa: E402
import aes_reference as aes  # noqa: E402


class GiraudTests(unittest.TestCase):
    @staticmethod
    def last_round_key(key):
        return bytes(b for word in aes.AES(key)._key_matrices[10] for b in word)

    def test_known_answer_recovers_key(self):
        recovered = giraud.recover_last_round_key(giraud.KEY, giraud.PLAINTEXT)
        self.assertEqual(recovered, self.last_round_key(giraud.KEY))
        self.assertEqual(giraud.invert_key_schedule(recovered), giraud.KEY)

    def test_key_schedule_inversion_roundtrip(self):
        for _ in range(20):
            key = os.urandom(16)
            self.assertEqual(giraud.invert_key_schedule(self.last_round_key(key)), key)

    def test_full_attack_on_random_instances(self):
        for _ in range(5):
            key, plaintext = os.urandom(16), os.urandom(16)
            k10 = giraud.recover_last_round_key(key, plaintext)
            self.assertEqual(giraud.invert_key_schedule(k10), key)

    def test_single_bit_fault_changes_one_output_byte(self):
        correct = giraud.encrypt(giraud.KEY, giraud.PLAINTEXT)
        faulty = giraud.fault_ciphertext(giraud.KEY, giraud.PLAINTEXT, row=0, column=0, mask=0x01)
        self.assertEqual(sum(a != b for a, b in zip(correct, faulty)), 1)


if __name__ == '__main__':
    unittest.main()
