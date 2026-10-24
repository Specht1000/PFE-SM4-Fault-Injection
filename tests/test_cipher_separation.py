"""Attacks must execute the actual ciphers, then leave normal calls unchanged."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import aes
import sm4
import piret
import giraud


class CipherSeparationTests(unittest.TestCase):
    def test_normal_ciphers_are_quiet_and_round_trip(self):
        output = io.StringIO()
        with redirect_stdout(output):
            for module, encrypt, decrypt in [(aes, aes.aes_encrypt, aes.aes_decrypt), (sm4, sm4.sm4_encrypt_block, sm4.sm4_decrypt_block)]:
                key, plaintext = bytes.fromhex(module.KEY), bytes.fromhex(module.PLAINTEXT)
                ciphertext = encrypt(plaintext, key)
                self.assertEqual(decrypt(ciphertext, key), plaintext)
        self.assertEqual(output.getvalue(), "")

    def test_aes_attacks_intervene_in_the_real_engine(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)
        clean = aes.aes_encrypt(plaintext, key)
        with patch.object(aes, "aes_encrypt", wraps=aes.aes_encrypt) as engine:
            piret_output, _ = piret.encrypt_with_trace(plaintext, key, mask=1, fault_round=9)
            self.assertEqual(engine.call_count, 1)
            self.assertIsNotNone(engine.call_args.kwargs["observer"])
        with patch.object(aes, "aes_encrypt", wraps=aes.aes_encrypt) as engine:
            giraud_output, _ = giraud.aes_fault_encrypt(plaintext, key, 0, 1)
            self.assertEqual(engine.call_count, 1)
        self.assertEqual(sum(a != b for a, b in zip(clean, piret_output)), 4)
        self.assertEqual(sum(a != b for a, b in zip(clean, giraud_output)), 1)
        self.assertEqual(aes.aes_encrypt(plaintext, key), clean)

    def test_sm4_attacks_intervene_in_the_real_engine(self):
        key, plaintext = bytes.fromhex(sm4.KEY), bytes.fromhex(sm4.PLAINTEXT)
        clean = sm4.sm4_encrypt_block(plaintext, key)
        for experiment in (piret.sm4_fault_encrypt, giraud.sm4_fault_encrypt):
            with patch.object(sm4, "sm4_encrypt_block", wraps=sm4.sm4_encrypt_block) as engine:
                faulty, _ = experiment(plaintext, key, 0, 1)
                self.assertEqual(engine.call_count, 1)
                self.assertIsNotNone(engine.call_args.kwargs["observer"])
            self.assertEqual(clean[4:], faulty[4:])
            self.assertNotEqual(clean[:4], faulty[:4])
            self.assertEqual(sm4.sm4_encrypt_block(plaintext, key), clean)


if __name__ == "__main__":
    unittest.main(verbosity=2)
