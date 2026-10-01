"""Known vectors, independent oracle, and ciphertext-only DFA regression tests."""
import random
import shutil
import subprocess
import unittest
from pathlib import Path
import fault_injection.piret_attack.piret as dfa

aes = dfa.aes


class LessonsTest(unittest.TestCase):
    def test_fips_vector_and_intermediate_states(self):
        states = {}
        result = aes.encrypt_block(aes.PLAINTEXT, aes.KEY,
                                   trace=lambda r, op, s: states.update({(r, op): s}))
        self.assertEqual(result, aes.CIPHERTEXT)
        self.assertEqual(states[0, 'AddRoundKey'].hex(), '00102030405060708090a0b0c0d0e0f0')
        self.assertEqual(states[1, 'SubBytes'].hex(), '63cab7040953d051cd60e0e7ba70e18c')
        self.assertEqual(states[1, 'MixColumns'].hex(), '5f72641557f5bc92f7be3b291db9f91a')
        self.assertNotIn((10, 'MixColumns'), states)
        self.assertEqual(aes.decrypt_block(result, aes.KEY), aes.PLAINTEXT)

    def test_random_against_openssl(self):
        openssl = shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe'
        if not Path(openssl).exists():
            self.skipTest('OpenSSL is not available.')
        rng = random.Random(128)
        for _ in range(20):
            key, block = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
            expected = subprocess.check_output([openssl, 'enc', '-aes-128-ecb', '-nopad', '-K', key.hex()], input=block)
            self.assertEqual(aes.encrypt_block(block, key), expected)
            self.assertEqual(aes.decrypt_block(expected, key), block)
            self.assertEqual(aes.reverse_key_schedule(aes.expand_key(key)[10]), key)

    def test_recovery_all_sixteen_fault_positions(self):
        rng = random.Random(2003)
        for row in range(4):
            for column in range(4):
                key, block = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
                correct = aes.encrypt_block(block, key)
                masks = rng.sample(range(1, 256), 8)
                outputs = [aes.encrypt_block(block, key, aes.Fault(8, row, column, mask)) for mask in masks]
                recovered, _, _ = dfa.recover_last_key(correct, outputs)
                self.assertIsNotNone(recovered, (row, column))
                self.assertEqual(aes.reverse_key_schedule(recovered), key)

    def test_ambiguity_and_wrong_fault_model(self):
        correct = aes.encrypt_block(aes.PLAINTEXT, aes.KEY)
        faulty = aes.encrypt_block(aes.PLAINTEXT, aes.KEY, aes.Fault())
        recovered, groups, _ = dfa.recover_last_key(correct, [faulty, faulty])
        self.assertIsNone(recovered)
        self.assertTrue(all(len(group) > 1 for group in groups))
        with self.assertRaises(ValueError):
            dfa.recover_last_key(correct, [correct])
        round9 = aes.encrypt_block(aes.PLAINTEXT, aes.KEY, aes.Fault(round=9))
        with self.assertRaises(ValueError):
            dfa.recover_last_key(correct, [round9])

    def test_invalid_inputs(self):
        for value in (b'', bytes(15), bytes(17)):
            with self.assertRaises(ValueError):
                aes.encrypt_block(value, aes.KEY)
            with self.assertRaises(ValueError):
                aes.expand_key(value)
        with self.assertRaises(ValueError):
            aes.Fault(mask=0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
