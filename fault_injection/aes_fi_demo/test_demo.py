"""Validate cryptographic results and propagation patterns used in the presentation."""
import random
import unittest

import aes_reference as aes
from demo import KEY, PLAINTEXT, EXPECTED, Fault, encrypt_trace, compare


class DemoTests(unittest.TestCase):
    def test_fips197_known_answer(self):
        self.assertEqual(encrypt_trace(KEY, PLAINTEXT)[0], EXPECTED)

    def test_instrumentation_matches_original(self):
        rng = random.Random(42)
        for _ in range(30):
            key = bytes(rng.randrange(256) for _ in range(16))
            block = bytes(rng.randrange(256) for _ in range(16))
            self.assertEqual(encrypt_trace(key, block)[0], aes.AES(key).encrypt_block(block))

    def test_round9_all_positions_and_nonzero_masks(self):
        _, clean = encrypt_trace(KEY, PLAINTEXT)
        for row in range(4):
            for column in range(4):
                for mask in (1, 0x55, 0x80, 0xff):
                    _, faulty = encrypt_trace(KEY, PLAINTEXT, Fault(row=row, column=column, mask=mask))
                    steps = compare(clean, faulty)
                    by_label = {s['label']: s for s in steps}
                    self.assertEqual(by_label['R09 after ShiftRows']['bytes_changed'], 0)
                    self.assertEqual(by_label['R09 before MixColumns']['bytes_changed'], 1)
                    self.assertEqual(by_label['R09 after MixColumns']['bytes_changed'], 4)
                    actual = {i for i, d in enumerate(steps[-1]['delta']) if d}
                    expected = {4 * ((column - r) % 4) + r for r in range(4)}
                    self.assertEqual(actual, expected)
                    # The identical round key cancels in the XOR of both executions.
                    self.assertEqual(by_label['R09 before AddRoundKey']['delta'],
                                     by_label['R09 after AddRoundKey']['delta'])

    def test_last_round_late_fault_affects_one_byte(self):
        _, clean = encrypt_trace(KEY, PLAINTEXT)
        for stage in ('SubBytes', 'ShiftRows', 'AddRoundKey'):
            _, faulty = encrypt_trace(KEY, PLAINTEXT, Fault(round=10, stage=stage))
            self.assertEqual(compare(clean, faulty)[-1]['bytes_changed'], 1)

    def test_reject_invalid_faults(self):
        for kwargs in ({'round': 0}, {'round': 11}, {'round': 10}, {'mask': 0},
                       {'mask': 256}, {'row': 4}, {'column': -1}, {'stage': 'invalid'}):
            with self.assertRaises(ValueError):
                Fault(**kwargs)

    def test_reject_wrong_block_and_key_sizes(self):
        with self.assertRaises(ValueError):
            encrypt_trace(bytes(24), PLAINTEXT)
        with self.assertRaises(ValueError):
            encrypt_trace(KEY, bytes(15))


if __name__ == '__main__':
    unittest.main()
