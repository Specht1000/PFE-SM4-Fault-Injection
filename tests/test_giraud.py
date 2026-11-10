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
import giraud_aes
import giraud_sm4
import gui as lab
import run as simulator


class GiraudTests(unittest.TestCase):
    def test_terminal_explains_full_schedules_in_both_bit_models(self):
        import re

        for algorithm in ('aes', 'sm4'):
            for known_bit in (False, True):
                with self.subTest(algorithm=algorithm, known_bit=known_bit):
                    output = io.StringIO()

                    if known_bit:
                        arguments_2 = ['--known-bit']
                    else:
                        arguments_2 = []

                    arguments = ['--algorithm', algorithm, '--color', 'never'] + arguments_2

                    with redirect_stdout(output):
                        if algorithm == 'aes':
                            entry = giraud_aes.main
                        else:
                            entry = giraud_sm4.main

                        self.assertEqual(entry(arguments), 0)

                    text = output.getvalue()

                    if algorithm == 'aes':
                        keys = aes.key_expansion(bytes.fromhex(aes.KEY))
                        derived = dict(re.findall(r'DERIVED K(\d+) = ([0-9A-F]{32})', text))
                        element_values_2 = {}

                        for index_2 in range(10):
                            element_values_2[str(index_2)] = aes.state_to_bytes(keys[index_2]).hex().upper()

                        self.assertEqual(derived, element_values_2)
                        self.assertEqual(len(re.findall(r'RECOVERED K10 byte \d+ =', text)), 16)
                        equations = re.findall(r'w\[\d+\] = w\[\d+\] XOR T\(w\[\d+\]\) = ([0-9A-F]{8}) XOR ([0-9A-F]{8}) = ([0-9A-F]{8})', text)
                        self.assertEqual(len(equations), 40)

                        for left, right, result in equations:
                            self.assertEqual(int(left, 16) ^ int(right, 16), int(result, 16))
                    else:
                        keys = sm4.key_expansion(bytes.fromhex(sm4.KEY))
                        derived = dict(re.findall(r'DERIVED rk(\d+) = ([0-9A-F]{8})', text))
                        element_values = {}

                        for index in range(28):
                            element_values[str(index)] = f'{keys[index]:08X}'

                        self.assertEqual(derived, element_values)

                        for number in range(28, 32):
                            self.assertIn(f'DFA ASSEMBLED rk{number} = {keys[number]:08X}', text)

                        self.assertIn('MK[0] = K[0] XOR FK[0]', text)

                    self.assertIn('Recovered-key ciphertext:', text)

                    if not known_bit:
                        self.assertIn('Allowed input errors: 01 02 04 08 10 20 40 80', text)
                        self.assertIn('NOT given to the candidate solver', text)
                    else:
                        self.assertNotIn('Allowed input errors: 01 02 04 08 10 20 40 80', text)

    def test_terminal_main(self):
        output = io.StringIO()

        with redirect_stdout(output), patch("builtins.input", return_value=""):
            self.assertEqual(giraud_aes.main(["--step", "--color", "never"]), 0)
            self.assertEqual(giraud_sm4.main(["--step", "--color", "never"]), 0)

        self.assertIn("Recovered master key: " + aes.KEY.upper(), output.getvalue())

        self.assertIn("Recovered rk31: 9124A012", output.getvalue())

        self.assertNotIn("\033[", output.getvalue())

        output = io.StringIO()

        with redirect_stdout(output):
            self.assertEqual(giraud_aes.main(["--algorithm", "aes", "--known-bit", "--color", "never"]), 0)

        self.assertIn("Bit known to solver: True", output.getvalue())

        with redirect_stdout(io.StringIO()):
            self.assertEqual(giraud_aes.main(["--observations", "1", "--color", "never"]), 2)

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
            if known:
                element_values_2 = 1
            else:
                element_values_2 = None

            a = giraud_aes.aes_candidates(correct, first, element_values_2)[1]

            if known:
                element_values = 2
            else:
                element_values = None

            b = giraud_aes.aes_candidates(correct, second, element_values)[1]
            self.assertEqual(a & b, {0x13})

    def test_pdf_sm4_example(self):
        key = bytes.fromhex(sm4.KEY)

        correct, _ = simulator.sm4_encrypt(key, key)

        first, _ = simulator.sm4_encrypt(key, key, 0, 1)

        self.assertEqual(first.hex(), "1b50e209d206965e86b3e94f536e4246")

        position, guesses, inputs, delta = giraud_sm4.sm4_candidates(correct, first, 1)

        self.assertEqual((position, inputs, delta), (0, {0x96, 0x97}, 0x4F000000))

        self.assertEqual(guesses, {0x91, 0x90})

        second, _ = simulator.sm4_encrypt(key, key, 0, 2)

        self.assertEqual(guesses & giraud_sm4.sm4_candidates(correct, second, 2)[1], {0x91})

    def test_all_aes_positions_and_known_bit_is_stronger(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)

        correct, _ = lab.aes_giraud_encrypt(plaintext, key)

        last_key = aes.state_to_bytes(aes.key_expansion(key)[10])

        for byte in range(16):
            for mask in giraud_aes.SINGLE_BITS:
                faulty, _ = lab.aes_giraud_encrypt(plaintext, key, byte, mask)
                position, unknown = giraud_aes.aes_candidates(correct, faulty)
                _, known = giraud_aes.aes_candidates(correct, faulty, mask)
                expected = 4 * ((byte // 4 - byte % 4) % 4) + byte % 4
                self.assertEqual(position, expected)
                self.assertIn(last_key[position], known)
                self.assertLessEqual(known, unknown)

    def test_random_key_recovery_both_models(self):
        rng = random.Random(2004)

        for _ in range(8):
            computed_value_values = []

            for unused_index in range(2):
                byte_values = []

                for candidate_input in range(16):
                    byte_values.append(rng.randrange(256))

                computed_value_values.append(bytes(byte_values))

            key, plaintext = computed_value_values

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
            giraud_aes.aes_candidates(correct, correct)

        with self.assertRaises(ValueError):
            giraud_aes.masks_for(1, 9)

        for algorithm in ("AES-128", "SM4"):
            result = lab.giraud_lesson(algorithm, plaintext, key, maximum=1)
            self.assertFalse(result["verified"])
            self.assertIsNone(result["recovered_key"])

        first, _ = lab.aes_giraud_encrypt(plaintext, key, 0, 1)

        second, _ = lab.aes_giraud_encrypt(plaintext, key, 0, 2)

        position, survivors = giraud_aes.recover_byte([(correct, first), (correct, second)])

        self.assertEqual((position, survivors), (0, {0x13}))

        other, _ = lab.aes_giraud_encrypt(plaintext, key, 1, 1)

        with self.assertRaises(ValueError):
            giraud_aes.recover_byte([(correct, first), (correct, other)])

        with self.assertRaises(ValueError):
            giraud_aes.intersect_candidates({1}, {2})

        self.assertEqual(giraud_sm4.recover_byte([]), (None, None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
