"""Check exhaustive candidate reporting and full GUI recovery timelines."""
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import aes
import sm4
import piret_aes
import piret_sm4
import giraud_aes
import giraud_sm4
import gui
import attack_steps


class DetailedAttackTests(unittest.TestCase):
    def test_piret_reports_every_guess_pattern_and_exact_intersection(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)

        correct = aes.aes_encrypt(plaintext, key)

        previous = None

        for mask in (1, 2):
            faulty = piret_aes.encrypt_with_trace(plaintext, key, mask=mask, fault_round=9)[0]
            events = list(attack_steps.aes_piret(correct, faulty, 0, previous))
            formatted_values = []

            for event in events:
                formatted_values.append(event['detail'])

            text = '\n'.join(formatted_values)
            self.assertEqual(len(re.findall(r'^k=[0-9A-F]{2}:', text, re.M)), 1024)
            self.assertEqual(len(re.findall(r'^e=[0-9A-F]{2};', text, re.M)), 1020)
            fresh = piret_aes.key_candidates(correct, faulty, 0)

            if previous is None:
                previous = fresh
            else:
                previous = previous & fresh

            final = events[-1]['detail'].split(f'Intersection: {len(previous)} tuples\n')[1]

            for candidate in previous:
                self.assertIn(bytes(candidate).hex().upper(), final)

        self.assertEqual(len(previous), 1)

    def test_giraud_reports_rejections_and_acceptances(self):
        key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)

        correct = aes.aes_encrypt(plaintext, key)

        faulty = giraud_aes.aes_fault_encrypt(plaintext, key, 5, 4)[0]

        position, expected = giraud_aes.aes_candidates(correct, faulty)

        events = list(attack_steps.aes_giraud(correct, faulty, position))

        text = events[0]['detail']

        self.assertEqual(len(re.findall(r'^k=', text, re.M)), 256)

        self.assertEqual(text.count('/ ACCEPT'), len(expected))

        self.assertEqual(text.count('/ REJECT'), 256-len(expected))

    def test_sm4_exhaustive_tests_match_unknown_and_known_bit_solvers(self):
        key = bytes.fromhex(sm4.KEY)

        correct = sm4.sm4_encrypt_block(key, key)

        for known_bit in (False, True):
            previous = {}

            def observe(event):
                identity = event['round'], event['byte']
                events = list(attack_steps.sm4_observation(event, previous.get(identity), known_bit))
                self.assertEqual(len(re.findall(r'^a=', events[-2]['detail'], re.M)), 256)
                self.assertEqual(len(re.findall(r'^bit ', events[-3]['detail'], re.M)), 32)
                previous[identity] = set(event['survivors'])

            def oracle(number, byte, mask):
                return piret_sm4.sm4_fault_encrypt(key, key, byte, mask, number)[0]

            result = giraud_sm4.recover_sm4_master_key(correct, oracle, known_bit=known_bit, observer=observe)
            self.assertEqual(result['master_key'], key)

    def test_gui_exposes_every_reversed_word_and_verification(self):
        for algorithm, key_text, block_text in [('AES-128', aes.KEY, aes.PLAINTEXT), ('SM4', sm4.KEY, sm4.PLAINTEXT)]:
            key, block = bytes.fromhex(key_text), bytes.fromhex(block_text)

            if algorithm == 'AES-128':
                lessons_2 = gui.pdf_aes_lesson(block, key, 0, 0, 1, 8)
            else:
                lessons_2 = gui.pdf_sm4_lesson(block, key, 0, 1, 8)

            lessons = [lessons_2, gui.giraud_lesson(algorithm, block, key, maximum=8)]

            for report in lessons:
                self.assertTrue(report['verified'])
                self.assertEqual(report['recovered_key'], key.hex())

                if algorithm == 'AES-128':
                    prefix = 'Reverse AES schedule:'
                else:
                    prefix = 'Reverse SM4 schedule:'

                element_values_2 = []

                for event_2 in report['steps']:
                    element_values_2.append(event_2['title'].startswith(prefix))

                if algorithm == 'AES-128':
                    element_values = 40
                else:
                    element_values = 32

                self.assertEqual(sum(element_values_2), element_values)
                has_match = False

                for event in report['steps']:
                    if 'Decrypt(C, recovered key)' in event['detail']:
                        has_match = True
                        break

                self.assertTrue(has_match)


if __name__ == '__main__':
    unittest.main()
