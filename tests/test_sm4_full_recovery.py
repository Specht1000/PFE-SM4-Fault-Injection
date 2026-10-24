"""Full recovery must work without schedule access or supplied reference keys."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import sm4
import piret
import giraud


class FullSM4Tests(unittest.TestCase):
    def test_random_keys_without_reference_schedule_access(self):
        rng = random.Random(128)
        masks = set(range(1, 9)) | set(giraud.SINGLE_BITS)
        for _ in range(8):
            key, plaintext = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
            correct = sm4.sm4_encrypt_block(plaintext, key)
            truth = sm4.key_expansion(key)
            # Prepare an opaque oracle: the solver sees output bytes only.
            outputs = {(r,b,m): piret.sm4_fault_encrypt(plaintext,key,b,m,r)[0] for r in range(28,32) for b in range(4) for m in masks}

            def oracle(number, byte, mask):
                return outputs[number, byte, mask]

            for attack, options in [(piret, {}), (giraud, {}), (giraud, dict(known_bit=True))]:
                with patch.object(sm4, "key_expansion", side_effect=AssertionError("Solver must not read a reference schedule")):
                    result = attack.recover_sm4_master_key(correct, oracle, **options)
                self.assertTrue(result['complete'])
                self.assertEqual(result['master_key'], key)
                self.assertEqual(result['round_keys'], {r: truth[r] for r in range(31,27,-1)})
                self.assertEqual(sm4.sm4_encrypt_block(plaintext,result['master_key']),correct)
                for event in result['history']:
                    expected_later = {str(r) for r in range(31,event['round'],-1)}
                    self.assertEqual(set(event['peeled_with']),expected_later)
                    self.assertGreaterEqual(event['before'],event['remaining'])

    def test_peeling_matches_actual_round_states(self):
        key = bytes.fromhex(sm4.KEY)
        plaintext = bytes.fromhex(sm4.PLAINTEXT)
        states = {}

        def record(number, operation, value):
            if operation == 'State output':
                states[number] = b''.join(v.to_bytes(4,'big') for v in value[::-1])

        ciphertext = sm4.sm4_encrypt_block(plaintext,key,observer=record)
        truth = sm4.key_expansion(key)
        for number in range(28,32):
            later = {r: truth[r] for r in range(number+1,32)}
            self.assertEqual(piret.peel_sm4(ciphertext,number,later),states[number])
        with self.assertRaises(ValueError):
            piret.peel_sm4(ciphertext,28,{})

    def test_ambiguity_stops_before_using_an_unknown_subkey(self):
        key = bytes.fromhex(sm4.KEY)
        correct = sm4.sm4_encrypt_block(key,key)
        queries = []

        def oracle(number, byte, mask):
            queries.append(number)
            return piret.sm4_fault_encrypt(key,key,byte,mask,number)[0]

        result = piret.recover_sm4_master_key(correct,oracle,masks=(1,))
        self.assertFalse(result['complete'])
        self.assertIsNone(result['master_key'])
        self.assertEqual(result['round_keys'],{})
        self.assertEqual(set(queries),{31})
        with self.assertRaises(ValueError):
            piret.recover_sm4_master_key(correct,lambda r,b,m: correct)

    def test_terminal_entry_points(self):
        for entry, arguments in [(piret.main, ['--algorithm','sm4','--color','never']), (giraud.main,['--algorithm','sm4','--color','never'])]:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(entry(arguments),0)
            self.assertIn(sm4.KEY.upper(),output.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
