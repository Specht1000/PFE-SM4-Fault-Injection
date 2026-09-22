"""Host protocol tests and native tests of the actual firmware AES backend."""
import importlib.util
from pathlib import Path
import random
import sys
import io
from contextlib import redirect_stdout
import shutil
import subprocess
import unittest
from unittest.mock import MagicMock

from Crypto.Cipher import AES

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('aes_capture', HERE / 'aes_capture.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
sys.path.insert(0, str(HERE))
import aes_terminal as terminal
reference_spec = importlib.util.spec_from_file_location(
    'aes_reference', HERE.parents[1] / 'fault_injection/aes_fi_demo/aes_reference.py')
reference = importlib.util.module_from_spec(reference_spec)
reference_spec.loader.exec_module(reference)


class TerminalTests(unittest.TestCase):
    def test_text_padding_and_utf8(self):
        raw, padded = terminal.prepare_input('hello', 'text')
        self.assertEqual(raw, b'hello')
        self.assertEqual(padded, b'hello' + bytes([11]) * 11)
        self.assertEqual(len(terminal.prepare_input('A' * 16, 'text')[1]), 32)
        self.assertEqual(terminal.prepare_input('', 'text')[1], bytes([16]) * 16)
        self.assertEqual(terminal.prepare_input('\u00e9', 'text')[0], b'\xc3\xa9')

    def test_raw_hex_and_invalid_input(self):
        self.assertEqual(terminal.prepare_input(host.PLAINTEXT.hex(), 'hex'),
                         (host.PLAINTEXT, host.PLAINTEXT))
        for invalid in ('', 'abc', 'zz' * 16, '00' * 15):
            with self.assertRaises(ValueError):
                terminal.prepare_input(invalid, 'hex')

    def test_reject_snapshot_headers_and_endpoints(self):
        with self.assertRaises(RuntimeError):
            terminal.decode_snapshot(bytes(18), 0)
        with self.assertRaises(RuntimeError):
            terminal.decode_snapshot(bytes([0, 0, 4]) + bytes(16), 0)
        target = MagicMock()
        target.simpleserial_wait_ack.return_value = 0
        packets = [bytes([i, *step]) + bytes(16) for i, step in enumerate(terminal.STEPS)]
        target.simpleserial_read.side_effect = [host.CIPHERTEXT] + packets
        with self.assertRaises(RuntimeError):
            terminal.fetch_trace(target, host.PLAINTEXT)

    def test_multiblock_terminal_uses_target_responses(self):
        raw, padded = terminal.prepare_input('This message spans several blocks.', 'text')
        expected = AES.new(host.KEY, AES.MODE_ECB).encrypt(padded)
        target = MagicMock()
        target.simpleserial_wait_ack.return_value = 0
        target.simpleserial_read.side_effect = [expected[i:i + 16] for i in range(0, len(expected), 16)]
        with redirect_stdout(io.StringIO()) as output:
            actual = terminal.process_message(target, raw.decode(), 'text', host.KEY, trace=False)
        self.assertEqual(actual, expected)
        self.assertIn(expected.hex(), output.getvalue())


class ProtocolTests(unittest.TestCase):
    def test_known_answer_and_identity(self):
        target = MagicMock()
        target.simpleserial_read.side_effect = [host.IDENTITY, host.CIPHERTEXT]
        target.simpleserial_wait_ack.return_value = 0
        host.verify(target)
        self.assertEqual(target.simpleserial_wait_ack.call_count, 3)

    def test_missing_and_error_ack(self):
        for status in (None, 1, 2):
            target = MagicMock()
            target.simpleserial_wait_ack.return_value = status
            with self.assertRaises(RuntimeError):
                host.require_ack(target)

    def test_missing_and_short_response(self):
        for response in (None, b'', bytes(15)):
            target = MagicMock()
            target.simpleserial_read.return_value = response
            with self.assertRaises(RuntimeError):
                host.read_response(target, 16)

    def test_wrong_firmware(self):
        target = MagicMock()
        target.simpleserial_wait_ack.return_value = 0
        target.simpleserial_read.return_value = b'BAD!'
        with self.assertRaises(RuntimeError):
            host.identify(target)

    def test_wrong_ciphertext(self):
        target = MagicMock()
        target.simpleserial_read.side_effect = [host.IDENTITY, bytes(16)]
        target.simpleserial_wait_ack.return_value = 0
        with self.assertRaises(RuntimeError):
            host.verify(target)

    def test_capture_timeout(self):
        scope, target = MagicMock(), MagicMock()
        scope.capture.return_value = True
        with self.assertRaises(RuntimeError):
            host.capture_one(scope, target, host.PLAINTEXT, host.CIPHERTEXT)
        target.simpleserial_read.assert_not_called()

    def test_capture_and_ciphertext_validation(self):
        scope, target = MagicMock(), MagicMock()
        scope.capture.return_value = False
        scope.adc.samples = 4
        scope.get_last_trace.return_value = [0.1, 0.2, -0.1, 0]
        target.simpleserial_read.return_value = host.CIPHERTEXT
        target.simpleserial_wait_ack.return_value = 0
        ciphertext, wave = host.capture_one(scope, target, host.PLAINTEXT, host.CIPHERTEXT)
        self.assertEqual(ciphertext, host.CIPHERTEXT)
        self.assertEqual(len(wave), 4)
        scope.get_last_trace.return_value = []
        with self.assertRaises(RuntimeError):
            host.capture_one(scope, target, host.PLAINTEXT, host.CIPHERTEXT)
        target.simpleserial_read.return_value = bytes(16)
        with self.assertRaises(RuntimeError):
            host.capture_one(scope, target, host.PLAINTEXT, host.CIPHERTEXT)


class NativeFirmwareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('gcc')
        if compiler is None:
            raise unittest.SkipTest('Native gcc is required for firmware callback tests.')
        roots = (HERE.parents[1] / 'chipwhisperer', HERE.parents[1] / 'third_party/chipwhisperer')
        crypto = next((root / 'firmware/mcu/crypto' for root in roots
                       if (root / 'firmware/mcu/crypto').is_dir()), None)
        if crypto is None:
            raise unittest.SkipTest('Download the upstream firmware sources first.')
        (HERE / 'build').mkdir(exist_ok=True)
        cls.binary = HERE / 'build/native_firmware_test.exe'
        command = [compiler, '-std=c99', '-DTINYAES128C', '-I' + str(HERE / 'tests/stubs'),
                   '-I' + str(crypto), '-I' + str(crypto / 'tiny-AES128-C'),
                   str(HERE / 'tests/native_firmware.c'), str(crypto / 'aes-independant.c'),
                   str(HERE / 'firmware/aes_trace.c'),
                   str(crypto / 'tiny-AES128-C/aes.c'), '-o', str(cls.binary)]
        subprocess.run(command, check=True, capture_output=True, text=True)

    def check_vector(self, key, plaintext, expected):
        actual = subprocess.check_output([str(self.binary), key.hex(), plaintext.hex()], text=True).strip()
        self.assertEqual(actual, expected.hex())

    def test_fips197_vector(self):
        self.check_vector(host.KEY, host.PLAINTEXT, host.CIPHERTEXT)

    def test_zero_vector(self):
        self.check_vector(bytes(16), bytes(16), bytes.fromhex('66e94bd4ef8a2c3b884cfa59ca342b2e'))

    def test_random_vectors_against_independent_aes(self):
        rng = random.Random(2026)
        for _ in range(32):
            key = bytes(rng.randrange(256) for _ in range(16))
            block = bytes(rng.randrange(256) for _ in range(16))
            self.check_vector(key, block, AES.new(key, AES.MODE_ECB).encrypt(block))

    def test_all_intermediate_states_and_terminal_transport(self):
        for key, block in ((host.KEY, host.PLAINTEXT), (bytes(16), bytes(16)),
                           (bytes(reversed(range(16))), bytes(range(16)))):
            lines = subprocess.check_output([str(self.binary), key.hex(), block.hex(), '--trace'], text=True).splitlines()
            packets = [bytes.fromhex(line) for line in lines[1:]]
            state = reference.bytes2matrix(block)
            keys = reference.AES(key)._key_matrices
            expected = [block]
            reference.add_round_key(state, keys[0])
            expected.append(reference.matrix2bytes(state))
            for rnd in range(1, 11):
                for operation in (reference.sub_bytes, reference.shift_rows):
                    operation(state)
                    expected.append(reference.matrix2bytes(state))
                if rnd < 10:
                    reference.mix_columns(state)
                    expected.append(reference.matrix2bytes(state))
                reference.add_round_key(state, keys[rnd])
                expected.append(reference.matrix2bytes(state))
            self.assertEqual(len(packets), 41)
            for index, packet in enumerate(packets):
                self.assertEqual(terminal.decode_snapshot(packet, index)['state'], expected[index])
            target = MagicMock()
            target.simpleserial_wait_ack.return_value = 0
            target.simpleserial_read.side_effect = [bytes.fromhex(lines[0])] + packets
            with redirect_stdout(io.StringIO()) as output:
                result = terminal.process_message(target, block.hex(), 'hex', key, matrix=True)
            self.assertEqual(result, AES.new(key, AES.MODE_ECB).encrypt(block))
            self.assertIn('R10 AddRoundKey', output.getvalue())


if __name__ == '__main__':
    unittest.main()
