"""Host protocol tests and native tests of the actual firmware AES backend."""
import importlib.util
from pathlib import Path
import random
import shutil
import subprocess
import unittest
from unittest.mock import MagicMock

from Crypto.Cipher import AES

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('aes_capture', HERE / 'aes_capture.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


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


if __name__ == '__main__':
    unittest.main()
