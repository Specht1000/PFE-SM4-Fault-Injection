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
    def test_fault_settings_and_interactive_commands(self):
        fault = terminal.parse_fault_command('/fault on')
        self.assertEqual(fault.wire_bytes(), bytes([9, 3, 0, 0, 1]))
        self.assertIsNone(terminal.parse_fault_command('/fault off', fault))
        fault = terminal.parse_fault_command('/fault 8 SubBytes 2 1 0x55 2')
        self.assertEqual(fault.wire_bytes(), bytes([8, 1, 2, 1, 0x55]))
        self.assertEqual(fault.block, 2)
        for parameters in ({'round': 0}, {'round': 11}, {'round': 10}, {'mask': 0},
                           {'mask': 256}, {'row': 4}, {'column': -1}, {'block': 0}, {'stage': 'Input'}):
            with self.assertRaises(ValueError):
                terminal.FaultSettings(**parameters)

    def test_fault_block_and_event_validation(self):
        target = MagicMock()
        with self.assertRaises(ValueError):
            terminal.process_fault_message(target, host.PLAINTEXT.hex(), 'hex', host.KEY,
                                           terminal.FaultSettings(block=2))
        target.simpleserial_write.assert_not_called()
        target.simpleserial_read.return_value = bytes(18)
        target.simpleserial_wait_ack.return_value = 0
        with self.assertRaises(RuntimeError):
            terminal.fetch_fault_trace(target, host.PLAINTEXT, terminal.FaultSettings())
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
        target.simpleserial_read.side_effect = [block for i in range(0, len(expected), 16)
                                              for block in (expected[i:i + 16], padded[i:i + 16])]
        with redirect_stdout(io.StringIO()) as output:
            actual = terminal.process_message(target, raw.decode(), 'text', host.KEY, trace=False)
        self.assertEqual(actual, expected)
        self.assertIn(expected.hex(), output.getvalue())
        self.assertIn('original plaintext: PASS', output.getvalue())

    def test_standalone_decryption_and_unpadding(self):
        original = b'Hello STM32!'
        padded = original + bytes([4]) * 4
        ciphertext = AES.new(host.KEY, AES.MODE_ECB).encrypt(padded)
        target = MagicMock()
        target.simpleserial_wait_ack.return_value = 0
        target.simpleserial_read.return_value = padded
        with redirect_stdout(io.StringIO()):
            result = terminal.process_decryption(target, ciphertext.hex(), host.KEY, unpad=True)
        self.assertEqual(result, original)
        target.simpleserial_write.assert_called_once_with('d', bytearray(ciphertext))

    def test_reject_invalid_padding(self):
        for invalid in (b'', bytes(15), bytes(16), bytes([17]) * 16,
                        b'A' * 14 + bytes([1, 2])):
            with self.assertRaises(ValueError):
                terminal.unpad_pkcs7(invalid)

    def test_reject_wrong_decryption_result(self):
        target = MagicMock()
        target.simpleserial_wait_ack.return_value = 0
        target.simpleserial_read.side_effect = [host.CIPHERTEXT, bytes(16)]
        with redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            terminal.process_message(target, host.PLAINTEXT.hex(), 'hex', host.KEY, trace=False)


class ProtocolTests(unittest.TestCase):
    def test_known_answer_and_identity(self):
        target = MagicMock()
        target.simpleserial_read.side_effect = [host.IDENTITY, host.CIPHERTEXT, host.PLAINTEXT]
        target.simpleserial_wait_ack.return_value = 0
        host.verify(target)
        self.assertEqual(target.simpleserial_wait_ack.call_count, 4)

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
            target.simpleserial_read.side_effect = [bytes.fromhex(lines[0])] + packets + [block]
            with redirect_stdout(io.StringIO()) as output:
                result = terminal.process_message(target, block.hex(), 'hex', key, matrix=True)
            self.assertEqual(result, AES.new(key, AES.MODE_ECB).encrypt(block))
            self.assertIn('R10 AddRoundKey', output.getvalue())

    def run_fault(self, fault):
        args = [str(self.binary), host.KEY.hex(), host.PLAINTEXT.hex(), '--fault']
        args.extend(str(value) for value in fault.wire_bytes())
        lines = subprocess.check_output(args, text=True).splitlines()
        clean, faulty, event = (bytes.fromhex(line) for line in lines[:3])
        packets = [bytes.fromhex(line) for line in lines[3:44]]
        recovered, clean_again = (bytes.fromhex(line) for line in lines[44:])
        self.assertEqual(clean, host.CIPHERTEXT)
        self.assertEqual(clean_again, clean, 'Fault must not persist into later requests')
        self.assertNotEqual(faulty, clean)
        self.assertNotEqual(recovered, host.PLAINTEXT)
        self.assertEqual(recovered, AES.new(host.KEY, AES.MODE_ECB).decrypt(faulty))
        state = reference.bytes2matrix(host.PLAINTEXT)
        keys = reference.AES(host.KEY)._key_matrices
        expected = [host.PLAINTEXT]
        reference.add_round_key(state, keys[0])
        expected.append(reference.matrix2bytes(state))
        operations = {1: reference.sub_bytes, 2: reference.shift_rows, 3: reference.mix_columns}
        for rnd in range(1, 11):
            for op in (1, 2, 3, 4):
                if rnd == 10 and op == 3:
                    continue
                if (rnd, op) == tuple(fault.wire_bytes()[:2]):
                    before = state[fault.column][fault.row]
                    state[fault.column][fault.row] ^= fault.mask
                    self.assertEqual(event, bytes([before, before ^ fault.mask]))
                if op == 4:
                    reference.add_round_key(state, keys[rnd])
                else:
                    operations[op](state)
                expected.append(reference.matrix2bytes(state))
        for i, packet in enumerate(packets):
            self.assertEqual(terminal.decode_snapshot(packet, i)['state'], expected[i])
        self.assertEqual(faulty, expected[-1])
        return faulty, event, packets, recovered

    def test_fault_all_positions_and_masks(self):
        for row in range(4):
            for column in range(4):
                for mask in (1, 0x55, 0x80, 0xff):
                    with self.subTest(row=row, column=column, mask=mask):
                        faulty, _, _, _ = self.run_fault(terminal.FaultSettings(row=row, column=column, mask=mask))
                        self.assertEqual(sum(a != b for a, b in zip(faulty, host.CIPHERTEXT)), 4)

    def test_fault_every_valid_round_and_operation(self):
        for rnd in range(1, 11):
            for stage in tuple(terminal.OPERATIONS.values())[1:]:
                if rnd == 10 and stage == 'MixColumns':
                    continue
                with self.subTest(round=rnd, stage=stage):
                    self.run_fault(terminal.FaultSettings(round=rnd, stage=stage))

    def test_fault_terminal_comparison(self):
        fault = terminal.FaultSettings()
        faulty, event, packets, recovered = self.run_fault(fault)
        self.assertEqual(faulty.hex(), '1bc4e0d86a7b04a5d8cd58807083c55a')
        clean_lines = subprocess.check_output([str(self.binary), host.KEY.hex(), host.PLAINTEXT.hex(), '--trace'], text=True).splitlines()
        target = MagicMock()
        target.simpleserial_wait_ack.return_value = 0
        target.simpleserial_read.side_effect = ([bytes.fromhex(line) for line in clean_lines] +
                                               [host.PLAINTEXT, faulty + event] + packets + [recovered])
        with redirect_stdout(io.StringIO()) as output:
            result = terminal.process_fault_message(target, host.PLAINTEXT.hex(), 'hex', host.KEY, fault)
        self.assertEqual(result, (host.CIPHERTEXT, faulty, recovered))
        self.assertIn('MISMATCH (expected', output.getvalue())


if __name__ == '__main__':
    unittest.main()
