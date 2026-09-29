"""Native C, independent OpenSSL, host workflow and local HTTP regression tests."""
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from sm4_reference import process, expand
from sm4_device import Device, KEY, CIPHERTEXT, execute, prepare, unpad
from gui_server import make_server


class SM4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('gcc') or 'C:/MinGW/bin/gcc.exe'
        cls.tmp = tempfile.TemporaryDirectory()
        cls.native = Path(cls.tmp.name) / ('sm4.exe' if os.name == 'nt' else 'sm4')
        subprocess.run([compiler, '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-I', str(HERE / 'firmware'), str(HERE / 'firmware/sm4.c'),
                        str(HERE / 'tests/native_runner.c'), '-o', str(cls.native)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def native_result(self, key, block, decrypt=False, fault=None):
        args = [str(self.native), key.hex(), block.hex(), str(int(decrypt))]
        if fault:
            args.extend(map(str, fault))
        lines = subprocess.check_output(args, text=True).splitlines()
        return bytes.fromhex(lines[0]), [bytes.fromhex(s) for s in lines[2:]], list(bytes.fromhex(lines[1])) if fault else None

    def test_known_answer_and_key_schedule(self):
        self.assertEqual(expand(KEY)[0], 0xf12186f9)
        self.assertEqual(expand(KEY)[-1], 0x9124a012)
        self.assertEqual(process(KEY, KEY)[0], CIPHERTEXT)
        self.assertEqual(self.native_result(KEY, KEY), process(KEY, KEY))
        self.assertEqual(self.native_result(KEY, CIPHERTEXT, True), process(CIPHERTEXT, KEY, True))
        self.assertEqual(process(CIPHERTEXT, KEY, True)[0], KEY)

    def test_random_blocks_against_openssl(self):
        openssl = shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe'
        if not Path(openssl).is_file():
            self.skipTest('OpenSSL is required for the independent oracle test.')
        rng = random.Random(303)
        for _ in range(24):
            key, block = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
            expected = subprocess.check_output([openssl, 'enc', '-sm4-ecb', '-K', key.hex(), '-nopad'], input=block)
            self.assertEqual(process(block, key)[0], expected)
            self.assertEqual(self.native_result(key, block), process(block, key))
            self.assertEqual(self.native_result(key, expected, True), process(expected, key, True))
            self.assertEqual(process(expected, key, True)[0], block)

    def test_faults_every_round_word_and_byte(self):
        for r in range(1, 33):
            for w in range(4):
                b = (r + w) % 4
                fault = [r, w, b, 1 << ((r+w) % 8)]
                result = self.native_result(KEY, KEY, fault=fault)
                self.assertEqual(result, process(KEY, KEY, fault=fault))
                self.assertNotEqual(result[0], CIPHERTEXT)
                self.assertEqual(result[1][:r], process(KEY, KEY)[1][:r])
        for b in range(4):
            for w in range(4):
                fault = [32, w, b, 255]
                self.assertEqual(self.native_result(KEY, KEY, fault=fault), process(KEY, KEY, fault=fault))

    def test_host_workflow_with_native_target_adapter(self):
        test = self

        class NativeTarget:
            key = KEY
            states = []
            corrupt = False

            def simpleserial_write(self, command, payload):
                payload = bytes(payload)
                if command == 'k':
                    self.key, self.reply = payload, b''
                elif command == 's':
                    i = payload[0]
                    self.reply = bytes([i, min(i, 32), 0 if i == 0 else 2 if i == 33 else 1]) + self.states[i]
                else:
                    fault = list(payload[:4]) if command == 'f' else None
                    block = payload[4:] if fault else payload
                    out, self.states, event = test.native_result(self.key, block, command in 'du', fault)
                    self.reply = out + (bytes(event) if event else b'')

            def simpleserial_read(self, *args, **kwargs):
                return bytes(len(self.reply)) if self.corrupt else self.reply

            def simpleserial_wait_ack(self, **kwargs):
                return 0

        device = Device()
        device.target = NativeTarget()
        encrypted = execute(device, dict(value='Hello, SM4! ' * 3, format='text'))
        recovered = execute(device, dict(value=encrypted['output'], format='hex', operation='decrypt', unpad=True))
        self.assertEqual(recovered['text'], 'Hello, SM4! ' * 3)
        faulty = execute(device, dict(value=(KEY * 2).hex(), format='hex', operation='fault', block=2))
        self.assertTrue(faulty['blocks'][0]['roundtrip_ok'])
        self.assertFalse(faulty['blocks'][1]['roundtrip_ok'])
        self.assertEqual(len(faulty['blocks'][1]['snapshots']), 34)
        device.target.corrupt = True
        with self.assertRaises(RuntimeError):
            device.block(KEY)

    def test_input_validation(self):
        for text in ('', 'a', 'ABCDEFGHIJKLMNOP', 'SM4 \u00e9\u6f22'):
            self.assertEqual(unpad(prepare(text, 'text')), text.encode())
        for value in ('', 'zz', '00'):
            with self.assertRaises(ValueError):
                prepare(value, 'hex')
        for fault in ([0, 0, 0, 1], [33, 0, 0, 1], [1, 4, 0, 1], [1, 0, 4, 1], [1, 0, 0, 0]):
            with self.assertRaises(ValueError):
                process(KEY, KEY, fault=fault)
        with self.assertRaises(ValueError):
            unpad(b'bad padding')

    def test_http_without_hardware(self):
        server = make_server(0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(base) as response:
                self.assertIn(b'PFE SM4 Live Console', response.read())
            with urlopen(base + '/app.js') as response:
                self.assertIn(b'function stepper', response.read())
            with urlopen(base + '/api/status') as response:
                self.assertFalse(json.load(response)['connected'])
            request = Request(base + '/api/run', data=json.dumps({'value': KEY.hex()}).encode(), headers={'Content-Type': 'application/json'})
            with self.assertRaises(HTTPError) as error:
                urlopen(request)
            self.assertEqual(error.exception.code, 503)
            request.add_header('Origin', 'https://example.com')
            with self.assertRaises(HTTPError) as error:
                urlopen(request)
            self.assertEqual(error.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main(verbosity=2)
