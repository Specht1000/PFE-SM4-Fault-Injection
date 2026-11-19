"""Check the portable C firmware core and host protocol without USB hardware."""
import importlib.util
from pathlib import Path
import random
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import sm4

spec = importlib.util.spec_from_file_location("cw_sm4_client", ROOT / "chipwhisperer" / "sm4" / "client.py")
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class FirmwareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("gcc")

        if compiler is None:
            raise unittest.SkipTest("Native GCC is required for the C-core comparison.")

        output = ROOT / ".build" / "sm4_firmware_tests"
        output.mkdir(parents=True, exist_ok=True)
        # A subprocess works even when native GCC and Python have different bitness.
        harness = output / "runner.c"
        harness.write_text('''#include <stdio.h>
#include <stdlib.h>
#include "sm4.h"
static unsigned int event_count;
static unsigned int event_round[64];
static unsigned int event_enter[64];
static void record(uint8_t round, uint8_t entering) {
    if (event_count < 64) {
        event_round[event_count] = round;
        event_enter[event_count] = entering;
        event_count++;
    }
}
int main(int argc, char **argv) {
    if (argc != 5) { return 2; }
    uint8_t key[16], input[16], output[16];
    sm4_context context;
    for (unsigned int i = 0; i < 16; i++) {
        char pair[3] = {argv[1][2*i], argv[1][2*i+1], 0};
        key[i] = (uint8_t)strtoul(pair, 0, 16);
        pair[0] = argv[2][2*i]; pair[1] = argv[2][2*i+1];
        input[i] = (uint8_t)strtoul(pair, 0, 16);
    }
    sm4_set_key(&context, key);
    sm4_round_hook hook = 0;
    if (atoi(argv[4])) { hook = record; }
    sm4_crypt_block(&context, input, output, (uint8_t)atoi(argv[3]), hook);
    for (unsigned int i = 0; i < 16; i++) { printf("%02X", output[i]); }
    puts("");
    for (unsigned int i = 0; i < 32; i++) { printf("%08lX ", (unsigned long)context.rk[i]); }
    puts("");
    for (unsigned int i = 0; i < event_count; i++) { printf("%u:%u ", event_round[i], event_enter[i]); }
    puts("");
    return 0;
}
''', encoding="utf-8")
        cls.executable = output / "sm4_core.exe"
        firmware = ROOT / "chipwhisperer" / "sm4" / "firmware"
        subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O0", "-I", str(firmware), str(firmware / "sm4.c"), str(harness), "-o", str(cls.executable)], check=True)

    def crypt(self, key, block, decrypt=False, hook=False):
        result = subprocess.run([str(self.executable), key.hex(), block.hex(), str(int(decrypt)), str(int(hook))], check=True, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        keys = []

        for value in lines[1].split():
            keys.append(int(value, 16))

        events = []

        for item in lines[2].split():
            number, entering = item.split(":")
            events.append((int(number), int(entering)))

        return bytes.fromhex(lines[0]), dict(rk=keys, events=events)

    def test_official_vector_and_decryption(self):
        key = bytes.fromhex(sm4.KEY)
        block = bytes.fromhex(sm4.PLAINTEXT)
        ciphertext, context = self.crypt(key, block)
        self.assertEqual(ciphertext.hex().upper(), "681EDF34D206965E86B3E94F536E4246")
        self.assertEqual(context["rk"], sm4.key_expansion(key))
        recovered, _ = self.crypt(key, ciphertext, True)
        self.assertEqual(recovered, block)

    def test_one_hundred_random_keys_and_blocks(self):
        rng = random.Random(3031173)

        for _ in range(100):
            key = rng.getrandbits(128).to_bytes(16, "big")
            block = rng.getrandbits(128).to_bytes(16, "big")
            ciphertext, _ = self.crypt(key, block)
            self.assertEqual(ciphertext, sm4.sm4_encrypt_block(block, key))
            recovered, _ = self.crypt(key, ciphertext, True)
            self.assertEqual(recovered, block)

    def test_trigger_hook_does_not_change_ciphertext(self):
        key = bytes.fromhex(sm4.KEY)
        block = bytes.fromhex(sm4.PLAINTEXT)
        ciphertext, context = self.crypt(key, block, hook=True)
        self.assertEqual(ciphertext, sm4.sm4_encrypt_block(block, key))
        expected = []

        for number in range(32):
            expected.append((number, 1))
            expected.append((number, 0))

        self.assertEqual(context["events"], expected)


class FakeTarget:
    def __init__(self, status=0, response=b"SM4\x01"):
        self.status = status
        self.response = response
        self.writes = []

    def simpleserial_write(self, command, data):
        self.writes.append((command, bytes(data)))

    def simpleserial_read(self, command, length, timeout, ack):
        assert command == "r"
        assert ack is False
        return self.response

    def simpleserial_wait_ack(self, timeout):
        return self.status


class ProtocolTests(unittest.TestCase):
    def test_read_response_and_ack(self):
        target = FakeTarget()
        self.assertEqual(client.exchange(target, "i", b"", 4), b"SM4\x01")
        self.assertEqual(target.writes, [("i", b"")])

    def test_no_response_command_still_checks_ack(self):
        self.assertEqual(client.exchange(FakeTarget(), "t", b"\x1f"), b"")

        for status in (1, 2, None):
            with self.assertRaises(RuntimeError):
                client.exchange(FakeTarget(status=status), "k", bytes(16))

    def test_missing_response_is_rejected(self):
        with self.assertRaises(RuntimeError):
            client.exchange(FakeTarget(response=None), "i", b"", 4)

    def test_block_validation(self):
        self.assertEqual(client.parse_block("00" * 16), bytes(16))

        for invalid in ("00", "ZZ" * 16, "00" * 17):
            with self.assertRaises(Exception):
                client.parse_block(invalid)


if __name__ == "__main__":
    unittest.main()
