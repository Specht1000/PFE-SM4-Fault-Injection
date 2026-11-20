"""Exercise FI acquisition, model rejection and cleanup without physical faults."""
import contextlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "chipwhisperer" / "sm4"))
sys.path.insert(0, str(ROOT / "src"))
import client
import clock_glitch
import glitch_common as campaign
import piret_sm4
import sm4
import voltage_glitch


class FakeScope:
    def __init__(self):
        self.io = SimpleNamespace(glitch_hp=False, glitch_lp=False, hs2="clkgen", nrst="high_z")
        self.glitch = SimpleNamespace(width=2, offset=0, readStatus=lambda: (0, 0, True, True))
        self.clock = SimpleNamespace()
        self.adc = SimpleNamespace()
        self.trigger = SimpleNamespace()
        self.armed = False
        self.closed = False

    def default_setup(self, verbose=False):
        pass

    def arm(self):
        self.armed = True

    def capture(self):
        return False

    def dis(self):
        self.closed = True


class FakeTarget:
    def __init__(self, scope, missing=False):
        self.scope = scope
        self.missing = missing
        self.responses = b""
        self.faults = 0
        self.closed = False

    def flush(self):
        pass

    def simpleserial_write(self, command, data):
        if command == "i":
            self.responses = b"SM4\x01"
        elif command == "k":
            self.key = bytes(data)
        elif command == "t":
            self.round = data[0]
        elif command == "p":
            if self.scope.armed:
                if self.missing:
                    self.responses = None
                else:
                    byte = self.faults // 2
                    mask = 3

                    if self.faults % 2:
                        mask = 1

                    self.responses, _ = piret_sm4.sm4_fault_encrypt(bytes(data), self.key, byte, mask, self.round)
                    self.faults += 1

                self.scope.armed = False
            else:
                self.responses = sm4.sm4_encrypt_block(bytes(data), self.key)

    def simpleserial_read(self, command, length, timeout, ack):
        return self.responses

    def simpleserial_wait_ack(self, timeout):
        if self.responses is None:
            return None

        return 0

    def dis(self):
        self.closed = True


class CampaignTests(unittest.TestCase):
    def test_observed_masks_for_all_words_and_bytes(self):
        key = bytes.fromhex(sm4.KEY)
        plaintext = bytes.fromhex(sm4.PLAINTEXT)
        correct = sm4.sm4_encrypt_block(plaintext, key)

        for word in (1, 2, 3):
            for byte in range(4):
                faulty, _ = piret_sm4.sm4_fault_encrypt(plaintext, key, byte, 3, 31, word)
                observation = campaign.infer_fault(correct, faulty)
                actual = (sm4.key_expansion(key)[31] >> (24 - 8 * byte)) & 255
                self.assertEqual(observation["word"], word)
                self.assertEqual(observation["byte"], byte)
                self.assertEqual(observation["mask"], 3)
                self.assertIn(actual, observation["candidates"])

    def test_rejects_identical_or_multibyte_input_differences(self):
        correct = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")

        with self.assertRaises(ValueError):
            campaign.infer_fault(correct, correct)

        words = list(struct.unpack(">4I", correct))
        words[3] ^= 0x01010000

        with self.assertRaises(ValueError):
            campaign.infer_fault(correct, struct.pack(">4I", *words))

    def test_multibyte_sbox_fault_is_rejected(self):
        # A real-board fault (clock delay 20) that changed only the newest word but
        # whose inverse-L difference spreads over all four bytes: a multi-byte S-box
        # fault, not single-bit exploitable. It must be rejected with a clear reason.
        clean = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")
        board = bytes.fromhex("0F58832BD206965E86B3E94F536E4246")

        with self.assertRaises(ValueError) as context:
            campaign.infer_fault(clean, board)

        self.assertIn("several bytes", str(context.exception))

    def test_single_bit_sbox_input_fault_recovers_via_giraud(self):
        # A genuine single-bit fault at the round-31 S-box input changes only the
        # newest word. The Giraud filter (eight one-bit masks) must accept it and
        # keep the true key byte among the candidates.
        key = bytes.fromhex(sm4.KEY)
        plaintext = bytes.fromhex(sm4.PLAINTEXT)
        clean = sm4.sm4_encrypt_block(plaintext, key)

        def observer(number, operation, value):
            if number == 31 and operation == "Sbox input":
                return value ^ (0x08 << 24)  # flip one bit of byte 0
            return value

        faulty = sm4.sm4_encrypt_block(plaintext, key, observer=observer)
        observation = campaign.infer_fault(clean, faulty)
        true_byte = (sm4.key_expansion(key)[31] >> 24) & 255

        self.assertEqual(observation["model"], "giraud-sbox-input")
        self.assertEqual(observation["byte"], 0)
        self.assertIn(true_byte, observation["candidates"])

    def test_stuck_at_recovers_master_key(self):
        # Instruction-skip / stuck-at faults (S-box output byte forced to 00 or FF)
        # must recover the full master key, verified by re-encryption, even when the
        # two stuck values are mixed across bytes and rounds.
        key = bytes.fromhex(sm4.KEY)
        plaintext = bytes.fromhex(sm4.PLAINTEXT)
        correct = sm4.sm4_encrypt_block(plaintext, key)

        def stuck(round_number, byte, value):
            def observer(number, operation, word):
                if number == round_number and operation == "Sbox output":
                    return (word & ~(0xFF << (24 - 8 * byte))) | (value << (24 - 8 * byte))
                return word
            return sm4.sm4_encrypt_block(plaintext, key, observer=observer)

        faulty_by_round = {}
        for number in (31, 30, 29, 28):
            collected = []
            for byte in range(4):
                for value in (0x00, 0xFF):
                    collected.append(stuck(number, byte, value))
            faulty_by_round[number] = collected

        master = piret_sm4.recover_stuck_at(plaintext, correct, faulty_by_round)
        self.assertEqual(master, key)

    def test_routes_are_distinct(self):
        scope = FakeScope()
        clock_glitch.configure_attack(scope, "lp")
        self.assertEqual(scope.io.hs2, "glitch")
        self.assertEqual(scope.glitch.output, "clock_xor")
        self.assertFalse(scope.io.glitch_lp)
        voltage_glitch.configure_attack(scope, "lp")
        self.assertEqual(scope.io.hs2, "clkgen")
        self.assertEqual(scope.glitch.output, "glitch_only")
        self.assertTrue(scope.io.glitch_lp)
        self.assertFalse(scope.io.glitch_hp)
        campaign.disable_attack(scope)
        self.assertFalse(scope.io.glitch_lp)

    def test_complete_round_acquisition_and_cleanup_both_methods(self):
        for kind, configure in (("clock", clock_glitch.configure_attack), ("voltage", voltage_glitch.configure_attack)):
            scope = FakeScope()
            target = FakeTarget(scope)
            fake = SimpleNamespace(scope=lambda sn: scope, target=lambda current, protocol: target, targets=SimpleNamespace(SimpleSerial=object()))

            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)

                with patch.object(campaign, "ROOT", root), patch.object(client, "ROOT", root), patch.object(campaign.time, "sleep"), patch.dict(sys.modules, {"chipwhisperer": fake}), contextlib.redirect_stdout(io.StringIO()):
                    status = campaign.run_campaign(kind, configure, ["--widths", "2", "--offsets", "0", "--delays", "0:100:10", "--max-trials", "8"])

                self.assertEqual(status, 0)
                result = json.loads((root / "logs" / (kind + "_glitch_recovery.json")).read_text())
                self.assertEqual(result["round_keys"]["31"], "9124A012")
                self.assertEqual(result["counts"]["dfa_compatible"], 8)
                self.assertFalse(result["master_key_verified"])
                self.assertTrue((root / "logs" / (kind + "_glitch.csv")).exists())
                self.assertTrue(scope.closed)
                self.assertTrue(target.closed)
                self.assertFalse(scope.io.glitch_lp)
                self.assertFalse(scope.io.glitch_hp)
                self.assertEqual(scope.io.hs2, "clkgen")

    def test_no_response_is_not_reported_as_confirmed_reset(self):
        scope = FakeScope()
        target = FakeTarget(scope, missing=True)
        result, status, detail = campaign.acquire(scope, target, bytes(16), 100)
        self.assertIsNone(result)
        self.assertEqual(status, "timeout_or_reset")
        self.assertIn("not independently confirmed", detail)

    def test_final_round28_campaign_verifies_master(self):
        scope = FakeScope()
        target = FakeTarget(scope)
        fake = SimpleNamespace(scope=lambda sn: scope, target=lambda current, protocol: target, targets=SimpleNamespace(SimpleSerial=object()))
        key = bytes.fromhex(sm4.KEY)
        plaintext = bytes.fromhex(sm4.PLAINTEXT)
        schedule = sm4.key_expansion(key)
        seed_keys = {}

        for number in range(29, 32):
            seed_keys[str(number)] = f"{schedule[number]:08X}"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = root / "later_keys.json"
            seed.write_text(json.dumps(dict(round_keys=seed_keys, plaintext=plaintext.hex(), correct=sm4.sm4_encrypt_block(plaintext, key).hex())), encoding="utf-8")

            with patch.object(campaign, "ROOT", root), patch.object(client, "ROOT", root), patch.object(campaign.time, "sleep"), patch.dict(sys.modules, {"chipwhisperer": fake}), contextlib.redirect_stdout(io.StringIO()):
                status = campaign.run_campaign("clock", clock_glitch.configure_attack, ["--round", "28", "--recovered-keys", str(seed), "--widths", "2", "--offsets", "0", "--delays", "0:100:10", "--max-trials", "8"])

            self.assertEqual(status, 0)
            document = json.loads((root / "logs" / "clock_glitch_recovery.json").read_text())
            self.assertTrue(document["master_key_verified"])
            self.assertEqual(document["round_keys"]["28"], "428D3654")
            self.assertTrue(scope.closed)

    def test_requires_later_subkeys_and_valid_grid(self):
        with self.assertRaises(ValueError):
            campaign.load_keys(None, 30)

        self.assertEqual(list(campaign.delay_values("0:20:10")), [0, 10, 20])

        for value in ("nan", "inf", "50"):
            with self.assertRaises(Exception):
                campaign.decimal_values(value)


if __name__ == "__main__":
    unittest.main()
