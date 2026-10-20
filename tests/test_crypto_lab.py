"""Offline regression checks. Add --gui to exercise hidden Tk widgets too."""
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import gui as lab

GUI = "--gui" in sys.argv
if GUI:
    sys.argv.remove("--gui")


class CryptoTests(unittest.TestCase):
    def test_vectors(self):
        for function, key, block, expected in [(lab.aes_trace, lab.AES_KEY, lab.AES_INPUT, "69c4e0d86a7b0430d8cdb78070b4c55a"), (lab.sm4_trace, lab.SM4_VECTOR, lab.SM4_VECTOR, "681edf34d206965e86b3e94f536e4246")]:
            key, block = bytes.fromhex(key), bytes.fromhex(block)
            output, steps = function(block, key)
            self.assertEqual(output.hex(), expected)
            self.assertEqual(function(output, key, True)[0], block)
            self.assertEqual(steps[-1]["state"], expected)

    def test_independent_openssl(self):
        openssl = shutil.which("openssl") or "C:/Program Files/Git/usr/bin/openssl.exe"
        if not Path(openssl).is_file():
            self.skipTest("OpenSSL unavailable")
        rng = random.Random(2026)
        for name, function in [("aes-128-ecb", lab.aes_trace), ("sm4-ecb", lab.sm4_trace)]:
            for _ in range(12):
                key, block = (bytes(rng.randrange(256) for _ in range(16)) for _ in range(2))
                expected = subprocess.check_output([openssl, "enc", "-" + name, "-K", key.hex(), "-nopad"], input=block)
                self.assertEqual(function(block, key)[0], expected)
                self.assertEqual(function(expected, key, True)[0], block)

    def test_piret_positions_and_ambiguity(self):
        key, block = bytes.fromhex(lab.AES_KEY), bytes.fromhex(lab.AES_INPUT)
        for row in range(4):
            for column in range(4):
                report = lab.piret_lesson(block, key, row, column, 17 + row + column, 6)
                self.assertEqual(report["recovered_key"], lab.AES_KEY)
                self.assertTrue(report["verified"])
        report = lab.piret_lesson(block, key, 0, 0, 1, 1)
        self.assertIsNone(report["recovered_key"])
        self.assertFalse(report["verified"])
        with self.assertRaises(ValueError):
            lab.recover_key(block, [block])

    def test_input_validation(self):
        for value in ("", "zz", "00", "00" * 17):
            with self.assertRaises(ValueError):
                lab.parse_block(value)

    def test_pdf_gui_attack_models(self):
        key, block = bytes.fromhex(lab.AES_KEY), bytes.fromhex(lab.AES_INPUT)
        result = lab.pdf_aes_lesson(block, key, 0, 0, 1, 6)
        self.assertTrue(result["verified"])
        self.assertEqual(result["recovered_key"], key.hex())
        self.assertIn("round-9", result["model"])
        key = bytes.fromhex(lab.SM4_VECTOR)
        result = lab.pdf_sm4_lesson(key, key, 0, 1, 6)
        self.assertTrue(result["verified"])
        self.assertEqual(result["recovered_subkey"], "9124A012")
        self.assertIsNone(result["recovered_key"])
        self.assertEqual(result["conditional_master_key"], key.hex())
        self.assertEqual(len(result["reference_subkeys"]), 3)
        result = lab.pdf_sm4_lesson(key, key, 0, 1, 1)
        self.assertFalse(result["verified"])
        self.assertIsNone(result["recovered_subkey"])

    @unittest.skipUnless(GUI, "Use --gui for Tk integration checks")
    def test_gui(self):
        from unittest.mock import patch
        import tempfile
        import json
        root = lab.tk.Tk()
        root.withdraw()
        app = lab.CryptoLab(root)
        errors = []
        root.report_callback_exception = lambda *args: errors.append(args)
        try:
            for algorithm, operation in [("AES-128", "Encrypt"), ("AES-128", "Decrypt"), ("SM4", "Encrypt"), ("SM4", "Decrypt"), ("AES-128", "Fault analysis"), ("SM4", "Fault analysis")]:
                app.algorithm.set(algorithm)
                app.operation.set(operation)
                app.load_example()
                app.run()
                deadline = time.monotonic() + 10
                while app.busy and time.monotonic() < deadline:
                    root.update()
                    time.sleep(0.01)
                self.assertFalse(app.busy)
                self.assertTrue(app.report["verified"])
                for index in range(len(app.report["steps"])):
                    app.select(index)
                app.select(0)
                app.play()
                self.assertIsNotNone(app.timer)
                app.stop()
                self.assertIsNone(app.timer)
                root.update()
                self.assertFalse(errors)
            with tempfile.TemporaryDirectory() as folder:
                target = str(Path(folder) / "report.json")
                with patch.object(lab.filedialog, "asksaveasfilename", return_value=target):
                    app.export()
                self.assertEqual(json.loads(Path(target).read_text())["recovered_subkey"], "9124A012")
            app.algorithm.set("SM4")
            self.assertEqual(app.operation.get(), "Fault analysis")
        finally:
            app.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
