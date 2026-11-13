"""Check numerical substitution, immutable snapshots and replay navigation."""
from pathlib import Path
import contextlib
import io
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import debug_sm4


class DebugSM4Tests(unittest.TestCase):
    def test_byte_order_equation_and_store_target(self):
        namespace = dict(start_byte=0, offset=1, words=[3, 4], index=0, mask=1)
        self.assertEqual(debug_sm4.equation("byte_order.append((start_byte + offset) % 4)", namespace), "byte_order.append((0 + 1) % 4)")
        self.assertEqual(debug_sm4.equation("words[index] = words[1] ^ mask", namespace), "words[0] = 4 ^ 1")

    def test_equation_does_not_execute_calls(self):
        called = []

        def probe(value):
            called.append(value)

        self.assertEqual(debug_sm4.equation("value = probe(mask)", dict(probe=probe, mask=2)), "value = probe(2)")
        self.assertEqual(called, [])

    def test_navigation_respects_depth_and_boundaries(self):
        steps = []

        for depth in (0, 1, 2, 1, 0):
            steps.append(dict(depth=depth))

        self.assertEqual(debug_sm4.navigate(steps, 0, "over"), 4)
        self.assertEqual(debug_sm4.navigate(steps, 1, "out"), 4)
        self.assertEqual(debug_sm4.navigate(steps, 1, "over"), 3)
        self.assertEqual(debug_sm4.navigate(steps, 0, "next"), 1)
        self.assertEqual(debug_sm4.navigate(steps, 0, "previous"), 0)

    def test_recording_real_loop_preserves_earlier_values(self):
        recorder = debug_sm4.Recorder()
        previous = sys.gettrace()

        try:
            sys.settrace(recorder.trace)
            debug_sm4.piret_sm4.inverse_linear(0x734E3D3D)
        finally:
            sys.settrace(previous)

        results = []

        for step in recorder.steps:
            if step["source"] == "result |= parity << index":
                results.append(step["after"]["result"])

        self.assertEqual(len(results), 32)
        self.assertTrue(results[-1].startswith(str(0x4F000000) + " |"))
        self.assertTrue(results[0].startswith("0 |"))

    def test_hidden_replay_buttons_and_search(self):
        try:
            root = debug_sm4.tk.Tk()
        except debug_sm4.tk.TclError as error:
            self.skipTest("Tcl/Tk is unavailable in this execution environment: " + str(error))

        root.withdraw()
        steps = []

        for offset in range(2):
            steps.append(dict(file="piret_sm4.py", function="recover_sm4_master_key", line=1, depth=0, source="byte_order.append((start_byte + offset) % 4)", equation=f"byte_order.append((0 + {offset}) % 4)", before=dict(offset=str(offset)), after=dict(offset=str(offset))))

        errors = []

        def check():
            try:
                toolbar = root.winfo_children()[0]
                buttons = {}
                entry = None

                for widget in toolbar.winfo_children():
                    if isinstance(widget, debug_sm4.ttk.Button):
                        buttons[widget.cget("text")] = widget
                    elif isinstance(widget, debug_sm4.ttk.Entry):
                        entry = widget

                text = None

                for widget in root.winfo_children()[1].winfo_children():
                    if isinstance(widget, debug_sm4.tk.Text):
                        text = widget
                buttons["Next / Step into"].invoke()
                self.assertIn("(0 + 1) % 4", text.get("1.0", "end"))
                buttons["Previous / Step back"].invoke()
                self.assertIn("(0 + 0) % 4", text.get("1.0", "end"))
                entry.insert(0, "byte_order.append")
                buttons["Find next source/function"].invoke()
                self.assertIn("(0 + 1) % 4", text.get("1.0", "end"))
            except Exception as error:
                errors.append(error)
            finally:
                root.destroy()

        root.after(10, check)

        with patch.object(debug_sm4.tk, "Tk", return_value=root), contextlib.redirect_stdout(io.StringIO()):
            debug_sm4.replay(steps)

        if errors:
            raise errors[0]


if __name__ == "__main__":
    unittest.main()
