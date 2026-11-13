"""Validate numerical detail in the established live SM4 debugger."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import debug_piret_sm4 as debugger


class OriginalDebuggerTests(unittest.TestCase):
    def test_real_worker_substitutes_byte_order_operands(self):
        engine = debugger.StepEngine()
        engine.start(debugger.scenario_full)
        found = False

        try:
            for index in range(200):
                message = engine.out_queue.get(timeout=5)
                self.assertEqual(message["type"], "step")

                if "byte_order.append((0 + 1) % 4)" in message["calculation"]:
                    found = True
                    engine.send("step")
                    after = engine.out_queue.get(timeout=5)
                    self.assertIn("byte_order = [0 1]", after["calculation"])
                    break

                engine.send("step")

            self.assertTrue(found)
        finally:
            engine.send("quit")
            engine.thread.join(timeout=5)

        self.assertFalse(engine.thread.is_alive())

    def test_existing_widgets_and_new_calculation_panel(self):
        try:
            root = debugger.tk.Tk()
        except debugger.tk.TclError as error:
            self.skipTest(str(error))

        root.withdraw()

        try:
            app = debugger.DebuggerApp(root)
            self.assertTrue(app.code.winfo_exists())
            self.assertTrue(app.vars.winfo_exists())
            self.assertTrue(app.step_button.winfo_exists())
            self.assertTrue(app.finish_button.winfo_exists())
            app._show_calculation("byte_order.append((0 + 1) % 4)")
            self.assertIn("(0 + 1) % 4", app.calculation.get("1.0", "end"))
            self.assertEqual(app.calculation.cget("bg"), debugger.CELL)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
