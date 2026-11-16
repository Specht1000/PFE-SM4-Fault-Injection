"""Check reversible matrix scenes, real attack values and animation controls."""
import contextlib
import io
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import animate_piret_sm4 as animation


class MatrixAnimationTests(unittest.TestCase):
    def test_snapshot_is_independent_of_mutable_rows(self):
        left = [1, 2]
        right = [3, 4]
        event = animation.record("test", "test", "", "", "", left, right)
        left[0] = 999
        right[1] = 999
        self.assertEqual(event["left"], (1, 2))
        self.assertEqual(event["right"], (3, 4))

    def test_four_bit_cell_extraction_and_row_assembly(self):
        events = animation.matrix_lesson(4)
        found = {}

        for event in events:
            if event["phase"] == animation.PHASES[1] and event["row"] == 1 and event["column"] == 2:
                found[event["source"]] = event

        extracted = found["output_bit = (columns[column_index] >> row_index) & 1"]
        self.assertEqual(extracted["variables"]["output_bit"], 1)
        assembled = found["matrix_row |= output_bit << column_index"]
        self.assertEqual(assembled["variables"]["before"], 2)
        self.assertEqual(assembled["variables"]["matrix_row"], 6)
        self.assertEqual(events[-1]["variables"]["result"], 5)

    def test_real_sm4_inverse_matches_engine(self):
        events = animation.matrix_lesson(32)
        self.assertEqual(events[-1]["variables"]["result"], 0x2E000000)
        inverse = None

        for event in events:
            if event["title"] == "The left half is I; the right half is the inverse":
                inverse = event["right"]

        self.assertEqual(inverse, animation.piret_sm4.inverse_rows())

    def test_actual_observations_and_final_key(self):
        events = animation.attack_lesson()
        self.assertEqual(events[1]["variables"]["mask"], 0x03)
        self.assertTrue(events[1]["attack"]["faulty"].startswith("FE30678C"))
        self.assertEqual(events[1]["variables"]["remaining"], 2)
        self.assertNotIn("31:0", events[1]["attack"]["recovered"])
        self.assertEqual(events[2]["attack"]["recovered"]["31:0"], 0x91)
        self.assertEqual(events[-1]["attack"]["master_key"], "0123456789ABCDEFFEDCBA9876543210")
        self.assertEqual(len(events[-1]["attack"]["recovered"]), 16)

    def test_hidden_ui_controls_and_both_matrix_sizes(self):
        try:
            root = animation.tk.Tk()
        except animation.tk.TclError as error:
            self.skipTest(str(error))

        root.withdraw()

        try:
            with contextlib.redirect_stdout(io.StringIO()):
                app = animation.Animation(root)
                root.update_idletasks()
                self.assertEqual(app.index, 0)
                app.move(1)
                self.assertEqual(app.index, 1)
                app.move(-1)
                self.assertEqual(app.index, 0)
                app.phase.set(animation.PHASES[1])
                app.jump_phase()
                self.assertEqual(app.events[app.index]["phase"], animation.PHASES[1])
                app.move(1)
                self.assertIn("output_bit", app.details.get("1.0", "end"))
                self.assertTrue(app.canvas.find_all())
                app.toggle()
                self.assertTrue(app.playing)
                app.pause()
                self.assertFalse(app.playing)
                app.model.set("32-bit real SM4 matrix")
                app.load()
                self.assertEqual(app.width, 32)
                app.phase.set(animation.PHASES[4])
                app.jump_phase()
                self.assertEqual(app.events[app.index]["phase"], animation.PHASES[4])
                app.seek(len(app.events) - 1)
                self.assertIn("Master key recovered", app.title.cget("text"))
        finally:
            if "app" in locals():
                app.close()
            else:
                root.destroy()


if __name__ == "__main__":
    unittest.main()
