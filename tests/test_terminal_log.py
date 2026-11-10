"""Check terminal mirroring, clean log files and captured CLI failures."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import terminal_log


class TerminalLogTests(unittest.TestCase):
    def test_stdout_stderr_colors_and_replacement(self):
        console, errors = io.StringIO(), io.StringIO()

        with tempfile.TemporaryDirectory() as folder:
            with redirect_stdout(console), redirect_stderr(errors):
                with terminal_log.terminal_log("lesson", folder) as first:
                    print("\033[31mChanged byte: FF\033[0m")
                    print("Model error", file=sys.stderr)

                text = first.read_text(encoding="utf-8")
                html = first.with_suffix(".html").read_text(encoding="utf-8")
                legacy = Path(folder) / 'lesson_20261107T123456_123456Z.txt'
                legacy.write_text('Old timestamped log', encoding='utf-8')
                unrelated = Path(folder) / 'another_program.txt'
                unrelated.write_text('Keep this log', encoding='utf-8')

                with terminal_log.terminal_log("lesson", folder) as second:
                    print("Second execution")

            self.assertIn("Changed byte: FF", text)
            self.assertIn("Model error", text)
            self.assertIn("\033[31m", text)
            self.assertIn('color:#ff7373;', html)
            self.assertIn('Changed byte: FF', html)
            self.assertNotIn("\033[", html)
            self.assertIn("\033[31m", console.getvalue())
            self.assertIn("Model error", errors.getvalue())
            self.assertEqual(first, second)
            self.assertNotIn('Changed byte: FF', second.read_text(encoding='utf-8'))
            self.assertNotIn('Changed byte: FF', second.with_suffix('.html').read_text(encoding='utf-8'))
            self.assertIn('Second execution', second.read_text(encoding='utf-8'))
            self.assertFalse(legacy.exists())
            self.assertEqual(unrelated.read_text(encoding='utf-8'), 'Keep this log')

    def test_terminal_detection_and_error_capture(self):
        console = io.StringIO()

        console.isatty = lambda: True

        def fail():
            self.assertTrue(sys.stdout.isatty())
            print("Before failure")
            raise ValueError("Example failure")

        with tempfile.TemporaryDirectory() as folder:
            with patch.object(terminal_log, "LOG_FOLDER", Path(folder)), redirect_stdout(console), redirect_stderr(console):
                self.assertEqual(terminal_log.run_with_log(fail, "failure"), 1)

            text = next(Path(folder).glob("*.txt")).read_text(encoding="utf-8")
            self.assertIn("Before failure", text)
            self.assertIn("ValueError: Example failure", text)
            self.assertIn("Exit status: 1", text)

    def test_real_cli_entry_points(self):
        for script in ("aes", "sm4", "piret_aes", "piret_sm4", "giraud_aes", "giraud_sm4", "run"):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as folder:
                if script in ('aes', 'sm4'):
                    arguments = []
                else:
                    if script.endswith('sm4') or script == 'run':
                        arguments_when_false = 'sm4'
                    else:
                        arguments_when_false = 'aes'

                    arguments = ['--algorithm', arguments_when_false, '--color', 'always']

                source = str(ROOT / "src" / f"{script}.py")
                code = f"import sys,runpy; from pathlib import Path; sys.path.insert(0,{str(ROOT / 'src')!r}); import terminal_log; terminal_log.LOG_FOLDER=Path({folder!r}); sys.argv={[source, *arguments]!r}; runpy.run_path({source!r},run_name='__main__')"
                result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
                self.assertEqual(result.returncode, 0, result.stderr)
                path = Path(result.stdout.splitlines()[0].removeprefix("Log file: "))
                self.assertEqual(path.parent.resolve(), Path(folder).resolve())

                try:
                    text = path.read_text(encoding="utf-8")
                    self.assertEqual(text, result.stdout)
                    self.assertTrue(path.with_suffix(".html").is_file())
                    self.assertIn("Exit status: 0", text)
                finally:
                    path.unlink()
                    path.with_suffix(".html").unlink()

    def test_gui_lesson_is_logged_with_all_steps_and_colors(self):
        import gui

        key = bytes.fromhex(gui.SM4_VECTOR)

        report = gui.pdf_sm4_lesson(key, key, 0, 1, 8)

        report.update(algorithm="SM4", operation="Fault analysis", key=key.hex(), input=key.hex())

        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            with terminal_log.terminal_log("gui", folder) as path:
                gui.log_report(report)

            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.count("GUI step "), len(report['steps']))
            self.assertIn("all 256 S-box inputs", text)
            self.assertIn("/ REJECT", text)
            self.assertIn("Recovered master key: " + key.hex(), text)
            self.assertIn("Verification: PASS", text)
            self.assertIn("\033[31m", text)
            self.assertIn("#ff7373", path.with_suffix('.html').read_text(encoding="utf-8"))

    def test_html_colors_reset_bold_and_escaping(self):
        html = terminal_log.colored_html('\033[1;31m<fault>&\033[0m normal \033[32mPASS\033[39m end')

        self.assertIn('<span style="color:#ff7373;font-weight:bold;">&lt;fault&gt;&amp;</span> normal ', html)

        self.assertIn('<span style="color:#78d994;">PASS</span> end', html)

        self.assertNotIn('\033[', html)


if __name__ == "__main__":
    unittest.main()
