"""Mirror lessons to ANSI text and browser-readable colored HTML logs."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from html import escape
import re
import sys
import traceback

ANSI_COLOR = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
LOG_FOLDER = Path(__file__).resolve().parents[1] / "logs"
COLORS = dict(zip(range(30, 38), ("#10151d", "#ff7373", "#78d994", "#ffcf75", "#82aaff", "#d4a1ff", "#4fd1c5", "#e6edf3")))
COLORS.update(dict(zip(range(90, 98), ("#8ea0b8", "#ff9191", "#a0efb0", "#ffe299", "#a4c1ff", "#e4beff", "#8aeee3", "#ffffff"))))


def colored_html(text):
    """Translate ANSI foreground colors and bold into escaped HTML spans."""
    pieces, color, bold, position = [], None, False, 0
    # Split visible text from ANSI control sequences; escape text before embedding it in HTML.
    for match in ANSI_COLOR.finditer(text):
        style = (f"color:{color};" if color else "") + ("font-weight:bold;" if bold else "")
        value = escape(text[position:match.start()])
        pieces.append(f'<span style="{style}">{value}</span>' if style else value)
        # Interpret only style/color codes; other terminal control sequences are not rendered as text.
        if match.group().endswith("m"):
            codes = match.group()[2:-1] or "0"
            for code in map(int, codes.split(";")):
                if code == 0:
                    color, bold = None, False
                elif code == 1:
                    bold = True
                elif code == 22:
                    bold = False
                elif code == 39:
                    color = None
                elif code in COLORS:
                    color = COLORS[code]
        position = match.end()
    style = (f"color:{color};" if color else "") + ("font-weight:bold;" if bold else "")
    tail = escape(text[position:])
    pieces.append(f'<span style="{style}">{tail}</span>' if style else tail)
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Crypto lesson log</title><style>body{background:#0b0f14;color:#e6edf3;margin:24px}pre{font:14px/1.5 Consolas,monospace;white-space:pre;tab-size:4}</style></head><body><pre>' + ''.join(pieces) + '</pre></body></html>'


class Tee:
    """Keep the terminal's color detection and preserve its exact output."""
    def __init__(self, terminal, output):
        self.terminal = terminal
        self.output = output

    def write(self, text):
        # Mirror each write to both destinations without removing ANSI color information.
        self.terminal.write(text)
        self.output.write(text)
        self.output.flush()
        return len(text)

    def flush(self):
        self.terminal.flush()
        self.output.flush()

    def __getattr__(self, name):
        return getattr(self.terminal, name)


@contextmanager
def terminal_log(name, folder=None):
    """Capture stdout and stderr; importing a cipher never creates a log."""
    directory = LOG_FOLDER if folder is None else Path(folder)
    directory.mkdir(parents=True, exist_ok=True)
    # Remove only this program's old timestamped logs from the previous format.
    legacy_name = re.compile(re.escape(name) + r"_\d{8}T\d{6}_\d{6}Z\.(txt|html)")
    for previous in directory.iterdir():
        if previous.is_file() and legacy_name.fullmatch(previous.name):
            previous.unlink()
    path = directory / f"{name}.txt"
    path.with_suffix(".html").write_text(colored_html(""), encoding="utf-8")
    # Opening in write mode replaces this program's previous run rather than appending.
    with path.open("w", encoding="utf-8") as output:
        try:
            # Capture stderr too, including tracebacks, while preserving live terminal output.
            with redirect_stdout(Tee(sys.stdout, output)), redirect_stderr(Tee(sys.stderr, output)):
                print(f"Log file: {path}")
                print(f"Colored HTML log: {path.with_suffix('.html')}")
                yield path
        # Finalize the browser-readable HTML even after an exception or interruption.
        finally:
            output.flush()
            path.with_suffix(".html").write_text(colored_html(path.read_text(encoding="utf-8")), encoding="utf-8")


def run_with_log(main, name):
    """Save normal output, interrupted lessons and unexpected error details."""
    with terminal_log(name):
        try:
            # Keep logging active throughout the executable's main function, including a GUI session.
            code = main()
        # Treat Ctrl+C and a closed input stream as an interrupted lesson, with a recorded exit code.
        except (KeyboardInterrupt, EOFError):
            print("\nLesson stopped.")
            code = 130
        except Exception:
            traceback.print_exc()
            code = 1
        code = 0 if code is None else code
        print(f"Exit status: {code}")
        return code
