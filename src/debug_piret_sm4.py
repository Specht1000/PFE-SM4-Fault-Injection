"""Interactive, step-by-step debugger for the functions of piret_sm4.py.

A small Tk window runs the REAL solver under ``sys.settrace`` and pauses on every
executed source line of the attack's functions. You drive it:

  * Step            - run exactly one line
  * Finish function - run until the current function returns
  * Run to end      - let it finish, then show the result
  * Auto / Pause    - step on a timer at the chosen speed
  * Restart         - re-launch the chosen scenario from the top

While paused you see the function's source with the current line highlighted and
a live table of local variables; the ones that just changed are lit up, so you
watch each action the code takes (invert L, solve the S-box differential, peel a
round, assemble a subkey, reverse the schedule).

Only the DFA functions are stepped; the SM4 cipher itself runs as a black box.
Run:  python src/debug_piret_sm4.py
"""
import builtins
from collections import ChainMap
import io
import keyword
import linecache
import os
import queue
import sys
import threading
import tkinter as tk
import tokenize
from tkinter import ttk
import piret_sm4 as P
from debug_sm4 import equation

# Width of the line-number gutter rendered before each source line.
GUTTER_W = 6
BUILTIN_NAMES = set(dir(builtins))

PLAINTEXT = bytes.fromhex("0123456789abcdeffedcba9876543210")
KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")

TARGET_FILE = os.path.abspath(P.__file__)

# Only the attack functions are stepped; the cipher (sm4.py) stays a black box.
WATCH = {
    "recover_sm4_master_key", "peel_sm4", "sm4_byte_candidates",
    "inverse_linear", "inverse_rows", "reverse_sm4",
}

SKIP_VARS = {"observer", "fields", "fault_oracle", "candidate_filter"}

BG, PANEL, CELL, TEXT, MUTED, ACCENT = "#0b0f14", "#121822", "#1b2636", "#e6edf3", "#8ea0b8", "#4fd1c5"
ORANGE, GREEN, CYAN, RED, GUTTER = "#ffb454", "#7ee787", "#79c0ff", "#ff7373", "#4b5a70"


def fmt(value):
    """Short, readable formatting; hex where it helps."""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        if 0 <= value <= 255:
            return str(value)
        if 0 <= value <= 0xFFFFFFFF:
            return f"0x{value:08x}"
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        text = value.hex()
        return text if len(text) <= 40 else text[:38] + "…"
    if isinstance(value, (set, frozenset)):
        try:
            items = sorted(value)
        except TypeError:
            items = list(value)
        shown = " ".join(fmt(item) for item in items[:8])
        extra = "" if len(value) <= 8 else f" …+{len(value) - 8}"
        return "{" + shown + extra + "}"
    if isinstance(value, (list, tuple)):
        if len(value) > 8:
            return f"{type(value).__name__}[{len(value)}]"
        return "[" + " ".join(fmt(item) for item in value) + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        return f"dict[{len(value)}]"
    if isinstance(value, str):
        return repr(value if len(value) <= 30 else value[:28] + "…")
    if callable(value):
        return f"<{getattr(value, '__name__', 'fn')}>"
    return type(value).__name__


def snapshot(local_dict):
    result = {}
    for name, value in local_dict.items():
        if name.startswith("__") or name in SKIP_VARS:
            continue
        try:
            result[name] = fmt(value)
        except Exception:
            result[name] = "?"
    return result


class _Quit(Exception):
    """Raised inside the worker to abort stepping on restart/close."""


# --------------------------------------------------------------------------- #
#  Scenarios the debugger can run.
# --------------------------------------------------------------------------- #
def scenario_one_byte():
    """Recover a single rk31 byte: peel -> invert L -> S-box differential."""
    correct, _ = P.sm4_fault_encrypt(PLAINTEXT, KEY)
    keys = {}
    clean_view = P.peel_sm4(correct, 31, keys)
    survivors = None
    for mask in (1, 2, 3, 4):
        faulty, _ = P.sm4_fault_encrypt(PLAINTEXT, KEY, 0, mask, 31)
        faulty_view = P.peel_sm4(faulty, 31, keys)
        fresh, _inputs, _delta = P.sm4_byte_candidates(clean_view, faulty_view, 0, mask)
        survivors = set(fresh) if survivors is None else survivors & fresh
        if len(survivors) == 1:
            break
    value = next(iter(survivors)) if survivors and len(survivors) == 1 else None
    return f"rk31 byte 0 recovered = {value:02X}" if value is not None else "still ambiguous"


def scenario_full():
    """Full recovery rk31..rk28 plus schedule inversion (covers every function)."""
    correct, _ = P.sm4_fault_encrypt(PLAINTEXT, KEY)

    def oracle(number, byte, mask):
        return P.sm4_fault_encrypt(PLAINTEXT, KEY, byte, mask, number)[0]

    result = P.recover_sm4_master_key(correct, oracle, tuple(range(1, 9)))
    if result["complete"] and result["master_key"] == KEY:
        return "master key recovered = " + result["master_key"].hex()
    return "recovery incomplete"


SCENARIOS = {
    "Deep-dive: one byte (peel - invert L - S-box diff)": scenario_one_byte,
    "Full recovery: rk31..rk28 + schedule inversion": scenario_full,
}


# --------------------------------------------------------------------------- #
#  The stepping engine: worker thread + settrace, driven by queue commands.
# --------------------------------------------------------------------------- #
class StepEngine:
    """Runs a scenario in a background thread and lets the UI walk it line by line.

    Two queues connect the worker thread and the UI thread:
      * out_queue: worker -> UI  (one "step"/"done"/"error" message at a time)
      * cmd_queue: UI -> worker  ("step"/"run"/"finish"/"quit")
    The worker blocks on cmd_queue after each paused line, so the UI is fully in
    control of how fast execution proceeds. The scenario runs in a thread so the
    Tk window stays responsive while the worker is blocked.
    """

    def __init__(self):
        self.cmd_queue = queue.Queue()   # UI -> worker commands
        self.out_queue = queue.Queue()   # worker -> UI step/result messages
        self.thread = None
        self.prev_locals = {}            # id(frame) -> last formatted locals
        self.prev_equations = {}         # previous statement in each live frame
        self.mode = "step"               # step | run | finish
        self.finish_frame = None         # the frame "Finish fn" is waiting to exit

    def start(self, scenario):
        # Reset state and launch the scenario in a fresh daemon thread.
        self.prev_locals = {}
        self.prev_equations = {}
        self.mode = "step"
        self.finish_frame = None
        # Drain any stale commands left from a previous run.
        while not self.cmd_queue.empty():
            self.cmd_queue.get_nowait()
        self.thread = threading.Thread(target=self._run, args=(scenario,), daemon=True)
        self.thread.start()

    def send(self, command):
        # Called by the UI thread when a button is pressed.
        self.cmd_queue.put(command)

    def _run(self, scenario):
        # sys.settrace installs _global as THIS thread's line tracer, then we run
        # the scenario (which calls the real solver). Any result or error is
        # reported back through out_queue; tracing is always removed at the end.
        sys.settrace(self._global)
        try:
            summary = scenario()
            self.out_queue.put({"type": "done", "summary": summary})
        except _Quit:
            pass  # a "quit" command unwound the worker on purpose (restart/close)
        except Exception as error:  # noqa: BLE001  (report any solver error to the UI)
            self.out_queue.put({"type": "error", "summary": f"{type(error).__name__}: {error}"})
        finally:
            sys.settrace(None)

    def _global(self, frame, event, arg):
        # Python calls this for EVERY function entry in the worker thread. We only
        # want to step the attack functions, so: trace a frame (return _local) only
        # when it belongs to piret_sm4.py AND its name is in WATCH; otherwise return
        # None, which tells Python "do not trace inside here" (the SM4 cipher runs
        # full speed as a black box).
        if event != "call":
            return None
        code = frame.f_code
        if os.path.abspath(code.co_filename) == TARGET_FILE and code.co_name in WATCH:
            self.prev_locals[id(frame)] = {}   # start a fresh "previous locals" record
            return self._local
        return None

    def _local(self, frame, event, arg):
        # Per-line tracer for a watched frame. "line" fires just before a line runs;
        # "return" fires when the function exits (we forget its locals snapshot).
        if event == "line":
            self._pause(frame)
        elif event == "return":
            self.prev_locals.pop(id(frame), None)
            self.prev_equations.pop(id(frame), None)
        return self._local

    def _pause(self, frame):
        # Called before each source line of a watched function. It (1) works out
        # which variables changed, (2) optionally reports to the UI, and (3) blocks
        # until the user clicks a button - that is what makes stepping "interactive".
        func = frame.f_code.co_name
        lineno = frame.f_lineno
        locs = snapshot(frame.f_locals)
        old = self.prev_locals.get(id(frame), {})
        # Diff against the previous line's locals so the UI can light up what the
        # last line actually assigned (compared by formatted value, so in-place
        # mutations like bytearray/set edits are detected too).
        changed = [name for name in locs if old.get(name) != locs[name]]
        self.prev_locals[id(frame)] = locs

        # Freeze the equation while its operands still have their pre-line values.
        # Rendering never evaluates calls or changes the live computation.
        source = linecache.getline(frame.f_code.co_filename, lineno).strip()
        numeric = equation(source, ChainMap(frame.f_locals, frame.f_globals))
        calculation = "NEXT LINE (not executed yet)\n" + numeric
        previous = self.prev_equations.get(id(frame))

        if previous is not None:
            calculation += "\n\nPREVIOUS LINE\n" + previous
            results = []

            for name in changed:
                results.append(name + " = " + locs[name])

            if results:
                calculation += "\nRESULT\n" + "\n".join(results)

        self.prev_equations[id(frame)] = numeric

        # Fast-forward modes skip the pause entirely so the worker runs on:
        if self.mode == "run":
            return                       # "Run to end": never pause again
        if self.mode == "finish" and id(frame) != self.finish_frame:
            # "Finish fn": keep running until we are back in the exact frame the
            # user asked to finish (id(frame) is that frame's unique identity).
            return

        # Call-stack depth, just for display (how deeply nested we are).
        depth = 0
        probe = frame
        while probe is not None:
            depth += 1
            probe = probe.f_back

        # Hand this step to the UI thread (widgets must never be touched from here).
        self.out_queue.put({
            "type": "step", "func": func, "line": lineno,
            "locals": locs, "changed": changed, "depth": depth,
            "calculation": calculation,
        })

        # BLOCK the worker until the UI puts a command back. This is the handshake
        # that turns a normal function call into a one-line-at-a-time walk-through.
        while True:
            command = self.cmd_queue.get()   # waits here until a button is pressed
            if command == "step":
                self.mode = "step"           # advance exactly one line
                return
            if command == "run":
                self.mode = "run"            # stop pausing; run to the end
                return
            if command == "finish":
                self.mode = "finish"         # run until THIS frame returns
                self.finish_frame = id(frame)
                return
            if command == "quit":
                raise _Quit()                # unwind the worker (restart/close)


# --------------------------------------------------------------------------- #
#  The UI.
# --------------------------------------------------------------------------- #
class DebuggerApp:
    def __init__(self, root):
        self.root = root
        self.engine = StepEngine()
        self.auto = False
        self.auto_id = None
        self.steps = 0
        self.running = False

        root.title("piret_sm4.py - interactive debugger")
        root.geometry("1240x840")
        root.configure(bg=BG)

        with open(TARGET_FILE, encoding="utf-8") as handle:
            self.source = handle.read().splitlines()

        self.scenario_name = tk.StringVar(value=list(SCENARIOS)[0])
        self.speed = tk.IntVar(value=350)
        self.status = tk.StringVar(value="Choose a scenario and press Start.")

        self._build()
        root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(40, self._poll)

    # -- layout ----------------------------------------------------------- #
    def _lbl(self, parent, text, size=10, color=TEXT):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI", size), anchor="w")

    def _btn(self, parent, text, command, primary=False):
        return tk.Button(parent, text=text, command=command,
                         bg=ACCENT if primary else CELL, fg=BG if primary else TEXT,
                         relief="flat", padx=12, pady=7, font=("Segoe UI", 10), cursor="hand2")

    def _build(self):
        top = tk.Frame(self.root, bg=BG, padx=16, pady=12)
        top.pack(fill="x")
        self._lbl(top, "SM4 Piret - interactive debugger", 16, ACCENT).pack(side="left")
        combo = ttk.Combobox(top, textvariable=self.scenario_name, values=list(SCENARIOS),
                             state="readonly", width=48)
        combo.pack(side="left", padx=16)
        self.start_button = self._btn(top, "Start", self._start, primary=True)
        self.start_button.pack(side="left")

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=16)

        # Left: source code with the current line highlighted.
        left = tk.Frame(body, bg=PANEL)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        self._lbl(left, "  piret_sm4.py", 11, MUTED).pack(anchor="w", pady=(6, 2))
        code_wrap = tk.Frame(left, bg=PANEL)
        code_wrap.pack(fill="both", expand=True)
        self.code = tk.Text(code_wrap, bg=BG, fg=TEXT, font=("Consolas", 10), wrap="none",
                            relief="flat", padx=8, pady=8)
        yscroll = ttk.Scrollbar(code_wrap, orient="vertical", command=self.code.yview)
        self.code.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.code.pack(side="left", fill="both", expand=True)
        self._load_source()

        # Right: current action, variables, controls.
        right = tk.Frame(body, bg=BG, width=430)
        right.pack(side="left", fill="y")
        right.pack_propagate(False)

        self.where = self._lbl(right, "Not running", 12, ACCENT)
        self.where.pack(anchor="w")
        self.action = self._lbl(right, "", 10, GREEN)
        self.action.configure(wraplength=410, justify="left")
        self.action.pack(anchor="w", pady=(2, 8))

        # Add numerical detail within the existing right-hand panel; retain the
        # source view, variable table, original theme and stepping controls.
        self._lbl(right, "Calculation / substituted values", 10, MUTED).pack(anchor="w")
        calculation_wrap = tk.Frame(right, bg=PANEL)
        calculation_wrap.pack(fill="x", pady=(4, 10))
        self.calculation = tk.Text(calculation_wrap, height=9, bg=CELL, fg=CYAN, font=("Consolas", 10), wrap="word", relief="flat", padx=8, pady=8)
        calculation_scroll = ttk.Scrollbar(calculation_wrap, command=self.calculation.yview)
        self.calculation.configure(yscrollcommand=calculation_scroll.set, state="disabled")
        calculation_scroll.pack(side="right", fill="y")
        self.calculation.pack(fill="x", expand=True)

        self._lbl(right, "Local variables", 10, MUTED).pack(anchor="w")
        table_wrap = tk.Frame(right, bg=BG)
        table_wrap.pack(fill="both", expand=True, pady=(4, 8))
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Debug.Treeview", background=CELL, fieldbackground=CELL,
                        foreground=TEXT, rowheight=22, font=("Consolas", 10), borderwidth=0)
        style.configure("Debug.Treeview.Heading", background=PANEL, foreground=MUTED,
                        font=("Segoe UI", 9))
        self.vars = ttk.Treeview(table_wrap, columns=("name", "value"), show="headings",
                                 style="Debug.Treeview")
        self.vars.heading("name", text="name")
        self.vars.heading("value", text="value")
        self.vars.column("name", width=130, anchor="w")
        self.vars.column("value", width=270, anchor="w")
        vscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.vars.yview)
        self.vars.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side="right", fill="y")
        self.vars.pack(side="left", fill="both", expand=True)
        self.vars.tag_configure("changed", foreground=CYAN, background="#102a33")

        controls = tk.Frame(right, bg=BG)
        controls.pack(fill="x", pady=4)
        self.step_button = self._btn(controls, "Step  (→)", lambda: self._cmd("step"))
        self.step_button.pack(side="left")
        self.finish_button = self._btn(controls, "Finish fn", lambda: self._cmd("finish"))
        self.finish_button.pack(side="left", padx=6)
        self.run_button = self._btn(controls, "Run to end", lambda: self._cmd("run"))
        self.run_button.pack(side="left")

        controls2 = tk.Frame(right, bg=BG)
        controls2.pack(fill="x", pady=4)
        self.auto_button = self._btn(controls2, "▶ Auto", self._toggle_auto)
        self.auto_button.pack(side="left")
        ttk.Combobox(controls2, textvariable=self.speed, values=(150, 350, 700, 1200),
                     width=6, state="readonly").pack(side="left", padx=6)
        self._lbl(controls2, "ms/step", 9, MUTED).pack(side="left")
        self.restart_button = self._btn(controls2, "Restart", self._start)
        self.restart_button.pack(side="right")

        self.counter = self._lbl(right, "", 9, MUTED)
        self.counter.pack(anchor="w", pady=(6, 0))

        tk.Label(self.root, textvariable=self.status, bg=BG, fg=MUTED, anchor="w",
                 padx=16, pady=10).pack(fill="x")
        self._enable_controls(False)

    def _load_source(self):
        self.code.configure(state="normal")
        self.code.delete("1.0", "end")
        for index, line in enumerate(self.source, 1):
            self.code.insert("end", f"{index:4d}  {line}\n")
            self.code.tag_add("gutter", f"{index}.0", f"{index}.{GUTTER_W}")

        # Line highlight (background only, so it coexists with syntax colours).
        self.code.tag_configure("current", background="#1d3b2a")
        self.code.tag_configure("gutter", foreground=GUTTER)
        self.code.tag_configure("syn_keyword", foreground="#ff7b72")
        self.code.tag_configure("syn_string", foreground="#a5d6ff")
        self.code.tag_configure("syn_comment", foreground="#8b949e", font=("Consolas", 10, "italic"))
        self.code.tag_configure("syn_number", foreground="#f0883e")
        self.code.tag_configure("syn_builtin", foreground="#79c0ff")
        self.code.tag_configure("syn_def", foreground="#d2a8ff")

        self._syntax_highlight()
        # The line highlight must sit under the foreground colours but above text.
        self.code.tag_raise("current")
        self.code.configure(state="disabled")

    def _tag_region(self, tag, srow, scol, erow, ecol):
        """Tag a token region, skipping the line-number gutter on every line."""
        if srow == erow:
            self.code.tag_add(tag, f"{srow}.{scol + GUTTER_W}", f"{srow}.{ecol + GUTTER_W}")
            return
        self.code.tag_add(tag, f"{srow}.{scol + GUTTER_W}", f"{srow}.end")
        for middle in range(srow + 1, erow):
            self.code.tag_add(tag, f"{middle}.{GUTTER_W}", f"{middle}.end")
        self.code.tag_add(tag, f"{erow}.{GUTTER_W}", f"{erow}.{ecol + GUTTER_W}")

    def _syntax_highlight(self):
        """Colour the source with Python's own tokenizer."""
        raw = "\n".join(self.source)
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(raw).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return

        previous = None
        for token in tokens:
            ttype, text, (srow, scol), (erow, ecol), _ = token
            name = tokenize.tok_name.get(ttype, "")
            tag = None

            if ttype == tokenize.COMMENT:
                tag = "syn_comment"
            elif ttype == tokenize.STRING or name.startswith("FSTRING"):
                tag = "syn_string"
            elif ttype == tokenize.NUMBER:
                tag = "syn_number"
            elif ttype == tokenize.NAME:
                if keyword.iskeyword(text):
                    tag = "syn_keyword"
                elif previous is not None and previous[0] == tokenize.NAME and previous[1] == "def":
                    tag = "syn_def"
                elif text in BUILTIN_NAMES:
                    tag = "syn_builtin"

            if tag:
                self._tag_region(tag, srow, scol, erow, ecol)

            if ttype not in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
                previous = token

    # -- control state ---------------------------------------------------- #
    def _enable_controls(self, enabled):
        state = "normal" if enabled else "disabled"
        for widget in (self.step_button, self.finish_button, self.run_button,
                       self.auto_button):
            widget.configure(state=state)

    # -- engine interaction ----------------------------------------------- #
    def _start(self):
        self._stop_auto()
        if self.running:
            self.engine.send("quit")
        self.steps = 0
        self.running = True
        self.engine.start(SCENARIOS[self.scenario_name.get()])
        self.status.set("Running - press Step to advance.")
        self._enable_controls(True)
        self.where.configure(text="Starting…")
        self.action.configure(text="")
        self._show_calculation("")
        for item in self.vars.get_children():
            self.vars.delete(item)

    def _cmd(self, command):
        if self.running:
            self.engine.send(command)

    def _toggle_auto(self):
        if self.auto:
            self._stop_auto()
        else:
            self.auto = True
            self.auto_button.configure(text="‖ Pause")
            self._auto_tick()

    def _stop_auto(self):
        self.auto = False
        if self.auto_id is not None:
            self.root.after_cancel(self.auto_id)
            self.auto_id = None
        self.auto_button.configure(text="▶ Auto")

    def _auto_tick(self):
        # Auto mode = send one "step" every `speed` ms via Tk's timer (no sleeping,
        # so the window stays responsive and Pause works instantly).
        if not (self.auto and self.running):
            return
        self.engine.send("step")
        self.auto_id = self.root.after(self.speed.get(), self._auto_tick)

    # -- polling the worker ----------------------------------------------- #
    def _poll(self):
        # Runs on the Tk thread every 40 ms: drain whatever the worker posted and
        # update the widgets. This is the only place worker messages reach the UI.
        try:
            while True:
                message = self.engine.out_queue.get_nowait()
                self._handle(message)
        except queue.Empty:
            pass
        self.root.after(40, self._poll)

    def _handle(self, message):
        kind = message["type"]
        if kind == "step":
            self.steps += 1
            self._show_step(message)
        elif kind == "done":
            self.running = False
            self._stop_auto()
            self._enable_controls(False)
            self.where.configure(text="Finished")
            self.action.configure(text=message["summary"])
            self.status.set("Done - " + message["summary"] + "  (Restart to run again)")
            self._clear_current_line()
        elif kind == "error":
            self.running = False
            self._stop_auto()
            self._enable_controls(False)
            self.where.configure(text="Error", fg=RED)
            self.action.configure(text=message["summary"], fg=RED)
            self.status.set("Error - " + message["summary"])

    def _show_step(self, message):
        func, lineno = message["func"], message["line"]
        self.where.configure(text=f"{func}()   line {lineno}   depth {message['depth']}")
        self._show_calculation(message.get("calculation", ""))
        print(f"{func}:{lineno}\n{message.get('calculation', '')}", flush=True)

        changed = message["changed"]
        if changed:
            effect = ", ".join(f"{name} = {message['locals'][name]}" for name in changed)
            self.action.configure(text="→  " + effect, fg=GREEN)
        else:
            self.action.configure(text="(control flow)", fg=MUTED)

        # Variables table: changed ones lit up.
        for item in self.vars.get_children():
            self.vars.delete(item)
        for name in sorted(message["locals"]):
            tag = ("changed",) if name in changed else ()
            self.vars.insert("", "end", values=(name, message["locals"][name]), tags=tag)

        self._highlight_line(lineno)
        self.counter.configure(text=f"steps: {self.steps}")

    def _show_calculation(self, content):
        self.calculation.configure(state="normal")
        self.calculation.delete("1.0", "end")
        self.calculation.insert("1.0", content)
        self.calculation.configure(state="disabled")

    def _highlight_line(self, lineno):
        # Move the green "current line" background to this line.
        self.code.tag_remove("current", "1.0", "end")
        self.code.tag_add("current", f"{lineno}.0", f"{lineno}.end")
        # Scroll so a few lines of context above AND below are visible, then make
        # sure the current line itself is on screen (keeps it roughly centred).
        self.code.see(f"{max(1, lineno - 4)}.0")
        self.code.see(f"{min(len(self.source), lineno + 4)}.0")
        self.code.see(f"{lineno}.0")

    def _clear_current_line(self):
        self.code.tag_remove("current", "1.0", "end")

    def _close(self):
        self._stop_auto()
        if self.running:
            self.engine.send("quit")
        self.root.destroy()


def main():
    root = tk.Tk()
    DebuggerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    from terminal_log import run_with_log
    raise SystemExit(run_with_log(main, "debug_piret_sm4"))
