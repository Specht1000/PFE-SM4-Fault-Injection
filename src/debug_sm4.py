"""Record real SM4 Piret calculations and replay them forwards or backwards."""
import argparse
import ast
from collections import ChainMap
import json
import linecache
from pathlib import Path
import sys
import tkinter as tk
from tkinter import ttk

import piret_sm4
import sm4
from terminal_log import run_with_log

ROOT = Path(__file__).resolve().parents[1]


def display(value, limit=256):
    """Freeze values as readable text, without retaining mutable target state."""
    if isinstance(value, bool) or value is None:
        return str(value)

    if isinstance(value, int):
        if value >= 0:
            return f"{value} | hex={value:X} | binary={value:b}"

        return str(value)

    if isinstance(value, (bytes, bytearray)):
        return value.hex().upper()

    if isinstance(value, (list, tuple, set)):
        items = value

        if isinstance(value, set):
            items = sorted(value)

        parts = []

        for item in items:
            if len(parts) >= limit:
                parts.append(f"... ({len(value)} entries; see the source history)")
                break

            if isinstance(item, int):
                parts.append(f"{item} (0x{item:X})")
            elif isinstance(item, dict):
                parts.append("<event dictionary>")
            else:
                parts.append(str(item))

        return "[" + ", ".join(parts) + "]"

    if isinstance(value, dict):
        if len(value) > 32:
            return f"<dictionary with {len(value)} entries>"

        parts = []

        for key, item in value.items():
            if isinstance(item, int):
                parts.append(f"{key}: 0x{item:X}")
            else:
                parts.append(f"{key}: {str(item)[:80]}")

        return "{" + ", ".join(parts) + "}"

    if callable(value):
        return "<function " + getattr(value, "__name__", "callback") + ">"

    return str(value)


def variables(frame):
    """Capture every local by value; summarize large reporting containers."""
    frozen = {}

    for name, value in frame.f_locals.items():
        if name in ("history", "trace"):
            frozen[name] = f"<{len(value)} recorded events>"
        else:
            frozen[name] = display(value)

    return frozen


class Substitute(ast.NodeTransformer):
    """Substitute data operands only; never execute calls to explain a line."""
    def __init__(self, namespace):
        self.namespace = namespace

    def visit_Name(self, node):
        value = self.namespace.get(node.id)

        if isinstance(node.ctx, ast.Load) and isinstance(value, (int, bool)):
            return ast.copy_location(ast.Constant(value=value), node)

        return node

    def visit_Call(self, node):
        # Keep the function/method name intact and replace only its arguments.
        arguments = []

        for argument in node.args:
            arguments.append(self.visit(argument))

        node.args = arguments

        for keyword in node.keywords:
            keyword.value = self.visit(keyword.value)

        return node

    def visit_Subscript(self, node):
        # Looking up a plain local array at a scalar index is side-effect free.
        container = None

        if isinstance(node.value, ast.Name):
            container = self.namespace.get(node.value.id)
        elif isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            if node.value.value.id == "sm4" and node.value.attr in ("SBOX", "FK", "CK"):
                container = getattr(sm4, node.value.attr)

        if isinstance(node.ctx, ast.Load) and container is not None:
            index = node.slice

            if isinstance(index, ast.Name):
                index = self.namespace.get(index.id)
            elif isinstance(index, ast.Constant):
                index = index.value
            else:
                index = None

            if isinstance(container, (list, tuple, bytes, bytearray, dict)) and isinstance(index, int):
                try:
                    value = container[index]

                    if isinstance(value, int):
                        return ast.copy_location(ast.Constant(value=value), node)
                except (KeyError, IndexError):
                    pass

        return self.generic_visit(node)


def equation(source, namespace):
    """Render a numerical expression while leaving all real execution untouched."""
    statement = source.strip()

    try:
        if statement.startswith(("if ", "elif ", "for ", "while ")):
            if statement.startswith("elif "):
                statement = "if " + statement[5:]

            statement += "\n    pass"

        tree = ast.parse(statement)
        tree = Substitute(namespace).visit(tree)
        ast.fix_missing_locations(tree)
        rendered = ast.unparse(tree)
        return rendered.replace("\n    pass", "")
    except (SyntaxError, ValueError):
        return statement


class Recorder:
    """Observe source execution; replay never changes a live interpreter frame."""
    def __init__(self):
        self.steps = []
        self.active = {}
        self.pending = {}

    def finish(self, frame):
        identity = id(frame)

        if identity in self.pending:
            record = self.steps[self.pending.pop(identity)]
            record["after"] = variables(frame)
            results = []

            for name, value in record["after"].items():
                if record["before"].get(name) != value:
                    results.append(name + " = " + value)

            record["results"] = results

    def trace(self, frame, event, argument):
        identity = id(frame)
        filename = Path(frame.f_code.co_filename).name
        function = frame.f_code.co_name

        if event == "call":
            included = filename == "piret_sm4.py"

            # Include public arithmetic helpers reached directly from traced math,
            # while skipping thousands of unrelated clean target-round operations.
            if filename == "sm4.py" and function in ("linear", "linear_key", "sbox", "rotl"):
                included = id(frame.f_back) in self.active

            if function == "observer" and filename == "piret_sm4.py":
                data = frame.f_locals
                included = data.get("number") == data.get("fault_round") and data.get("operation") == "Sbox input" and data.get("byte") is not None

            if not included:
                return None

            depth = 0
            parent = frame.f_back

            while parent is not None:
                if id(parent) in self.active:
                    depth += 1

                parent = parent.f_back

            self.active[identity] = depth
            return self.trace

        if identity not in self.active:
            return None

        if event in ("line", "return", "exception"):
            self.finish(frame)

        if event == "line":
            source = linecache.getline(frame.f_code.co_filename, frame.f_lineno).strip()

            if source and not source.startswith(('"""', "'''")):
                self.pending[identity] = len(self.steps)
                operands = ChainMap(frame.f_locals, frame.f_globals)
                self.steps.append(dict(function=function, file=filename, line=frame.f_lineno, depth=self.active[identity], source=source, equation=equation(source, operands), before=variables(frame), after={}))

        elif event == "return":
            # Return expressions have no local assignment; show their actual result.
            if self.steps:
                for record in reversed(self.steps):
                    if record["function"] == function and record["depth"] == self.active[identity]:
                        record["returned"] = display(argument)
                        break

            self.active.pop(identity, None)

        return self.trace


def record_attack(start_byte=0):
    """Execute the actual solver; only the oracle closure knows the target key."""
    key = bytes.fromhex(sm4.KEY)
    plaintext = bytes.fromhex(sm4.PLAINTEXT)
    correct = sm4.sm4_encrypt_block(plaintext, key)

    def oracle(number, byte, mask):
        faulty, trace = piret_sm4.sm4_fault_encrypt(plaintext, key, byte, mask, number)
        return faulty

    # Include inverse-matrix construction even after a prior run in this process.
    piret_sm4.inverse_rows.cache_clear()
    recorder = Recorder()
    previous_trace = sys.gettrace()

    try:
        sys.settrace(recorder.trace)
        result = piret_sm4.recover_sm4_master_key(correct, oracle, start_byte=start_byte)
    finally:
        sys.settrace(previous_trace)

    if not result["complete"] or result["master_key"] != key:
        raise RuntimeError("Debug execution did not recover the correct master key.")

    if sm4.sm4_encrypt_block(plaintext, result["master_key"]) != correct or sm4.sm4_decrypt_block(correct, result["master_key"]) != plaintext:
        raise RuntimeError("Recovered debug key failed encrypt/decrypt verification.")

    return recorder.steps, result


def navigate(steps, index, action):
    """Move through real recorded call depth or reverse the recorded timeline."""
    if action == "previous":
        return max(0, index - 1)

    if action == "next":
        return min(len(steps) - 1, index + 1)

    depth = steps[index]["depth"]

    for candidate in range(index + 1, len(steps)):
        if action == "over" and steps[candidate]["depth"] <= depth:
            return candidate

        if action == "out" and steps[candidate]["depth"] < depth:
            return candidate

    return len(steps) - 1


def lesson_text(record):
    lines = [record["file"] + ":" + str(record["line"]), "Function: " + record["function"] + " | Call depth: " + str(record["depth"]), "", "SOURCE", record["source"], "", "EQUATION WITH CURRENT NUMBERS (decimal)", record["equation"], "", "VARIABLES: BEFORE -> AFTER (integers also show hex and binary)"]
    if record.get("results"):
        # Put actual computed values next to the substituted equation.
        insertion = lines.index("VARIABLES: BEFORE -> AFTER (integers also show hex and binary)")
        lines[insertion:insertion] = ["ACTUAL COMPUTED VALUES", "\n".join(record["results"]), ""]

    names = list(record["before"])

    for name in record["after"]:
        if name not in names:
            names.append(name)

    for name in names:
        before = record["before"].get(name, "<not assigned>")
        after = record["after"].get(name, "<not assigned>")
        lines.append("\n" + name + " = " + before)

        if after != before:
            lines.append("  -> " + after)

    if "returned" in record:
        lines.extend(["", "ACTUAL RETURN VALUE", record["returned"]])

    return "\n".join(lines)


def replay(steps):
    """Replay captured calculations with Previous/Next/Step Over/Step Out."""
    window = tk.Tk()
    window.title("SM4 Piret: numerical debug replay")
    window.geometry("1200x800")
    position = tk.IntVar(value=0)
    status = tk.StringVar()
    toolbar = ttk.Frame(window, padding=8)
    toolbar.pack(fill="x")
    body = ttk.Frame(window)
    body.pack(fill="both", expand=True)
    text = tk.Text(body, wrap="word", font=("Consolas", 11), padx=12, pady=12)
    scrollbar = ttk.Scrollbar(body, command=text.yview)
    text.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    text.pack(fill="both", expand=True)
    text.tag_configure("changed", foreground="#c62828")

    def show():
        record = steps[position.get()]
        status.set(f"Step {position.get() + 1}/{len(steps)} | {record['function']}:{record['line']}")
        content = lesson_text(record)
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("1.0", content)

        for number, line in enumerate(content.splitlines(), 1):
            if line.startswith("  -> "):
                text.tag_add("changed", f"{number}.0", f"{number}.end")

        text.configure(state="disabled")
        colored_lines = []

        for line in content.splitlines():
            if line.startswith("  -> "):
                line = "\033[31m" + line + "\033[0m"

            colored_lines.append(line)

        print(status.get() + "\n" + "\n".join(colored_lines) + "\n", flush=True)

    def move(action):
        position.set(navigate(steps, position.get(), action))
        show()

    def previous():
        move("previous")

    def next_step():
        move("next")

    def step_over():
        move("over")

    def step_out():
        move("out")

    def find():
        needle = search.get().lower()

        for offset in range(1, len(steps) + 1):
            candidate = (position.get() + offset) % len(steps)
            record = steps[candidate]

            if needle in (record["source"] + " " + record["function"]).lower():
                position.set(candidate)
                show()
                return

    ttk.Button(toolbar, text="Previous / Step back", command=previous).pack(side="left")
    ttk.Button(toolbar, text="Next / Step into", command=next_step).pack(side="left")
    ttk.Button(toolbar, text="Step over", command=step_over).pack(side="left")
    ttk.Button(toolbar, text="Step out", command=step_out).pack(side="left")
    search = ttk.Entry(toolbar, width=25)
    search.pack(side="left", padx=8)
    ttk.Button(toolbar, text="Find next source/function", command=find).pack(side="left")
    ttk.Label(window, textvariable=status, padding=8).pack(fill="x")
    ttk.Label(window, text="Replay of a completed real run. Previous restores a recorded view; it does not undo live Python execution.", padding=8).pack(fill="x")
    window.bind("<Left>", lambda event: previous())
    window.bind("<Right>", lambda event: next_step())
    window.bind("<F11>", lambda event: next_step())
    window.bind("<F10>", lambda event: step_over())
    window.bind("<Shift-F10>", lambda event: previous())
    window.bind("<Shift-F11>", lambda event: step_out())
    show()
    window.mainloop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-only", action="store_true", help="Record and verify without opening the replay window.")
    parser.add_argument("--start-byte", type=int, choices=range(4), default=0)
    args = parser.parse_args(argv)

    if not args.record_only:
        # Keep the established debugger UI; numerical detail lives in its panel.
        import debug_piret_sm4
        return debug_piret_sm4.main()

    print("Recording actual SM4 Piret execution; numerical replay opens after verification.", flush=True)
    steps, result = record_attack(args.start_byte)
    destination = ROOT / "logs" / "debug_sm4_trace.json"
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(dict(steps=steps, master_key=result["master_key"].hex(), faulty_outputs=result["used"])), encoding="utf-8")
    print(f"Recorded {len(steps)} steps; {result['used']} faulty outputs; master key {result['master_key'].hex().upper()} / PASS", flush=True)
    print(f"Full numerical trace (overwritten each run): {destination}", flush=True)

    if not args.record_only:
        replay(steps)

    return 0


if __name__ == "__main__":
    raise SystemExit(run_with_log(main, "debug_sm4"))
