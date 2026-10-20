"""AES / SM4 / Piret interactive lesson. Run: python src/crypto_lab_gui.py."""
import json
import queue
import random
import struct
import threading
import tkinter as tk
from itertools import product
from tkinter import filedialog, messagebox, ttk
import aes
import sm4
import run as console

AES_KEY = "000102030405060708090a0b0c0d0e0f"
AES_INPUT = "00112233445566778899aabbccddeeff"
SM4_VECTOR = "0123456789abcdeffedcba9876543210"
BG, PANEL, CELL, TEXT, MUTED, ACCENT, ORANGE, RED = "#0b0f14", "#121822", "#1b2636", "#e6edf3", "#8ea0b8", "#4fd1c5", "#ffb454", "#ff7373"
INV_SBOX = [aes.SBOX.index(i) for i in range(256)]


def parse_block(value):
    data = bytes.fromhex(value)
    if len(data) != 16:
        raise ValueError("Enter exactly 16 bytes (32 hexadecimal digits).")
    return data


def snapshot(number, title, explanation, state, detail="", reference=None):
    return dict(round=number, title=title, explanation=explanation, state=bytes(state).hex(), detail=detail, reference=None if reference is None else bytes(reference).hex())


def aes_trace(block, key, decrypt=False, fault=None):
    """Use the existing AES primitives; expose each operation as a lesson step."""
    keys = aes.key_expansion(key)
    state = aes.bytes_to_state(block)
    steps = [snapshot(10 if decrypt else 0, "Input", "AES stores consecutive input bytes vertically in columns.", block)]

    def record(number, operation, description):
        steps.append(snapshot(number, operation, description, aes.state_to_bytes(state), "Round key: " + aes.state_to_bytes(keys[number]).hex() if operation == "AddRoundKey" else ""))

    def substitute(inverse):
        for row in range(4):
            for column in range(4):
                state[row][column] = (INV_SBOX if inverse else aes.SBOX)[state[row][column]]

    def rotate(inverse):
        for row in range(1, 4):
            state[row] = state[row][-row:] + state[row][:-row] if inverse else state[row][row:] + state[row][:row]

    def mix(inverse):
        matrix = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14)) if inverse else aes.MIX_MATRIX
        for column in range(4):
            old = [state[row][column] for row in range(4)]
            for row in range(4):
                value = 0
                for i in range(4):
                    value ^= aes.gf_mul(matrix[row][i], old[i])
                state[row][column] = value

    aes.add_round_key(state, keys[10 if decrypt else 0])
    record(10 if decrypt else 0, "AddRoundKey", "XOR the state with the round key. XOR is its own inverse.")
    if decrypt:
        for number in range(9, -1, -1):
            rotate(True)
            record(number, "InvShiftRows", "Rotate row r right by r positions to undo ShiftRows.")
            substitute(True)
            record(number, "InvSubBytes", "Apply the inverse S-box to every byte.")
            aes.add_round_key(state, keys[number])
            record(number, "AddRoundKey", "Undo the round-key XOR using the same round key.")
            if number:
                mix(True)
                record(number, "InvMixColumns", "Multiply each column by the inverse matrix in GF(2^8).")
    else:
        for number in range(1, 11):
            substitute(False)
            record(number, "SubBytes", "Replace each byte using the nonlinear S-box.")
            rotate(False)
            record(number, "ShiftRows", "Rotate row r left by r columns, moving bytes between columns.")
            if number != 10:
                if fault and number == fault[0]:
                    _, row, column, mask = fault
                    state[row][column] ^= mask
                    record(number, "Injected XOR", f"Before MixColumns: byte at row {row}, column {column} XOR {mask:02x}.")
                mix(False)
                record(number, "MixColumns", "Mix four bytes within each column using GF(2^8), where addition is XOR.")
            aes.add_round_key(state, keys[number])
            record(number, "AddRoundKey", "XOR with this round key. Round 10 has no MixColumns.")
    return aes.state_to_bytes(state), steps


def sm4_trace(block, key, decrypt=False):
    """Expose the round XOR, S-box, linear map and new word independently."""
    keys = sm4.key_expansion(key)
    words = list(struct.unpack(">4I", block))
    steps = [snapshot(0, "Input", "SM4 uses four big-endian 32-bit words. Each displayed row is one word.", block)]
    for index in range(32):
        key_index = 31 - index if decrypt else index
        rk = keys[key_index]
        mixed = words[1] ^ words[2] ^ words[3] ^ rk
        substituted = sm4.sbox(mixed)
        linear = sm4.linear(substituted)
        new_word = words[0] ^ linear
        state = struct.pack(">4I", *words)
        steps.append(snapshot(index + 1, "Round XOR", "Combine the last three words with the round key.", state, f"B = W1 XOR W2 XOR W3 XOR rk[{key_index}]\n  = {words[1]:08x} XOR {words[2]:08x} XOR {words[3]:08x} XOR {rk:08x}\n  = {mixed:08x}"))
        steps.append(snapshot(index + 1, "S-box / tau", "Apply the S-box independently to each byte of B. The rolling state has not shifted yet.", state, f"tau({mixed:08x}) = {substituted:08x}"))
        steps.append(snapshot(index + 1, "Linear transform", "Diffuse substituted bits with XOR and rotations.", state, f"L(B) = B XOR ROL(B,2) XOR ROL(B,10) XOR ROL(B,18) XOR ROL(B,24)\nL({substituted:08x}) = {linear:08x}\nNew word = W0 XOR L(B) = {words[0]:08x} XOR {linear:08x} = {new_word:08x}"))
        words = words[1:] + [new_word]
        steps.append(snapshot(index + 1, "Shift / new word", "Discard the oldest word, shift left, and append the new word.", struct.pack(">4I", *words), f"Round key index: {key_index}. Decryption uses rk[31] down to rk[0]."))
    output = struct.pack(">4I", *words[::-1])
    steps.append(snapshot(32, "Output reversal", "Reverse the four words: X35 || X34 || X33 || X32.", output))
    return output, steps


def positions(column):
    return tuple(4 * ((column - row) % 4) + row for row in range(4))


def candidates(correct, faulty, column):
    """Ciphertext-only solver; no injected mask, coordinates or key arguments."""
    tables = []
    for position in positions(column):
        table = [[] for _ in range(256)]
        for guess in range(256):
            delta = INV_SBOX[correct[position] ^ guess] ^ INV_SBOX[faulty[position] ^ guess]
            table[delta].append(guess)
        tables.append(table)
    survivors = set()
    for row in range(4):
        for error in range(1, 256):
            survivors.update(product(*(tables[r][aes.gf_mul(aes.MIX_MATRIX[r][row], error)] for r in range(4))))
    return survivors


def reverse_schedule(last_key):
    words = [None] * 44
    words[40:] = [list(last_key[i:i+4]) for i in range(0, 16, 4)]
    for index in range(43, 3, -1):
        temp = words[index - 1][:]
        if index % 4 == 0:
            temp = [aes.SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= aes.RCON[index // 4]
        words[index - 4] = [a ^ b for a, b in zip(words[index], temp)]
    return bytes(sum(words[:4], []))


def recover_key(correct, observations):
    """Intersect four-byte tuples per group; return only a unique K10."""
    groups = [None] * 4
    history = []
    for index, faulty in enumerate(observations, 1):
        if len(correct) != 16 or len(faulty) != 16 or any(a == b for a, b in zip(correct, faulty)):
            raise ValueError("Expected the round-8 byte-fault model (16 changed output bytes).")
        for column in range(4):
            found = candidates(correct, faulty, column)
            groups[column] = found if groups[column] is None else groups[column] & found
            history.append((index, column, len(found), len(groups[column])))
            if not groups[column]:
                raise ValueError("No compatible key candidates. Check the fault model.")
        if all(len(group) == 1 for group in groups):
            key = bytearray(16)
            for column in range(4):
                for position, value in zip(positions(column), next(iter(groups[column]))):
                    key[position] = value
            return bytes(key), history, index
    return None, history, len(observations)


def piret_lesson(block, key, row, column, mask, maximum):
    """Teacher trace plus ciphertext-only recovery, joined into one timeline."""
    clean_ct, clean_steps = aes_trace(block, key)
    first_ct, faulty_steps = aes_trace(block, key, fault=(8, row, column, mask))
    lookup = {(s["round"], s["title"]): s for s in clean_steps}
    steps = []
    for step in faulty_steps:
        if step["round"] >= 8:
            reference = lookup[(8, "ShiftRows")] if step["title"] == "Injected XOR" else lookup[(step["round"], step["title"])]
            steps.append(dict(step, reference=reference["state"]))
    steps.append(snapshot(10, "DFA equations", "Guess a final-round key byte, remove its XOR and undo the S-box. Four differences must share one unknown error.", first_ct, "d[r] = InvSbox[C[p] XOR k] XOR InvSbox[Cfault[p] XOR k]\nFor error row 0: d = [2e, e, e, 3e] in GF(2^8).\nTry all 4 rows and 255 nonzero e values.\nIntersect FOUR-BYTE tuples across observations.\nThe effective round-9 error differs from the original round-8 mask.", clean_ct))
    masks = [mask] + random.Random(42).sample([v for v in range(1, 256) if v != mask], maximum - 1)
    outputs = [first_ct] + [aes_trace(block, key, fault=(8, row, column, value))[0] for value in masks[1:]]
    last_key, history, used = recover_key(clean_ct, outputs)
    for index, group, count, remaining in history:
        detail = f"Correct: {clean_ct.hex()}\nFaulty #{index}: {outputs[index-1].hex()}\nGroup {group} output positions: {positions(group)}\nCandidates from this pair: {count}\nCandidates after intersection: {remaining}\nSolver inputs: ciphertexts only; no key, mask or intermediate states."
        steps.append(snapshot(10, f"Observation {index} / group {group}", "Each independent fault filters candidate tuples. A unique tuple reveals four K10 bytes.", outputs[index-1], detail, clean_ct))
    recovered = None if last_key is None else reverse_schedule(last_key)
    if recovered is not None and (aes_trace(block, recovered)[0] != clean_ct or recovered != key):
        raise RuntimeError("Recovered key verification failed.")
    detail = "Ambiguous candidates remain. Increase the observation count." if recovered is None else f"Recovered K10: {last_key.hex()}\nRecovered K0:  {recovered.hex()}\nKnown-plaintext verification: PASS\nSimulation ground-truth check: PASS\nUsed {used} faulty ciphertexts."
    steps.append(snapshot(10, "Recovery result", "Reverse the AES-128 key schedule once all four groups are unique. This simplified Piret-style solver does not guarantee two faults.", clean_ct, detail))
    return dict(steps=steps, output=first_ct.hex(), correct=clean_ct.hex(), recovered_key=None if recovered is None else recovered.hex(), used=used, history=history, verified=recovered is not None)


def pdf_aes_lesson(block, key, row, column, mask, maximum):
    """PDF round-9 model: recover four groups with independent column faults."""
    correct, clean_steps = aes_trace(block, key)
    steps = list(clean_steps)
    lookup = {(step["round"], step["title"]): step for step in clean_steps}
    masks = [mask] + [value for value in range(1, 256) if value != mask][:maximum-1]
    last_key, history, used = bytearray(16), [], 0
    first_faulty = None
    for group in [(column + offset) % 4 for offset in range(4)]:
        survivors = None
        for observation, value in enumerate(masks, 1):
            faulty, trace = aes_trace(block, key, fault=(9, row, group, value))
            first_faulty = first_faulty or faulty
            used += 1
            if observation == 1:
                for step in trace:
                    if step["round"] >= 9:
                        reference = lookup[(9, "ShiftRows")] if step["title"] == "Injected XOR" else lookup[(step["round"], step["title"])]
                        steps.append(dict(step, title=f"Column {group} / {step['title']}", reference=reference["state"]))
            fresh = console.piret.key_candidates(correct, faulty, group)
            before = None if survivors is None else len(survivors)
            survivors = fresh if survivors is None else survivors & fresh
            if not survivors:
                raise ValueError("No compatible AES candidates.")
            history.append((observation, group, len(fresh), len(survivors)))
            detail = f"d = InvSbox[C[p] XOR k] XOR InvSbox[F[p] XOR k]\nMatch one of 1020 MixColumns difference patterns.\nOutput positions: {positions(group)}\nSimulator: round 9 / row {row} / column {group} / mask {value:02X}\nCandidates from pair: {len(fresh)}\nIntersection: {before} -> {len(survivors)}\nFirst candidates: " + " | ".join(bytes(candidate).hex() for candidate in sorted(survivors)[:4]) + "\nSolver receives ciphertexts and column group, not the key or mask."
            steps.append(snapshot(10, f"Column {group} / observation {observation}", "One round-9 fault affects four output bytes. Intersect four-byte key tuples for this group.", faulty, detail, correct))
            if len(survivors) == 1:
                for position, byte in zip(positions(group), next(iter(survivors))):
                    last_key[position] = byte
                break
        else:
            steps.append(snapshot(10, "Ambiguous recovery", "Increase maximum observations per column. No master key is claimed.", correct))
            return dict(steps=steps, output=first_faulty.hex(), correct=correct.hex(), recovered_key=None, used=used, history=history, verified=False, model="AES round-9 Piret")
    recovered = console.piret.reverse_key_schedule(last_key)
    if aes_trace(block, recovered)[0] != correct or recovered != key:
        raise RuntimeError("AES recovered-key verification failed.")
    steps.append(snapshot(10, "Recovered AES master key", "Reverse the AES-128 key expansion after all four K10 groups become unique.", correct, f"Recovered K10: {last_key.hex()}\nRecovered K0: {recovered.hex()}\nVerification: PASS\nUsed {used} faulty ciphertexts."))
    return dict(steps=steps, output=first_faulty.hex(), correct=correct.hex(), recovered_key=recovered.hex(), used=used, history=history, verified=True, model="AES round-9 Piret")


def pdf_sm4_lesson(block, key, start_byte, mask, maximum):
    """Recover rk31 under the PDF's known-XOR last-round S-box-input model."""
    correct, clean_trace = console.sm4_encrypt(block, key)
    _, steps = sm4_trace(block, key)
    masks = [mask] + [value for value in range(1, 256) if value != mask][:maximum-1]
    recovered_bytes, history, used = bytearray(4), [], 0
    first_faulty = None
    known_words = struct.unpack(">4I", correct)
    known = known_words[1] ^ known_words[2] ^ known_words[3]
    for byte in [(start_byte + offset) % 4 for offset in range(4)]:
        survivors = None
        for observation, value in enumerate(masks, 1):
            faulty, faulty_trace = console.sm4_encrypt(block, key, byte, value)
            first_faulty = first_faulty or faulty
            used += 1
            fresh, inputs, delta = console.sm4_byte_candidates(correct, faulty, byte, value)
            before = 256 if survivors is None else len(survivors)
            survivors = fresh if survivors is None else survivors & fresh
            if not survivors:
                raise ValueError("No compatible SM4 key-byte candidates.")
            history.append((observation, byte, len(fresh), len(survivors)))
            for name, field in [("S-box input A", "a"), ("S-box output B", "b")]:
                clean_word, faulty_word = clean_trace[-1][field], faulty_trace[-1][field]
                # Place the scalar in W0 and pad W1-W3 with zeros for the common viewer.
                state, reference = faulty_word.to_bytes(4, "big") + bytes(12), clean_word.to_bytes(4, "big") + bytes(12)
                steps.append(snapshot(31, f"Byte {byte} / {name}", "Teacher view: only row W0 contains this scalar word; W1-W3 are zero placeholders.", state, f"Known fault mask: {value:02X}\nClean {name}: {clean_word:08X}\nFaulty {name}: {faulty_word:08X}\nThese hidden values are not passed to the solver.", reference))
            detail = f"Known fault: byte {byte}, mask {value:02X}\nL-inverse(C0 XOR F0) = {delta:08X}\nS(a) XOR S(a XOR {value:02X}) = {(delta >> (24-8*byte)) & 255:02X}\nObserved X32 XOR X33 XOR X34 = {known:08X}\nKey guess = input guess XOR {(known >> (24-8*byte)) & 255:02X}\nInput guesses: " + " ".join(f"{a:02X}" for a in sorted(inputs)) + f"\nKey-byte intersection: {before} -> {len(survivors)}\nSurviving key bytes: " + " ".join(f"{a:02X}" for a in sorted(survivors))
            steps.append(snapshot(31, f"Byte {byte} / observation {observation}", "Invert L from output differences, then intersect S-box input/key-byte candidates using the known XOR mask.", faulty, detail, correct))
            if len(survivors) == 1:
                recovered_bytes[byte] = next(iter(survivors))
                break
        else:
            steps.append(snapshot(31, "Ambiguous rk31", "Increase observations per byte. No unique subkey is claimed.", correct))
            return dict(steps=steps, output=first_faulty.hex(), correct=correct.hex(), recovered_key=None, recovered_subkey=None, used=used, history=history, verified=False, model="SM4 controlled last-round DFA")
    rk31 = int.from_bytes(recovered_bytes, "big")
    if rk31 != clean_trace[-1]["rk"]:
        raise RuntimeError("SM4 recovered-subkey verification failed.")
    steps.append(snapshot(31, "DFA recovered rk31", "All four subkey bytes are unique. This DFA recovers rk31, not the complete master key.", correct, f"Recovered rk31: {rk31:08X}\nVerification: PASS"))
    reference_keys = sm4.key_expansion(key)[28:31]
    conditional_key = console.reverse_sm4(reference_keys + [rk31])
    if conditional_key != key or console.sm4_encrypt(block, conditional_key)[0] != correct:
        raise RuntimeError("Conditional SM4 schedule verification failed.")
    steps.append(snapshot(31, "Conditional master-key reversal", "PDF chapter 6: rk28..rk30 are supplied reference keys. They were NOT recovered by the DFA.", correct, "Reference rk28..rk30: " + " ".join(f"{v:08X}" for v in reference_keys) + f"\nDFA-recovered rk31: {rk31:08X}\nMaster key using reference keys: {conditional_key.hex()}\nVerification: PASS"))
    return dict(steps=steps, output=first_faulty.hex(), correct=correct.hex(), recovered_key=None, recovered_subkey=f"{rk31:08X}", conditional_master_key=conditional_key.hex(), reference_subkeys=[f"{v:08X}" for v in reference_keys], used=used, history=history, verified=True, model="SM4 controlled last-round DFA")


class CryptoLab:
    def __init__(self, root):
        self.root, self.report, self.index, self.timer, self.busy = root, None, 0, None, False
        self.messages = queue.Queue()
        root.title("Crypto Lab | AES · SM4 · Piret DFA")
        root.geometry("1280x900")
        root.minsize(1130, 780)
        root.configure(bg=BG)
        self.algorithm = tk.StringVar(value="AES-128")
        self.operation = tk.StringVar(value="Encrypt")
        self.key, self.value = tk.StringVar(value=AES_KEY), tk.StringVar(value=AES_INPUT)
        self.row, self.column = tk.IntVar(value=0), tk.IntVar(value=0)
        self.mask, self.maximum = tk.StringVar(value="01"), tk.IntVar(value=6)
        self.status = tk.StringVar(value="Ready · choose an algorithm and load the example")
        self.speed = tk.IntVar(value=1000)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=CELL, foreground=TEXT, padding=(18, 10))
        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", ACCENT)])
        self.build()
        self.algorithm.trace_add("write", self.selection_changed)
        self.operation.trace_add("write", self.selection_changed)
        root.bind("<Left>", lambda event: self.move(-1) if not isinstance(root.focus_get(), (tk.Entry, ttk.Combobox)) else None)
        root.bind("<Right>", lambda event: self.move(1) if not isinstance(root.focus_get(), (tk.Entry, ttk.Combobox)) else None)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_id = root.after(100, self.poll)
        self.selection_changed()

    def label(self, parent, text, size=11, color=TEXT):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color, font=("Segoe UI", size), anchor="w")

    def button(self, parent, title, action, primary=False):
        return tk.Button(parent, text=title, command=action, bg=ACCENT if primary else CELL, fg=BG if primary else TEXT, relief="flat", padx=12, pady=8, font=("Segoe UI", 10), cursor="hand2")

    def build(self):
        header = tk.Frame(self.root, bg=BG, padx=22, pady=16)
        header.pack(fill="x")
        self.label(header, "CRYPTO LAB", 24, ACCENT).pack(side="left")
        self.label(header, "AES / SM4 / Piret · Learn one transformation at a time", 12, MUTED).pack(side="left", padx=24)
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=22)
        sidebar = tk.Frame(body, bg=PANEL, padx=16, pady=16, width=295)
        sidebar.pack(side="left", fill="y", padx=(0, 16))
        sidebar.pack_propagate(False)
        self.controls = []
        for title, variable, values in [("Algorithm", self.algorithm, ("AES-128", "SM4")), ("Lesson", self.operation, ("Encrypt", "Decrypt", "Fault analysis"))]:
            self.label(sidebar, title, color=MUTED).pack(anchor="w", pady=(0, 5))
            widget = ttk.Combobox(sidebar, textvariable=variable, values=values, state="readonly")
            widget.pack(fill="x", pady=(0, 14))
            self.controls.append(widget)
        for title, variable in [("128-bit key · hex", self.key), ("Input block · hex", self.value)]:
            self.label(sidebar, title, color=MUTED).pack(anchor="w")
            widget = tk.Entry(sidebar, textvariable=variable, bg=CELL, fg=TEXT, insertbackground=ACCENT, relief="flat", font=("Consolas", 10))
            widget.pack(fill="x", ipady=8, pady=(5, 14))
            self.controls.append(widget)
        self.hint = self.label(sidebar, "", 10, MUTED)
        self.hint.configure(wraplength=255, justify="left")
        self.hint.pack(fill="x", pady=(0, 10))
        fault_panel = tk.Frame(sidebar, bg=PANEL)
        fault_panel.pack(fill="x")
        self.fault_title = self.label(fault_panel, "", 10, ORANGE)
        self.fault_title.pack(anchor="w")
        row = tk.Frame(fault_panel, bg=PANEL)
        row.pack(fill="x", pady=8)
        for index, (title, variable) in enumerate([("Row / byte", self.row), ("Start column", self.column)]):
            self.label(row, title, 10, MUTED).grid(row=0, column=index, sticky="w")
            widget = ttk.Combobox(row, textvariable=variable, values=(0, 1, 2, 3), width=8, state="readonly")
            widget.grid(row=1, column=index, padx=(0, 12), pady=5)
            self.controls.append(widget)
        for title, variable in [("First XOR mask · hex 01..FF", self.mask), ("Maximum faulty observations · 1..20", self.maximum)]:
            self.label(fault_panel, title, 9, MUTED).pack(anchor="w")
            widget = tk.Entry(fault_panel, textvariable=variable, bg=CELL, fg=TEXT, insertbackground=ACCENT, relief="flat", font=("Consolas", 11))
            widget.pack(fill="x", ipady=5, pady=(3, 10))
            self.controls.append(widget)
        self.example_button = self.button(sidebar, "Load standard example", self.load_example)
        self.example_button.pack(fill="x", pady=(12, 5))
        self.run_button = self.button(sidebar, "Build lesson", self.run, True)
        self.run_button.pack(fill="x", pady=5)
        self.export_button = self.button(sidebar, "Export lesson JSON", self.export)
        self.export_button.pack(fill="x", pady=5)
        self.export_button.configure(state="disabled")
        self.label(sidebar, "Offline simulation · no board needed", 9, MUTED).pack(anchor="w", pady=10)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self.tabs = ttk.Notebook(right)
        self.tabs.pack(fill="both", expand=True)
        explorer, summary_tab = [tk.Frame(self.tabs, bg=PANEL, padx=16, pady=14) for _ in range(2)]
        self.tabs.add(explorer, text="Step-by-step explorer")
        self.tabs.add(summary_tab, text="Results & reading guide")
        self.title = self.label(explorer, "Build a lesson to begin", 18, ACCENT)
        self.title.pack(anchor="w")
        self.explanation = self.label(explorer, "Choose AES or SM4, then Encrypt, Decrypt or the AES Piret lesson.", 11, MUTED)
        self.explanation.configure(wraplength=740, justify="left")
        self.explanation.pack(fill="x", pady=(10, 12))
        self.metrics = self.label(explorer, "", 10, ORANGE)
        self.metrics.pack(anchor="w")
        matrices = tk.Frame(explorer, bg=PANEL)
        matrices.pack(fill="x", pady=8)
        self.cells, self.matrix_titles = [], []
        for title in ("Current state", "Comparison state", "XOR difference"):
            frame = tk.Frame(matrices, bg=PANEL)
            frame.pack(side="left", fill="x", expand=True)
            heading = self.label(frame, title, 10)
            heading.pack(anchor="center", pady=4)
            self.matrix_titles.append(heading)
            grid = tk.Frame(frame, bg=PANEL)
            grid.pack()
            cells = []
            for row in range(4):
                row_cells = []
                for column in range(4):
                    cell = tk.Label(grid, text="--", bg=CELL, fg=TEXT, width=3, height=2, font=("Consolas", 13, "bold"))
                    cell.grid(row=row, column=column, padx=2, pady=2)
                    row_cells.append(cell)
                cells.append(row_cells)
            self.cells.append(cells)
        self.layout_label = self.label(explorer, "", 10, MUTED)
        self.layout_label.pack(anchor="w", pady=6)
        self.details = tk.Text(explorer, height=8, bg=BG, fg=TEXT, relief="flat", font=("Consolas", 10), wrap="word", padx=10, pady=10)
        self.details.pack(fill="both", expand=True, pady=8)
        navigation = tk.Frame(explorer, bg=PANEL)
        navigation.pack(fill="x", pady=6)
        self.previous = self.button(navigation, "← Previous", lambda: self.move(-1))
        self.previous.pack(side="left")
        self.play_button = self.button(navigation, "▶ Play", self.play)
        self.play_button.pack(side="left", padx=8)
        self.next_button = self.button(navigation, "Next →", lambda: self.move(1))
        self.next_button.pack(side="left")
        self.progress = self.label(navigation, "0 / 0", 10, MUTED)
        self.progress.pack(side="right")
        seek = tk.Frame(explorer, bg=PANEL)
        seek.pack(fill="x")
        self.seek = tk.Scale(seek, from_=0, to=1, orient="horizontal", command=self.seek_to, bg=PANEL, fg=TEXT, highlightthickness=0, showvalue=False)
        self.seek.pack(side="left", fill="x", expand=True)
        ttk.Combobox(seek, textvariable=self.speed, values=(300, 600, 1000, 1800), width=6, state="readonly").pack(side="right")
        self.label(seek, "ms / step", 9, MUTED).pack(side="right", padx=5)
        self.step_list = ttk.Combobox(explorer, state="readonly")
        self.step_list.pack(fill="x", pady=(6, 0))
        self.step_list.bind("<<ComboboxSelected>>", lambda event: self.select(self.step_list.current()))
        scrollbar = ttk.Scrollbar(summary_tab)
        scrollbar.pack(side="right", fill="y")
        self.summary = tk.Text(summary_tab, bg=BG, fg=TEXT, font=("Consolas", 11), wrap="word", relief="flat", padx=14, pady=14, yscrollcommand=scrollbar.set)
        self.summary.pack(fill="both", expand=True)
        scrollbar.configure(command=self.summary.yview)
        tk.Label(self.root, textvariable=self.status, bg=BG, fg=MUTED, anchor="w", padx=22, pady=12).pack(fill="x")
        self.navigation()

    def selection_changed(self, *_):
        if self.busy:
            return
        attack = self.operation.get() == "Fault analysis"
        is_sm4 = self.algorithm.get() == "SM4"
        self.controls[1].configure(values=("Encrypt", "Decrypt", "Fault analysis"))
        self.fault_title.configure(text="SM4 DFA / round 31 / S-box input" if is_sm4 else "AES Piret / round 9 / MixColumns")
        self.hint.configure(text=("Known XOR fault: recover rk31. Master-key reversal also uses three reference subkeys." if is_sm4 else "Piret recovers all four AES key groups. Row selects the fault row; all columns are processed.") if attack else "One raw 16-byte block. Decrypt expects ciphertext; no text padding is applied.")
        for widget in self.controls[4:]:
            widget.configure(state="readonly" if attack and isinstance(widget, ttk.Combobox) else "normal" if attack else "disabled")
        if is_sm4:
            self.controls[5].configure(state="disabled")
        if self.report:
            self.status.set("Settings changed · Build lesson to apply. Timeline retains its original inputs.")

    def load_example(self):
        if self.busy:
            return
        is_sm4 = self.algorithm.get() == "SM4"
        self.key.set(SM4_VECTOR if is_sm4 else AES_KEY)
        self.value.set(("681edf34d206965e86b3e94f536e4246" if is_sm4 else "69c4e0d86a7b0430d8cdb78070b4c55a") if self.operation.get() == "Decrypt" else SM4_VECTOR if is_sm4 else AES_INPUT)
        self.status.set("Standard vector loaded · press Build lesson")

    def set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def run(self):
        if self.busy:
            return
        self.stop()
        try:
            key, block = parse_block(self.key.get()), parse_block(self.value.get())
            attack = self.operation.get() == "Fault analysis"
            row, column, mask, maximum = 0, 0, 1, 6
            if attack:
                row, column, mask, maximum = self.row.get(), self.column.get(), int(self.mask.get(), 16), self.maximum.get()
                if not (0 <= row < 4 and 0 <= column < 4 and 1 <= mask <= 255 and 1 <= maximum <= 20):
                    raise ValueError("Fault settings: row/column 0..3, mask 01..FF, observations 1..20.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid input", str(error), parent=self.root)
            return
        algorithm, operation = self.algorithm.get(), self.operation.get()
        self.busy = True
        self.navigation()
        for widget in self.controls:
            widget.configure(state="disabled")
        self.run_button.configure(state="disabled", text="Computing…")
        self.example_button.configure(state="disabled")
        self.status.set("Building the lesson and checking its result…")
        threading.Thread(target=self.compute, args=(algorithm, operation, key, block, row, column, mask, maximum), daemon=True).start()

    def compute(self, algorithm, operation, key, block, row, column, mask, maximum):
        try:
            if operation == "Fault analysis":
                report = pdf_sm4_lesson(block, key, row, mask, maximum) if algorithm == "SM4" else pdf_aes_lesson(block, key, row, column, mask, maximum)
                report.update(fault=dict(row=row, column=column, mask=mask, maximum=maximum))
            else:
                function = sm4_trace if algorithm == "SM4" else aes_trace
                output, steps = function(block, key, operation == "Decrypt")
                recovered = function(output, key, operation != "Decrypt")[0]
                if recovered != block:
                    raise RuntimeError("Inverse verification failed.")
                report = dict(steps=steps, output=output.hex(), recovered=recovered.hex(), verified=True)
            report.update(algorithm=algorithm, operation=operation, key=key.hex(), input=block.hex())
            self.messages.put((report, None))
        except Exception as error:
            self.messages.put((None, str(error)))

    def poll(self):
        try:
            report, error = self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            for widget in self.controls:
                widget.configure(state="readonly" if isinstance(widget, ttk.Combobox) else "normal")
            self.run_button.configure(state="normal", text="Build lesson")
            self.example_button.configure(state="normal")
            self.selection_changed()
            if error:
                self.status.set("Error · " + error)
                messagebox.showerror("Lesson error", error, parent=self.root)
            else:
                self.report, self.index = report, 0
                self.seek.configure(to=len(report["steps"]) - 1)
                self.step_list.configure(values=[f"{i+1}. R{s['round']:02d} · {s['title']}" for i, s in enumerate(report["steps"])])
                self.render()
                self.fill_summary()
                self.export_button.configure(state="normal")
                self.status.set("Lesson ready · " + ("verification PASS" if report["verified"] else "key recovery ambiguous; increase observations"))
                self.tabs.select(0)
            self.navigation()
        self.poll_id = self.root.after(100, self.poll)

    def render(self):
        if not self.report:
            return
        step = self.report["steps"][self.index]
        previous = self.report["steps"][self.index - 1]["state"] if self.index else step["state"]
        reference = step["reference"] or previous
        state, comparison = bytes.fromhex(step["state"]), bytes.fromhex(reference)
        delta = bytes(a ^ b for a, b in zip(state, comparison))
        sm4_layout = self.report["algorithm"] == "SM4"
        self.title.configure(text=f"Round {step['round']:02d} · {step['title']}")
        self.explanation.configure(text=step["explanation"])
        self.matrix_titles[1].configure(text="Correct state" if step["reference"] else "Previous state")
        self.layout_label.configure(text="SM4: each row is one word, bytes MSB → LSB" if sm4_layout else "AES: row/column matrix; byte index = 4 × column + row")
        self.metrics.configure(text=f"Changed: {sum(bool(b) for b in delta)} / 16 bytes · {sum(bin(b).count('1') for b in delta)} / 128 bits")
        for panel, data in enumerate((state, comparison, delta)):
            for row in range(4):
                for column in range(4):
                    position = 4 * row + column if sm4_layout else 4 * column + row
                    changed = bool(delta[position]) and panel != 1
                    self.cells[panel][row][column].configure(text=f"{data[position]:02X}", bg="#482121" if changed else CELL, fg=RED if changed else TEXT)
        self.set_text(self.details, step["detail"] or "Follow the highlighted bytes. The middle panel provides the comparison state; XOR shows which bits differ.")
        self.progress.configure(text=f"{self.index+1} / {len(self.report['steps'])}")
        self.seek.set(self.index)
        self.step_list.current(self.index)
        self.navigation()

    def navigation(self):
        ready = bool(self.report) and not self.busy
        self.previous.configure(state="normal" if ready and self.index > 0 else "disabled")
        self.next_button.configure(state="normal" if ready and self.index < len(self.report["steps"]) - 1 else "disabled")
        self.play_button.configure(state="normal" if ready else "disabled")
        self.step_list.configure(state="readonly" if ready else "disabled")
        self.seek.configure(state="normal" if ready else "disabled")

    def select(self, index):
        if self.report and not self.busy:
            self.stop()
            self.index = index
            self.render()

    def seek_to(self, value):
        index = int(float(value))
        if self.report and index != self.index:
            self.select(index)

    def move(self, direction):
        if self.report:
            self.select(max(0, min(len(self.report["steps"]) - 1, self.index + direction)))

    def play(self):
        if self.timer is not None:
            self.stop()
            return
        if not self.report or self.busy:
            return
        if self.index == len(self.report["steps"]) - 1:
            self.index = 0
        self.play_button.configure(text="Ⅱ Pause")
        self.render()
        self.timer = self.root.after(self.speed.get(), self.tick)

    def tick(self):
        self.timer = None
        self.index += 1
        self.render()
        if self.index < len(self.report["steps"]) - 1:
            self.timer = self.root.after(self.speed.get(), self.tick)
        else:
            self.stop()

    def stop(self):
        if self.timer is not None:
            self.root.after_cancel(self.timer)
            self.timer = None
        self.play_button.configure(text="▶ Play")

    def fill_summary(self):
        report = self.report
        lines = [report["algorithm"] + " / " + report["operation"], "", "Input:  " + report["input"], "Key:    " + report["key"], "Output: " + report["output"], ""]
        if report["operation"] == "Fault analysis":
            lines.extend(["Model: " + report["model"], "Correct ciphertext: " + report["correct"], f"Faulty observations consumed: {report['used']}", ""])
            if report["algorithm"] == "SM4":
                lines.extend(["DFA-recovered rk31: " + str(report.get("recovered_subkey")), "Master key using reference rk28..rk30: " + str(report.get("conditional_master_key")), "Only rk31 is recovered by the DFA; the other three keys are references."])
            else:
                lines.extend(["DFA-recovered master key: " + str(report["recovered_key"]), "Round-9 faults affect one key quartet at a time. All four groups are processed."])
            lines.extend(["", "Red highlights show all fault-modified bytes and XOR differences.", "No unique key is claimed when candidates remain ambiguous."])

        else:
            lines.extend(["Inverse verification: PASS", "Recovered input: " + report["recovered"], "", "AES: initial key XOR, 9 full rounds, final round without MixColumns.", "SM4: 32 rounds, four 32-bit words, final word reversal.", "SM4 decryption reverses the round-key order.", "", "Select a step from the dropdown or drag the slider.", "For SM4, intermediate scalar calculations appear below the state."])
        lines.extend(["", "Offline software simulation on one raw block.", "JSON export includes the teaching key and internal states."])
        self.set_text(self.summary, "\n".join(lines))

    def export(self):
        if not self.report:
            return
        filename = filedialog.asksaveasfilename(parent=self.root, title="Export lesson", defaultextension=".json", filetypes=[("JSON lesson", "*.json")], initialfile="crypto-lab-lesson.json")
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as output:
                    json.dump(self.report, output, indent=2)
                self.status.set("Lesson exported · " + filename)
            except OSError as error:
                messagebox.showerror("Export error", str(error), parent=self.root)

    def close(self):
        self.stop()
        self.root.after_cancel(self.poll_id)
        self.root.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    CryptoLab(window)
    window.mainloop()
