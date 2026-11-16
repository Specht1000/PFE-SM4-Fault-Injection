"""User-controlled matrix animation and real SM4 fault-recovery walkthrough."""
import argparse
import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk

import piret_sm4
import sm4
from terminal_log import run_with_log

BG = "#0b0f14"
PANEL = "#121822"
CELL = "#1b2636"
TEXT = "#e6edf3"
MUTED = "#8ea0b8"
ACCENT = "#4fd1c5"
BLUE = "#79c0ff"
ORANGE = "#ffb454"
RED = "#ff7373"
GREEN = "#7ee787"
PHASES = ("1. Build columns", "2. Collect rows", "3. Invert the matrix", "4. Apply the inverse", "5. Recover the SM4 key")


def matrix_rows(columns, width):
    """Convert packed column vectors to packed rows using the real indexing."""
    rows = []

    for row in range(width):
        value = 0

        for column in range(width):
            value |= ((columns[column] >> row) & 1) << column

        rows.append(value)

    return rows


def record(phase, title, source, equation, why, left, right, **values):
    """Freeze independent snapshots so moving backwards never reruns a fault."""
    event = dict(phase=phase, title=title, source=source, equation=equation, why=why, left=tuple(left), right=tuple(right), row=-1, column=-1, variables={}, strip=None)
    event.update(values)
    return event


def matrix_lesson(width):
    """Record basis construction, every nested-loop operation and Gauss-Jordan."""
    if width not in (4, 32):
        raise ValueError("Choose the four-bit teaching matrix or the real 32-bit SM4 matrix.")

    columns = []

    if width == 4:
        # This invertible teaching matrix matches the drawings in the PDF.
        columns = [0b0101, 0b0011, 0b0010, 0b1000]
    else:
        for bit in range(width):
            columns.append(sm4.linear(1 << bit))

    original = matrix_rows(columns, width)
    empty = [0] * width
    events = []
    digits = width // 4

    for column in range(width):
        value = columns[column]
        events.append(record(PHASES[0], f"Unit vector {column} reveals column {column}", "basis_word = 1 << bit_index; transformed_word = L(basis_word)", f"1 << {column} = {1 << column:0{width}b}\nL({1 << column:0{width}b}) = {value:0{width}b}", "A linear transformation is determined by its unit-vector outputs. Each output bit becomes one cell in this column. Blue highlights the column; row 0 is the TOP cell, stored in bit 0 (the RIGHTMOST printed bit).", original, empty, column=column, variables=dict(bit_index=column, basis_word=1 << column, transformed_word=value), strip=("Column as a packed word: bit 0 is on the right", value, column)))

    collected = [0] * width
    identity = [0] * width

    for row in range(width):
        accumulator = 0
        events.append(record(PHASES[1], f"Outer loop: row_index = {row}", "for row_index in range(width): matrix_row = 0", f"row_index = {row}\nmatrix_row = {0:0{width}b}", "Move DOWN to a new row and clear its accumulator. The original columns stay unchanged. The inner loop will move RIGHT while this row index stays fixed.", original, identity, row=row, variables=dict(row_index=row, matrix_row=accumulator), strip=("Current reconstructed row", accumulator, -1)))

        for column in range(width):
            shifted = columns[column] >> row
            bit = shifted & 1
            placed = bit << column
            after = accumulator | placed
            values = dict(row_index=row, column_index=column, column_word=columns[column], shifted_word=shifted, output_bit=bit, matrix_row=accumulator)
            events.append(record(PHASES[1], f"Read cell [{row}, {column}]", "output_bit = (columns[column_index] >> row_index) & 1", f"({columns[column]:0{width}b} >> {row}) & 1\n= {shifted:0{width}b} & {1:0{width}b}\n= {bit}", "Shift the desired column bit down to position 0, then AND with 1 to discard every other bit. The orange cell is the exact matrix coefficient being read.", original, identity, row=row, column=column, variables=values, strip=("Shifted column; AND selects its rightmost bit", shifted, 0)))
            events.append(record(PHASES[1], f"Place the bit at column position {column}", "placed = output_bit << column_index", f"{bit} << {column} = {placed:0{width}b}", "The reconstructed row stores column c at bit c. Shift LEFT to place the extracted 0 or 1 there. This is a different shift from the earlier extraction.", original, identity, row=row, column=column, variables=dict(output_bit=bit, column_index=column, placed=placed, matrix_row=accumulator), strip=("Contribution to the reconstructed row", placed, column)))
            events.append(record(PHASES[1], f"Accumulate cell [{row}, {column}] with OR", "matrix_row |= output_bit << column_index", f"{accumulator:0{width}b} | {placed:0{width}b}\n= {after:0{width}b}", "OR writes this coefficient without deleting earlier columns. A zero contribution preserves the accumulator. The next inner-loop iteration moves to the next column.", original, identity, row=row, column=column, variables=dict(row_index=row, column_index=column, before=accumulator, contribution=placed, matrix_row=after), strip=("Accumulated row after OR", after, column)))
            accumulator = after

        collected[row] = accumulator
        identity[row] = 1 << row
        packed = accumulator | (1 << (width + row))
        events.append(record(PHASES[1], f"Attach identity row {row} and append", "identity_bit = 1 << (width + row_index); rows.append(matrix_row | identity_bit)", f"1 << ({width} + {row}) = {1 << (width + row):0{2 * width}b}\n{accumulator:0{2 * width}b} | {1 << (width + row):0{2 * width}b}\n= {packed:0{2 * width}b}", "Attach one identity coefficient in the HIGH half. The reconstructed matrix row is the LOW half. The right grid now shows the identity rows attached so far. Only now does the outer loop advance.", original, identity, row=row, variables=dict(row_index=row, matrix_row=accumulator, identity_bit=1 << (width + row), augmented_row=packed), strip=("Completed matrix row (low half)", accumulator, -1)))

    if collected != original:
        raise RuntimeError("The nested loops changed the matrix instead of repacking it.")

    left = list(collected)
    right = list(identity)

    for column in range(width):
        pivot = None

        for candidate in range(column, width):
            bit = (left[candidate] >> column) & 1
            events.append(record(PHASES[2], f"Search down pivot column {column}: row {candidate}", "pivot_bit = (rows[candidate_row] >> column) & 1", f"({left[candidate]:0{width}b} >> {column}) & 1 = {bit}", "Search only the current diagonal row and rows below it. A 1 is a valid pivot. Earlier pivot columns have already been processed.", left, right, row=candidate, column=column, variables=dict(column=column, candidate_row=candidate, pivot_bit=bit)))

            if bit == 1:
                pivot = candidate
                break

        if pivot is None:
            raise ValueError("The selected matrix has no inverse.")

        left[column], left[pivot] = left[pivot], left[column]
        right[column], right[pivot] = right[pivot], right[column]
        events.append(record(PHASES[2], f"Pivot {column}: swap rows {column} and {pivot}", "rows[column], rows[pivot] = rows[pivot], rows[column]", f"R{column} <-> R{pivot}\nSwap BOTH matrix halves.", "The pivot must be on the diagonal. Swapping a row with itself changes nothing. Every operation includes the attached identity half.", left, right, row=column, column=column, variables=dict(column=column, pivot=pivot)))

        for row in range(width):
            if row != column and (left[row] >> column) & 1:
                before_left = left[row]
                before_right = right[row]
                left[row] ^= left[column]
                right[row] ^= right[column]
                events.append(record(PHASES[2], f"Eliminate cell [{row}, {column}] with pivot row {column}", "rows[row] ^= rows[column]", f"Matrix: {before_left:0{width}b} XOR {left[column]:0{width}b} = {left[row]:0{width}b}\nRight:  {before_right:0{width}b} XOR {right[column]:0{width}b} = {right[row]:0{width}b}", "1 XOR 1 becomes 0 in this pivot column. Red cells changed in the target row. The same XOR must also update the right half; that is how the inverse is formed.", left, right, row=row, column=column, pivot=column, changed_left=before_left ^ left[row], changed_right=before_right ^ right[row], variables=dict(row=row, column=column, before=before_left, pivot_row=left[column], after=left[row])))

    for index in range(width):
        if left[index] != 1 << index:
            raise RuntimeError("Elimination failed to produce the identity.")

    events.append(record(PHASES[2], "The left half is I; the right half is the inverse", "inverse_row = augmented_row >> width", f"[M | I] -> [I | inverse(M)]\nExtract the HIGH {width} bits of each packed row.", "No secret key was needed. These inverse rows are fixed for this public matrix. inverse_rows() prepares them; inverse_linear(value) applies them.", left, right))
    inverse = tuple(right)

    if width == 32 and inverse != piret_sm4.inverse_rows():
        raise RuntimeError("Animated inverse differs from the real SM4 attack.")

    value = 0b0111

    if width == 32:
        value = 0x962EB8B8

    output = 0

    for index, row in enumerate(inverse):
        selected = row & value
        count = selected.bit_count()
        parity = count & 1
        before = output
        output |= parity << index
        events.append(record(PHASES[3], f"Inverse row {index}: select participating input bits", "selected_bits = row & value", f"{row:0{width}b}\nAND {value:0{width}b}\n  = {selected:0{width}b}", "Read one inverse row. AND selects the input positions whose coefficients are 1. This is the beginning of one binary dot product, not another matrix inversion.", inverse, empty, row=index, input_value=value, variables=dict(index=index, row=row, value=value, selected_bits=selected), strip=("Selected bits after AND", selected, -1)))
        events.append(record(PHASES[3], f"Inverse row {index}: XOR is parity", "set_bit_count = bin(selected_bits).count('1'); parity = set_bit_count & 1", f"popcount({selected:0{width}b}) = {count}\n{count} & 1 = {parity}", "An odd number of selected ones gives 1; an even number gives 0. This is the XOR of the selected bits over GF(2).", inverse, empty, row=index, input_value=value, variables=dict(index=index, set_bit_count=count, parity=parity), strip=("Selected input bits", selected, -1)))
        events.append(record(PHASES[3], f"Write recovered output bit {index}", "result |= parity << index", f"{before:0{width}b} | ({parity} << {index})\n= {output:0{width}b}\nresult = 0x{output:0{digits}X}", "Place the dot-product result at its output index and preserve earlier output bits. The next iteration reads the next inverse row.", inverse, empty, row=index, input_value=value, variables=dict(index=index, parity=parity, result=output), strip=("Recovered output word", output, index)))

    expected = 0b0101

    if width == 32:
        expected = 0x2E000000

    if output != expected:
        raise RuntimeError("The animated inverse application failed its known example.")

    return events


def attack_lesson():
    """Drive the real fault oracle and expose its actual candidate intersections."""
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    correct, clean_trace = piret_sm4.sm4_fault_encrypt(key, key)

    def oracle(number, byte, mask):
        faulty, trace = piret_sm4.sm4_fault_encrypt(key, key, byte, mask, number)
        return faulty

    # Start with 03 = binary 00000011: flip two bits in the selected byte.
    result = piret_sm4.recover_sm4_master_key(correct, oracle, masks=(3, 1, 2, 4, 5, 6, 7, 8))

    if not result["complete"] or result["master_key"] != key:
        raise RuntimeError("The animated attack did not recover the reference key.")

    filled = {}
    events = []
    base = dict(correct=correct.hex().upper(), recovered={})
    events.append(record(PHASES[4], "Start the real 32-bit SM4 recovery", "recover_sm4_master_key(correct, oracle)", "C = " + correct.hex().upper() + "\nkeys = {}; used = 0", "The following states come from actual SM4 ciphertexts and solver events. The four-bit teaching matrix is not used by the attack.", (), (), attack=base))

    for query, observation in enumerate(result["history"], 1):
        number = observation["round"]
        byte = observation["byte"]
        q = bytes.fromhex(observation["clean_view"])
        q_word = int.from_bytes(q[4:8], "big") ^ int.from_bytes(q[8:12], "big") ^ int.from_bytes(q[12:16], "big")
        known = (q_word >> (24 - 8 * byte)) & 255
        delta_byte = (observation["delta_b"] >> (24 - 8 * byte)) & 255
        inputs = []
        survivors = []

        for value in observation["inputs"]:
            inputs.append(f"{value:02X}")

        for value in observation["survivors"]:
            survivors.append(f"{value:02X}")

        if observation["remaining"] == 1:
            filled[f"{number}:{byte}"] = observation["survivors"][0]

        attack = dict(correct=correct.hex().upper(), faulty=observation["faulty"].upper(), recovered=dict(filled), query=query, round=number, byte=byte)
        events.append(record(PHASES[4], f"Fault {query}: rk{number}, byte {byte}, mask {observation['mask']:02X}", "delta_b = inverse_linear(delta_x); survivors &= fresh", f"L^-1(delta_x) = {observation['delta_b']:08X}\nS(a) XOR S(a XOR {observation['mask']:02X}) = {delta_byte:02X}\nInputs: {' '.join(inputs)}\nKey byte = a XOR {known:02X}\nRemaining key bytes: {' '.join(survivors)}", "Only the ciphertexts and controlled fault descriptors enter the filter. A byte is written into the grid only when one candidate remains. Later keys must be recovered before peeling an earlier round.", (), (), attack=attack, variables=dict(round=number, byte=byte, mask=observation["mask"], used=query, remaining=observation["remaining"], delta_b=observation["delta_b"])))

    schedule = {}

    def observe(index, word):
        schedule[index] = word

    tail = []

    for number in range(28, 32):
        tail.append(result["round_keys"][number])

    recovered = piret_sm4.reverse_sm4(tail, observer=observe)

    for index in range(31, -1, -1):
        right = []

        for other in range(index + 1, index + 5):
            if other >= 32:
                right.append(tail[other - 32])
            else:
                right.append(schedule[other])

        q = right[0] ^ right[1] ^ right[2] ^ sm4.CK[index]
        equation = f"Q = {right[0]:08X} XOR {right[1]:08X} XOR {right[2]:08X} XOR {sm4.CK[index]:08X}\nQ = {q:08X}; tau(Q) = {sm4.sbox(q):08X}\nK[{index}] = {right[3]:08X} XOR {sm4.linear_key(sm4.sbox(q)):08X}\nK[{index}] = {schedule[index]:08X}"
        events.append(record(PHASES[4], f"Reverse expansion: recover K[{index}]", "words[index] = words[index+4] ^ linear_key(sbox(value))", equation, "This uses already recovered schedule words and public CK. L-prime uses rotations 13 and 23, different from the matrix L in the earlier chapters. No new fault is needed.", (), (), attack=dict(correct=correct.hex().upper(), recovered=dict(filled)), variables=dict(index=index, CK=sm4.CK[index], value=q, recovered_word=schedule[index])))

    for index in range(4):
        master_word = schedule[index] ^ sm4.FK[index]
        events.append(record(PHASES[4], f"Remove public FK[{index}]", "master_word = words[index] ^ sm4.FK[index]", f"{schedule[index]:08X} XOR {sm4.FK[index]:08X} = {master_word:08X}", "The original key words were XORed with fixed FK constants before expansion. XORing the same constant removes this whitening.", (), (), attack=dict(correct=correct.hex().upper(), recovered=dict(filled)), variables=dict(index=index, K=schedule[index], FK=sm4.FK[index], master_word=master_word)))

    if sm4.sm4_encrypt_block(key, recovered) != correct or sm4.sm4_decrypt_block(correct, recovered) != key:
        raise RuntimeError("The animated recovered key failed verification.")

    events.append(record(PHASES[4], "Master key recovered and verified", "encrypt(plaintext, recovered_key); decrypt(ciphertext, recovered_key)", "MK = " + recovered.hex().upper() + "\nEncrypt and decrypt: PASS\n32 faulty outputs + one clean reference", "All four subkeys came from intersections. The master key came from inverse expansion and FK removal. These are verified software observations, not physical STM32 measurements.", (), (), attack=dict(correct=correct.hex().upper(), recovered=dict(filled), master_key=recovered.hex().upper())))
    return events


class Animation:
    """Keep one current scene, reversible navigation and optional timer playback."""
    def __init__(self, root):
        self.root = root
        root.title("SM4 Piret: matrix animation")
        root.geometry("1460x900")
        root.minsize(1100, 740)
        root.configure(bg=BG)
        self.index = 0
        self.playing = False
        self.timer = None
        self.pulse = None
        self.width = 4
        self.cache = {}
        self.attack = attack_lesson()
        self.model = tk.StringVar(value="4-bit teaching matrix")
        self.phase = tk.StringVar(value=PHASES[0])
        self.speed = tk.IntVar(value=700)
        self.progress = tk.DoubleVar(value=0)
        self.status = tk.StringVar()
        self._build()
        self.load()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.bind("<Right>", lambda event: self.move(1))
        root.bind("<Left>", lambda event: self.move(-1))
        root.bind("<space>", lambda event: self.toggle())
        root.bind("<Home>", lambda event: self.restart())

    def button(self, parent, text, command):
        widget = tk.Button(parent, text=text, command=command, bg=CELL, fg=TEXT, activebackground=ACCENT, relief="flat", padx=12, pady=8, font=("Segoe UI", 10))
        widget.pack(side="left", padx=3)
        return widget

    def _build(self):
        top = tk.Frame(self.root, bg=BG, padx=14, pady=12)
        top.pack(fill="x")
        tk.Label(top, text="SM4 Piret | follow every bit", bg=BG, fg=ACCENT, font=("Segoe UI", 18)).pack(side="left", padx=(0, 20))
        model = ttk.Combobox(top, textvariable=self.model, values=("4-bit teaching matrix", "32-bit real SM4 matrix"), state="readonly", width=25)
        model.pack(side="left")
        model.bind("<<ComboboxSelected>>", lambda event: self.load())
        chapter = ttk.Combobox(top, textvariable=self.phase, values=PHASES, state="readonly", width=30)
        chapter.pack(side="left", padx=12)
        chapter.bind("<<ComboboxSelected>>", lambda event: self.jump_phase())
        controls = tk.Frame(self.root, bg=BG, padx=12)
        controls.pack(fill="x")
        self.button(controls, "Previous  [Left]", lambda: self.move(-1))
        self.button(controls, "Next  [Right]", lambda: self.move(1))
        self.play_button = self.button(controls, "Play  [Space]", self.toggle)
        self.button(controls, "Restart chapter", self.restart)
        ttk.Combobox(controls, textvariable=self.speed, values=(150, 350, 700, 1200, 2000), state="readonly", width=6).pack(side="left", padx=8)
        tk.Label(controls, text="ms / calculation", bg=BG, fg=MUTED).pack(side="left")
        tk.Label(controls, text="Orange: selected | Blue: column | Teal: row | Red: changed", bg=BG, fg=MUTED).pack(side="right")
        self.title = tk.Label(self.root, bg=BG, fg=TEXT, font=("Segoe UI", 14), anchor="w", padx=16, pady=10)
        self.title.pack(fill="x")
        body = tk.PanedWindow(self.root, orient="horizontal", bg=BG, sashwidth=7)
        body.pack(fill="both", expand=True, padx=14)
        self.canvas = tk.Canvas(body, bg=PANEL, highlightthickness=0)
        body.add(self.canvas, stretch="always", minsize=650)
        self.canvas.bind("<Configure>", lambda event: self.draw())
        side = tk.Frame(body, bg=CELL, width=380)
        body.add(side, stretch="never", minsize=340)
        self.details = tk.Text(side, wrap="word", bg=CELL, fg=TEXT, relief="flat", font=("Consolas", 11), padx=12, pady=12)
        scroll = ttk.Scrollbar(side, command=self.details.yview)
        self.details.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.details.pack(fill="both", expand=True)
        self.slider = ttk.Scale(self.root, from_=0, to=1, variable=self.progress, command=self.seek)
        self.slider.pack(fill="x", padx=18, pady=(10, 4))
        tk.Label(self.root, textvariable=self.status, bg=BG, fg=MUTED, anchor="w", padx=16, pady=8).pack(fill="x")

    def load(self):
        self.pause()
        self.width = 4

        if self.model.get().startswith("32"):
            self.width = 32

        if self.width not in self.cache:
            self.cache[self.width] = matrix_lesson(self.width) + self.attack

        self.events = self.cache[self.width]
        destination = Path(__file__).resolve().parents[1] / "logs" / "animate_piret_sm4_trace.json"
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(dict(matrix_width=self.width, steps=self.events)), encoding="utf-8")
        self.slider.configure(to=len(self.events) - 1)
        self.index = 0
        self.show()

    def show(self):
        if self.pulse is not None:
            self.root.after_cancel(self.pulse)
            self.pulse = None

        event = self.events[self.index]
        self.phase.set(event["phase"])
        self.progress.set(self.index)
        self.title.configure(text=event["title"])
        lines = ["CODE", event["source"], "", "SUBSTITUTED EQUATION", event["equation"], "", "WHY THIS OPERATION?", event["why"], "", "CURRENT VALUES"]

        for name, value in event["variables"].items():
            lines.append(f"{name} = {value} (0x{value:X})")

        content = "\n".join(lines)
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", content)
        self.details.configure(state="disabled")
        self.status.set(f"Step {self.index + 1}/{len(self.events)} | {event['phase']} | Matrix rows start at the top; printed bit 0 is on the right.")
        self.draw()
        print(f"\n\033[36mStep {self.index + 1}: {event['title']}\033[0m\n{content}", flush=True)

    def seek(self, value):
        if not hasattr(self, "events"):
            return

        target = max(0, min(len(self.events) - 1, int(float(value))))

        if target != self.index:
            self.pause()
            self.index = target
            self.show()

    def move(self, change):
        self.pause()
        self.index = max(0, min(len(self.events) - 1, self.index + change))
        self.show()

    def jump_phase(self):
        self.pause()
        selected = self.phase.get()

        for index, event in enumerate(self.events):
            if event["phase"] == selected:
                self.index = index
                self.show()
                return

    def restart(self):
        self.jump_phase()

    def pause(self):
        self.playing = False

        if self.timer is not None:
            self.root.after_cancel(self.timer)
            self.timer = None

        if hasattr(self, "play_button"):
            self.play_button.configure(text="Play  [Space]")

    def toggle(self):
        if self.playing:
            self.pause()
        else:
            self.playing = True
            self.play_button.configure(text="Pause  [Space]")
            self.tick()

    def tick(self):
        if not self.playing:
            return

        if self.index >= len(self.events) - 1:
            self.pause()
            return

        self.index += 1
        self.show()
        self.timer = self.root.after(self.speed.get(), self.tick)

    def grid(self, rows, x, y, cell, title, event, changed=0):
        n = self.width
        c = self.canvas
        c.create_text(x + n * cell / 2, y - 42, text=title, fill=TEXT, font=("Segoe UI", 12))

        for row in range(n):
            for column in range(n):
                color = CELL

                if column == event["column"]:
                    color = "#183c58"

                if row == event["row"]:
                    color = "#17413c"

                if row == event["row"] and (changed >> column) & 1:
                    color = "#763235"

                if row == event["row"] and column == event["column"]:
                    color = "#885c25"

                left = x + column * cell
                top = y + row * cell
                c.create_rectangle(left, top, left + cell, top + cell, fill=color, outline="#31414e")
                bit_text = str((rows[row] >> column) & 1)

                if event["phase"] == PHASES[0] and title == "Source matrix M" and column > event["column"]:
                    bit_text = "."

                c.create_text(left + cell / 2, top + cell / 2, text=bit_text, fill=TEXT, font=("Consolas", max(8, int(cell * 0.43))))

            if n == 4 or row % 4 == 0 or row == event["row"]:
                c.create_text(x - 16, y + row * cell + cell / 2, text=str(row), fill=MUTED, font=("Consolas", 10))

        for column in range(n):
            if n == 4 or column % 4 == 0 or column == event["column"]:
                c.create_text(x + column * cell + cell / 2, y - 14, text=str(column), fill=MUTED, font=("Consolas", 10))

        if event["row"] >= 0:
            row_y = y + event["row"] * cell + cell / 2
            c.create_line(x - 32, row_y, x - 3, row_y, fill=ACCENT, arrow="last", width=2)

    def draw(self):
        if not hasattr(self, "events"):
            return

        c = self.canvas
        c.delete("all")
        event = self.events[self.index]
        w = max(650, c.winfo_width())

        if event["phase"] == PHASES[4]:
            self.draw_attack(event, w)
            return

        n = self.width
        cell = min(48, (w - 135) / (2 * n))
        cell = min(cell, max(8, (c.winfo_height() - 250) / n))
        left = event["left"]
        right = event["right"]
        left_title = "Source matrix M"
        right_title = "Identity rows attached"

        if event["phase"] == PHASES[2]:
            left_title = "Left half: M becomes I"
            right_title = "Right half: I becomes inverse(M)"
        elif event["phase"] == PHASES[3]:
            left_title = "Inverse matrix: select one row"
            right_title = "Input vector y (bit 0 at TOP)"

        x1 = 44
        x2 = x1 + n * cell + 60
        y = 70
        self.grid(left, x1, y, cell, left_title, event, event.get("changed_left", 0))

        if event["phase"] == PHASES[3]:
            vector_x = x2 + n * cell / 2
            c.create_text(vector_x, y - 42, text=right_title, fill=TEXT, font=("Segoe UI", 11))

            for row in range(n):
                color = CELL

                if (event["left"][event["row"]] >> row) & 1:
                    color = "#17413c"

                c.create_rectangle(vector_x - cell / 2, y + row * cell, vector_x + cell / 2, y + (row + 1) * cell, fill=color, outline=BLUE)
                c.create_text(vector_x, y + (row + 0.5) * cell, text=str((event["input_value"] >> row) & 1), fill=TEXT, font=("Consolas", max(8, int(cell * 0.43))))
        else:
            self.grid(right, x2, y, cell, right_title, event, event.get("changed_right", 0))

        strip = event.get("strip")

        if strip:
            label, value, selected = strip
            strip_y = y + n * cell + 60
            c.create_text(30, strip_y - 22, text=label, anchor="w", fill=ACCENT, font=("Segoe UI", 12))
            size = min(38, (w - 65) / n)

            for index in range(n):
                bit = n - 1 - index
                color = CELL

                if bit == selected:
                    color = "#885c25"

                x = 32 + index * size
                c.create_rectangle(x, strip_y, x + size, strip_y + 30, fill=color, outline=MUTED)
                c.create_text(x + size / 2, strip_y + 15, text=str((value >> bit) & 1), fill=TEXT, font=("Consolas", 12))

                if n == 4 or bit % 4 == 0 or bit == selected:
                    c.create_text(x + size / 2, strip_y + 43, text=str(bit), fill=MUTED, font=("Consolas", 9))

            if event["row"] >= 0 and event["column"] >= 0:
                start_x = x1 + (event["column"] + 0.5) * cell
                start_y = y + (event["row"] + 0.5) * cell
                target_bit = max(0, selected)
                target_x = 32 + (n - 1 - target_bit + 0.5) * size
                bit_value = (event["left"][event["row"]] >> event["column"]) & 1
                self.animate_bit(start_x, start_y, target_x, strip_y + 15, bit_value)

        if n == 4:
            note = "4-bit teaching matrix: the real attack uses the 32-bit SM4 matrix."
        else:
            note = "Real SM4 L matrix. Matrix columns increase to the right; the packed word below prints bit 0 on the right."

        c.create_text(25, max(y + n * cell + 125, c.winfo_height() - 28), text=note, anchor="w", fill=MUTED, width=w - 50, font=("Segoe UI", 10))

    def animate_bit(self, x1, y1, x2, y2, value):
        token = self.canvas.create_oval(x1 - 10, y1 - 10, x1 + 10, y1 + 10, fill=ORANGE, outline="")
        label = self.canvas.create_text(x1, y1, text=str(value), fill=BG, font=("Consolas", 10, "bold"))
        origin = self.index

        def frame(count):
            if origin != self.index or not self.canvas.winfo_exists():
                return

            fraction = count / 15
            x = x1 + (x2 - x1) * fraction
            y = y1 + (y2 - y1) * fraction
            self.canvas.coords(token, x - 10, y - 10, x + 10, y + 10)
            self.canvas.coords(label, x, y)

            if count < 15:
                self.pulse = self.root.after(20, frame, count + 1)
            else:
                self.canvas.delete(token)
                self.canvas.delete(label)
                self.pulse = None

        frame(0)

    def draw_attack(self, event, width):
        c = self.canvas
        data = event["attack"]
        size = min(48, (width - 85) / 16)

        for index, label in enumerate(("Correct ciphertext", "Faulty ciphertext")):
            field = "correct"

            if index == 1:
                field = "faulty"

            value = data.get(field)

            if value is None:
                continue

            y = 68 + 95 * index
            c.create_text(32, y - 25, text=label, fill=TEXT, anchor="w", font=("Segoe UI", 12))

            for byte in range(16):
                text = value[2 * byte:2 * byte + 2]
                color = TEXT

                if index == 1 and text != data["correct"][2 * byte:2 * byte + 2]:
                    color = RED

                x = 32 + byte * size
                c.create_rectangle(x, y, x + size, y + 34, fill=CELL, outline=MUTED)
                c.create_text(x + size / 2, y + 17, text=text, fill=color, font=("Consolas", 12))

        c.create_text(32, 230, text="Recovered subkey bytes: only unique candidates are written", fill=ACCENT, anchor="w", font=("Segoe UI", 13))

        for row, number in enumerate(range(31, 27, -1)):
            y = 260 + row * 50
            c.create_text(32, y + 20, text=f"rk{number}", fill=TEXT, anchor="w", font=("Consolas", 13))

            for byte in range(4):
                x = 120 + byte * 85
                value = data["recovered"].get(f"{number}:{byte}")
                text = "--"
                color = MUTED

                if value is not None:
                    text = f"{value:02X}"
                    color = GREEN

                c.create_rectangle(x, y, x + 72, y + 40, fill=CELL, outline=color)
                c.create_text(x + 36, y + 20, text=text, fill=color, font=("Consolas", 17))

        if "master_key" in data:
            c.create_text(32, 490, text="Master key: " + data["master_key"], fill=GREEN, anchor="w", font=("Consolas", 14))

    def close(self):
        self.pause()

        if self.pulse is not None:
            self.root.after_cancel(self.pulse)

        self.root.destroy()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify both matrix lessons and the attack without opening a window.")
    args = parser.parse_args(argv)

    if args.check:
        for width in (4, 32):
            events = matrix_lesson(width)
            print(f"Verified {width}-bit lesson: {len(events)} reversible calculation snapshots.")

        events = attack_lesson()
        print(f"Verified real SM4 recovery: {len(events)} scenes; final encrypt/decrypt PASS.")
        return 0

    root = tk.Tk()
    Animation(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_with_log(main, "animate_piret_sm4"))
