"""Build the concise full-file guide: python build_piret_sm4_guide.py."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from build_pdf import find_compiler

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
import piret_sm4
import sm4
from terminal_log import run_with_log


def generate_execution_flow(generated, recovered, plaintext, correct):
    """Turn actual solver events into a chronological, numerical call narrative."""
    lines = []
    completed_keys = {}
    used = 0

    for number in range(31, 27, -1):
        events = []

        for event in recovered["history"]:
            if event["round"] == number:
                events.append(event)

        clean_view = bytes.fromhex(events[0]["clean_view"])
        expected = piret_sm4.peel_sm4(correct, number, completed_keys)

        if clean_view != expected:
            raise RuntimeError("Execution-flow views disagree with real round peeling.")

        lines.extend([r"\subsubsection*{Round " + str(number) + r": input views and the byte loop}", r"Before this round, recovered subkeys are:"])
        labels = []

        for index, value in completed_keys.items():
            labels.append(f"rk{index}={value:08X}")

        if not labels:
            labels.append("none")

        lines.append(r"\hx{" + ", ".join(labels) + "}.")
        lines.extend([r"The clean view returned by \texttt{peel\_sm4} is", r"\[C_{\rm view}=\hx{" + clean_view.hex().upper() + r"}.\]"])

        if number < 31:
            words = []

            for offset in (12, 8, 4, 0):
                words.append(int.from_bytes(correct[offset:offset + 4], "big"))

            lines.extend([r"For the clean ciphertext, the peeling calls perform the following actual calculations in order. The last column is the recovered older state word:", r"\begin{center}\small\begin{tabular}{rllll}\toprule", r"Undone round & S-box input & $\tau$ output & $L$ output & Older word\\\midrule"])

            for undone in range(31, number, -1):
                a = words[0] ^ words[1] ^ words[2] ^ completed_keys[undone]
                b = sm4.sbox(a)
                diffusion = sm4.linear(b)
                previous = words[3] ^ diffusion
                lines.append(f"{undone} & {a:08X} & {b:08X} & {diffusion:08X} & {previous:08X}" + r"\\")
                words = [previous, words[0], words[1], words[2]]

            lines.append(r"\bottomrule\end{tabular}\end{center}")

        first_fault = events[0]
        lines.extend([r"The first oracle response for this round and its peeled view are", r"\[\begin{aligned}F&=\hx{" + first_fault["faulty"].upper() + r"},\\F_{\rm view}&=\hx{" + first_fault["faulty_view"].upper() + r"}.\end{aligned}\]", r"The filter operates on these views. In the table, ``fresh'' is the key-byte set for this pair and ``remaining'' is the intersection with earlier observations for the same byte.", r"\begin{center}\small\begin{tabular}{rrrlll}\toprule", r"Query & Byte & Mask & $\Delta B$ & Fresh & Remaining\\\midrule"])
        subkey = bytearray(4)
        milestones = []

        for event in events:
            used += 1
            fresh, inputs, delta = piret_sm4.sm4_byte_candidates(bytes.fromhex(event["clean_view"]), bytes.fromhex(event["faulty_view"]), event["byte"], event["mask"])
            fresh_labels = []
            remaining_labels = []

            for value in sorted(fresh):
                fresh_labels.append(f"{value:02X}")

            for value in event["survivors"]:
                remaining_labels.append(f"{value:02X}")

            lines.append(f"{used} & {event['byte']} & {event['mask']:02X} & {delta:08X} & " + " ".join(fresh_labels) + " & " + " ".join(remaining_labels) + r"\\")

            if event["remaining"] == 1:
                subkey[event["byte"]] = event["survivors"][0]
                milestones.append([event["byte"], event["survivors"][0], subkey.hex().upper(), used])

        if int.from_bytes(subkey, "big") != recovered["round_keys"][number]:
            raise RuntimeError("Execution-flow byte buffers do not assemble the recovered subkey.")

        lines.extend([r"\bottomrule\end{tabular}\end{center}", r"Unique bytes are written into the subkey buffer in the following order. Zero-filled positions not yet written are placeholders, not recovered bytes.", r"\begin{center}\small\begin{tabular}{rrlr}\toprule", r"Byte written & Value & Buffer after write & Queries used\\\midrule"])

        for byte, value, buffer, count in milestones:
            lines.append(f"{byte} & {value:02X} & {buffer} & {count}" + r"\\")

        completed_keys[number] = int.from_bytes(subkey, "big")
        next_action = "This word may be used to peel the next attacked round."

        if number == 28:
            next_action = "The four required subkeys are now known; leave the round loop and reverse the key schedule."

        lines.extend([r"\bottomrule\end{tabular}\end{center}", r"Only now is \texttt{keys[" + str(number) + r"]} assigned: $rk_{" + str(number) + r"}=\hx{" + f"{completed_keys[number]:08X}" + "}$. " + next_action])

    if used != recovered["used"]:
        raise RuntimeError("Execution-flow observation counts disagree with the solver.")

    (generated / "execution_observations.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    tail = []

    for number in range(28, 32):
        tail.append(completed_keys[number])

    schedule = {}

    def collect(index, value):
        schedule[index] = value

    master = piret_sm4.reverse_sm4(tail, observer=collect)
    lines = [r"\begin{center}\begin{tabular}{rlll}\toprule", r"$i$ & $K_i$ & $FK_i$ & $MK_i=K_i\oplus FK_i$\\\midrule"]

    for index in range(4):
        word = schedule[index] ^ sm4.FK[index]
        lines.append(f"{index} & {schedule[index]:08X} & {sm4.FK[index]:08X} & {word:08X}" + r"\\")

    lines.extend([r"\bottomrule\end{tabular}\end{center}", r"Concatenation returns the 16 bytes \hx{" + master.hex().upper() + "}."])
    (generated / "execution_fk.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Exercise the actual terminal entry point too, but avoid interactive input
    # and retain its long teaching output in a separate overwritten text file.
    captured = io.StringIO()

    with contextlib.redirect_stdout(captured):
        status = piret_sm4.main(["--faults", "8", "--row", "0", "--color", "never"])

    terminal = captured.getvalue()

    if status != 0 or "SM4 MASTER KEY: " + master.hex().upper() + " / PASS" not in terminal:
        raise RuntimeError("The real terminal entry point failed the execution-flow check.")

    (generated / "execution_terminal.txt").write_text(terminal, encoding="utf-8")
    data = dict(plaintext=plaintext.hex(), correct=correct.hex(), master_key=master.hex(), observations=recovered["history"], round_keys=completed_keys, faulty_outputs=used, terminal_exit_code=status)
    (generated / "execution_values.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("Verified chronological execution: all 32 observations, byte buffers, peeling, FK removal and the real terminal entry point.", flush=True)


def generate_row_building(generated):
    """Publish every loop iteration of the small example and one real SM4 row."""
    columns = [0b0101, 0b0011, 0b0010, 0b1000]
    lines = []
    rows = []
    records = []

    for row_index in range(4):
        matrix_row = 0
        lines.extend([r"\paragraph{Outer iteration: row\_index = " + str(row_index) + r".}", r"Start with \hx{matrix\_row = 0000}.", r"\begin{center}\small\begin{tabular}{rllllll}\toprule", r"$c$ & $C$ & Shifted & $b$ & Placed & Row before & Row after\\\midrule"])

        for column_index in range(4):
            column = columns[column_index]
            shifted = column >> row_index
            output_bit = shifted & 1
            placed = output_bit << column_index
            before = matrix_row
            matrix_row |= placed
            lines.append(f"{column_index} & {column:04b} & {shifted:04b} & {output_bit} & {placed:04b} & {before:04b} & {matrix_row:04b}" + r"\\")
            records.append(dict(width=4, row=row_index, column=column_index, source=column, shifted=shifted, bit=output_bit, placed=placed, before=before, after=matrix_row))

        identity = 1 << (4 + row_index)
        augmented = matrix_row | identity
        rows.append(augmented)
        formatted_rows = []

        for value in rows:
            formatted_rows.append(f"{value:02X}")

        lines.extend([r"\bottomrule\end{tabular}\end{center}", r"\[\begin{aligned}", r"\hx{identity\_bit}&=1\ll(4+" + str(row_index) + ")=" + str(1 << (4 + row_index)) + r"=\hx{" + f"{identity:08b}" + r"},\\", r"\hx{augmented\_row}&=\hx{" + f"{matrix_row:08b}" + r"}\,|\,\hx{" + f"{identity:08b}" + r"}=\hx{" + f"{augmented:08b}" + r"}.\end{aligned}\]", r"Append to \hx{rows}. List so far (hex): \hx{" + ", ".join(formatted_rows) + "}."])

    if rows != [0x13, 0x26, 0x41, 0x88]:
        raise RuntimeError("The complete row-building example failed.")

    (generated / "row_building_small.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    lines = [r"\begingroup\small\begin{longtable}{rllrlll}\toprule", r"$c$ & $L(2^c)$ & Shifted by 1 & $b$ & Placed & Row before & Row after\\\midrule", r"\endhead"]
    matrix_row = 0

    for column_index in range(32):
        column = sm4.linear(1 << column_index)
        shifted = column >> 1
        bit = shifted & 1
        placed = bit << column_index
        before = matrix_row
        matrix_row |= placed
        lines.append(f"{column_index} & {column:08X} & {shifted:08X} & {bit} & {placed:08X} & {before:08X} & {matrix_row:08X}" + r"\\")
        records.append(dict(width=32, row=1, column=column_index, source=column, shifted=shifted, bit=bit, placed=placed, before=before, after=matrix_row))

    if matrix_row != 0x80808202 or matrix_row | (1 << 33) != 0x0000000280808202:
        raise RuntimeError("The real SM4 row-building example failed.")

    lines.append(r"\bottomrule\end{longtable}\endgroup")
    (generated / "row_building_real.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (generated / "row_building_values.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print("Verified row construction: all 16 small-matrix iterations and all 32 columns of SM4 row 1.", flush=True)


def generate_examples(source):
    """Verify the numerical lesson against the current target and solver."""
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    clean, trace = piret_sm4.sm4_fault_encrypt(key, key)
    first, unused_trace = piret_sm4.sm4_fault_encrypt(key, key, 0, 1, 31)
    second, unused_trace = piret_sm4.sm4_fault_encrypt(key, key, 0, 2, 31)
    first_keys, first_inputs, delta = piret_sm4.sm4_byte_candidates(clean, first, 0, 1)
    second_keys, second_inputs, second_delta = piret_sm4.sm4_byte_candidates(clean, second, 0, 2)

    if first_keys != {0x90, 0x91} or first_inputs != {0x96, 0x97} or delta != 0x4F000000:
        raise RuntimeError("The first numerical example no longer matches the source.")

    if second_keys != {0x70, 0x72, 0x93, 0x91} or first_keys & second_keys != {0x91}:
        raise RuntimeError("The intersection example no longer matches the source.")

    if sm4.linear(1) != 0x01040405 or piret_sm4.inverse_rows()[0] != 0x51154505:
        raise RuntimeError("The inverse-matrix example no longer matches the source.")

    selected = piret_sm4.inverse_rows()[0] & 0x734E3D3D

    if selected != 0x51040505 or selected.bit_count() != 8:
        raise RuntimeError("The parity example no longer matches the source.")

    # Check the four-bit drawings using the same indexing as the real code.
    teaching_columns = [0b0101, 0b0011, 0b0010, 0b1000]
    teaching_rows = []

    for row_index in range(4):
        matrix_row = 0

        for column_index in range(4):
            bit = (teaching_columns[column_index] >> row_index) & 1
            matrix_row |= bit << column_index

        teaching_rows.append(matrix_row)

    if teaching_rows != [0b0011, 0b0110, 0b0001, 0b1000]:
        raise RuntimeError("The illustrated row traversal is inconsistent.")

    augmented = []

    for index, row in enumerate(teaching_rows):
        augmented.append(row | (1 << (4 + index)))

    if augmented[1] != 0b00100110 or augmented[2] ^ augmented[0] != 0b01010010:
        raise RuntimeError("The illustrated augmented row is inconsistent.")

    for column in range(4):
        pivot = None

        for candidate in range(column, 4):
            if (augmented[candidate] >> column) & 1:
                pivot = candidate
                break

        if pivot is None:
            raise RuntimeError("The teaching matrix is singular.")

        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]

        for row in range(4):
            if row != column and (augmented[row] >> column) & 1:
                augmented[row] ^= augmented[column]

    inverse = []

    for row in augmented:
        inverse.append(row >> 4)

    if inverse != [0b0100, 0b0101, 0b0111, 0b1000]:
        raise RuntimeError("The drawn teaching inverse is incorrect.")

    for word in range(16):
        transformed = 0

        for index, row in enumerate(teaching_rows):
            transformed |= ((row & word).bit_count() & 1) << index

        restored = 0

        for index, row in enumerate(inverse):
            restored |= ((row & transformed).bit_count() & 1) << index

        if restored != word:
            raise RuntimeError("The teaching inverse failed a four-bit round trip.")

    print("Verified drawings: row traversal, packed XOR, inverse and all 16 four-bit inputs.", flush=True)

    def oracle(number, byte, mask):
        ciphertext, target_trace = piret_sm4.sm4_fault_encrypt(key, key, byte, mask, number)
        return ciphertext

    recovered = piret_sm4.recover_sm4_master_key(clean, oracle)

    if not recovered["complete"] or recovered["master_key"] != key or recovered["used"] != 32:
        raise RuntimeError("The full-recovery example failed.")

    if sm4.sm4_encrypt_block(key, recovered["master_key"]) != clean or sm4.sm4_decrypt_block(clean, recovered["master_key"]) != key:
        raise RuntimeError("Recovered-key verification failed.")

    peeled = piret_sm4.peel_sm4(clean, 30, {31: recovered["round_keys"][31]})

    if peeled.hex().upper() != "D206965E86B3E94F536E42467B938F4C":
        raise RuntimeError("The peeling example no longer matches the source.")

    generated = source / "generated"
    generated.mkdir(exist_ok=True)
    generate_row_building(generated)
    generate_execution_flow(generated, recovered, key, clean)
    q = recovered["round_keys"][28] ^ recovered["round_keys"][29] ^ recovered["round_keys"][30] ^ sm4.CK[31]
    z = sm4.sbox(q)
    transformed = sm4.linear_key(z)
    k31 = recovered["round_keys"][31] ^ transformed
    reverse = [r"For the first backward step ($i=31$), substitute the recovered words:", r"\begin{align*}", r"Q&=\hx{428D3654}\xor\hx{62293496}\xor\hx{01CF72E5}\xor\hx{646B7279}\\", r"&=\hx{" + f"{q:08X}" + r"},\\", r"\tau(Q)&=\hx{" + f"{z:08X}" + r"},\qquad T'(Q)=\hx{" + f"{transformed:08X}" + r"},\\", r"K_{31}&=\hx{9124A012}\xor\hx{" + f"{transformed:08X}" + r"}=\hx{" + f"{k31:08X}" + r"}.\end{align*}", "The same rule repeats down to index 0; no further faulty encryptions are needed for this inversion."]
    (generated / "reverse_example.tex").write_text("\n".join(reverse) + "\n", encoding="utf-8")
    stages = [r"\begin{center}\begin{tabular}{ccc}\toprule", r"Recovered subkey & Value & Cumulative faulty outputs\\\midrule"]

    for number in range(31, 27, -1):
        cost = 0

        for event in recovered["history"]:
            if event["round"] >= number:
                cost += 1

        stages.append(r"$rk_{" + str(number) + r"}$ & \hx{" + f"{recovered['round_keys'][number]:08X}" + "} & " + str(cost) + r"\\")

    stages.extend([r"\bottomrule\end{tabular}\end{center}", r"This default-vector run uses 32 faulty outputs, plus the clean reference. It recovers $MK=\hx{0123456789ABCDEFFEDCBA9876543210}$. The observation count is an example result, not a universal physical requirement."])
    (generated / "recovery_example.tex").write_text("\n".join(stages) + "\n", encoding="utf-8")

    # Reject future undocumented functions rather than silently claiming coverage.
    path = ROOT / "src" / "piret_sm4.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.append(node.name)

    covered = ["sm4_fault_encrypt", "observer", "inverse_rows", "inverse_linear", "sm4_byte_candidates", "reverse_sm4", "peel_sm4", "recover_sm4_master_key", "main"]

    if sorted(functions) != sorted(covered):
        raise RuntimeError("Function coverage changed; update the written guide before building.")

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    info = r"\subsection{Source and verification record}" + "\n"
    info += r"This edition covers all eight top-level functions and the nested observer in \texttt{src/piret\_sm4.py}. Source SHA-256: \url{" + digest + "}.\n"
    info += "Its generated examples were checked using an actual complete recovery, matrix/parity checks, candidate intersections, peeling, re-encryption and decryption.\n"
    (generated / "source_info.tex").write_text(info, encoding="utf-8")
    (generated / "verification.json").write_text(json.dumps(dict(source_sha256=digest, covered_functions=covered, faulty_outputs=recovered["used"], master_key=recovered["master_key"].hex(), verified=True), indent=2) + "\n", encoding="utf-8")
    print("Verified all 9 functions/callbacks, example calculations and complete 32-output recovery.", flush=True)


def main():
    source = ROOT / "docs" / "piret_sm4_explained"
    generate_examples(source)
    output = ROOT / ".build" / "piret_sm4_explained"
    output.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["TECTONIC_CACHE_DIR"] = str(ROOT / ".tools" / "tectonic" / "cache")
    command = [str(find_compiler()), "-X", "compile", "--untrusted", "--keep-logs", "--outdir", str(output), "main.tex"]
    generated = output / "main.pdf"

    if generated.exists():
        generated.unlink()

    print("Compiling the independent function-by-function guide...", flush=True)
    # Print captured diagnostics through the shared TXT/HTML logger as well.
    completed = subprocess.run(command, cwd=source, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    print(completed.stdout, end="", flush=True)
    completed.check_returncode()

    if not generated.is_file() or not generated.read_bytes().startswith(b"%PDF-"):
        raise RuntimeError("The guide compiler did not produce a valid PDF.")

    destination = ROOT / "docs" / "Piret_SM4_Explained.pdf"
    temporary = destination.with_suffix(".pdf.tmp")
    shutil.copyfile(generated, temporary)
    temporary.replace(destination)
    print(f"PDF generated: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_with_log(main, "build_piret_sm4_guide"))
