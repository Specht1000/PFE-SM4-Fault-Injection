
# ============================================================
# PIRET-QUISQUATER-STYLE AES-128 KEY RECOVERY LESSON
# AES-128 / PFE 5A
#
# Requires aes.py in the same directory (src/).
#
# Run:
#     python piret.py
#
# Run with --step for pauses, --color always for ANSI colors.
# The terminal lesson reads aes.py configuration and injects before
# round-8 MixColumns, then recovers K10 and reverses the key schedule.
# Legacy round-9 helpers remain available for existing callers.
# ============================================================

import argparse
from contextlib import redirect_stdout
import io
from itertools import product
import os
import random
import sys
import aes
from aes import (bytes_to_state, state_to_bytes, key_expansion, sub_bytes, shift_rows, mix_columns, add_round_key, SBOX,)

# ============================================================
# LEGACY ROUND-9 RELATION DEMO CONFIGURATION
# The main key-recovery lesson reads KEY and PLAINTEXT from aes.py.
# ============================================================

KEY = "000102030405060708090A0B0C0D0E0F"
PLAINTEXT = "00112233445566778899AABBCCDDEEFF"

# Position of the injected fault in the AES state.
# Rows and columns range from 0 to 3.
FAULT_ROW = 0
FAULT_COL = 0

# Nonzero 8-bit fault mask.
FAULT_VALUE = 0x01

# ============================================================
# DISPLAY UTILITIES
# ============================================================

def show_state(title, state):
    print("\n" + title)
    print("-" * 32)
    for row in state:
        print(" ".join(f"{byte:02X}" for byte in row))


def difference(a, b):
    return [[a[r][c] ^ b[r][c] for c in range(4)] for r in range(4)]


def show_difference(title, a, b):
    show_state(title, difference(a, b))


def clone(state):
    return [row[:] for row in state]


# ============================================================
# AES ENCRYPTION WITH OPTIONAL FAULT
# ============================================================

def encrypt(plaintext, key, inject_fault=False):
    state = bytes_to_state(plaintext)
    round_keys = key_expansion(key)

    snapshots = {}

    # Round 0
    add_round_key(state, round_keys[0])

    # Rounds 1 through 9
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)

        if rnd == 9:
            snapshots["before_fault"] = clone(state)

            if inject_fault:
                state[FAULT_ROW][FAULT_COL] ^= FAULT_VALUE

            snapshots["after_fault"] = clone(state)

        mix_columns(state)

        if rnd == 9:
            snapshots["after_mixcolumns"] = clone(state)

        add_round_key(state, round_keys[rnd])

    # Final round (no MixColumns)
    snapshots["before_last_subbytes"] = clone(state)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    snapshots["ciphertext"] = clone(state)

    return state_to_bytes(state), snapshots, round_keys


# ============================================================
# AES INVERSE S-BOX
# ============================================================

INV_SBOX = [0] * 256

for index, value in enumerate(SBOX):
    INV_SBOX[value] = index


# ============================================================
# GF(2^8) MULTIPLICATION
# ============================================================

def gf_multiply(a, b):
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        carry = a & 0x80
        a = (a << 1) & 0xFF

        if carry:
            a ^= 0x1B

        b >>= 1

    return result


MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]


def predicted_mixcolumns_difference(row, fault):
    return [gf_multiply(MIX_MATRIX[r][row], fault) for r in range(4)]


# ============================================================
# RECONSTRUCT THE DIFFERENCE BEFORE FINAL SUBBYTES
#
# We use the known round key ONLY to demonstrate the
# mathematical relationship. In a real DFA attack,
# the corresponding key bytes are unknown.
# ============================================================

def reverse_last_round_difference(correct_ciphertext, faulty_ciphertext, last_round_key,):
    correct = bytes_to_state(correct_ciphertext)
    faulty = bytes_to_state(faulty_ciphertext)

    # Undo final AddRoundKey
    for r in range(4):
        for c in range(4):
            correct[r][c] ^= last_round_key[r][c]
            faulty[r][c] ^= last_round_key[r][c]

    # Undo ShiftRows: rotate row r to the right by r.
    for r in range(1, 4):
        correct[r] = correct[r][-r:] + correct[r][:-r]
        faulty[r] = faulty[r][-r:] + faulty[r][:-r]

    # Undo SubBytes
    for r in range(4):
        for c in range(4):
            correct[r][c] = INV_SBOX[correct[r][c]]
            faulty[r][c] = INV_SBOX[faulty[r][c]]

    return difference(correct, faulty)


# ============================================================
# MAIN SIMULATION
# ============================================================

def relation_demo():
    key = bytes.fromhex(KEY)
    plaintext = bytes.fromhex(PLAINTEXT)

    if len(key) != 16 or len(plaintext) != 16:
        raise ValueError("KEY and PLAINTEXT must each contain 16 bytes.")

    if not (0 <= FAULT_ROW < 4 and 0 <= FAULT_COL < 4):
        raise ValueError("Fault row/column must be 0..3.")

    if not (1 <= FAULT_VALUE <= 255):
        raise ValueError("FAULT_VALUE must be 0x01..0xFF.")

    print("=" * 55)
    print("PIRET-QUISQUATER - AES-128 FAULT SIMULATION")
    print("=" * 55)

    print(f"\nKEY       : {KEY}")
    print(f"PLAINTEXT : {PLAINTEXT}")
    print(f"FAULT     : row={FAULT_ROW}, col={FAULT_COL}")
    print(f"MASK      : 0x{FAULT_VALUE:02X}")

    correct_ct, correct, round_keys = encrypt(plaintext, key, inject_fault=False)

    faulty_ct, faulty, _ = encrypt(plaintext, key, inject_fault=True)

    # --------------------------------------------------------
    # 1. Fault injection
    # --------------------------------------------------------

    show_state("ROUND 9 - BEFORE FAULT", correct["before_fault"],)

    show_state("ROUND 9 - AFTER FAULT", faulty["after_fault"],)

    show_difference("DIFFERENCE BEFORE MIXCOLUMNS", correct["before_fault"], faulty["after_fault"],)

    # --------------------------------------------------------
    # 2. Fault propagation through MixColumns
    # --------------------------------------------------------

    show_difference("DIFFERENCE AFTER MIXCOLUMNS", correct["after_mixcolumns"], faulty["after_mixcolumns"],)

    expected = predicted_mixcolumns_difference(FAULT_ROW, FAULT_VALUE)

    print("\nPREDICTED DIFFERENCE IN AFFECTED COLUMN:")
    print(" ".join(f"{x:02X}" for x in expected))

    actual_mix_diff = difference(correct["after_mixcolumns"], faulty["after_mixcolumns"],)

    actual_column = [actual_mix_diff[r][FAULT_COL] for r in range(4)]

    assert actual_column == expected, ("MixColumns propagation does not match.")

    # --------------------------------------------------------
    # 3. Final round
    # --------------------------------------------------------

    show_difference("DIFFERENCE BEFORE FINAL SUBBYTES", correct["before_last_subbytes"], faulty["before_last_subbytes"],)

    print("\nCORRECT CIPHERTEXT:")
    print(correct_ct.hex().upper())

    print("\nFAULTY CIPHERTEXT:")
    print(faulty_ct.hex().upper())

    ct_difference = bytes(a ^ b for a, b in zip(correct_ct, faulty_ct))

    print("\nCIPHERTEXT XOR DIFFERENCE:")
    print(ct_difference.hex().upper())

    changed_positions = [i for i, byte in enumerate(ct_difference) if byte != 0]

    print("\nCHANGED BYTE POSITIONS:")
    print(changed_positions)

    # --------------------------------------------------------
    # 4. Verify Piret-Quisquater differential relation
    # --------------------------------------------------------

    recovered_difference = reverse_last_round_difference(correct_ct, faulty_ct, round_keys[10],)

    show_state("DIFFERENCE RECOVERED BEFORE LAST SUBBYTES", recovered_difference,)

    expected_full = [[0] * 4 for _ in range(4)]

    for r in range(4):
        expected_full[r][FAULT_COL] = expected[r]

    assert recovered_difference == expected_full, ("DFA differential relation failed.")

    print("\n" + "=" * 55)
    print("RESULT")
    print("=" * 55)
    print("MixColumns fault propagation: PASS")
    print("Inverse last-round differential: PASS")

    print("\nNOTE:")
    print("The key was known in this simulation.")
    print("This verifies the DFA relation; it does")
    print("not recover an unknown key.")


def trace_round8(plaintext, key, row=0, column=0, mask=0, fault_round=8):
    """Simulator only: XOR a byte before selected round-8/9 MixColumns.

    The old encrypt() above retains its round-9 behavior for existing callers.
    This earlier location makes all four key groups observable in one output.
    """
    if len(plaintext) != 16 or len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key and plaintext.")
    if not (0 <= row < 4 and 0 <= column < 4 and 0 <= mask <= 255):
        raise ValueError("Fault coordinates must be 0..3 and mask 0..255.")
    if fault_round not in (8, 9):
        raise ValueError("Fault round must be 8 or 9.")
    state, keys, trace = bytes_to_state(plaintext), key_expansion(key), []

    def record(number, operation):
        trace.append((number, operation, state_to_bytes(state)))

    add_round_key(state, keys[0])
    for number in range(1, 11):
        sub_bytes(state)
        record(number, "SubBytes")
        shift_rows(state)
        record(number, "ShiftRows")
        if number == fault_round:
            state[row][column] ^= mask
            record(number, "Fault point")
        if number != 10:
            # Implement the same column operation without the terminal demo's prints.
            for col in range(4):
                original = [state[r][col] for r in range(4)]
                for r in range(4):
                    value = 0
                    for index in range(4):
                        value ^= gf_multiply(MIX_MATRIX[r][index], original[index])
                    state[r][col] = value
            record(number, "MixColumns")
        add_round_key(state, keys[number])
        record(number, "AddRoundKey")
    return state_to_bytes(state), trace


def output_positions(column):
    """Undo the final ShiftRows position mapping, keeping row order."""
    return tuple(4 * ((column - row) % 4) + row for row in range(4))


def key_candidates(correct, faulty, column):
    """Derive four-byte K10 candidates from ciphertexts only.

    For each guessed byte k, undo final AddRoundKey and SubBytes:
      d = InvSbox[C[p] XOR k] XOR InvSbox[Cfault[p] XOR k].
    All four differences must fit ONE matrix column times ONE unknown error.
    """
    tables = []
    for position in output_positions(column):
        table = [[] for _ in range(256)]
        for guess in range(256):
            delta = INV_SBOX[correct[position] ^ guess] ^ INV_SBOX[faulty[position] ^ guess]
            table[delta].append(guess)
        tables.append(table)
    found = set()
    for unknown_row in range(4):
        for unknown_error in range(1, 256):
            choices = [tables[r][gf_multiply(MIX_MATRIX[r][unknown_row], unknown_error)] for r in range(4)]
            found.update(product(*choices))
    return found


def recover_last_key(correct, faulty_outputs, observer=None):
    """Attacker API: no master key, plaintext, fault mask or internal states.

    The optional observer is for logging only; it cannot modify candidate sets.
    A None result means ambiguity, never an arbitrary candidate selection.
    """
    if len(correct) != 16:
        raise ValueError("Correct ciphertext must contain 16 bytes.")
    groups, used = [None] * 4, 0
    for used, faulty in enumerate(faulty_outputs, 1):
        if len(faulty) != 16 or any(a == b for a, b in zip(correct, faulty)):
            raise ValueError("Expected 16 changed output bytes for the round-8 byte-fault model.")
        for column in range(4):
            fresh = key_candidates(correct, faulty, column)
            before = None if groups[column] is None else len(groups[column])
            groups[column] = fresh if groups[column] is None else groups[column] & fresh
            if not groups[column]:
                raise ValueError("Empty candidate intersection: incompatible ciphertexts or fault model.")
            if observer:
                observer(used, column, before, len(fresh), tuple(sorted(groups[column])))
        if all(len(group) == 1 for group in groups):
            last_key = bytearray(16)
            for column in range(4):
                for position, byte in zip(output_positions(column), next(iter(groups[column]))):
                    last_key[position] = byte
            return bytes(last_key), used
    return None, used


def reverse_key_schedule(last_key, observer=None):
    """AES-128 recurrence reversed: w[i-4] = w[i] XOR transform(w[i-1])."""
    if len(last_key) != 16:
        raise ValueError("K10 must contain 16 bytes.")
    words = [None] * 44
    words[40:] = [list(last_key[index:index+4]) for index in range(0, 16, 4)]
    for index in range(43, 3, -1):
        transformed = words[index - 1][:]
        if index % 4 == 0:
            transformed = [SBOX[byte] for byte in transformed[1:] + transformed[:1]]
            transformed[0] ^= aes.RCON[index // 4]
        words[index - 4] = [a ^ b for a, b in zip(words[index], transformed)]
        if observer:
            observer(index, bytes(words[index]), bytes(transformed), bytes(words[index - 4]))
    return bytes(sum(words[:4], []))


class Terminal:
    """ANSI styling is optional; redirected output stays readable by default."""
    def __init__(self, color="auto", step=False):
        self.color = color == "always" or color == "auto" and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        self.step = step
        if self.color and os.name == "nt":
            # Enable virtual-terminal processing without requiring colorama.
            import ctypes
            kernel = ctypes.windll.kernel32
            handle, mode = kernel.GetStdHandle(-11), ctypes.c_ulong()
            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)) or not kernel.SetConsoleMode(handle, mode.value | 4):
                self.color = color == "always"

    def paint(self, text, code="36"):
        return f"\033[{code}m{text}\033[0m" if self.color else str(text)

    def section(self, title):
        print("\n" + self.paint("=" * 76, "36"))
        print(self.paint(title, "1;36"))

    def pause(self):
        if self.step:
            input("\nPress Enter to continue...")

    def compare(self, correct, faulty):
        delta = bytes(a ^ b for a, b in zip(correct, faulty))
        print("          CLEAN STATE         FAULTY STATE        XOR DIFFERENCE")
        for row in range(4):
            clean_cells, faulty_cells, diff_cells = [], [], []
            for column in range(4):
                index = 4 * column + row
                clean_cells.append(f"{correct[index]:02X}")
                faulty_cells.append(self.paint(f"{faulty[index]:02X}", "31") if delta[index] else f"{faulty[index]:02X}")
                diff_cells.append(self.paint(f"{delta[index]:02X}", "31") if delta[index] else "00")
            print(f"row {row}:    {' '.join(clean_cells)}        {' '.join(faulty_cells)}        {' '.join(diff_cells)}")
        changed = [i for i, byte in enumerate(delta) if byte]
        print(f"Changed bytes: {len(changed)}/16 | Changed bits: {sum(bin(b).count('1') for b in delta)}/128")
        print(f"Changed flat positions (4*column+row): {changed}")


def aes_target_encrypt(plaintext, key):
    """Call the actual aes.py cipher while suppressing its teaching print/pause."""
    previous = aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS
    try:
        aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS = False, False
        with redirect_stdout(io.StringIO()):
            return aes.aes_encrypt(plaintext, key)
    finally:
        aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS = previous


def main(argv=None):
    parser = argparse.ArgumentParser(description="Recover the AES-128 key configured in aes.py with a didactic Piret-style software DFA.")
    parser.add_argument("--step", action="store_true", help="Pause after each teaching stage and key-schedule round.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--faults", type=int, default=8, help="Maximum distinct faulty outputs (1..255).")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--row", type=int, choices=range(4), default=FAULT_ROW)
    parser.add_argument("--column", type=int, choices=range(4), default=FAULT_COL)
    args = parser.parse_args(argv)
    try:
        # Only the target simulator reads aes.KEY; the solver receives ciphertexts.
        target_key, plaintext = bytes.fromhex(aes.KEY), bytes.fromhex(aes.PLAINTEXT)
        if len(target_key) != 16 or len(plaintext) != 16 or not 1 <= args.faults <= 255:
            raise ValueError("aes.py KEY/PLAINTEXT must each contain 16 bytes; --faults must be 1..255.")
    except ValueError as error:
        parser.error(str(error))
    terminal = Terminal(args.color, args.step)
    terminal.section("1. TARGET: THE AES KEY CONFIGURED IN aes.py")
    print("The target simulator uses aes.KEY and aes.PLAINTEXT, exactly as configured in aes.py.")
    print("The recovery function receives only correct/faulty ciphertexts; it never reads aes.KEY.")
    print("Software fault: one unknown nonzero byte XOR before round-8 MixColumns.")
    print("This simplified Piret-style solver may require more than two faulty outputs.")
    print("Matrices: AES rows, column-major byte index = 4*column + row.")
    correct = aes_target_encrypt(plaintext, target_key)
    reference, clean_trace = trace_round8(plaintext, target_key)
    if correct != reference:
        raise RuntimeError("Trace simulator does not match aes.py encryption.")
    print("Plaintext:          " + plaintext.hex().upper())
    print("Correct ciphertext: " + correct.hex().upper())
    terminal.pause()
    masks = random.Random(args.seed).sample(range(1, 256), args.faults)
    first_faulty, first_trace = trace_round8(plaintext, target_key, args.row, args.column, masks[0])
    clean_lookup = {(number, op): state for number, op, state in clean_trace}
    selected = {(8, "ShiftRows"), (8, "Fault point"), (8, "MixColumns"), (9, "SubBytes"), (9, "ShiftRows"), (9, "MixColumns"), (10, "AddRoundKey")}
    terminal.section("2. TEACHER VIEW: WHAT CHANGES INSIDE THE AES STATE")
    print(f"First simulated fault: row {args.row}, column {args.column}, XOR mask {masks[0]:02X}.")
    print("Red = modified byte or nonzero XOR. These hidden states are NOT solver inputs.")
    for number, operation, state in first_trace:
        if (number, operation) in selected:
            print(terminal.paint(f"\nRound {number:02d} / {operation}", "1;33"))
            terminal.compare(clean_lookup[number, operation], state)
            terminal.pause()
    print("Propagation: 1 changed byte -> 4 in one column -> 1 per column -> 16 changed bytes.")
    terminal.section("3. THE FOUR EQUATIONS FOR EACH KEY GROUP")
    print("d[r] = InvSbox[C[p[r]] XOR k[r]] XOR InvSbox[Cfault[p[r]] XOR k[r]]")
    print("If the effective round-9 fault is in row 0: d = [2e, e, e, 3e].")
    print("Other error rows use the other MixColumns matrix columns; multiplication is in GF(2^8).")
    print("The SAME unknown row and unknown e must satisfy all four equations together.")
    print("The round-9 effective error is generally NOT the round-8 injected mask.")
    print("Try 256 key-byte guesses, 4 effective fault rows, and 255 nonzero error values.")
    for column in range(4):
        print(f"Group {column}: K10/ciphertext positions {output_positions(column)}")
    terminal.pause()
    terminal.section("4. ATTACKER VIEW: COLLECT OUTPUTS AND INTERSECT CANDIDATE TUPLES")

    def observations():
        for index, mask in enumerate(masks, 1):
            faulty = first_faulty if index == 1 else trace_round8(plaintext, target_key, args.row, args.column, mask)[0]
            print(terminal.paint(f"\nObservation {index}", "1;36"))
            print("Correct: " + correct.hex().upper())
            print("Faulty:  " + faulty.hex().upper())
            print("XOR:     " + bytes(a ^ b for a, b in zip(correct, faulty)).hex().upper())
            yield faulty

    def report(index, column, before, fresh, survivors):
        after = len(survivors)
        print(f"  Group {column}: {fresh} tuples satisfy this pair.")
        print("    Remaining: " + ("unconstrained" if before is None else str(before)) + " -> " + terminal.paint(str(after), "32" if after == 1 else "33") + ("" if before is None else f" ({before-after} eliminated)"))
        examples = [" ".join(f"{byte:02X}" for byte in candidate) for candidate in survivors[:3]]
        print("    " + ("Unique tuple: " if after == 1 else "First candidates: ") + " | ".join(examples))
        if column == 3:
            terminal.pause()

    last_key, used = recover_last_key(correct, observations(), report)
    if last_key is None:
        print(terminal.paint(f"\nAMBIGUOUS after {used} observations. Increase --faults; no key is claimed.", "33"))
        return 2
    terminal.section("5. ASSEMBLE K10 AND CHECK THE RECOVERED DIFFERENTIAL EQUATIONS")
    print("Recovered K10: " + terminal.paint(last_key.hex().upper(), "1;32"))
    for column in range(4):
        deltas = []
        for position in output_positions(column):
            left = INV_SBOX[correct[position] ^ last_key[position]]
            right = INV_SBOX[first_faulty[position] ^ last_key[position]]
            deltas.append(left ^ right)
            print(f"  p={position:2d}, k={last_key[position]:02X}: InvSbox[{correct[position]:02X} XOR {last_key[position]:02X}] XOR InvSbox[{first_faulty[position]:02X} XOR {last_key[position]:02X}] = {left:02X} XOR {right:02X} = {left ^ right:02X}")
        witnesses = [(r, e) for r in range(4) for e in range(1, 256) if [gf_multiply(MIX_MATRIX[i][r], e) for i in range(4)] == deltas]
        if not witnesses:
            raise RuntimeError("Recovered key violates the differential equations.")
        r, e = witnesses[0]
        print(terminal.paint(f"  Group {column}: compatible effective row={r}, e={e:02X}. All 4 equations PASS.", "32"))
    terminal.pause()
    terminal.section("6. REVERSE THE AES-128 KEY SCHEDULE: K10 -> K0")
    print("Forward: w[i] = w[i-4] XOR T(w[i-1]); reverse: w[i-4] = w[i] XOR T(w[i-1]).")
    print("T is RotWord -> SubWord -> Rcon when i is a multiple of 4; otherwise T is identity.")

    def schedule_report(index, current, transformed, previous):
        print(f"w[{index-4:02d}] = w[{index:02d}] XOR T(w[{index-1:02d}]) = {current.hex().upper()} XOR {transformed.hex().upper()} = " + terminal.paint(previous.hex().upper(), "32"))
        if index % 4 == 0:
            terminal.pause()

    recovered = reverse_key_schedule(last_key, schedule_report)
    terminal.section("7. VERIFY THE RECOVERED MASTER KEY")
    print("Recovered K0: " + terminal.paint(recovered.hex().upper(), "1;32"))
    verified = aes_target_encrypt(plaintext, recovered)
    print("Expected ciphertext: " + correct.hex().upper())
    print("Recovered-key AES:   " + verified.hex().upper())
    if verified != correct or recovered != target_key:
        raise RuntimeError("Recovered key verification failed.")
    print("aes.py KEY (revealed only for final ground-truth comparison): " + target_key.hex().upper())
    print(terminal.paint(f"KEY RECOVERY: PASS using {used} faulty ciphertexts.", "1;32"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nLesson stopped.")
