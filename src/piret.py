"""Piret-style AES differential fault analysis: simulation, solving and teaching.

Author: Guilherme Martins Specht / PFE 5A / Polytech Montpellier.

The target simulator receives a secret key and can expose internal states for a
teacher view. The attacker functions receive ciphertext observations only.
Keeping these roles explicit prevents a known-key demonstration from being
mistaken for a real reconstruction of unknown key bytes.

Fault models: round 8 reaches all four final-round key groups; round 9 reaches
one group and must be repeated across columns. Both inject a nonzero byte XOR
immediately before MixColumns. The default CLI uses round 8; run.py follows the
PDF round-9 model. Existing public helper names remain available to callers.

Read sections 3-6 for the mathematics, then sections 7-9 for terminal output.
Run: python src/piret.py --step
"""


import argparse
from contextlib import redirect_stdout
import io
from itertools import product
import os
import random
import sys
import aes
from aes import bytes_to_state, state_to_bytes, key_expansion, sub_bytes, shift_rows, mix_columns, add_round_key, SBOX


# ============================================================================
# 1. CONFIGURATION FOR THE LEGACY KNOWN-KEY DEMONSTRATION
# ============================================================================


# Only relation_demo() uses these legacy example values.
# main() reads aes.KEY/aes.PLAINTEXT; every simulation engine gets explicit inputs.
KEY = "000102030405060708090A0B0C0D0E0F"
PLAINTEXT = "00112233445566778899AABBCCDDEEFF"
FAULT_ROW = 0
FAULT_COL = 0
FAULT_VALUE = 0x01


# ============================================================================
# 2. INVERSE S-BOX AND DIFFUSION CONSTANTS
# ============================================================================


# Build the inverse table once: INV_SBOX[SBOX[x]] == x for every byte x.
INV_SBOX = [0] * 256
for index, value in enumerate(SBOX):
    INV_SBOX[value] = index

# Share the specification matrix with the AES implementation; never mutate it.
MIX_MATRIX = aes.MIX_MATRIX


# ============================================================================
# 3. STATE HELPERS AND FINITE-FIELD DIFFERENTIALS
# ============================================================================


def difference(a, b):
    """Return a fresh XOR-difference matrix; inputs are never modified."""
    return [[a[r][c] ^ b[r][c] for c in range(4)] for r in range(4)]


def clone(state):
    """Copy each row so a stored snapshot does not alias the active state."""
    return [row[:] for row in state]


def gf_multiply(a, b):
    """Retain the historical DFA helper name while sharing AES field arithmetic.

    This makes the cipher and its differential equations use the same reduction
    polynomial. The data being modeled is still a byte, not an integer product.
    """
    return aes.gf_mul(a, b)


def predicted_mixcolumns_difference(row, fault):
    """Multiply the selected unit-column error by the AES mixing matrix.

    For fault row 0 the result is [2e, e, e, 3e]. Multiplications are in GF(2^8).
    """
    return [gf_multiply(MIX_MATRIX[r][row], fault) for r in range(4)]


def reverse_last_round_difference(correct_ciphertext, faulty_ciphertext, last_round_key,):
    """Verify the differential relation with an already known K10 matrix.

    This is a teacher-only check. It must not be confused with key_candidates,
    which enumerates unknown key guesses from observable ciphertext pairs.
    """
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


# ============================================================================
# 4. TARGET SIMULATION: ROUND-8/9 FAULTS AND IMMUTABLE TRACES
# ============================================================================


def encrypt_with_trace(plaintext, key, row=0, column=0, mask=0, fault_round=8):
    """Simulator only: XOR a byte before selected round-8/9 MixColumns.

    Round 8 lets one fault propagate into all four final-round key groups.
    Round 9 constrains one group; the PDF runner repeats across all columns.
    mask=0 records a clean execution at the same labeled injection point.
    Snapshots are immutable bytes, so later operations cannot overwrite them.
    """
    if len(plaintext) != 16 or len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key and plaintext.")
    if not (0 <= row < 4 and 0 <= column < 4 and 0 <= mask <= 255):
        raise ValueError("Fault coordinates must be 0..3 and mask 0..255.")
    if fault_round not in (8, 9):
        raise ValueError("Fault round must be 8 or 9.")
    state, keys, trace = bytes_to_state(plaintext), key_expansion(key), []

    def record(number, operation):
        # Serialize now: retaining a reference to state would corrupt old steps.
        trace.append((number, operation, state_to_bytes(state)))

    add_round_key(state, keys[0])
    for number in range(1, 11):
        sub_bytes(state)
        record(number, "SubBytes")
        shift_rows(state)
        record(number, "ShiftRows")
        if number == fault_round:
            # One transient data fault: do not modify key material or the S-box.
            state[row][column] ^= mask
            record(number, "Fault point")
        if number != 10:
            # Use the pure single-column AES helper to avoid presentation prints.
            for col in range(4):
                mixed = aes.mix_column([state[r][col] for r in range(4)])
                for r in range(4):
                    state[r][col] = mixed[r]
            record(number, "MixColumns")
        add_round_key(state, keys[number])
        record(number, "AddRoundKey")
    return state_to_bytes(state), trace


def trace_round8(plaintext, key, row=0, column=0, mask=0, fault_round=8):
    """Backward-compatible name used by terminal, GUI and MATLAB export tools.

    Despite its historical name, fault_round explicitly supports both 8 and 9.
    New simulation code should read encrypt_with_trace for the complete engine.
    """
    return encrypt_with_trace(plaintext, key, row, column, mask, fault_round)


def encrypt(plaintext, key, inject_fault=False):
    """Compatibility API for the original round-9 known-key relation lesson.

    Return (ciphertext, named state snapshots, round-key matrices). The public
    fault globals still control this helper, but the underlying engine receives
    them as explicit arguments instead of modifying global cipher behavior.
    """
    ciphertext, trace = encrypt_with_trace(plaintext, key, FAULT_ROW, FAULT_COL, FAULT_VALUE if inject_fault else 0, fault_round=9)
    states = {(number, operation): value for number, operation, value in trace}
    snapshot_points = {"before_fault": (9, "ShiftRows"), "after_fault": (9, "Fault point"), "after_mixcolumns": (9, "MixColumns"), "before_last_subbytes": (9, "AddRoundKey"), "ciphertext": (10, "AddRoundKey")}
    snapshots = {name: bytes_to_state(states[point]) for name, point in snapshot_points.items()}
    return ciphertext, snapshots, key_expansion(key)


def aes_target_encrypt(plaintext, key):
    """Call the actual aes.py cipher while suppressing its teaching print/pause."""
    previous = aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS
    try:
        aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS = False, False
        with redirect_stdout(io.StringIO()):
            return aes.aes_encrypt(plaintext, key)
    finally:
        # Restore caller settings even if encryption or validation raises an error.
        aes.STEP_BY_STEP, aes.SHOW_CALCULATIONS = previous


# ============================================================================
# 5. ATTACKER VIEW: POSITION MAPPING AND KEY-CANDIDATE INTERSECTIONS
# ============================================================================


def output_positions(column):
    """Undo the final ShiftRows position mapping, keeping row order."""
    if not 0 <= column < 4:
        raise ValueError("AES column must be 0..3.")
    # Row r moves from column c to (c-r) mod 4 in the final ShiftRows.
    return tuple(4 * ((column - row) % 4) + row for row in range(4))


def key_candidates(correct, faulty, column):
    """Derive four-byte K10 candidates from ciphertexts only.

    For each guessed byte k, undo final AddRoundKey and SubBytes:
      d = InvSbox[C[p] XOR k] XOR InvSbox[Cfault[p] XOR k].
    All four differences must fit ONE matrix column times ONE unknown error.
    """
    if len(correct) != 16 or len(faulty) != 16:
        raise ValueError("Ciphertexts must each contain exactly 16 bytes.")
    # Each table maps a possible input difference d to compatible byte guesses.
    # Four small lookups avoid brute-force enumeration of all 2^32 quartets.
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
            # A single shared row/error must satisfy ALL four equations.
            # Independent byte filtering alone would lose this constraint.
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
            # An intersection can retain/remove candidates, never introduce new ones.
            groups[column] = fresh if groups[column] is None else groups[column] & fresh
            if not groups[column]:
                raise ValueError("Empty candidate intersection: incompatible ciphertexts or fault model.")
            if observer:
                observer(used, column, before, len(fresh), tuple(sorted(groups[column])))
        if all(len(group) == 1 for group in groups):
            # Group tuples are in pre-ShiftRows row order. Restore true K10 order.
            last_key = bytearray(16)
            for column in range(4):
                for position, byte in zip(output_positions(column), next(iter(groups[column]))):
                    last_key[position] = byte
            return bytes(last_key), used
    return None, used


# ============================================================================
# 6. REVERSE THE KEY SCHEDULE: FINAL ROUND KEY K10 TO MASTER KEY K0
# ============================================================================


def reverse_key_schedule(last_key, observer=None):
    """AES-128 recurrence reversed: w[i-4] = w[i] XOR transform(w[i-1]).

    Descending order guarantees that both right-hand words are already known.
    Reversal still uses the FORWARD S-box: its input word is known, so there
    is no reason to invert SubWord. This function never reads the master key.
    """
    if len(last_key) != 16:
        raise ValueError("K10 must contain 16 bytes.")
    words = [None] * 44
    # K10 occupies the final four schedule words, w40 through w43.
    words[40:] = [list(last_key[index:index+4]) for index in range(0, 16, 4)]
    for index in range(43, 3, -1):
        transformed = words[index - 1][:]
        if index % 4 == 0:
            # Same RotWord/SubWord/Rcon transformation as forward expansion.
            transformed = [SBOX[byte] for byte in transformed[1:] + transformed[:1]]
            transformed[0] ^= aes.RCON[index // 4]
        words[index - 4] = [a ^ b for a, b in zip(words[index], transformed)]
        if observer:
            observer(index, bytes(words[index]), bytes(transformed), bytes(words[index - 4]))
    return bytes(sum(words[:4], []))


# ============================================================================
# 7. PRESENTATION: MATRICES, ANSI COLORS AND OPTIONAL PAUSES
# ============================================================================


def show_state(title, state):
    """Display a row-indexed state without transposing its AES layout."""
    print("\n" + title)
    print("-" * 32)
    for row in state:
        print(" ".join(f"{byte:02X}" for byte in row))


def show_difference(title, a, b):
    """Present the difference rather than the two underlying secret states."""
    show_state(title, difference(a, b))


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
        """Wrap one fragment in ANSI codes; reset immediately to avoid color bleed."""
        return f"\033[{code}m{text}\033[0m" if self.color else str(text)

    def section(self, title):
        """Print a visible teaching boundary without affecting cryptographic data."""
        print("\n" + self.paint("=" * 76, "36"))
        print(self.paint(title, "1;36"))

    def pause(self):
        """Automatic execution remains the default unless --step was requested."""
        if self.step:
            input("\nPress Enter to continue...")

    def compare(self, correct, faulty):
        """Compare two 16-byte states in AES row order and highlight fault effects."""
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


# ============================================================================
# 8. LEGACY ROUND-9 RELATION CHECK WITH A KNOWN KEY
# ============================================================================


def relation_demo():
    """Original known-key illustration; the recovery CLI lives in main()."""
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


# ============================================================================
# 9. TERMINAL KEY-RECOVERY LESSON
# ============================================================================


def main(argv=None):
    """Orchestrate teacher views, ciphertext-only solving and final verification.

    Reading aes.KEY belongs to the target simulator. The solver is deliberately
    called with only outputs; known plaintext enters again during verification.
    """
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
