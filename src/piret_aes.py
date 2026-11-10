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
Run: python src/piret_aes.py --step
"""


import argparse
from itertools import product
import os
import random
import sys
import aes
from aes import bytes_to_state, state_to_bytes, key_expansion, SBOX


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

    # XOR corresponding positions; equal bytes become zero in the difference matrix.
    result_values = []

    for row in range(4):
        element_value_values = []

        for column in range(4):
            element_value_values.append(a[row][column] ^ b[row][column])

        result_values.append(element_value_values)

    return result_values


def clone(state):
    """Copy each row so a stored snapshot does not alias the active state."""

    # Copy every row as well as the outer list to prevent snapshot aliasing.
    result_values = []

    for row in state:
        result_values.append(row[:])

    return result_values


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

    result_values = []

    for candidate_row in range(4):
        result_values.append(gf_multiply(MIX_MATRIX[candidate_row][row], fault))

    return result_values


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
    """Run aes.py itself; this external observer injects and records the fault.

    Round 8 spreads to four key groups. Round 9 reaches one key quartet.
    No second AES implementation is used by the attacker.
    """

    if not (0 <= row < 4 and 0 <= column < 4 and 0 <= mask <= 255 and fault_round in (8, 9)):
        raise ValueError("Fault: row/column 0..3, mask 0..255, round 8 or 9.")

    trace = []

    def observer(number, operation, state):
        # Inject only once at the selected round and operation, outside the AES implementation.
        if number == fault_round and operation == "Before MixColumns":
            state[row][column] ^= mask
            trace.append((number, "Fault point", aes.state_to_bytes(state)))

        if number > 0 and operation.startswith("After "):
            trace.append((number, operation[6:], aes.state_to_bytes(state)))

    ciphertext = aes.aes_encrypt(plaintext, key, observer=observer)

    return ciphertext, trace


def trace_round8(plaintext, key, row=0, column=0, mask=0, fault_round=8):
    """Backward-compatible name used by terminal and GUI tools.

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

    if inject_fault:
        element_values_7 = FAULT_VALUE
    else:
        element_values_7 = 0

    ciphertext, trace = encrypt_with_trace(plaintext, key, FAULT_ROW, FAULT_COL, element_values_7, fault_round=9)

    states = {}

    for number, operation, value in trace:
        states[number, operation] = value

    snapshot_points = {"before_fault": (9, "ShiftRows"), "after_fault": (9, "Fault point"), "after_mixcolumns": (9, "MixColumns"), "before_last_subbytes": (9, "AddRoundKey"), "ciphertext": (10, "AddRoundKey")}

    snapshots = {}

    for name, point in snapshot_points.items():
        snapshots[name] = bytes_to_state(states[point])

    return ciphertext, snapshots, key_expansion(key)


def aes_target_encrypt(plaintext, key):
    """Normal baseline encryption, without an observer or any changed settings."""

    return aes.aes_encrypt(plaintext, key)


# ============================================================================
# 5. ATTACKER VIEW: POSITION MAPPING AND KEY-CANDIDATE INTERSECTIONS
# ============================================================================


def output_positions(column):
    """Undo the final ShiftRows position mapping, keeping row order."""

    if not 0 <= column < 4:
        raise ValueError("AES column must be 0..3.")

    # Row r moves from column c to (c-r) mod 4 in the final ShiftRows.
    element_values = []

    for row in range(4):
        element_values.append(4 * ((column - row) % 4) + row)

    return tuple(element_values)


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
        # Use 256 independent buckets, one for each possible inverse-S-box difference.
        table = []

        for unused_index in range(256):
            table.append([])

        for guess in range(256):
            # Remove a guessed final-key byte from both outputs before undoing their S-boxes.
            delta = INV_SBOX[correct[position] ^ guess] ^ INV_SBOX[faulty[position] ^ guess]
            # Record which byte guesses produce this difference; joint constraints are applied later.
            table[delta].append(guess)

        tables.append(table)

    found = set()

    for unknown_row in range(4):
        for unknown_error in range(1, 256):
            # A single shared row/error must satisfy ALL four equations.
            # Independent byte filtering alone would lose this constraint.
            choices = []

            for row in range(4):
                choices.append(tables[row][gf_multiply(MIX_MATRIX[row][unknown_row], unknown_error)])

            # Enumerate compatible four-byte combinations for this shared error pattern; deduplicate tuples.
            found.update(product(*choices))

    return found


def recover_last_key(correct, faulty_outputs, observer=None):
    """Attacker API: no master key, plaintext, fault mask or internal states.

    The optional observer is for logging only; it cannot modify candidate sets.
    A None result means ambiguity, never an arbitrary candidate selection.
    """

    if len(correct) != 16:
        raise ValueError("Correct ciphertext must contain 16 bytes.")

    # Track each quartet separately; None means no observation has constrained that group yet.
    groups, used = [None] * 4, 0

    for used, faulty in enumerate(faulty_outputs, 1):
        condition_value = len(faulty) != 16

        if not condition_value:
            has_match = False

            for input_value, candidate_byte in zip(correct, faulty):
                if input_value == candidate_byte:
                    has_match = True
                    break

            condition_value = has_match

        if condition_value:
            raise ValueError("Expected 16 changed output bytes for the round-8 byte-fault model.")

        for column in range(4):
            fresh = key_candidates(correct, faulty, column)

            if groups[column] is None:
                before = None
            else:
                before = len(groups[column])

            # An intersection can retain/remove candidates, never introduce new ones.
            if groups[column] is None:
                computed_value = fresh
            else:
                computed_value = groups[column] & fresh

            groups[column] = computed_value

            if not groups[column]:
                raise ValueError("Empty candidate intersection: incompatible ciphertexts or fault model.")

            if observer:
                observer(used, column, before, len(fresh), tuple(sorted(groups[column])))

        # All four quartets must be unique before claiming a complete final-round key.
        all_match = True

        for group in groups:
            if not len(group) == 1:
                all_match = False
                break

        if all_match:
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
    computed_value_values_2 = []

    for candidate_index in range(0, 16, 4):
        computed_value_values_2.append(list(last_key[candidate_index:candidate_index + 4]))

    words[40:] = computed_value_values_2

    for index in range(43, 3, -1):
        # Copy the known preceding word before applying the schedule core, if required.
        transformed = words[index - 1][:]

        if index % 4 == 0:
            # Same RotWord/SubWord/Rcon transformation as forward expansion.
            transformed_values = []

            for byte_2 in transformed[1:] + transformed[:1]:
                transformed_values.append(SBOX[byte_2])

            transformed = transformed_values
            transformed[0] ^= aes.RCON[index // 4]

        # Rearrange the forward recurrence: XOR removes the transformed neighboring word.
        computed_value_values = []

        for input_value, byte in zip(words[index], transformed):
            computed_value_values.append(input_value ^ byte)

        words[index - 4] = computed_value_values

        if observer:
            observer(index, bytes(words[index]), bytes(transformed), bytes(words[index - 4]))

    # Concatenate w0..w3 in their original order to reconstruct the AES master key.
    return bytes(sum(words[:4], []))


# ============================================================================
# 7. PRESENTATION: MATRICES, ANSI COLORS AND OPTIONAL PAUSES
# ============================================================================


def show_state(title, state):
    """Display a row-indexed state without transposing its AES layout."""

    print("\n" + title)
    print("-" * 32)

    for row in state:
        formatted_values = []

        for byte in row:
            formatted_values.append(f'{byte:02X}')

        print(' '.join(formatted_values))


def show_difference(title, a, b):
    """Present the difference rather than the two underlying secret states."""

    show_state(title, difference(a, b))


class Terminal:
    """ANSI styling is optional; redirected output stays readable by default."""
    def __init__(self, color="auto", step=False):
        # Respect explicit color settings, terminal capability and the NO_COLOR environment flag.
        self.color = color == "always" or color == "auto" and sys.stdout.isatty() and "NO_COLOR" not in os.environ

        self.step = step

        if self.color and os.name == "nt":
            # Enable virtual-terminal processing without requiring colorama.
            import ctypes
            kernel = ctypes.windll.kernel32
            handle, mode = kernel.GetStdHandle(-11), ctypes.c_ulong()

            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)) or not kernel.SetConsoleMode(handle, mode.value | 4):
                # Respect explicit color settings, terminal capability and the NO_COLOR environment flag.
                self.color = color == "always"

    def paint(self, text, code="36"):
        """Wrap one fragment in ANSI codes; reset immediately to avoid color bleed."""

        # Reset ANSI styling after each fragment so red does not leak into neighboring values.
        if self.color:
            result_value = f'\x1b[{code}m{text}\x1b[0m'
        else:
            result_value = str(text)

        return result_value

    def section(self, title):
        """Print a visible teaching boundary without affecting cryptographic data."""

        print("\n" + self.paint("=" * 76, "36"))
        print(self.paint(title, "1;36"))

    def pause(self):
        """Automatic execution remains the default unless --step was requested."""

        # Pause only in interactive step mode; ordinary execution and tests remain automatic.
        if self.step:
            input("\nPress Enter to continue...")

    def compare(self, correct, faulty):
        """Compare two 16-byte states in AES row order and highlight fault effects."""

        byte_values = []

        for input_value, byte_2 in zip(correct, faulty):
            byte_values.append(input_value ^ byte_2)

        delta = bytes(byte_values)

        print("          CLEAN STATE         FAULTY STATE        XOR DIFFERENCE")

        for row in range(4):
            clean_cells, faulty_cells, diff_cells = [], [], []

            for column in range(4):
                # Render AES rows while reading bytes in their actual column-major order.
                index = 4 * column + row
                clean_cells.append(f"{correct[index]:02X}")

                if delta[index]:
                    element_values_6 = self.paint(f'{faulty[index]:02X}', '31')
                else:
                    element_values_6 = f'{faulty[index]:02X}'

                faulty_cells.append(element_values_6)

                if delta[index]:
                    element_values_5 = self.paint(f'{delta[index]:02X}', '31')
                else:
                    element_values_5 = '00'

                diff_cells.append(element_values_5)

            print(f"row {row}:    {' '.join(clean_cells)}        {' '.join(faulty_cells)}        {' '.join(diff_cells)}")

        changed = []

        for candidate_index, byte_3 in enumerate(delta):
            if byte_3:
                changed.append(candidate_index)

        element_values = []

        for byte in delta:
            element_values.append(bin(byte).count('1'))

        print(f'Changed bytes: {len(changed)}/16 | Changed bits: {sum(element_values)}/128')
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

    formatted_values = []

    for x in expected:
        formatted_values.append(f'{x:02X}')

    print(' '.join(formatted_values))

    actual_mix_diff = difference(correct["after_mixcolumns"], faulty["after_mixcolumns"],)

    actual_column = []

    for row in range(4):
        actual_column.append(actual_mix_diff[row][FAULT_COL])


    assert actual_column == expected, ("MixColumns propagation does not match.")

    # --------------------------------------------------------
    # 3. Final round
    # --------------------------------------------------------

    show_difference("DIFFERENCE BEFORE FINAL SUBBYTES", correct["before_last_subbytes"], faulty["before_last_subbytes"],)

    print("\nCORRECT CIPHERTEXT:")
    print(correct_ct.hex().upper())

    print("\nFAULTY CIPHERTEXT:")
    print(faulty_ct.hex().upper())

    byte_values = []

    for input_value, byte in zip(correct_ct, faulty_ct):
        byte_values.append(input_value ^ byte)

    ct_difference = bytes(byte_values)

    print("\nCIPHERTEXT XOR DIFFERENCE:")
    print(ct_difference.hex().upper())

    changed_positions = []

    for index, byte_2 in enumerate(ct_difference):
        if byte_2 != 0:
            changed_positions.append(index)


    print("\nCHANGED BYTE POSITIONS:")
    print(changed_positions)

    # --------------------------------------------------------
    # 4. Verify Piret-Quisquater differential relation
    # --------------------------------------------------------

    recovered_difference = reverse_last_round_difference(correct_ct, faulty_ct, round_keys[10],)

    show_state("DIFFERENCE RECOVERED BEFORE LAST SUBBYTES", recovered_difference,)

    expected_full = []

    for unused_index in range(4):
        expected_full.append([0] * 4)


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

    parser.add_argument("--algorithm", choices=("aes",), default="aes", help="Select AES Piret or the controlled SM4 DFA extension.")
    parser.add_argument("--step", action="store_true", help="Pause after each teaching stage and key-schedule round.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--faults", type=int, default=8, help="Maximum distinct faulty outputs (1..255).")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--row", type=int, choices=range(4), default=FAULT_ROW)
    parser.add_argument("--column", type=int, choices=range(4), default=FAULT_COL)

    # Convert command-line strings to validated settings before querying the simulated target.
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

    # Use reproducible distinct nonzero errors; these simulator values are not solver inputs.
    masks = random.Random(args.seed).sample(range(1, 256), args.faults)

    first_faulty, first_trace = trace_round8(plaintext, target_key, args.row, args.column, masks[0])

    clean_lookup = {}

    for candidate_number, op, candidate_state in clean_trace:
        clean_lookup[candidate_number, op] = candidate_state

    terminal.section("2. TEACHER VIEW: WHAT CHANGES INSIDE THE AES STATE")

    print(f"First simulated fault: row {args.row}, column {args.column}, XOR mask {masks[0]:02X}.")
    print("Red = modified byte or nonzero XOR. These hidden states are NOT solver inputs.")

    for number, operation, state in first_trace:
        if number >= 8:
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

    displayed_groups = {}

    displayed_pair = {}

    # Generate target outputs lazily so recovery can stop as soon as all groups are unique.
    def observations():
        for index, mask in enumerate(masks, 1):
            if index == 1:
                faulty = first_faulty
            else:
                faulty = trace_round8(plaintext, target_key, args.row, args.column, mask)[0]

            print(terminal.paint(f"\nObservation {index}", "1;36"))
            print("Correct: " + correct.hex().upper())
            print("Faulty:  " + faulty.hex().upper())
            byte_values = []

            for input_value, byte in zip(correct, faulty):
                byte_values.append(input_value ^ byte)

            print('XOR:     ' + bytes(byte_values).hex().upper())

            if index > 1:
                _, propagation = trace_round8(plaintext, target_key, args.row, args.column, mask)

                for number, operation, state in propagation:
                    if number >= 8:
                        print(f"R{number:02d} {operation}")
                        terminal.compare(clean_lookup[number, operation], state)
                        terminal.pause()

            displayed_pair["faulty"] = faulty
            yield faulty

    # Keep display bookkeeping separate from the candidate sets owned by the solver.
    def report(index, column, before, fresh, survivors):
        import attack_steps

        attack_steps.emit(terminal, attack_steps.aes_piret(correct, displayed_pair["faulty"], column, displayed_groups.get(column)))

        displayed_groups[column] = set(survivors)

        after = len(survivors)

        print(f"  Group {column}: {fresh} tuples satisfy this pair.")

        if before is None:
            element_values_2 = 'unconstrained'
        else:
            element_values_2 = str(before)

        if after == 1:
            element_values_3 = '32'
        else:
            element_values_3 = '33'

        if before is None:
            element_values_4 = ''
        else:
            element_values_4 = f' ({before - after} eliminated)'

        print('    Remaining: ' + element_values_2 + ' -> ' + terminal.paint(str(after), element_values_3) + element_values_4)

        examples = []

        for candidate in survivors[:3]:
            formatted_values = []

            for byte in candidate:
                formatted_values.append(f'{byte:02X}')

            examples.append(' '.join(formatted_values))

        if after == 1:
            element_values = 'Unique tuple: '
        else:
            element_values = 'First candidates: '

        print('    ' + element_values + ' | '.join(examples))

        if column == 3:
            terminal.pause()

    # The solver consumes the ciphertext generator and stops when every quartet is unique.
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

        witnesses = []

        for row in range(4):
            for candidate_e in range(1, 256):
                filter_matches_values = []

                for candidate_index in range(4):
                    filter_matches_values.append(gf_multiply(MIX_MATRIX[candidate_index][row], candidate_e))

                if filter_matches_values == deltas:
                    witnesses.append((row, candidate_e))

        if not witnesses:
            raise RuntimeError("Recovered key violates the differential equations.")

        r, e = witnesses[0]

        print(terminal.paint(f"  Group {column}: compatible effective row={r}, e={e:02X}. All 4 equations PASS.", "32"))

    terminal.pause()

    terminal.section("6. REVERSE THE AES-128 KEY SCHEDULE: K10 -> K0")

    print("Forward: w[i] = w[i-4] XOR T(w[i-1]); reverse: w[i-4] = w[i] XOR T(w[i-1]).")
    print("T is RotWord -> SubWord -> Rcon when i is a multiple of 4; otherwise T is identity.")

    import attack_steps

    recovered, schedule_steps = attack_steps.aes_schedule(last_key)

    attack_steps.emit(terminal, schedule_steps)

    attack_steps.emit(terminal, attack_steps.verification("aes", plaintext, recovered, correct))

    terminal.section("7. VERIFY THE RECOVERED MASTER KEY")

    print("Recovered K0: " + terminal.paint(recovered.hex().upper(), "1;32"))

    # Re-encrypt with the recovered key and compare with the independently captured baseline.
    verified = aes_target_encrypt(plaintext, recovered)

    print("Expected ciphertext: " + correct.hex().upper())
    print("Recovered-key AES:   " + verified.hex().upper())

    if verified != correct or recovered != target_key:
        raise RuntimeError("Recovered key verification failed.")

    print("aes.py KEY (revealed only for final ground-truth comparison): " + target_key.hex().upper())
    print(terminal.paint(f"KEY RECOVERY: PASS using {used} faulty ciphertexts.", "1;32"))

    return 0


if __name__ == "__main__":
    from terminal_log import run_with_log

    raise SystemExit(run_with_log(main, "piret_aes"))
