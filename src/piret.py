
# ============================================================
# PIRET-QUISQUATER - EDUCATIONAL FAULT SIMULATION
# AES-128 / PFE 5A
#
# Requires aes.py in the same directory (src/).
#
# Run:
#     python piret.py
#
# Simulates a one-byte fault before MixColumns in round 9.
# Shows fault propagation and the DFA equations.
# ============================================================

from aes import (bytes_to_state, state_to_bytes, key_expansion, sub_bytes, shift_rows, mix_columns, add_round_key, SBOX,)

# ============================================================
# CONFIGURATION - MODIFY HERE
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

def main():
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


if __name__ == "__main__":
    main()
