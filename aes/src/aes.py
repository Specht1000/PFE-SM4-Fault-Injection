
# ============================================================
# AES-128 - DIDACTIC IMPLEMENTATION
# PFE 5A - Polytech Montpellier / STMicroelectronics
#
# Educational implementation:
# - AES-128 encryption
# - Key expansion
# - SubBytes
# - ShiftRows
# - MixColumns
# - AddRoundKey
# - State visualization after each operation
#
# Run: python aes.py
# ============================================================

# ============================================================
# 1. CONFIGURATION - CHANGE VALUES HERE
# ============================================================

KEY = "000102030405060708090A0B0C0D0E0F"

PLAINTEXT = "00112233445566778899AABBCCDDEEFF"

# True: pause after each operation (press Enter)
# False: execute everything automatically
STEP_BY_STEP = True

# True: show detailed calculations in MixColumns
SHOW_CALCULATIONS = True


# ============================================================
# 2. AES S-BOX
# ============================================================

SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,
    0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,
    0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,
    0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,
    0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,
    0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,
    0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,
    0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,
    0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,
    0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,
    0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,
    0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,
    0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,
    0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,
    0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,
    0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,
    0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
]

RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]


# ============================================================
# 3. DISPLAY FUNCTIONS
# ============================================================

def pause():
    if STEP_BY_STEP:
        input("\nPress ENTER to continue...")


def print_state(state, title):
    print(f"\n{title}")
    print("-" * 35)

    for row in range(4):
        print(
            "   " +
            "  ".join(f"{state[row][col]:02X}"
                      for col in range(4))
        )


def print_separator(round_number):
    print("\n" + "=" * 55)
    print(f"                 ROUND {round_number}")
    print("=" * 55)


# ============================================================
# 4. STATE CONVERSION
# AES uses COLUMN-MAJOR representation
# ============================================================

def bytes_to_state(data):
    state = [[0] * 4 for _ in range(4)]

    for col in range(4):
        for row in range(4):
            state[row][col] = data[4 * col + row]

    return state


def state_to_bytes(state):
    return bytes(
        state[row][col]
        for col in range(4)
        for row in range(4)
    )


# ============================================================
# 5. SUBBYTES
# Replace each byte using the AES S-BOX
# ============================================================

def sub_bytes(state):
    for row in range(4):
        for col in range(4):
            original = state[row][col]
            state[row][col] = SBOX[original]


# ============================================================
# 6. SHIFTROWS
# Row 0: shift 0
# Row 1: shift 1
# Row 2: shift 2
# Row 3: shift 3
# ============================================================

def shift_rows(state):
    for row in range(1, 4):
        state[row] = (
            state[row][row:] + state[row][:row]
        )


# ============================================================
# 7. FINITE FIELD ARITHMETIC
# Multiplication in GF(2^8)
# AES polynomial: x^8+x^4+x^3+x+1
# ============================================================

def xtime(a):
    result = a << 1

    if a & 0x80:
        result ^= 0x1B

    return result & 0xFF


def gf_mul(a, b):
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        a = xtime(a)
        b >>= 1

    return result


# ============================================================
# 8. MIXCOLUMNS
#
# [02 03 01 01]
# [01 02 03 01]
# [01 01 02 03]
# [03 01 01 02]
# ============================================================

MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
]


def mix_columns(state):
    for col in range(4):
        original = [state[row][col] for row in range(4)]
        result = [0] * 4

        for row in range(4):
            value = 0

            for k in range(4):
                value ^= gf_mul(
                    MIX_MATRIX[row][k],
                    original[k]
                )

            result[row] = value

        if SHOW_CALCULATIONS and col == 0:
            print("\nMixColumns - First column example:")
            print("Input:", [f"{x:02X}" for x in original])

            for row in range(4):
                terms = [
                    f"{MIX_MATRIX[row][k]:02X}*{original[k]:02X}"
                    for k in range(4)
                ]

                print(
                    f"b{row} = {' XOR '.join(terms)}"
                    f" = {result[row]:02X}"
                )

        for row in range(4):
            state[row][col] = result[row]


# ============================================================
# 9. ADDROUNDKEY
# State XOR Round Key
# ============================================================

def add_round_key(state, round_key):
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]


# ============================================================
# 10. KEY EXPANSION
# Generate 11 round keys (AES-128)
# ============================================================

def rot_word(word):
    return word[1:] + word[:1]


def sub_word(word):
    return [SBOX[b] for b in word]


def key_expansion(key):
    # AES-128: 44 words of 4 bytes
    words = [
        list(key[4 * i:4 * i + 4])
        for i in range(4)
    ]

    for i in range(4, 44):
        temp = words[i - 1].copy()

        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]

        new_word = [
            words[i - 4][j] ^ temp[j]
            for j in range(4)
        ]

        words.append(new_word)

    round_keys = []

    for round_number in range(11):
        key_bytes = []

        for i in range(4):
            key_bytes.extend(
                words[round_number * 4 + i]
            )

        round_keys.append(
            bytes_to_state(key_bytes)
        )

    return round_keys


# ============================================================
# 11. COMPLETE AES-128 ENCRYPTION
# ============================================================

def aes_encrypt(plaintext, key):
    state = bytes_to_state(plaintext)
    round_keys = key_expansion(key)

    print("\nINITIAL PLAINTEXT")
    print_state(state, "Initial State")
    pause()

    # --------------------------------------------------------
    # ROUND 0
    # --------------------------------------------------------

    print_separator(0)

    print_state(round_keys[0], "Initial Round Key")

    add_round_key(state, round_keys[0])
    print_state(state, "After AddRoundKey")

    pause()

    # --------------------------------------------------------
    # ROUNDS 1 TO 9
    # --------------------------------------------------------

    for round_number in range(1, 10):
        print_separator(round_number)

        print("\n[1] SUBBYTES")
        sub_bytes(state)
        print_state(state, "After SubBytes")
        pause()

        print("\n[2] SHIFTROWS")
        shift_rows(state)
        print_state(state, "After ShiftRows")
        pause()

        print("\n[3] MIXCOLUMNS")
        mix_columns(state)
        print_state(state, "After MixColumns")
        pause()

        print("\n[4] ADDROUNDKEY")
        print_state(
            round_keys[round_number],
            f"Round Key {round_number}"
        )

        add_round_key(
            state,
            round_keys[round_number]
        )

        print_state(state, "After AddRoundKey")
        pause()

    # --------------------------------------------------------
    # ROUND 10 - NO MIXCOLUMNS
    # --------------------------------------------------------

    print_separator(10)

    print("\n[1] SUBBYTES")
    sub_bytes(state)
    print_state(state, "After SubBytes")
    pause()

    print("\n[2] SHIFTROWS")
    shift_rows(state)
    print_state(state, "After ShiftRows")
    pause()

    print("\n[3] ADDROUNDKEY")
    print("\nNOTE: The last AES round has no MixColumns.")

    print_state(round_keys[10], "Final Round Key")

    add_round_key(state, round_keys[10])
    print_state(state, "Final State")

    return state_to_bytes(state)


# ============================================================
# 12. MAIN
# ============================================================

def main():
    key = bytes.fromhex(KEY)
    plaintext = bytes.fromhex(PLAINTEXT)

    if len(key) != 16:
        raise ValueError("AES-128 key must contain 16 bytes.")

    if len(plaintext) != 16:
        raise ValueError("Plaintext must contain 16 bytes.")

    print("=" * 55)
    print("            AES-128 EDUCATIONAL DEMO")
    print("=" * 55)

    print("\nKEY       :", key.hex().upper())
    print("PLAINTEXT :", plaintext.hex().upper())

    ciphertext = aes_encrypt(plaintext, key)

    print("\n" + "=" * 55)
    print("               FINAL RESULT")
    print("=" * 55)

    print("\nPLAINTEXT :", plaintext.hex().upper())
    print("KEY       :", key.hex().upper())
    print("CIPHERTEXT:", ciphertext.hex().upper())

    # Official AES-128 known-answer test
    if (
        KEY.upper() == "000102030405060708090A0B0C0D0E0F"
        and PLAINTEXT.upper() ==
        "00112233445566778899AABBCCDDEEFF"
    ):
        expected = "69C4E0D86A7B0430D8CDB78070B4C55A"

        print("\nEXPECTED  :", expected)

        if ciphertext.hex().upper() == expected:
            print("TEST RESULT: PASS")
        else:
            print("TEST RESULT: FAIL")


if __name__ == "__main__":
    main()
