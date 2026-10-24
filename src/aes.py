"""Normal AES-128 encryption and decryption, with reusable round primitives.

Author: Guilherme Martins Specht / PFE 5A / Polytech Montpellier.
Academic and industrial context: STMicroelectronics.

Reading order: configuration -> constants -> state conversion -> finite-field
arithmetic -> round transformations -> key expansion -> terminal demonstration.

The state is stored as state[row][column]. Input and output bytes are serialized
column by column: byte_index = 4 * column + row. Round transformations modify
this matrix in place; conversion functions produce independent containers.

Normal block functions return bytes without printing or pausing. External tools
may attach an observer for tracing or fault experiments; no fault rule is part
of this cipher. main() runs ordinary encryption/decryption on one raw block.
"""


# ============================================================================
# 1. EDITABLE EXAMPLE INPUTS AND ALGORITHM CONSTANTS
# ============================================================================


KEY = "000102030405060708090A0B0C0D0E0F"


PLAINTEXT = "00112233445566778899AABBCCDDEEFF"


BLOCK_SIZE = 16


N_ROUNDS = 10


# ============================================================================
# 2. AES CONSTANTS: NONLINEAR SUBSTITUTION AND LINEAR DIFFUSION
# ============================================================================


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


# Index 0 is unused; RCON[1] is applied when deriving the first round key.
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]


# Each row contains the coefficients for one output byte of a column.
MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
]

INV_SBOX = tuple(SBOX.index(value) for value in range(256))
INV_MIX_MATRIX = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


# ============================================================================
# 3. INPUT VALIDATION AND COLUMN-MAJOR STATE CONVERSION
# ============================================================================


def validate_block(data, label="Block"):
    """Reject incomplete or oversized inputs instead of silently dropping bytes."""
    if len(data) != BLOCK_SIZE:
        raise ValueError(f"{label} must contain exactly {BLOCK_SIZE} bytes.")


def bytes_to_state(data):
    """Map 16 bytes into a fresh 4x4 matrix using the AES column-major layout."""
    validate_block(data)
    state = [[0] * 4 for _ in range(4)]

    for col in range(4):
        for row in range(4):
            state[row][col] = data[4 * col + row]

    return state


def state_to_bytes(state):
    """Serialize the matrix in the same column order used by bytes_to_state."""
    return bytes(state[row][col] for col in range(4) for row in range(4))


# ============================================================================
# 4. FINITE-FIELD ARITHMETIC: GF(2^8), POLYNOMIAL 0x11B
# ============================================================================


def xtime(a):
    """Multiply a byte by x (02) in GF(2^8), reducing by polynomial 0x11B."""
    result = a << 1

    # If the x^8 term overflows, reduction contributes 0x1B to the low byte.
    if a & 0x80:
        result ^= 0x1B

    return result & 0xFF


def gf_mul(a, b):
    """Multiply bytes in the AES field; field addition is XOR, not integer +."""
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        # Shift-and-add multiplication, using xtime for polynomial reduction.
        a = xtime(a)
        b >>= 1

    return result


# ============================================================================
# 5. ROUND TRANSFORMATIONS: ALL MATRIX OPERATIONS ARE IN PLACE
# ============================================================================


def sub_bytes(state):
    """Apply the nonlinear S-box independently to each byte, in place.

    This changes byte values but does not move bytes between state positions.
    """
    for row in range(4):
        for col in range(4):
            original = state[row][col]
            state[row][col] = SBOX[original]


def shift_rows(state):
    """Rotate row r left by r bytes so the next MixColumns sees new groups."""
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def mix_column(column):
    """Return M * column in GF(2^8), without modifying the four input bytes.

    Copying a column before mixing matters: every output byte must use the same
    original input, never a value already overwritten earlier in the operation.
    """
    result = []
    for coefficients in MIX_MATRIX:
        value = 0
        for coefficient, byte in zip(coefficients, column):
            value ^= gf_mul(coefficient, byte)
        result.append(value)
    return result


def mix_columns(state):
    """Mix each column in place; the normal algorithm never prints output."""
    for column in range(4):
        mixed = mix_column([state[row][column] for row in range(4)])
        for row in range(4):
            state[row][column] = mixed[row]


def add_round_key(state, round_key):
    """XOR each state byte with its key byte. The same operation undoes itself.

    Applying the same round key to clean/faulty executions preserves their XOR
    difference, which is one of the properties used in differential analysis.
    """
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]


# ============================================================================
# 6. KEY SCHEDULE: MASTER KEY K0 TO FINAL ROUND KEY K10
# ============================================================================


def rot_word(word):
    """Rotate a four-byte key word left by one byte; leave the input unchanged."""
    return word[1:] + word[:1]


def sub_word(word):
    """Apply the encryption S-box to all four bytes of a key-schedule word."""
    return [SBOX[b] for b in word]


def key_expansion(key):
    """Expand the 16-byte master key into eleven independent round-key matrices.

    Each new word XORs the word four positions back with the previous word.
    Every fourth word first applies RotWord, SubWord and the round constant.
    """
    validate_block(key, "AES-128 key")
    # Four initial words become 44 words: K0 plus ten encryption round keys.
    words = [list(key[4 * i:4 * i + 4]) for i in range(4)]

    for i in range(4, 4 * (N_ROUNDS + 1)):
        temp = words[i - 1].copy()

        if i % 4 == 0:
            # Rcon changes only the first byte of the transformed key word.
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]

        new_word = [words[i - 4][j] ^ temp[j] for j in range(4)]

        words.append(new_word)

    round_keys = []

    for round_number in range(N_ROUNDS + 1):
        # Convert four consecutive words into the same layout as the data state.
        key_bytes = []

        for i in range(4):
            key_bytes.extend(words[round_number * 4 + i])

        round_keys.append(bytes_to_state(key_bytes))

    return round_keys


# ============================================================================
# 7. NORMAL ENCRYPTION / DECRYPTION AND OPTIONAL EXTERNAL OBSERVATION
# ============================================================================


def _operation(state, number, name, transform, observer):
    """Optional instrumentation surrounds a normal transformation.

    The cipher contains no fault rules. An external experiment may inspect or
    change the state in its observer. Without an observer this is ordinary AES.
    """
    if observer is not None:
        observer(number, "Before " + name, state)
    transform(state)
    if observer is not None:
        observer(number, "After " + name, state)


def aes_encrypt(plaintext, key, observer=None):
    """Encrypt one raw block. No printing, pauses or built-in fault injection."""
    state = bytes_to_state(plaintext)
    keys = key_expansion(key)
    _operation(state, 0, "AddRoundKey", lambda s: add_round_key(s, keys[0]), observer)
    for number in range(1, N_ROUNDS + 1):
        _operation(state, number, "SubBytes", sub_bytes, observer)
        _operation(state, number, "ShiftRows", shift_rows, observer)
        if number != N_ROUNDS:
            _operation(state, number, "MixColumns", mix_columns, observer)
        _operation(state, number, "AddRoundKey", lambda s: add_round_key(s, keys[number]), observer)
    return state_to_bytes(state)


def inv_sub_bytes(state):
    """Undo byte substitution with the inverse table."""
    for row in range(4):
        for column in range(4):
            state[row][column] = INV_SBOX[state[row][column]]


def inv_shift_rows(state):
    """Undo row r by rotating it right by r positions."""
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


def inv_mix_columns(state):
    """Multiply each column by the inverse diffusion matrix in GF(2^8)."""
    for column in range(4):
        original = [state[row][column] for row in range(4)]
        for row in range(4):
            value = 0
            for index in range(4):
                value ^= gf_mul(INV_MIX_MATRIX[row][index], original[index])
            state[row][column] = value


def aes_decrypt(ciphertext, key, observer=None):
    """Decrypt one raw block by reversing operations and round-key order."""
    state = bytes_to_state(ciphertext)
    keys = key_expansion(key)
    _operation(state, N_ROUNDS, "AddRoundKey", lambda s: add_round_key(s, keys[N_ROUNDS]), observer)
    for number in range(N_ROUNDS - 1, -1, -1):
        _operation(state, number, "InvShiftRows", inv_shift_rows, observer)
        _operation(state, number, "InvSubBytes", inv_sub_bytes, observer)
        _operation(state, number, "AddRoundKey", lambda s: add_round_key(s, keys[number]), observer)
        if number:
            _operation(state, number, "InvMixColumns", inv_mix_columns, observer)
    return state_to_bytes(state)


def main():
    """Run normal AES encryption and decryption using the configured inputs."""
    key, plaintext = bytes.fromhex(KEY), bytes.fromhex(PLAINTEXT)
    ciphertext = aes_encrypt(plaintext, key)
    recovered = aes_decrypt(ciphertext, key)
    print("AES-128")
    print("Key:        " + key.hex().upper())
    print("Plaintext:  " + plaintext.hex().upper())
    print("Ciphertext: " + ciphertext.hex().upper())
    print("Recovered:  " + recovered.hex().upper())
    if recovered != plaintext:
        raise RuntimeError("AES round-trip verification failed.")
    print("Round-trip verification: PASS")


if __name__ == "__main__":
    main()
