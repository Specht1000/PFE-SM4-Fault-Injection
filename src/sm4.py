"""Readable SM4 block cipher and round-key schedule.

Author: Guilherme Martins Specht / PFE 5A / Polytech Montpellier.

Reading order: configuration -> constants -> byte/word transformations -> key
expansion -> shared encryption/decryption routine -> standalone example.

A block is four big-endian 32-bit words. The data linear map L and schedule map
L-prime use DIFFERENT rotation constants. Both directions share the same round
function; decryption changes only the order of the 32 round keys.
"""
import struct

# ============================================================================
# 1. CONFIGURATION: ONE RAW 128-BIT BLOCK AND ONE 128-BIT MASTER KEY
# ============================================================================

N_ROUNDS = 32
KEY = "0123456789ABCDEFFEDCBA9876543210"
PLAINTEXT = "0123456789ABCDEFFEDCBA9876543210"
BLOCK_SIZE = 16
WORD_MASK = 0xFFFFFFFF

# ============================================================================
# 2. SPECIFICATION CONSTANTS
# ============================================================================

# Nonlinear substitution table: replace each input byte independently.
SBOX = (
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
)

# FK whitens the four master-key words before the key-schedule recurrence.
FK = (
    0xa3b1bac6, 0x56aa3350,
    0x677d9197, 0xb27022dc,
)

# CK[i] bytes follow ((4*i+j)*7) mod 256 for byte positions j=0..3.
CK = (
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
)

# ============================================================================
# 3. WORD TRANSFORMATIONS: ROTATIONS, NONLINEAR TAU AND LINEAR MAPS
# ============================================================================


def rotl(val: int, count: int) -> int:
    """Rotate a 32-bit unsigned word left; overflow wraps into the low bits."""
    return ((val << count) & WORD_MASK) | (val >> (32 - count))


def linear(b: int) -> int:
    """Data diffusion L: XOR the word with rotations by 2, 10, 18 and 24.

    L is XOR-linear: L(a XOR b) = L(a) XOR L(b). The SM4 DFA uses this
    property to invert an observed output difference before testing the S-box.
    """
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)


def linear_key(b: int) -> int:
    """Key-schedule diffusion L-prime: rotations 13 and 23, not data-map L."""
    return b ^ rotl(b, 13) ^ rotl(b, 23)


def sbox(a: int) -> int:
    """Apply tau: substitute all four bytes, preserving big-endian word order."""
    input_bytes = struct.pack('>I', a)
    substituted_bytes = bytes(SBOX[byte] for byte in input_bytes)
    return struct.unpack('>I', substituted_bytes)[0]


# ============================================================================
# 4. SINGLE-ROUND RECURRENCES
# ============================================================================


def round(x: list[int], rk: int):
    """Return the next rolling window without modifying the supplied words.

    A = X[i+1] XOR X[i+2] XOR X[i+3] XOR rk[i]
    X[i+4] = X[i] XOR L(tau(A))
    """
    sbox_input = x[1] ^ x[2] ^ x[3] ^ rk
    substituted = sbox(sbox_input)
    new_word = x[0] ^ linear(substituted)
    return x[1], x[2], x[3], new_word


def generate_round_key(k: list[int], round: int) -> int:
    """Compute K[i+4] from four consecutive schedule words and CK[i].

    The parameter name round is retained for callers using keyword arguments.
    Encryption and expansion share tau, but expansion must use linear_key.
    """
    return k[0] ^ linear_key(sbox(k[1] ^ k[2] ^ k[3] ^ CK[round]))


# ============================================================================
# 5. KEY EXPANSION: FOUR MASTER WORDS TO 32 ROUND KEYS
# ============================================================================


def key_expansion(key: bytes) -> list[int]:
    """Return rk0..rk31; each is one new word from the key recurrence."""
    if len(key) != BLOCK_SIZE:
        raise ValueError("SM4 key must contain exactly 16 bytes.")
    master_words = struct.unpack(">4I", key)
    schedule_words = [master_words[i] ^ FK[i] for i in range(4)]

    for i in range(N_ROUNDS):
        # Keep previous words for readability; the recurrence consumes a window.
        next_key = generate_round_key(schedule_words[i:i+4], i)
        schedule_words.append(next_key)

    # The initial four whitened words are not encryption round keys.
    return schedule_words[4:]


# ============================================================================
# 6. SHARED BLOCK PROCESSING AND PUBLIC ENCRYPT/DECRYPT WRAPPERS
# ============================================================================


def sm4_process_block(block: bytes, key: bytes, encrypt: bool) -> bytes:
    """Process a single block, printing the new word and actual key each round.

    The final four-word reversal is part of SM4, not a byte-endianness change.
    Reversing only the key order is sufficient to run the inverse cipher.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("SM4 block must contain exactly 16 bytes.")
    state = list(struct.unpack(">4I", block))
    round_keys = key_expansion(key)
    for i in range(N_ROUNDS):
        key_index = i if encrypt else N_ROUNDS - 1 - i
        state = list(round(state, round_keys[key_index]))
        print(f"x[{i+4}] = {state[3]:08X}\trk[{key_index}] = {round_keys[key_index]:08X}")
    return struct.pack(">4I", *state[::-1])


def sm4_encrypt_block(x: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block using round keys in forward order."""
    return sm4_process_block(x, key, encrypt=True)


def sm4_decrypt_block(x: bytes, key: bytes) -> bytes:
    """Decrypt one 16-byte block using the identical round function."""
    return sm4_process_block(x, key, encrypt=False)


# ============================================================================
# 7. STANDALONE EXAMPLE: ENCRYPT, DECRYPT AND VERIFY
# ============================================================================


def main():
    """Run the editable example; importing SM4 never starts this demonstration."""
    plaintext, key = bytes.fromhex(PLAINTEXT), bytes.fromhex(KEY)
    print("SM4 ENCRYPTION\nPlaintext: " + plaintext.hex().upper())
    ciphertext = sm4_encrypt_block(plaintext, key)
    print("Ciphertext: " + ciphertext.hex().upper())
    print("\nSM4 DECRYPTION: round keys are used in reverse order")
    recovered = sm4_decrypt_block(ciphertext, key)
    print("Recovered: " + recovered.hex().upper())
    if recovered != plaintext:
        raise RuntimeError("SM4 round-trip verification failed.")
    print("Round-trip verification: PASS")


if __name__ == "__main__":
    main()
