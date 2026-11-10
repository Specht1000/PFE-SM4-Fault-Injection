"""Controlled-byte SM4 DFA: target faults, candidate filtering and full key recovery.

The solver receives ciphertexts and controlled fault descriptors, never a secret
key. Four recovered consecutive tail subkeys are required to reverse the schedule.
Run: python src/piret_sm4.py --step
"""
import argparse
from functools import lru_cache
import struct
import aes
import sm4


def sm4_fault_encrypt(plaintext, key, byte=None, mask=0, fault_round=31):
    """Run sm4.py with an external S-box-input XOR in a selected round.

    This PDF model assumes a controlled known byte fault. Giraud restricts the
    mask to a single bit before reusing this target adapter.
    """

    if byte is not None and not (0 <= byte < 4 and 1 <= mask <= 255):
        raise ValueError("SM4 fault requires byte 0..3 and mask 1..255.")

    if not 0 <= fault_round < 32:
        raise ValueError("SM4 fault round must be 0..31.")

    # A list holds one 32-bit round key at each index from 0 through 31.
    keys = sm4.key_expansion(key)

    # {round: i, rk: 32-bit integer}
    trace = []

    for index in range(32):
        trace.append(dict(round=index, rk=keys[index]))

    fields = {"Sbox input": "a", "Sbox output": "b", "Linear output": "linear", "New word": "new"}

    def observer(number, operation, value):
        # Byte 0 is the most significant byte: move its mask to bits 31..24.
        # Returning this replacement changes the real cipher at this exact event.
        if number == fault_round and operation == "Sbox input" and byte is not None:
            value ^= mask << (24 - 8 * byte)

        if operation in fields:
            trace[number][fields[operation]] = value

        return value

    ciphertext = sm4.sm4_encrypt_block(plaintext, key, observer=observer)

    return ciphertext, trace


@lru_cache(maxsize=1)
def inverse_rows():
    """Invert SM4 L's 32x32 binary matrix with Gaussian elimination."""

    # L(2^i) gives column i of L's binary matrix: each input bit is a basis vector.
    columns = []

    for bit_index in range(32):
        basis_word = 1 << bit_index

        transformed_word = sm4.linear(basis_word)

        columns.append(transformed_word)

    # Store each augmented row [L | I] in one 64-bit integer; upper bits hold I.
    rows = []

    for row_index in range(32):
        matrix_row = 0

        for column_index in range(32):
            output_bit = (columns[column_index] >> row_index) & 1
            matrix_row |= output_bit << column_index

        identity_bit = 1 << (32 + row_index)

        augmented_row = matrix_row | identity_bit

        rows.append(augmented_row)

    for column in range(32):
        # Find a row with a 1 in this column, then move it to the pivot position.
        pivot = None

        for candidate_row in range(column, 32):
            pivot_bit = (rows[candidate_row] >> column) & 1

            if pivot_bit == 1:
                pivot = candidate_row
                break

        if pivot is None:
            raise StopIteration()

        rows[column], rows[pivot] = rows[pivot], rows[column]

        for row in range(32):
            if row != column and (rows[row] >> column) & 1:
                # XOR eliminates the column bit; GF(2) requires no division.
                rows[row] ^= rows[column]

    # The lower half is now I; the upper half contains the rows of inverse L.
    inverse_matrix_rows = []

    for augmented_row in rows:
        inverse_row = augmented_row >> 32

        inverse_matrix_rows.append(inverse_row)

    return tuple(inverse_matrix_rows)


def inverse_linear(value):
    # AND selects input bits used by each inverse-matrix row. Their parity is
    # the GF(2) dot product; shift that one-bit result into its output position.
    result = 0

    for index, row in enumerate(inverse_rows()):
        selected_bits = row & value

        set_bit_count = bin(selected_bits).count("1")

        parity = set_bit_count & 1

        result |= parity << index

    return result


def sm4_byte_candidates(correct, faulty, byte, mask):
    """Attacker API: outputs and the PDF's KNOWN fault byte/value only."""

    if len(correct) != 16 or len(faulty) != 16 or not 0 <= byte < 4 or not 1 <= mask <= 255:
        raise ValueError("Invalid SM4 output or known-fault descriptor.")

    c, f = struct.unpack(">4I", correct), struct.unpack(">4I", faulty)

    # The restored last-round model allows only its newest output word to change.
    if c[1:] != f[1:]:
        raise ValueError("The last-round model requires three output words unchanged.")

    # Cancel the unchanged older word and undo diffusion to isolate S-box differences.
    delta_b = inverse_linear(c[0] ^ f[0])

    shift = 24 - 8 * byte

    if not delta_b or delta_b & ~(255 << shift):
        # Reject both a missing fault and differences outside the selected byte.
        raise ValueError("Difference does not match a single-byte S-box input fault.")

    d = (delta_b >> shift) & 255

    # These three output words are public; their selected XOR byte is q.
    known = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255

    # Enumerate unknown S-box inputs a, then convert each to a key guess a XOR q.
    inputs = set()

    for candidate_input in range(256):
        faulty_input = candidate_input ^ mask

        output_difference = sm4.SBOX[candidate_input] ^ sm4.SBOX[faulty_input]

        if output_difference == d:
            inputs.add(candidate_input)

    key_candidates = set()

    for candidate_input in inputs:
        key_byte = candidate_input ^ known

        key_candidates.add(key_byte)

    return key_candidates, inputs, delta_b


def reverse_sm4(final_keys, observer=None):
    """Four consecutive keys rk28..rk31 are REQUIRED, not merely rk31."""

    if len(final_keys) != 4:
        raise ValueError("SM4 reversal requires four consecutive final subkeys.")

    # rk28..rk31 occupy K32..K35, supplying the four-word seed for inversion.
    words = [None] * 32 + list(final_keys)

    for index in range(31, -1, -1):
        # Descending order ensures all words on the right are already known.
        # CK is public; use the key-schedule transform L', not encryption's L.
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]

        words[index] = words[index+4] ^ sm4.linear_key(sm4.sbox(value))

        if observer:
            observer(index, words[index])

    # K0..K3 still include FK whitening; remove it and serialize the master key.
    master_words = []

    for word_index in range(4):
        master_word = words[word_index] ^ sm4.FK[word_index]
        master_words.append(master_word)

    return struct.pack(">4I", *master_words)


def peel_sm4(ciphertext, target_round, recovered_keys):
    """Undo only rounds whose subkeys have ALREADY been recovered by DFA.

    Return a reversed four-word output at the end of target_round. This lets
    the same last-round equations analyze rounds 30, 29 and 28 in succession.
    No reference round keys or secret intermediate values are accepted.
    """

    aes.validate_block(ciphertext, "SM4 ciphertext")

    if not 28 <= target_round <= 31:
        raise ValueError("Full SM4 recovery targets rounds 28..31.")

    # Ciphertext reverses the final four words; restore chronological state order.
    words = list(struct.unpack(">4I", ciphertext))[::-1]

    for number in range(31, target_round, -1):
        if number not in recovered_keys:
            raise ValueError(f"Cannot undo round {number} before recovering its subkey.")

        # Recompute the round transform with an already recovered key; XOR the
        # newest word to recover the word that was dropped from the window.
        previous = words[3] ^ sm4.linear(sm4.sbox(words[0] ^ words[1] ^ words[2] ^ recovered_keys[number]))

        words = [previous, words[0], words[1], words[2]]

    # Return ciphertext-style order so the same last-round filter can be reused.
    return struct.pack(">4I", *words[::-1])


def recover_sm4_master_key(correct, fault_oracle, masks=(1, 2, 3, 4, 5, 6, 7, 8), start_byte=0, candidate_filter=None, observer=None):
    """Recover rk31 -> rk28 and reverse the schedule, using outputs only.

    fault_oracle(round, byte, mask) returns a faulty ciphertext. It represents
    a target capable of a controlled fault in EACH of the final four rounds.
    The solver receives no master key, schedule, or reference subkeys.
    The default filter uses known masks; Giraud supplies its single-bit filter.
    """

    aes.validate_block(correct, "Correct SM4 ciphertext")

    masks = tuple(masks)

    if not masks:
        raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    if len(set(masks)) != len(masks):
        raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    for candidate_mask in masks:
        if not 1 <= candidate_mask <= 255:
            raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    if not 0 <= start_byte < 4:
        raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    keys, history, counts, used = {}, [], {}, 0

    for number in range(31, 27, -1):
        # Recover later keys first; only those keys may be used for round peeling.
        clean_view = peel_sm4(correct, number, keys)

        subkey = bytearray(4)

        byte_order = []

        for offset in range(4):
            byte_order.append((start_byte + offset) % 4)

        for byte in byte_order:
            survivors = None

            # None means no observation yet, not an empty or failed candidate set.
            for observation, mask in enumerate(masks, 1):
                faulty = bytes(fault_oracle(number, byte, mask))
                # The oracle knows the target secret, but returns only ciphertext.
                faulty_view = peel_sm4(faulty, number, keys)

                if candidate_filter is None:
                    # Default DFA knows the mask; Giraud supplies a different filter.
                    fresh, inputs, delta = sm4_byte_candidates(clean_view, faulty_view, byte, mask)
                else:
                    position, fresh, inputs, delta = candidate_filter(clean_view, faulty_view, mask)

                    if position != byte:
                        raise ValueError("Fault observation does not match the requested byte.")

                if survivors is None:
                    before = 256
                    survivors = set(fresh)
                else:
                    before = len(survivors)
                    survivors = survivors & fresh

                # Independent observations can remove candidates, never add them.
                if not survivors:
                    raise ValueError("SM4 candidate intersection is empty; fault model is incompatible.")

                used += 1
                counts[f"{number}:{byte}"] = len(survivors)
                recovered_key_labels = {}

                for index, value in keys.items():
                    recovered_key_labels[str(index)] = f'{value:08X}'

                event = dict(round=number, byte=byte, observation=observation, mask=mask, before=before, pair_candidates=len(fresh), remaining=len(survivors), survivors=sorted(survivors), inputs=sorted(inputs), delta_b=delta, correct=correct.hex(), faulty=faulty.hex(), clean_view=clean_view.hex(), faulty_view=faulty_view.hex(), peeled_with=recovered_key_labels)
                history.append(event)

                if observer is not None:
                    # Copy event metadata so presentation code cannot edit solver state.
                    observer(dict(event))

                if len(survivors) == 1:
                    # Only uniqueness permits using this byte in a recovered round key.
                    subkey[byte] = next(iter(survivors))
                    break
            else:
                # The loop exhausted its budget without a unique byte; do not peel
                # an earlier round with a guessed key or claim a complete master key.
                return dict(master_key=None, round_keys=keys, history=history, candidate_counts=counts, used=used, complete=False, blocked_round=number)

        keys[number] = int.from_bytes(subkey, "big")

    # All four tail keys now come from observations; invert the schedule once.
    final_keys = []

    for candidate_number in range(28, 32):
        final_keys.append(keys[candidate_number])

    master = reverse_sm4(final_keys)

    return dict(master_key=master, round_keys=keys, history=history, candidate_counts=counts, used=used, complete=True)


def main(argv=None):
    """Use the existing SM4 terminal presentation without changing its output."""

    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("--algorithm", choices=("sm4",), default="sm4")
    parser.add_argument("--step", action="store_true")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--faults", type=int, default=8, help="Maximum observations per byte, 1..255.")
    parser.add_argument("--row", type=int, choices=range(4), default=0, help="First target byte.")
    # Keep the same optional terminal settings for both Piret entry points.
    parser.add_argument("--column", type=int, choices=range(4), default=0)
    parser.add_argument("--seed", type=int, default=42)

    args = parser.parse_args(argv)

    if not 1 <= args.faults <= 255:
        parser.error("--faults must be 1..255.")

    import run

    if run.sm4_demo(run.LessonTerminal(args.color, args.step), args.faults, args.row):
        return 0

    return 2


if __name__ == "__main__":
    from terminal_log import run_with_log

    raise SystemExit(run_with_log(main, "piret_sm4"))
