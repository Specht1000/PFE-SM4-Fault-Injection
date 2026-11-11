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
    """The TARGET: a normal SM4 encryption that we can glitch at one chosen spot.

    It stands in for the physical chip. With byte=None it is an ordinary, correct
    encryption (used to get the reference ciphertext). With a byte/mask/round it
    XORs `mask` into one byte of the S-box INPUT of `fault_round`, modelling a
    single controlled fault. The solver never calls this with the key; only an
    oracle wrapper does, and it returns just the ciphertext.
    """

    if byte is not None and not (0 <= byte < 4 and 1 <= mask <= 255):
        raise ValueError("SM4 fault requires byte 0..3 and mask 1..255.")

    if not 0 <= fault_round < 32:
        raise ValueError("SM4 fault round must be 0..31.")

    # A list holds one 32-bit round key at each index from 0 through 31.
    keys = sm4.key_expansion(key)

    # Pre-fill a per-round record (teaching only); the observer adds a/b/linear/new.
    trace = []

    for index in range(32):
        trace.append(dict(round=index, rk=keys[index]))

    # Maps the cipher's event names to the trace keys we store them under.
    fields = {"Sbox input": "a", "Sbox output": "b", "Linear output": "linear", "New word": "new"}

    def observer(number, operation, value):
        # sm4.py calls this at each internal event and uses our RETURN value, so
        # returning a modified value is what actually injects the fault into the
        # real cipher - here, only at the chosen round and S-box input.
        if number == fault_round and operation == "Sbox input" and byte is not None:
            # byte 0 is the most significant byte, so shift the mask to bits 31..24.
            value ^= mask << (24 - 8 * byte)

        # Record the (possibly faulted) value for the teaching trace.
        if operation in fields:
            trace[number][fields[operation]] = value

        return value

    ciphertext = sm4.sm4_encrypt_block(plaintext, key, observer=observer)

    return ciphertext, trace


@lru_cache(maxsize=1)
def inverse_rows():
    """Invert SM4 L's 32x32 binary matrix with Gaussian elimination.

    WHY THIS EXISTS: the attack must undo the linear layer L, i.e. apply L^-1.
    L is a linear map over GF(2) (bits, where "+" is XOR), so it equals a fixed
    32x32 binary matrix. There is no formula for L^-1 in sm4.py, so we build the
    matrix once, invert it with Gaussian elimination, and cache the result (the
    @lru_cache means this whole routine runs only on the first call, ever).
    """

    # STEP 1 - recover L's matrix one column at a time.
    # A linear map is fully described by what it does to the basis vectors.
    # Feeding L the word 2^i (only bit i set) returns exactly column i of its
    # matrix, because L(2^i) = (matrix) * (unit vector e_i) = column i.
    columns = []

    for bit_index in range(32):
        basis_word = 1 << bit_index            # the unit vector e_i

        transformed_word = sm4.linear(basis_word)   # = column i of L

        columns.append(transformed_word)

    # STEP 2 - build the augmented matrix [ L | I ] used for inversion.
    # We pack each 64-bit row as: bits 0..31 hold one row of L, bits 32..63 hold
    # the matching row of the identity I. As we row-reduce the left half to I,
    # the right half turns into L^-1 (standard [A|I] -> [I|A^-1] trick).
    rows = []

    for row_index in range(32):
        matrix_row = 0

        # Transpose columns -> rows: bit (row_index) of column j is entry [row_index][j].
        for column_index in range(32):
            output_bit = (columns[column_index] >> row_index) & 1
            matrix_row |= output_bit << column_index

        identity_bit = 1 << (32 + row_index)   # the single 1 of I on this row

        augmented_row = matrix_row | identity_bit

        rows.append(augmented_row)

    # STEP 3 - Gauss-Jordan elimination over GF(2), column by column.
    for column in range(32):
        # Find any row at/under this column that has a 1 here: the pivot.
        pivot = None

        for candidate_row in range(column, 32):
            pivot_bit = (rows[candidate_row] >> column) & 1

            if pivot_bit == 1:
                pivot = candidate_row
                break

        # No pivot => the column is all zeros => L is singular (cannot happen for
        # a real SM4 L, so this signals a broken matrix rather than normal flow).
        if pivot is None:
            raise StopIteration()

        # Move the pivot row into position `column` on the diagonal.
        rows[column], rows[pivot] = rows[pivot], rows[column]

        # Clear this column in EVERY other row by XORing the pivot row into them.
        for row in range(32):
            if row != column and (rows[row] >> column) & 1:
                # Over GF(2), subtraction == addition == XOR, so no division is
                # ever needed; one XOR both subtracts and keeps entries in {0,1}.
                rows[row] ^= rows[column]

    # STEP 4 - the left half is now I, so the right half (upper 32 bits) is L^-1.
    inverse_matrix_rows = []

    for augmented_row in rows:
        inverse_row = augmented_row >> 32      # drop the now-identity left half

        inverse_matrix_rows.append(inverse_row)

    return tuple(inverse_matrix_rows)


def inverse_linear(value):
    """Apply L^-1 to a 32-bit word: result = (inverse matrix) * value over GF(2).

    Each output bit i is the dot product of row i of L^-1 with the input vector.
    A GF(2) dot product is just "AND the two vectors, then take the parity (XOR)
    of the surviving bits" - that is exactly what the three lines below do.
    """
    result = 0

    for index, row in enumerate(inverse_rows()):
        # AND keeps only the input bits that this matrix row actually uses.
        selected_bits = row & value

        # Count them; the sum over GF(2) is their parity (odd -> 1, even -> 0).
        set_bit_count = bin(selected_bits).count("1")

        parity = set_bit_count & 1

        # Place that single output bit at position i of the result word.
        result |= parity << index

    return result


def sm4_byte_candidates(correct, faulty, byte, mask):
    """Core DFA step: from one correct/faulty pair, list the key-byte guesses.

    Inputs are PUBLIC only: the two 16-byte ciphertexts, which byte was faulted,
    and the known XOR mask. No secret key or internal state is used. It returns
    the surviving key-byte candidates for the selected byte of the round key.

    The maths (one SM4 round, last round, at the faulted byte):
        output word = L( tau( X xor rk ) ) xor (older word)
    A fault flips the S-box input X by `mask`. Subtracting the two executions,
    the older word and rk cancel, leaving  word_diff = L( tau(a) xor tau(a^mask) ).
    Undo L to see the raw S-box output difference, then search for inputs a that
    reproduce it, and turn each a into a key-byte guess.
    """

    if len(correct) != 16 or len(faulty) != 16 or not 0 <= byte < 4 or not 1 <= mask <= 255:
        raise ValueError("Invalid SM4 output or known-fault descriptor.")

    # Split each 16-byte ciphertext into four big-endian 32-bit words.
    c, f = struct.unpack(">4I", correct), struct.unpack(">4I", faulty)

    # Only the newest word (index 0) may differ: the fault touched the last round,
    # and the other three words were already finalised, so they must match.
    if c[1:] != f[1:]:
        raise ValueError("The last-round model requires three output words unchanged.")

    # Undo the linear layer on the changed word. L is linear, so L^-1 of the word
    # difference equals the S-box OUTPUT difference  tau(a) xor tau(a^mask).
    delta_b = inverse_linear(c[0] ^ f[0])

    # `byte` 0 is the most significant byte, so it lives at bits 31..24 -> shift 24.
    shift = 24 - 8 * byte

    # Sanity of the fault model: the difference must be nonzero AND confined to the
    # one selected byte. `~(255 << shift)` is a mask of all the OTHER bytes; if any
    # of them is set, the fault spread (multi-byte) and the single-byte model fails.
    if not delta_b or delta_b & ~(255 << shift):
        raise ValueError("Difference does not match a single-byte S-box input fault.")

    # d = the one-byte S-box output difference we must explain.
    d = (delta_b >> shift) & 255

    # In the restored last-round model the round's "older word" added to the S-box
    # output is public: it is c[1]^c[2]^c[3] (the three unchanged words). Its byte
    # at `shift` is q, the known constant that links the S-box input a to the key:
    #   key_byte = a xor q   (because X = key xor q held during encryption).
    known = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255

    # SOLVE THE S-BOX DIFFERENTIAL: which inputs a give S(a) xor S(a^mask) == d?
    # Brute-force all 256 bytes; usually only a few survive (often two).
    inputs = set()

    for candidate_input in range(256):
        faulty_input = candidate_input ^ mask

        output_difference = sm4.SBOX[candidate_input] ^ sm4.SBOX[faulty_input]

        if output_difference == d:
            inputs.add(candidate_input)

    # Convert each surviving S-box input into its implied round-key byte.
    key_candidates = set()

    for candidate_input in inputs:
        key_byte = candidate_input ^ known

        key_candidates.add(key_byte)

    # The caller intersects these sets across several faults until one byte remains.
    return key_candidates, inputs, delta_b


def reverse_sm4(final_keys, observer=None):
    """Turn the four last round keys rk28..rk31 back into the 16-byte master key.

    WHY FOUR KEYS: SM4's key schedule is the SAME sliding-window recurrence as the
    cipher. Each round key K[i+4] = K[i] xor T'(K[i+1] xor K[i+2] xor K[i+3] xor CK[i]).
    To run that recurrence BACKWARDS you need four consecutive known keys as a
    seed - one is not enough. rk28..rk31 are exactly K32..K35, the last window.
    """

    if len(final_keys) != 4:
        raise ValueError("SM4 reversal requires four consecutive final subkeys.")

    # Lay the 36 schedule words K0..K35 out; only the last four are known so far.
    words = [None] * 32 + list(final_keys)

    for index in range(31, -1, -1):
        # Solve the recurrence for K[index] using the four words to its right,
        # which are always already known because we go from 31 down to 0.
        # CK is the PUBLIC schedule constant; T' uses linear_key (L'), which is a
        # DIFFERENT linear map from the cipher's L (do not mix them up).
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]

        words[index] = words[index+4] ^ sm4.linear_key(sm4.sbox(value))

        if observer:
            observer(index, words[index])

    # K0..K3 are the master key XORed with the fixed FK whitening constant; undo it.
    master_words = []

    for word_index in range(4):
        master_word = words[word_index] ^ sm4.FK[word_index]
        master_words.append(master_word)

    # Re-serialize the four recovered master-key words into 16 bytes.
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

    # WHY PEELING: the last-round equations in sm4_byte_candidates only work on the
    # state as it was at the end of round `target_round`. To attack round 30 we must
    # first strip rounds 31 (and later 31,30 for round 29, etc.) using the subkeys we
    # ALREADY recovered - we never guess or borrow a key we have not solved.

    # SM4 outputs the final four words in REVERSE order; undo that to get the real
    # chronological window [oldest, ..., newest].
    words = list(struct.unpack(">4I", ciphertext))[::-1]

    for number in range(31, target_round, -1):
        if number not in recovered_keys:
            raise ValueError(f"Cannot undo round {number} before recovering its subkey.")

        # One round pushed a new word in and dropped the oldest. Recompute that round
        # function with the known key and XOR it into the newest word to recover the
        # word that was dropped - i.e. run the round backwards by one step.
        previous = words[3] ^ sm4.linear(sm4.sbox(words[0] ^ words[1] ^ words[2] ^ recovered_keys[number]))

        # Slide the window back one round: the recovered word becomes the oldest.
        words = [previous, words[0], words[1], words[2]]

    # Re-reverse to ciphertext-style order so sm4_byte_candidates can treat this
    # peeled state exactly like a fresh last-round ciphertext.
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

    # keys: round -> recovered 32-bit subkey. history/counts/used are for reporting.
    keys, history, counts, used = {}, [], {}, 0

    # Attack the four tail rounds newest-first (31, 30, 29, 28). Newest-first is
    # mandatory: peeling round N needs every later round key already recovered.
    for number in range(31, 27, -1):
        # Strip the already-solved later rounds so this round looks like a fresh
        # last round to the solver (keys holds only DFA-recovered subkeys).
        clean_view = peel_sm4(correct, number, keys)

        subkey = bytearray(4)

        # Visit the four bytes of this subkey in a rotated order starting at
        # start_byte (purely which byte we demonstrate first; all four are solved).
        byte_order = []

        for offset in range(4):
            byte_order.append((start_byte + offset) % 4)

        for byte in byte_order:
            # survivors = running intersection of candidate values for THIS byte.
            survivors = None

            # None means no observation yet, not an empty or failed candidate set.
            for observation, mask in enumerate(masks, 1):
                # Ask the target for a faulty ciphertext (same input, chosen fault).
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

                # Intersect: each independent fault can only REMOVE wrong guesses,
                # never add them, so the set shrinks toward the single true byte.
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

        # All four bytes of this round key are now unique: assemble the 32-bit key.
        keys[number] = int.from_bytes(subkey, "big")

    # All four tail keys now come from observations; invert the schedule once to
    # get the master key (needs rk28..rk31, in ascending order, as the seed).
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
