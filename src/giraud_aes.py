"""Giraud AES attack calculations and terminal entry point.

Candidate filters receive ciphertexts, never the target secret key.
"""
import aes
element_values_items = []

for input_value in range(256):
    element_values_items.append(aes.SBOX.index(input_value))

AES_INVERSE_SBOX = tuple(element_values_items)
from giraud_common import SINGLE_BITS, validate_mask, masks_for, intersect_candidates
from giraud_common import recover_byte as filter_observations


def aes_fault_encrypt(plaintext, key, byte=0, mask=None):
    """Interfere with the real aes.py execution before final SubBytes.

    Only this attack callback changes the state. Without it AES is unchanged.
    Snapshots are copies for teaching; they are never inputs to the solver.
    """

    if not 0 <= byte < 16:
        raise ValueError("AES input byte must be 0..15.")

    if mask is not None:
        validate_mask(mask)

    trace = {}

    def observer(number, operation, state):
        # Restrict the intervention to final SubBytes input, before nonlinear mixing.
        if number == 10 and operation == "Before SubBytes":
            trace["Before fault"] = aes.state_to_bytes(state)

            if mask is not None:
                # Convert the serialized input index to AES's column-major matrix.
                state[byte % 4][byte // 4] ^= mask

            trace["Injected bit"] = aes.state_to_bytes(state)

        if number == 10 and operation.startswith("After "):
            # Serialize a copy at each stage so later in-place operations cannot
            # overwrite earlier teaching snapshots.
            if operation == 'After AddRoundKey':
                name = 'Ciphertext'
            else:
                name = operation[6:]

            trace[name] = aes.state_to_bytes(state)

    ciphertext = aes.aes_encrypt(plaintext, key, observer=observer)

    return ciphertext, trace


def aes_candidates(correct, faulty, known_mask=None):
    """Return the affected output position and its compatible K10 byte values.

    For each guess k:
      delta = InvSbox[C[j] XOR k] XOR InvSbox[F[j] XOR k]
    Keep k when delta has exactly one set bit, or equals the known bit mask.
    """

    aes.validate_block(correct, "Correct ciphertext")

    aes.validate_block(faulty, "Faulty ciphertext")

    if known_mask is not None:
        validate_mask(known_mask)

    # Without final-round MixColumns, only one ciphertext byte should change.
    changed = []

    for index in range(16):
        if correct[index] != faulty[index]:
            changed.append(index)

    if len(changed) != 1:
        raise ValueError("AES Giraud requires exactly one changed ciphertext byte.")

    position = changed[0]

    if known_mask is None:
        allowed = SINGLE_BITS
    else:
        allowed = (known_mask,)

    # Unknown-bit filtering accepts any one-bit input difference; known-bit mode
    # accepts only the exact mask and therefore assumes more attacker knowledge.

    candidates = set()

    for guess in range(256):
        # Guess the final key byte, remove AddRoundKey, then undo SubBytes on both outputs.
        clean_input = AES_INVERSE_SBOX[correct[position] ^ guess]

        faulty_input = AES_INVERSE_SBOX[faulty[position] ^ guess]

        difference = clean_input ^ faulty_input

        # A valid guess must reconstruct a difference permitted by the fault model.
        if difference in allowed:
            candidates.add(guess)

    return position, candidates


def recover_byte(observations):
    """Intersect observations for one AES key byte; require a consistent location."""

    # Bind the shared intersection routine to AES equations only.
    return filter_observations(aes_candidates, observations)


def main(argv=None):
    """Use the shared terminal lesson with the AES fault model."""

    # Import presentation only when running the CLI; importing the solver stays quiet.
    from giraud_terminal import main as terminal_main

    return terminal_main("aes", argv)


if __name__ == "__main__":
    from terminal_log import run_with_log

    raise SystemExit(run_with_log(main, "giraud_aes"))
