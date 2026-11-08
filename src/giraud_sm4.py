"""Giraud SM4 attack calculations and terminal entry point.

Candidate filters receive ciphertexts, never the target secret key.
"""
import aes
import sm4
import piret_sm4
from piret_sm4 import inverse_linear
from giraud_common import SINGLE_BITS, validate_mask, masks_for, intersect_candidates
from giraud_common import recover_byte as filter_observations


def sm4_fault_encrypt(plaintext, key, byte=None, mask=0, fault_round=31):
    """Restrict the external SM4 experiment to Giraud's one-bit fault model."""
    if byte is not None:
        validate_mask(mask)
    return piret_sm4.sm4_fault_encrypt(plaintext, key, byte, mask, fault_round)


def recover_sm4_master_key(correct, fault_oracle, first_mask=1, maximum=8, known_bit=False, start_byte=0, observer=None):
    """Full SM4 recovery using single-bit filtering in rounds 31, 30, 29, 28."""
    def candidate_filter(clean, faulty, simulator_mask):
        # Unknown-bit mode deliberately does not pass the oracle's mask onward.
        return sm4_candidates(clean, faulty, simulator_mask if known_bit else None)

    return piret_sm4.recover_sm4_master_key(correct, fault_oracle, masks_for(first_mask, maximum), start_byte, candidate_filter, observer)


def sm4_candidates(correct, faulty, known_mask=None):
    """Return affected byte, round-key guesses, input guesses and DeltaB.

    Inputs may be actual final ciphertexts or peeled views at an earlier round.

    1. Observe DeltaX35 from the first output word.
    2. Undo linear diffusion: DeltaB = L-inverse(DeltaX35).
    3. Keep a if S(a) XOR S(a XOR e) matches the observed byte difference.
    4. Convert a into a key guess using the three unchanged output words.
    """
    aes.validate_block(correct, "Correct ciphertext")
    aes.validate_block(faulty, "Faulty ciphertext")
    if known_mask is not None:
        validate_mask(known_mask)

    # SM4 outputs X35 || X34 || X33 || X32; only X35 may change in this model.
    if correct[4:] != faulty[4:]:
        raise ValueError("SM4 last-round model requires three output words unchanged.")
    delta_x35 = int.from_bytes(correct[:4], "big") ^ int.from_bytes(faulty[:4], "big")
    delta_b = inverse_linear(delta_x35)
    differences = delta_b.to_bytes(4, "big")
    changed = [index for index in range(4) if differences[index] != 0]
    if len(changed) != 1:
        raise ValueError("SM4 inverse-L difference must affect one S-box byte.")
    position = changed[0]
    allowed = SINGLE_BITS if known_mask is None else (known_mask,)

    # The input value a is unknown. Test every value against each permitted bit.
    inputs = set()
    for guess in range(256):
        for error in allowed:
            difference = sm4.SBOX[guess] ^ sm4.SBOX[guess ^ error]
            if difference == differences[position]:
                inputs.add(guess)
                break

    # A = X32 XOR X33 XOR X34 XOR rk31; all three data words are observable.
    x34 = int.from_bytes(correct[4:8], "big")
    x33 = int.from_bytes(correct[8:12], "big")
    x32 = int.from_bytes(correct[12:16], "big")
    known_byte = ((x32 ^ x33 ^ x34) >> (24 - 8 * position)) & 0xFF
    candidates = {guess ^ known_byte for guess in inputs}
    return position, candidates, inputs, delta_b


def recover_byte(observations):
    """Intersect observations for one SM4 key byte; require a consistent location."""
    return filter_observations(sm4_candidates, observations)


def main(argv=None):
    """Use the shared terminal lesson with the SM4 fault model."""
    from giraud_terminal import main as terminal_main
    return terminal_main("sm4", argv)


if __name__ == "__main__":
    from terminal_log import run_with_log
    raise SystemExit(run_with_log(main, "giraud_sm4"))
