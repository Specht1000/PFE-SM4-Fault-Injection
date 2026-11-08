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
    keys = sm4.key_expansion(key)
    trace = [dict(round=i, rk=keys[i]) for i in range(32)]
    fields = {"Sbox input": "a", "Sbox output": "b", "Linear output": "linear", "New word": "new"}

    def observer(number, operation, value):
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
    columns = [sm4.linear(1 << i) for i in range(32)]
    rows = [sum(((columns[col] >> row) & 1) << col for col in range(32)) | (1 << (32 + row)) for row in range(32)]
    for column in range(32):
        pivot = next(row for row in range(column, 32) if (rows[row] >> column) & 1)
        rows[column], rows[pivot] = rows[pivot], rows[column]
        for row in range(32):
            if row != column and (rows[row] >> column) & 1:
                rows[row] ^= rows[column]
    return tuple(row >> 32 for row in rows)



def inverse_linear(value):
    return sum((bin(row & value).count("1") & 1) << index for index, row in enumerate(inverse_rows()))



def sm4_byte_candidates(correct, faulty, byte, mask):
    """Attacker API: outputs and the PDF's KNOWN fault byte/value only."""
    if len(correct) != 16 or len(faulty) != 16 or not 0 <= byte < 4 or not 1 <= mask <= 255:
        raise ValueError("Invalid SM4 output or known-fault descriptor.")
    c, f = struct.unpack(">4I", correct), struct.unpack(">4I", faulty)
    if c[1:] != f[1:]:
        raise ValueError("The last-round model requires three output words unchanged.")
    delta_b = inverse_linear(c[0] ^ f[0])
    shift = 24 - 8 * byte
    if not delta_b or delta_b & ~(255 << shift):
        raise ValueError("Difference does not match a single-byte S-box input fault.")
    d = (delta_b >> shift) & 255
    known = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255
    inputs = {a for a in range(256) if sm4.SBOX[a] ^ sm4.SBOX[a ^ mask] == d}
    return {a ^ known for a in inputs}, inputs, delta_b



def reverse_sm4(final_keys, observer=None):
    """Four consecutive keys rk28..rk31 are REQUIRED, not merely rk31."""
    if len(final_keys) != 4:
        raise ValueError("SM4 reversal requires four consecutive final subkeys.")
    words = [None] * 32 + list(final_keys)
    for index in range(31, -1, -1):
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]
        words[index] = words[index+4] ^ sm4.linear_key(sm4.sbox(value))
        if observer:
            observer(index, words[index])
    return struct.pack(">4I", *(words[i] ^ sm4.FK[i] for i in range(4)))



def peel_sm4(ciphertext, target_round, recovered_keys):
    """Undo only rounds whose subkeys have ALREADY been recovered by DFA.

    Return a reversed four-word output at the end of target_round. This lets
    the same last-round equations analyze rounds 30, 29 and 28 in succession.
    No reference round keys or secret intermediate values are accepted.
    """
    aes.validate_block(ciphertext, "SM4 ciphertext")
    if not 28 <= target_round <= 31:
        raise ValueError("Full SM4 recovery targets rounds 28..31.")
    words = list(struct.unpack(">4I", ciphertext))[::-1]
    for number in range(31, target_round, -1):
        if number not in recovered_keys:
            raise ValueError(f"Cannot undo round {number} before recovering its subkey.")
        previous = words[3] ^ sm4.linear(sm4.sbox(words[0] ^ words[1] ^ words[2] ^ recovered_keys[number]))
        words = [previous, words[0], words[1], words[2]]
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
    if not masks or len(set(masks)) != len(masks) or any(not 1 <= mask <= 255 for mask in masks) or not 0 <= start_byte < 4:
        raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")
    keys, history, counts, used = {}, [], {}, 0
    for number in range(31, 27, -1):
        clean_view = peel_sm4(correct, number, keys)
        subkey = bytearray(4)
        for byte in [(start_byte + offset) % 4 for offset in range(4)]:
            survivors = None
            for observation, mask in enumerate(masks, 1):
                faulty = bytes(fault_oracle(number, byte, mask))
                faulty_view = peel_sm4(faulty, number, keys)
                if candidate_filter is None:
                    fresh, inputs, delta = sm4_byte_candidates(clean_view, faulty_view, byte, mask)
                else:
                    position, fresh, inputs, delta = candidate_filter(clean_view, faulty_view, mask)
                    if position != byte:
                        raise ValueError("Fault observation does not match the requested byte.")
                before = 256 if survivors is None else len(survivors)
                survivors = set(fresh) if survivors is None else survivors & fresh
                if not survivors:
                    raise ValueError("SM4 candidate intersection is empty; fault model is incompatible.")
                used += 1
                counts[f"{number}:{byte}"] = len(survivors)
                event = dict(round=number, byte=byte, observation=observation, mask=mask, before=before, pair_candidates=len(fresh), remaining=len(survivors), survivors=sorted(survivors), inputs=sorted(inputs), delta_b=delta, correct=correct.hex(), faulty=faulty.hex(), clean_view=clean_view.hex(), faulty_view=faulty_view.hex(), peeled_with={str(i): f"{value:08X}" for i, value in keys.items()})
                history.append(event)
                if observer is not None:
                    observer(dict(event))
                if len(survivors) == 1:
                    subkey[byte] = next(iter(survivors))
                    break
            else:
                return dict(master_key=None, round_keys=keys, history=history, candidate_counts=counts, used=used, complete=False, blocked_round=number)
        keys[number] = int.from_bytes(subkey, "big")
    master = reverse_sm4([keys[number] for number in range(28, 32)])
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
    return 0 if run.sm4_demo(run.LessonTerminal(args.color, args.step), args.faults, args.row) else 2


if __name__ == "__main__":
    from terminal_log import run_with_log
    raise SystemExit(run_with_log(main, "piret_sm4"))
