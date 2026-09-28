#!/usr/bin/env python3
"""Giraud single-bit DFA on AES-128, demonstrated on this project's AES.

This recovers the AES-128 key from correct/faulty ciphertext pairs, where each
fault is a single-bit disturbance of one state byte at the input of the last
round (immediately before the final SubBytes). It reuses the software AES and
the fault-injection instrumentation in ../aes_fi_demo, so it runs with the
Python standard library only and needs no hardware:

    python fault_injection/giraud_attack/giraud.py

Reference: C. Giraud, "DFA on AES", 2004 (Attack 1, the bit-fault variant).

This is an offline analysis of simulated faults for study. It recovers a key
from data the attacker is assumed to obtain; it neither controls physical
glitching equipment nor claims that the intermediate states used to check the
result are observable in a real attack.
"""
import argparse
from pathlib import Path
import sys

DEMO_DIR = Path(__file__).resolve().parents[1] / 'aes_fi_demo'
sys.path.insert(0, str(DEMO_DIR))

import aes_reference as aes  # noqa: E402
import demo  # noqa: E402

# Public FIPS 197 example values. The key is what the attack must recover.
KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
PLAINTEXT = bytes.fromhex('00112233445566778899aabbccddeeff')


def popcount(value):
    return bin(value).count('1')


def encrypt(key, plaintext):
    return aes.AES(key).encrypt_block(plaintext)


def fault_ciphertext(key, plaintext, row, column, mask):
    """Ciphertext when one byte is XORed with `mask` just before round-10 SubBytes."""
    fault = demo.Fault(round=10, stage='SubBytes', row=row, column=column, mask=mask)
    ciphertext, _ = demo.encrypt_trace(key, plaintext, fault)
    return ciphertext


def candidate_key_bytes(correct, faulty, position):
    """K10 byte candidates at `position` consistent with a single-bit fault.

    A last-round output byte is C = SBOX(a) XOR k, where `a` is the state byte
    entering the final SubBytes and `k` is the round-10 key byte. A fault turns
    `a` into a XOR e. For every guess k the implied fault is
    e = INV_SBOX(C XOR k) XOR INV_SBOX(C' XOR k); Giraud keeps the guesses whose
    implied fault flips exactly one bit.
    """
    keep = set()
    for k in range(256):
        a = aes.inv_s_box[correct[position] ^ k]
        a_faulty = aes.inv_s_box[faulty[position] ^ k]
        if popcount(a ^ a_faulty) == 1:
            keep.add(k)
    return keep


def recover_last_round_key(key, plaintext, verbose=False):
    """Recover the 16 bytes of the round-10 key using single-bit faults."""
    correct = encrypt(key, plaintext)
    recovered = [None] * 16
    for column in range(4):
        for row in range(4):
            # Intersect the candidate sets from faults on different bits until
            # a single key byte survives. Its output position follows ShiftRows.
            surviving = None
            output_position = None
            for bit in range(8):
                faulty = fault_ciphertext(key, plaintext, row, column, 1 << bit)
                diff = [i for i in range(16) if correct[i] != faulty[i]]
                if len(diff) != 1:
                    raise RuntimeError('A last-round bit fault must change exactly one output byte.')
                position = diff[0]
                if output_position is None:
                    output_position = position
                elif position != output_position:
                    raise RuntimeError('Faults on one input byte reached different output bytes.')
                candidates = candidate_key_bytes(correct, faulty, position)
                surviving = candidates if surviving is None else (surviving & candidates)
                if len(surviving) == 1:
                    break
            if not surviving or len(surviving) != 1:
                raise RuntimeError(f'Could not isolate key byte at output {output_position} '
                                   f'(remaining candidates: {sorted(surviving or [])}).')
            recovered[output_position] = next(iter(surviving))
            if verbose:
                print(f'  input ({row},{column}) -> output byte {output_position:2d}: '
                      f'0x{recovered[output_position]:02x}')
    if any(value is None for value in recovered):
        raise RuntimeError('Some round-key bytes were not recovered.')
    return bytes(recovered)


def invert_key_schedule(last_round_key):
    """Invert the AES-128 key schedule: round-10 key -> 16-byte master key."""
    words = [None] * 44
    for column in range(4):
        words[40 + column] = list(last_round_key[4 * column:4 * column + 4])
    for index in range(43, 3, -1):
        previous = words[index - 1]
        if index % 4 == 0:
            rotated = previous[1:] + previous[:1]
            temp = [aes.s_box[b] for b in rotated]
            temp[0] ^= aes.r_con[index // 4]
        else:
            temp = previous
        words[index - 4] = [a ^ b for a, b in zip(words[index], temp)]
    return bytes(sum((words[i] for i in range(4)), []))


def run(key, plaintext, verbose=False):
    correct = encrypt(key, plaintext)
    print(f'Plaintext:         {plaintext.hex()}')
    print(f'Correct ciphertext:{correct.hex()}')
    print('Recovering the round-10 key from single-bit last-round faults...')
    last_round_key = recover_last_round_key(key, plaintext, verbose)
    print(f'Recovered K10:     {last_round_key.hex()}')
    recovered_key = invert_key_schedule(last_round_key)
    print(f'Recovered key:     {recovered_key.hex()}')
    print(f'Actual key:        {key.hex()}')
    match = recovered_key == key
    print('Key recovery:      ' + ('SUCCESS' if match else 'FAILED'))
    return match


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--key', default=KEY.hex(), help='AES-128 key as 32 hex digits')
    parser.add_argument('--plaintext', default=PLAINTEXT.hex(), help='16-byte block as 32 hex digits')
    parser.add_argument('--verbose', action='store_true', help='Print each recovered key byte')
    args = parser.parse_args()
    key = bytes.fromhex(args.key)
    plaintext = bytes.fromhex(args.plaintext)
    if len(key) != 16 or len(plaintext) != 16:
        parser.error('Key and plaintext must each be exactly 16 bytes (32 hex digits).')
    ok = run(key, plaintext, args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
