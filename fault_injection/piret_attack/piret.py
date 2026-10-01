"""Educational Piret-Quisquater-style AES-128 differential fault analysis.

Software experiment: a single unknown byte fault BEFORE round-8 MixColumns.
One fault spreads into all four columns before round-9 MixColumns.
We solve the final-round differential equations and intersect candidates.
This transparent variant may need more than the paper's two faulty outputs;
it does not implement all of the paper's cross-column optimizations.
No hardware, external packages, or imported ciphertext files are required.
"""
import argparse
from itertools import product
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'aes/src'))
import aes_didactic as aes


def output_positions(column):
    """Round-10 ShiftRows moves (row, column) to (row, column-row)."""
    return tuple(4 * ((column - row) % 4) + row for row in range(4))


def column_candidates(correct, faulty, column):
    """Return candidate K10 byte tuples in pre-ShiftRows row order.

    For output position p and guessed last-round key byte k:
      d = InvSbox[C[p] XOR k] XOR InvSbox[C_fault[p] XOR k]

    A single-byte error entering round-9 MixColumns forces the four d values
    to equal one column of the MixColumns matrix times an UNKNOWN nonzero e.
    Neither the error row nor its value is passed to this function.
    """
    aes.require_block(correct)
    aes.require_block(faulty)
    if column not in range(4):
        raise ValueError('Column must be 0..3.')
    positions = output_positions(column)

    # For each output byte, group all 256 key guesses by their implied d.
    # Indexing this table avoids enumerating all 2^32 four-byte key tuples.
    key_guesses = []
    for position in positions:
        by_difference = [[] for _ in range(256)]
        for guess in range(256):
            difference = aes.INV_SBOX[correct[position] ^ guess] ^ aes.INV_SBOX[faulty[position] ^ guess]
            by_difference[difference].append(guess)
        key_guesses.append(by_difference)

    candidates = set()
    for unknown_row in range(4):
        coefficients = [aes.MIX[row][unknown_row] for row in range(4)]
        for unknown_error in range(1, 256):
            choices = [key_guesses[row][aes.gf_mul(coefficients[row], unknown_error)] for row in range(4)]
            # The SAME error and row must satisfy all four equations.
            # Treating each byte independently would discard this constraint.
            candidates.update(product(*choices))
    return candidates


def recover_last_key(correct, faulty_outputs, report=None):
    """Attacker view: ciphertexts only, no master key, masks or internal states.

    Return (K10 or None, remaining candidates per group, outputs consumed).
    None means ambiguous: never pick an arbitrary surviving tuple.
    """
    aes.require_block(correct)
    survivors = [None] * 4
    used = 0
    for used, faulty in enumerate(faulty_outputs, 1):
        aes.require_block(faulty)
        if any(a == b for a, b in zip(correct, faulty)):
            raise ValueError('Expected all 16 bytes to change under this round-8 single-byte model.')
        for column in range(4):
            current = column_candidates(correct, faulty, column)
            previous_count = None if survivors[column] is None else len(survivors[column])
            survivors[column] = current if survivors[column] is None else survivors[column] & current
            if report:
                report(used, column, previous_count, len(current), len(survivors[column]))
            if not survivors[column]:
                raise ValueError('No candidates: incompatible key, pair alignment, or fault model.')
        if all(len(group) == 1 for group in survivors):
            last_key = bytearray(16)
            for column in range(4):
                for position, byte in zip(output_positions(column), next(iter(survivors[column]))):
                    last_key[position] = byte
            return bytes(last_key), survivors, used
    return None, survivors, used


def show_propagation(key, plaintext, fault):
    """Teacher view ONLY: visualize internal states; never used by the solver."""
    clean, faulty = {}, {}
    aes.encrypt_block(plaintext, key, trace=lambda r, op, s: clean.update({(r, op): s}))
    aes.encrypt_block(plaintext, key, fault, trace=lambda r, op, s: faulty.update({(r, op): s}))
    print('\n1. FAULT PROPAGATION (teacher view, hidden from the attacker)')
    for number, operation in [(8, 'ShiftRows'), (8, 'Injected XOR before MixColumns'),
                              (8, 'MixColumns'), (9, 'SubBytes'), (9, 'ShiftRows'),
                              (9, 'MixColumns'), (10, 'AddRoundKey')]:
        reference = clean[(8, 'ShiftRows')] if operation.startswith('Injected') else clean[(number, operation)]
        delta = bytes(a ^ b for a, b in zip(reference, faulty[(number, operation)]))
        print(f'R{number:02d} {operation:35s}: {sum(bool(b) for b in delta):2d} changed bytes')
        print('  XOR difference, displayed as AES rows:')
        for row in range(4):
            print('  ' + ' '.join(f'{delta[4*column+row]:02x}' for column in range(4)))
    print('One byte -> four bytes in one column -> one byte per column -> sixteen bytes.')


def show_equations():
    print('\n2. REMOVE THE LAST ROUND UNDER A KEY GUESS')
    print('d[r] = InvSbox[C[p[r]] XOR k[r]] XOR InvSbox[C_fault[p[r]] XOR k[r]]')
    print('For an error in row 0 before round-9 MixColumns: d = [2e, e, e, 3e].')
    print('Multiplication is in GF(2^8). Other error rows use the other matrix columns.')
    print('The solver tries all four rows and all 255 nonzero errors, not the injected mask.')
    print('The effective round-9 errors differ from the original round-8 mask because of SubBytes.')
    for column in range(4):
        print(f'Column group {column}: ciphertext/K10 positions {output_positions(column)}')
    print('Intersect candidate FOUR-BYTE TUPLES from independent faulty encryptions.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key', default=aes.KEY.hex(), help='Simulator key only; never passed to the solver.')
    parser.add_argument('--plaintext', default=aes.PLAINTEXT.hex())
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--faults', type=int, default=6, help='Maximum generated outputs (1..255); stop when unique.')
    parser.add_argument('--row', type=int, choices=range(4), default=0)
    parser.add_argument('--column', type=int, choices=range(4), default=0)
    parser.add_argument('--step', action='store_true', help='Pause between teaching sections and faulty outputs.')
    args = parser.parse_args()
    try:
        key, plaintext = bytes.fromhex(args.key), bytes.fromhex(args.plaintext)
        aes.require_block(key)
        aes.require_block(plaintext)
        if not 1 <= args.faults <= 255:
            raise ValueError('--faults must be 1..255.')
    except ValueError as error:
        parser.error(str(error))

    def pause():
        if args.step:
            input('Press Enter to continue...')

    masks = random.Random(args.seed).sample(range(1, 256), args.faults)
    first = aes.Fault(8, args.row, args.column, masks[0])
    print('PIRET-QUISQUATER-STYLE DFA | local AES-128 software laboratory')
    print('Fault point: immediately before MixColumns in round 8.')
    print('This teaching solver uses final-round constraints and may need more than two faults.')
    show_propagation(key, plaintext, first)
    pause()
    show_equations()
    pause()
    correct = aes.encrypt_block(plaintext, key)
    print(f'\n3. ATTACKER OBSERVATIONS\nCorrect ciphertext: {correct.hex()}')

    def observations():
        for index, mask in enumerate(masks, 1):
            faulty = aes.encrypt_block(plaintext, key, aes.Fault(8, args.row, args.column, mask))
            print(f'\nFaulty ciphertext {index}: {faulty.hex()}')
            yield faulty
            pause()

    def report(index, column, before, current, remaining):
        print(f'  Group {column}: {current} candidates from pair {index}; '
              f'intersection {before if before is not None else "unconstrained"} -> {remaining}')

    last_key, survivors, used = recover_last_key(correct, observations(), report)
    if last_key is None:
        print(f'\nAMBIGUOUS after {used} outputs: {[len(s) for s in survivors]} candidates per group.')
        print('Increase --faults. The program will not claim an unverified key.')
        return 2
    recovered_key = aes.reverse_key_schedule(last_key)
    print(f'\n4. REVERSE THE AES-128 KEY SCHEDULE\nRecovered K10: {last_key.hex()}')
    print(f'Recovered K0 : {recovered_key.hex()}')
    # Only now use known plaintext for verification; it was not needed by DFA.
    if aes.encrypt_block(plaintext, recovered_key) != correct:
        raise RuntimeError('Recovered key failed known-plaintext verification.')
    if recovered_key != key:
        raise RuntimeError('Simulation ground-truth verification failed.')
    print(f'Key recovery: PASS using {used} faulty ciphertexts.')
    print('The solver received no key, fault mask, fault coordinates, or intermediate state.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
