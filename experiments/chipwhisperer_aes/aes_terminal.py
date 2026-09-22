"""Send plaintext to the STM32F303 and print AES results and on-device states.

Interactive input: ordinary UTF-8 text, hex:<raw blocks>, or /quit.
Text uses PKCS#7 padding; hex input must contain complete 16-byte blocks.
Multi-block messages use independent AES blocks (ECB) for this teaching demo.
"""
import argparse
from contextlib import contextmanager
import time

from aes_capture import KEY, identify, set_key, encrypt, read_response, verify

OPERATIONS = {0: 'Input', 1: 'SubBytes', 2: 'ShiftRows', 3: 'MixColumns', 4: 'AddRoundKey'}
STEPS = [(0, 0), (0, 4)] + [(r, op) for r in range(1, 10) for op in (1, 2, 3, 4)] + [(10, 1), (10, 2), (10, 4)]


def prepare_input(value, input_format):
    if input_format == 'hex':
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError('Hex input must contain hexadecimal byte pairs.') from exc
        if not raw or len(raw) % 16:
            raise ValueError('Hex input must contain a nonzero multiple of 16 bytes (32 hex digits per block).')
        return raw, raw
    raw = value.encode('utf-8')
    padding = 16 - len(raw) % 16
    return raw, raw + bytes([padding]) * padding


def decode_snapshot(packet, index):
    if len(packet) != 19 or tuple(packet[:3]) != (index, *STEPS[index]):
        raise RuntimeError(f'Unexpected snapshot header at index {index}. Reflash the matching firmware.')
    return {'index': index, 'round': packet[1], 'operation': OPERATIONS[packet[2]],
            'state': bytes(packet[3:])}


def fetch_trace(target, plaintext):
    target.simpleserial_write('t', bytearray(plaintext))
    ciphertext = read_response(target, 16)
    snapshots = []
    for index in range(len(STEPS)):
        target.simpleserial_write('s', bytearray([index]))
        snapshots.append(decode_snapshot(read_response(target, 19), index))
    if snapshots[0]['state'] != plaintext or snapshots[-1]['state'] != ciphertext:
        raise RuntimeError('Snapshot endpoints do not match the submitted plaintext and ciphertext.')
    return ciphertext, snapshots


def print_snapshot(snapshot, matrix=False):
    print(f'  R{snapshot["round"]:02d} {snapshot["operation"]:<12} {snapshot["state"].hex()}')
    if matrix:
        for row in range(4):
            print('       ' + ' '.join(f'{snapshot["state"][4 * column + row]:02x}' for column in range(4)))


def process_message(target, value, input_format, key, trace=True, matrix=False, step=False):
    from Crypto.Cipher import AES

    raw, padded = prepare_input(value, input_format)
    print(f'\nInput format: {input_format.upper()} | Original length: {len(raw)} bytes')
    print(f'Plaintext:    {raw.hex() or "(empty)"}')
    print('Mode: AES-128 ECB | Padding: ' + ('PKCS#7' if input_format == 'text' else 'none'))
    if padded != raw:
        print(f'Padded input: {padded.hex()}')
    print(f'Key:          {key.hex()}')
    if trace:
        print('States below were recorded on the STM32 during encryption, then fetched over UART.')
    reference = AES.new(key, AES.MODE_ECB)
    blocks = []
    for offset in range(0, len(padded), 16):
        plaintext = padded[offset:offset + 16]
        print(f'\nBlock {offset // 16 + 1}/{len(padded) // 16} | PC -> STM32: {plaintext.hex()}')
        if trace:
            ciphertext, snapshots = fetch_trace(target, plaintext)
        else:
            ciphertext, snapshots = encrypt(target, plaintext), []
        if ciphertext != reference.encrypt(plaintext):
            raise RuntimeError('The ciphertext returned by the STM32 failed independent AES verification.')
        for snapshot in snapshots:
            print_snapshot(snapshot, matrix)
            if step:
                input('  Press Enter to display the next recorded state...')
        print(f'STM32 -> PC: {ciphertext.hex()} | Verification: PASS')
        blocks.append(ciphertext)
    result = b''.join(blocks)
    print(f'\nCiphertext (hex): {result.hex()}\n')
    return result


@contextmanager
def hardware_target(serial_number=None):
    import chipwhisperer as cw

    scope = None
    target = None
    try:
        scope = cw.scope(sn=serial_number)
        scope.default_setup()
        scope.io.glitch_hp = False
        scope.io.glitch_lp = False
        scope.io.hs2 = 'clkgen'
        scope.io.nrst = 'low'
        time.sleep(0.05)
        scope.io.nrst = 'high_z'
        time.sleep(0.25)
        target = cw.target(scope, cw.targets.SimpleSerial)
        target.baud = 38400
        target.flush()
        yield target
    finally:
        try:
            if target is not None:
                target.dis()
        finally:
            if scope is not None:
                scope.dis()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    message = parser.add_mutually_exclusive_group()
    message.add_argument('--text', help='Encrypt a UTF-8 message using PKCS#7 padding')
    message.add_argument('--hex', help='Encrypt raw blocks given as hexadecimal, without padding')
    parser.add_argument('--key', default=KEY.hex(), help='AES-128 key: 32 hex digits (default: public demo key)')
    parser.add_argument('--no-trace', action='store_true', help='Use normal encryption; print only input/output')
    parser.add_argument('--matrix', action='store_true', help='Also display each state as a 4x4 matrix')
    parser.add_argument('--step', action='store_true', help='Pause while displaying each recorded state')
    parser.add_argument('--serial-number')
    args = parser.parse_args()
    try:
        key = bytes.fromhex(args.key)
        if len(key) != 16:
            raise ValueError('The AES-128 key must contain exactly 16 bytes.')
        if args.text is not None:
            prepare_input(args.text, 'text')
        if args.hex is not None:
            prepare_input(args.hex, 'hex')
    except ValueError as exc:
        parser.error(str(exc))
    try:
        with hardware_target(args.serial_number) as target:
            identity = verify(target)
            if not args.no_trace and identity != b'AES\x02':
                raise RuntimeError('Trace mode requires firmware revision 2. Run aes_capture.py flash first.')
            set_key(target, key)
            print('Connected to STM32F303. Encryption runs on the target.')

            def run(value, kind):
                return process_message(target, value, kind, key, not args.no_trace, args.matrix, args.step)

            if args.text is not None:
                run(args.text, 'text')
            elif args.hex is not None:
                run(args.hex, 'hex')
            else:
                print('Enter UTF-8 text, hex:<raw blocks>, text:<literal text>, or /quit.')
                while True:
                    value = input('Plaintext> ')
                    if value.strip().lower() == '/quit':
                        break
                    kind = 'hex' if value.startswith('hex:') else 'text'
                    value = value[4:] if kind == 'hex' else value[5:] if value.startswith('text:') else value
                    try:
                        run(value, kind)
                    except ValueError as exc:
                        print(f'Input error: {exc}')
    except (KeyboardInterrupt, EOFError):
        print('\nSession closed.')
    except (RuntimeError, OSError, ImportError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
