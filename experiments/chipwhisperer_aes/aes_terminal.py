"""Encrypt/decrypt on the STM32F303 and print AES results and on-device states.

Interactive input: ordinary UTF-8 text, hex:<raw blocks>, or /quit.
Text uses PKCS#7 padding; hex input must contain complete 16-byte blocks.
Multi-block messages use independent AES blocks (ECB) for this teaching demo.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import time

from aes_capture import KEY, set_key, encrypt, decrypt, read_response, verify

OPERATIONS = {0: 'Input', 1: 'SubBytes', 2: 'ShiftRows', 3: 'MixColumns', 4: 'AddRoundKey'}
STEPS = [(0, 0), (0, 4)] + [(r, op) for r in range(1, 10) for op in (1, 2, 3, 4)] + [(10, 1), (10, 2), (10, 4)]


@dataclass(frozen=True)
class FaultSettings:
    round: int = 9
    stage: str = 'MixColumns'
    row: int = 0
    column: int = 0
    mask: int = 1
    block: int = 1

    def __post_init__(self):
        if not 1 <= self.round <= 10:
            raise ValueError('Fault round must be 1-10.')
        if self.stage not in tuple(OPERATIONS.values())[1:]:
            raise ValueError('Fault stage must be SubBytes, ShiftRows, MixColumns, or AddRoundKey.')
        if self.round == 10 and self.stage == 'MixColumns':
            raise ValueError('Round 10 has no MixColumns operation.')
        if not 0 <= self.row <= 3 or not 0 <= self.column <= 3:
            raise ValueError('Fault row and column must be 0-3.')
        if not 1 <= self.mask <= 255 or self.block < 1:
            raise ValueError('Fault mask must be 1-255 and block must be at least 1.')

    def wire_bytes(self):
        operation = next(op for op, name in OPERATIONS.items() if name == self.stage)
        return bytes((self.round, operation, self.row, self.column, self.mask))


def parse_fault_command(value, current=None):
    parts = value.split()
    if parts == ['/fault', 'off']:
        return None
    if parts == ['/fault', 'on']:
        return current or FaultSettings()
    if len(parts) in (6, 7) and parts[0] == '/fault':
        return FaultSettings(int(parts[1]), parts[2], int(parts[3]), int(parts[4]),
                             int(parts[5], 0), int(parts[6]) if len(parts) == 7 else 1)
    raise ValueError('Use /fault on, /fault off, or /fault ROUND STAGE ROW COLUMN MASK [BLOCK].')


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
    return ciphertext, read_snapshots(target, plaintext, ciphertext)


def read_snapshots(target, plaintext, ciphertext):
    snapshots = []
    for index in range(len(STEPS)):
        target.simpleserial_write('s', bytearray([index]))
        snapshots.append(decode_snapshot(read_response(target, 19), index))
    if snapshots[0]['state'] != plaintext or snapshots[-1]['state'] != ciphertext:
        raise RuntimeError('Snapshot endpoints do not match the submitted plaintext and ciphertext.')
    return snapshots


def fetch_fault_trace(target, plaintext, fault):
    target.simpleserial_write('f', bytearray(fault.wire_bytes() + plaintext))
    response = read_response(target, 18)
    ciphertext, event = response[:16], response[16:]
    if event[0] ^ event[1] != fault.mask:
        raise RuntimeError('Target fault event does not match the requested XOR mask.')
    return ciphertext, read_snapshots(target, plaintext, ciphertext), event


def process_fault_message(target, value, input_format, key, fault, matrix=False, step=False):
    from Crypto.Cipher import AES

    raw, padded = prepare_input(value, input_format)
    block_count = len(padded) // 16
    if fault.block > block_count:
        raise ValueError(f'Fault block {fault.block} exceeds the message length ({block_count} blocks).')
    reference = AES.new(key, AES.MODE_ECB)
    clean_blocks, faulty_blocks, recovered_blocks = [], [], []
    print('\nSOFTWARE FAULT INJECTION ON STM32 (no physical glitch)')
    print(f'One XOR in block {fault.block}, round {fault.round}, BEFORE {fault.stage}, '
          f'row {fault.row}, column {fault.column}, mask 0x{fault.mask:02x}.')
    print('Padding: ' + ('PKCS#7' if input_format == 'text' else 'none'))
    print(f'Original input: {raw.hex()}\nAES input:      {padded.hex()}')
    for number in range(1, block_count + 1):
        plaintext = padded[(number - 1) * 16:number * 16]
        clean, clean_states = fetch_trace(target, plaintext)
        if clean != reference.encrypt(plaintext) or decrypt(target, clean) != plaintext:
            raise RuntimeError('The fault-free baseline failed AES or decryption verification.')
        faulty = clean
        if number == fault.block:
            faulty, faulty_states, event = fetch_fault_trace(target, plaintext, fault)
            if faulty == clean:
                raise RuntimeError('The requested nonzero state fault did not change the ciphertext.')
            operation = fault.wire_bytes()[1]
            injection_index = STEPS.index((fault.round, operation))
            position = 4 * fault.column + fault.row
            if event[0] != clean_states[injection_index - 1]['state'][position]:
                raise RuntimeError('The fault event does not match the expected injection location.')
            if any(a['state'] != b['state'] for a, b in
                   zip(clean_states[:injection_index], faulty_states[:injection_index])):
                raise RuntimeError('States differ before the requested injection point.')
            print(f'\nInjected byte: 0x{event[0]:02x} -> 0x{event[1]:02x} '
                  f'(XOR 0x{fault.mask:02x}; 1 byte, {bin(fault.mask).count("1")} bits changed)')
            print('Saved states below are AFTER each operation; the XOR happens BEFORE the selected operation.')
            print('Round / operation       XOR difference                   Bytes  Bits')
            for a, b in zip(clean_states, faulty_states):
                delta = bytes(x ^ y for x, y in zip(a['state'], b['state']))
                print(f'R{a["round"]:02d} {a["operation"]:<18} {delta.hex()}  '
                      f'{sum(bool(x) for x in delta):2}/16  {sum(bin(x).count("1") for x in delta):3}/128')
                if matrix:
                    print('  Correct state:')
                    print_snapshot(a, True)
                    print('  Faulty state:')
                    print_snapshot(b, True)
                if step:
                    input('Press Enter to display the next comparison...')
        recovered = decrypt(target, faulty)
        if recovered != reference.decrypt(faulty):
            raise RuntimeError('Target decryption failed verification for the faulty ciphertext.')
        clean_blocks.append(clean)
        faulty_blocks.append(faulty)
        recovered_blocks.append(recovered)
    correct, faulty, recovered = map(b''.join, (clean_blocks, faulty_blocks, recovered_blocks))
    print(f'\nCorrect ciphertext: {correct.hex()}')
    print(f'Faulty ciphertext:  {faulty.hex()}')
    print(f'Ciphertext XOR:     {bytes(a ^ b for a, b in zip(correct, faulty)).hex()}')
    print(f'Decrypted faulty ciphertext (raw, padding retained): {recovered.hex()}')
    if recovered == padded:
        raise RuntimeError('Unexpected original plaintext after decrypting a changed ciphertext.')
    print('Original plaintext comparison: MISMATCH (expected consequence of the injected fault).')
    print('Baseline AES and target decryption: PASS. Fault is confined to this request.\n')
    return correct, faulty, recovered


def print_snapshot(snapshot, matrix=False):
    print(f'  R{snapshot["round"]:02d} {snapshot["operation"]:<12} {snapshot["state"].hex()}')
    if matrix:
        for row in range(4):
            print('       ' + ' '.join(f'{snapshot["state"][4 * column + row]:02x}' for column in range(4)))


def unpad_pkcs7(data):
    if not data or len(data) % 16:
        raise ValueError('PKCS#7 data must contain complete AES blocks.')
    count = data[-1]
    if not 1 <= count <= 16 or data[-count:] != bytes([count]) * count:
        raise ValueError('Invalid PKCS#7 padding. Check the key, ciphertext, and padding mode.')
    return data[:-count]


def print_plaintext(plaintext):
    print(f'Plaintext (hex): {plaintext.hex()}')
    try:
        print(f'Plaintext (UTF-8): {plaintext.decode("utf-8")!r}')
    except UnicodeDecodeError:
        print('Plaintext is binary data (not valid UTF-8).')


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
    recovered_blocks = []
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
        print(f'PC -> STM32 [decrypt]: {ciphertext.hex()}')
        recovered = decrypt(target, ciphertext)
        if recovered != plaintext:
            raise RuntimeError('STM32 decryption did not recover the original plaintext block.')
        print(f'STM32 -> PC [plaintext]: {recovered.hex()} | Round-trip: PASS')
        blocks.append(ciphertext)
        recovered_blocks.append(recovered)
    result = b''.join(blocks)
    print(f'\nCiphertext (hex): {result.hex()}\n')
    recovered = b''.join(recovered_blocks)
    if input_format == 'text':
        recovered = unpad_pkcs7(recovered)
    if recovered != raw:
        raise RuntimeError('Recovered message does not match the original input.')
    print_plaintext(recovered)
    print('STM32 encrypt -> STM32 decrypt -> original plaintext: PASS\n')
    return result


def process_decryption(target, value, key, unpad=False):
    from Crypto.Cipher import AES

    _, ciphertext = prepare_input(value, 'hex')
    reference = AES.new(key, AES.MODE_ECB)
    blocks = []
    print('\nMode: AES-128 ECB decryption on STM32')
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        print(f'PC -> STM32 [decrypt]: {block.hex()}')
        recovered = decrypt(target, block)
        if recovered != reference.decrypt(block):
            raise RuntimeError('STM32 decryption failed independent AES verification.')
        print(f'STM32 -> PC [plaintext]: {recovered.hex()} | Verification: PASS')
        blocks.append(recovered)
    plaintext = b''.join(blocks)
    if unpad:
        plaintext = unpad_pkcs7(plaintext)
    print_plaintext(plaintext)
    print('Padding: ' + ('PKCS#7 removed' if unpad else 'none removed'))
    return plaintext


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
    message.add_argument('--decrypt', metavar='HEX', help='Decrypt a hexadecimal ciphertext on the STM32')
    parser.add_argument('--unpad', action='store_true', help='Remove PKCS#7 padding with --decrypt')
    parser.add_argument('--key', default=KEY.hex(), help='AES-128 key: 32 hex digits (default: public demo key)')
    parser.add_argument('--no-trace', action='store_true', help='Use normal encryption; print only input/output')
    parser.add_argument('--matrix', action='store_true', help='Also display each state as a 4x4 matrix')
    parser.add_argument('--step', action='store_true', help='Pause while displaying each recorded state')
    parser.add_argument('--serial-number')
    parser.add_argument('--fault', action='store_true', help='Compare normal AES with a software state fault on STM32')
    parser.add_argument('--fault-round', type=int, default=9)
    parser.add_argument('--fault-stage', choices=tuple(OPERATIONS.values())[1:], default='MixColumns')
    parser.add_argument('--fault-row', type=int, default=0)
    parser.add_argument('--fault-column', type=int, default=0)
    parser.add_argument('--fault-mask', type=lambda value: int(value, 0), default=1)
    parser.add_argument('--fault-block', type=int, default=1, help='Message block to fault (1-based)')
    args = parser.parse_args()
    if args.unpad and args.decrypt is None:
        parser.error('--unpad requires --decrypt. Interactive mode uses decrypt-text:<hex>.')
    if args.fault and (args.decrypt is not None or args.no_trace):
        parser.error('--fault requires encryption with trace mode enabled.')
    try:
        configured_fault = FaultSettings(args.fault_round, args.fault_stage, args.fault_row,
                                         args.fault_column, args.fault_mask, args.fault_block)
        active_fault = configured_fault if args.fault else None
        key = bytes.fromhex(args.key)
        if len(key) != 16:
            raise ValueError('The AES-128 key must contain exactly 16 bytes.')
        if args.text is not None:
            prepare_input(args.text, 'text')
        if args.hex is not None:
            prepare_input(args.hex, 'hex')
        if args.decrypt is not None:
            prepare_input(args.decrypt, 'hex')
    except ValueError as exc:
        parser.error(str(exc))
    try:
        with hardware_target(args.serial_number) as target:
            identity = verify(target)
            if identity not in (b'AES\x02', b'AES\x03'):
                raise RuntimeError('This terminal requires firmware revision 2. Run aes_capture.py flash first.')
            if active_fault and identity != b'AES\x03':
                raise RuntimeError('Fault injection requires firmware revision 3. Run aes_capture.py flash first.')
            set_key(target, key)
            print('Connected to STM32F303. Encryption runs on the target.')

            def run(value, kind):
                if active_fault:
                    return process_fault_message(target, value, kind, key, active_fault, args.matrix, args.step)
                return process_message(target, value, kind, key, not args.no_trace, args.matrix, args.step)

            if args.text is not None:
                run(args.text, 'text')
            elif args.hex is not None:
                run(args.hex, 'hex')
            elif args.decrypt is not None:
                process_decryption(target, args.decrypt, key, args.unpad)
            else:
                print('Encrypt: UTF-8 text, hex:<raw blocks>, or text:<literal text>.')
                print('Decrypt: decrypt:<hex> (raw) or decrypt-text:<hex> (PKCS#7). Exit: /quit.')
                print('Software FI: /fault on, /fault off, /fault ROUND STAGE ROW COLUMN MASK [BLOCK].')
                print(f'Fault mode: {active_fault or "OFF"}')
                while True:
                    value = input('AES> ')
                    if value.strip().lower() == '/quit':
                        break
                    try:
                        if value.startswith('/fault'):
                            selected = parse_fault_command(value, active_fault or configured_fault)
                            if selected and (identity != b'AES\x03' or args.no_trace):
                                raise ValueError('Software FI requires firmware revision 3 and trace mode.')
                            active_fault = selected
                            print(f'Fault mode: {active_fault or "OFF"}')
                        elif value.startswith('decrypt-text:'):
                            process_decryption(target, value[13:], key, unpad=True)
                        elif value.startswith('decrypt:'):
                            process_decryption(target, value[8:], key)
                        else:
                            kind = 'hex' if value.startswith('hex:') else 'text'
                            value = value[4:] if kind == 'hex' else value[5:] if value.startswith('text:') else value
                            run(value, kind)
                    except ValueError as exc:
                        print(f'Input error: {exc}')
    except (KeyboardInterrupt, EOFError):
        print('\nSession closed.')
    except (RuntimeError, OSError, ImportError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
