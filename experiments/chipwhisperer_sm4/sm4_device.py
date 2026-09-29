"""ChipWhisperer connection, strict SimpleSerial protocol, and verified workflows."""
import time
from sm4_reference import process, validate_fault

KEY = bytes.fromhex('0123456789abcdeffedcba9876543210')
CIPHERTEXT = bytes.fromhex('681edf34d206965e86b3e94f536e4246')


class Device:
    def __init__(self):
        self.scope = self.target = None
        self.key = KEY

    def close(self):
        try:
            if self.target is not None:
                self.target.dis()
        finally:
            self.target = None
            try:
                if self.scope is not None:
                    self.scope.dis()
            finally:
                self.scope = None

    def connect(self, serial=None, firmware=None):
        import chipwhisperer as cw
        if self.scope is not None:
            raise ValueError('Disconnect before opening another connection.')
        try:
            self.scope = cw.scope(sn=serial or None)
            self.scope.default_setup()
            self.scope.io.glitch_hp = False
            self.scope.io.glitch_lp = False
            self.scope.io.hs2 = 'clkgen'
            if firmware:
                cw.program_target(self.scope, cw.programmers.STM32FProgrammer, str(firmware))
            self.scope.io.nrst = 'low'
            time.sleep(0.05)
            self.scope.io.nrst = 'high_z'
            time.sleep(0.25)
            self.target = cw.target(self.scope, cw.targets.SimpleSerial)
            self.target.baud = 38400
            self.target.flush()
            if self.command('i', b'', 4) != b'SM4\x01':
                raise RuntimeError('Unexpected firmware. Flash pfe-sm4-CWLITEARM.hex.')
            self.set_key(KEY)
            if self.command('p', KEY) != CIPHERTEXT or self.command('d', CIPHERTEXT) != KEY:
                raise RuntimeError('Target SM4 known-answer test failed.')
        except BaseException:
            self.close()
            raise

    def read(self, length):
        data = self.target.simpleserial_read('r', length, timeout=2000, ack=False) if length else b''
        if data is None or len(data) != length:
            raise RuntimeError('Incomplete target response. Disconnect and reconnect.')
        ack = self.target.simpleserial_wait_ack(timeout=2000)
        if ack != 0:
            raise RuntimeError(f'Target acknowledgement failed: {ack!r}')
        return bytes(data)

    def command(self, command, payload, length=16):
        if self.target is None:
            raise RuntimeError('Connect to the target first.')
        self.target.simpleserial_write(command, bytearray(payload))
        return self.read(length)

    def set_key(self, key):
        if len(key) != 16:
            raise ValueError('Key must be 32 hexadecimal digits.')
        self.command('k', key, 0)
        self.key = bytes(key)

    def block(self, data, decrypt=False, trace=True, fault=None):
        expected, states, event = process(data, self.key, decrypt, fault)
        if decrypt and fault:
            raise ValueError('Software fault injection is available for encryption only.')
        command = 'f' if fault else ('u' if decrypt else 't') if trace else ('d' if decrypt else 'p')
        reply = self.command(command, bytes(fault) + data if fault else data, 18 if fault else 16)
        if reply[:16] != expected:
            raise RuntimeError('Target output differs from the Python reference.')
        if fault and list(reply[16:]) != event:
            raise RuntimeError('Target fault event differs from the reference.')
        snapshots = []
        if trace or fault:
            for i, expected_state in enumerate(states):
                packet = self.command('s', bytes([i]), 19)
                header = bytes([i, min(i, 32), 0 if i == 0 else 2 if i == 33 else 1])
                if packet != header + expected_state:
                    raise RuntimeError(f'Target snapshot {i} differs from the reference.')
                snapshots.append({'index': i, 'round': min(i, 32),
                                  'stage': 'Input' if i == 0 else 'Output reversal' if i == 33 else 'Round',
                                  'state': packet[3:].hex()})
        return reply[:16], snapshots, list(reply[16:]) if fault else None


def prepare(value, mode, decrypt=False):
    if mode not in ('text', 'hex'):
        raise ValueError('Input format must be text or hex.')
    if decrypt and mode != 'hex':
        raise ValueError('Ciphertext must use hexadecimal input.')
    if mode == 'text':
        data = value.encode('utf-8')
        padding = 16 - len(data) % 16
        return data + bytes([padding]) * padding
    data = bytes.fromhex(value)
    if not data or len(data) % 16:
        raise ValueError('Hex input must contain a positive multiple of 16 bytes.')
    return data


def unpad(data):
    n = data[-1] if data else 0
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError('Invalid PKCS#7 padding. Use raw decryption for unpadded hex input.')
    return data[:-n]


def execute(device, request):
    operation = request.get('operation', 'encrypt')
    if operation not in ('encrypt', 'decrypt', 'fault'):
        raise ValueError('Unknown operation.')
    decrypt = operation == 'decrypt'
    data = prepare(request['value'], request.get('format', 'hex'), decrypt)
    if len(data) > 4096:
        raise ValueError('Interactive messages are limited to 4096 bytes.')
    fault = request.get('fault', [31, 1, 0, 1]) if operation == 'fault' else None
    validate_fault(fault)
    selected = int(request.get('block', 1))
    if fault and not 1 <= selected <= len(data) // 16:
        raise ValueError('Fault block is outside the message (block numbers start at 1).')
    if 'key' in request:
        device.set_key(bytes.fromhex(request['key']))
    blocks, output, recovered = [], bytearray(), bytearray()
    for start in range(0, len(data), 16):
        block = data[start:start+16]
        active = fault if start // 16 + 1 == selected else None
        baseline = device.block(block, trace=True)[0:2] if active else None
        result, states, event = device.block(block, decrypt, request.get('trace', True), active)
        inverse, _, _ = device.block(result, not decrypt, False)
        if not active and inverse != block:
            raise RuntimeError('Target round-trip verification failed.')
        item = {'block': start // 16 + 1, 'input': block.hex(), 'output': result.hex(),
                'recovered': inverse.hex(), 'roundtrip_ok': inverse == block,
                'snapshots': states, 'fault_event': event}
        if active:
            clean, clean_states = baseline
            item.update(clean_output=clean.hex(), clean_snapshots=clean_states,
                        changed_bytes=sum(a != b for a, b in zip(clean, result)),
                        changed_bits=sum((a ^ b).bit_count() for a, b in zip(clean, result)))
        blocks.append(item)
        output.extend(result)
        recovered.extend(inverse)
    decoded = unpad(bytes(output)) if decrypt and request.get('unpad', False) else bytes(output)
    return {'operation': operation, 'output': output.hex(), 'decoded_hex': decoded.hex(),
            'text': decoded.decode('utf-8', errors='replace') if decrypt else None,
            'recovered': recovered.hex(), 'verified': True, 'blocks': blocks}
