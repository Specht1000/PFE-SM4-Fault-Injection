"""Program and validate the AES-128 target, then capture baseline power traces.

Commands: connect, flash, verify, capture. No fault injection is enabled.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import time

HERE = Path(__file__).resolve().parent
KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
PLAINTEXT = bytes.fromhex('00112233445566778899aabbccddeeff')
CIPHERTEXT = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
IDENTITY = b'AES\x01'


def require_ack(target):
    status = target.simpleserial_wait_ack(timeout=1000)
    if status != 0:
        raise RuntimeError(f'Missing or unsuccessful SimpleSerial acknowledgement: {status!r}')


def read_response(target, length):
    # Read acknowledgement separately so firmware errors cannot be ignored.
    data = target.simpleserial_read('r', length, timeout=1000, ack=False)
    if data is None or len(data) != length:
        raise RuntimeError('Missing or malformed target response. Check firmware, clock, and UART.')
    require_ack(target)
    return bytes(data)


def identify(target):
    target.simpleserial_write('i', bytearray())
    if read_response(target, 4) != IDENTITY:
        raise RuntimeError('Unexpected firmware identity. Flash the supplied pfe-aes firmware.')


def set_key(target, key):
    target.simpleserial_write('k', bytearray(key))
    require_ack(target)


def encrypt(target, plaintext):
    target.simpleserial_write('p', bytearray(plaintext))
    return read_response(target, 16)


def verify(target):
    identify(target)
    set_key(target, KEY)
    actual = encrypt(target, PLAINTEXT)
    if actual != CIPHERTEXT:
        raise RuntimeError(f'AES known-answer test failed: {actual.hex()} != {CIPHERTEXT.hex()}')
    print(f'AES-128 known-answer test: PASS ({actual.hex()})')


def capture_one(scope, target, plaintext, expected):
    scope.arm()
    target.simpleserial_write('p', bytearray(plaintext))
    if scope.capture():
        raise RuntimeError('Capture timeout: no complete trace. Check the TIO4 trigger and firmware.')
    ciphertext = read_response(target, 16)
    if ciphertext != expected:
        raise RuntimeError(f'Baseline ciphertext mismatch: {ciphertext.hex()} != {expected.hex()}')
    wave = scope.get_last_trace()
    if wave is None or len(wave) != scope.adc.samples:
        raise RuntimeError('Incomplete capture buffer.')
    return ciphertext, wave


def capture(scope, target, args, cw_version):
    import numpy as np
    from Crypto.Cipher import AES

    cipher = AES.new(KEY, AES.MODE_ECB)
    rng = random.Random(args.seed)
    folder = args.output / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    folder.mkdir(parents=True, exist_ok=False)
    metadata = dict(created_utc=datetime.now(timezone.utc).isoformat(),
                    platform='CWLITEARM', firmware_identity=IDENTITY.hex(),
                    protocol='SimpleSerial V1.1', chipwhisperer_version=cw_version,
                    key=KEY.hex(), seed=args.seed, requested_traces=args.traces,
                    samples=args.samples, adc_frequency_hz=float(scope.clock.adc_freq),
                    target_clock_hz=float(scope.clock.clkgen_freq), scope_settings=str(scope),
                    completed_traces=0, status='running',
                    note='Public lab key. ADC samples are normalized readings, not watts. '
                         'The capture window may cover only part of the encryption.')
    info = folder / 'metadata.json'
    info.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    try:
        for index in range(args.traces):
            plaintext = PLAINTEXT if index == 0 else bytes(rng.randrange(256) for _ in range(16))
            ciphertext, wave = capture_one(scope, target, plaintext, cipher.encrypt(plaintext))
            # Persist each successful capture immediately, including input and key.
            np.savez_compressed(folder / f'trace_{index:05d}.npz', wave=wave,
                                plaintext=np.frombuffer(plaintext, dtype=np.uint8),
                                ciphertext=np.frombuffer(ciphertext, dtype=np.uint8),
                                key=np.frombuffer(KEY, dtype=np.uint8))
            metadata['completed_traces'] = index + 1
            print(f'[{index + 1}/{args.traces}] AES verified; {len(wave)} samples saved.')
        metadata['status'] = 'complete'
    except BaseException as exc:
        metadata.update(status='failed', error=f'{type(exc).__name__}: {exc}')
        raise
    finally:
        info.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
        print(f'Results: {folder.resolve()}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('connect', 'flash', 'verify', 'capture'))
    parser.add_argument('--firmware', type=Path, default=HERE / 'build/pfe-aes-CWLITEARM.hex')
    parser.add_argument('--serial-number', help='Select a specific capture device')
    parser.add_argument('--traces', type=int, default=10)
    parser.add_argument('--samples', type=int, default=24000)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--output', type=Path, default=HERE / 'results')
    args = parser.parse_args()
    if args.traces < 1 or not 1 <= args.samples <= 24573:
        parser.error('Use at least one trace and 1–24573 samples for ChipWhisperer-Lite.')
    if args.command == 'flash' and not args.firmware.is_file():
        parser.error(f'Firmware not found: {args.firmware}. Run build.py first.')
    try:
        import chipwhisperer as cw
        if args.command == 'capture':
            import numpy
            from Crypto.Cipher import AES
    except ImportError as exc:
        parser.exit(1, f'Missing dependency: {exc}. Install this directory\'s requirements.txt.\n')

    scope = None
    target = None
    try:
        scope = cw.scope(sn=args.serial_number)
        scope.default_setup()
        scope.io.glitch_hp = False
        scope.io.glitch_lp = False
        scope.io.hs2 = 'clkgen'
        scope.adc.samples = args.samples
        scope.adc.offset = 0
        scope.adc.timeout = 2
        if args.command == 'connect':
            print(f'ChipWhisperer {cw.__version__}: connected.')
            print(scope)
            return
        if args.command == 'flash':
            print(f'Programming STM32F303: {args.firmware.resolve()}')
            print(f'SHA-256: {hashlib.sha256(args.firmware.read_bytes()).hexdigest()}')
            cw.program_target(scope, cw.programmers.STM32FProgrammer, str(args.firmware.resolve()))
        # Reset the target to a known state before starting the protocol.
        scope.io.nrst = 'low'
        time.sleep(0.05)
        scope.io.nrst = 'high_z'
        time.sleep(0.25)
        target = cw.target(scope, cw.targets.SimpleSerial)
        target.baud = 38400
        target.flush()
        verify(target)
        if args.command == 'capture':
            capture(scope, target, args, cw.__version__)
    finally:
        try:
            if target is not None:
                target.dis()
        finally:
            if scope is not None:
                scope.dis()


if __name__ == '__main__':
    main()
