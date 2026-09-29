"""Flash or verify the SM4 target and capture baseline power traces."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import random
from sm4_device import Device, KEY
from sm4_reference import process

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['flash', 'verify', 'capture'])
    parser.add_argument('--firmware', type=Path, default=HERE / 'build/pfe-sm4-CWLITEARM.hex')
    parser.add_argument('--serial-number')
    parser.add_argument('--traces', type=int, default=10)
    parser.add_argument('--samples', type=int, default=24000)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--output', type=Path, default=HERE / 'results')
    args = parser.parse_args()
    if args.traces < 1 or not 1 <= args.samples <= 24573:
        parser.error('Use a positive trace count and 1..24573 samples.')
    if args.command == 'flash' and not args.firmware.is_file():
        parser.error('Firmware not found. Run build.py first.')
    device = Device()
    try:
        device.connect(args.serial_number, args.firmware.resolve() if args.command == 'flash' else None)
        print('STM32 SM4 encryption and decryption known-answer tests: PASS')
        if args.command != 'capture':
            return
        import numpy as np
        import chipwhisperer as cw
        scope = device.scope
        scope.adc.samples = args.samples
        scope.adc.offset = 0
        scope.adc.timeout = 2
        folder = args.output / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
        folder.mkdir(parents=True)
        metadata = dict(key=KEY.hex(), seed=args.seed, requested_traces=args.traces,
                        completed_traces=0, status='running', samples=args.samples,
                        chipwhisperer_version=cw.__version__, firmware_identity='534d3401',
                        adc_frequency_hz=float(scope.clock.adc_freq),
                        target_clock_hz=float(scope.clock.clkgen_freq), scope_settings=str(scope),
                        note='Normalized ADC readings, not watts. The window may cover only part of SM4.')
        rng = random.Random(args.seed)
        try:
            for index in range(args.traces):
                block = KEY if index == 0 else bytes(rng.randrange(256) for _ in range(16))
                scope.arm()
                device.target.simpleserial_write('p', bytearray(block))
                if scope.capture():
                    raise RuntimeError('Capture timed out.')
                result = device.read(16)
                if result != process(block, KEY)[0]:
                    raise RuntimeError('Baseline ciphertext verification failed.')
                wave = scope.get_last_trace()
                if wave is None or len(wave) != args.samples:
                    raise RuntimeError('Incomplete ADC buffer.')
                np.savez_compressed(folder / f'trace_{index:05d}.npz', wave=wave,
                                    plaintext=np.frombuffer(block, dtype=np.uint8),
                                    ciphertext=np.frombuffer(result, dtype=np.uint8),
                                    key=np.frombuffer(KEY, dtype=np.uint8))
                metadata['completed_traces'] += 1
                print(f'Capture {index+1}/{args.traces}: verified')
            metadata['status'] = 'complete'
        except BaseException as exc:
            metadata.update(status='failed', error=str(exc))
            raise
        finally:
            (folder / 'metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
            print(f'Results: {folder.resolve()}')
    finally:
        device.close()


if __name__ == '__main__':
    main()
