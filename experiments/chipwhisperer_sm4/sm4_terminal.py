"""Interactive STM32 SM4 encryption, decryption, round tracing, and software FI."""
import argparse
import json
from sm4_device import Device, KEY, execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial-number')
    parser.add_argument('--key', default=KEY.hex())
    parser.add_argument('--operation', choices=['encrypt', 'decrypt', 'fault'], default='encrypt')
    parser.add_argument('--format', choices=['text', 'hex'], default='hex')
    parser.add_argument('--value', help='Omit to open the interactive prompt.')
    parser.add_argument('--fault', nargs=4, type=lambda v: int(v, 0),
                        default=[31, 1, 0, 1], metavar=('ROUND', 'WORD', 'BYTE', 'MASK'))
    parser.add_argument('--block', type=int, default=1)
    parser.add_argument('--unpad', action='store_true')
    parser.add_argument('--no-trace', action='store_true')
    args = parser.parse_args()
    device = Device()
    try:
        device.connect(args.serial_number)
        request = dict(operation=args.operation, format=args.format, key=args.key,
                       fault=args.fault, block=args.block, unpad=args.unpad, trace=not args.no_trace)
        if args.value is not None:
            print(json.dumps(execute(device, dict(request, value=args.value)), indent=2))
            return
        print('SM4 target verified. Commands: text:<message>, hex:<blocks>, decrypt:<hex>,')
        print('decrypt-text:<hex>, fault:<hex>, /fault ROUND WORD BYTE MASK, /quit')
        while True:
            try:
                line = input('SM4> ')
                if line == '/quit':
                    break
                if line.startswith('/fault '):
                    from sm4_reference import validate_fault
                    fault = [int(v, 0) for v in line.split()[1:]]
                    validate_fault(fault)
                    request['fault'] = fault
                    print(f'Fault configured: {fault}')
                    continue
                prefix, separator, value = line.partition(':')
                if not separator:
                    prefix, value = 'text', line
                modes = {'text': ('encrypt', 'text'), 'hex': ('encrypt', 'hex'),
                         'decrypt': ('decrypt', 'hex'), 'decrypt-text': ('decrypt', 'hex'),
                         'fault': ('fault', 'hex')}
                if prefix not in modes:
                    raise ValueError('Unknown input prefix.')
                operation, fmt = modes[prefix]
                result = execute(device, dict(request, value=value, operation=operation,
                                              format=fmt, unpad=prefix == 'decrypt-text'))
                print(json.dumps(result, indent=2))
            except (ValueError, RuntimeError) as exc:
                print(f'Error: {exc}')
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        device.close()


if __name__ == '__main__':
    main()
