"""Local web GUI for interactive AES-128 encryption, decryption, and fault
injection on the STM32F303 target.

Run:
    python gui_server.py
Then open http://127.0.0.1:8765 in a browser (it opens automatically).

This process keeps a single persistent ChipWhisperer connection for the
lifetime of the server, so only one browser tab should drive it at a time.
It reuses the exact same protocol functions as aes_capture.py and
aes_terminal.py; no new hardware behavior is introduced here.
"""
import argparse
import json
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from aes_capture import KEY, set_key, verify  # noqa: E402
import aes_terminal as terminal  # noqa: E402

INDEX_HTML = HERE / 'gui' / 'index.html'


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class Session:
    """Owns the single hardware connection and the current AES key."""

    def __init__(self):
        self.lock = threading.RLock()
        self.scope = None
        self.target = None
        self.identity = None
        self.key = KEY

    @property
    def connected(self):
        return self.target is not None

    def status(self):
        return {
            'connected': self.connected,
            'identity': self.identity.decode('ascii', 'replace') if self.identity else None,
            'fault_capable': self.identity == b'AES\x03',
            'trace_capable': self.identity in (b'AES\x02', b'AES\x03'),
            'key': self.key.hex(),
        }

    def _require_connected(self):
        if self.target is None:
            raise ApiError('Not connected to the target. Click Connect first.')

    def connect(self, serial_number=None):
        with self.lock:
            if self.target is not None:
                return self.status()
            try:
                import chipwhisperer as cw
            except ImportError as exc:
                raise ApiError(f'Missing dependency: {exc}. Install requirements.txt in this venv.', 500) from exc
            scope = cw.scope(sn=serial_number or None)
            target = None
            try:
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
                identity = verify(target)
                if identity not in (b'AES\x01', b'AES\x02', b'AES\x03'):
                    raise ApiError('Unexpected firmware identity. Run the flash step first.', 500)
                set_key(target, self.key)
            except ApiError:
                if target is not None:
                    target.dis()
                scope.dis()
                raise
            except Exception as exc:
                if target is not None:
                    target.dis()
                scope.dis()
                raise ApiError(f'Could not connect: {exc}', 500) from exc
            self.scope, self.target, self.identity = scope, target, identity
            return self.status()

    def disconnect(self):
        with self.lock:
            try:
                if self.target is not None:
                    self.target.dis()
            finally:
                if self.scope is not None:
                    self.scope.dis()
                self.target = None
                self.scope = None
                self.identity = None
            return self.status()

    def set_key(self, key_hex):
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise ApiError('Key must be hexadecimal.') from exc
        if len(key) != 16:
            raise ApiError('Key must be exactly 32 hex digits (16 bytes).')
        with self.lock:
            if self.target is not None:
                set_key(self.target, key)
            self.key = key
            return self.status()

    def encrypt(self, value, fmt, trace):
        with self.lock:
            self._require_connected()
            if trace and self.identity not in (b'AES\x02', b'AES\x03'):
                raise ApiError('Recording states requires firmware revision 2 or 3.')
            try:
                raw, padded = terminal.prepare_input(value, fmt)
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            from Crypto.Cipher import AES
            reference = AES.new(self.key, AES.MODE_ECB)
            blocks = []
            try:
                for offset in range(0, len(padded), 16):
                    plaintext = padded[offset:offset + 16]
                    if trace:
                        ciphertext, snapshots = terminal.fetch_trace(self.target, plaintext)
                    else:
                        from aes_capture import encrypt as raw_encrypt
                        ciphertext, snapshots = raw_encrypt(self.target, plaintext), []
                    if ciphertext != reference.encrypt(plaintext):
                        raise ApiError('Target ciphertext failed independent AES verification.', 500)
                    from aes_capture import decrypt as raw_decrypt
                    recovered = raw_decrypt(self.target, ciphertext)
                    blocks.append({
                        'plaintext': plaintext.hex(),
                        'ciphertext': ciphertext.hex(),
                        'roundtrip_ok': recovered == plaintext,
                        'snapshots': [dump_snapshot(s) for s in snapshots],
                    })
            except (RuntimeError, OSError) as exc:
                raise ApiError(str(exc), 500) from exc
            ciphertext = bytes.fromhex(''.join(b['ciphertext'] for b in blocks))
            recovered_raw = bytes.fromhex(''.join(b['plaintext'] for b in blocks))
            recovered_text = None
            padding_ok = True
            if fmt == 'text':
                try:
                    recovered_text = terminal.unpad_pkcs7(recovered_raw).decode('utf-8')
                except (ValueError, UnicodeDecodeError):
                    padding_ok = False
            return {
                'raw': raw.hex(),
                'padded': padded.hex(),
                'padded_applied': padded != raw,
                'ciphertext': ciphertext.hex(),
                'blocks': blocks,
                'padding_ok': padding_ok,
                'recovered_text': recovered_text,
                'key': self.key.hex(),
            }

    def decrypt(self, value, unpad):
        with self.lock:
            self._require_connected()
            try:
                _, ciphertext = terminal.prepare_input(value, 'hex')
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            from Crypto.Cipher import AES
            from aes_capture import decrypt as raw_decrypt
            reference = AES.new(self.key, AES.MODE_ECB)
            blocks = []
            try:
                for offset in range(0, len(ciphertext), 16):
                    block = ciphertext[offset:offset + 16]
                    recovered = raw_decrypt(self.target, block)
                    if recovered != reference.decrypt(block):
                        raise ApiError('Target decryption failed independent AES verification.', 500)
                    blocks.append(recovered)
            except (RuntimeError, OSError) as exc:
                raise ApiError(str(exc), 500) from exc
            plaintext = b''.join(blocks)
            text = None
            padding_ok = True
            if unpad:
                try:
                    plaintext = terminal.unpad_pkcs7(plaintext)
                except ValueError:
                    padding_ok = False
            try:
                text = plaintext.decode('utf-8')
            except UnicodeDecodeError:
                text = None
            return {'plaintext': plaintext.hex(), 'text': text, 'padding_ok': padding_ok}

    def fault(self, value, fmt, fault_args):
        with self.lock:
            self._require_connected()
            if self.identity != b'AES\x03':
                raise ApiError('Fault injection requires firmware revision 3. Reflash the target.')
            try:
                fault = terminal.FaultSettings(**fault_args)
            except (ValueError, TypeError) as exc:
                raise ApiError(str(exc)) from exc
            try:
                raw, padded = terminal.prepare_input(value, fmt)
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            block_count = len(padded) // 16
            if fault.block > block_count:
                raise ApiError(f'Fault block {fault.block} exceeds the message length ({block_count} blocks).')
            from Crypto.Cipher import AES
            from aes_capture import decrypt as raw_decrypt
            reference = AES.new(self.key, AES.MODE_ECB)
            blocks = []
            fault_report = None
            try:
                for number in range(1, block_count + 1):
                    plaintext = padded[(number - 1) * 16:number * 16]
                    clean, clean_states = terminal.fetch_trace(self.target, plaintext)
                    if clean != reference.encrypt(plaintext) or raw_decrypt(self.target, clean) != plaintext:
                        raise ApiError('The fault-free baseline failed AES or decryption verification.', 500)
                    faulty = clean
                    faulty_states = []
                    if number == fault.block:
                        faulty, faulty_states, event = terminal.fetch_fault_trace(self.target, plaintext, fault)
                        if faulty == clean:
                            raise ApiError('The requested nonzero state fault did not change the ciphertext.', 500)
                        operation = fault.wire_bytes()[1]
                        injection_index = terminal.STEPS.index((fault.round, operation))
                        position = 4 * fault.column + fault.row
                        if event[0] != clean_states[injection_index - 1]['state'][position]:
                            raise ApiError('Fault event does not match the expected injection location.', 500)
                        fault_report = {
                            'injection_index': injection_index,
                            'byte_before': f'{event[0]:02x}',
                            'byte_after': f'{event[1]:02x}',
                            'bits_changed': bin(fault.mask).count('1'),
                            'rows': [dump_delta_row(a, b) for a, b in zip(clean_states, faulty_states)],
                        }
                    recovered = raw_decrypt(self.target, faulty)
                    if recovered != reference.decrypt(faulty):
                        raise ApiError('Target decryption failed verification for the faulty ciphertext.', 500)
                    blocks.append({
                        'clean': clean.hex(),
                        'faulty': faulty.hex(),
                        'recovered': recovered.hex(),
                        'is_fault_block': number == fault.block,
                    })
            except (RuntimeError, OSError) as exc:
                raise ApiError(str(exc), 500) from exc
            correct = bytes.fromhex(''.join(b['clean'] for b in blocks))
            faulty_all = bytes.fromhex(''.join(b['faulty'] for b in blocks))
            recovered_all = bytes.fromhex(''.join(b['recovered'] for b in blocks))
            return {
                'raw': raw.hex(),
                'padded': padded.hex(),
                'correct_ciphertext': correct.hex(),
                'faulty_ciphertext': faulty_all.hex(),
                'ciphertext_xor': bytes(a ^ b for a, b in zip(correct, faulty_all)).hex(),
                'recovered_faulty_plaintext': recovered_all.hex(),
                'blocks': blocks,
                'fault': dict(fault_args, wire=fault.wire_bytes().hex()),
                'report': fault_report,
                'key': self.key.hex(),
            }


def dump_snapshot(snapshot):
    return {
        'index': snapshot['index'],
        'round': snapshot['round'],
        'operation': snapshot['operation'],
        'state': snapshot['state'].hex(),
    }


def dump_delta_row(clean, faulty):
    delta = bytes(x ^ y for x, y in zip(clean['state'], faulty['state']))
    return {
        'round': clean['round'],
        'operation': clean['operation'],
        'clean_state': clean['state'].hex(),
        'faulty_state': faulty['state'].hex(),
        'delta': delta.hex(),
        'bytes_changed': sum(bool(x) for x in delta),
        'bits_changed': sum(bin(x).count('1') for x in delta),
    }


OPERATIONS_LIST = list(dict.fromkeys(terminal.OPERATIONS.values()))


class Handler(BaseHTTPRequestHandler):
    session: Session = None  # set by serve()
    server_version = 'PFE-AES-GUI/1.0'

    def log_message(self, fmt, *args):
        sys.stderr.write('[gui] ' + (fmt % args) + '\n')

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b'{}')
        except json.JSONDecodeError as exc:
            raise ApiError(f'Invalid JSON body: {exc}') from exc

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            body = INDEX_HTML.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/api/status':
            self._send_json(self.session.status())
        elif self.path == '/api/meta':
            self._send_json({'operations': OPERATIONS_LIST, 'steps': terminal.STEPS})
        else:
            self._send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        routes = {
            '/api/connect': lambda b: self.session.connect(b.get('serial_number') or None),
            '/api/disconnect': lambda b: self.session.disconnect(),
            '/api/key': lambda b: self.session.set_key(b['key']),
            '/api/encrypt': lambda b: self.session.encrypt(b['value'], b.get('format', 'text'), bool(b.get('trace', True))),
            '/api/decrypt': lambda b: self.session.decrypt(b['value'], bool(b.get('unpad', False))),
            '/api/fault': self._fault_route,
        }
        handler = routes.get(self.path)
        if handler is None:
            self._send_json({'error': 'Not found'}, 404)
            return
        try:
            body = self._read_json()
            result = handler(body)
            self._send_json(result)
        except ApiError as exc:
            self._send_json({'error': str(exc)}, exc.status)
        except KeyError as exc:
            self._send_json({'error': f'Missing field: {exc}'}, 400)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI instead of crashing the server
            self._send_json({'error': f'{type(exc).__name__}: {exc}'}, 500)

    def _fault_route(self, body):
        fault_args = dict(
            round=int(body['round']), stage=body['stage'], row=int(body['row']),
            column=int(body['column']), mask=int(body['mask'], 0) if isinstance(body['mask'], str) else int(body['mask']),
            block=int(body.get('block', 1)),
        )
        return self.session.fault(body['value'], body.get('format', 'text'), fault_args)


def serve(host='127.0.0.1', port=8765, serial_number=None, open_browser=True):
    Handler.session = Session()
    if serial_number:
        Handler.session.connect(serial_number)
    server = ThreadingHTTPServer((host, port), Handler)
    url = f'http://{host}:{port}/'
    print(f'PFE AES GUI: {url}')
    print('Press Ctrl+C to stop. Only one browser tab should drive the hardware at a time.')
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        Handler.session.disconnect()
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--serial-number', help='Connect to this device automatically on startup')
    parser.add_argument('--no-browser', action='store_true', help='Do not open a browser tab automatically')
    args = parser.parse_args()
    serve(args.host, args.port, args.serial_number, not args.no_browser)


if __name__ == '__main__':
    main()
