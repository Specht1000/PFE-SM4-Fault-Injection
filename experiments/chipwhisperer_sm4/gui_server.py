"""Local browser interface. Only this process owns the USB connection."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from sm4_device import Device, execute

HERE = Path(__file__).resolve().parent


def make_server(port=8766):
    device = Device()
    lock = threading.RLock()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, data, mime='application/json'):
            body = json.dumps(data).encode() if mime == 'application/json' else data
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/':
                self.reply(200, (HERE / 'gui/index.html').read_bytes(), 'text/html; charset=utf-8')
            elif self.path == '/app.js':
                self.reply(200, (HERE / 'gui/app.js').read_bytes(), 'text/javascript; charset=utf-8')
            elif self.path == '/api/status':
                with lock:
                    self.reply(200, {'connected': device.target is not None, 'key': device.key.hex()})
            else:
                self.reply(404, {'error': 'Not found'})

        def do_POST(self):
            # The local UI uses JSON. Reject cross-site browser requests.
            origin = self.headers.get('Origin')
            allowed = f'http://127.0.0.1:{self.server.server_port}'
            if origin and origin != allowed:
                self.reply(403, {'error': 'Origin rejected'})
                return
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                self.reply(415, {'error': 'JSON is required'})
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 32768:
                    raise ValueError('Invalid request size.')
                request = json.loads(self.rfile.read(size))
                if not isinstance(request, dict):
                    raise ValueError('Request must be a JSON object.')
                with lock:
                    if self.path == '/api/connect':
                        device.connect(request.get('serial'))
                        result = {'connected': True, 'key': device.key.hex(), 'verified': True}
                    elif self.path == '/api/disconnect':
                        device.close()
                        result = {'connected': False}
                    elif self.path == '/api/run':
                        result = execute(device, request)
                    elif self.path == '/api/key':
                        device.set_key(bytes.fromhex(request['key']))
                        result = {'key': device.key.hex()}
                    else:
                        self.reply(404, {'error': 'Not found'})
                        return
                self.reply(200, result)
            except (ValueError, KeyError, TypeError) as exc:
                self.reply(400, {'error': str(exc)})
            except Exception as exc:
                self.reply(503, {'error': str(exc)})

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.device = device
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8766)
    args = parser.parse_args()
    server = make_server(args.port)
    print(f'Open http://127.0.0.1:{server.server_port} in your browser. Ctrl+C stops the server.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.device.close()


if __name__ == '__main__':
    main()
