"""Loopback-only, fixed-route gateway for a temporary Muse HTTPS tunnel.

No credentials are stored here. Only the client's bearer header is forwarded
to the existing application, which remains responsible for authorization.
Compatible with the deployment host's Python 3.6; no extra dependencies.
"""
import http.client
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit

PREFIX = '/api/integrations/muse/v1/'
PATHS = frozenset(PREFIX + name for name in (
    'overview', 'submissions', 'datasets', 'training', 'models', 'audit'))
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ReadOnlyGateway(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port=18561, upstream_port=5001):
        self.upstream_port = upstream_port
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(('127.0.0.1', port), GatewayHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(12)
        return connection, address

    def process_request(self, connection, address):
        if not self.slots.acquire(False):
            try:
                connection.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                connection.shutdown(socket.SHUT_WR)
                # Drain the initial request packet so an unread socket does
                # not reset the response on Windows. Bound the accept delay.
                connection.settimeout(.05)
                connection.recv(8192)
            except OSError:
                pass
            self.shutdown_request(connection)
            return
        try:
            super().process_request(connection, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, connection, address):
        try:
            super().process_request_thread(connection, address)
        finally:
            self.slots.release()

    def handle_error(self, connection, address):
        # Do not log client-controlled request details or credential values.
        pass


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = 'MuseReadOnlyGateway'
    sys_version = ''

    def log_message(self, *_args):
        pass

    def respond(self, status, body=b'', content_type='application/json', retry=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Connection', 'close')
        if retry:
            self.send_header('Retry-After', retry)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)
        self.close_connection = True

    def deny(self, status):
        self.respond(status, json.dumps({'code': status, 'msg': 'Read-only gateway request rejected'}).encode())

    def do_GET(self):
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self.deny(400)
            return
        # Reject absolute-form URLs, encoded paths, redirects and other routes.
        if len(self.path) > 2048 or parsed.scheme or parsed.netloc or parsed.fragment or parsed.path not in PATHS:
            self.deny(404)
            return
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
            self.deny(400)
            return
        authorization = self.headers.get_all('Authorization') or []
        if len(authorization) != 1 or not authorization[0].startswith('Bearer ') or len(authorization[0]) > 270:
            self.deny(401)
            return
        connection = http.client.HTTPConnection('127.0.0.1', self.server.upstream_port, timeout=10)
        try:
            # Never forward admin cookies, proxy headers, host or request bodies.
            connection.request(self.command, self.path, headers={
                'Authorization': authorization[0], 'Accept': 'application/json',
                'Connection': 'close',
            })
            upstream = connection.getresponse()
            body = upstream.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES or upstream.status not in (200, 400, 401, 403, 404, 405, 429, 503):
                self.deny(502)
                return
            self.respond(upstream.status, body, retry=upstream.getheader('Retry-After'))
        except (OSError, http.client.HTTPException, socket.timeout):
            self.deny(502)
        finally:
            connection.close()

    do_HEAD = do_GET

    def do_POST(self):
        self.deny(405)

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST
    do_TRACE = do_POST
    do_CONNECT = do_POST


if __name__ == '__main__':
    server = ReadOnlyGateway()
    print('Muse gateway listening on loopback only; six fixed read-only resources', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
