"""Real loopback HTTP checks for the route-isolated tunnel gateway."""
import http.client
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('muse_gateway', Path(__file__).resolve().parents[1] / 'scripts/muse_readonly_gateway.py')
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


@pytest.fixture
def service():
    received = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            received.append(dict(self.headers))
            self.send_response(401 if self.headers.get('Authorization') == 'Bearer bad' else 200)
            self.send_header('Set-Cookie', 'admin=must-not-forward')
            self.end_headers()
            self.wfile.write(json.dumps({'path': self.path}).encode())

    upstream = HTTPServer(('127.0.0.1', 0), Upstream)
    proxy = gateway.ReadOnlyGateway(port=0, upstream_port=upstream.server_port)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, proxy)]
    for thread in threads:
        thread.start()
    yield proxy, received
    for server in (proxy, upstream):
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(timeout=2)


def call(service, method='GET', path=gateway.PREFIX + 'overview', headers=None, body=None):
    client = http.client.HTTPConnection('127.0.0.1', service[0].server_port, timeout=3)
    try:
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        client.close()


@pytest.mark.parametrize('path', sorted(gateway.PATHS))
def test_fixed_read_routes_and_header_isolation(service, path):
    status, headers, body = call(service, path=path, headers={
        'Authorization': 'Bearer test-only', 'Cookie': 'admin=true',
        'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '203.0.113.1',
    })
    assert status == 200 and json.loads(body)['path'] == path
    assert headers['Cache-Control'] == 'no-store'
    assert 'Set-Cookie' not in headers
    forwarded = service[1][-1]
    assert not {'Cookie', 'X-Forwarded-Proto', 'X-Forwarded-For'} & set(forwarded)
    assert forwarded['Host'].startswith('127.0.0.1:')


@pytest.mark.parametrize('path', ['/', '/api/admin/login', '/api/admin/train',
    '/api/integrations/muse/v1/overview/extra', '/api/integrations/muse/v1/%6fverview',
    'http://example.test/api/integrations/muse/v1/overview', '//example.test/overview'])
def test_other_routes_never_reach_app(service, path):
    assert call(service, path=path, headers={'Authorization': 'Bearer test-only'})[0] == 404
    assert not service[1]


@pytest.mark.parametrize('method', ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT'])
def test_writes_never_reach_app(service, method):
    assert call(service, method=method, headers={'Authorization': 'Bearer test-only'})[0] == 405
    assert not service[1]


def test_auth_and_body_rejected(service):
    assert call(service)[0] == 401
    assert not service[1]
    assert call(service, headers={'Authorization': 'Bearer bad'})[0] == 401
    assert len(service[1]) == 1
    assert call(service, headers={'Authorization': 'Bearer test-only'}, body='no')[0] == 400
    assert len(service[1]) == 1


def test_concurrency_is_bounded(service):
    proxy = service[0]
    for _ in range(4):
        assert proxy.slots.acquire(False)
    try:
        assert call(service)[0] == 503
        assert not service[1]
    finally:
        for _ in range(4):
            proxy.slots.release()
