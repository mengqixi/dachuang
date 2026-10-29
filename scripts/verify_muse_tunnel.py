"""Verify the HTTPS route and authorization without printing credentials/data."""
import json
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def verify():
    state = json.loads((ROOT / 'data/muse_tunnel/state.json').read_text())
    base = state['base_url']
    parts = urlsplit(base)
    assert parts.scheme == 'https' and parts.hostname.endswith('.trycloudflare.com')
    assert parts.path == '/api/integrations/muse/v1/' and not parts.query and not parts.fragment
    token = (ROOT / 'data/keys/muse_readonly.token').read_text().strip()
    opener = build_opener(NoRedirect())

    def call(url, credential=token, method='GET'):
        request = Request(url, method=method, headers={'Authorization': 'Bearer ' + credential})
        start = time.monotonic()
        try:
            with opener.open(request, timeout=15) as response:
                return response.status, response.read(2 * 1024 * 1024), round(time.monotonic() - start, 3)
        except HTTPError as error:
            return error.code, b'', round(time.monotonic() - start, 3)

    results = {}
    for resource in ('overview', 'submissions', 'datasets', 'training', 'models', 'audit'):
        status, body, elapsed = call(base + resource)
        assert status == 200, (resource, status)
        result = json.loads(body)
        assert result['meta']['read_only'] is True
        assert token.encode() not in body
        results[resource] = {'http': status, 'seconds': elapsed, 'warnings': len(result['meta']['warnings'])}
    origin = parts.scheme + '://' + parts.netloc
    checks = (
        ('wrong_token', base + 'overview', 'invalid', 'GET', 401),
        ('writes', base + 'overview', token, 'POST', 405),
        ('admin_hidden', origin + '/api/admin/submissions', token, 'GET', 404),
        ('page_hidden', origin + '/', token, 'GET', 404),
        ('invalid_query', base + 'overview?path=/etc/passwd', token, 'GET', 400),
        ('head', base + 'overview', token, 'HEAD', 200),
    )
    for name, url, credential, method, expected in checks:
        status, _, _ = call(url, credential, method)
        assert status == expected, (name, status, expected)
        results[name] = {'http': status}
    result = {'base_url': base, 'checks': results, 'verified_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    (ROOT / 'data/muse_tunnel/verification.json').write_text(json.dumps(result, sort_keys=True))
    print(json.dumps(result))


if __name__ == '__main__':
    verify()
