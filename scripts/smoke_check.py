#!/usr/bin/env python3
"""Read-only smoke checks for the canonical user/admin Flask application."""

import argparse
import json
import sys
import urllib.error
import urllib.request


class SmokeClient:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

    def request(self, method, url, payload=None, timeout=8):
        body = None
        headers = {}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                return response.status, response.read().decode("utf-8", errors="replace"), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", errors="replace"), dict(error.headers)
        except Exception as error:
            return 0, str(error), {}


def parse_json(text):
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def page_check(client, name, url):
    status, text, _ = client.request("GET", url)
    ok = status == 200 and "密码攻击检测与隐私训练平台" in text
    return ok, f"{name}: GET {url} -> http={status}"


def api_check(client, name, url, method="GET", payload=None, expected_http=(200,), expected_api=(200,)):
    status, text, _ = client.request(method, url, payload=payload)
    api_code = parse_json(text).get("code")
    ok = status in expected_http and api_code in expected_api
    return ok, f"{name}: {method} {url} -> http={status}, api={api_code}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run non-mutating Flask smoke checks.")
    parser.add_argument("--user-base", default="http://127.0.0.1:5000")
    parser.add_argument("--admin-base", default="http://127.0.0.1:5001")
    parser.add_argument("--admin-user", default="")
    parser.add_argument("--admin-password", default="")
    parser.add_argument("--check-admin-login", action="store_true")
    args = parser.parse_args()

    user = args.user_base.rstrip("/")
    admin = args.admin_base.rstrip("/")
    client = SmokeClient()
    checks = [
        page_check(client, "user page", user + "/"),
        api_check(client, "system health", user + "/api/system/health"),
        api_check(client, "dataset status", user + "/api/dataset/unsw/status"),
        page_check(client, "admin page", admin + "/"),
        api_check(client, "admin session", admin + "/api/admin/session"),
    ]

    if args.check_admin_login:
        if not args.admin_user or not args.admin_password:
            checks.append((False, "admin login: credentials were not supplied"))
        else:
            checks.append(api_check(
                client,
                "admin login",
                admin + "/api/admin/login",
                method="POST",
                payload={"username": args.admin_user, "password": args.admin_password},
            ))
            checks.append(api_check(client, "authenticated session", admin + "/api/admin/session"))

    failures = 0
    for ok, message in checks:
        print(("[OK] " if ok else "[FAIL] ") + message)
        failures += 0 if ok else 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
