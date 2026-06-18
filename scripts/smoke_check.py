#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight smoke checks for the user/admin Flask endpoints.

This script intentionally uses only the Python standard library. It checks the
main pages and key JSON APIs without mutating business data by default.
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def _request(method, url, payload=None, timeout=8):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            return resp.status, text, dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, raw.decode("utf-8", errors="replace"), dict(e.headers)
    except Exception as e:
        return 0, str(e), {}


def _json(text):
    try:
        return json.loads(text)
    except Exception:
        return {}


def check_page(name, url, contains=None):
    status, text, _ = _request("GET", url)
    ok = status == 200 and (contains is None or contains in text)
    return ok, "%s GET %s -> %s" % (name, url, status)


def check_api(name, url, expected_codes=(200,), method="GET", payload=None):
    status, text, _ = _request(method, url, payload=payload)
    data = _json(text)
    api_code = data.get("code") if isinstance(data, dict) else None
    ok = status == 200 and api_code in expected_codes
    return ok, "%s %s %s -> http=%s api_code=%s" % (name, method, url, status, api_code)


def main():
    parser = argparse.ArgumentParser(description="Run lightweight smoke checks.")
    parser.add_argument("--user-base", default="http://127.0.0.1:5000")
    parser.add_argument("--admin-base", default="http://127.0.0.1:5001")
    parser.add_argument("--admin-user", default="")
    parser.add_argument("--admin-password", default="")
    parser.add_argument("--check-admin-login", action="store_true")
    args = parser.parse_args()

    user = args.user_base.rstrip("/")
    admin = args.admin_base.rstrip("/")

    checks = [
        check_page("user page", user + "/", "用户端"),
        check_api("system health", user + "/api/system/health"),
        check_api("dataset status", user + "/api/dataset/unsw/status"),
        check_page("admin page", admin + "/", "管理端"),
        check_api("admin session", admin + "/api/admin/session"),
    ]

    if args.check_admin_login:
        if not args.admin_user or not args.admin_password:
            checks.append((False, "admin login skipped: --admin-user and --admin-password are required"))
        else:
            checks.append(check_api(
                "admin login",
                admin + "/api/admin/login",
                method="POST",
                payload={"username": args.admin_user, "password": args.admin_password},
            ))

    failed = 0
    for ok, message in checks:
        print(("[OK] " if ok else "[FAIL] ") + message)
        failed += 0 if ok else 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
