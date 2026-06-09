"""
Tests for Rate Limiter sliding-window in-memory implementation.

Run with:
    python -m pytest tests/test_rate_limiter.py -v
    python -m unittest tests.test_rate_limiter -v
    FLASK_TEST=1 python -m unittest tests.test_rate_limiter -v
"""

import os
import sys
import time
import unittest
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.security.rate_limiter import RateLimiter

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "logs")
LOG_PATH = os.path.join(LOG_DIR, "rate_limit_test.log")


class MockRequest:
    """Minimal Flask request stand-in for test purposes."""
    def __init__(self, ip="127.0.0.1", path="/api/test", method="GET"):
        self.remote_addr = ip
        self.path = path
        self.method = method
        self.headers = {"User-Agent": "unittest"}


def _clean_log():
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)


class TestRateLimiterUnit(unittest.TestCase):
    """Unit tests for RateLimiter logic."""

    def tearDown(self):
        _clean_log()

    def test_disabled_by_default(self):
        rl = RateLimiter({"enabled": False})
        ok, reason = rl.check(MockRequest("1.2.3.4"))
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_allows_below_limit(self):
        rl = RateLimiter({"enabled": True, "default_limit_per_minute": 5})
        for _ in range(4):
            ok, reason = rl.check(MockRequest("10.0.0.1"))
            self.assertTrue(ok, "should allow within limit")

    def test_blocks_at_limit(self):
        rl = RateLimiter({"enabled": True, "default_limit_per_minute": 3})
        for _ in range(3):
            rl.check(MockRequest("10.0.0.2"))
        ok, reason = rl.check(MockRequest("10.0.0.2"))
        self.assertFalse(ok)
        self.assertEqual(reason["reason"], "rate_limit_exceeded")
        self.assertEqual(reason["path"], "/api/test")
        self.assertEqual(reason["limit_per_minute"], 3)

    def test_different_ips_independent(self):
        rl = RateLimiter({"enabled": True, "default_limit_per_minute": 2})
        rl.check(MockRequest("10.0.0.3"))
        rl.check(MockRequest("10.0.0.3"))
        # 10.0.0.3 hits limit
        ok, _ = rl.check(MockRequest("10.0.0.3"))
        self.assertFalse(ok)
        # 10.0.0.4 unaffected
        ok, _ = rl.check(MockRequest("10.0.0.4"))
        self.assertTrue(ok)

    def test_window_expires(self):
        rl = RateLimiter({"enabled": True, "default_limit_per_minute": 2})
        # Fill the window
        rl.check(MockRequest("10.0.0.5"))
        rl.check(MockRequest("10.0.0.5"))
        ok, _ = rl.check(MockRequest("10.0.0.5"))
        self.assertFalse(ok)
        # Manually age the timestamps
        cutoff = time.time() - 61
        with rl._lock:
            rl._buckets["10.0.0.5:/api/test"] = [cutoff]
        ok, _ = rl.check(MockRequest("10.0.0.5"))
        self.assertTrue(ok, "should allow after window expires")

    def test_returns_429_reason(self):
        rl = RateLimiter({"enabled": True, "default_limit_per_minute": 1})
        rl.check(MockRequest("10.0.0.6"))
        ok, reason = rl.check(MockRequest("10.0.0.6"))
        self.assertFalse(ok)
        self.assertEqual(reason["reason"], "rate_limit_exceeded")
        self.assertIn("retry_after", reason)

    def test_different_paths_independent(self):
        rl = RateLimiter({"enabled": True, "default_limit_per_minute": 1})
        rl.check(MockRequest("10.0.0.7", path="/api/a"))
        ok, _ = rl.check(MockRequest("10.0.0.7", path="/api/b"))
        self.assertTrue(ok)

    def test_include_and_exclude_paths(self):
        rl = RateLimiter({
            "enabled": True,
            "default_limit_per_minute": 1,
            "include_paths": ["/api/"],
            "exclude_paths": ["/", "/static/", "/favicon.ico"],
        })
        rl.check(MockRequest("10.0.0.8", path="/api/health"))
        ok, _ = rl.check(MockRequest("10.0.0.8", path="/api/health"))
        self.assertFalse(ok)

        for path in ["/", "/static/app.js", "/favicon.ico", "/assets/app.js"]:
            ok, _ = rl.check(MockRequest("10.0.0.8", path=path))
            self.assertTrue(ok)

    def test_rate_limit_log_jsonl(self):
        _clean_log()
        rl = RateLimiter({
            "enabled": True,
            "default_limit_per_minute": 1,
            "log_path": LOG_PATH,
        })
        rl.check(MockRequest("10.0.0.9", path="/api/log"))
        ok, info = rl.check(MockRequest("10.0.0.9", path="/api/log"))
        self.assertFalse(ok)
        rl.log_triggered("trace-rate-unit", MockRequest("10.0.0.9", path="/api/log"), info)

        with open(LOG_PATH, "r", encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["trace_id"], "trace-rate-unit")
        self.assertEqual(entry["path"], "/api/log")
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["limit_per_minute"], 1)
        self.assertEqual(entry["current_count"], 2)
        self.assertIn("timestamp", entry)


@unittest.skipIf("FLASK_TEST" not in os.environ,
                 "Set FLASK_TEST=1 to run Flask-integration tests")
class TestRateLimiterFlask(unittest.TestCase):
    """Integration tests against the running Flask app."""

    @classmethod
    def setUpClass(cls):
        from app import app
        cls.app = app.test_client()

    def _enable_rate_limit(self):
        """Dynamically enable rate limit with low threshold for testing."""
        from app import security_middleware
        if security_middleware:
            security_middleware.config.setdefault("rate_limit", {})["enabled"] = True
            security_middleware._enabled = True
            security_middleware.rate_limiter = RateLimiter({
                "enabled": True,
                "default_limit_per_minute": 3,
                "include_paths": ["/api/"],
                "exclude_paths": ["/", "/static/", "/favicon.ico"],
            })

    def _disable_rate_limit(self):
        from app import security_middleware
        if security_middleware:
            security_middleware.config.setdefault("rate_limit", {})["enabled"] = False
            security_middleware._enabled = False

    def test_health_still_200(self):
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)

    def test_trace_id_still_present(self):
        resp = self.app.get("/api/system/health")
        self.assertIn("X-Trace-Id", resp.headers)

    def test_rate_limit_returns_429_and_trace_id(self):
        self._enable_rate_limit()
        try:
            # Use up the 3-request allowance
            for _ in range(3):
                self.app.get("/api/test-ratelimit", headers={"X-Forwarded-For": "99.99.99.99"})
            resp = self.app.get("/api/test-ratelimit", headers={"X-Forwarded-For": "99.99.99.99"})
            self.assertEqual(resp.status_code, 429)
            self.assertIn("X-Trace-Id", resp.headers)
            self.assertIn("X-Response-Time-Ms", resp.headers)
            body = resp.get_json()
            self.assertEqual(body["code"], 429)
            self.assertEqual(body["msg"], "请求过于频繁，请稍后再试")
            self.assertEqual(body["data"]["risk_event"], "rate_limit_triggered")
            self.assertEqual(body["data"]["path"], "/api/test-ratelimit")
            self.assertIn("trace_id", body["data"])
        finally:
            self._disable_rate_limit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
