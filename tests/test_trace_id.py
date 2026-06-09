"""
Tests for TraceId middleware — request chain tracking.

Run with:
    python -m pytest tests/test_trace_id.py -v
    python -m unittest tests.test_trace_id -v
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.security.trace_id import get_or_create_trace_id, _generate_trace_id, _validate_trace_id


@unittest.skipIf("FLASK_TEST" not in os.environ,
                 "Set FLASK_TEST=1 to run Flask-integration tests "
                 "(these start a live server on port 15555)")
class TestTraceIdFlask(unittest.TestCase):
    """Flask-integration tests that verify TraceId in request/response cycle."""

    @classmethod
    def setUpClass(cls):
        from app import app
        cls.app = app.test_client()

    def test_auto_generates_trace_id(self):
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Trace-Id", resp.headers)
        trace_id = resp.headers["X-Trace-Id"]
        self.assertTrue(trace_id.startswith("trace-"))
        self.assertGreater(len(trace_id), 15)

    def test_preserves_valid_incoming_trace_id(self):
        resp = self.app.get(
            "/api/system/health",
            headers={"X-Trace-Id": "trace-20260609-deadbeef"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Trace-Id"), "trace-20260609-deadbeef")

    def test_sanitizes_invalid_trace_id(self):
        resp = self.app.get(
            "/api/system/health",
            headers={"X-Trace-Id": "../../../etc/passwd"},
        )
        self.assertEqual(resp.status_code, 200)
        trace_id = resp.headers.get("X-Trace-Id")
        self.assertTrue(trace_id.startswith("trace-"))
        self.assertNotEqual(trace_id, "../../../etc/passwd")

    def test_root_page_has_trace_id(self):
        resp = self.app.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Trace-Id", resp.headers)

    def test_has_response_time_header(self):
        resp = self.app.get("/api/system/health")
        self.assertIn("X-Response-Time-Ms", resp.headers)
        val = resp.headers["X-Response-Time-Ms"]
        self.assertGreater(float(val), 0)

    def test_not_found_has_trace_id(self):
        resp = self.app.get("/api/nonexistent")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("X-Trace-Id", resp.headers)

    def test_security_log_exists(self):
        """Verify that request start/end events appear in security.log."""
        log_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "logs", "security.log",
        )
        if not os.path.exists(log_path):
            self.skipTest("security.log not found")
        # Make a request to trigger logging
        self.app.get("/api/system/health", headers={"X-Trace-Id": "trace-test-unit-log"})
        found = False
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                if "trace-test-unit-log" in line:
                    found = True
                    break
        self.assertTrue(found, "Expected trace-test-unit-log in security.log")


class TestTraceIdUnit(unittest.TestCase):
    """Unit tests for trace_id helper functions."""

    def test_generate_format(self):
        tid = _generate_trace_id()
        self.assertTrue(tid.startswith("trace-"))
        parts = tid.split("-")
        self.assertEqual(len(parts), 3)
        self.assertEqual(len(parts[2]), 8)  # random hex

    def test_validate_normal(self):
        self.assertTrue(_validate_trace_id("trace-20260609-abcdef12"))
        self.assertTrue(_validate_trace_id("hello-world"))
        self.assertTrue(_validate_trace_id("a" * 128))

    def test_validate_invalid(self):
        self.assertFalse(_validate_trace_id(""))
        self.assertFalse(_validate_trace_id("a" * 129))  # too long
        self.assertFalse(_validate_trace_id("../etc/passwd"))
        self.assertFalse(_validate_trace_id("hello world"))  # space

    def test_get_or_create_without_flask_returns_valid(self):
        """When flask.g is not available, returns a generated trace_id."""
        tid = get_or_create_trace_id("X-Trace-Id")
        self.assertTrue(tid.startswith("trace-"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
