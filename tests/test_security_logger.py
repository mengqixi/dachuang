"""Tests for file-based request and security event logging."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.security.security_logger import SecurityEventLogger


class TestSecurityEventLogger(unittest.TestCase):
    """Unit tests for SecurityEventLogger."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="security-logger-test-")
        self.request_log = os.path.join(self.tmpdir, "security.log")
        self.events_log = os.path.join(self.tmpdir, "security_events.log")
        self.logger = SecurityEventLogger({
            "enabled": True,
            "request_log_path": self.request_log,
            "log_path": self.events_log,
            "max_events": 200,
            "max_extra_chars": 128,
        })

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _read_jsonl(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_log_request_start_writes_security_log(self):
        self.logger.log_request_start("tid-001", "/test", "GET", "1.2.3.4")
        rows = self._read_jsonl(self.request_log)
        self.assertEqual(rows[0]["event"], "request_start")
        self.assertEqual(rows[0]["trace_id"], "tid-001")
        self.assertFalse(os.path.exists(self.events_log))

    def test_log_request_end_writes_security_log(self):
        self.logger.log_request_end("tid-002", "/health", "GET", 200, 15.3)
        rows = self._read_jsonl(self.request_log)
        self.assertEqual(rows[0]["event"], "request_end")
        self.assertEqual(rows[0]["status_code"], 200)
        self.assertEqual(rows[0]["duration_ms"], 15.3)

    def test_log_security_event_required_fields(self):
        self.logger.log_security_event(
            trace_id="tid-003",
            event_type="rate_limit_triggered",
            risk_level="medium",
            path="/api/system/health",
            method="GET",
            ip="127.0.0.1",
            user_agent="unittest",
            message="too many requests",
            extra={"limit": 60, "count": 61},
        )
        rows = self._read_jsonl(self.events_log)
        entry = rows[0]
        for key in [
            "timestamp",
            "trace_id",
            "event_type",
            "risk_level",
            "path",
            "method",
            "ip",
            "user_agent",
            "message",
            "extra",
        ]:
            self.assertIn(key, entry)
        self.assertEqual(entry["event_type"], "rate_limit_triggered")
        self.assertEqual(entry["extra"]["limit"], 60)

    def test_security_events_disabled_does_not_write(self):
        disabled = SecurityEventLogger({
            "enabled": False,
            "request_log_path": self.request_log,
            "log_path": self.events_log,
        })
        disabled.log_security_event("tid-disabled", "blocked", "blocked")
        self.assertFalse(os.path.exists(self.events_log))
        self.assertEqual(disabled.get_recent_events(), [])

    def test_missing_trace_and_event_type_defaults(self):
        self.logger.log_security_event(message="missing fields")
        entry = self._read_jsonl(self.events_log)[0]
        self.assertEqual(entry["trace_id"], "unknown")
        self.assertEqual(entry["event_type"], "unknown_event")

    def test_non_json_extra_does_not_crash(self):
        self.logger.log_security_event(
            "tid-extra",
            "bad_extra",
            "has object",
            extra={"object": object()},
        )
        entry = self._read_jsonl(self.events_log)[0]
        self.assertIn("object", entry["extra"])

    def test_long_extra_is_truncated(self):
        self.logger.log_security_event(
            "tid-long",
            "long_extra",
            "long",
            extra={"payload": "x" * 1000},
        )
        entry = self._read_jsonl(self.events_log)[0]
        self.assertTrue(entry["extra"]["_truncated"])
        self.assertLessEqual(len(entry["extra"]["value"]), 128)

    def test_write_failure_does_not_raise(self):
        bad_path = os.path.join(self.tmpdir, "events_as_directory")
        os.makedirs(bad_path, exist_ok=True)
        logger = SecurityEventLogger({
            "enabled": True,
            "request_log_path": self.request_log,
            "log_path": bad_path,
        })
        logger.log_security_event("tid-fail", "write_fail", "should not raise")

    def test_recent_events_buffer_max_200(self):
        for i in range(300):
            self.logger.log_security_event("tid-%03d" % i, "test_event", "msg")
        recent = self.logger.get_recent_events(999)
        self.assertEqual(len(recent), 200)
        self.assertEqual(recent[-1]["trace_id"], "tid-299")

    def test_log_event_with_type_routes_to_security_events(self):
        self.logger.log_event({
            "type": "blocked_request",
            "trace_id": "tid-legacy",
            "reason": "blocked",
            "path": "/api/x",
        })
        rows = self._read_jsonl(self.events_log)
        self.assertEqual(rows[0]["event_type"], "blocked_request")
        self.assertEqual(rows[0]["trace_id"], "tid-legacy")

    def test_log_event_without_type_routes_to_security_log(self):
        self.logger.log_event({"event": "request_custom", "trace_id": "tid-log"})
        rows = self._read_jsonl(self.request_log)
        self.assertEqual(rows[0]["event"], "request_custom")
        self.assertFalse(os.path.exists(self.events_log))


@unittest.skipIf("FLASK_TEST" not in os.environ,
                 "Set FLASK_TEST=1 to run Flask-integration tests")
class TestSecurityEventLoggerFlask(unittest.TestCase):
    """Integration tests for middleware lifecycle logging."""

    @classmethod
    def setUpClass(cls):
        from app import app
        cls.app = app.test_client()

    def test_request_still_has_trace_and_timing_headers(self):
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Trace-Id", resp.headers)
        self.assertIn("X-Response-Time-Ms", resp.headers)

    def test_root_page_still_has_trace_id(self):
        resp = self.app.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Trace-Id", resp.headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
