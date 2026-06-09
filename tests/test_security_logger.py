"""
Tests for Security Event Logger — both security.log and security_events.log.

Run with:
    python -m pytest tests/test_security_logger.py -v
    python -m unittest tests.test_security_logger -v
    FLASK_TEST=1 python -m unittest tests.test_security_logger -v  (Flask integration)
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.security.security_logger import SecurityEventLogger

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "logs")
SECURITY_LOG = os.path.join(LOG_DIR, "security.log")
EVENTS_LOG = os.path.join(LOG_DIR, "security_events.log")


def _clean_logs():
    for path in [SECURITY_LOG, EVENTS_LOG]:
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


class TestSecurityEventLogger(unittest.TestCase):
    """Unit tests for SecurityEventLogger."""

    def setUp(self):
        _clean_logs()
        self.logger = SecurityEventLogger({})

    def tearDown(self):
        _clean_logs()

    def test_log_request_start(self):
        self.logger.log_request_start("tid-001", "/test", "GET", "1.2.3.4")
        self.assertTrue(os.path.exists(SECURITY_LOG))
        with open(SECURITY_LOG, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["event"], "request_start")
        self.assertEqual(entry["trace_id"], "tid-001")

    def test_log_request_end(self):
        self.logger.log_request_end("tid-002", "/health", "GET", 200, 15.3)
        self.assertTrue(os.path.exists(SECURITY_LOG))
        with open(SECURITY_LOG, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["event"], "request_end")
        self.assertEqual(entry["status_code"], 200)
        self.assertEqual(entry["duration_ms"], 15.3)

    def test_log_security_event(self):
        self.logger.log_security_event(
            "tid-003", "rate_limit_triggered", "too many requests",
            extra={"limit": 60, "count": 61}
        )
        self.assertTrue(os.path.exists(EVENTS_LOG))
        with open(EVENTS_LOG, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["event"], "rate_limit_triggered")
        self.assertEqual(entry["message"], "too many requests")
        self.assertEqual(entry["extra"]["limit"], 60)

    def test_security_event_includes_all_required_fields(self):
        self.logger.log_security_event("tid-004", "slow_api", "threshold exceeded",
                                       extra={"duration_ms": 2500})
        with open(EVENTS_LOG, "r") as f:
            entry = json.loads(f.readline())
        self.assertIn("trace_id", entry)
        self.assertIn("event", entry)
        self.assertIn("message", entry)
        self.assertIn("timestamp", entry)
        self.assertIn("extra", entry)

    def test_log_event_legacy_with_type_goes_to_events_log(self):
        self.logger.log_event({
            "type": "blocked_request",
            "trace_id": "tid-005",
            "reason": "ip_blocked",
        })
        self.assertTrue(os.path.exists(EVENTS_LOG))
        with open(EVENTS_LOG, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["type"], "blocked_request")

    def test_log_event_legacy_without_type_goes_to_security_log(self):
        self.logger.log_event({
            "id": 1,
            "trace_id": "tid-006",
            "data": "some data",
        })
        self.assertTrue(os.path.exists(SECURITY_LOG))
        with open(SECURITY_LOG, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["data"], "some data")

    def test_recent_events_buffer(self):
        for i in range(10):
            self.logger.log_security_event("tid-%03d" % i, "test_event", "msg %d" % i)
        recent = self.logger.get_recent_events(5)
        self.assertEqual(len(recent), 5)

    def test_recent_events_buffer_max(self):
        for i in range(300):
            self.logger.log_security_event("tid-%03d" % i, "test_event", "msg %d" % i)
        recent = self.logger.get_recent_events(999)
        self.assertLessEqual(len(recent), 200)  # max 200 in buffer

    def test_missing_trace_id_filled(self):
        self.logger.log_event({"event": "test"})
        with open(SECURITY_LOG, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["trace_id"], "unknown")

    def test_start_and_end_go_to_different_files(self):
        """Request start/end should be in security.log, not events log."""
        self.logger.log_request_start("tid-010", "/a", "GET", "1.1.1.1")
        self.logger.log_security_event("tid-010", "blocked", "blocked")

        # security.log should have request_start
        with open(SECURITY_LOG, "r") as f:
            content = f.read()
        self.assertIn("request_start", content)

        # events log should have the security event
        with open(EVENTS_LOG, "r") as f:
            content = f.read()
        self.assertIn("blocked", content)


@unittest.skipIf("FLASK_TEST" not in os.environ,
                 "Set FLASK_TEST=1 to run Flask-integration tests")
class TestSecurityEventLoggerFlask(unittest.TestCase):
    """Integration tests — verify that middleware logs reach the files."""

    @classmethod
    def setUpClass(cls):
        from app import app
        cls.app = app.test_client()
        _clean_logs()

    def test_request_produces_start_and_end(self):
        _clean_logs()
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Trace-Id", resp.headers)
        trace_id = resp.headers["X-Trace-Id"]

        # Check security.log for this trace
        found_start = found_end = False
        if os.path.exists(SECURITY_LOG):
            with open(SECURITY_LOG, "r") as f:
                for line in f:
                    if trace_id in line:
                        if '"event": "request_start"' in line:
                            found_start = True
                        if '"event": "request_end"' in line:
                            found_end = True
        self.assertTrue(found_start, "request_start not found for trace " + trace_id)
        self.assertTrue(found_end, "request_end not found for trace " + trace_id)

    def test_root_page_has_trace_id(self):
        resp = self.app.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Trace-Id", resp.headers)
        self.assertIn("X-Response-Time-Ms", resp.headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
