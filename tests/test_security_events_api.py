"""
Tests for security events read-only query API.

Run with:
    python -m pytest tests/test_security_events_api.py -v
    python -m unittest tests.test_security_events_api -v
    FLASK_TEST=1 python -m unittest tests.test_security_events_api -v  # Flask integration
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.security.events_api import read_events


SAMPLE_EVENTS = [
    {"timestamp": "2026-06-10T12:00:01", "trace_id": "tid-001", "event_type": "rate_limit_triggered", "risk_level": "medium", "path": "/api/test", "method": "GET", "ip": "1.1.1.1", "user_agent": "curl", "message": "too fast", "extra": {"limit": 60}},
    {"timestamp": "2026-06-10T12:00:02", "trace_id": "tid-002", "event_type": "slow_api", "risk_level": "low", "path": "/api/slow", "method": "POST", "ip": "2.2.2.2", "user_agent": "wget", "message": "slow request", "extra": {"duration_ms": 2500}},
    {"timestamp": "2026-06-10T12:00:03", "trace_id": "tid-003", "event_type": "blocked_request", "risk_level": "high", "path": "/api/admin", "method": "DELETE", "ip": "3.3.3.3", "user_agent": "python", "message": "blocked", "extra": {}},
    {"timestamp": "2026-06-10T12:00:04", "trace_id": "tid-004", "event_type": "rate_limit_triggered", "risk_level": "medium", "path": "/api/test2", "method": "GET", "ip": "4.4.4.4", "user_agent": "curl", "message": "too fast again", "extra": {"limit": 30}},
]


class TestReadEvents(unittest.TestCase):
    """Unit tests for read_events function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="events-api-test-")
        self.log_path = os.path.join(self.tmpdir, "security_events.log")
        self._write_events(SAMPLE_EVENTS)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_events(self, events):
        with open(self.log_path, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    def _count_lines(self):
        with open(self.log_path, "r") as f:
            return len(f.readlines())

    # ── Existence / empty ──

    def test_file_not_exists_returns_empty(self):
        result = read_events("/tmp/nonexistent_file_xyz.log")
        self.assertEqual(result, [])

    def test_empty_file_returns_empty(self):
        open(self.log_path, "w").close()
        result = read_events(self.log_path)
        self.assertEqual(result, [])

    # ── Basic reading ──

    def test_reads_all_events(self):
        result = read_events(self.log_path, limit=10)
        self.assertEqual(len(result), 4)
        # Newest first
        self.assertEqual(result[0]["trace_id"], "tid-004")

    def test_reads_with_limit(self):
        result = read_events(self.log_path, limit=2)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["trace_id"], "tid-004")
        self.assertEqual(result[1]["trace_id"], "tid-003")

    def test_limit_exceeds_max_is_clamped(self):
        result = read_events(self.log_path, limit=999, max_limit=200)
        self.assertEqual(len(result), 4)  # only 4 events total

    def test_limit_zero_uses_default(self):
        result = read_events(self.log_path, limit=0)
        self.assertEqual(len(result), 4)

    def test_limit_negative_uses_default(self):
        result = read_events(self.log_path, limit=-5)
        self.assertEqual(len(result), 4)

    # ── Filtering ──

    def test_filter_by_event_type(self):
        result = read_events(self.log_path, event_type="slow_api")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["trace_id"], "tid-002")

    def test_filter_by_risk_level(self):
        result = read_events(self.log_path, risk_level="medium")
        self.assertEqual(len(result), 2)
        for ev in result:
            self.assertEqual(ev["risk_level"], "medium")

    def test_filter_combined(self):
        result = read_events(self.log_path, event_type="rate_limit_triggered", risk_level="medium")
        self.assertEqual(len(result), 2)

    def test_filter_no_match_returns_empty(self):
        result = read_events(self.log_path, event_type="nonexistent")
        self.assertEqual(result, [])

    # ── Malformed lines ──

    def test_skips_broken_json_lines(self):
        # Append a broken line
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write("{not json}\n")
            f.write('{"valid": true}\n')
        result = read_events(self.log_path, limit=10)
        # Should include the valid line but skip the broken one
        valid_ids = [ev.get("trace_id", "") for ev in result]
        self.assertIn("tid-004", valid_ids)

    def test_mixed_valid_and_invalid(self):
        lines = [
            '{"trace_id": "a", "event_type": "x", "risk_level": "low"}\n',
            "garbage\n",
            '{"trace_id": "b", "event_type": "y", "risk_level": "high"}\n',
        ]
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        result = read_events(self.log_path, limit=10)
        self.assertEqual(len(result), 2)

    # ── Large data ──

    def test_deque_maxlen_works(self):
        """Write 300 events, read with limit=10, should only get 10 newest."""
        many = []
        for i in range(300):
            many.append({"trace_id": "tid-%03d" % i, "event_type": "test", "risk_level": "low"})
        self._write_events(many)
        result = read_events(self.log_path, limit=10)
        self.assertEqual(len(result), 10)
        self.assertEqual(result[0]["trace_id"], "tid-299")

    def test_default_limit_is_50(self):
        many = [{"trace_id": "tid-%03d" % i, "event_type": "test", "risk_level": "low"} for i in range(100)]
        self._write_events(many)
        result = read_events(self.log_path)  # no limit arg
        self.assertEqual(len(result), 50)


class TestApiResponseFormat(unittest.TestCase):
    """Verify API return format via read_events utility."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="events-api-fmt-")
        self.log_path = os.path.join(self.tmpdir, "security_events.log")
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENTS[0]) + "\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_field_order(self):
        events = read_events(self.log_path)
        self.assertGreater(len(events), 0)
        ev = events[0]
        # All standard fields present
        for key in ["timestamp", "trace_id", "event_type", "risk_level", "path", "method", "ip", "user_agent", "message", "extra"]:
            self.assertIn(key, ev)


@unittest.skipIf("FLASK_TEST" not in os.environ,
                 "Set FLASK_TEST=1 to run Flask-integration tests")
class TestSecurityEventsApiFlask(unittest.TestCase):
    """Integration tests against the running Flask app."""

    @classmethod
    def setUpClass(cls):
        from app import app
        cls.app = app.test_client()

    def test_events_api_returns_200(self):
        resp = self.app.get("/api/security/events/recent")
        self.assertEqual(resp.status_code, 200)

    def test_events_api_format(self):
        resp = self.app.get("/api/security/events/recent")
        body = resp.get_json()
        self.assertIn("code", body)
        self.assertIn("data", body)
        self.assertIn("events", body["data"])
        self.assertIn("total", body["data"])
        self.assertIn("limit", body["data"])

    def test_events_api_has_trace_id_header(self):
        resp = self.app.get("/api/security/events/recent")
        self.assertIn("X-Trace-Id", resp.headers)

    def test_events_api_has_response_time_header(self):
        resp = self.app.get("/api/security/events/recent")
        self.assertIn("X-Response-Time-Ms", resp.headers)

    def test_health_still_200(self):
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)

    def test_root_still_200(self):
        resp = self.app.get("/")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
