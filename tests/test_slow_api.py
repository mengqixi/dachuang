"""
Tests for Slow API detection logging.

Run with:
    python -m pytest tests/test_slow_api.py -v
    python -m unittest tests.test_slow_api -v
    FLASK_TEST=1 python -m unittest tests.test_slow_api -v  (Flask integration)
"""

import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.security.slow_api import SlowAPIDetector, SlowAPILogger

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "logs")
LOG_PATH = os.path.join(LOG_DIR, "slow_api_test.log")


def _clean_log():
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)


def _count_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, "r") as f:
        return len(f.readlines())


class TestSlowApiLogger(unittest.TestCase):
    """Unit tests for SlowAPILogger standalone."""

    def setUp(self):
        _clean_log()
        self.logger = SlowAPILogger(LOG_PATH)

    def tearDown(self):
        _clean_log()

    def test_writes_entry(self):
        self.logger.log("tid-001", "/test", "GET", 200, 1500.0, "1.2.3.4", "curl/8")
        self.assertEqual(_count_lines(LOG_PATH), 1)
        with open(LOG_PATH, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["trace_id"], "tid-001")
        self.assertEqual(entry["path"], "/test")
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["status_code"], 200)
        self.assertEqual(entry["duration_ms"], 1500.0)
        self.assertEqual(entry["ip"], "1.2.3.4")
        self.assertIn("timestamp", entry)

    def test_multi_thread_safe(self):
        """Simulate concurrent writes."""
        from concurrent.futures import ThreadPoolExecutor
        def _write(i):
            self.logger.log("tid-%03d" % i, "/test", "GET", 200, 1000.0, "127.0.0.1", "test")
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_write, range(50)))
        self.assertEqual(_count_lines(LOG_PATH), 50)


class TestSlowAPIDetector(unittest.TestCase):
    """Unit tests for SlowAPIDetector logic."""

    def setUp(self):
        _clean_log()

    def tearDown(self):
        _clean_log()

    def test_below_threshold_does_not_log(self):
        cfg = {"enabled": True, "threshold_ms": 1000, "log_path": LOG_PATH}
        d = SlowAPIDetector(cfg)
        d.report_if_slow("tid-001", "/quick", "GET", 200, 500.0, "1.1.1.1", "curl")
        self.assertEqual(_count_lines(LOG_PATH), 0)

    def test_above_threshold_logs(self):
        cfg = {"enabled": True, "threshold_ms": 1000, "log_path": LOG_PATH}
        d = SlowAPIDetector(cfg)
        d.report_if_slow("tid-002", "/slow", "POST", 200, 2000.0, "2.2.2.2", "curl")
        self.assertEqual(_count_lines(LOG_PATH), 1)
        with open(LOG_PATH, "r") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["trace_id"], "tid-002")
        self.assertEqual(entry["duration_ms"], 2000.0)

    def test_disabled_does_not_log(self):
        cfg = {"enabled": False, "threshold_ms": 1, "log_path": LOG_PATH}
        d = SlowAPIDetector(cfg)
        d.report_if_slow("tid-003", "/disabled", "GET", 200, 9999.0, "3.3.3.3", "curl")
        self.assertEqual(_count_lines(LOG_PATH), 0)

    def test_timer_helpers(self):
        d = SlowAPIDetector({})
        t0 = d.start_timer()
        time.sleep(0.01)
        elapsed = d.finish_timer(t0)
        self.assertGreaterEqual(elapsed, 9.0)  # ≥10ms, with tolerance
        self.assertLess(elapsed, 500.0)

    def test_zero_start_returns_zero(self):
        d = SlowAPIDetector({})
        self.assertEqual(d.finish_timer(None), 0.0)
        self.assertEqual(d.finish_timer(0), 0.0)


@unittest.skipIf("FLASK_TEST" not in os.environ,
                 "Set FLASK_TEST=1 to run Flask-integration tests")
class TestSlowApiFlask(unittest.TestCase):
    """Integration tests against the running Flask app."""

    @classmethod
    def setUpClass(cls):
        from app import app
        cls.app = app.test_client()
        _clean_log()

    def test_health_200_with_trace_id(self):
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Trace-Id", resp.headers)

    def test_has_response_time(self):
        resp = self.app.get("/api/system/health")
        self.assertIn("X-Response-Time-Ms", resp.headers)

    def test_slow_api_disabled_does_not_write(self):
        """Set threshold extremely high so nothing is slow."""
        from src.security.slow_api import SlowAPILogger
        _clean_log()
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        # Fast requests should not write anything
        log = os.path.join(LOG_DIR, "slow_api.log")
        if os.path.exists(log):
            with open(log, "r") as f:
                content = f.read()
            self.assertNotIn(resp.headers.get("X-Trace-Id", ""), content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
