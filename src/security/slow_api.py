"""Slow API detector and dedicated logger.

Writes slow request entries to a separate slow_api.log file in JSON Lines format.
Does NOT block or rate-limit any requests — pure detection and logging only.
"""

import os
import json
import threading
import time
from datetime import datetime

from loguru import logger

DEFAULT_LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "logs"
)
DEFAULT_LOG_PATH = os.path.join(DEFAULT_LOG_DIR, "slow_api.log")


class SlowAPILogger:
    """Dedicated slow-API logger.

    Writes one JSON line per slow request to slow_api.log.
    Thread-safe. Fail-safe: exceptions are caught and logged via loguru.
    """

    def __init__(self, log_path: str = DEFAULT_LOG_PATH):
        self.log_path = log_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def log(self, trace_id: str, path: str, method: str,
            status_code: int, duration_ms: float, ip: str,
            user_agent: str):
        """Write a single slow-request entry."""
        try:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "trace_id": trace_id,
                "path": path,
                "method": method,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 2),
                "ip": ip,
                "user_agent": user_agent,
            }
            line = json.dumps(entry, ensure_ascii=False)
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception as e:
            logger.warning("Failed to write slow_api log: %s", e)


class SlowAPIDetector:
    """Slow API detector.

    Public interface used by SecurityMiddleware:

        detector = SlowAPIDetector(config)
        detector.start_timer()            # → float start
        detector.finish_timer(start)      # → float elapsed_ms
        detector.report_if_slow(...)      # write to log when over threshold
    """

    def __init__(self, config=None):
        self.config = config or {}
        self._enabled = self.config.get("enabled", True)
        self._threshold_ms = self.config.get("threshold_ms", 1000)

        log_path = self.config.get("log_path", DEFAULT_LOG_PATH)
        self._slow_logger = SlowAPILogger(log_path)

    # -- Timer helpers (used by Middleware) --

    def start_timer(self):
        return time.time()

    def finish_timer(self, started_at):
        if not started_at:
            return 0.0
        return (time.time() - started_at) * 1000.0

    # -- Reporting (called from Middleware.after_request) --

    def report_if_slow(self, trace_id: str, path: str, method: str,
                       status_code: int, duration_ms: float, ip: str,
                       user_agent: str):
        """Write to slow_api.log when duration exceeds threshold.

        No-op when:
        - self._enabled is False
        - duration_ms < threshold_ms
        """
        if not self._enabled:
            return
        if duration_ms < self._threshold_ms:
            return

        self._slow_logger.log(
            trace_id=trace_id,
            path=path,
            method=method,
            status_code=status_code,
            duration_ms=duration_ms,
            ip=ip,
            user_agent=user_agent,
        )
