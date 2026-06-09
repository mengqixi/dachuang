"""Security event logger with file-based trace_id logging.

Writes structured log entries to a dedicated security log file.
Supports two categories of logging:
1. Request lifecycle: log_request_start / log_request_end → security.log
2. Security events: log_security_event / log_event → security_events.log

SQLite persistence is reserved for a later task; this module focuses on
file-based logging with full trace_id support.
"""

import os
import json
import threading
from datetime import datetime

from loguru import logger

SECURITY_LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "logs"
)
SECURITY_LOG_PATH = os.path.join(SECURITY_LOG_DIR, "security.log")
SECURITY_EVENTS_LOG_PATH = os.path.join(SECURITY_LOG_DIR, "security_events.log")


class SecurityEventLogger:
    """Security event logger.

    Writes request lifecycle events to security.log and security events
    (rate_limit_triggered, slow_api, blocked_request, etc.) to
    security_events.log, both in JSONL format.

    Current: file-based logging.
    Future: SQLite persistence (reserved).
    """

    def __init__(self, config=None):
        self.config = config or {}
        self._lock = threading.Lock()
        self._events_lock = threading.Lock()
        self._events = []  # in-memory ring buffer for recent events
        self._max_events = 200
        os.makedirs(SECURITY_LOG_DIR, exist_ok=True)

        # If config has a log_path for events, use it; otherwise default
        events_path = None
        if self.config:
            events_path = self.config.get("events_log_path")
        self._events_log_path = events_path or SECURITY_EVENTS_LOG_PATH

    def _write_event(self, event: dict):
        """Write a single event as JSON line to security.log."""
        try:
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self._lock:
                with open(SECURITY_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception as e:
            logger.warning("Failed to write security event: %s", e)

    def _write_security_event(self, event: dict):
        """Write a single security event as JSON line to security_events.log."""
        try:
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self._events_lock:
                with open(self._events_log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                # Also keep in-memory
                self._events.append(event)
                if len(self._events) > self._max_events:
                    self._events.pop(0)
        except Exception as e:
            logger.warning("Failed to write security event log: %s", e)

    def log_request_start(self, trace_id: str, path: str, method: str, ip: str):
        """Log the start of a request."""
        event = {
            "event": "request_start",
            "trace_id": trace_id,
            "path": path,
            "method": method,
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
        }
        self._write_event(event)

    def log_request_end(self, trace_id: str, path: str, method: str,
                        status_code: int, duration_ms: float):
        """Log the completion of a request."""
        event = {
            "event": "request_end",
            "trace_id": trace_id,
            "path": path,
            "method": method,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
            "timestamp": datetime.now().isoformat(),
        }
        self._write_event(event)

    def log_security_event(self, trace_id: str, event_type: str,
                           message: str, extra: dict = None):
        """Log a security-related event to security_events.log.

        This is the unified entry point for all security events:
        - rate_limit_triggered
        - slow_api
        - blocked_request
        - anti_replay
        - sign_verify_failed
        - ip_blocked
        - api_disabled
        """
        event = {
            "event": event_type,
            "trace_id": trace_id,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
        if extra:
            event["extra"] = extra
        self._write_security_event(event)

    def log_event(self, event):
        """Legacy: accept raw dict, ensure trace_id exists.

        If event contains a 'type' key, it's treated as a security event
        and written to security_events.log. Otherwise written to security.log.
        """
        if "trace_id" not in event:
            event["trace_id"] = "unknown"
        if "timestamp" not in event:
            event["timestamp"] = datetime.now().isoformat()

        # Security events have a 'type'; lifecycle events have an 'event' key
        if "type" in event:
            self._write_security_event(event)
        else:
            self._write_event(event)

    def get_recent_events(self, limit: int = 50) -> list:
        """Return recent security events from the in-memory buffer."""
        return list(self._events[-limit:]) if self._events else []
