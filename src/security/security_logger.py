"""Security event logger with file-based trace_id logging.

Writes structured log entries to a dedicated security log file.
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


class SecurityEventLogger:
    """Security event logger.

    Writes events to data/logs/security.log in JSONL format.
    Each event is guaranteed to contain a trace_id field.

    Current: file-based logging.
    Future: SQLite persistence (reserved).
    """

    def __init__(self, config=None):
        self.config = config or {}
        self._lock = threading.Lock()
        os.makedirs(SECURITY_LOG_DIR, exist_ok=True)

    def _write_event(self, event: dict):
        """Write a single event as JSON line to security.log."""
        try:
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self._lock:
                with open(SECURITY_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception as e:
            logger.warning("Failed to write security event: %s", e)

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
        """Log a security-related event."""
        event = {
            "event": event_type,
            "trace_id": trace_id,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
        if extra:
            event["extra"] = extra
        self._write_event(event)

    def log_event(self, event):
        """Legacy: accept raw dict, ensure trace_id exists."""
        if "trace_id" not in event:
            event["trace_id"] = "unknown"
        if "timestamp" not in event:
            event["timestamp"] = datetime.now().isoformat()
        self._write_event(event)
