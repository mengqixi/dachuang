"""File-based request lifecycle and security event logging."""

import json
import os
import threading
from datetime import datetime

from loguru import logger

SECURITY_LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "logs"
)
SECURITY_LOG_PATH = os.path.join(SECURITY_LOG_DIR, "security.log")
SECURITY_EVENTS_LOG_PATH = os.path.join(SECURITY_LOG_DIR, "security_events.log")


class SecurityEventLogger:
    """Write request lifecycle logs and security event logs.

    `security.log` stores request_start/request_end.
    `security_events.log` stores normalized security events when enabled.
    """

    def __init__(self, config=None):
        self.config = config or {}
        self._lock = threading.Lock()
        self._events_lock = threading.Lock()
        self._events = []
        self._max_events = int(self.config.get("max_events", 200))
        self._max_extra_chars = int(self.config.get("max_extra_chars", 4096))
        self._events_enabled = self.config.get("enabled", True)
        self._request_log_path = self.config.get("request_log_path", SECURITY_LOG_PATH)
        self._events_log_path = (
            self.config.get("log_path")
            or self.config.get("events_log_path")
            or SECURITY_EVENTS_LOG_PATH
        )

        os.makedirs(os.path.dirname(self._request_log_path), exist_ok=True)
        os.makedirs(os.path.dirname(self._events_log_path), exist_ok=True)

    def _write_event(self, event):
        """Write request lifecycle events to security.log."""
        try:
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self._lock:
                with open(self._request_log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception as e:
            logger.warning("Failed to write security lifecycle log: %s", e)

    def _write_security_event(self, event):
        """Write normalized security events to security_events.log."""
        if not self._events_enabled:
            return
        try:
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self._events_lock:
                with open(self._events_log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                self._events.append(event)
                if len(self._events) > self._max_events:
                    self._events = self._events[-self._max_events:]
        except Exception as e:
            logger.warning("Failed to write security event log: %s", e)

    def log_request_start(self, trace_id, path, method, ip):
        event = {
            "event": "request_start",
            "trace_id": trace_id or "unknown",
            "path": path or "",
            "method": method or "",
            "ip": ip or "unknown",
            "timestamp": datetime.now().isoformat(),
        }
        self._write_event(event)

    def log_request_end(self, trace_id, path, method, status_code, duration_ms):
        event = {
            "event": "request_end",
            "trace_id": trace_id or "unknown",
            "path": path or "",
            "method": method or "",
            "status_code": status_code,
            "duration_ms": round(duration_ms or 0.0, 2),
            "timestamp": datetime.now().isoformat(),
        }
        self._write_event(event)

    def log_security_event(
        self,
        trace_id=None,
        event_type=None,
        message="",
        extra=None,
        risk_level="info",
        path="",
        method="",
        ip="unknown",
        user_agent="",
    ):
        """Normalize and write a security event."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "trace_id": trace_id or "unknown",
            "event_type": event_type or "unknown_event",
            "risk_level": risk_level or "info",
            "path": path or "",
            "method": method or "",
            "ip": ip or "unknown",
            "user_agent": user_agent or "",
            "message": message or "",
            "extra": self._safe_extra(extra),
        }
        self._write_security_event(event)

    def log_event(self, event):
        """Legacy dict logging.

        Dicts with `type` or `event_type` are security events. Other dicts are
        request lifecycle/general logs and continue to use security.log.
        """
        event = dict(event or {})
        if "trace_id" not in event:
            event["trace_id"] = "unknown"
        if "timestamp" not in event:
            event["timestamp"] = datetime.now().isoformat()

        if "type" in event or "event_type" in event:
            event_type = event.get("event_type") or event.get("type") or "unknown_event"
            extra = {
                key: value
                for key, value in event.items()
                if key not in {
                    "timestamp",
                    "trace_id",
                    "event_type",
                    "type",
                    "risk_level",
                    "path",
                    "method",
                    "ip",
                    "user_agent",
                    "message",
                    "extra",
                }
            }
            if event.get("extra"):
                extra["extra"] = event.get("extra")
            self.log_security_event(
                trace_id=event.get("trace_id"),
                event_type=event_type,
                risk_level=event.get("risk_level", "info"),
                path=event.get("path", ""),
                method=event.get("method", ""),
                ip=event.get("ip", "unknown"),
                user_agent=event.get("user_agent", ""),
                message=event.get("message") or event.get("reason", ""),
                extra=extra,
            )
        else:
            self._write_event(event)

    def get_recent_events(self, limit=50):
        """Return recent normalized security events without unbounded growth."""
        safe_limit = max(0, min(int(limit), self._max_events))
        with self._events_lock:
            return list(self._events[-safe_limit:])

    def _safe_extra(self, extra):
        if extra is None:
            extra = {}
        try:
            text = json.dumps(extra, ensure_ascii=False, default=str)
        except Exception:
            text = json.dumps(str(extra), ensure_ascii=False)

        if len(text) > self._max_extra_chars:
            return {
                "_truncated": True,
                "value": text[:self._max_extra_chars],
            }

        try:
            return json.loads(text)
        except Exception:
            return {"value": text}
