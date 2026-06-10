"""Read-only helpers for querying security_events.log."""

import json
import os
from collections import deque

from loguru import logger

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def normalize_limit(limit, default=DEFAULT_LIMIT, max_limit=MAX_LIMIT):
    """Normalize API limit values."""
    try:
        parsed = int(limit)
    except (ValueError, TypeError):
        return default
    if parsed <= 0:
        return default
    return min(parsed, max_limit)


def read_events(log_path, limit=DEFAULT_LIMIT, event_type=None, risk_level=None,
                max_limit=MAX_LIMIT):
    """Read recent events from a JSON Lines log file.

    Returns newest events first. This function is read-only and never raises for
    missing files, malformed lines, or read errors.
    """
    normalized_limit = normalize_limit(limit, max_limit=max_limit)

    if not os.path.exists(log_path):
        return []

    recent = deque(maxlen=normalized_limit)

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                if event_type and event.get("event_type") != event_type:
                    continue
                if risk_level and event.get("risk_level") != risk_level:
                    continue
                recent.append(_normalize_event(event))
    except Exception as e:
        logger.warning("Failed to read security events log: %s", e)
        return []

    events = list(recent)
    events.reverse()
    return events


def _normalize_event(event):
    """Ensure returned events have the standard public fields."""
    extra = event.get("extra")
    return {
        "timestamp": event.get("timestamp", ""),
        "trace_id": event.get("trace_id") or "unknown",
        "event_type": event.get("event_type") or event.get("type") or "unknown_event",
        "risk_level": event.get("risk_level") or "info",
        "path": event.get("path") or "",
        "method": event.get("method") or "",
        "ip": event.get("ip") or "unknown",
        "user_agent": event.get("user_agent") or "",
        "message": event.get("message") or event.get("reason") or "",
        "extra": extra if isinstance(extra, dict) else {},
    }
