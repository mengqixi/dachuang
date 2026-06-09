"""Security events read-only API helper.

Provides functions for reading and filtering security_events.log.
Does NOT modify the log file — read-only.
"""

import json
import os
from collections import deque

from loguru import logger


def read_events(log_path: str, limit: int = 50, event_type: str = None,
                risk_level: str = None, max_limit: int = 200) -> list:
    """Read recent events from a JSON Lines log file.

    Args:
        log_path: Path to the JSON Lines file.
        limit: Max events to return (default 50, clamped to max_limit).
        event_type: Optional filter by event_type.
        risk_level: Optional filter by risk_level.
        max_limit: Hard maximum for limit (default 200).

    Returns:
        List of event dicts, most recent first (last lines in file).
    """
    # Validate limit
    try:
        limit = int(limit)
    except (ValueError, TypeError):
        limit = 50
    if limit <= 0 or limit > max_limit:
        limit = 50

    if not os.path.exists(log_path):
        return []

    # Use deque(maxlen=limit) to keep only the last N events
    recent = deque(maxlen=limit)

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    # Skip malformed lines
                    continue

                # Apply filters
                if event_type and event.get("event_type") != event_type:
                    continue
                if risk_level and event.get("risk_level") != risk_level:
                    continue

                recent.append(event)
    except Exception as e:
        logger.warning("Failed to read security events log: %s", e)
        return []

    # Reverse to show newest first
    events = list(recent)
    events.reverse()
    return events
