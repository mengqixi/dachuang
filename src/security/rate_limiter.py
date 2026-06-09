"""Rate limiter - minimal in-memory sliding-window implementation.

Default state: disabled. When enabled, it applies only to configured
include_paths, skips configured exclude_paths, and records trigger events in
JSON Lines format. It does not use Redis, Celery, or a database.
"""

import json
import os
import threading
import time
from collections import defaultdict
from datetime import datetime

from loguru import logger

DEFAULT_LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "logs"
)
DEFAULT_RATE_LIMIT_LOG_PATH = os.path.join(DEFAULT_LOG_DIR, "rate_limit.log")


class RateLimitLogger:
    """Fail-safe JSONL logger for rate-limit trigger events."""

    def __init__(self, log_path=DEFAULT_RATE_LIMIT_LOG_PATH):
        self.log_path = log_path or DEFAULT_RATE_LIMIT_LOG_PATH
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log(self, event):
        try:
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception as e:
            logger.warning("Failed to write rate_limit log: %s", e)


class RateLimiter:
    """Sliding-window in-memory rate limiter.

    Config keys:
        enabled: false
        default_limit_per_minute: 60
        window_seconds: 60
        include_paths: ["/api/"]
        exclude_paths: ["/", "/static/", "/favicon.ico"]
        log_path: data/logs/rate_limit.log
    """

    def __init__(self, config=None):
        config = config or {}
        self._enabled = config.get("enabled", False)
        self._limit = int(config.get("default_limit_per_minute", 60))
        self._window_sec = float(config.get("window_seconds", 60))
        self._include_paths = config.get("include_paths", [])
        self._exclude_paths = config.get(
            "exclude_paths", ["/", "/static/", "/favicon.ico"]
        )
        self._cleanup_interval = float(config.get("cleanup_interval", 300))
        self._logger = RateLimitLogger(
            config.get("log_path", DEFAULT_RATE_LIMIT_LOG_PATH)
        )

        self._buckets = defaultdict(list)
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup()

    def check(self, flask_request):
        """Return (allowed, info).

        `info` is None for allowed requests. When limited, it is a dict with
        fields needed by middleware response and logging.
        """
        if not self._enabled:
            return True, None

        path = getattr(flask_request, "path", "") if flask_request else ""
        if self._is_excluded(path) or not self._is_included(path):
            return True, None

        self._prune_if_needed()

        ip = self._get_client_ip(flask_request)
        key = "%s:%s" % (ip, path)
        now = time.time()
        cutoff = now - self._window_sec

        with self._lock:
            timestamps = self._buckets[key]
            timestamps[:] = [t for t in timestamps if t > cutoff]
            count = len(timestamps)

            if count >= self._limit:
                retry_after = int(timestamps[0] + self._window_sec - now) + 1
                return False, {
                    "reason": "rate_limit_exceeded",
                    "message": "请求过于频繁，请稍后再试",
                    "ip": ip,
                    "path": path,
                    "limit_per_minute": self._limit,
                    "window_seconds": int(self._window_sec),
                    "current_count": count + 1,
                    "retry_after": retry_after,
                }

            timestamps.append(now)
            return True, None

    def log_triggered(self, trace_id, flask_request, info):
        """Write a trigger record. Logging failures never affect the request."""
        info = info or {}
        event = {
            "timestamp": datetime.now().isoformat(),
            "trace_id": trace_id,
            "ip": info.get("ip") or self._get_client_ip(flask_request),
            "path": info.get("path") or (getattr(flask_request, "path", "") if flask_request else ""),
            "method": getattr(flask_request, "method", "") if flask_request else "",
            "limit_per_minute": info.get("limit_per_minute", self._limit),
            "window_seconds": info.get("window_seconds", int(self._window_sec)),
            "current_count": info.get("current_count", 0),
            "user_agent": flask_request.headers.get("User-Agent", "") if flask_request else "",
        }
        self._logger.log(event)

    def _cleanup(self):
        cutoff = time.time() - self._window_sec
        with self._lock:
            for key in list(self._buckets.keys()):
                self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]
                if not self._buckets[key]:
                    del self._buckets[key]

    def _prune_if_needed(self):
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup()
            self._last_cleanup = now

    def _is_excluded(self, path):
        return any(self._path_matches(path, pattern) for pattern in self._exclude_paths)

    def _is_included(self, path):
        if not self._include_paths:
            return True
        return any(self._path_matches(path, pattern) for pattern in self._include_paths)

    def _path_matches(self, path, pattern):
        if pattern == path:
            return True
        if pattern == "/":
            return False
        return pattern.endswith("/") and path.startswith(pattern)

    def _get_client_ip(self, flask_request):
        if not flask_request:
            return "unknown"
        forwarded_for = flask_request.headers.get("X-Forwarded-For", "")
        return forwarded_for.split(",")[0].strip() or flask_request.remote_addr or "unknown"
