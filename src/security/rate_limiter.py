"""Rate limiter — minimal sliding-window in-memory implementation.

Default state: DISABLED. When enabled, tracks request counts per IP within
a sliding time window and returns 429 when the limit is exceeded.

The middleware calls `check(request)` before each request.
The response retains X-Trace-Id even when rate-limited.
"""

import time
import threading
from collections import defaultdict


class RateLimiter:
    """Sliding-window in-memory rate limiter.

    Architecture:
        _buckets: dict[ip, list[float]] — timestamps of recent requests per IP
        _lock: threading.Lock — protecting bucket access

    Thread-safe. Uses a lightweight periodic cleanup to prevent memory leaks.

    Config (from security.yaml > rate_limit):
        enabled: false           # OFF by default
        default_limit_per_minute: 60
        cleanup_interval: 300    # purge stale entries every 300s
    """

    def __init__(self, config=None):
        config = config or {}
        self._enabled = config.get("enabled", False)
        self._limit = config.get("default_limit_per_minute", 60)
        self._window_sec = 60.0  # sliding window = 60 seconds
        self._cleanup_interval = config.get("cleanup_interval", 300)

        self._buckets = defaultdict(list)  # ip → [timestamp, ...]
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

        self._cleanup()

    def _cleanup(self):
        """Purge timestamps older than the window to avoid unbounded growth."""
        now = time.time()
        cutoff = now - self._window_sec
        with self._lock:
            for ip in list(self._buckets.keys()):
                self._buckets[ip] = [t for t in self._buckets[ip] if t > cutoff]
                if not self._buckets[ip]:
                    del self._buckets[ip]

    def _prune_if_needed(self):
        """Periodic full cleanup — run every `_cleanup_interval` seconds."""
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup()
            self._last_cleanup = now

    def check(self, flask_request):
        """Check whether the request should be allowed.

        Returns:
            (True, None) — allowed
            (False, reason_string) — rate-limited
        """
        if not self._enabled:
            return True, None

        self._prune_if_needed()

        # Determine client identity — prefer X-Forwarded-For
        ip = "unknown"
        if flask_request:
            ip = (flask_request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                  or flask_request.remote_addr
                  or "unknown")

        now = time.time()
        cutoff = now - self._window_sec

        with self._lock:
            # Prune old entries for this IP
            timestamps = self._buckets[ip]
            timestamps[:] = [t for t in timestamps if t > cutoff]

            count = len(timestamps)
            if count >= self._limit:
                retry_after = int(timestamps[0] + self._window_sec - now) + 1
                reason = "rate_limit_exceeded: %d req/min, retry after %ds" % (self._limit, retry_after)
                return False, reason

            # Record this request
            timestamps.append(now)
            return True, None
