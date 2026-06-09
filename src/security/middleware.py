"""Non-blocking security middleware for Flask.

Default safe mode: create/propagate TraceId, collect timing metadata,
log request start/end to security log, but do NOT reject any requests.
"""

import os
import time

try:
    import yaml
except ImportError:
    yaml = None

try:
    from flask import g, jsonify, request
except ImportError:
    g = None
    jsonify = None
    request = None

from src.security.security_logger import SecurityEventLogger
from src.security.trace_id import DEFAULT_TRACE_HEADER, get_or_create_trace_id


class _AllowAllChecker:
    """Fallback for phase-2 security modules that may not be present yet."""

    def __init__(self, config=None):
        self.config = config or {}

    def check(self, _request):
        return True, None

    def verify(self, _request):
        return True, None


try:
    from src.security.anti_replay import AntiReplayChecker
except Exception:
    AntiReplayChecker = _AllowAllChecker

try:
    from src.security.api_switch import APISwitch
except Exception:
    APISwitch = _AllowAllChecker

try:
    from src.security.ip_filter import IPFilter
except Exception:
    IPFilter = _AllowAllChecker

try:
    from src.security.rate_limiter import RateLimiter
except Exception:
    RateLimiter = _AllowAllChecker

try:
    from src.security.sign_verify import SignVerifier
except Exception:
    SignVerifier = _AllowAllChecker

try:
    from src.security.slow_api import SlowAPIDetector
except Exception:
    SlowAPIDetector = _AllowAllChecker


class SecurityMiddleware:
    """Flask security extension point.

    Default config is safe mode: propagate TraceId, collect timing metadata,
    log request start/end events, but do NOT reject requests.

    Phase 2 operators (rate_limit, anti_replay, sign, ip_filter, api_switch)
    are imported and registered but remain disabled in safe mode.
    """

    def __init__(self, config_path=None):
        self.config_path = config_path or os.path.join("config", "security.yaml")
        self.config = self._load_config().get("security", {})
        self.trace_header = self.config.get("trace_id", {}).get(
            "header_name", DEFAULT_TRACE_HEADER
        )
        self._enabled = self.config.get("enabled", False)

        # Sub-components (placeholders for Phase 2)
        self.rate_limiter = RateLimiter(self.config.get("rate_limit", {}))
        self.anti_replay = AntiReplayChecker(self.config.get("anti_replay", {}))
        self.sign_verifier = SignVerifier(self.config.get("sign_verify", {}))
        self.ip_filter = IPFilter(self.config.get("ip_filter", {}))
        self.api_switch = APISwitch(self.config.get("api_switch", {}))
        self.slow_api = SlowAPIDetector(self.config.get("slow_api", {}))
        self.security_logger = SecurityEventLogger(
            self.config.get("security_logger", {})
        )

    def _load_config(self):
        if not os.path.exists(self.config_path) or yaml is None:
            return {"security": {"enabled": False, "trace_id": {"enabled": True}}}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                return loaded if loaded else {}
        except Exception:
            return {"security": {"enabled": False, "trace_id": {"enabled": True}}}

    def before_request(self):
        if g is None:
            return None

        # Start timer
        g.security_started_at = time.time()

        # Get or create trace_id (core functionality for this task)
        trace_id = get_or_create_trace_id(self.trace_header)
        g.trace_id = trace_id

        # Log request start
        try:
            self.security_logger.log_request_start(
                trace_id=trace_id,
                path=request.path if request else "",
                method=request.method if request else "",
                ip=request.remote_addr or request.headers.get("X-Forwarded-For", "unknown") if request else "unknown",
            )
        except Exception:
            pass

        # Blocking checks — all disabled in safe mode
        if not self._enabled:
            return None

        checks = [
            self.api_switch.check,
            self.ip_filter.check,
            self.anti_replay.check,
            self.sign_verifier.verify,
            self.rate_limiter.check,
        ]
        for check in checks:
            allowed, reason = check(request)
            if not allowed:
                self.security_logger.log_event({
                    "type": "blocked_request",
                    "reason": reason,
                    "trace_id": trace_id,
                })
                if jsonify is None:
                    return None
                return jsonify({"code": 403, "msg": reason or "request blocked", "data": {}}), 403
        return None

    def after_request(self, response):
        if g is None:
            return response

        trace_id = get_or_create_trace_id(self.trace_header)

        # Set response headers
        response.headers[self.trace_header] = trace_id

        elapsed_ms = 0.0
        started_at = getattr(g, "security_started_at", None)
        if started_at:
            elapsed_ms = (time.time() - started_at) * 1000.0

        response.headers["X-Response-Time-Ms"] = "%.2f" % elapsed_ms

        # Log request end
        try:
            self.security_logger.log_request_end(
                trace_id=trace_id,
                path=request.path if request else "",
                method=request.method if request else "",
                status_code=response.status_code,
                duration_ms=elapsed_ms,
            )
        except Exception:
            pass

        # Slow API detection (reserved for later)
        slow_config = self.config.get("slow_api", {})
        if slow_config.get("enabled", True) and elapsed_ms >= slow_config.get("threshold_ms", 1000):
            try:
                self.security_logger.log_security_event(
                    trace_id=trace_id,
                    event_type="slow_api",
                    message="Request exceeded threshold",
                    extra={"path": request.path if request else "", "elapsed_ms": round(elapsed_ms, 2)},
                )
            except Exception:
                pass

        return response

    def init_app(self, app):
        """Flask extension style: register hooks."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
