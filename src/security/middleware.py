"""Non-blocking security middleware for Flask."""

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
    """Flask security extension point."""

    def __init__(self, config_path=None):
        self.config_path = config_path or os.path.join("config", "security.yaml")
        self.config = self._load_config().get("security", {})
        self.trace_header = self.config.get("trace_id", {}).get(
            "header_name", DEFAULT_TRACE_HEADER
        )
        self._enabled = self.config.get("enabled", False)

        self.rate_limiter = RateLimiter(self.config.get("rate_limit", {}))
        self.anti_replay = AntiReplayChecker(self.config.get("anti_replay", {}))
        self.sign_verifier = SignVerifier(self.config.get("sign_verify", {}))
        self.ip_filter = IPFilter(self.config.get("ip_filter", {}))
        self.api_switch = APISwitch(self.config.get("api_switch", {}))
        self.slow_api = SlowAPIDetector(self.config.get("slow_api", {}))
        self.security_logger = SecurityEventLogger(
            self.config.get("security_events", self.config.get("security_logger", {}))
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

        g.security_started_at = time.time()

        trace_id = get_or_create_trace_id(self.trace_header)
        g.trace_id = trace_id

        try:
            self.security_logger.log_request_start(
                trace_id=trace_id,
                path=request.path if request else "",
                method=request.method if request else "",
                ip=request.remote_addr or request.headers.get("X-Forwarded-For", "unknown") if request else "unknown",
            )
        except Exception:
            pass

        if self.config.get("rate_limit", {}).get("enabled", False):
            allowed, reason = self.rate_limiter.check(request)
            if not allowed:
                return self._build_rate_limit_response(trace_id, reason)

        if not self._enabled:
            return None

        checks = [
            self.api_switch.check,
            self.ip_filter.check,
            self.anti_replay.check,
            self.sign_verifier.verify,
        ]
        for check in checks:
            allowed, reason = check(request)
            if not allowed:
                try:
                    self.security_logger.log_event({
                        "type": "blocked_request",
                        "reason": reason,
                        "trace_id": trace_id,
                        "path": request.path if request else "",
                        "method": request.method if request else "",
                    })
                except Exception:
                    pass
                if jsonify is None:
                    return None
                return jsonify({
                    "code": 403,
                    "msg": reason or "request blocked",
                    "data": {},
                }), 403
        return None

    def _build_rate_limit_response(self, trace_id, reason):
        if jsonify is None:
            return None
        reason = reason or {}
        try:
            self.rate_limiter.log_triggered(trace_id, request, reason)
        except Exception:
            pass
        try:
            self.security_logger.log_security_event(
                trace_id=trace_id,
                event_type="rate_limit_triggered",
                message="请求过于频繁，请稍后再试",
                risk_level="medium",
                path=reason.get("path", request.path if request else ""),
                method=request.method if request else "",
                ip=reason.get("ip", request.remote_addr if request else "unknown"),
                user_agent=request.headers.get("User-Agent", "") if request else "",
                extra={
                    "limit_per_minute": reason.get("limit_per_minute", 60),
                    "window_seconds": reason.get("window_seconds", 60),
                    "current_count": reason.get("current_count", 0),
                },
            )
        except Exception:
            pass
        return jsonify({
            "code": 429,
            "msg": "请求过于频繁，请稍后再试",
            "data": {
                "risk_event": "rate_limit_triggered",
                "trace_id": trace_id,
                "path": reason.get("path", request.path if request else ""),
                "limit_per_minute": reason.get("limit_per_minute", 60),
            },
        }), 429

    def after_request(self, response):
        if g is None:
            return response

        trace_id = get_or_create_trace_id(self.trace_header)
        response.headers[self.trace_header] = trace_id

        elapsed_ms = 0.0
        started_at = getattr(g, "security_started_at", None)
        if started_at:
            elapsed_ms = (time.time() - started_at) * 1000.0
        response.headers["X-Response-Time-Ms"] = "%.2f" % elapsed_ms

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

        try:
            self.slow_api.report_if_slow(
                trace_id=trace_id,
                path=request.path if request else "",
                method=request.method if request else "",
                status_code=response.status_code,
                duration_ms=elapsed_ms,
                ip=request.remote_addr or request.headers.get("X-Forwarded-For", "unknown") if request else "unknown",
                user_agent=request.headers.get("User-Agent", "") if request else "",
            )
            if self.slow_api.was_slow(elapsed_ms):
                self.security_logger.log_security_event(
                    trace_id=trace_id,
                    event_type="slow_api_detected",
                    message="Request exceeded slow API threshold",
                    risk_level="low",
                    path=request.path if request else "",
                    method=request.method if request else "",
                    ip=request.remote_addr or request.headers.get("X-Forwarded-For", "unknown") if request else "unknown",
                    user_agent=request.headers.get("User-Agent", "") if request else "",
                    extra={
                        "status_code": response.status_code,
                        "duration_ms": round(elapsed_ms, 2),
                        "threshold_ms": getattr(self.slow_api, "_threshold_ms", 1000),
                    },
                )
        except Exception:
            pass

        return response

    def init_app(self, app):
        """Flask extension style: register hooks."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
