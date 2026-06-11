"""Non-blocking security middleware for Flask."""

import os
import time
from urllib.parse import unquote_plus

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
from src.security.ip_geo import lookup_ip_geo
from src.security.trace_id import DEFAULT_TRACE_HEADER, get_or_create_trace_id
from src.security.user_agent_parser import parse_user_agent


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
                ip=self._get_client_ip(request) if request else "unknown",
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

    def _log_site_visit(self, trace_id, duration_ms=0.0, status_code=None):
        if request is None:
            return
        if not self._should_log_site_visit(request):
            return

        user_agent = request.headers.get("User-Agent", "")
        ip = self._get_client_ip(request)
        ua_info = parse_user_agent(user_agent)
        risk = self._assess_visit_risk(request, user_agent)
        self.security_logger.log_security_event(
            trace_id=trace_id,
            event_type="site_visit",
            message=risk["message"],
            risk_level=risk["risk_level"],
            path=request.path,
            method=request.method,
            ip=ip,
            user_agent=user_agent,
            extra={
                "device_type": ua_info["device_type"],
                "device_model": ua_info["device_model"],
                "browser": ua_info["browser"],
                "browser_version": ua_info["browser_version"],
                "os": ua_info["os"],
                "os_version": ua_info["os_version"],
                "is_bot": ua_info["is_bot"],
                "forwarded_for": self._limit_text(request.headers.get("X-Forwarded-For", ""), 300),
                "real_ip": self._limit_text(request.headers.get("X-Real-IP", ""), 100),
                "ip_source": self._get_ip_source(request),
                "remote_addr": request.remote_addr or "unknown",
                "host": self._limit_text(request.host or "", 200),
                "scheme": request.scheme or "",
                "server_port": self._get_server_port(request),
                "client_port": self._get_client_port(request),
                "query_string": self._limit_text(
                    (request.query_string or b"").decode("utf-8", "ignore"), 500
                ),
                "referer": self._limit_text(request.headers.get("Referer", ""), 500),
                "accept_language": self._limit_text(request.headers.get("Accept-Language", ""), 200),
                "geo": lookup_ip_geo(ip),
                "full_path": self._limit_text(request.full_path.rstrip("?"), 500),
                "status_code": status_code,
                "duration_ms": round(duration_ms or 0.0, 2),
                "risk_reasons": risk["reasons"],
                "risk_reason_details": risk["reason_details"],
            },
        )

    def _should_log_site_visit(self, flask_request):
        """Log human page visits and suspicious page probes, not API/static noise."""
        if flask_request.method != "GET":
            return False

        path = flask_request.path or "/"
        if path.startswith("/api/") or path.startswith("/static/"):
            return False
        if path in ("/favicon.ico", "/robots.txt"):
            return False
        if path.lower().endswith((
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".map",
        )):
            return False
        return True

    def _assess_visit_risk(self, flask_request, user_agent):
        """Small offline heuristic for access-log risk labels.

        It is intentionally conservative: the request is only recorded, never
        blocked. This gives the dashboard medium/high risk examples without
        adding a scanner, WAF, or external threat-intelligence dependency.
        """
        path = (flask_request.path or "").lower()
        query = (flask_request.query_string or b"").decode("utf-8", "ignore").lower()
        ua = (user_agent or "").lower()
        target = unquote_plus("%s?%s" % (path, query))

        high_markers = (
            ".env", "wp-login", "wp-admin", "phpmyadmin", "/admin", "../",
            "..%2f", "/etc/passwd", "select%20", "union%20", " or 1=1",
            "or%201%3d1", "<script", "%3cscript",
        )
        medium_path_markers = (
            "login", "backup", ".git", "config", "debug", "console",
            "shell", "upload",
        )
        high_ua_markers = ("sqlmap", "nikto", "acunetix", "nessus", "masscan", "nmap")
        medium_ua_markers = ("curl/", "python-requests", "wget/", "httpclient")

        reasons = []
        reason_details = []
        risk_level = "info"

        for marker in high_markers:
            if marker in target:
                reasons.append("high_risk_path_or_query:%s" % marker)
                reason_details.append(self._describe_visit_risk_reason(
                    "high", "path_or_query", marker
                ))
                risk_level = "high"
                break

        if risk_level != "high":
            for marker in high_ua_markers:
                if marker in ua:
                    reasons.append("high_risk_user_agent:%s" % marker)
                    reason_details.append(self._describe_visit_risk_reason(
                        "high", "user_agent", marker
                    ))
                    risk_level = "high"
                    break

        if risk_level == "info":
            for marker in medium_path_markers:
                if marker in target:
                    reasons.append("medium_risk_path_or_query:%s" % marker)
                    reason_details.append(self._describe_visit_risk_reason(
                        "medium", "path_or_query", marker
                    ))
                    risk_level = "medium"
                    break

        if risk_level == "info":
            for marker in medium_ua_markers:
                if marker in ua:
                    reasons.append("medium_risk_user_agent:%s" % marker)
                    reason_details.append(self._describe_visit_risk_reason(
                        "medium", "user_agent", marker
                    ))
                    risk_level = "medium"
                    break

        messages = {
            "high": "高风险可疑访问记录",
            "medium": "中风险可疑访问记录",
            "info": "网站访问记录",
        }
        return {
            "risk_level": risk_level,
            "message": messages.get(risk_level, "网站访问记录"),
            "reasons": reasons,
            "reason_details": reason_details,
        }

    def _describe_visit_risk_reason(self, risk_level, reason_type, marker):
        if reason_type == "user_agent":
            if risk_level == "high":
                return "User-Agent 包含高风险扫描器特征：%s，常见于自动化漏洞扫描或探测工具。" % marker
            return "User-Agent 包含自动化客户端特征：%s，可能是脚本、命令行工具或接口探测请求。" % marker

        high_descriptions = {
            ".env": "访问了 .env 配置文件路径，可能在探测环境变量、密钥或数据库连接信息。",
            "wp-login": "访问了 WordPress 登录入口，当前系统不是 WordPress，通常属于批量弱口令或后台探测。",
            "wp-admin": "访问了 WordPress 管理后台路径，当前系统不是 WordPress，通常属于后台探测。",
            "phpmyadmin": "访问了 phpMyAdmin 管理路径，可能在探测数据库管理入口。",
            "/admin": "访问了常见管理后台路径，可能在尝试发现隐藏管理入口。",
            "../": "请求中包含目录穿越特征 ../，可能在尝试读取上级目录文件。",
            "..%2f": "请求中包含 URL 编码后的目录穿越特征 ..%2f，可能在尝试绕过路径过滤。",
            "/etc/passwd": "请求中包含 Linux 敏感文件 /etc/passwd，可能在尝试读取系统账户文件。",
            "select ": "请求参数中包含 SQL SELECT 片段，可能存在 SQL 注入探测。",
            "union ": "请求参数中包含 SQL UNION 片段，可能存在联合查询注入探测。",
            " or 1=1": "请求参数中包含 or 1=1，常见于 SQL 注入绕过条件探测。",
            "<script": "请求中包含 script 标签，可能存在 XSS 跨站脚本探测。",
        }
        medium_descriptions = {
            "login": "访问了登录相关路径，属于需要关注的入口探测行为。",
            "backup": "访问了备份相关路径，可能在探测备份文件或历史数据泄露。",
            ".git": "访问了 .git 相关路径，可能在探测源码仓库泄露。",
            "config": "访问了配置相关路径，可能在探测配置文件泄露。",
            "debug": "访问了调试相关路径，可能在探测调试接口是否暴露。",
            "console": "访问了控制台相关路径，可能在探测管理控制台入口。",
            "shell": "访问了 shell 相关路径，可能在探测 WebShell 或命令执行入口。",
            "upload": "访问了上传相关路径，可能在探测文件上传入口。",
        }

        if risk_level == "high":
            return high_descriptions.get(
                marker,
                "访问路径或参数包含高风险特征：%s，可能是敏感文件、后台入口或注入类探测。" % marker,
            )
        return medium_descriptions.get(
            marker,
            "访问路径或参数包含中风险特征：%s，建议关注是否为正常业务访问。" % marker,
        )

    def _get_client_ip(self, flask_request):
        forwarded_for = flask_request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            first_ip = forwarded_for.split(",")[0].strip()
            if first_ip:
                return first_ip
        real_ip = flask_request.headers.get("X-Real-IP", "").strip()
        if real_ip:
            return real_ip
        return flask_request.remote_addr or "unknown"

    def _get_ip_source(self, flask_request):
        if flask_request.headers.get("X-Forwarded-For", ""):
            return "x_forwarded_for"
        if flask_request.headers.get("X-Real-IP", ""):
            return "x_real_ip"
        return "remote_addr"

    def _detect_device_type(self, user_agent):
        ua = (user_agent or "").lower()
        if any(token in ua for token in ("bot", "spider", "crawler")):
            return "bot"
        if any(token in ua for token in ("mobile", "iphone", "android")):
            return "mobile"
        if any(token in ua for token in ("ipad", "tablet")):
            return "tablet"
        if user_agent:
            return "desktop"
        return "unknown"

    def _detect_browser(self, user_agent):
        ua = (user_agent or "").lower()
        if "edg/" in ua or "edge/" in ua:
            return "Edge"
        if "chrome/" in ua and "chromium" not in ua:
            return "Chrome"
        if "firefox/" in ua:
            return "Firefox"
        if "safari/" in ua and "chrome/" not in ua:
            return "Safari"
        if "curl/" in ua:
            return "curl"
        if "python-requests" in ua:
            return "python-requests"
        return "unknown"

    def _detect_os(self, user_agent):
        ua = (user_agent or "").lower()
        if "windows" in ua:
            return "Windows"
        if "android" in ua:
            return "Android"
        if "iphone" in ua or "ipad" in ua or "ios" in ua:
            return "iOS"
        if "mac os" in ua or "macintosh" in ua:
            return "macOS"
        if "linux" in ua:
            return "Linux"
        return "unknown"

    @staticmethod
    def _limit_text(value, max_length):
        value = "" if value is None else str(value)
        return value[:max_length]

    @staticmethod
    def _get_server_port(flask_request):
        port = flask_request.environ.get("SERVER_PORT")
        if port:
            return str(port)
        host = flask_request.host or ""
        if ":" in host:
            return host.rsplit(":", 1)[-1]
        return "443" if flask_request.scheme == "https" else "80"

    @staticmethod
    def _get_client_port(flask_request):
        return str(flask_request.environ.get("REMOTE_PORT") or "unknown")

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
            self._log_site_visit(trace_id, duration_ms=elapsed_ms, status_code=response.status_code)
        except Exception:
            pass

        try:
            self.slow_api.report_if_slow(
                trace_id=trace_id,
                path=request.path if request else "",
                method=request.method if request else "",
                status_code=response.status_code,
                duration_ms=elapsed_ms,
                ip=self._get_client_ip(request) if request else "unknown",
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
                    ip=self._get_client_ip(request) if request else "unknown",
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
