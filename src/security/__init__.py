"""Phase 2 security framework placeholders.

The modules in this package are intentionally non-blocking by default.
They provide import-stable extension points for TraceId, rate limiting,
anti-replay, signing, IP filtering, API switches, slow API logging, and
security event persistence.
"""

from src.security.middleware import SecurityMiddleware
from src.security.trace_id import get_or_create_trace_id

__all__ = ["SecurityMiddleware", "get_or_create_trace_id"]
