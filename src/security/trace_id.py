"""TraceId helper for request chain tracking.

Generates, validates and propagates trace IDs across the request lifecycle.
Format: trace-YYYYMMDD-8charhex  (e.g. trace-20260609-8f3a21ab)
"""

import re
import uuid
import time

try:
    from flask import g, request
except ImportError:
    g = None
    request = None


DEFAULT_TRACE_HEADER = "X-Trace-Id"
_TRACE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
_MAX_TRACE_ID_LENGTH = 128


def _generate_trace_id() -> str:
    """Generate a new trace ID in format: trace-YYYYMMDD-8charhex"""
    date_part = time.strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:8]
    return "trace-%s-%s" % (date_part, random_part)


def _validate_trace_id(trace_id: str) -> bool:
    """Validate trace_id format: only alphanumeric, dash, underscore, max 128 chars."""
    if not trace_id or len(trace_id) > _MAX_TRACE_ID_LENGTH:
        return False
    return bool(_TRACE_ID_PATTERN.match(trace_id))


def get_or_create_trace_id(header_name: str = DEFAULT_TRACE_HEADER) -> str:
    """Return the current request TraceId, creating/validating one when needed.

    Priority:
    1. flask.g.trace_id (already set in this request)
    2. Incoming X-Trace-Id header (validated)
    3. Auto-generated new trace_id

    Returns:
        str: A valid trace_id
    """
    if g is None or request is None:
        return _generate_trace_id()

    try:
        trace_id = getattr(g, "trace_id", None)
        if trace_id:
            return trace_id
    except RuntimeError:
        return _generate_trace_id()

    incoming = request.headers.get(header_name) if request else None

    if incoming and _validate_trace_id(incoming):
        trace_id = incoming
    else:
        trace_id = _generate_trace_id()

    try:
        g.trace_id = trace_id
    except RuntimeError:
        pass
    return trace_id
