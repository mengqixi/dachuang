# -*- coding: utf-8 -*-
"""Lightweight User-Agent parsing without external dependencies."""

import re


def parse_user_agent(user_agent):
    ua = user_agent or ""
    low = ua.lower()
    return {
        "device_type": _device_type(low),
        "device_model": _device_model(ua, low),
        "browser": _browser(ua, low)[0],
        "browser_version": _browser(ua, low)[1],
        "os": _os(ua, low)[0],
        "os_version": _os(ua, low)[1],
        "is_bot": _is_bot(low),
    }


def _match(pattern, text):
    m = re.search(pattern, text, re.I)
    return m.group(1).replace("_", ".") if m else "unknown"


def _is_bot(low):
    return any(token in low for token in (
        "bot", "spider", "crawler", "slurp", "bingpreview",
        "curl/", "python-requests", "wget/",
    ))


def _device_type(low):
    if _is_bot(low):
        return "bot"
    if "ipad" in low or "tablet" in low:
        return "tablet"
    if "mobile" in low or "iphone" in low or "android" in low:
        return "mobile"
    if low:
        return "desktop"
    return "unknown"


def _device_model(ua, low):
    if "iphone" in low:
        return "iPhone"
    if "ipad" in low:
        return "iPad"
    if "windows" in low:
        return "Windows PC"
    if "macintosh" in low or "mac os" in low:
        return "Mac"
    if "linux" in low and "android" not in low:
        return "Linux PC"

    if "android" in low:
        # Android UA examples often contain "(Linux; Android 13; Pixel 7 ...)"
        inside = _match(r"\(([^)]*android[^)]*)\)", ua)
        if inside != "unknown":
            parts = [p.strip() for p in inside.split(";") if p.strip()]
            candidates = []
            for part in parts:
                p_low = part.lower()
                if (
                    "android" in p_low or p_low in {"linux", "mobile"}
                    or p_low.startswith("wv") or "build/" in p_low
                    or "applewebkit" in p_low
                ):
                    continue
                candidates.append(part)
            if candidates:
                return _clean_model(candidates[-1])

        for pattern in (
            r"(Pixel\s+[A-Za-z0-9 ProXL]+)",
            r"(SM-[A-Za-z0-9]+)",
            r"(HUAWEI\s+[A-Za-z0-9\-]+)",
            r"(HONOR\s+[A-Za-z0-9\-]+)",
            r"(Redmi\s+[A-Za-z0-9 ]+)",
            r"(MI\s+[A-Za-z0-9 ]+)",
            r"(OPPO\s+[A-Za-z0-9]+)",
            r"(Vivo\s+[A-Za-z0-9]+)",
            r"(OnePlus\s+[A-Za-z0-9]+)",
        ):
            m = re.search(pattern, ua, re.I)
            if m:
                return _clean_model(m.group(1))
        return "Android"

    if _is_bot(low):
        if "curl/" in low:
            return "curl client"
        if "python-requests" in low:
            return "python-requests client"
        if "wget/" in low:
            return "wget client"
        return "bot"
    return "unknown"


def _clean_model(value):
    value = re.sub(r"\s+", " ", value or "").strip()
    value = re.sub(r"\s+Build/.*$", "", value, flags=re.I)
    return value[:80] if value else "unknown"


def _browser(ua, low):
    checks = (
        ("Edge", r"(?:Edg|Edge)/([0-9.]+)"),
        ("Firefox", r"Firefox/([0-9.]+)"),
        ("Chrome", r"Chrome/([0-9.]+)"),
        ("Safari", r"Version/([0-9.]+).*Safari/"),
        ("curl", r"curl/([0-9.]+)"),
        ("python-requests", r"python-requests/([0-9.]+)"),
        ("wget", r"Wget/([0-9.]+)"),
    )
    for name, pattern in checks:
        version = _match(pattern, ua)
        if version != "unknown":
            return name, version
    if "safari/" in low and "chrome/" not in low:
        return "Safari", "unknown"
    return "unknown", "unknown"


def _os(ua, low):
    if "windows nt 10.0" in low:
        return "Windows", "10/11"
    if "windows nt 6.3" in low:
        return "Windows", "8.1"
    if "windows nt 6.1" in low:
        return "Windows", "7"
    if "android" in low:
        return "Android", _match(r"Android\s+([0-9.]+)", ua)
    if "iphone" in low:
        return "iOS", _match(r"iPhone OS\s+([0-9_]+)", ua)
    if "ipad" in low:
        return "iOS", _match(r"CPU OS\s+([0-9_]+)", ua)
    if "mac os x" in low:
        return "macOS", _match(r"Mac OS X\s+([0-9_]+)", ua)
    if "linux" in low:
        return "Linux", "unknown"
    return "unknown", "unknown"
