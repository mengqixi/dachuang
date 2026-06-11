# -*- coding: utf-8 -*-
"""Offline IP geolocation helpers.

The project intentionally avoids third-party IP lookup APIs.  If an optional
local database is available it can be used, otherwise public IPs are reported
as unknown while loopback/private addresses are classified locally.
"""

import csv
import ipaddress
import os
from functools import lru_cache


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DEFAULT_IPDB_DIR = os.path.join(PROJECT_ROOT, "data", "ipdb")
DEFAULT_XDB_PATH = os.path.join(DEFAULT_IPDB_DIR, "ip2region_v4.xdb")
LEGACY_XDB_PATH = os.path.join(DEFAULT_IPDB_DIR, "ip2region.xdb")
DEFAULT_CSV_PATH = os.path.join(DEFAULT_IPDB_DIR, "ip_geo.csv")


def _base_geo(country="unknown", region="unknown", city="unknown",
              isp="unknown", source="unknown", configured=False):
    return {
        "country": country,
        "region": region,
        "city": city,
        "isp": isp,
        "source": source,
        "configured": bool(configured),
    }


def lookup_ip_geo(ip, xdb_path=DEFAULT_XDB_PATH, csv_path=DEFAULT_CSV_PATH):
    """Return a normalized geo object for an IP address.

    Supported offline sources:
    - data/ipdb/ip_geo.csv with columns: start_ip,end_ip,country,region,city,isp
    - data/ipdb/ip2region_v4.xdb when py-ip2region is installed
    """
    ip = (ip or "").strip()
    try:
        parsed = ipaddress.ip_address(ip)
    except Exception:
        return _base_geo(source="invalid")

    if parsed.is_loopback:
        return _base_geo("local", "local", "localhost", "local", "local")
    if parsed.is_private:
        return _base_geo("private", "private", "private", "private", "private")

    csv_geo = _lookup_csv(parsed, csv_path)
    if csv_geo:
        return csv_geo

    xdb_geo = _lookup_ip2region(ip, xdb_path)
    if not xdb_geo and xdb_path != LEGACY_XDB_PATH:
        xdb_geo = _lookup_ip2region(ip, LEGACY_XDB_PATH)
    if xdb_geo:
        return xdb_geo

    configured = os.path.exists(csv_path) or os.path.exists(xdb_path) or os.path.exists(LEGACY_XDB_PATH)
    return _base_geo(source="unknown", configured=configured)


@lru_cache(maxsize=1)
def _load_csv_ranges(csv_path):
    ranges = []
    if not os.path.exists(csv_path):
        return ranges
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                start = row.get("start_ip") or row.get("start")
                end = row.get("end_ip") or row.get("end")
                if not start or not end:
                    continue
                try:
                    ranges.append((
                        int(ipaddress.ip_address(start.strip())),
                        int(ipaddress.ip_address(end.strip())),
                        _base_geo(
                            row.get("country") or "unknown",
                            row.get("region") or "unknown",
                            row.get("city") or "unknown",
                            row.get("isp") or "unknown",
                            "csv",
                            True,
                        ),
                    ))
                except Exception:
                    continue
    except Exception:
        return []
    ranges.sort(key=lambda item: item[0])
    return ranges


def _lookup_csv(parsed_ip, csv_path):
    ip_num = int(parsed_ip)
    for start, end, geo in _load_csv_ranges(csv_path):
        if start <= ip_num <= end:
            return dict(geo)
    return None


@lru_cache(maxsize=1)
def _load_ip2region_searcher(xdb_path):
    if not os.path.exists(xdb_path):
        return None
    try:
        from ip2region import searcher, util
        return searcher.new_with_file_only(util.IPv4, xdb_path)
    except Exception:
        pass
    try:
        from ip2region.xdbSearcher import XdbSearcher
        content = XdbSearcher.loadContentFromFile(xdb_path)
        return XdbSearcher(contentBuff=content)
    except Exception:
        return None


def _lookup_ip2region(ip, xdb_path):
    searcher = _load_ip2region_searcher(xdb_path)
    if searcher is None:
        return None
    try:
        if hasattr(searcher, "searchByIPStr"):
            region = searcher.searchByIPStr(ip)
        else:
            region = searcher.search(ip)
    except Exception:
        return None
    parts = (region or "").split("|")
    while len(parts) < 5:
        parts.append("unknown")

    # py-ip2region 3.x returns: country|region|city|isp|country_code.
    # Older bindings commonly return: country|area|province|city|isp.
    if len(parts[4]) in (2, 3):
        country, region, city, isp = parts[0], parts[1], parts[2], parts[3]
    else:
        country, _, region, city, isp = parts[:5]

    return _base_geo(
        _clean_region_value(country),
        _clean_region_value(region),
        _clean_region_value(city),
        _clean_region_value(isp),
        "ip2region",
        True,
    )


def _clean_region_value(value):
    value = (value or "").strip()
    return "unknown" if value in ("", "0") else value
