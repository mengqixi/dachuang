# -*- coding: utf-8 -*-
"""Feature extraction for network/security datasets.

The project uses a fixed 18-dimensional feature vector.  This module accepts
UNSW-NB15 style CSV files, the project's generated CSV files, and simple
numeric CSV files with a label column.
"""

import csv
import os
import threading
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np


FEATURE_NAMES = [
    "key_generation_time",
    "ciphertext_entropy",
    "hash_collision_count",
    "request_frequency",
    "response_time",
    "payload_size",
    "connection_duration",
    "packet_interarrival",
    "failed_attempts",
    "session_duration",
    "request_size_variance",
    "encryption_rounds",
    "decryption_success_rate",
    "memory_usage",
    "cpu_usage",
    "network_latency",
    "protocol_violations",
    "anomaly_score",
]

# One fixed transform is shared by preparation, training and inference.  A
# per-file min/max transform makes the same row receive different values in a
# one-row upload, a 500-row upload and the training dataset.
FEATURE_NORMALIZATION_VERSION = "security-fixed-ranges-v1"
FEATURE_MIN_VALUES = np.array([
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
], dtype=np.float64)
FEATURE_MAX_VALUES = np.array([
    10.0, 8.0, 100.0, 1000.0, 5.0, 1_000_000.0, 3600.0,
    1.0, 100.0, 7200.0, 10_000.0, 10.0, 1.0, 1.0, 1.0,
    5.0, 10.0, 1.0,
], dtype=np.float64)


UNSW_FEATURE_ALIASES = {
    "key_generation_time": ["key_generation_time", "stime"],
    "ciphertext_entropy": ["ciphertext_entropy", "ct_ftp_cmd"],
    "hash_collision_count": ["hash_collision_count", "ct_srv_src"],
    "request_frequency": ["request_frequency", "request_rate", "rate", "flow_packets_s"],
    "response_time": ["response_time", "latency", "dur", "sload"],
    "payload_size": ["payload_size", "spkts", "sbytes"],
    "connection_duration": ["connection_duration", "dur"],
    "packet_interarrival": ["packet_interarrival", "sjit"],
    "failed_attempts": ["failed_attempts", "ct_dst_src_ltm"],
    "session_duration": ["session_duration", "rate"],
    "request_size_variance": ["request_size_variance", "sbytes"],
    "encryption_rounds": ["encryption_rounds", "ct_srv_dst"],
    "decryption_success_rate": ["decryption_success_rate"],
    "memory_usage": ["memory_usage"],
    "cpu_usage": ["cpu_usage"],
    "network_latency": ["network_latency", "trans_depth"],
    "protocol_violations": ["protocol_violations", "ct_state_ttl"],
    "anomaly_score": ["anomaly_score", "label"],
}

LABEL_COLUMNS = ["label", "is_attack", "attack", "target", "class"]
_INSPECT_CACHE = {}
_INSPECT_CACHE_LOCK = threading.Lock()


def _to_float(value, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _read_first(row: Dict, aliases: Iterable[str], default: float = 0.0) -> float:
    for key in aliases:
        if key in row and row.get(key) not in (None, ""):
            return _to_float(row.get(key), default)
    return default


def infer_label(row: Dict) -> int:
    """Return 1 for attack rows and 0 for normal rows."""
    for key in LABEL_COLUMNS:
        if key in row and row.get(key) not in (None, ""):
            value = str(row.get(key)).strip().lower()
            if value in {"0", "0.0", "normal", "benign", "false", "no"}:
                return 0
            if value in {"1", "1.0", "attack", "true", "yes"}:
                return 1
            return 0 if value == "normal" else 1

    attack_cat = str(row.get("attack_cat", "")).strip().lower()
    if attack_cat:
        return 0 if attack_cat in {"normal", "benign"} else 1

    return 0


def extract_features_structured(row: Dict) -> np.ndarray:
    """Extract the fixed 18-dimensional vector from a dictionary row."""
    vec = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    for i, feature in enumerate(FEATURE_NAMES):
        vec[i] = _read_first(row, UNSW_FEATURE_ALIASES.get(feature, [feature]))
    # API/upload schemas often express response latency in milliseconds while
    # the canonical model feature uses seconds.
    if row.get("response_time_ms") not in (None, ""):
        vec[FEATURE_NAMES.index("response_time")] = _to_float(row.get("response_time_ms")) / 1000.0
    return vec


def normalize_security_features(X: np.ndarray) -> np.ndarray:
    """Apply the canonical, batch-independent security feature transform."""
    X = np.asarray(X, dtype=np.float64)
    if X.size == 0:
        return X
    if X.shape[-1] != len(FEATURE_NAMES):
        raise ValueError("security feature matrix must have %d columns" % len(FEATURE_NAMES))
    return np.clip(
        (X - FEATURE_MIN_VALUES) / (FEATURE_MAX_VALUES - FEATURE_MIN_VALUES),
        0.0,
        1.0,
    )


def minmax_normalize(X: np.ndarray, fit_params: Optional[Dict] = None) -> np.ndarray:
    """Normalize a matrix into [0, 1]."""
    X = np.asarray(X, dtype=np.float64)
    if X.size == 0:
        return X
    if fit_params:
        mins, maxs = fit_params["mins"], fit_params["maxs"]
    else:
        mins, maxs = X.min(axis=0), X.max(axis=0)
    return np.clip((X - mins) / (maxs - mins + 1e-10), 0, 1)


def load_security_csv(filepath: str, limit: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray, List[Dict]]:
    """Load a CSV into features, labels, and raw records."""
    rows: List[Dict] = []
    X_rows: List[np.ndarray] = []
    y_vals: List[int] = []

    with open(filepath, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return np.empty((0, len(FEATURE_NAMES))), np.empty(0, dtype=np.int32), []
        for row in reader:
            vec = extract_features_structured(row)
            label = infer_label(row)
            rows.append(row)
            X_rows.append(vec)
            y_vals.append(label)
            # The caller uses ``limit`` as a processing ceiling.  Stop while
            # streaming instead of reading and feature-extracting the whole
            # file before truncating it; large CSV files otherwise make the
            # management "prepare nodes" action unnecessarily slow.
            if limit and len(X_rows) >= int(limit):
                break

    if not X_rows:
        return np.empty((0, len(FEATURE_NAMES))), np.empty(0, dtype=np.int32), []
    return np.asarray(X_rows, dtype=np.float64), np.asarray(y_vals, dtype=np.int32), rows


def load_unsw_nb15(filepath: str, limit: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray]:
    """Backward-compatible loader for UNSW-NB15 style CSV files."""
    X, y, _ = load_security_csv(filepath, limit=limit)
    return X, y


def inspect_csv(filepath: str) -> Dict:
    """Return cached CSV metadata without parsing every record.

    Security training CSV files use one record per physical line. Counting
    newline bytes in large chunks is dramatically faster than constructing a
    ``DictReader`` row for every record, while the header is still parsed with
    the CSV module for correct feature and label names.
    """
    absolute_path = os.path.normcase(os.path.abspath(filepath))
    stat = os.stat(filepath)
    fingerprint = (
        absolute_path,
        int(stat.st_size),
        int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1000000000))),
    )
    with _INSPECT_CACHE_LOCK:
        cached = _INSPECT_CACHE.get(fingerprint)
        if cached is not None:
            return dict(cached)

    info = {
        "path": filepath,
        "name": os.path.basename(filepath),
        "samples": 0,
        "features": 0,
        "label_column": None,
        "row_count_method": "physical_lines",
    }
    with open(filepath, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        info["features"] = len([c for c in fields if c not in set(LABEL_COLUMNS + ["attack_cat", "id"])])
        for col in LABEL_COLUMNS + ["attack_cat"]:
            if col in fields:
                info["label_column"] = col
                break

    newline_count = 0
    last_byte = b""
    with open(filepath, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            newline_count += chunk.count(b"\n")
            last_byte = chunk[-1:]
    record_count = newline_count + (1 if stat.st_size and last_byte != b"\n" else 0)
    info["samples"] = max(0, int(record_count) - 1)

    with _INSPECT_CACHE_LOCK:
        for old_key in list(_INSPECT_CACHE):
            if old_key[0] == absolute_path and old_key != fingerprint:
                _INSPECT_CACHE.pop(old_key, None)
        _INSPECT_CACHE[fingerprint] = dict(info)
    return dict(info)
