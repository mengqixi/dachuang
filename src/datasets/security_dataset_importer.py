"""Lightweight security dataset importer.

This module converts local/generated CSV files and public security datasets into
one account-security training schema. It intentionally uses only the Python
standard library and streams CSV rows so it can run on a small Flask server.
"""

import csv
import glob
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple


UNIFIED_FIELDS = [
    "sample_id",
    "source_dataset",
    "attack_type",
    "label",
    "src_ip",
    "dst_ip",
    "protocol",
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_bytes_s",
    "flow_packets_s",
    "request_frequency",
    "response_time",
    "failed_attempts",
    "unusual_hour",
    "payload_size",
    "device_type",
    "browser",
    "os",
    "username_masked",
]

TEXT_DEFAULT = "-"
NUMBER_DEFAULT = "0"

NUMERIC_FIELDS = {
    "label",
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_bytes_s",
    "flow_packets_s",
    "request_frequency",
    "response_time",
    "failed_attempts",
    "unusual_hour",
    "payload_size",
}

BRUTE_FORCE_KEYWORDS = (
    "brute force",
    "bruteforce",
    "ftp-patator",
    "ssh-patator",
    "ssh-bruteforce",
    "ftp-bruteforce",
    "web attack-brute force",
    "password",
)

ANOMALY_KEYWORDS = (
    "ddos",
    "dos",
    "portscan",
    "bot",
    "botnet",
    "infiltration",
    "exploit",
    "scan",
    "attack",
)

FIELD_ALIASES = {
    "src_ip": ["src_ip", "source_ip", "srcip", "src ip", "source ip", "source"],
    "dst_ip": ["dst_ip", "destination_ip", "dstip", "dst ip", "destination ip", "destination"],
    "protocol": ["protocol", "proto"],
    "flow_duration": ["flow_duration", "flow duration", "dur", "duration"],
    "total_fwd_packets": ["total_fwd_packets", "tot fwd pkts", "total fwd packets"],
    "total_bwd_packets": ["total_bwd_packets", "tot bwd pkts", "total backward packets", "total bwd packets"],
    "flow_bytes_s": ["flow_bytes_s", "flow bytes/s", "flow byts/s", "bytes_per_second"],
    "flow_packets_s": ["flow_packets_s", "flow packets/s", "flow pkts/s", "packets_per_second", "rate"],
    "request_frequency": ["request_frequency", "request_rate", "rate", "flow packets/s", "flow pkts/s"],
    "response_time": ["response_time", "response_time_ms", "latency", "average packet size"],
    "failed_attempts": ["failed_attempts", "ct_dst_src_ltm", "login_failed", "failed_login_count"],
    "unusual_hour": ["unusual_hour", "is_unusual_hour"],
    "payload_size": ["payload_size", "packet length mean", "avg pkt size", "packet_length"],
    "device_type": ["device_type", "device"],
    "browser": ["browser", "user_browser"],
    "os": ["os", "operating_system"],
    "username_masked": ["username_masked", "username", "user", "account"],
}

LABEL_ALIASES = ["label", "Label", "attack_cat", "attack type", "attack_type", "is_attack", "class"]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _normalize_key(value: str) -> str:
    return str(value or "").strip().lower().replace("_", " ")


def _clean_number(value, default: str = NUMBER_DEFAULT) -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    try:
        float(text)
        return text
    except Exception:
        return default


def _mask_username(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return TEXT_DEFAULT
    if len(text) <= 2:
        return text[0] + "*"
    return text[:2] + "***" + text[-1:]


def _get(row: Dict[str, str], aliases: Iterable[str], default: str = "") -> str:
    normalized = {_normalize_key(k): v for k, v in row.items()}
    for alias in aliases:
        key = _normalize_key(alias)
        if key in normalized and str(normalized[key]).strip() != "":
            return normalized[key]
    return default


def map_attack_type(raw_value: str) -> Tuple[str, int]:
    text = str(raw_value or "").strip()
    lowered = text.lower()
    if lowered in ("", "0", "benign", "normal", "false", "none"):
        return "normal", 0
    if any(key in lowered for key in BRUTE_FORCE_KEYWORDS):
        return "password_attack", 1
    if any(key in lowered for key in ANOMALY_KEYWORDS):
        return "anomaly_attack", 1
    if lowered in ("1", "true", "attack", "malicious"):
        return "anomaly_attack", 1
    return text or "unknown_attack", 1


class SecurityDatasetImporter:
    """Convert configured CSV sources into a unified lightweight training file."""

    def __init__(self, config_path: str = "config/dataset_sources.json"):
        self.config_path = config_path
        self.config = self._load_config(config_path)

    @staticmethod
    def _load_config(config_path: str) -> Dict:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def resolve_files(self, source_id: str) -> Tuple[Dict, List[str]]:
        source = next((x for x in self.config.get("sources", []) if x.get("id") == source_id), None)
        if source is None:
            raise ValueError("Unknown dataset source: %s" % source_id)
        files: List[str] = []
        for pattern in source.get("paths", []):
            matches = glob.glob(pattern, recursive=True)
            if matches:
                files.extend(matches)
            elif os.path.exists(pattern):
                files.append(pattern)
        unique = []
        seen = set()
        for path in files:
            normalized = os.path.normpath(path)
            if normalized not in seen and os.path.isfile(normalized):
                unique.append(normalized)
                seen.add(normalized)
        return source, unique

    def import_source(
        self,
        source_id: str,
        output_path: Optional[str] = None,
        metadata_path: Optional[str] = None,
        per_class_limit: Optional[int] = None,
    ) -> Dict:
        source, files = self.resolve_files(source_id)
        if not files:
            raise FileNotFoundError("No local CSV files found for source: %s" % source_id)

        output_path = output_path or self.config.get("default_output", "data/datasets/processed/security_training_sample.csv")
        metadata_path = metadata_path or self.config.get("default_metadata", "data/datasets/processed/security_dataset_metadata.json")
        per_class_limit = int(per_class_limit or self.config.get("per_class_limit", 20000))
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        os.makedirs(os.path.dirname(metadata_path), exist_ok=True)

        raw_rows = 0
        written_rows = 0
        label_distribution = Counter()
        attack_distribution = Counter()
        field_mapping = {}
        class_counts = defaultdict(int)

        with open(output_path, "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=UNIFIED_FIELDS)
            writer.writeheader()
            sample_id = 1
            for csv_path in files:
                with open(csv_path, "r", encoding="utf-8-sig", newline="", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    if not reader.fieldnames:
                        continue
                    field_mapping[os.path.basename(csv_path)] = self._describe_mapping(reader.fieldnames)
                    for row in reader:
                        raw_rows += 1
                        unified = self._convert_row(row, source, sample_id)
                        attack_type = unified["attack_type"]
                        if class_counts[attack_type] >= per_class_limit:
                            continue
                        class_counts[attack_type] += 1
                        writer.writerow(unified)
                        written_rows += 1
                        sample_id += 1
                        label_distribution[str(unified["label"])] += 1
                        attack_distribution[attack_type] += 1

        metadata = {
            "source_id": source.get("id"),
            "dataset_name": source.get("name"),
            "dataset_type": source.get("type"),
            "input_files": files,
            "output_path": output_path,
            "import_time": _now(),
            "raw_rows": raw_rows,
            "sampled_rows": written_rows,
            "per_class_limit": per_class_limit,
            "label_distribution": dict(label_distribution),
            "attack_type_distribution": dict(attack_distribution),
            "field_mapping": field_mapping,
            "trainable": written_rows > 0,
        }
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        return metadata

    def _describe_mapping(self, fieldnames: Iterable[str]) -> Dict[str, str]:
        names = list(fieldnames)
        normalized_names = {_normalize_key(name): name for name in names}
        mapping = {}
        for field in UNIFIED_FIELDS:
            if field in ("sample_id", "source_dataset", "attack_type", "label"):
                continue
            aliases = FIELD_ALIASES.get(field, [field])
            matched = next((normalized_names.get(_normalize_key(alias)) for alias in aliases if _normalize_key(alias) in normalized_names), None)
            if matched:
                mapping[field] = matched
        label_match = next((normalized_names.get(_normalize_key(alias)) for alias in LABEL_ALIASES if _normalize_key(alias) in normalized_names), None)
        if label_match:
            mapping["label"] = label_match
        return mapping

    def _convert_row(self, row: Dict[str, str], source: Dict, sample_id: int) -> Dict[str, str]:
        raw_label = _get(row, LABEL_ALIASES, "")
        if not raw_label:
            raw_label = _get(row, ["attack_type", "attack_cat"], "")
        attack_type, label = map_attack_type(raw_label)
        unified = {
            "sample_id": str(sample_id),
            "source_dataset": source.get("id", TEXT_DEFAULT),
            "attack_type": attack_type,
            "label": str(label),
        }
        for field in UNIFIED_FIELDS:
            if field in unified:
                continue
            aliases = FIELD_ALIASES.get(field, [field])
            value = _get(row, aliases, "")
            if field == "username_masked":
                unified[field] = _mask_username(value)
            elif field in NUMERIC_FIELDS:
                unified[field] = _clean_number(value)
            else:
                unified[field] = str(value).strip() or TEXT_DEFAULT
        return unified
