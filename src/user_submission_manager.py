# -*- coding: utf-8 -*-
"""User submission, encrypted archive, and training-pool helpers.

This module intentionally keeps storage simple:
- metadata is stored in JSON under data/user_submissions/index.json;
- uploaded source files are encrypted at rest with AES-GCM;
- plaintext is only written to a temporary analysis file owned by the server;
- admin APIs expose summaries and masked previews, not raw source files.
"""

import base64
import csv
import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np

try:
    import pandas as pd
except ImportError:  # pragma: no cover - pandas is in requirements, keep fallback.
    pd = None

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:  # pragma: no cover
    AES = None
    get_random_bytes = None

from src.preprocess.feature_engineering import (
    FEATURE_NAMES,
    extract_features_structured,
    infer_label,
    minmax_normalize,
)


PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
DATA_ROOT = os.path.join(PROJECT_ROOT, "data", "user_submissions")
TEMP_DIR = os.path.join(DATA_ROOT, "plain_temp")
ARCHIVE_DIR = os.path.join(DATA_ROOT, "archive")
REPORT_DIR = os.path.join(DATA_ROOT, "reports")
INDEX_FILE = os.path.join(DATA_ROOT, "index.json")
KEY_DIR = os.path.join(PROJECT_ROOT, "data", "keys")
KEY_FILE = os.path.join(KEY_DIR, "user_archive.key")
MAX_PREVIEW_ROWS = 8
MAX_TRAIN_ROWS = 20000
MAX_UPLOAD_ROWS = 50000

LOGIN_SECURITY_FIELD_HINTS = {
    "ip", "client_ip", "remote_ip", "source_ip", "src_ip",
    "username", "user", "account", "login_name",
    "failed_attempts", "fail_count", "login_failures",
    "request_rate", "request_frequency", "rate",
    "response_time", "response_time_ms", "latency",
    "session_duration", "duration", "dur",
    "login_success", "success", "is_success",
    "device", "device_type", "browser", "os", "user_agent",
    "hour", "timestamp", "login_time", "unusual_hour",
}

PASSWORD_FIELD_HINTS = {
    "password", "passwd", "pwd", "user_password", "login_password",
}

CREDENTIAL_FIELD_HINTS = {
    "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
    "client_secret", "authorization", "auth", "credential", "session_key",
    "private_key",
}

SENSITIVE_FIELD_HINTS = {
    "username", "user_name", "account", "login_name", "账号", "用户名",
    "phone", "mobile", "tel", "telephone", "cellphone", "手机号", "电话",
    "email", "mail", "邮箱",
    "id_card", "idcard", "identity", "身份证", "证件",
    "bank_card", "bankcard", "card_no", "card_number", "银行卡", "卡号",
    "salary", "income", "wage", "pay", "薪资", "工资", "收入",
    "address", "addr", "住址", "地址",
}

RISK_LEVEL_ZH = {
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
    "critical": "严重风险",
}

REVIEW_STATUS = {
    "pending": "待审核",
    "archived": "已归档",
    "trainable": "可训练",
    "rejected": "已拒绝",
}

REVIEW_STATUS_NOTE = {
    REVIEW_STATUS["pending"]: "已加密归档，等待管理员确认是否进入训练池。",
    REVIEW_STATUS["archived"]: "已确认归档，可继续审核是否允许用于训练。",
    REVIEW_STATUS["trainable"]: "管理员已确认该数据可进入本地训练和联邦训练流程。",
    REVIEW_STATUS["rejected"]: "管理员已拒绝该数据进入训练池，仅保留加密归档和风险报告。",
}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dirs() -> None:
    for path in (DATA_ROOT, TEMP_DIR, ARCHIVE_DIR, REPORT_DIR, KEY_DIR):
        os.makedirs(path, exist_ok=True)
    if not os.path.exists(INDEX_FILE):
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump({"submissions": []}, f, ensure_ascii=False, indent=2)


def _safe_filename(filename: str) -> str:
    name = os.path.basename(filename or "upload.dat")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "upload.dat"


def _read_index() -> Dict:
    _ensure_dirs()
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not isinstance(data.get("submissions"), list):
            return {"submissions": []}
        return data
    except Exception:
        return {"submissions": []}


def _write_index(data: Dict) -> None:
    _ensure_dirs()
    tmp = INDEX_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, INDEX_FILE)


def _get_key() -> bytes:
    _ensure_dirs()
    if AES is None or get_random_bytes is None:
        raise RuntimeError("pycryptodome is required for AES encrypted archive storage")
    if os.path.exists(KEY_FILE):
        raw = open(KEY_FILE, "rb").read().strip()
        try:
            key = base64.b64decode(raw)
            if len(key) == 32:
                return key
        except Exception:
            pass
    key = get_random_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(base64.b64encode(key))
    return key


def _encrypt_file(src_path: str, dest_path: str) -> Dict:
    key = _get_key()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = open(src_path, "rb").read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(dest_path, "wb") as f:
        f.write(b"DCENC1")
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)
    return {
        "algorithm": "AES-256-GCM",
        "cipher_size": os.path.getsize(dest_path),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
    }


def _decrypt_file(enc_path: str) -> bytes:
    key = _get_key()
    raw = open(enc_path, "rb").read()
    if not raw.startswith(b"DCENC1") or len(raw) < 34:
        raise ValueError("invalid encrypted archive format")
    nonce = raw[6:18]
    tag = raw[18:34]
    ciphertext = raw[34:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _detect_label_column(columns: List[str]) -> Optional[str]:
    candidates = ["label", "attack_cat", "is_attack", "attack", "target", "class", "y"]
    lower_map = {c.lower(): c for c in columns}
    for name in candidates:
        if name in lower_map:
            return lower_map[name]
    return None


def _load_rows(path: str, filename: str, limit: Optional[int] = None) -> Tuple[List[Dict], List[str]]:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "csv":
        if pd is not None:
            df = pd.read_csv(path, nrows=limit)
            rows = df.where(pd.notnull(df), None).to_dict(orient="records")
            return rows, list(df.columns)
        rows = []
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
                if limit and len(rows) >= limit:
                    break
            return rows, list(reader.fieldnames or [])
    if ext == "json":
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("records") or data.get("data") or [data]
        if not isinstance(data, list):
            data = []
        rows = [r for r in data if isinstance(r, dict)]
        if limit:
            rows = rows[:limit]
        columns = list(rows[0].keys()) if rows else []
        return rows, columns
    raise ValueError("only CSV/JSON files are supported")


def _normalize_key(key) -> str:
    return re.sub(r"[^a-z0-9_\u4e00-\u9fff]+", "_", str(key or "").strip().lower())


def _field_matches(key, hints) -> bool:
    normalized = _normalize_key(key)
    compact = normalized.replace("_", "")
    for hint in hints:
        h = _normalize_key(hint)
        if normalized == h or normalized.endswith("_" + h) or h in normalized or h.replace("_", "") in compact:
            return True
    return False


def _sensitive_type(key, value=None) -> Optional[str]:
    normalized_key = _normalize_key(key)
    if normalized_key in {
        "password_present", "password_length", "password_strength", "weak_password",
        "token_present", "token_length", "secret_present", "secret_length",
        "api_key_present", "api_key_length", "apikey_present", "apikey_length",
    } or normalized_key.endswith("_present") or normalized_key.endswith("_length"):
        return None
    if normalized_key in {
        "ip", "srcip", "src_ip", "source_ip", "dstip", "dst_ip",
        "destination_ip", "client_ip", "remote_ip", "ip_address",
        "user_agent",
    }:
        return None
    if _field_matches(key, PASSWORD_FIELD_HINTS):
        return "password"
    if _field_matches(key, CREDENTIAL_FIELD_HINTS):
        return "credential"
    if _field_matches(key, SENSITIVE_FIELD_HINTS):
        return "sensitive"
    text = str(value or "")
    if re.fullmatch(r"1[3-9]\d{9}", text):
        return "sensitive"
    if re.fullmatch(r"\d{16,19}", text):
        return "sensitive"
    if re.fullmatch(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
        return "sensitive"
    return None


def _safe_feature_name(key: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]+", "_", str(key or "secret").strip().lower()).strip("_")
    return name[:40] or "secret"


def _mask_value(value, key=None):
    if value is None:
        return None
    text = str(value)
    normalized_key = _normalize_key(key)
    if normalized_key in {
        "ip", "srcip", "src_ip", "source_ip", "dstip", "dst_ip",
        "destination_ip", "client_ip", "remote_ip", "ip_address",
        "user_agent",
    }:
        return text
    kind = _sensitive_type(key or "", text)
    if kind == "password":
        return "[password_derived_only]"
    if kind == "credential":
        return "[secret_masked]"
    if kind == "sensitive":
        if not text:
            return text
        if "@" in text:
            left, _, right = text.partition("@")
            return (left[:2] + "***@" + right[-18:]) if left else "***@" + right[-18:]
        if len(text) <= 4:
            return "*" * len(text)
        return text[:2] + "***" + text[-2:]
    if len(text) <= 4:
        return text
    if re.fullmatch(r"[\d\s+.-]{6,}", text):
        return text[:2] + "***" + text[-2:]
    if "@" in text:
        left, _, right = text.partition("@")
        return (left[:2] + "***@" + right) if left else "***@" + right
    return text[:8] + ("..." if len(text) > 8 else "")


def _masked_preview(rows: List[Dict]) -> List[Dict]:
    preview = []
    for row in rows[:MAX_PREVIEW_ROWS]:
        preview.append({k: _mask_value(v, k) for k, v in row.items()})
    return preview


def _password_strength(value) -> int:
    text = str(value or "")
    if not text:
        return 0
    score = 1
    if len(text) >= 8:
        score += 1
    if re.search(r"[A-Z]", text) and re.search(r"[a-z]", text):
        score += 1
    if re.search(r"\d", text):
        score += 1
    if re.search(r"[^A-Za-z0-9]", text):
        score += 1
    return min(score, 5)


def _sanitize_sensitive_rows(rows: List[Dict]) -> Tuple[List[Dict], List[str]]:
    sanitized = []
    sensitive_columns = []
    for row in rows:
        new_row = dict(row)
        for key in list(row.keys()):
            kind = _sensitive_type(key, row.get(key))
            if not kind:
                continue
            sensitive_columns.append(key)
            raw = row.get(key)
            if kind == "password":
                new_row["password_present"] = 1 if raw not in (None, "") else 0
                new_row["password_length"] = len(str(raw or ""))
                strength = _password_strength(raw)
                new_row["password_strength"] = strength
                new_row["weak_password"] = 1 if raw not in (None, "") and strength <= 2 else 0
                new_row.pop(key, None)
            elif kind == "credential":
                feature = _safe_feature_name(key)
                new_row[f"{feature}_present"] = 1 if raw not in (None, "") else 0
                new_row[f"{feature}_length"] = len(str(raw or ""))
                new_row.pop(key, None)
        sanitized.append(new_row)
    return sanitized, sorted(set(sensitive_columns))


def _write_rows(path: str, filename: str, rows: List[Dict]) -> List[str]:
    columns = []
    for row in rows:
        for key in row.keys():
            if key not in columns:
                columns.append(key)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "csv"
    if ext == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
    else:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
    return columns


def _profile_rows(rows: List[Dict], columns: List[str]) -> Dict:
    missing = 0
    total_cells = max(len(rows) * max(len(columns), 1), 1)
    numeric_columns = 0
    for col in columns:
        nums = 0
        for row in rows[:200]:
            value = row.get(col)
            if value in (None, ""):
                missing += 1
                continue
            try:
                float(value)
                nums += 1
            except Exception:
                pass
        if rows and nums >= max(1, int(len(rows[:200]) * 0.5)):
            numeric_columns += 1
    return {
        "rows": len(rows),
        "columns": len(columns),
        "missing_cells": missing,
        "missing_rate": round(missing / total_cells, 4),
        "numeric_columns": numeric_columns,
    }


def _has_login_security_fields(columns: List[str]) -> bool:
    normalized = {_normalize_key(c) for c in columns}
    compact = {c.replace("_", "") for c in normalized}
    hits = 0
    for hint in LOGIN_SECURITY_FIELD_HINTS:
        h = _normalize_key(hint)
        if h in normalized or h.replace("_", "") in compact:
            hits += 1
    return hits >= 2


def _schema_check(profile: Dict, columns: List[str], label_col: Optional[str],
                  sensitive_columns: List[str], truncated: bool = False) -> Dict:
    warnings = []
    row_count = int(profile.get("rows") or 0)
    column_count = int(profile.get("columns") or 0)
    missing_rate = float(profile.get("missing_rate") or 0)
    has_login_security_fields = _has_login_security_fields(columns)

    if row_count <= 0:
        warnings.append("文件没有可分析的数据行。")
    if column_count < 3:
        warnings.append("字段数量较少，风险检测可信度可能不足。")
    if not label_col:
        warnings.append("未识别到 label / attack_cat / is_attack 等标签列，系统会按无标签数据处理。")
    if missing_rate >= 0.2:
        warnings.append("缺失值比例较高，建议先清洗数据后再分析。")
    if not has_login_security_fields:
        warnings.append("缺少典型登录安全字段，风险原因可能主要依赖通用数值特征。")
    if truncated:
        warnings.append("上传数据超过处理上限，本次仅处理前 %d 行。" % MAX_UPLOAD_ROWS)

    return {
        "row_count": row_count,
        "column_count": column_count,
        "label_column": label_col,
        "missing_ratio": missing_rate,
        "missing_cells": int(profile.get("missing_cells") or 0),
        "numeric_columns": int(profile.get("numeric_columns") or 0),
        "sensitive_column_count": len(sensitive_columns),
        "has_login_security_fields": has_login_security_fields,
        "ready_for_detection": row_count > 0 and column_count >= 3,
        "warnings": warnings,
    }


def _features_from_rows(rows: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
    X = []
    y = []
    for row in rows:
        X.append(extract_features_structured(row))
        y.append(infer_label(row))
    if not X:
        return np.empty((0, len(FEATURE_NAMES))), np.empty(0, dtype=np.int32)
    return minmax_normalize(np.asarray(X, dtype=np.float64)), np.asarray(y, dtype=np.int32)


def _reason_for_detection(det: Dict, row: Optional[Dict] = None) -> str:
    score = float(det.get("risk_score", det.get("score", 0)) or 0)
    reasons = []
    if score >= 0.75:
        reasons.append("风险分数处于高区间")
    elif score >= 0.45:
        reasons.append("风险分数处于中等区间")
    if det.get("is_attack"):
        reasons.append("模型判断为异常或攻击样本")
    if row:
        try:
            failed = float(row.get("failed_attempts") or row.get("ct_dst_src_ltm") or 0)
        except Exception:
            failed = 0.0
        try:
            freq = float(row.get("request_frequency") or row.get("rate") or 0)
        except Exception:
            freq = 0.0
        if failed > 10:
            reasons.append("失败尝试或连接异常计数偏高")
        if freq > 100:
            reasons.append("访问频率偏高")
        missing = sum(1 for v in row.values() if v in (None, ""))
        if missing >= max(3, len(row) // 4):
            reasons.append("缺失字段较多，需复核数据质量")
    return "；".join(reasons[:3]) or "未发现明显异常特征，建议结合业务场景复核"


def _suggestions(summary: Dict) -> List[str]:
    suggestions = []
    high = summary.get("high", 0) + summary.get("critical", 0)
    medium = summary.get("medium", 0)
    if high:
        suggestions.append("优先复核高风险样本，确认是否存在异常访问、暴力尝试或异常流量。")
        suggestions.append("对高风险来源加强访问频率监控，并保留检测报告用于后续追踪。")
    if medium:
        suggestions.append("中风险样本建议结合时间、来源和业务字段进一步核验。")
    suggestions.append("上传数据建议使用加密归档，训练前由管理员确认数据质量和授权范围。")
    suggestions.append("如需进入训练中心，应先完成归档并标记为可训练。")
    return suggestions


def _num(row: Dict, *keys: str, default: float = 0.0) -> float:
    for key in keys:
        if key in row:
            try:
                value = row.get(key)
                if value is None or value == "":
                    return default
                return float(value)
            except Exception:
                return default
    return default


def _trigger_features(row: Optional[Dict]) -> List[str]:
    if not row:
        return []
    triggers = []
    failed = _num(row, "failed_attempts", "ct_dst_src_ltm")
    freq = _num(row, "request_rate", "request_frequency", "rate")
    response = _num(row, "response_time_ms", "response_time", "latency", "dur")
    session = _num(row, "session_duration", "connection_duration", "dur")
    password_strength = _num(row, "password_strength", default=3)
    unusual_hour = _num(row, "unusual_hour")
    login_success = _num(row, "login_success", default=1)
    if login_success == 0 and failed >= 3:
        triggers.append("多次失败登录")
    if failed >= 5:
        triggers.append("失败次数偏高")
    if freq >= 80:
        triggers.append("请求频率偏高")
    if response >= 1200:
        triggers.append("响应时间异常")
    if session >= 1800:
        triggers.append("会话时长异常")
    if password_strength and password_strength <= 2:
        triggers.append("密码强度偏低")
    if unusual_hour >= 1:
        triggers.append("异常时间段访问")
    missing = sum(1 for v in row.values() if v in (None, ""))
    if missing >= max(3, len(row) // 4):
        triggers.append("缺失字段较多")
    return triggers[:5]


def _risk_breakdown(row: Optional[Dict], det: Dict) -> Dict:
    row = row or {}
    score = float(det.get("risk_score", det.get("score", 0)) or 0)
    failed = _num(row, "failed_attempts", "ct_dst_src_ltm")
    freq = _num(row, "request_rate", "request_frequency", "rate")
    response = _num(row, "response_time_ms", "response_time", "latency", "dur")
    session = _num(row, "session_duration", "connection_duration", "dur")
    password_strength = _num(row, "password_strength", default=3)
    unusual_hour = _num(row, "unusual_hour")
    login_success = _num(row, "login_success", default=1)
    indicators = [
        {
            "name": "失败登录次数",
            "value": failed,
            "threshold": ">= 5 触发关注，>= 10 明显异常",
            "impact": "高" if failed >= 10 else ("中" if failed >= 5 else "低"),
            "explain": "连续失败登录通常对应撞库、暴力尝试或账号异常使用。",
        },
        {
            "name": "请求频率",
            "value": freq,
            "threshold": ">= 80 触发关注，>= 150 明显异常",
            "impact": "高" if freq >= 150 else ("中" if freq >= 80 else "低"),
            "explain": "短时间高频请求可能对应自动化脚本、扫描或异常重试。",
        },
        {
            "name": "响应时间",
            "value": response,
            "threshold": ">= 1200ms 触发关注",
            "impact": "中" if response >= 1200 else "低",
            "explain": "响应时间异常可能说明请求负载偏大或接口被异常访问。",
        },
        {
            "name": "会话时长",
            "value": session,
            "threshold": ">= 1800s 触发关注",
            "impact": "中" if session >= 1800 else "低",
            "explain": "过长会话需要结合登录地点、设备和历史行为复核。",
        },
        {
            "name": "密码强度派生特征",
            "value": password_strength,
            "threshold": "<= 2 触发关注",
            "impact": "中" if password_strength <= 2 else "低",
            "explain": "系统不保存明文密码，只使用密码强度派生特征辅助判断。",
        },
        {
            "name": "异常时间段",
            "value": unusual_hour,
            "threshold": "= 1 触发关注",
            "impact": "中" if unusual_hour >= 1 else "低",
            "explain": "非惯常时间访问需要结合账号历史和设备变化判断。",
        },
        {
            "name": "登录结果",
            "value": login_success,
            "threshold": "0 且失败次数偏高时触发关注",
            "impact": "中" if login_success == 0 and failed >= 3 else "低",
            "explain": "登录失败本身不一定危险，但和高失败次数组合时风险升高。",
        },
    ]
    risk_level = str(det.get("risk_level") or "").lower()
    if risk_level in ("critical", "high") or score >= 0.75:
        level_explain = "高风险：模型分数和规则触发项均较高，建议优先复核。"
    elif risk_level == "medium" or score >= 0.45:
        level_explain = "中风险：存在若干异常行为特征，建议结合业务上下文确认。"
    else:
        level_explain = "低风险：当前样本未表现出明显异常组合。"
    triggered = [
        item for item in indicators
        if item.get("impact") in ("中", "高")
    ]
    dominant = triggered[0]["name"] if triggered else ("模型分数" if score >= 0.35 else "未发现明显触发项")
    return {
        "final_score": round(score, 4),
        "score_range": "0 到 1，越接近 1 表示模型认为异常概率越高",
        "level_explain": level_explain,
        "model_signal": "融合检测模型输出的风险分数",
        "rule_signal": "登录安全字段触发的规则解释",
        "score_formula": "排序优先看风险分数，其次看是否达到中高风险等级和触发特征数量。",
        "dominant_factor": dominant,
        "triggered_count": len(triggered),
        "triggered_indicators": triggered,
        "indicators": indicators,
    }


def _clean_reason_for_detection(det: Dict, row: Optional[Dict] = None) -> str:
    score = float(det.get("risk_score", det.get("score", 0)) or 0)
    risk_level = str(det.get("risk_level") or "").lower()
    reasons = []
    if risk_level in ("critical", "high") or score >= 0.75:
        reasons.append("风险分数处于高区间")
    elif risk_level == "medium" or score >= 0.45:
        reasons.append("风险分数处于中等区间")
    if det.get("is_attack"):
        reasons.append("模型判断为异常或攻击样本")
    breakdown = _risk_breakdown(row, det)
    triggered = breakdown.get("triggered_indicators", [])
    if triggered:
        detail = []
        for item in triggered[:3]:
            detail.append("%s=%s，阈值%s" % (
                item.get("name", "指标"),
                item.get("value", "-"),
                item.get("threshold", "-"),
            ))
        reasons.append("触发指标：" + "；".join(detail))
    return "；".join(reasons[:3]) or "未发现明显异常特征，建议结合业务场景复核"


def _clean_suggestion_for_detection(det: Dict, row: Optional[Dict] = None) -> str:
    triggers = set(_trigger_features(row))
    if "失败次数偏高" in triggers or "多次失败登录" in triggers or "密码强度偏低" in triggers:
        return "建议核验账号登录行为，并按业务策略启用二次验证或密码重置流程。"
    if "请求频率偏高" in triggers:
        return "建议关注同一来源的访问频率，结合限流策略和业务白名单进行复核。"
    if "异常时间段访问" in triggers or "会话时长异常" in triggers:
        return "建议复核访问时间、设备和账号历史行为，确认是否为本人操作。"
    if det.get("risk_level") in ("high", "critical"):
        return "建议优先人工复核该样本，并结合来源 IP、设备和业务标签判断。"
    return "建议持续观察同类样本，作为后续模型训练和策略优化的参考。"


def _clean_suggestions(summary: Dict) -> List[str]:
    suggestions = []
    high = summary.get("high", 0) + summary.get("critical", 0)
    medium = summary.get("medium", 0)
    if high:
        suggestions.append("优先复核高风险样本，重点查看失败登录、请求频率、异常时间段和设备变化。")
        suggestions.append("对高风险来源加强访问频率监测，并保留检测报告用于后续追踪。")
    if medium:
        suggestions.append("中风险样本建议结合访问时间、来源 IP、设备类型和业务字段进一步核验。")
    suggestions.append("上传数据已进行 AES 加密归档；训练前应由管理员确认数据质量和授权范围。")
    suggestions.append("如需进入训练中心，应先完成归档确认并标记为可训练。")
    return suggestions


def _update_submission(submission_id: str, patch: Dict) -> Optional[Dict]:
    data = _read_index()
    for i, item in enumerate(data["submissions"]):
        if item.get("id") == submission_id:
            item.update(patch)
            item["updated_at"] = _now()
            data["submissions"][i] = item
            _write_index(data)
            return item
    return None


class UserSubmissionManager:
    def create_submission(self, src_path: str, filename: str) -> Dict:
        _ensure_dirs()
        safe = _safe_filename(filename)
        ext = safe.rsplit(".", 1)[-1].lower() if "." in safe else ""
        if ext not in ("csv", "json"):
            raise ValueError("仅支持 CSV/JSON 文件")

        submission_id = "sub_%s_%s" % (datetime.now().strftime("%Y%m%d%H%M%S"), uuid.uuid4().hex[:8])
        plain_path = os.path.join(TEMP_DIR, submission_id + "_" + safe)
        enc_path = os.path.join(ARCHIVE_DIR, submission_id + ".enc")
        shutil.copy2(src_path, plain_path)

        rows, columns = _load_rows(plain_path, safe, limit=MAX_UPLOAD_ROWS + 1)
        truncated = len(rows) > MAX_UPLOAD_ROWS
        if truncated:
            rows = rows[:MAX_UPLOAD_ROWS]
        rows, sensitive_columns = _sanitize_sensitive_rows(rows)
        if sensitive_columns:
            columns = _write_rows(plain_path, safe, rows)
        profile = _profile_rows(rows, columns)
        label_col = _detect_label_column(columns)
        schema_check = _schema_check(profile, columns, label_col, sensitive_columns, truncated=truncated)
        enc_info = _encrypt_file(plain_path, enc_path)

        item = {
            "id": submission_id,
            "filename": safe,
            "upload_time": _now(),
            "status": "待分析",
            "review_status": "待审核",
            "trainable": False,
            "archived": True,
            "encrypted": True,
            "encryption": enc_info["algorithm"],
            "encrypted_path": enc_path,
            "plain_temp_path": plain_path,
            "file_size": os.path.getsize(src_path),
            "sha256": enc_info["sha256"],
            "row_count": profile["rows"],
            "column_count": profile["columns"],
            "columns": columns[:80],
            "label_column": label_col,
            "profile": profile,
            "schema_check": schema_check,
            "masked_preview": _masked_preview(rows),
            "sensitive_columns": sensitive_columns,
            "privacy_notice": "password fields are converted to derived strength features before archive storage" if sensitive_columns else "",
            "risk_summary": {},
            "report_path": None,
            "source": "用户上传数据",
        }
        data = _read_index()
        data["submissions"].append(item)
        _write_index(data)
        return self.public_summary(item)

    def public_summary(self, item: Dict) -> Dict:
        review_status = item.get("review_status") or REVIEW_STATUS["pending"]
        trainable = bool(item.get("trainable"))
        actions = []
        if review_status == REVIEW_STATUS["pending"]:
            actions.extend(["archive", "reject"])
        elif review_status == REVIEW_STATUS["archived"]:
            actions.extend(["mark_trainable", "reject"])
        elif review_status == REVIEW_STATUS["trainable"]:
            actions.extend(["archive", "reject"])
        elif review_status == REVIEW_STATUS["rejected"]:
            actions.append("archive")
        return {
            "id": item.get("id"),
            "filename": item.get("filename"),
            "upload_time": item.get("upload_time"),
            "status": item.get("status"),
            "review_status": review_status,
            "review_status_note": REVIEW_STATUS_NOTE.get(review_status, "等待管理员审核。"),
            "reviewed_at": item.get("reviewed_at"),
            "trainable": trainable,
            "training_status": "已进入训练池" if trainable else "未进入训练池",
            "allowed_actions": actions,
            "archived": bool(item.get("archived")),
            "encrypted": bool(item.get("encrypted")),
            "encryption": item.get("encryption"),
            "row_count": item.get("row_count", 0),
            "column_count": item.get("column_count", 0),
            "label_column": item.get("label_column"),
            "schema_check": item.get("schema_check", {}),
            "profile": item.get("profile", {}),
            "risk_summary": item.get("risk_summary", {}),
            "masked_preview": item.get("masked_preview", []),
            "sensitive_columns": item.get("sensitive_columns", []),
            "privacy_notice": item.get("privacy_notice", ""),
            "source": item.get("source", "用户上传数据"),
        }

    def list_submissions(self) -> List[Dict]:
        items = _read_index().get("submissions", [])
        return [self.public_summary(x) for x in sorted(items, key=lambda v: v.get("upload_time", ""), reverse=True)]

    def get_submission(self, submission_id: str, include_preview: bool = True) -> Optional[Dict]:
        for item in _read_index().get("submissions", []):
            if item.get("id") == submission_id:
                result = self.public_summary(item)
                if include_preview:
                    result["columns"] = item.get("columns", [])
                    result["profile"] = item.get("profile", {})
                    result["analysis"] = item.get("analysis", {})
                return result
        return None

    def _load_plain_rows(self, item: Dict, limit: Optional[int] = None) -> Tuple[List[Dict], List[str]]:
        plain_path = item.get("plain_temp_path")
        filename = item.get("filename", "upload.csv")
        if plain_path and os.path.exists(plain_path):
            return _load_rows(plain_path, filename, limit=limit)
        enc_path = item.get("encrypted_path")
        if not enc_path or not os.path.exists(enc_path):
            return [], []
        raw = _decrypt_file(enc_path)
        tmp_path = os.path.join(TEMP_DIR, item["id"] + "_decrypt_" + filename)
        with open(tmp_path, "wb") as f:
            f.write(raw)
        try:
            return _load_rows(tmp_path, filename, limit=limit)
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    def analyze(self, submission_id: str, detector=None, limit: int = 500) -> Optional[Dict]:
        data = _read_index()
        item = next((x for x in data.get("submissions", []) if x.get("id") == submission_id), None)
        if item is None:
            return None
        rows, columns = self._load_plain_rows(item, limit=limit)
        if not rows:
            analysis = {
                "total": 0,
                "risk_summary": {"high": 0, "medium": 0, "low": 0, "critical": 0},
                "detections": [],
                "reasons": [],
                "suggestions": ["文件为空或无法解析，请检查 CSV/JSON 格式。"],
            }
            _update_submission(submission_id, {"status": "分析失败", "analysis": analysis, "risk_summary": analysis["risk_summary"]})
            return analysis

        X, y = _features_from_rows(rows)
        detections = []
        if detector is not None and len(X):
            if not detector.is_ready():
                detector.load_or_init()
            preds, scores, risk_levels = detector.predict(X)
            risk_names = {0: "low", 1: "medium", 2: "high", 3: "critical"}
            for i in range(len(X)):
                detections.append({
                    "id": i + 1,
                    "is_attack": bool(preds[i]),
                    "actual_label": int(y[i]) if len(y) > i else None,
                    "risk_score": round(float(scores[i]), 4),
                    "risk_level": risk_names.get(int(risk_levels[i]), "low"),
                    "attack_type": "Attack" if int(preds[i]) else "Normal",
                })
        else:
            for i, row in enumerate(rows):
                label = infer_label(row)
                score = 0.72 if label else 0.18
                detections.append({
                    "id": i + 1,
                    "is_attack": bool(label),
                    "actual_label": label,
                    "risk_score": score,
                    "risk_level": "high" if score >= 0.7 else "low",
                    "attack_type": "Attack" if label else "Normal",
                })

        summary = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        attack_types = {}
        for det in detections:
            rl = det.get("risk_level", "low")
            summary[rl] = summary.get(rl, 0) + 1
            attack_types[det.get("attack_type", "unknown")] = attack_types.get(det.get("attack_type", "unknown"), 0) + 1

        row_by_id = {i + 1: row for i, row in enumerate(rows)}
        def _attention_key(d):
            row = row_by_id.get(d.get("id")) or {}
            triggers = _trigger_features(row)
            score = float(d.get("risk_score") or 0)
            level_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(d.get("risk_level"), 0)
            return (level_weight, score, len(triggers))

        high_items = [
            d for d in detections
            if d.get("risk_level") in ("medium", "high", "critical")
            or float(d.get("risk_score") or 0) >= 0.35
            or _trigger_features(row_by_id.get(d.get("id")))
        ]
        high_items = sorted(high_items, key=_attention_key, reverse=True)
        reasons = []
        for det in high_items[:20]:
            row = row_by_id.get(det.get("id")) or {}
            breakdown = _risk_breakdown(row, det)
            reasons.append({
                "rank": len(reasons) + 1,
                "id": det.get("id"),
                "username": _mask_value(row.get("username") or row.get("user") or row.get("account") or "", "username"),
                "ip": row.get("ip") or row.get("srcip") or row.get("source_ip") or "",
                "risk_score": det.get("risk_score"),
                "risk_level": det.get("risk_level"),
                "risk_level_zh": RISK_LEVEL_ZH.get(det.get("risk_level"), det.get("risk_level")),
                "attack_type": det.get("attack_type", "unknown"),
                "model_judgement": "异常/攻击倾向" if det.get("is_attack") else "正常倾向",
                "trigger_features": _trigger_features(row),
                "dominant_factor": breakdown.get("dominant_factor"),
                "triggered_count": breakdown.get("triggered_count", 0),
                "score_breakdown": breakdown,
                "reason": _clean_reason_for_detection(det, row),
                "suggestion": _clean_suggestion_for_detection(det, row),
            })

        analysis = {
            "submission_id": submission_id,
            "total": len(detections),
            "profile": _profile_rows(rows, columns),
            "label_column": item.get("label_column"),
            "risk_summary": summary,
            "attack_types": attack_types,
            "detections": detections[:200],
            "high_risk_reasons": reasons,
            "top_reason_limit": 20,
            "top_reason_order": "risk_score_desc",
            "suggestions": _clean_suggestions(summary),
            "sensitive_columns": item.get("sensitive_columns", []),
            "privacy_notice": item.get("privacy_notice", ""),
            "boundary": "?????????????????????????????????",
            "analyzed_at": _now(),
        }
        report_path = self._write_clean_report(item, analysis)
        _update_submission(submission_id, {
            "status": "已分析",
            "analysis": analysis,
            "risk_summary": summary,
            "report_path": report_path,
            "row_count": len(rows),
            "column_count": len(columns),
            "columns": columns[:80],
        })
        return analysis

    def _write_clean_report(self, item: Dict, analysis: Dict) -> str:
        path = os.path.join(REPORT_DIR, item["id"] + ".md")
        summary = analysis.get("risk_summary", {})
        lines = [
            "# 用户数据风险分析报告",
            "",
            "## 数据概况",
            "",
            "- 提交编号：%s" % item.get("id"),
            "- 文件名称：%s" % item.get("filename"),
            "- 上传时间：%s" % item.get("upload_time"),
            "- 样本数量：%s" % analysis.get("total", 0),
            "- 标签列：%s" % (analysis.get("label_column") or "未识别"),
            "- 加密归档：AES-256-GCM",
            "",
            "## 风险摘要",
            "",
            "- 高风险：%s" % (summary.get("high", 0) + summary.get("critical", 0)),
            "- 中风险：%s" % summary.get("medium", 0),
            "- 低风险：%s" % summary.get("low", 0),
            "",
            "## 高风险样本原因",
            "",
        ]
        reasons = analysis.get("high_risk_reasons", [])[:10]
        if reasons:
            for reason in reasons:
                triggers = "、".join(reason.get("trigger_features", []) or ["无明显触发特征"])
                lines.append(
                    "- 样本 %s：%s；触发特征：%s；建议：%s" % (
                        reason.get("id"), reason.get("reason"), triggers, reason.get("suggestion")
                    )
                )
        else:
            lines.append("- 当前数据未发现需要优先关注的中高风险样本。")

        lines.extend(["", "## 处理建议", ""])
        for suggestion in analysis.get("suggestions", []):
            lines.append("- " + suggestion)

        sensitive_columns = analysis.get("sensitive_columns", [])
        lines.extend([
            "",
            "## 隐私保护说明",
            "",
            "- 原始上传文件由系统使用 AES 加密归档。",
            "- 管理端默认展示摘要和脱敏预览，不直接展示原始明文数据。",
            "- 如存在 password 等敏感字段，系统会转换为密码长度、强度等派生特征后再归档。",
            "- Paillier 用于敏感数值字段密态展示和安全聚合方向说明，不用于直接密文训练完整模型。",
        ])
        if sensitive_columns:
            lines.append("- 本次识别并处理的敏感字段：%s。" % "、".join(sensitive_columns))

        lines.extend(["", "## 系统边界", "", analysis.get("boundary", "")])
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def _write_report(self, item: Dict, analysis: Dict) -> str:
        path = os.path.join(REPORT_DIR, item["id"] + ".md")
        lines = [
            "# 用户数据风险分析报告",
            "",
            "- 提交编号：%s" % item.get("id"),
            "- 文件名：%s" % item.get("filename"),
            "- 上传时间：%s" % item.get("upload_time"),
            "- 样本数：%s" % analysis.get("total", 0),
            "- 标签列：%s" % (analysis.get("label_column") or "未识别"),
            "",
            "## 风险摘要",
            "",
            json.dumps(analysis.get("risk_summary", {}), ensure_ascii=False),
            "",
            "## 主要原因",
            "",
        ]
        for reason in analysis.get("high_risk_reasons", [])[:10]:
            lines.append("- 样本 %s：%s；建议：%s" % (
                reason.get("id"), reason.get("reason"), reason.get("suggestion")
            ))
        lines.extend(["", "## 处理建议", ""])
        for suggestion in analysis.get("suggestions", []):
            lines.append("- " + suggestion)
        lines.extend(["", "## 系统边界", "", analysis.get("boundary", "")])
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def get_report(self, submission_id: str) -> Optional[Dict]:
        item = next((x for x in _read_index().get("submissions", []) if x.get("id") == submission_id), None)
        if not item:
            return None
        report_path = item.get("report_path")
        content = ""
        if report_path and os.path.exists(report_path):
            content = open(report_path, "r", encoding="utf-8").read()
        return {
            "submission": self.public_summary(item),
            "report_markdown": content,
            "analysis": item.get("analysis", {}),
        }

    def set_status(self, submission_id: str, review_status: str = None, trainable: Optional[bool] = None, review_note: str = "") -> Optional[Dict]:
        patch = {}
        if review_status:
            if review_status not in REVIEW_STATUS_NOTE:
                return None
            patch["review_status"] = review_status
            patch["reviewed_at"] = _now()
            patch["review_note"] = str(review_note or "")[:300]
            if review_status == REVIEW_STATUS["trainable"]:
                patch["trainable"] = True
            elif review_status in (REVIEW_STATUS["archived"], REVIEW_STATUS["pending"], REVIEW_STATUS["rejected"]):
                patch["trainable"] = False
        if trainable is not None:
            patch["trainable"] = bool(trainable)
            if trainable:
                patch["review_status"] = REVIEW_STATUS["trainable"]
                patch["reviewed_at"] = _now()
            elif not review_status:
                patch["review_status"] = REVIEW_STATUS["archived"]
                patch["reviewed_at"] = _now()
        if patch:
            data = _read_index()
            item = next((x for x in data.get("submissions", []) if x.get("id") == submission_id), None)
            if item is None:
                return None
            history = item.get("review_history", [])
            if not isinstance(history, list):
                history = []
            history.append({
                "time": _now(),
                "review_status": patch.get("review_status", item.get("review_status", REVIEW_STATUS["pending"])),
                "trainable": bool(patch.get("trainable", item.get("trainable", False))),
                "note": patch.get("review_note", review_note or ""),
            })
            patch["review_history"] = history[-20:]
        item = _update_submission(submission_id, patch)
        return self.public_summary(item) if item else None

    def load_trainable_features(self, ids: Optional[List[str]] = None, limit: int = MAX_TRAIN_ROWS) -> Tuple[np.ndarray, np.ndarray, Dict]:
        selected = []
        for item in _read_index().get("submissions", []):
            if ids and item.get("id") not in ids:
                continue
            if not item.get("trainable"):
                continue
            selected.append(item)
        X_all = []
        y_all = []
        source_items = []
        remaining = max(1, int(limit))
        for item in selected:
            if remaining <= 0:
                break
            rows, _ = self._load_plain_rows(item, limit=remaining)
            X, y = _features_from_rows(rows)
            if len(X):
                X_all.append(X)
                y_all.append(y)
                source_items.append({
                    "id": item.get("id"),
                    "filename": item.get("filename"),
                    "samples": int(len(X)),
                })
                remaining -= len(X)
        if not X_all:
            return np.empty((0, len(FEATURE_NAMES))), np.empty(0, dtype=np.int32), {"sources": []}
        X = np.vstack(X_all)
        y = np.concatenate(y_all)
        return X, y, {"sources": source_items, "samples": int(len(X))}


user_submission_manager = UserSubmissionManager()
