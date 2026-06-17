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


def _mask_value(value):
    if value is None:
        return None
    text = str(value)
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
        preview.append({k: _mask_value(v) for k, v in row.items()})
    return preview


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

        rows, columns = _load_rows(plain_path, safe, limit=500)
        profile = _profile_rows(rows, columns)
        label_col = _detect_label_column(columns)
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
            "masked_preview": _masked_preview(rows),
            "risk_summary": {},
            "report_path": None,
            "source": "用户上传数据",
        }
        data = _read_index()
        data["submissions"].append(item)
        _write_index(data)
        return self.public_summary(item)

    def public_summary(self, item: Dict) -> Dict:
        return {
            "id": item.get("id"),
            "filename": item.get("filename"),
            "upload_time": item.get("upload_time"),
            "status": item.get("status"),
            "review_status": item.get("review_status"),
            "trainable": bool(item.get("trainable")),
            "archived": bool(item.get("archived")),
            "encrypted": bool(item.get("encrypted")),
            "encryption": item.get("encryption"),
            "row_count": item.get("row_count", 0),
            "column_count": item.get("column_count", 0),
            "label_column": item.get("label_column"),
            "risk_summary": item.get("risk_summary", {}),
            "masked_preview": item.get("masked_preview", []),
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

        high_items = [
            d for d in detections
            if d.get("risk_level") in ("medium", "high", "critical") or float(d.get("risk_score") or 0) >= 0.35
        ]
        high_items = sorted(high_items, key=lambda d: float(d.get("risk_score") or 0), reverse=True)
        reasons = []
        row_by_id = {i + 1: row for i, row in enumerate(rows)}
        for det in high_items[:20]:
            reasons.append({
                "id": det.get("id"),
                "risk_score": det.get("risk_score"),
                "risk_level": det.get("risk_level"),
                "reason": _reason_for_detection(det, row_by_id.get(det.get("id"))),
                "suggestion": "建议优先核验该样本来源、访问频率、失败尝试和业务标签是否一致。",
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
            "suggestions": _suggestions(summary),
            "boundary": "本系统输出为机器学习辅助分析结果，需结合业务背景和人工复核使用。",
            "analyzed_at": _now(),
        }
        report_path = self._write_report(item, analysis)
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

    def set_status(self, submission_id: str, review_status: str = None, trainable: Optional[bool] = None) -> Optional[Dict]:
        patch = {}
        if review_status:
            patch["review_status"] = review_status
        if trainable is not None:
            patch["trainable"] = bool(trainable)
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
