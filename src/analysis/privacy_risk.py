"""Policy-based privacy exposure and dual-risk summaries.

The helpers in this module intentionally avoid machine-learning or service
dependencies.  They evaluate field names and aggregate statistics only; raw
field values are never returned.  This keeps the analysis deterministic,
auditable, and suitable for the project's low-memory deployment target.
"""

import re
from typing import Dict, Iterable, List


ANALYSIS_API_VERSION = "v1"
ANALYSIS_POLICY_VERSION = "dual-risk-policy-v1"


_CATEGORY_RULES = (
    {
        "key": "credentials",
        "label": "凭据与密钥",
        "weight": 0.45,
        "hints": {
            "password", "passwd", "pwd", "token", "access_token",
            "refresh_token", "api_key", "apikey", "secret",
            "client_secret", "authorization", "credential", "session_key",
            "private_key",
        },
    },
    {
        "key": "financial",
        "label": "财务信息",
        "weight": 0.35,
        "hints": {
            "bank_card", "bankcard", "card_no", "card_number", "credit_card",
            "salary", "income", "wage", "pay", "credit_score",
            "银行卡", "卡号", "薪资", "工资", "收入", "信用分",
        },
    },
    {
        "key": "identity",
        "label": "身份标识",
        "weight": 0.25,
        "hints": {
            "username", "user_name", "account", "login_name", "id_card",
            "idcard", "identity_number", "passport", "real_name",
            "账号", "用户名", "身份证", "证件", "姓名",
        },
    },
    {
        "key": "contact",
        "label": "联系方式与地址",
        "weight": 0.22,
        "hints": {
            "phone", "mobile", "tel", "telephone", "cellphone", "email",
            "mail", "address", "addr", "location", "手机号", "电话",
            "邮箱", "住址", "地址",
        },
    },
    {
        "key": "network_identifier",
        "label": "网络与设备标识",
        "weight": 0.14,
        "hints": {
            "ip", "src_ip", "srcip", "source_ip", "dst_ip", "dstip",
            "destination_ip", "client_ip", "remote_ip", "ip_address",
            "user_agent", "device_id", "device_type", "browser", "os",
            "mac_address", "imei",
        },
    },
)


_LEVEL_ZH = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
}

_DERIVED_CREDENTIAL_FIELDS = {
    "password_present",
    "password_length",
    "password_strength",
    "weak_password",
    "token_present",
    "token_length",
    "secret_present",
    "secret_length",
    "api_key_present",
    "api_key_length",
    "apikey_present",
    "apikey_length",
}


def _normalize_field(value) -> str:
    return re.sub(r"[^a-z0-9_\u4e00-\u9fff]+", "_", str(value or "").strip().lower()).strip("_")


def _field_matches(field: str, hints: Iterable[str]) -> bool:
    normalized = _normalize_field(field)
    compact = normalized.replace("_", "")
    for hint in hints:
        candidate = _normalize_field(hint)
        candidate_compact = candidate.replace("_", "")
        if normalized == candidate or normalized.endswith("_" + candidate):
            return True
        if len(candidate_compact) >= 5 and candidate_compact in compact:
            return True
    return False


def _is_derived_credential_field(field: str) -> bool:
    normalized = _normalize_field(field)
    return any(
        normalized == derived or normalized.endswith("_" + derived)
        for derived in _DERIVED_CREDENTIAL_FIELDS
    )


def _risk_level(score: float) -> str:
    if score >= 0.80:
        return "critical"
    if score >= 0.58:
        return "high"
    if score >= 0.30:
        return "medium"
    return "low"


def assess_privacy_exposure(columns: List[str], sensitive_columns: List[str], profile: Dict) -> Dict:
    """Return an explainable privacy exposure score without inspecting values."""
    ordered_fields = []
    for field in list(columns or []) + list(sensitive_columns or []):
        name = str(field or "").strip()
        if name and name not in ordered_fields:
            ordered_fields.append(name)

    categories = []
    categorized_fields = set()
    network_hints = next(
        rule["hints"] for rule in _CATEGORY_RULES
        if rule["key"] == "network_identifier"
    )
    for rule in _CATEGORY_RULES:
        matched = [
            field for field in ordered_fields
            if field not in categorized_fields
            and _field_matches(field, rule["hints"])
            and not (
                rule["key"] == "credentials"
                and _is_derived_credential_field(field)
            )
            and not (
                rule["key"] == "contact"
                and _field_matches(field, network_hints)
            )
        ]
        if not matched:
            continue
        categorized_fields.update(matched)
        categories.append({
            "key": rule["key"],
            "label": rule["label"],
            "weight": rule["weight"],
            "fields": matched,
            "field_count": len(matched),
        })

    uncategorized_sensitive = [
        field for field in sensitive_columns or []
        if field not in categorized_fields
    ]
    if uncategorized_sensitive:
        categories.append({
            "key": "other_sensitive",
            "label": "其他敏感字段",
            "weight": 0.18,
            "fields": uncategorized_sensitive,
            "field_count": len(uncategorized_sensitive),
        })
        categorized_fields.update(uncategorized_sensitive)

    field_count = len(categorized_fields)
    column_count = max(int((profile or {}).get("columns") or len(columns or []) or 0), 1)
    row_count = max(int((profile or {}).get("rows") or 0), 0)
    base = max([float(item["weight"]) for item in categories] or [0.0])
    category_bonus = min(0.18, max(0, len(categories) - 1) * 0.06)
    density_bonus = min(0.15, (float(field_count) / column_count) * 0.45)
    volume_bonus = 0.10 if row_count >= 10000 else (0.05 if row_count >= 1000 else 0.0)
    score = round(min(1.0, base + category_bonus + density_bonus + volume_bonus), 4)
    level = _risk_level(score)

    factors = []
    for category in categories:
        factors.append("识别到%s %d 个字段" % (category["label"], category["field_count"]))
    if volume_bonus:
        factors.append("数据规模较大，泄露后的影响范围更广")
    if not factors:
        factors.append("未识别到常见敏感字段，仍建议遵循数据最小化原则")

    if level in ("high", "critical"):
        recommendation = "优先在用户侧提取特征；如需上传，仅发送脱敏摘要或加密归档，并单独确认训练授权。"
        upload_strategy = "local_features_preferred"
    elif level == "medium":
        recommendation = "上传前删除非必要标识符，外部分析 API 只接收脱敏后的统计摘要。"
        upload_strategy = "encrypted_archive_or_features"
    else:
        recommendation = "可使用加密归档，但仍应限制字段和保留期限。"
        upload_strategy = "encrypted_archive"

    return {
        "score": score,
        "level": level,
        "level_zh": _LEVEL_ZH[level],
        "method": "field_policy_rules",
        "policy_version": ANALYSIS_POLICY_VERSION,
        "field_count": field_count,
        "category_count": len(categories),
        "categories": categories,
        "factors": factors,
        "recommendation": recommendation,
        "recommended_upload_strategy": upload_strategy,
        "external_api_payload_policy": "redacted_aggregates_only",
        "is_model_score": False,
    }


def summarize_attack_risk(risk_summary: Dict, average_score: float, total: int) -> Dict:
    """Summarize row-level attack detections into a dataset-level risk view."""
    summary = risk_summary or {}
    total = max(int(total or 0), 0)
    medium = int(summary.get("medium") or 0)
    high = int(summary.get("high") or 0)
    critical = int(summary.get("critical") or 0)
    denominator = max(total, 1)
    priority_count = medium + high + critical
    high_ratio = float(high + critical) / denominator
    priority_ratio = float(priority_count) / denominator
    score = max(float(average_score or 0.0), min(1.0, high_ratio * 1.5 + priority_ratio * 0.35))
    score = round(min(1.0, max(0.0, score)), 4)
    level = _risk_level(score)
    highest_sample_level = (
        "critical" if critical else "high" if high else "medium" if medium else "low"
    )
    return {
        "score": score,
        "level": level,
        "level_zh": _LEVEL_ZH[level],
        "highest_sample_level": highest_sample_level,
        "priority_count": priority_count,
        "priority_ratio": round(priority_ratio, 4),
        "high_or_critical_count": high + critical,
        "high_or_critical_ratio": round(high_ratio, 4),
        "method": "runtime_detector_aggregate",
        "is_model_score": True,
    }


def build_dual_risk_summary(privacy_risk: Dict, attack_risk: Dict) -> Dict:
    """Combine two independent risk axes into a routing recommendation."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    privacy_level = str((privacy_risk or {}).get("level") or "low")
    attack_level = str((attack_risk or {}).get("level") or "low")
    attack_peak_level = str((attack_risk or {}).get("highest_sample_level") or attack_level)
    overall_level = max(
        (privacy_level, attack_level, attack_peak_level),
        key=lambda level: order.get(level, 0),
    )

    if privacy_level in ("high", "critical"):
        action = "优先本地特征分析；确需上传时使用加密归档和受控解密，并禁止向外部 API 发送原始行。"
        route = "local_feature_first"
    elif attack_level in ("high", "critical") or attack_peak_level in ("high", "critical"):
        action = "保留加密证据并优先人工复核高风险样本，暂缓直接进入训练池。"
        route = "encrypted_review_first"
    else:
        action = "可按现有加密归档流程处理，外部解释服务仅使用脱敏统计摘要。"
        route = "encrypted_archive"

    return {
        "privacy_level": privacy_level,
        "attack_level": attack_level,
        "attack_peak_level": attack_peak_level,
        "overall_level": overall_level,
        "overall_level_zh": _LEVEL_ZH.get(overall_level, overall_level),
        "recommended_route": route,
        "recommended_action": action,
        "axes_are_independent": True,
    }
