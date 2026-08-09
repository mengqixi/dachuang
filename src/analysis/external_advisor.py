"""Optional external-AI interpretation for aggregate privacy-risk results.

This module is deliberately isolated from the local detector and training
pipeline.  It only accepts an allow-listed aggregate payload, never uploaded
rows, field values, filenames, user identifiers, IP addresses, or detection
details.  Provider failures therefore cannot change the local analysis result.
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
from datetime import datetime
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from src.utils.atomic_files import atomic_write_bytes, atomic_write_json


EXTERNAL_ADVISOR_INPUT_VERSION = "external-advisor-input-v1"
EXTERNAL_ADVISOR_RESULT_VERSION = "external-advisor-result-v1"
EXTERNAL_ADVISOR_PROMPT_VERSION = "privacy-advisor-zh-v1"
EXTERNAL_PAYLOAD_POLICY = "redacted_aggregates_only"
MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_MODEL = "gpt-5.6-sol"
DEFAULT_MODE = "chat_completions"
ALLOWED_MODES = ("chat_completions", "responses")

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_DEFAULT_SETTINGS_PATH = os.path.join(_PROJECT_ROOT, "data", "keys", "external_ai_settings.json")
_DEFAULT_KEY_PATH = os.path.join(_PROJECT_ROOT, "data", "keys", "external_ai_settings.key")
_SETTINGS_AAD = b"dachuang-external-ai-settings-v1"

_SYSTEM_INSTRUCTIONS = """你是隐私数据安全双模型辅助判定与训练方案选择助手。你只能依据收到的脱敏聚合统计和归一化风险信号工作，不能猜测、还原或索取原始数据、个人身份、IP、账号、字段值或样本明细。必须尊重 payload 中的 evidence_boundaries 和 comparison_fairness：指标口径不同时不得直接宣称某算法更准确；模拟四节点不得表述为真实跨机构联邦；Paillier 展示层未替代实际 FedAvg 权重链路时不得宣称完整密态训练。区分本地确定性事实与 AI 二次判定，不得擅自改写本地风险分数或模型权重。对于样本复核，可以确认、建议升级或要求人工复核，但不能建议降低本地 high/critical 风险。输出一个 JSON 对象，且只能包含 summary、privacy_findings、attack_findings、security_findings、metric_findings、data_quality_findings、federated_tradeoffs、recommended_actions、training_readiness、comparison_verdict、training_advice、comparison_advice、sample_reviews、confidence_note 十四个字段。training_readiness 只能是 ready、review_first、not_recommended、insufficient_information 之一；comparison_verdict 只能是 local_preferred、federated_preferred、tradeoff、not_comparable 之一。sample_reviews 的每项只能包含 rank、assessment、ai_risk_level、ai_confidence、ai_attack_type、reason、recommended_action，其中 assessment 只能是 agree、escalate、review、insufficient。"""


class ExternalAdvisorError(Exception):
    """Base error for the optional external advisor."""


class ExternalAdvisorConfigError(ExternalAdvisorError):
    """Configuration is invalid or incomplete."""


class ExternalAdvisorDisabledError(ExternalAdvisorError):
    """The optional feature is disabled."""


class ExternalAdvisorProviderError(ExternalAdvisorError):
    """The provider could not complete the request."""


class ExternalAdvisorResponseError(ExternalAdvisorError):
    """The provider response did not match the safe result schema."""


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _as_bool(value, default=False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _bounded_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return max(minimum, min(parsed, maximum))


def _safe_model_name(value) -> str:
    model = str(value or DEFAULT_MODEL).strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$", model):
        raise ExternalAdvisorConfigError("模型名称格式无效。")
    return model


def normalize_base_url(value: str, allow_private=False) -> str:
    """Validate and normalize a provider base URL without endpoint suffix."""
    raw = str(value or "").strip()
    if not raw:
        raise ExternalAdvisorConfigError("请配置 API Base URL。")
    if len(raw) > 500:
        raise ExternalAdvisorConfigError("API Base URL 过长。")
    parsed = urlsplit(raw)
    hostname = (parsed.hostname or "").strip().lower()
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ExternalAdvisorConfigError("API Base URL 不能包含账号、查询参数或片段。")
    if not hostname:
        raise ExternalAdvisorConfigError("API Base URL 缺少有效主机名。")
    local_host = hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (allow_private and local_host and parsed.scheme == "http"):
        raise ExternalAdvisorConfigError("API Base URL 必须使用 HTTPS。")
    try:
        literal_ip = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        literal_ip = None
    if literal_ip is not None and not allow_private:
        if (
            literal_ip.is_private
            or literal_ip.is_loopback
            or literal_ip.is_link_local
            or literal_ip.is_multicast
            or literal_ip.is_reserved
            or literal_ip.is_unspecified
        ):
            raise ExternalAdvisorConfigError("API Base URL 不能指向本机或内网地址。")
    path = (parsed.path or "").rstrip("/")
    authority = hostname
    if ":" in hostname and not hostname.startswith("["):
        authority = "[" + hostname + "]"
    try:
        port = parsed.port
    except ValueError:
        raise ExternalAdvisorConfigError("API Base URL 端口格式无效。")
    if port:
        authority += ":%d" % port
    return "%s://%s%s" % (parsed.scheme, authority, path)


def _validate_settings(settings: Dict) -> Dict:
    result = dict(settings or {})
    result["allow_private_base_url"] = _as_bool(result.get("allow_private_base_url"), False)
    result["base_url"] = normalize_base_url(
        result.get("base_url", ""),
        allow_private=result["allow_private_base_url"],
    )
    result["model"] = _safe_model_name(result.get("model"))
    mode = str(result.get("mode") or DEFAULT_MODE).strip().lower()
    if mode not in ALLOWED_MODES:
        raise ExternalAdvisorConfigError("接口模式仅支持 Chat Completions 或 Responses。")
    result["mode"] = mode
    result["timeout_seconds"] = _bounded_int(result.get("timeout_seconds"), 45, 5, 90)
    result["max_output_tokens"] = _bounded_int(result.get("max_output_tokens"), 800, 200, 1600)
    result["calls_per_hour"] = _bounded_int(result.get("calls_per_hour"), 20, 1, 100)
    result["enabled"] = _as_bool(result.get("enabled"), False)
    result["user_enabled"] = _as_bool(result.get("user_enabled"), False)
    api_key = str(result.get("api_key") or "").strip()
    if api_key and (len(api_key) < 8 or len(api_key) > 512 or any(ch.isspace() for ch in api_key)):
        raise ExternalAdvisorConfigError("API Key 格式无效。")
    result["api_key"] = api_key
    return result


def _chmod_private(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class ExternalAdvisorSettingsStore:
    """Encrypted-at-rest settings used by the compact admin dialog."""

    def __init__(self, settings_path=None, key_path=None):
        self.settings_path = settings_path or _DEFAULT_SETTINGS_PATH
        self.key_path = key_path or _DEFAULT_KEY_PATH
        self._lock = threading.RLock()

    def _read_file(self) -> Dict:
        try:
            with open(self.settings_path, "r", encoding="utf-8") as stream:
                value = json.load(stream)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _load_or_create_key(self, create=False) -> Optional[bytes]:
        try:
            with open(self.key_path, "rb") as stream:
                decoded = base64.b64decode(stream.read())
            if len(decoded) == 32:
                return decoded
        except (OSError, ValueError, TypeError):
            pass
        if not create:
            return None
        key = get_random_bytes(32)
        atomic_write_bytes(self.key_path, base64.b64encode(key))
        _chmod_private(self.key_path)
        return key

    def _encrypt_api_key(self, value: str) -> Dict:
        key = self._load_or_create_key(create=True)
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(_SETTINGS_AAD)
        ciphertext, tag = cipher.encrypt_and_digest(value.encode("utf-8"))
        return {
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(cipher.nonce).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def _decrypt_api_key(self, value) -> str:
        if not isinstance(value, dict) or not value.get("ciphertext"):
            return ""
        key = self._load_or_create_key(create=False)
        if key is None:
            raise ExternalAdvisorConfigError("外部 AI 密钥存储不可用，请重新配置 API Key。")
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(value["nonce"]))
            cipher.update(_SETTINGS_AAD)
            plaintext = cipher.decrypt_and_verify(
                base64.b64decode(value["ciphertext"]),
                base64.b64decode(value["tag"]),
            )
            return plaintext.decode("utf-8")
        except Exception:
            raise ExternalAdvisorConfigError("外部 AI 密钥存储校验失败，请重新配置 API Key。")

    def _stored_values(self, include_secret=True) -> Dict:
        raw = self._read_file()
        result = {
            "enabled": _as_bool(raw.get("enabled"), False),
            "user_enabled": _as_bool(raw.get("user_enabled"), False),
            "base_url": str(raw.get("base_url") or "").strip(),
            "model": str(raw.get("model") or DEFAULT_MODEL).strip(),
            "mode": str(raw.get("mode") or DEFAULT_MODE).strip(),
            "timeout_seconds": _bounded_int(raw.get("timeout_seconds"), 45, 5, 90),
            "max_output_tokens": _bounded_int(raw.get("max_output_tokens"), 800, 200, 1600),
            "calls_per_hour": _bounded_int(raw.get("calls_per_hour"), 20, 1, 100),
            "updated_at": str(raw.get("updated_at") or ""),
        }
        if include_secret:
            result["api_key"] = self._decrypt_api_key(raw.get("api_key_encrypted"))
        return result

    @staticmethod
    def _environment_overrides() -> Dict:
        mapping = {
            "enabled": "DACHUANG_EXTERNAL_ANALYSIS_ENABLED",
            "user_enabled": "DACHUANG_EXTERNAL_ANALYSIS_USER_ENABLED",
            "base_url": "DACHUANG_EXTERNAL_ANALYSIS_BASE_URL",
            "api_key": "DACHUANG_EXTERNAL_ANALYSIS_API_KEY",
            "model": "DACHUANG_EXTERNAL_ANALYSIS_MODEL",
            "mode": "DACHUANG_EXTERNAL_ANALYSIS_MODE",
            "timeout_seconds": "DACHUANG_EXTERNAL_ANALYSIS_TIMEOUT_SECONDS",
            "max_output_tokens": "DACHUANG_EXTERNAL_ANALYSIS_MAX_OUTPUT_TOKENS",
            "calls_per_hour": "DACHUANG_EXTERNAL_ANALYSIS_CALLS_PER_HOUR",
            "allow_private_base_url": "DACHUANG_EXTERNAL_ANALYSIS_ALLOW_PRIVATE_BASE_URL",
        }
        return {
            field: os.environ[name]
            for field, name in mapping.items()
            if name in os.environ and str(os.environ.get(name) or "").strip() != ""
        }

    def get_effective(self, require_ready=False) -> Dict:
        with self._lock:
            overrides = self._environment_overrides()
            # A server-managed environment key remains usable even if an old
            # UI-managed encrypted key file is missing or damaged.
            values = self._stored_values(include_secret="api_key" not in overrides)
            values.update(overrides)
            values.setdefault("allow_private_base_url", False)
            values.setdefault("api_key", "")
            managed_fields = sorted(overrides.keys())
            values["managed_fields"] = managed_fields
            values["source"] = (
                "environment" if "api_key" in overrides
                else "admin_ui" if values.get("api_key")
                else "unconfigured"
            )
            if values.get("base_url"):
                values = _validate_settings(values)
            else:
                values["enabled"] = _as_bool(values.get("enabled"), False)
                values["user_enabled"] = _as_bool(values.get("user_enabled"), False)
                values["model"] = _safe_model_name(values.get("model"))
                values["mode"] = str(values.get("mode") or DEFAULT_MODE).strip().lower()
                values["timeout_seconds"] = _bounded_int(values.get("timeout_seconds"), 45, 5, 90)
                values["max_output_tokens"] = _bounded_int(values.get("max_output_tokens"), 800, 200, 1600)
                values["calls_per_hour"] = _bounded_int(values.get("calls_per_hour"), 20, 1, 100)
                values["api_key"] = str(values.get("api_key") or "").strip()
            values["configured"] = bool(values.get("base_url") and values.get("model") and values.get("api_key"))
            values["ready"] = bool(values.get("enabled") and values.get("configured"))
            if require_ready:
                if not values.get("enabled"):
                    raise ExternalAdvisorDisabledError("外部 AI 脱敏解读尚未启用。")
                if not values.get("configured"):
                    raise ExternalAdvisorConfigError("外部 AI 接口尚未完成配置。")
            return values

    def candidate(self, patch: Dict) -> Dict:
        values = self.get_effective(require_ready=False)
        candidate = {
            key: values.get(key)
            for key in (
                "enabled", "user_enabled", "base_url", "api_key", "model", "mode",
                "timeout_seconds", "max_output_tokens", "calls_per_hour", "allow_private_base_url",
            )
        }
        patch = patch if isinstance(patch, dict) else {}
        for key in ("enabled", "user_enabled", "base_url", "model", "mode", "timeout_seconds"):
            if key in patch:
                candidate[key] = patch.get(key)
        supplied_key = str(patch.get("api_key") or "").strip() if "api_key" in patch else ""
        if supplied_key:
            candidate["api_key"] = supplied_key
        if _as_bool(patch.get("clear_api_key"), False):
            candidate["api_key"] = ""
        return _validate_settings(candidate)

    def save(self, patch: Dict) -> Dict:
        with self._lock:
            candidate = self.candidate(patch)
            current_raw = self._read_file()
            supplied_key = str((patch or {}).get("api_key") or "").strip()
            clear_key = _as_bool((patch or {}).get("clear_api_key"), False)
            encrypted_key = current_raw.get("api_key_encrypted")
            if supplied_key:
                encrypted_key = self._encrypt_api_key(candidate["api_key"])
            elif clear_key:
                encrypted_key = None
            output = {
                "version": 1,
                "enabled": bool(candidate["enabled"]),
                "user_enabled": bool(candidate["user_enabled"]),
                "base_url": candidate["base_url"],
                "model": candidate["model"],
                "mode": candidate["mode"],
                "timeout_seconds": candidate["timeout_seconds"],
                "max_output_tokens": candidate["max_output_tokens"],
                "calls_per_hour": candidate["calls_per_hour"],
                "updated_at": _now(),
            }
            if encrypted_key:
                output["api_key_encrypted"] = encrypted_key
            atomic_write_json(self.settings_path, output)
            _chmod_private(self.settings_path)
            return self.get_effective(require_ready=False)

    @staticmethod
    def public_status(settings: Dict, secret_input_allowed=True) -> Dict:
        settings = settings or {}
        key = str(settings.get("api_key") or "")
        mode = str(settings.get("mode") or DEFAULT_MODE)
        return {
            "enabled": bool(settings.get("enabled")),
            "user_enabled": bool(settings.get("user_enabled")),
            "configured": bool(settings.get("configured") or (
                settings.get("base_url") and settings.get("model") and key
            )),
            "ready": bool(settings.get("ready") or (
                settings.get("enabled") and settings.get("base_url") and settings.get("model") and key
            )),
            "base_url": str(settings.get("base_url") or ""),
            "model": str(settings.get("model") or DEFAULT_MODEL),
            "mode": mode,
            "endpoint_path": "/responses" if mode == "responses" else "/chat/completions",
            "timeout_seconds": int(settings.get("timeout_seconds") or 45),
            "calls_per_hour": int(settings.get("calls_per_hour") or 20),
            "api_key_configured": bool(key),
            "api_key_masked": ("****" + key[-4:]) if key else "",
            "source": str(settings.get("source") or "unconfigured"),
            "managed_fields": list(settings.get("managed_fields") or []),
            "updated_at": str(settings.get("updated_at") or ""),
            "secret_input_allowed": bool(secret_input_allowed),
            "payload_policy": EXTERNAL_PAYLOAD_POLICY,
        }


def _number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _count(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _bounded_count_map(value, limit=20) -> Dict:
    if not isinstance(value, dict):
        return {}
    output = {}
    for key in sorted(value.keys(), key=lambda item: str(item))[:limit]:
        label = re.sub(r"[\x00-\x1f\x7f]+", " ", str(key or "")).strip()[:80]
        if label:
            output[label] = _count(value.get(key))
    return output


def build_redacted_analysis_payload(analysis: Dict) -> Dict:
    """Build the only payload shape permitted to leave this application."""
    analysis = analysis if isinstance(analysis, dict) else {}
    privacy = analysis.get("privacy_risk") if isinstance(analysis.get("privacy_risk"), dict) else {}
    attack = analysis.get("attack_risk") if isinstance(analysis.get("attack_risk"), dict) else {}
    dual = analysis.get("dual_risk") if isinstance(analysis.get("dual_risk"), dict) else {}
    trace = analysis.get("analysis_trace") if isinstance(analysis.get("analysis_trace"), dict) else {}
    profile = analysis.get("profile") if isinstance(analysis.get("profile"), dict) else {}
    categories = []
    for item in privacy.get("categories", []) if isinstance(privacy.get("categories"), list) else []:
        if not isinstance(item, dict):
            continue
        categories.append({
            "key": str(item.get("key") or "")[:50],
            "label": str(item.get("label") or "")[:50],
            "field_count": _count(item.get("field_count")),
        })
        if len(categories) >= 10:
            break
    review_candidates = []
    ranking = analysis.get("risk_ranking") or analysis.get("high_risk_reasons") or []
    for item in ranking if isinstance(ranking, list) else []:
        if not isinstance(item, dict):
            continue
        breakdown = item.get("score_breakdown") if isinstance(item.get("score_breakdown"), dict) else {}
        component_scores = {}
        for key in (
            "model_score", "failed_attempts_score", "request_frequency_score",
            "unusual_time_score", "response_time_score", "device_ip_score",
        ):
            if key in breakdown:
                component_scores[key] = round(max(0.0, min(1.0, _number(breakdown.get(key)))), 4)
        triggers = []
        for trigger in item.get("trigger_features", []) if isinstance(item.get("trigger_features"), list) else []:
            cleaned = _clean_text(trigger, 60)
            if cleaned:
                triggers.append(cleaned)
            if len(triggers) >= 5:
                break
        review_candidates.append({
            # Rank is a request-local ordinal.  The original sample id is
            # deliberately omitted so the provider cannot link a person/row.
            "rank": len(review_candidates) + 1,
            "local_risk_score": round(max(0.0, min(1.0, _number(item.get("risk_score")))), 4),
            "local_risk_level": _clean_text(item.get("risk_level"), 20),
            "attack_type": _clean_text(item.get("attack_type"), 60),
            "confidence": round(max(0.0, min(1.0, _number(item.get("confidence")))), 4),
            "trigger_signals": triggers,
            "dominant_signal": _clean_text(item.get("dominant_factor"), 60),
            "component_scores": component_scores,
        })
        if len(review_candidates) >= 12:
            break
    return {
        "schema_version": EXTERNAL_ADVISOR_INPUT_VERSION,
        "analysis_kind": "dataset_security",
        "payload_policy": EXTERNAL_PAYLOAD_POLICY,
        "analysis_scope": {
            "analyzed_rows": _count(trace.get("analyzed_rows", analysis.get("total"))),
            "source_rows": _count(trace.get("source_rows")),
            "source_rows_exact": bool(trace.get("source_rows_exact")),
            "scope": str(trace.get("scope") or "unknown")[:40],
        },
        "privacy_risk": {
            "score": round(_number(privacy.get("score")), 4),
            "level": str(privacy.get("level") or "unknown")[:20],
            "field_count": _count(privacy.get("field_count")),
            "category_count": _count(privacy.get("category_count")),
            "categories": categories,
            "method": str(privacy.get("method") or "")[:60],
            "is_model_score": bool(privacy.get("is_model_score")),
        },
        "attack_risk": {
            "score": round(_number(attack.get("score")), 4),
            "level": str(attack.get("level") or "unknown")[:20],
            "highest_sample_level": str(attack.get("highest_sample_level") or "unknown")[:20],
            "priority_count": _count(attack.get("priority_count")),
            "priority_ratio": round(_number(attack.get("priority_ratio")), 4),
            "high_or_critical_count": _count(attack.get("high_or_critical_count")),
            "high_or_critical_ratio": round(_number(attack.get("high_or_critical_ratio")), 4),
            "method": str(attack.get("method") or "")[:60],
            "is_model_score": bool(attack.get("is_model_score")),
        },
        "risk_counts": _bounded_count_map(analysis.get("risk_summary"), limit=8),
        "attack_type_counts": _bounded_count_map(analysis.get("attack_types"), limit=20),
        "risk_score_distribution": _bounded_count_map(analysis.get("risk_score_distribution"), limit=12),
        "trigger_signal_counts": _bounded_count_map(analysis.get("trigger_feature_stats"), limit=20),
        "data_quality": {
            "rows": _count(profile.get("rows")),
            "columns": _count(profile.get("columns")),
            "missing_cells": _count(profile.get("missing_cells")),
            "missing_rate": round(max(0.0, min(1.0, _number(profile.get("missing_rate")))), 4),
            "numeric_columns": _count(profile.get("numeric_columns")),
        },
        "review_candidates": review_candidates,
        "dual_risk": {
            "privacy_level": str(dual.get("privacy_level") or "unknown")[:20],
            "attack_level": str(dual.get("attack_level") or "unknown")[:20],
            "attack_peak_level": str(dual.get("attack_peak_level") or "unknown")[:20],
            "overall_level": str(dual.get("overall_level") or "unknown")[:20],
            "recommended_route": str(dual.get("recommended_route") or "")[:60],
            "axes_are_independent": bool(dual.get("axes_are_independent", True)),
        },
        "versions": {
            "analysis_api": str(trace.get("api_version") or "")[:40],
            "preprocessing": str(trace.get("preprocessing_version") or "")[:80],
            "detector_model": str(trace.get("model_version") or "")[:100],
            "analysis_policy": str(trace.get("analysis_policy_version") or "")[:80],
        },
        "evidence_boundaries": {
            "raw_rows_included": False,
            "identifiers_included": False,
            "field_values_included": False,
            "candidate_signals_are_normalized": True,
            "ai_may_override_local_score": False,
            "ai_may_change_model_weights": False,
            "ai_role": "second_review_and_improvement_advice",
        },
    }


def _dict_value(value) -> Dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


def _optional_number(value):
    if value is None or value == "":
        return None
    try:
        parsed = float(value)
        if parsed != parsed or parsed in (float("inf"), float("-inf")):
            return None
        return round(parsed, 6)
    except (TypeError, ValueError):
        return None


def _merged_training_task(task: Dict) -> Dict:
    task = task if isinstance(task, dict) else {}
    metadata = _dict_value(task.get("metadata"))
    nested = _dict_value(metadata.get("metadata"))
    merged = {}
    merged.update(metadata)
    merged.update(nested)
    merged.update(task)
    return merged


def _client_metric_summary(value) -> Dict:
    clients = value if isinstance(value, list) else []
    rows = []
    for item in clients:
        if not isinstance(item, dict):
            continue
        samples = _count(item.get("samples"))
        accuracy = _optional_number(item.get("accuracy"))
        loss = _optional_number(item.get("loss"))
        rows.append({"samples": samples, "accuracy": accuracy, "loss": loss})
    if not rows:
        return {"node_count": 0, "samples": 0, "weighted_accuracy": None, "weighted_loss": None}
    total = sum(item["samples"] for item in rows)

    def weighted(key):
        usable = [item for item in rows if item[key] is not None]
        denominator = sum(item["samples"] for item in usable)
        if denominator > 0:
            return round(sum(item[key] * item["samples"] for item in usable) / denominator, 6)
        if usable:
            return round(sum(item[key] for item in usable) / len(usable), 6)
        return None

    accuracy_values = [item["accuracy"] for item in rows if item["accuracy"] is not None]
    loss_values = [item["loss"] for item in rows if item["loss"] is not None]
    return {
        "node_count": len(rows),
        "samples": total,
        "weighted_accuracy": weighted("accuracy"),
        "weighted_loss": weighted("loss"),
        "accuracy_min": min(accuracy_values) if accuracy_values else None,
        "accuracy_max": max(accuracy_values) if accuracy_values else None,
        "loss_min": min(loss_values) if loss_values else None,
        "loss_max": max(loss_values) if loss_values else None,
    }


def _training_task_payload(task: Dict, task_kind: str) -> Dict:
    merged = _merged_training_task(task)
    clients = _client_metric_summary(merged.get("clients"))
    accuracy = _optional_number(
        merged.get("accuracy")
        if merged.get("accuracy") is not None
        else merged.get("avg_accuracy")
    )
    if task_kind == "federated" and clients.get("weighted_accuracy") is not None:
        accuracy = _optional_number(merged.get("avg_accuracy")) or clients.get("weighted_accuracy")
    paillier = merged.get("paillier") if isinstance(merged.get("paillier"), dict) else {}
    return {
        "training_type": task_kind,
        "algorithm": _clean_text(
            merged.get("algorithm") or ("fedavg" if task_kind == "federated" else "ensemble_detector"),
            80,
        ),
        "metrics": {
            "accuracy": accuracy,
            "precision": _optional_number(merged.get("precision")),
            "recall": _optional_number(merged.get("recall")),
            "f1": _optional_number(merged.get("f1", merged.get("f1_score"))),
            "loss": clients.get("weighted_loss") if task_kind == "federated" else _optional_number(merged.get("loss")),
            "metric_scope": _clean_text(merged.get("metric_scope"), 80),
            "metric_label": _clean_text(merged.get("metric_label"), 100),
            "validation_available": bool(merged.get("validation_available")),
        },
        "data_summary": {
            "samples": _count(merged.get("samples")),
            "source_samples": _count(merged.get("source_samples")),
            "label_distribution": _bounded_count_map(merged.get("label_distribution"), limit=10),
            "node_count": _count(merged.get("node_count")) or (clients.get("node_count") if task_kind == "federated" else 1),
        },
        "training_process": {
            "epochs": _count(merged.get("epochs")),
            "rounds": _count(merged.get("rounds", merged.get("round"))),
            "uses_prepared_nodes": bool(merged.get("uses_prepared_nodes")),
            "node_metric_summary": clients if task_kind == "federated" else {},
        },
        "aggregation": {
            "method": _clean_text(merged.get("aggregation_method"), 60) if task_kind == "federated" else "centralized",
            "paillier_demo_enabled": bool(paillier.get("paillier_enabled")),
            "timing_method": _clean_text(paillier.get("timing_method"), 60),
            "actual_crypto_operations_performed": bool(paillier.get("actual_crypto_operations_performed")),
            "encryption_time_ms": _optional_number(paillier.get("encryption_time_ms")),
            "aggregation_time_ms": _optional_number(paillier.get("aggregation_time_ms")),
            "decryption_time_ms": _optional_number(paillier.get("decryption_time_ms")),
            "encrypted_parameter_count": _count(paillier.get("encrypted_parameter_count")),
        },
        # These values are used only for same-revision checks below and are
        # removed from the outbound object before it is returned.
        "_dataset_revision": str(merged.get("dataset_revision") or ""),
        "_preparation_id": str(merged.get("preparation_id") or ""),
        "_dataset_source_id": str(merged.get("dataset_source_id") or ""),
    }


def build_redacted_training_comparison_payload(local_task: Dict, federated_task: Dict) -> Dict:
    """Build an aggregate-only comparison of current production training paths."""
    local = _training_task_payload(local_task, "local")
    federated = _training_task_payload(federated_task, "federated")
    local_metrics = local["metrics"]
    federated_metrics = federated["metrics"]

    same_revision = bool(
        local.get("_dataset_revision")
        and local.get("_dataset_revision") == federated.get("_dataset_revision")
    )
    same_preparation = bool(
        local.get("_preparation_id")
        and local.get("_preparation_id") == federated.get("_preparation_id")
    )
    same_source = bool(
        local.get("_dataset_source_id")
        and local.get("_dataset_source_id") == federated.get("_dataset_source_id")
    )
    same_metric_scope = bool(
        local_metrics.get("metric_scope")
        and local_metrics.get("metric_scope") == federated_metrics.get("metric_scope")
    )
    direct_ranking_allowed = bool(
        same_revision
        and same_source
        and same_metric_scope
        and local_metrics.get("validation_available")
        and federated_metrics.get("validation_available")
    )

    def delta(key, multiplier=1.0):
        left = local_metrics.get(key)
        right = federated_metrics.get(key)
        if left is None or right is None:
            return None
        return round((right - left) * multiplier, 6)

    for private_key in ("_dataset_revision", "_preparation_id", "_dataset_source_id"):
        local.pop(private_key, None)
        federated.pop(private_key, None)

    return {
        "schema_version": EXTERNAL_ADVISOR_INPUT_VERSION,
        "analysis_kind": "training_security_comparison",
        "payload_policy": EXTERNAL_PAYLOAD_POLICY,
        "local_training": local,
        "federated_training": federated,
        "deterministic_differences": {
            "federated_minus_local_accuracy_percentage_points": delta("accuracy", 100.0),
            "federated_minus_local_precision_percentage_points": delta("precision", 100.0),
            "federated_minus_local_recall_percentage_points": delta("recall", 100.0),
            "federated_minus_local_f1_percentage_points": delta("f1", 100.0),
            "federated_minus_local_loss": delta("loss", 1.0),
            "federated_minus_local_samples": (
                federated["data_summary"]["samples"] - local["data_summary"]["samples"]
            ),
        },
        "comparison_fairness": {
            "same_dataset_source": same_source,
            "same_dataset_revision": same_revision,
            "same_preparation_revision": same_preparation,
            "same_sample_count": local["data_summary"]["samples"] == federated["data_summary"]["samples"],
            "same_metric_scope": same_metric_scope,
            "direct_accuracy_ranking_allowed": direct_ranking_allowed,
            "reason_if_not_directly_comparable": (
                "两种训练结果的指标范围或验证方式不同，只能描述数值差异，不能直接判定算法优劣。"
                if not direct_ranking_allowed else "指标来源一致，可在该数据修订内进行有限对比。"
            ),
        },
        "security_architecture": {
            "archive_at_rest": "AES-256-GCM",
            "local_training": {
                "centralized_server_access": True,
                "temporary_plaintext_in_server_memory": True,
                "node_isolation": False,
                "runtime_model_can_be_updated": True,
            },
            "federated_training": {
                "prepared_node_partitions": True,
                "simulated_nodes_on_single_host": True,
                "real_cross_institution_network": False,
                "model_updates_aggregated": True,
                "actual_weight_aggregation": "FedAvg",
                "actual_weight_secure_aggregation": False,
                "paillier_is_measurement_demo_layer": bool(federated["aggregation"].get("paillier_demo_enabled")),
                "paillier_timings_are_estimates": (
                    federated["aggregation"].get("timing_method") == "parameter_count_estimate"
                ),
                "actual_paillier_crypto_operations_performed": bool(
                    federated["aggregation"].get("actual_crypto_operations_performed")
                ),
                "paillier_replaces_actual_weight_path": False,
                "automatically_replaces_runtime_detector": False,
            },
        },
        "evidence_boundaries": {
            "raw_rows_included": False,
            "identifiers_included": False,
            "field_values_included": False,
            "independent_external_test_set_available": bool(
                direct_ranking_allowed
                and local_metrics.get("metric_scope") == "external_test"
            ),
            "ai_may_override_metrics": False,
            "ai_may_change_model_weights": False,
            "ai_role": "security_review_comparison_and_improvement_advice",
        },
    }


def canonical_fingerprint(value: Dict) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def settings_fingerprint(settings: Dict) -> str:
    return canonical_fingerprint({
        "base_url": str(settings.get("base_url") or ""),
        "model": str(settings.get("model") or ""),
        "mode": str(settings.get("mode") or ""),
        "prompt_version": EXTERNAL_ADVISOR_PROMPT_VERSION,
    })


def external_cache_key(payload: Dict, settings: Dict) -> str:
    return canonical_fingerprint({
        "payload": payload,
        "settings_fingerprint": settings_fingerprint(settings),
    })


def _clean_text(value, maximum: int) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+", " ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:maximum]


def _clean_list(value, maximum_items: int, maximum_length: int) -> List[str]:
    if not isinstance(value, list):
        return []
    output = []
    for item in value:
        if isinstance(item, (dict, list)):
            continue
        cleaned = _clean_text(item, maximum_length)
        if cleaned:
            output.append(cleaned)
        if len(output) >= maximum_items:
            break
    return output


def _clean_sample_reviews(value) -> List[Dict]:
    if not isinstance(value, list):
        return []
    output = []
    seen_ranks = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            rank = int(item.get("rank"))
        except (TypeError, ValueError):
            continue
        if rank < 1 or rank > 12:
            continue
        if rank in seen_ranks:
            continue
        seen_ranks.add(rank)
        assessment = _clean_text(item.get("assessment"), 20).lower()
        if assessment not in {"agree", "escalate", "review", "insufficient"}:
            assessment = "insufficient"
        level = _clean_text(item.get("ai_risk_level"), 20).lower()
        if level not in {"low", "medium", "high", "critical", "unknown"}:
            level = "unknown"
        output.append({
            "rank": rank,
            "assessment": assessment,
            "ai_risk_level": level,
            "ai_confidence": round(max(0.0, min(1.0, _number(item.get("ai_confidence")))), 4),
            "ai_attack_type": _clean_text(item.get("ai_attack_type"), 80),
            "reason": _clean_text(item.get("reason"), 400),
            "recommended_action": _clean_text(item.get("recommended_action"), 300),
        })
        if len(output) >= 12:
            break
    output.sort(key=lambda item: item["rank"])
    return output


def validate_advice(value: Dict) -> Dict:
    if not isinstance(value, dict):
        raise ExternalAdvisorResponseError("外部分析结果不是有效 JSON 对象。")
    readiness = _clean_text(value.get("training_readiness"), 40).lower()
    if readiness not in {"ready", "review_first", "not_recommended", "insufficient_information"}:
        readiness = "insufficient_information"
    verdict = _clean_text(value.get("comparison_verdict"), 40).lower()
    if verdict not in {"local_preferred", "federated_preferred", "tradeoff", "not_comparable"}:
        verdict = "not_comparable"
    result = {
        "summary": _clean_text(value.get("summary"), 800),
        "privacy_findings": _clean_list(value.get("privacy_findings"), 5, 300),
        "attack_findings": _clean_list(value.get("attack_findings"), 5, 300),
        "security_findings": _clean_list(value.get("security_findings"), 6, 300),
        "metric_findings": _clean_list(value.get("metric_findings"), 6, 300),
        "data_quality_findings": _clean_list(value.get("data_quality_findings"), 5, 300),
        "federated_tradeoffs": _clean_list(value.get("federated_tradeoffs"), 6, 300),
        "recommended_actions": _clean_list(value.get("recommended_actions"), 6, 300),
        "training_readiness": readiness,
        "comparison_verdict": verdict,
        "training_advice": _clean_text(value.get("training_advice"), 600),
        "comparison_advice": _clean_text(value.get("comparison_advice"), 600),
        "sample_reviews": _clean_sample_reviews(value.get("sample_reviews")),
        "confidence_note": _clean_text(value.get("confidence_note"), 400),
    }
    if not result["summary"]:
        raise ExternalAdvisorResponseError("外部分析结果缺少摘要。")
    if not result["confidence_note"]:
        result["confidence_note"] = "该内容仅解释脱敏聚合统计，不替代本地检测结果或人工复核。"
    return result


def _strip_json_fence(text: str) -> str:
    value = str(text or "").strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*", "", value, flags=re.IGNORECASE)
        value = re.sub(r"\s*```$", "", value)
    first = value.find("{")
    last = value.rfind("}")
    if first >= 0 and last > first:
        value = value[first:last + 1]
    return value.strip()


def _content_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for block in value:
            if not isinstance(block, dict):
                continue
            text = block.get("text") or block.get("output_text")
            if isinstance(text, dict):
                text = text.get("value")
            if isinstance(text, str):
                parts.append(text)
        return "\n".join(parts)
    return ""


def extract_provider_text(response_json: Dict, mode: str) -> str:
    if not isinstance(response_json, dict):
        return ""
    if mode == "responses":
        direct = response_json.get("output_text")
        if isinstance(direct, str) and direct.strip():
            return direct
        parts = []
        output = response_json.get("output")
        for item in output if isinstance(output, list) else []:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            for block in content if isinstance(content, list) else []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") in ("output_text", "text"):
                    text = _content_text(block.get("text") or block.get("output_text"))
                    if text:
                        parts.append(text)
        return "\n".join(parts)
    choices = response_json.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            return _content_text(message.get("content"))
    return ""


def parse_provider_advice(response_json: Dict, mode: str) -> Dict:
    text = extract_provider_text(response_json, mode)
    if not text:
        raise ExternalAdvisorResponseError("外部分析服务未返回可读取文本。")
    try:
        value = json.loads(_strip_json_fence(text))
    except (TypeError, ValueError):
        raise ExternalAdvisorResponseError("外部分析服务未返回约定的 JSON 结果。")
    return validate_advice(value)


def _usage_summary(value) -> Dict:
    if not isinstance(value, dict):
        return {}
    aliases = {
        "input_tokens": ("input_tokens", "prompt_tokens"),
        "output_tokens": ("output_tokens", "completion_tokens"),
        "total_tokens": ("total_tokens",),
    }
    output = {}
    for target, names in aliases.items():
        for name in names:
            if name in value:
                output[target] = _count(value.get(name))
                break
    return output


def _safe_request_id(headers) -> str:
    for name in ("x-request-id", "request-id", "openai-request-id"):
        try:
            value = headers.get(name)
        except AttributeError:
            value = None
        if value:
            return re.sub(r"[^A-Za-z0-9._:-]", "", str(value))[:120]
    return ""


def enforce_advice_boundaries(payload: Dict, advice: Dict):
    """Apply deterministic local safety rules to untrusted AI output."""
    payload = payload if isinstance(payload, dict) else {}
    result = validate_advice(advice)
    guards = []
    analysis_kind = str(payload.get("analysis_kind") or "dataset_security")

    if analysis_kind == "training_security_comparison":
        fairness = payload.get("comparison_fairness")
        fairness = fairness if isinstance(fairness, dict) else {}
        if (
            not fairness.get("direct_accuracy_ranking_allowed")
            and result.get("comparison_verdict") in {"local_preferred", "federated_preferred"}
        ):
            result["comparison_verdict"] = "not_comparable"
            guards.append("incomparable_metrics_cannot_select_a_preferred_model")
    elif analysis_kind == "dataset_security":
        levels = []
        for section_name in ("privacy_risk", "attack_risk", "dual_risk"):
            section = payload.get(section_name)
            if not isinstance(section, dict):
                continue
            for key in ("level", "highest_sample_level", "attack_peak_level", "overall_level"):
                value = str(section.get(key) or "").lower()
                if value:
                    levels.append(value)
        if (
            any(level in {"high", "critical"} for level in levels)
            and result.get("training_readiness") == "ready"
        ):
            result["training_readiness"] = "review_first"
            guards.append("high_local_risk_requires_review_before_training")

    return result, guards


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_resolved_host(url: str, allow_private=False) -> None:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    try:
        addresses = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ExternalAdvisorProviderError("无法解析外部分析服务地址。")
    if not addresses:
        raise ExternalAdvisorProviderError("无法解析外部分析服务地址。")
    if allow_private:
        return
    for item in addresses:
        address = str(item[4][0]).split("%", 1)[0]
        try:
            ip_value = ipaddress.ip_address(address)
        except ValueError:
            raise ExternalAdvisorProviderError("外部分析服务地址解析结果无效。")
        if (
            ip_value.is_private
            or ip_value.is_loopback
            or ip_value.is_link_local
            or ip_value.is_multicast
            or ip_value.is_reserved
            or ip_value.is_unspecified
        ):
            raise ExternalAdvisorProviderError("外部分析服务地址不能解析到本机或内网。")


def _default_transport(url: str, body: bytes, headers: Dict, timeout: int, allow_private=False):
    _validate_resolved_host(url, allow_private=allow_private)
    request = Request(url, data=body, headers=headers, method="POST")
    opener = build_opener(_NoRedirectHandler())
    try:
        response = opener.open(request, timeout=timeout)
        try:
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ExternalAdvisorProviderError("外部分析服务响应过大。")
            return int(response.getcode() or 200), response.headers, data
        finally:
            response.close()
    except HTTPError as error:
        raise ExternalAdvisorProviderError("外部分析服务返回 HTTP %s。" % int(error.code or 502))
    except (URLError, socket.timeout, TimeoutError):
        raise ExternalAdvisorProviderError("外部分析服务连接失败或超时。")


class ExternalAdvisorClient:
    """Small OpenAI-compatible HTTP client with a bounded response surface."""

    def __init__(self, settings: Dict, transport=None):
        self.settings = _validate_settings(settings)
        if not self.settings.get("enabled"):
            raise ExternalAdvisorDisabledError("外部 AI 脱敏解读尚未启用。")
        if not self.settings.get("api_key"):
            raise ExternalAdvisorConfigError("外部 AI 接口尚未配置 API Key。")
        self.transport = transport

    def _request_body(self, payload: Dict) -> Dict:
        analysis_kind = str(payload.get("analysis_kind") or "dataset_security")
        if analysis_kind == "training_security_comparison":
            task = "依据实际训练记录，对普通训练与联邦训练的判定能力、安全边界和适用性进行对比，给出当前平台应采用的方案判断。"
        else:
            task = "对本地检测模型的脱敏风险信号进行第二判定，帮助用户得到更可靠的综合风险结论，并解释隐私与攻击风险。"
        user_input = json.dumps({
            "task": task,
            "output_schema": {
                "summary": "string",
                "privacy_findings": ["string"],
                "attack_findings": ["string"],
                "security_findings": ["string"],
                "metric_findings": ["string"],
                "data_quality_findings": ["string"],
                "federated_tradeoffs": ["string"],
                "recommended_actions": ["string"],
                "training_readiness": "ready | review_first | not_recommended | insufficient_information",
                "comparison_verdict": "local_preferred | federated_preferred | tradeoff | not_comparable",
                "training_advice": "string",
                "comparison_advice": "string",
                "sample_reviews": [{
                    "rank": "integer 1..12",
                    "assessment": "agree | escalate | review | insufficient",
                    "ai_risk_level": "low | medium | high | critical | unknown",
                    "ai_confidence": "number 0..1",
                    "ai_attack_type": "string",
                    "reason": "string",
                    "recommended_action": "string",
                }],
                "confidence_note": "string",
            },
            "aggregate_analysis": payload,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        common = {
            "model": self.settings["model"],
            "store": False,
        }
        if self.settings["mode"] == "responses":
            common.update({
                "instructions": _SYSTEM_INSTRUCTIONS,
                "input": user_input,
                "max_output_tokens": self.settings["max_output_tokens"],
            })
        else:
            common.update({
                "messages": [
                    {"role": "system", "content": _SYSTEM_INSTRUCTIONS},
                    {"role": "user", "content": user_input},
                ],
                "max_completion_tokens": self.settings["max_output_tokens"],
            })
        return common

    def analyze(self, payload: Dict) -> Dict:
        if not isinstance(payload, dict) or payload.get("payload_policy") != EXTERNAL_PAYLOAD_POLICY:
            raise ExternalAdvisorConfigError("外部分析仅接受经过白名单构建的脱敏聚合载荷。")
        endpoint = "/responses" if self.settings["mode"] == "responses" else "/chat/completions"
        url = self.settings["base_url"].rstrip("/") + endpoint
        body = json.dumps(self._request_body(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": "Bearer " + self.settings["api_key"],
            "User-Agent": "Dachuang-Privacy-Advisor/1.0",
        }
        if self.transport is None:
            status, response_headers, raw = _default_transport(
                url,
                body,
                headers,
                self.settings["timeout_seconds"],
                allow_private=self.settings.get("allow_private_base_url", False),
            )
        else:
            status, response_headers, raw = self.transport(
                url,
                body,
                headers,
                self.settings["timeout_seconds"],
            )
        if int(status or 0) < 200 or int(status or 0) >= 300:
            raise ExternalAdvisorProviderError("外部分析服务返回 HTTP %s。" % int(status or 502))
        if len(raw or b"") > MAX_RESPONSE_BYTES:
            raise ExternalAdvisorProviderError("外部分析服务响应过大。")
        try:
            response_json = json.loads((raw or b"").decode("utf-8"))
        except (UnicodeDecodeError, ValueError, TypeError):
            raise ExternalAdvisorResponseError("外部分析服务返回内容无法解析。")
        advice = parse_provider_advice(response_json, self.settings["mode"])
        return {
            "advice": advice,
            "usage": _usage_summary(response_json.get("usage")),
            "provider_request_id": _safe_request_id(response_headers),
        }


def make_external_analysis_record(payload: Dict, settings: Dict, provider_result: Dict) -> Dict:
    advice, boundary_guards = enforce_advice_boundaries(
        payload,
        (provider_result or {}).get("advice"),
    )
    return {
        "schema_version": EXTERNAL_ADVISOR_RESULT_VERSION,
        "analysis_kind": str(payload.get("analysis_kind") or "dataset_security"),
        "generated_at": _now(),
        "model": str(settings.get("model") or DEFAULT_MODEL),
        "mode": str(settings.get("mode") or DEFAULT_MODE),
        "prompt_version": EXTERNAL_ADVISOR_PROMPT_VERSION,
        "payload_policy": EXTERNAL_PAYLOAD_POLICY,
        "input_fingerprint": external_cache_key(payload, settings),
        "settings_fingerprint": settings_fingerprint(settings),
        "cache_reused": False,
        "advice": advice,
        "boundary_guards": boundary_guards,
        "usage": _usage_summary((provider_result or {}).get("usage")),
        "provider_request_id": _safe_request_id({
            "x-request-id": (provider_result or {}).get("provider_request_id", ""),
        }),
    }


def build_ai_assisted_decisions(analysis: Dict, advice: Dict) -> Dict:
    """Fuse local and AI second opinions with a conservative safety policy.

    The local model remains authoritative.  AI may confirm a result or raise a
    review priority, but it can never lower the local level.  No local score is
    rewritten and conflicts are made explicit to the user.
    """
    analysis = analysis if isinstance(analysis, dict) else {}
    advice = advice if isinstance(advice, dict) else {}
    ranking = analysis.get("risk_ranking") or analysis.get("high_risk_reasons") or []
    ranking = ranking if isinstance(ranking, list) else []
    local_by_rank = {
        index + 1: item
        for index, item in enumerate(ranking[:12])
        if isinstance(item, dict)
    }
    reviews = _clean_sample_reviews(advice.get("sample_reviews"))
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": -1}
    level_zh = {"low": "低", "medium": "中", "high": "高", "critical": "严重", "unknown": "未知"}
    items = []
    counters = {
        "reviewed": 0,
        "agreed": 0,
        "ai_escalated": 0,
        "conflicts": 0,
        "insufficient": 0,
    }
    for review in reviews:
        local = local_by_rank.get(review.get("rank"))
        if not local:
            continue
        local_level = str(local.get("risk_level") or "low").lower()
        if local_level not in order:
            local_level = "low"
        ai_level = str(review.get("ai_risk_level") or "unknown").lower()
        if ai_level not in order:
            ai_level = "unknown"
        assessment = str(review.get("assessment") or "insufficient")
        confidence = round(max(0.0, min(1.0, _number(review.get("ai_confidence")))), 4)
        combined_level = local_level
        decision_status = "local_preserved"
        needs_manual_review = False
        counters["reviewed"] += 1
        if ai_level == "unknown" or assessment == "insufficient":
            counters["insufficient"] += 1
            decision_status = "ai_insufficient_local_preserved"
        elif order[ai_level] > order[local_level] and confidence >= 0.55:
            combined_level = ai_level
            decision_status = "ai_escalated_review"
            needs_manual_review = True
            counters["ai_escalated"] += 1
        elif ai_level == local_level and assessment == "agree":
            decision_status = "local_ai_agree"
            counters["agreed"] += 1
        elif ai_level != local_level or assessment in {"review", "escalate"}:
            # A lower AI level is never applied.  Conflicting evidence is sent
            # to manual review instead of silently weakening local protection.
            decision_status = "conflict_local_preserved"
            needs_manual_review = True
            counters["conflicts"] += 1
        else:
            counters["agreed"] += 1
            decision_status = "local_ai_consistent"
        items.append({
            "rank": int(review.get("rank")),
            "sample_id": local.get("id"),
            "local_risk_level": local_level,
            "local_risk_score": round(max(0.0, min(1.0, _number(local.get("risk_score")))), 4),
            "ai_risk_level": ai_level,
            "ai_confidence": confidence,
            "ai_attack_type": review.get("ai_attack_type", ""),
            "combined_risk_level": combined_level,
            "combined_risk_level_zh": level_zh.get(combined_level, combined_level),
            "decision_status": decision_status,
            "needs_manual_review": needs_manual_review,
            "reason": review.get("reason", ""),
            "recommended_action": review.get("recommended_action", ""),
            "local_score_preserved": True,
        })
    counters["local_only_unreviewed"] = max(0, min(len(ranking), 12) - len(items))
    return {
        "policy": "local_primary_ai_may_only_confirm_or_escalate",
        "items": items,
        "summary": counters,
    }


def test_payload() -> Dict:
    """Return a fixed, non-user-data payload for the explicit Test button."""
    return {
        "schema_version": EXTERNAL_ADVISOR_INPUT_VERSION,
        "analysis_kind": "connection_test",
        "payload_policy": EXTERNAL_PAYLOAD_POLICY,
        "analysis_scope": {
            "analyzed_rows": 10,
            "source_rows": 10,
            "source_rows_exact": True,
            "scope": "connection_test",
        },
        "privacy_risk": {
            "score": 0.2,
            "level": "low",
            "field_count": 0,
            "category_count": 0,
            "categories": [],
            "method": "connection_test",
            "is_model_score": False,
        },
        "attack_risk": {
            "score": 0.1,
            "level": "low",
            "highest_sample_level": "low",
            "priority_count": 0,
            "priority_ratio": 0.0,
            "high_or_critical_count": 0,
            "high_or_critical_ratio": 0.0,
            "method": "connection_test",
            "is_model_score": True,
        },
        "risk_counts": {"low": 10, "medium": 0, "high": 0, "critical": 0},
        "attack_type_counts": {},
        "risk_score_distribution": {"0.00-0.35": 10},
        "dual_risk": {
            "privacy_level": "low",
            "attack_level": "low",
            "attack_peak_level": "low",
            "overall_level": "low",
            "recommended_route": "connection_test",
            "axes_are_independent": True,
        },
        "versions": {
            "analysis_api": "connection-test",
            "preprocessing": "connection-test",
            "detector_model": "connection-test",
            "analysis_policy": "connection-test",
        },
    }
