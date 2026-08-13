# -*- coding: utf-8 -*-
"""轻量级数据漂移指标，避免为 2GB 部署引入额外服务或大型依赖。"""

from typing import Dict

import numpy as np


DRIFT_POLICY_VERSION = "feature-psi-label-rate-v1"


def _feature_psi(reference, current, bins=5):
    reference = np.asarray(reference, dtype=np.float64).reshape(-1)
    current = np.asarray(current, dtype=np.float64).reshape(-1)
    if len(reference) < bins or len(current) < 2:
        return 0.0
    edges = np.unique(np.quantile(reference, np.linspace(0.0, 1.0, bins + 1)))
    if len(edges) < 3:
        return 0.0
    edges = edges.astype(np.float64)
    edges[0] = -np.inf
    edges[-1] = np.inf
    ref_counts, _ = np.histogram(reference, bins=edges)
    cur_counts, _ = np.histogram(current, bins=edges)
    ref_ratio = np.maximum(ref_counts / max(1.0, float(ref_counts.sum())), 1e-6)
    cur_ratio = np.maximum(cur_counts / max(1.0, float(cur_counts.sum())), 1e-6)
    return float(np.sum((cur_ratio - ref_ratio) * np.log(cur_ratio / ref_ratio)))


def calculate_data_drift(reference_x, reference_y, current_x, current_y) -> Dict:
    """比较既有训练数据与新增/新修订数据，返回无需原始字段的聚合指标。"""
    reference_x = np.asarray(reference_x, dtype=np.float64)
    current_x = np.asarray(current_x, dtype=np.float64)
    reference_y = np.asarray(reference_y).reshape(-1)
    current_y = np.asarray(current_y).reshape(-1)
    if (
        reference_x.ndim != 2
        or current_x.ndim != 2
        or reference_x.shape[1:] != current_x.shape[1:]
        or len(reference_x) == 0
        or len(current_x) == 0
    ):
        return {
            "version": DRIFT_POLICY_VERSION,
            "available": False,
            "level": "unknown",
            "reason": "insufficient_comparable_rows",
        }

    feature_psi = [
        _feature_psi(reference_x[:, index], current_x[:, index])
        for index in range(reference_x.shape[1])
    ]
    mean_psi = float(np.mean(feature_psi)) if feature_psi else 0.0
    max_psi = float(np.max(feature_psi)) if feature_psi else 0.0
    reference_attack_rate = float(np.mean(reference_y > 0)) if len(reference_y) else 0.0
    current_attack_rate = float(np.mean(current_y > 0)) if len(current_y) else 0.0
    label_rate_delta = abs(current_attack_rate - reference_attack_rate)

    if mean_psi >= 0.25 or max_psi >= 0.5 or label_rate_delta >= 0.20:
        level = "high"
        action = "review_before_training"
    elif mean_psi >= 0.10 or max_psi >= 0.25 or label_rate_delta >= 0.10:
        level = "medium"
        action = "monitor_and_validate"
    else:
        level = "low"
        action = "normal_validation"

    return {
        "version": DRIFT_POLICY_VERSION,
        "available": True,
        "level": level,
        "recommended_action": action,
        "reference_samples": int(len(reference_x)),
        "current_samples": int(len(current_x)),
        "mean_feature_psi": round(mean_psi, 6),
        "max_feature_psi": round(max_psi, 6),
        "reference_attack_rate": round(reference_attack_rate, 4),
        "current_attack_rate": round(current_attack_rate, 4),
        "label_rate_delta": round(label_rate_delta, 4),
    }
