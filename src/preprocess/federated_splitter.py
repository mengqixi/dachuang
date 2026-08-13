# -*- coding: utf-8 -*-
"""联邦数据拆分器。

默认使用确定性的业务 Non-IID 划分：不同节点具有不同样本规模、攻击标签比例
和特征区间。这样四节点不再只是名称不同的均匀副本，同时仍保证同一数据修订
和随机种子能够得到完全一致的拆分结果。
"""

import json
import os
from typing import Dict, List, Tuple

import numpy as np
from loguru import logger

from src.utils.atomic_files import atomic_save_npy, atomic_write_json


FEDERATED_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data",
    "federated",
)

NODE_NAMES = ["hospital", "bank", "insurance", "government"]
FEDERATED_SPLIT_VERSION = "business-noniid-label-feature-v1"

# 样本占比与攻击偏好共同决定各标签的分配权重。数值不是对真实行业风险的
# 断言，而是可复现的跨机构数据异质性场景，便于检验联邦训练的稳定性。
NODE_PROFILES = {
    "hospital": {
        "display_name": "医疗机构节点",
        "sample_share": 0.22,
        "attack_preference": 0.55,
        "feature_band": "中低区间",
    },
    "bank": {
        "display_name": "金融机构节点",
        "sample_share": 0.30,
        "attack_preference": 0.70,
        "feature_band": "高区间",
    },
    "insurance": {
        "display_name": "保险机构节点",
        "sample_share": 0.20,
        "attack_preference": 0.45,
        "feature_band": "中高区间",
    },
    "government": {
        "display_name": "政务机构节点",
        "sample_share": 0.28,
        "attack_preference": 0.25,
        "feature_band": "低区间",
    },
}


def _allocate_counts(total: int, weights: np.ndarray) -> np.ndarray:
    """按最大余数法分配整数样本数，保证总数不变。"""
    total = max(0, int(total))
    weights = np.asarray(weights, dtype=np.float64)
    if total == 0:
        return np.zeros(len(weights), dtype=np.int64)
    weights = np.maximum(weights, 0.0)
    if float(weights.sum()) <= 0:
        weights = np.ones(len(weights), dtype=np.float64)
    raw = total * weights / weights.sum()
    counts = np.floor(raw).astype(np.int64)
    remainder = total - int(counts.sum())
    if remainder:
        order = np.argsort(-(raw - counts), kind="mergesort")
        counts[order[:remainder]] += 1

    # 样本足够时，让每个节点至少获得一个该类别样本，避免人为制造空类别。
    if total >= len(weights):
        empty = np.where(counts == 0)[0]
        for target in empty:
            donor = int(np.argmax(counts))
            if counts[donor] > 1:
                counts[donor] -= 1
                counts[target] += 1
    return counts


def _feature_order(X: np.ndarray, indices: np.ndarray, rng, reverse: bool = False) -> np.ndarray:
    """使用两个稳定特征和微小随机扰动生成确定性特征区间顺序。"""
    if len(indices) <= 1 or X.shape[1] == 0:
        return indices
    primary = X[indices, 0]
    secondary_index = min(4, X.shape[1] - 1)
    secondary = X[indices, secondary_index]
    score = primary + 0.35 * secondary + rng.normal(0.0, 1e-6, len(indices))
    order = np.argsort(score, kind="mergesort")
    if reverse:
        order = order[::-1]
    return indices[order]


def split_federated(
    X: np.ndarray,
    y: np.ndarray,
    seed: int = 42,
) -> List[Tuple[np.ndarray, np.ndarray]]:
    """将训练分区拆为四个确定性业务 Non-IID 节点。"""
    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y, dtype=np.int32).reshape(-1)
    if X.ndim != 2 or len(X) != len(y):
        raise ValueError("federated split requires aligned 2D features and labels")

    rng = np.random.RandomState(int(seed) & 0xFFFFFFFF)
    node_indices = [[] for _ in NODE_NAMES]
    sample_shares = np.asarray(
        [NODE_PROFILES[name]["sample_share"] for name in NODE_NAMES],
        dtype=np.float64,
    )
    attack_preferences = np.asarray(
        [NODE_PROFILES[name]["attack_preference"] for name in NODE_NAMES],
        dtype=np.float64,
    )

    binary_y = (y > 0).astype(np.int32)
    for label in (0, 1):
        indices = np.where(binary_y == label)[0]
        if not len(indices):
            continue
        # 正常与攻击样本采用相反的特征区间方向，形成标签偏移和特征偏移并存
        # 的跨机构场景，同时避免依赖任何原始隐私字段。
        ordered = _feature_order(X, indices, rng, reverse=bool(label))
        label_weights = sample_shares * (
            attack_preferences if label else (1.0 - attack_preferences)
        )
        counts = _allocate_counts(len(ordered), label_weights)
        cursor = 0
        # 不同标签使用不同节点区间顺序，降低“节点编号=单一特征大小”的偏差。
        node_order = [3, 0, 2, 1] if label == 0 else [1, 2, 0, 3]
        for node_index, count in zip(node_order, counts[node_order]):
            count = int(count)
            if count:
                node_indices[node_index].extend(ordered[cursor:cursor + count].tolist())
            cursor += count

    nodes = []
    for indices in node_indices:
        indices = np.asarray(indices, dtype=np.int64)
        rng.shuffle(indices)
        nodes.append((X[indices], y[indices]))

    logger.info(
        "联邦 Non-IID 数据拆分完成: version={}, 节点样本数={}",
        FEDERATED_SPLIT_VERSION,
        [len(item[0]) for item in nodes],
    )
    return nodes


def _label_distribution(values: np.ndarray) -> Dict[str, int]:
    binary = (np.asarray(values).reshape(-1) > 0).astype(np.int32)
    return {
        str(int(key)): int(value)
        for key, value in zip(*np.unique(binary, return_counts=True))
    } if len(binary) else {}


def _jensen_shannon_binary(node_rate: float, global_rate: float) -> float:
    p = np.asarray([1.0 - node_rate, node_rate], dtype=np.float64)
    q = np.asarray([1.0 - global_rate, global_rate], dtype=np.float64)
    p = np.clip(p, 1e-9, 1.0)
    q = np.clip(q, 1e-9, 1.0)
    m = 0.5 * (p + q)
    value = 0.5 * np.sum(p * np.log(p / m)) + 0.5 * np.sum(q * np.log(q / m))
    return float(max(0.0, value))


def summarize_federated_split(
    X: np.ndarray,
    y: np.ndarray,
    nodes: List[Tuple[np.ndarray, np.ndarray]],
) -> Dict:
    """计算可展示、可审计的节点异质性和数据质量指标。"""
    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y).reshape(-1)
    total = max(1, len(X))
    global_attack_rate = float(np.mean(y > 0)) if len(y) else 0.0
    global_label_classes = set(np.unique(y > 0).tolist())
    global_mean = np.mean(X, axis=0) if len(X) else np.zeros(X.shape[1], dtype=np.float64)
    global_std = np.std(X, axis=0) if len(X) else np.ones(X.shape[1], dtype=np.float64)
    global_std = np.where(global_std < 1e-6, 1.0, global_std)

    details = []
    for name, (node_x, node_y) in zip(NODE_NAMES, nodes):
        count = int(len(node_x))
        attack_rate = float(np.mean(node_y > 0)) if count else 0.0
        label_js = _jensen_shannon_binary(attack_rate, global_attack_rate) if count else 0.0
        if count:
            standardized_shift = (np.mean(node_x, axis=0) - global_mean) / global_std
            feature_mean_shift = float(np.sqrt(np.mean(np.square(np.clip(standardized_shift, -10, 10)))))
        else:
            feature_mean_shift = 0.0
        expected_share = float(NODE_PROFILES[name]["sample_share"])
        actual_share = float(count / total)
        feature_finite_ratio = float(np.mean(np.isfinite(node_x))) if node_x.size else 0.0
        node_label_classes = set(np.unique(node_y > 0).tolist()) if count else set()
        label_coverage = (
            float(len(global_label_classes.intersection(node_label_classes)) / len(global_label_classes))
            if global_label_classes else 1.0
        )
        adequate_sample_floor = max(1.0, total * expected_share * 0.75)
        sample_adequacy = min(1.0, count / adequate_sample_floor)
        # Non-IID difference is intentional and belongs to heterogeneity, not
        # data quality. Quality only reflects usable values, class coverage and
        # whether the node has enough samples for stable local training.
        quality_score = 100.0 * (
            0.55 * feature_finite_ratio
            + 0.25 * label_coverage
            + 0.20 * sample_adequacy
        )
        details.append({
            "name": name,
            "display_name": NODE_PROFILES[name]["display_name"],
            "samples": count,
            "ready": bool(count),
            "sample_share": round(actual_share, 4),
            "expected_sample_share": round(expected_share, 4),
            "label_distribution": _label_distribution(node_y),
            "attack_rate": round(attack_rate, 4),
            "attack_rate_delta": round(attack_rate - global_attack_rate, 4),
            "label_js_divergence": round(label_js, 6),
            "feature_mean_shift": round(feature_mean_shift, 4),
            "quality_score": round(quality_score, 2),
            "feature_finite_ratio": round(feature_finite_ratio, 4),
            "label_coverage": round(label_coverage, 4),
            "sample_adequacy": round(sample_adequacy, 4),
            "profile": {
                "attack_preference": NODE_PROFILES[name]["attack_preference"],
                "feature_band": NODE_PROFILES[name]["feature_band"],
            },
        })

    mean_js = float(np.mean([item["label_js_divergence"] for item in details])) if details else 0.0
    mean_feature_shift = float(np.mean([item["feature_mean_shift"] for item in details])) if details else 0.0
    return {
        "version": FEDERATED_SPLIT_VERSION,
        "strategy": "business_noniid_label_and_feature_shift",
        "global_attack_rate": round(global_attack_rate, 4),
        "mean_label_js_divergence": round(mean_js, 6),
        "mean_feature_shift": round(mean_feature_shift, 4),
        "heterogeneity_level": (
            "high" if mean_js >= 0.08 or mean_feature_shift >= 0.9
            else "medium" if mean_js >= 0.02 or mean_feature_shift >= 0.35
            else "low"
        ),
        "nodes": details,
    }


def save_federated_data(
    X: np.ndarray,
    y: np.ndarray,
    names: List[str] = None,
    seed: int = 42,
    return_metadata: bool = False,
):
    """拆分并保存四节点数据；默认返回值兼容旧版 ``[(name, count)]``。"""
    if names is None:
        names = NODE_NAMES
    if len(names) != 4:
        raise ValueError("federated split requires exactly four node names")

    nodes = split_federated(X, y, seed=seed)
    split_metadata = summarize_federated_split(X, y, nodes)
    os.makedirs(FEDERATED_DIR, exist_ok=True)

    saved = []
    detail_by_name = {
        item["name"]: item for item in split_metadata.get("nodes", [])
    }
    for index, (node_x, node_y) in enumerate(nodes):
        name = names[index]
        node_dir = os.path.join(FEDERATED_DIR, name)
        os.makedirs(node_dir, exist_ok=True)
        atomic_save_npy(os.path.join(node_dir, "X.npy"), node_x)
        atomic_save_npy(os.path.join(node_dir, "y.npy"), node_y)
        node_manifest = dict(detail_by_name.get(NODE_NAMES[index]) or {})
        node_manifest["name"] = name
        node_manifest["split_version"] = FEDERATED_SPLIT_VERSION
        atomic_write_json(os.path.join(node_dir, "manifest.json"), node_manifest)
        saved.append((name, len(node_x)))

    atomic_write_json(
        os.path.join(FEDERATED_DIR, "manifest.json"),
        split_metadata,
    )
    logger.info("联邦数据已保存到 {}: {}", FEDERATED_DIR, saved)
    if return_metadata:
        return saved, split_metadata
    return saved


def load_split_metadata() -> Dict:
    path = os.path.join(FEDERATED_DIR, "manifest.json")
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def load_node_data(node_name: str):
    """加载指定节点的数据。"""
    path = os.path.join(FEDERATED_DIR, node_name)
    X = np.load(os.path.join(path, "X.npy"))
    y = np.load(os.path.join(path, "y.npy"))
    return X, y
