# -*- coding: utf-8 -*-
"""联邦数据集拆分器 - 按类别分层抽样拆分为4节点"""

import os
import numpy as np
from typing import Tuple, List
from loguru import logger

from src.utils.atomic_files import atomic_save_npy

FEDERATED_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "federated")

NODE_NAMES = ["hospital", "bank", "insurance", "government"]


def split_federated(X: np.ndarray, y: np.ndarray, seed: int = 42) -> List[Tuple[np.ndarray, np.ndarray]]:
    """按标签分层抽样，均匀拆分为4份

    Args:
        X: 特征矩阵
        y: 标签向量

    Returns:
        [(X_node, y_node)] * 4
    """
    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y, dtype=np.int32).reshape(-1)
    if X.ndim != 2 or len(X) != len(y):
        raise ValueError("federated split requires aligned 2D features and labels")
    n_nodes = 4
    nodes = [(np.empty((0, X.shape[1]), dtype=np.float64), np.empty(0, dtype=np.int32)) for _ in range(n_nodes)]

    rng = np.random.default_rng(int(seed))

    # 按类别分组。同一数据修订使用同一 seed，避免重复准备时节点内容随机变化。
    unique_labels = np.unique(y)
    for label in unique_labels:
        idx = np.where(y == label)[0]
        rng.shuffle(idx)
        # 尽可能均分
        splits = np.array_split(idx, n_nodes)
        for i in range(n_nodes):
            if len(splits[i]) > 0:
                X_part = X[splits[i]]
                y_part = y[splits[i]]
                nodes[i] = (np.vstack([nodes[i][0], X_part]) if nodes[i][0].size > 0 else X_part,
                           np.concatenate([nodes[i][1], y_part]) if nodes[i][1].size > 0 else y_part)

    logger.info("联邦数据拆分完成: 4节点, 各节点样本数={}",
                [len(n[0]) for n in nodes])
    return nodes


def save_federated_data(X: np.ndarray, y: np.ndarray, names: List[str] = None, seed: int = 42):
    """拆分并保存联邦数据到各节点目录

    Args:
        X: 特征矩阵
        y: 标签
        names: 节点名称列表，默认hospital/bank/insurance/government
    """
    if names is None:
        names = NODE_NAMES
    if len(names) != 4:
        raise ValueError("federated split requires exactly four node names")

    nodes = split_federated(X, y, seed=seed)
    os.makedirs(FEDERATED_DIR, exist_ok=True)

    saved = []
    for i, (Xn, yn) in enumerate(nodes):
        node_dir = os.path.join(FEDERATED_DIR, names[i])
        os.makedirs(node_dir, exist_ok=True)
        atomic_save_npy(os.path.join(node_dir, "X.npy"), Xn)
        atomic_save_npy(os.path.join(node_dir, "y.npy"), yn)
        saved.append((names[i], len(Xn)))

    logger.info("联邦数据已保存到 {}: {}", FEDERATED_DIR, saved)
    return saved


def load_node_data(node_name: str):
    """加载指定节点的数据"""
    path = os.path.join(FEDERATED_DIR, node_name)
    X = np.load(os.path.join(path, "X.npy"))
    y = np.load(os.path.join(path, "y.npy"))
    return X, y
