# -*- coding: utf-8 -*-
"""联邦学习客户端 - 4节点模拟"""

import os
import numpy as np
from typing import Dict, List, Optional
from loguru import logger

from src.preprocess.federated_splitter import NODE_NAMES


class FederatedClient:
    """联邦学习客户端 - 代表一个机构节点"""

    def __init__(self, name: str, data_dir: str):
        self.name = name
        self.data_dir = data_dir
        self.X = None
        self.y = None
        self.model = None
        self._loaded = False

    def load_data(self):
        """加载节点数据"""
        X_path = os.path.join(self.data_dir, "X.npy")
        y_path = os.path.join(self.data_dir, "y.npy")
        if os.path.exists(X_path) and os.path.exists(y_path):
            self.X = np.load(X_path)
            self.y = np.load(y_path)
            self._loaded = True
            logger.info("客户端[%s] 加载数据: %d条", self.name, len(self.y))
            return True
        logger.warning("客户端[%s] 无数据", self.name)
        return False

    @staticmethod
    def _sigmoid(z: np.ndarray) -> np.ndarray:
        z = np.clip(z, -50, 50)
        return 1.0 / (1.0 + np.exp(-z))

    @staticmethod
    def _split_train_validation(X: np.ndarray, y: np.ndarray, seed: int):
        rng = np.random.default_rng(seed)
        train_idx = []
        val_idx = []
        for label in np.unique(y):
            idx = np.where(y == label)[0]
            rng.shuffle(idx)
            if len(idx) <= 2:
                train_idx.extend(idx.tolist())
                continue
            split = max(1, int(len(idx) * 0.8))
            if split >= len(idx):
                split = len(idx) - 1
            train_idx.extend(idx[:split].tolist())
            val_idx.extend(idx[split:].tolist())

        if not train_idx:
            train_idx = list(range(len(y)))
        if not val_idx:
            val_idx = train_idx

        rng.shuffle(train_idx)
        rng.shuffle(val_idx)
        return X[train_idx], y[train_idx], X[val_idx], y[val_idx]

    def train_local(self, global_weights: Optional[np.ndarray] = None, epochs: int = 5) -> Dict:
        """本地训练

        Args:
            global_weights: 全局模型权重 (None=第一次训练)
            epochs: 本地训练轮数

        Returns:
            梯度/权重字典
        """
        if not self._loaded or self.X is None or len(self.X) == 0:
            return {"weights": None, "samples": 0, "accuracy": 0}

        X = np.asarray(self.X, dtype=np.float64)
        y = (self.y > 0).astype(int)  # 二分类
        n_samples, n_features = X.shape

        if len(np.unique(y)) < 2:
            majority_acc = float(np.mean(y == y[0])) if len(y) else 0.0
            return {
                "weights": np.zeros(n_features + 1, dtype=np.float64),
                "samples": int(n_samples),
                "accuracy": round(majority_acc, 4),
                "loss": 0.0,
                "name": self.name,
            }

        seed = sum(ord(ch) for ch in self.name) + n_samples
        X_train, y_train, X_val, y_val = self._split_train_validation(X, y, seed)

        if global_weights is not None and len(global_weights) == n_features + 1:
            weights = np.asarray(global_weights, dtype=np.float64).copy()
        else:
            weights = np.zeros(n_features + 1, dtype=np.float64)

        local_epochs = max(1, int(epochs))
        learning_rate = 0.35
        l2 = 0.01
        Xb = np.c_[X_train, np.ones(len(X_train))]

        for _ in range(local_epochs):
            probs = self._sigmoid(Xb @ weights)
            grad = (Xb.T @ (probs - y_train)) / max(len(y_train), 1)
            grad[:-1] += l2 * weights[:-1]
            weights -= learning_rate * grad

        Xv = np.c_[X_val, np.ones(len(X_val))]
        val_probs = np.clip(self._sigmoid(Xv @ weights), 1e-6, 1 - 1e-6)
        val_preds = (val_probs >= 0.5).astype(int)
        val_acc = float(np.mean(val_preds == y_val))
        val_loss = float(-np.mean(y_val * np.log(val_probs) + (1 - y_val) * np.log(1 - val_probs)))

        return {
            "weights": weights,
            "samples": int(n_samples),
            "accuracy": round(val_acc, 4),
            "loss": round(val_loss, 4),
            "name": self.name,
        }
