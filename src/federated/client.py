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

        from sklearn.linear_model import LogisticRegression

        X = self.X
        y = (self.y > 0).astype(int)  # 二分类

        # 使用逻辑回归作为本地模型
        model = LogisticRegression(C=1.0, max_iter=200, solver="lbfgs")
        model.fit(X, y)

        local_acc = float(model.score(X, y))

        return {
            "weights": np.concatenate([model.coef_.flatten(), model.intercept_]),
            "samples": len(y),
            "accuracy": round(local_acc, 4),
            "name": self.name,
        }
