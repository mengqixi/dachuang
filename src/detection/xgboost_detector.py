# -*- coding: utf-8 -*-
"""XGBoost攻击检测器"""

import os
import numpy as np
from typing import Dict, Tuple
from loguru import logger

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "models")

ATTACK_TYPES = ["Normal", "DoS", "Backdoor", "Reconnaissance", "Exploits", "Worms", "Shellcode"]


class XGBoostDetector:
    """XGBoost攻击检测器 - 支持7种攻击分类"""

    def __init__(self):
        self.model = None
        self._is_fitted = False
        self._feature_dim = 18

    def fit(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """训练XGBoost模型"""
        import xgboost as xgb
        logger.info("训练XGBoost: X.shape=%s", X.shape)

        self.model = xgb.XGBClassifier(
            n_estimators=100, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            random_state=42, n_jobs=1,
            use_label_encoder=False, eval_metric='mlogloss'
        )
        self.model.fit(X, y)
        train_acc = float(self.model.score(X, y))
        self._is_fitted = True
        self._feature_dim = X.shape[1]
        logger.info("XGBoost训练完成: accuracy=%.4f", train_acc)
        return {"accuracy": train_acc}

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self._is_fitted or self.model is None:
            return np.zeros(len(X))
        return self.model.predict(X).astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self._is_fitted or self.model is None:
            return np.zeros((len(X), 2))
        return self.model.predict_proba(X)

    def save(self, path: str = None):
        if path is None:
            path = os.path.join(MODEL_DIR, "xgboost.pkl")
        import joblib
        joblib.dump(self.model, path)
        logger.info("XGBoost已保存: %s", path)

    def load(self, path: str = None) -> bool:
        if path is None:
            path = os.path.join(MODEL_DIR, "xgboost.pkl")
        try:
            import joblib
            self.model = joblib.load(path)
            self._is_fitted = True
            logger.info("XGBoost已加载: %s", path)
            return True
        except Exception as e:
            logger.warning("XGBoost加载失败: %s", e)
            return False

    def is_fitted(self) -> bool:
        return self._is_fitted
