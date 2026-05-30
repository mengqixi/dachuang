# -*- coding: utf-8 -*-
"""三模型融合检测器 - IF 0.3 + XGBoost 0.3 + LSTM 0.4"""

import os
import numpy as np
from typing import Dict, Tuple, Optional
from loguru import logger

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "models")


class EnsembleDetector:
    """三模型融合检测器

    加权投票: Isolation Forest (0.3) + XGBoost (0.3) + LSTM (0.4)
    输出 attack_type, risk_score, confidence
    """

    ATTACK_TYPES = ["Normal", "DoS", "Backdoor", "Reconnaissance", "Exploits", "Worms", "Shellcode"]

    def __init__(self):
        self.if_model = None
        self.xgb_model = None
        self.lstm_model = None
        self.weights = np.array([0.3, 0.3, 0.4])
        self._is_ready = False
        self._feature_dim = 18

    def load_or_init(self):
        """加载已训练模型或初始化为空"""
        import joblib
        # Try loading IF
        from sklearn.ensemble import IsolationForest
        if_path = os.path.join(MODEL_DIR, "isolation_forest.pkl")
        if os.path.exists(if_path):
            self.if_model = joblib.load(if_path)
            logger.info("Ensemble: IF已加载")
        else:
            self.if_model = IsolationForest(n_estimators=80, contamination=0.15, random_state=42)
            logger.info("Ensemble: IF初始化为新模型")

        # Try loading XGBoost
        xgb_path = os.path.join(MODEL_DIR, "xgboost.pkl")
        if os.path.exists(xgb_path):
            import joblib
            self.xgb_model = joblib.load(xgb_path)
            logger.info("Ensemble: XGBoost已加载")
        else:
            self.xgb_model = None

        # Try loading LSTM
        lstm_path = os.path.join(MODEL_DIR, "lstm_model.npz")
        if os.path.exists(lstm_path):
            from src.detection.lstm_detector import NumPyLSTM
            self.lstm_model = NumPyLSTM()
            self.lstm_model.load(lstm_path)
            logger.info("Ensemble: LSTM已加载")
        else:
            self.lstm_model = None

        self._is_ready = (self.if_model is not None)
        return self._is_ready

    def fit(self, X: np.ndarray, y: np.ndarray, X_seq: Optional[np.ndarray] = None):
        """训练所有模型

        Args:
            X: 静态特征 (n, 18)
            y: 标签 (n,)
            X_seq: 序列特征 (n-seq_len, seq_len, 18)
        """
        logger.info("训练三模型融合检测器: X.shape=%s", str(X.shape))

        # 初始化模型（如果未加载）
        if self.if_model is None:
            from sklearn.ensemble import IsolationForest
            self.if_model = IsolationForest(n_estimators=80, contamination=0.15, random_state=42, n_jobs=1)
            logger.info("Ensemble: IF初始化为新模型")

        # 1. 训练IF
        self.if_model.fit(X)
        import joblib
        joblib.dump(self.if_model, os.path.join(MODEL_DIR, "isolation_forest.pkl"))
        logger.info("Ensemble: IF训练完成")

        # 2. 训练XGBoost
        try:
            import xgboost as xgb
            self.xgb_model = xgb.XGBClassifier(
                n_estimators=100, max_depth=6, learning_rate=0.1,
                random_state=42, n_jobs=1,
                use_label_encoder=False, eval_metric='mlogloss'
            )
            # 将多分类标签映射到0/1二分类便于融合
            y_bin = (y > 0).astype(int)
            self.xgb_model.fit(X, y_bin)
            joblib.dump(self.xgb_model, os.path.join(MODEL_DIR, "xgboost.pkl"))
            logger.info("Ensemble: XGBoost训练完成")
        except Exception as e:
            logger.warning("Ensemble: XGBoost训练失败: %s", e)

        # 3. 训练LSTM
        try:
            if X_seq is not None and len(X_seq) > 0:
                from src.detection.lstm_detector import NumPyLSTM
                self.lstm_model = NumPyLSTM(input_dim=self._feature_dim)
                y_seq = np.array([1.0 if np.mean(y[i:i+10]) > 0.3 else 0.0 for i in range(len(X_seq))])
                self.lstm_model.fit(X_seq, y_seq, epochs=10, lr=0.01)
                self.lstm_model.save(os.path.join(MODEL_DIR, "lstm_model.npz"))
                logger.info("Ensemble: LSTM训练完成")
        except Exception as e:
            logger.warning("Ensemble: LSTM训练失败: %s", e)

        self._is_ready = True

        # 评估
        preds = self.predict(X)
        accuracy = float(np.mean(preds == (y > 0).astype(int)))
        logger.info("三模型融合检测器训练完成: accuracy=%.4f", accuracy)
        return {"accuracy": accuracy}

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """三模型融合预测

        Returns:
            (final_preds, risk_scores, confidences)
        """
        n = len(X)
        scores = np.zeros((n, 3))  # IF, XGB, LSTM

        # IF score
        if self.if_model is not None:
            if_raw = self.if_model.decision_function(X)
            scores[:, 0] = 1.0 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)
        else:
            scores[:, 0] = X[:, -1]  # fallback to anomaly_score

        # XGBoost score
        if self.xgb_model is not None:
            try:
                scores[:, 1] = self.xgb_model.predict_proba(X)[:, 1]
            except Exception:
                scores[:, 1] = 0.5
        else:
            scores[:, 1] = 0.3

        # LSTM score (uses original features directly as single-step)
        if self.lstm_model is not None and self.lstm_model.is_fitted():
            try:
                X_seq_3d = X.reshape(n, 1, -1)
                # Pad to at least sequence length
                if X.shape[1] < self.lstm_model.input_dim:
                    X_seq_3d = np.pad(X_seq_3d, ((0,0),(0,0),(0, self.lstm_model.input_dim - X.shape[1])))
                scores[:, 2] = self.lstm_model.predict(X_seq_3d)
            except Exception:
                scores[:, 2] = 0.3
        else:
            scores[:, 2] = 0.3

        # Weighted fusion
        final_scores = np.dot(scores, self.weights)
        final_preds = (final_scores >= 0.5).astype(int)

        # Risk level
        risk_levels = np.where(final_scores >= 0.8, 3,
                              np.where(final_scores >= 0.5, 2,
                                      np.where(final_scores >= 0.2, 1, 0)))

        return final_preds, final_scores, risk_levels

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """返回异常概率"""
        _, scores, _ = self.predict(X)
        return np.clip(scores, 0, 1)

    def is_ready(self) -> bool:
        return self._is_ready


ensemble_detector = EnsembleDetector()
