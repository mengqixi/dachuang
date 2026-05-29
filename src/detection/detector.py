"""混合攻击检测器

融合孤立森林(静态异常)和LSTM(时序异常)的混合检测模型。
采用加权投票机制融合两个模型的预测结果。
支持训练、保存、加载和实时预测。
"""

from typing import Tuple, List, Dict, Any, Optional
import numpy as np
from loguru import logger

from src.detection.models.isolation_forest import IsolationForestModel
from src.detection.models.lstm_detector import LSTMDetector


class HybridDetector:
    """混合攻击检测器

    融合孤立森林和LSTM的检测结果，采用加权投票机制。
    孤立森林权重: 0.4 (擅长静态点异常)
    LSTM权重: 0.6 (擅长时序模式异常)

    属性:
        isolation_forest: 孤立森林模型
        lstm: LSTM模型
        if_weight: 孤立森林投票权重
        lstm_weight: LSTM投票权重
        feature_dim: 特征维度
        sequence_length: LSTM序列长度
    """

    def __init__(
        self,
        feature_dim: int = 18,
        sequence_length: int = 10,
        if_weight: float = 0.4,
        lstm_weight: float = 0.6,
        if_n_estimators: int = 100,
        if_contamination: float = 0.1,
        lstm_hidden_units: int = 128,
    ):
        # 权重归一化
        total = if_weight + lstm_weight
        self.if_weight = if_weight / total
        self.lstm_weight = lstm_weight / total
        self.feature_dim = feature_dim
        self.sequence_length = sequence_length

        self.isolation_forest = IsolationForestModel(
            n_estimators=if_n_estimators,
            contamination=if_contamination,
        )
        self.lstm = LSTMDetector(
            input_dim=feature_dim,
            hidden_units=lstm_hidden_units,
            sequence_length=sequence_length,
        )
        self._is_fitted = False
        logger.info(
            f"混合检测器初始化: IF权重={self.if_weight:.2f}, "
            f"LSTM权重={self.lstm_weight:.2f}"
        )

    def fit(
        self,
        X: np.ndarray,
        X_seq: np.ndarray,
        y: np.ndarray,
        epochs: int = 50,
        batch_size: int = 64,
    ) -> Dict[str, Any]:
        """训练混合模型

        Args:
            X: 静态特征, shape (n_samples, feature_dim)
            X_seq: 序列特征, shape (n_seq_samples, sequence_length, feature_dim)
            y: 标签
            epochs: LSTM训练轮数
            batch_size: LSTM批大小

        Returns:
            训练历史
        """
        logger.info("开始训练混合检测模型...")

        # 1. 训练孤立森林
        self.isolation_forest.fit(X)

        # 2. 训练LSTM
        lstm_history = self.lstm.fit(X_seq, y, epochs=epochs, batch_size=batch_size)

        self._is_fitted = True
        logger.info("混合检测模型训练完成")
        return lstm_history

    def predict(
        self,
        X: np.ndarray,
        X_seq: Optional[np.ndarray] = None,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """加权投票预测

        Args:
            X: 静态特征, shape (n_samples, feature_dim)
            X_seq: 序列特征, shape (n_samples, sequence_length, feature_dim)

        Returns:
            (combined, if_preds, lstm_preds) 融合/IF/LSTM预测结果
        """
        n_samples = len(X)

        # IF预测
        if_preds = self.isolation_forest.predict(X)

        # LSTM预测
        if X_seq is not None and self.lstm.is_fitted():
            lstm_preds = self.lstm.predict(X_seq)
        else:
            lstm_preds = np.zeros(n_samples)

        # 加权投票
        weighted_scores = (
            self.if_weight * if_preds + self.lstm_weight * lstm_preds
        )
        combined = (weighted_scores >= 0.5).astype(int)

        return combined, if_preds, lstm_preds

    def predict_proba(
        self,
        X: np.ndarray,
        X_seq: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        """加权投票概率输出

        Args:
            X: 静态特征
            X_seq: 序列特征（可选）

        Returns:
            异常概率 [0, 1]
        """
        # IF异常概率
        if_probs = self.isolation_forest.predict_proba(X)

        # LSTM异常概率
        if X_seq is not None and self.lstm.is_fitted():
            lstm_probs = self.lstm.predict_proba(X_seq)
        else:
            lstm_probs = np.zeros(len(X))

        # 加权融合
        combined_probs = self.if_weight * if_probs + self.lstm_weight * lstm_probs
        return np.clip(combined_probs, 0.0, 1.0)

    def is_fitted(self) -> bool:
        """模型是否已训练"""
        return self._is_fitted

    def save(self, path: str) -> None:
        """保存模型"""
        import joblib
        state = {
            "if_weight": self.if_weight,
            "lstm_weight": self.lstm_weight,
            "feature_dim": self.feature_dim,
            "if_model": self.isolation_forest.model,
        }
        joblib.dump(state, f"{path}_if.pkl")
        self.lstm.save(f"{path}_lstm")
        logger.info(f"混合检测模型已保存: {path}")

    def load(self, path: str) -> bool:
        """加载模型"""
        import joblib
        try:
            state = joblib.load(f"{path}_if.pkl")
            self.isolation_forest.model = state["if_model"]
            self.isolation_forest._is_fitted = True
            self._is_fitted = True
            self.lstm.load(f"{path}_lstm")
            logger.info(f"混合检测模型已加载: {path}")
            return True
        except Exception as e:
            logger.warning(f"加载混合检测模型失败: {e}")
            return False
