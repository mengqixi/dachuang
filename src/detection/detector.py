# -*- coding: utf-8 -*-
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

    def fit_isolation_forest(self, X: np.ndarray) -> None:
        """仅训练孤立森林（兼容模式）

        Args:
            X: 训练数据
        """
        self.isolation_forest.fit(X)
        self._is_fitted = True
        logger.info("孤立森林训练完成: samples=%d" % len(X))

    def fit_lstm(
        self,
        X_seq: np.ndarray,
        y: np.ndarray,
        epochs: int = 10,
        batch_size: int = 32,
    ) -> Dict[str, Any]:
        """仅训练LSTM模型（兼容模式）

        Args:
            X_seq: 序列数据
            y: 标签
            epochs: 训练轮数
            batch_size: 批大小

        Returns:
            训练历史
        """
        history = self.lstm.fit(X_seq, y, epochs=epochs, batch_size=batch_size)
        logger.info("LSTM训练完成: samples=%d, epochs=%d" % (len(X_seq), epochs))
        return history

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


class RealDetector:
    """真实攻击检测器（IF + 轻量MLP）

    使用sklearn IsolationForest + LogisticRegression进行真实检测。
    加权投票：IF权重0.4 + MLP权重0.6
    所有训练在真实生成数据上进行。
    """

    def __init__(self, feature_dim: int = 18):
        self.feature_dim = feature_dim
        self.if_weight = 0.4
        self.mlp_weight = 0.6
        self._is_fitted = False

        # IF模型
        from sklearn.ensemble import IsolationForest
        self.if_model = IsolationForest(
            n_estimators=80, max_samples=200,
            contamination=0.15, random_state=42,
            n_jobs=1,
        )

        # MLP（用LogisticRegression作为轻量MLP）
        from sklearn.linear_model import LogisticRegression
        self.mlp_model = LogisticRegression(
            C=1.0, max_iter=500, solver="lbfgs",
            random_state=42, n_jobs=1,
        )

        # 保存的MLP权重（numpy格式）
        self.mlp_coef = None
        self.mlp_intercept = None

        logger.info("RealDetector初始化: IF(%.1f) + MLP(%.1f), %d维",
                    self.if_weight, self.mlp_weight, feature_dim)

    def fit(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """训练检测器

        Args:
            X: 特征矩阵 (n_samples, n_features)
            y: 标签 (n_samples,)

        Returns:
            训练指标
        """
        logger.info("开始训练真实检测器: X.shape=%s", X.shape)

        # 训练IF
        self.if_model.fit(X)
        logger.info("IF训练完成")

        # 训练MLP
        self.mlp_model.fit(X, y)
        self.mlp_coef = self.mlp_model.coef_.copy()
        self.mlp_intercept = self.mlp_model.intercept_.copy()
        train_acc = self.mlp_model.score(X, y)
        logger.info("MLP训练完成, 训练准确率=%.4f", train_acc)

        self._is_fitted = True

        # 评估
        preds, if_scores, mlp_scores = self.predict(X)
        accuracy = float(np.mean(preds == y))

        return {"accuracy": accuracy, "train_accuracy": float(train_acc)}

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """预测

        Returns:
            (combined_pred, if_score_norm, mlp_score)
        """
        # IF: -1异常, 1正常 → 归一化为[0,1]异常分数
        if_raw = self.if_model.decision_function(X)
        if_score = 1.0 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)
        if_binary = (if_score > 0.5).astype(int)

        # MLP: 预测概率
        if self.mlp_coef is not None:
            z = np.dot(X, self.mlp_coef.T) + self.mlp_intercept
            mlp_prob = 1.0 / (1.0 + np.exp(-z)).flatten()
        else:
            mlp_prob = self.mlp_model.predict_proba(X)[:, 1]
        mlp_binary = (mlp_prob >= 0.5).astype(int)

        # 加权投票
        weighted = self.if_weight * if_score + self.mlp_weight * mlp_prob
        combined = (weighted >= 0.5).astype(int)

        return combined, if_binary, mlp_binary

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """返回异常概率 [0, 1]"""
        if_raw = self.if_model.decision_function(X)
        if_score = 1.0 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)

        if self.mlp_coef is not None:
            z = np.dot(X, self.mlp_coef.T) + self.mlp_intercept
            mlp_prob = 1.0 / (1.0 + np.exp(-z)).flatten()
        else:
            mlp_prob = self.mlp_model.predict_proba(X)[:, 1]

        return np.clip(self.if_weight * if_score + self.mlp_weight * mlp_prob, 0.0, 1.0)

    def is_fitted(self) -> bool:
        return self._is_fitted

    def save(self, path: str) -> None:
        import joblib
        joblib.dump({
            "if_model": self.if_model,
            "mlp_model": self.mlp_model,
            "mlp_coef": self.mlp_coef,
            "mlp_intercept": self.mlp_intercept,
            "feature_dim": self.feature_dim,
        }, "%s_real.pkl" % path)
        logger.info("RealDetector已保存: %s", path)

    def load(self, path: str) -> bool:
        import joblib
        try:
            state = joblib.load("%s_real.pkl" % path)
            self.if_model = state["if_model"]
            self.mlp_model = state["mlp_model"]
            self.mlp_coef = state["mlp_coef"]
            self.mlp_intercept = state["mlp_intercept"]
            self.feature_dim = state["feature_dim"]
            self._is_fitted = True
            logger.info("RealDetector已加载: %s", path)
            return True
        except Exception as e:
            logger.warning("RealDetector加载失败: %s", e)
            return False
