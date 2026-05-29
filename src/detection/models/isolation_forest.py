"""孤立森林异常检测模型

基于scikit-learn的孤立森林(IsolationForest)实现，
用于检测静态点异常，如密钥生成时间异常、请求频率异常等。
"""

from typing import Optional, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from loguru import logger


class IsolationForestModel:
    """孤立森林异常检测模型

    检测静态点异常，适用于实时特征的单点判断。
    支持训练、预测、概率输出、保存和加载。

    属性:
        model: scikit-learn IsolationForest实例
        contamination: 预期异常比例
        n_estimators: 树的数量
        feature_names: 特征名称列表（可选）
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.1,
        max_samples: float = 1.0,
        random_state: int = 42,
    ):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=max_samples,
            random_state=random_state,
            bootstrap=True,
            n_jobs=-1,
        )
        self._is_fitted = False

    def fit(self, X: np.ndarray) -> "IsolationForestModel":
        """训练孤立森林模型

        Args:
            X: 训练特征矩阵，shape (n_samples, n_features)

        Returns:
            self: 训练后的模型实例
        """
        logger.info(f"训练孤立森林: X.shape={X.shape}")
        self.model.fit(X)
        self._is_fitted = True
        logger.info("孤立森林训练完成")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测是否异常

        Args:
            X: 特征矩阵

        Returns:
            预测结果: 1=异常, 0=正常
        """
        preds = self.model.predict(X)
        return np.where(preds == -1, 1, 0)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测异常概率

        Args:
            X: 特征矩阵

        Returns:
            异常概率分数 [0, 1]
        """
        scores = self.model.decision_function(X)
        # 将异常分数映射到 [0, 1]，分数越低越异常
        prob = 1.0 - (scores - scores.min()) / (
            scores.max() - scores.min() + 1e-8
        )
        return np.clip(prob, 0.0, 1.0)

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """获取原始异常分数

        Returns:
            原始异常分数（负值表示异常）
        """
        return self.model.score_samples(X)

    def is_fitted(self) -> bool:
        """模型是否已训练"""
        return self._is_fitted

    def get_params(self) -> Dict[str, Any]:
        """获取模型参数"""
        return self.model.get_params()

    def save(self, path: str) -> None:
        """保存模型到文件"""
        import joblib
        joblib.dump(self.model, path)
        logger.info(f"孤立森林模型已保存: {path}")

    def load(self, path: str) -> bool:
        """从文件加载模型"""
        import joblib
        try:
            self.model = joblib.load(path)
            self._is_fitted = True
            logger.info(f"孤立森林模型已加载: {path}")
            return True
        except Exception as e:
            logger.warning(f"加载孤立森林模型失败: {e}")
            return False
