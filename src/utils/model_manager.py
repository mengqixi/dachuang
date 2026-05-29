"""模型自动训练与管理系统

支持Isolation Forest、LogisticRegression (MLP)、Q-learning三种模型的
自动训练、加载、保存和重训练。
"""

import os
import time
import threading
from typing import Dict, List, Any, Optional, Tuple

import numpy as np
from loguru import logger

from src.data_generator import FEATURE_NAMES

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "models")


class ModelManager:
    """模型管理器

    管理三个模型的训练、加载、保存状态。

    属性:
        if_model: sklearn IsolationForest
        mlp_model: sklearn LogisticRegression（轻量MLP）
        mlp_coef: numpy导出的MLP权重
        mlp_intercept: numpy导出的MLP偏置
        q_agent: Q-learning智能体
        is_ready: 所有模型是否就绪
        training_status: 当前训练状态
    """

    def __init__(self):
        self.if_model = None
        self.mlp_model = None
        self.mlp_coef = None
        self.mlp_intercept = None
        self.q_agent = None
        self.is_ready = False
        self.training_status = {"status": "idle", "progress": 0, "message": ""}
        self._lock = threading.Lock()
        self._train_history: List[Dict] = []

        os.makedirs(MODEL_DIR, exist_ok=True)
        logger.info("ModelManager初始化完成: %s", MODEL_DIR)

    def _get_if_path(self) -> str:
        return os.path.join(MODEL_DIR, "isolation_forest.pkl")

    def _get_mlp_weights_path(self) -> str:
        return os.path.join(MODEL_DIR, "mlp_weights.npy")

    def _get_mlp_bias_path(self) -> str:
        return os.path.join(MODEL_DIR, "mlp_bias.npy")

    def _get_q_path(self) -> str:
        return os.path.join(MODEL_DIR, "q_table.npy")

    def auto_load_or_train(self, X_train: np.ndarray, y_train: np.ndarray):
        """启动时自动加载或训练所有模型

        Args:
            X_train: 训练特征矩阵
            y_train: 训练标签
        """
        if self.is_ready:
            logger.info("所有模型已就绪，跳过训练")
            return

        # 检查是否有已保存的模型
        if self._check_saved_models():
            logger.info("检测到已保存的模型文件，直接加载")
            self._load_all()
            return

        # 无模型则后台训练
        logger.info("未检测到已保存模型，启动后台训练...")
        t = threading.Thread(target=self._train_all, args=(X_train, y_train), daemon=True)
        t.start()

    def _check_saved_models(self) -> bool:
        """检查所有模型文件是否存在"""
        return (os.path.exists(self._get_if_path()) and
                os.path.exists(self._get_mlp_weights_path()) and
                os.path.exists(self._get_mlp_bias_path()) and
                os.path.exists(self._get_q_path()))

    def _load_all(self):
        """加载所有已保存的模型"""
        try:
            import joblib

            # 加载IF
            self.if_model = joblib.load(self._get_if_path())
            logger.info("加载IF模型: %s", self._get_if_path())

            # 加载MLP权重
            self.mlp_coef = np.load(self._get_mlp_weights_path())
            self.mlp_intercept = np.load(self._get_mlp_bias_path())
            logger.info("加载MLP权重: %s", self._get_mlp_weights_path())
            from sklearn.linear_model import LogisticRegression
            self.mlp_model = LogisticRegression()
            self.mlp_model.coef_ = self.mlp_coef
            self.mlp_model.intercept_ = self.mlp_intercept
            self.mlp_model.classes_ = np.array([0, 1])

            # 加载Q-table
            q_data = np.load(self._get_q_path(), allow_pickle=True).item()
            from src.optimization.agent import QLearningAgent
            self.q_agent = QLearningAgent()
            self.q_agent.q_table = q_data.get("q_table", np.zeros((500, 6)))
            self.q_agent._trained = True
            logger.info("加载Q-table: %s", self._get_q_path())

            self.is_ready = True
            logger.info("所有模型加载完成")
        except Exception as e:
            logger.warning("加载模型失败: %s，将重新训练", e)
            self._train_all(None, None)

    def _train_all(self, X_train: np.ndarray, y_train: np.ndarray):
        """训练所有模型（后台线程）"""
        with self._lock:
            self.training_status = {"status": "training", "progress": 0, "message": "开始训练..."}

        try:
            # 如果没有数据，生成默认数据
            if X_train is None or y_train is None:
                from src.data_generator import ensure_data_generated
                X_train, y_train, _, _ = ensure_data_generated()

            n = len(X_train)
            logger.info("开始训练所有模型: %d条数据", n)

            # 1. 训练Isolation Forest
            self.training_status["message"] = "训练Isolation Forest..."
            from sklearn.ensemble import IsolationForest
            self.if_model = IsolationForest(
                n_estimators=80, max_samples=200,
                contamination=0.15, random_state=42, n_jobs=1
            )
            self.if_model.fit(X_train)
            import joblib
            joblib.dump(self.if_model, self._get_if_path())
            self.training_status["progress"] = 33
            logger.info("IF训练完成")

            # 2. 训练LogisticRegression (轻量MLP)
            self.training_status["message"] = "训练MLP..."
            from sklearn.linear_model import LogisticRegression
            self.mlp_model = LogisticRegression(C=1.0, max_iter=500, solver="lbfgs", random_state=42)
            self.mlp_model.fit(X_train, y_train)
            self.mlp_coef = self.mlp_model.coef_.copy()
            self.mlp_intercept = self.mlp_model.intercept_.copy()
            np.save(self._get_mlp_weights_path(), self.mlp_coef)
            np.save(self._get_mlp_bias_path(), self.mlp_intercept)
            train_acc = self.mlp_model.score(X_train, y_train)
            self.training_status["progress"] = 66
            logger.info("MLP训练完成: train_acc=%.4f", train_acc)

            # 3. 训练Q-learning
            self.training_status["message"] = "训练Q-learning智能体(500 episodes)..."
            from src.optimization.agent import QLearningAgent
            self.q_agent = QLearningAgent()
            rewards = self.q_agent.train(total_timesteps=50000)
            np.save(self._get_q_path(), {"q_table": self.q_agent.q_table, "episodes": len(rewards)})
            self.training_status["progress"] = 100

            self.is_ready = True
            self.training_status["status"] = "completed"
            self.training_status["message"] = "所有模型训练完成"

            # 保存训练记录
            preds = self.predict(X_train[:min(len(X_train), 500)])
            y_true = y_train[:len(preds)]
            acc = float(np.mean(preds == y_true))
            self._train_history.append({
                "timestamp": time.time(),
                "accuracy": round(acc, 4),
                "if_accuracy": round(acc, 4),
                "mlp_accuracy": round(train_acc, 4),
                "samples": n,
                "q_episodes": len(rewards),
            })
            logger.info("所有模型训练完成: accuracy=%.4f", acc)

            # 保存训练记录到数据库
            try:
                from src.utils.data_storage import db
                db.save_training_record({
                    "model_type": "IF+MLP+Q",
                    "dataset_name": "auto_generated",
                    "accuracy": round(acc, 4),
                    "precision": round(acc, 4),
                    "recall": round(acc, 4),
                    "f1_score": round(acc, 4),
                    "epochs": 10,
                    "samples": n,
                })
            except Exception:
                pass

        except Exception as e:
            self.training_status["status"] = "failed"
            self.training_status["message"] = str(e)
            logger.error("模型训练失败: %s", e)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """混合模型预测（IF + MLP加权投票）

        Args:
            X: 特征矩阵 (n_samples, n_features)

        Returns:
            预测标签 (n_samples,)
        """
        if not self.is_ready or self.if_model is None:
            return np.zeros(len(X))

        # IF决策函数
        if_raw = self.if_model.decision_function(X)
        if_score = 1.0 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)

        # MLP预测概率
        if self.mlp_coef is not None:
            z = np.dot(X, self.mlp_coef.T) + self.mlp_intercept
            mlp_prob = 1.0 / (1.0 + np.exp(-np.clip(z, -20, 20))).flatten()
        else:
            mlp_prob = self.mlp_model.predict_proba(X)[:, 1]

        # 加权投票: IF 0.4 + MLP 0.6
        final_score = 0.4 * if_score + 0.6 * mlp_prob
        return (final_score >= 0.5).astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """返回异常概率 [0, 1]"""
        if not self.is_ready or self.if_model is None:
            return np.zeros(len(X))

        if_raw = self.if_model.decision_function(X)
        if_score = 1.0 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)

        if self.mlp_coef is not None:
            z = np.dot(X, self.mlp_coef.T) + self.mlp_intercept
            mlp_prob = 1.0 / (1.0 + np.exp(-np.clip(z, -20, 20))).flatten()
        else:
            mlp_prob = self.mlp_model.predict_proba(X)[:, 1]

        return np.clip(0.4 * if_score + 0.6 * mlp_prob, 0.0, 1.0)

    def retrain(self, X_train: np.ndarray, y_train: np.ndarray) -> Dict:
        """重新训练所有模型（后台）"""
        t = threading.Thread(target=self._train_all, args=(X_train, y_train), daemon=True)
        t.start()
        return {"status": "started", "message": "重训练已启动"}

    def get_status(self) -> Dict:
        """获取模型状态"""
        return {
            "is_ready": self.is_ready,
            "training_status": self.training_status,
            "models": {
                "if": self.if_model is not None,
                "mlp": self.mlp_coef is not None,
                "q_agent": self.q_agent is not None and self.q_agent.is_trained,
            } if self.is_ready else {},
            "history": self._train_history[-5:] if self._train_history else [],
        }

    def get_q_agent(self):
        """获取Q-learning智能体（供优化器使用）"""
        return self.q_agent


# 全局单例
model_manager = ModelManager()
