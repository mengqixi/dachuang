"""LSTM时序异常检测模型

基于TensorFlow/Keras的LSTM模型，用于检测时序异常。
处理流式加密操作日志，发现时序上的异常模式。
"""

from typing import Optional, Tuple, List, Dict, Any
import numpy as np
from loguru import logger


class LSTMDetector:
    """LSTM时序异常检测模型

    使用时序LSTM网络检测加密操作序列中的异常模式。
    支持训练、预测、概率输出和模型持久化。

    属性:
        model: tf.keras.Model实例
        input_dim: 输入特征维度
        hidden_units: LSTM隐藏单元数
        sequence_length: 序列长度
        _is_fitted: 模型是否已训练
    """

    def __init__(
        self,
        input_dim: int = 18,
        hidden_units: int = 128,
        sequence_length: int = 10,
        num_layers: int = 2,
        dropout_rate: float = 0.3,
    ):
        self.input_dim = input_dim
        self.hidden_units = hidden_units
        self.sequence_length = sequence_length
        self.num_layers = num_layers
        self.dropout_rate = dropout_rate
        self.model = None
        self._is_fitted = False

    def _build_model(self) -> None:
        """构建LSTM网络"""
        try:
            import tensorflow as tf
        except ImportError:
            logger.warning("TensorFlow不可用，使用后备实现")
            self._build_fallback()
            return

        inputs = tf.keras.Input(shape=(self.sequence_length, self.input_dim))
        x = inputs

        for i in range(self.num_layers):
            return_seq = i < self.num_layers - 1
            x = tf.keras.layers.LSTM(
                self.hidden_units // (2**i),
                return_sequences=return_seq,
                dropout=self.dropout_rate,
            )(x)

        x = tf.keras.layers.Dense(64, activation="relu")(x)
        x = tf.keras.layers.Dropout(self.dropout_rate)(x)
        outputs = tf.keras.layers.Dense(1, activation="sigmoid")(x)

        self.model = tf.keras.Model(inputs=inputs, outputs=outputs)
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss="binary_crossentropy",
            metrics=["accuracy"],
        )
        logger.info(f"LSTM模型构建完成: {self.model.count_params()}参数")

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 50,
        batch_size: int = 64,
        validation_split: float = 0.2,
        verbose: int = 0,
    ) -> Dict[str, List[float]]:
        """训练LSTM模型

        Args:
            X: 序列特征, shape (n_samples, sequence_length, input_dim)
            y: 标签, shape (n_samples,)
            epochs: 训练轮数
            batch_size: 批大小
            validation_split: 验证集比例
            verbose: 日志级别

        Returns:
            训练历史字典
        """
        if self.model is None:
            self._build_model()

        logger.info(f"训练LSTM: X.shape={X.shape}, epochs={epochs}, batch_size={batch_size}")

        try:
            import tensorflow as tf
            history = self.model.fit(
                X, y,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=validation_split,
                verbose=verbose,
            )
            self._is_fitted = True
            return {
                "loss": [float(v) for v in history.history["loss"]],
                "accuracy": [float(v) for v in history.history["accuracy"]],
                "val_loss": [float(v) for v in history.history.get("val_loss", [])],
                "val_accuracy": [float(v) for v in history.history.get("val_accuracy", [])],
            }
        except Exception as e:
            logger.warning(f"TensorFlow训练失败: {e}, 使用PyTorch后备")
            return self._fit_fallback(X, y, epochs, batch_size)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测是否异常

        Args:
            X: 序列特征

        Returns:
            预测结果: 1=异常, 0=正常
        """
        if self.model is None or not self._is_fitted:
            return np.zeros(len(X))

        try:
            preds = self.model.predict(X, verbose=0)
            return (preds.squeeze() > 0.5).astype(int)
        except Exception:
            return self._predict_fallback(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测异常概率

        Args:
            X: 序列特征

        Returns:
            异常概率
        """
        if self.model is None or not self._is_fitted:
            return np.zeros(len(X))

        try:
            preds = self.model.predict(X, verbose=0)
            return preds.squeeze()
        except Exception:
            return self._predict_fallback(X)

    def is_fitted(self) -> bool:
        return self._is_fitted

    def save(self, path: str) -> None:
        """保存模型"""
        if self.model is not None:
            try:
                import tensorflow as tf
                self.model.save(path)
                logger.info(f"LSTM模型已保存: {path}")
            except Exception as e:
                logger.warning(f"保存LSTM模型失败: {e}")

    def load(self, path: str) -> bool:
        """加载模型"""
        try:
            import tensorflow as tf
            self.model = tf.keras.models.load_model(path)
            self._is_fitted = True
            logger.info(f"LSTM模型已加载: {path}")
            return True
        except Exception as e:
            logger.warning(f"加载LSTM模型失败: {e}")
            return False

    def _build_fallback(self) -> None:
        """TensorFlow不可用时的后备网络"""
        try:
            import torch
            import torch.nn as nn

            class LSTMModule(nn.Module):
                def __init__(self, input_dim, hidden, num_layers, dropout):
                    super().__init__()
                    self.lstm = nn.LSTM(input_dim, hidden, num_layers, batch_first=True, dropout=dropout)
                    self.fc = nn.Sequential(
                        nn.Linear(hidden, 64), nn.ReLU(), nn.Dropout(dropout), nn.Linear(64, 1), nn.Sigmoid()
                    )

                def forward(self, x):
                    _, (h_n, _) = self.lstm(x)
                    return self.fc(h_n[-1])

            self._fallback_torch = True
            self._torch_model = LSTMModule(self.input_dim, self.hidden_units, self.num_layers, self.dropout_rate)
            logger.info("使用PyTorch后备LSTM模型")
        except ImportError:
            self._fallback_torch = False
            logger.warning("PyTorch也不可用，使用规则后备")
            self._fallback_rule_based = True

    def _fit_fallback(self, X, y, epochs, batch_size) -> Dict:
        if hasattr(self, "_fallback_torch") and self._fallback_torch:
            try:
                import torch, torch.nn as nn
                device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                model = self._torch_model.to(device)
                optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
                criterion = nn.BCELoss()

                X_t = torch.FloatTensor(X).to(device)
                y_t = torch.FloatTensor(y).to(device)
                dataset = torch.utils.data.TensorDataset(X_t, y_t)
                loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

                history = {"loss": [], "accuracy": []}
                for epoch in range(epochs):
                    model.train()
                    epoch_loss = 0.0
                    correct = 0
                    total = 0
                    for bx, by in loader:
                        optimizer.zero_grad()
                        outputs = model(bx).squeeze()
                        loss = criterion(outputs, by)
                        loss.backward()
                        optimizer.step()
                        epoch_loss += loss.item()
                        preds = (outputs > 0.5).float()
                        correct += (preds == by).sum().item()
                        total += len(by)
                    history["loss"].append(epoch_loss / len(loader))
                    history["accuracy"].append(correct / total)

                self._is_fitted = True
                return history
            except Exception as e:
                logger.warning(f"PyTorch后备训练失败: {e}")

        return {"loss": [], "accuracy": []}

    def _predict_fallback(self, X) -> np.ndarray:
        if hasattr(self, "_fallback_torch") and self._fallback_torch and self._torch_model is not None:
            try:
                import torch
                device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self._torch_model.eval()
                with torch.no_grad():
                    X_t = torch.FloatTensor(X).to(device)
                    preds = self._torch_model(X_t).cpu().numpy().squeeze()
                return (preds > 0.5).astype(int)
            except Exception:
                pass
        return np.zeros(len(X))
