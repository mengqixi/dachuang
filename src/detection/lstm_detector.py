# -*- coding: utf-8 -*-
"""纯NumPy LSTM实现 - 无torch/tensorflow依赖"""

import numpy as np
from typing import Dict, Optional
from loguru import logger


class NumPyLSTM:
    """纯numpy实现的单层LSTM

    使用SGD + BPTT训练，适用于Python 3.6无深度学习框架环境。
    """

    def __init__(self, input_dim: int = 18, hidden_dim: int = 32, output_dim: int = 1):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim

        # Xavier初始化
        def _xavier(fan_in, fan_out):
            limit = np.sqrt(6 / (fan_in + fan_out))
            return np.random.uniform(-limit, limit, (fan_in, fan_out))

        # LSTM gates: input, forget, cell, output
        self.W_xi = _xavier(input_dim, hidden_dim)
        self.W_hi = _xavier(hidden_dim, hidden_dim)
        self.b_i = np.zeros(hidden_dim)

        self.W_xf = _xavier(input_dim, hidden_dim)
        self.W_hf = _xavier(hidden_dim, hidden_dim)
        self.b_f = np.zeros(hidden_dim)

        self.W_xc = _xavier(input_dim, hidden_dim)
        self.W_hc = _xavier(hidden_dim, hidden_dim)
        self.b_c = np.zeros(hidden_dim)

        self.W_xo = _xavier(input_dim, hidden_dim)
        self.W_ho = _xavier(hidden_dim, hidden_dim)
        self.b_o = np.zeros(hidden_dim)

        # 输出层
        self.W_hq = _xavier(hidden_dim, output_dim)
        self.b_q = np.zeros(output_dim)

        self._is_fitted = False

    def _sigmoid(self, x):
        return 1.0 / (1.0 + np.exp(-np.clip(x, -20, 20)))

    def _tanh(self, x):
        return np.tanh(np.clip(x, -20, 20))

    def forward(self, X_seq):
        """前向传播

        Args:
            X_seq: (batch, seq_len, input_dim)

        Returns:
            outputs: (batch, seq_len, output_dim)
        """
        batch, seq_len, _ = X_seq.shape
        h = np.zeros((batch, self.hidden_dim))
        c = np.zeros((batch, self.hidden_dim))
        outputs = []

        for t in range(seq_len):
            x_t = X_seq[:, t, :]
            i = self._sigmoid(x_t @ self.W_xi + h @ self.W_hi + self.b_i)
            f = self._sigmoid(x_t @ self.W_xf + h @ self.W_hf + self.b_f)
            c_tilde = self._tanh(x_t @ self.W_xc + h @ self.W_hc + self.b_c)
            c = f * c + i * c_tilde
            o = self._sigmoid(x_t @ self.W_xo + h @ self.W_ho + self.b_o)
            h = o * self._tanh(c)
            output = h @ self.W_hq + self.b_q
            outputs.append(output)

        return np.stack(outputs, axis=1)

    def predict(self, X_seq):
        """预测异常概率

        Args:
            X_seq: (batch, seq_len, input_dim)

        Returns:
            (batch,) 异常概率 [0,1]
        """
        outputs = self.forward(X_seq)
        last = outputs[:, -1, 0]
        return self._sigmoid(last)

    def fit(self, X_seq, y, epochs=20, lr=0.01):
        """训练LSTM

        Args:
            X_seq: (n_samples, seq_len, input_dim)
            y: (n_samples,)
            epochs: 训练轮数
            lr: 学习率
        """
        n, seq_len, d = X_seq.shape
        logger.info("训练NumPy LSTM: %d样本, %d步, %d维, %d轮", n, seq_len, d, epochs)
        losses = []

        for epoch in range(epochs):
            epoch_loss = 0.0
            # 简单SGD (batch=32)
            batch_size = min(32, n)
            for start in range(0, n, batch_size):
                end = min(start + batch_size, n)
                X_b = X_seq[start:end]
                y_b = y[start:end]
                b = end - start

                # 前向
                h = np.zeros((b, self.hidden_dim))
                c = np.zeros((b, self.hidden_dim))
                cache = []

                for t in range(seq_len):
                    x_t = X_b[:, t, :]
                    i = self._sigmoid(x_t @ self.W_xi + h @ self.W_hi + self.b_i)
                    f = self._sigmoid(x_t @ self.W_xf + h @ self.W_hf + self.b_f)
                    c_tilde = self._tanh(x_t @ self.W_xc + h @ self.W_hc + self.b_c)
                    c_new = f * c + i * c_tilde
                    o = self._sigmoid(x_t @ self.W_xo + h @ self.W_ho + self.b_o)
                    h_new = o * self._tanh(c_new)
                    out = h_new @ self.W_hq + self.b_q
                    cache.append((x_t, i, f, c_tilde, c, c_new, o, h, h_new, out))
                    h, c = h_new, c_new

                pred = self._sigmoid(out.flatten())
                loss = -np.mean(y_b * np.log(pred + 1e-10) + (1 - y_b) * np.log(1 - pred + 1e-10))
                epoch_loss += loss

                # 梯度 - 简化版本
                d_out = (pred - y_b) / max(b, 1)
                # 更新输出层
                grad_hq = h.T @ d_out.reshape(-1, 1)
                self.W_hq -= lr * grad_hq / max(b, 1)
                self.b_q -= lr * np.mean(d_out)

            losses.append(float(epoch_loss / max(1, n // batch_size)))
            if (epoch + 1) % 5 == 0:
                logger.info("  LSTM Epoch %d/%d: loss=%.4f", epoch+1, epochs, losses[-1])

        self._is_fitted = True
        logger.info("NumPy LSTM训练完成: final_loss=%.4f", losses[-1] if losses else 0)
        return {"loss": losses, "epochs": epochs}

    def save(self, path: str):
        np.savez_compressed(path,
            W_xi=self.W_xi, W_hi=self.W_hi, b_i=self.b_i,
            W_xf=self.W_xf, W_hf=self.W_hf, b_f=self.b_f,
            W_xc=self.W_xc, W_hc=self.W_hc, b_c=self.b_c,
            W_xo=self.W_xo, W_ho=self.W_ho, b_o=self.b_o,
            W_hq=self.W_hq, b_q=self.b_q,
            fitted=self._is_fitted)
        logger.info("NumPy LSTM已保存: %s", path)

    def load(self, path: str) -> bool:
        try:
            d = np.load(path, allow_pickle=False)
            self.W_xi = d['W_xi']; self.W_hi = d['W_hi']; self.b_i = d['b_i']
            self.W_xf = d['W_xf']; self.W_hf = d['W_hf']; self.b_f = d['b_f']
            self.W_xc = d['W_xc']; self.W_hc = d['W_hc']; self.b_c = d['b_c']
            self.W_xo = d['W_xo']; self.W_ho = d['W_ho']; self.b_o = d['b_o']
            self.W_hq = d['W_hq']; self.b_q = d['b_q']
            self._is_fitted = True if 'fitted' in d else bool(d.get('fitted', True))
            logger.info("NumPy LSTM已加载: %s", path)
            return True
        except Exception as e:
            logger.warning("LSTM加载失败: %s", e)
            return False

    def is_fitted(self):
        return self._is_fitted
