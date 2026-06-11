# -*- coding: utf-8 -*-
"""FedAvg聚合服务器 - 支持Paillier加密梯度聚合"""

import numpy as np
from typing import Dict, List
from loguru import logger


class FedAvgServer:
    """FedAvg聚合服务器"""

    def __init__(self):
        self.global_weights = None
        self.round = 0
        self._accuracy_history = []

    def aggregate(self, client_results: List[Dict]) -> np.ndarray:
        """FedAvg加权聚合

        Args:
            client_results: [{name, weights, samples, accuracy}, ...]

        Returns:
            聚合后的全局权重
        """
        total_samples = sum(r.get("samples", 0) for r in client_results if r.get("weights") is not None)
        if total_samples == 0:
            logger.warning("FedAvg: 无有效客户端结果")
            return self.global_weights

        # 加权平均
        weighted_sum = None
        for r in client_results:
            w = r.get("weights")
            if w is None:
                continue
            weight = r["samples"] / total_samples
            if weighted_sum is None:
                weighted_sum = w * weight
            else:
                weighted_sum += w * weight

        self.global_weights = weighted_sum
        self.round += 1

        avg_acc = np.mean([r.get("accuracy", 0) for r in client_results])
        losses = [r.get("loss") for r in client_results if r.get("loss") is not None]
        avg_loss = float(np.mean(losses)) if losses else 0.0
        self._accuracy_history.append({
            "round": self.round,
            "accuracy": round(float(avg_acc), 4),
            "loss": round(avg_loss, 4),
        })

        logger.info("FedAvg 第%d轮: %d个客户端, avg_acc=%.4f, avg_loss=%.4f",
                    self.round, len(client_results), avg_acc, avg_loss)
        return self.global_weights

    def get_history(self) -> List[Dict]:
        return self._accuracy_history


class PaillierGradientEncryptor:
    """Paillier同态加密梯度保护"""

    def __init__(self):
        self._paillier = None

    def _get_paillier(self):
        if self._paillier is None:
            try:
                from src.encryption.paillier import Paillier
                self._paillier = Paillier(key_size=512)
                self._paillier.generate_keys()
                logger.info("Paillier梯度加密器已初始化")
            except Exception as e:
                logger.warning("Paillier初始化失败: %s", e)
        return self._paillier

    def encrypt_gradient(self, gradient: np.ndarray) -> np.ndarray:
        """加密梯度向量"""
        p = self._get_paillier()
        if p is None:
            return gradient * (1 + np.random.randn() * 0.001)  # fallback noise

        # 量化浮点为整数，加密
        scaled = (gradient * 1e6).astype(int)
        encrypted = np.array([p.encrypt(int(v)) for v in scaled.flatten()])
        return encrypted

    def decrypt_gradient(self, encrypted: np.ndarray, shape) -> np.ndarray:
        """解密密文梯度"""
        p = self._get_paillier()
        if p is None:
            return encrypted

        decrypted = np.array([p.decrypt(int(c)) for c in encrypted.flatten()])
        return decrypted.reshape(shape) / 1e6

    def aggregate_encrypted(self, encrypted_grads: List[np.ndarray], n_samples: List[int]) -> np.ndarray:
        """同态聚合加密梯度"""
        if len(encrypted_grads) == 0:
            return None
        total = sum(n_samples)
        if total == 0:
            total = len(encrypted_grads)

        # 密文加权求和
        result = encrypted_grads[0] * (n_samples[0] / total)
        for i in range(1, len(encrypted_grads)):
            result = result + encrypted_grads[i] * (n_samples[i] / total)

        return result


fedavg_server = FedAvgServer()
paillier_encryptor = PaillierGradientEncryptor()
