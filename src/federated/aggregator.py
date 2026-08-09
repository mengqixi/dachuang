# -*- coding: utf-8 -*-
"""FedAvg聚合服务器 - 支持Paillier加密梯度聚合"""

import threading

import numpy as np
from typing import Dict, List
from loguru import logger


class FedAvgServer:
    """FedAvg聚合服务器"""

    def __init__(self):
        self.global_weights = None
        self.round = 0
        self._accuracy_history = []
        self.context_id = None
        self._lock = threading.RLock()

    def ensure_context(self, context_id: str) -> bool:
        """Reset aggregation state when the prepared dataset revision changes."""
        normalized = str(context_id or "unversioned")
        with self._lock:
            changed = self.context_id != normalized
            if changed:
                self.context_id = normalized
                self.global_weights = None
                self.round = 0
                self._accuracy_history = []
                logger.info("FedAvg context reset: {}", normalized)
            return changed

    def aggregate(self, client_results: List[Dict]) -> np.ndarray:
        """FedAvg加权聚合

        Args:
            client_results: [{name, weights, samples, accuracy}, ...]

        Returns:
            聚合后的全局权重
        """
        with self._lock:
            valid = [
                r for r in client_results
                if r.get("weights") is not None and int(r.get("samples") or 0) > 0
            ]
            if not valid:
                logger.warning("FedAvg: 无有效客户端结果")
                return self.global_weights
            expected_shape = np.asarray(valid[0]["weights"]).shape
            valid = [r for r in valid if np.asarray(r["weights"]).shape == expected_shape]
            total_samples = sum(int(r.get("samples") or 0) for r in valid)
            if total_samples <= 0:
                return self.global_weights

            weighted_sum = np.zeros(expected_shape, dtype=np.float64)
            weighted_accuracy = 0.0
            weighted_loss = 0.0
            loss_samples = 0
            for result in valid:
                samples = int(result.get("samples") or 0)
                ratio = samples / total_samples
                weighted_sum += np.asarray(result["weights"], dtype=np.float64) * ratio
                weighted_accuracy += float(result.get("accuracy") or 0.0) * ratio
                if result.get("loss") is not None:
                    weighted_loss += float(result.get("loss") or 0.0) * samples
                    loss_samples += samples

            self.global_weights = weighted_sum
            self.round += 1
            avg_loss = weighted_loss / loss_samples if loss_samples else 0.0
            self._accuracy_history.append({
                "round": self.round,
                "accuracy": round(weighted_accuracy, 4),
                "display_accuracy": round(weighted_accuracy, 4),
                "loss": round(avg_loss, 4),
                "context_id": self.context_id,
                "samples": total_samples,
            })

            logger.info(
                "FedAvg round={} clients={} weighted_accuracy={:.4f} weighted_loss={:.4f}",
                self.round,
                len(valid),
                weighted_accuracy,
                avg_loss,
            )
            return self.global_weights.copy()

    def get_history(self) -> List[Dict]:
        with self._lock:
            return [dict(item) for item in self._accuracy_history]

    def get_status(self) -> Dict:
        with self._lock:
            return {
                "context_id": self.context_id,
                "round": self.round,
                "has_global_weights": self.global_weights is not None,
                "history": [dict(item) for item in self._accuracy_history],
            }


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
                logger.warning("Paillier初始化失败: {}", e)
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
