# -*- coding: utf-8 -*-
"""FedAvg 聚合服务器与轻量 Paillier 权重安全聚合。"""

import threading
import time

import numpy as np
from typing import Dict, List, Tuple
from loguru import logger


def _valid_client_results(client_results: List[Dict]) -> List[Dict]:
    """Return finite, shape-compatible client updates with positive weights."""
    candidates = []
    for result in client_results or []:
        try:
            samples = int(result.get("samples") or 0)
            weights = np.asarray(result.get("weights"), dtype=np.float64)
        except (TypeError, ValueError):
            continue
        if samples <= 0 or weights.size == 0 or not np.all(np.isfinite(weights)):
            continue
        candidates.append(result)
    if not candidates:
        return []
    expected_shape = np.asarray(candidates[0]["weights"], dtype=np.float64).shape
    return [
        result for result in candidates
        if np.asarray(result["weights"], dtype=np.float64).shape == expected_shape
    ]


def _decode_signed(value: int, modulus: int) -> int:
    """Decode one signed integer represented in the Paillier plaintext ring."""
    return int(value - modulus) if value > modulus // 2 else int(value)


def paillier_weighted_average(
    client_results: List[Dict],
    paillier,
    quantization_scale: int = 1000000,
    max_clients: int = 16,
    max_parameters: int = 256,
) -> Tuple[np.ndarray, Dict]:
    """Aggregate client weights through real Paillier ciphertext operations.

    Each node vector is fixed-point encoded and encrypted. The aggregation
    path performs only ciphertext scalar multiplication and ciphertext
    addition before decrypting the final weighted sum. The current platform
    still runs all logical nodes in one process, so this proves the encrypted
    aggregation path but does not claim cross-institution key isolation.
    """
    valid = _valid_client_results(client_results)
    if not valid:
        raise ValueError("没有可用于安全聚合的节点权重")
    if paillier is None or not getattr(paillier, "_ready", False) or not getattr(paillier, "n", None):
        raise ValueError("Paillier 安全聚合密钥尚未就绪")
    if len(valid) > max_clients:
        raise ValueError("安全聚合节点数量超过上限 %d" % max_clients)

    shape = np.asarray(valid[0]["weights"], dtype=np.float64).shape
    parameter_count = int(np.asarray(valid[0]["weights"]).size)
    if parameter_count > max_parameters:
        raise ValueError("安全聚合参数数量超过上限 %d" % max_parameters)
    scale = max(1, int(quantization_scale))
    samples = [int(result.get("samples") or 0) for result in valid]
    total_samples = sum(samples)
    vectors = [np.asarray(result["weights"], dtype=np.float64).reshape(-1) for result in valid]
    quantized = [np.rint(vector * scale).astype(object) for vector in vectors]

    max_abs_weighted_sum = 0
    for parameter_index in range(parameter_count):
        bound = sum(
            abs(int(quantized[client_index][parameter_index])) * samples[client_index]
            for client_index in range(len(valid))
        )
        max_abs_weighted_sum = max(max_abs_weighted_sum, bound)
    if max_abs_weighted_sum >= paillier.n // 3:
        raise OverflowError("量化后的节点权重超出 Paillier 安全编码范围")

    encryption_started = time.perf_counter()
    encrypted_updates = [
        [paillier.encrypt(int(value) % paillier.n) for value in vector]
        for vector in quantized
    ]
    encryption_time_ms = (time.perf_counter() - encryption_started) * 1000.0

    aggregation_started = time.perf_counter()
    encrypted_totals = []
    for parameter_index in range(parameter_count):
        encrypted_total = paillier.multiply(encrypted_updates[0][parameter_index], samples[0])
        for client_index in range(1, len(valid)):
            weighted_ciphertext = paillier.multiply(
                encrypted_updates[client_index][parameter_index],
                samples[client_index],
            )
            encrypted_total = paillier.add(encrypted_total, weighted_ciphertext)
        encrypted_totals.append(encrypted_total)
    aggregation_time_ms = (time.perf_counter() - aggregation_started) * 1000.0

    decryption_started = time.perf_counter()
    decoded = []
    for encrypted_total in encrypted_totals:
        signed_total = _decode_signed(paillier.decrypt(encrypted_total), paillier.n)
        decoded.append(signed_total / float(scale * total_samples))
    decryption_time_ms = (time.perf_counter() - decryption_started) * 1000.0

    aggregated = np.asarray(decoded, dtype=np.float64).reshape(shape)
    plain_reference = np.zeros(shape, dtype=np.float64)
    for vector, sample_count in zip(vectors, samples):
        plain_reference += vector.reshape(shape) * (sample_count / float(total_samples))
    max_abs_delta = float(np.max(np.abs(aggregated - plain_reference)))
    encrypted_parameter_count = parameter_count * len(valid)
    key_size_bits = int(getattr(paillier, "key_size", 0) or 0)
    ciphertext_payload_bytes = encrypted_parameter_count * ((key_size_bits * 2 + 7) // 8)

    metrics = {
        "paillier_enabled": True,
        "secure_aggregation": True,
        "secure_aggregation_requested": True,
        "display_only": False,
        "timing_method": "measured_wall_clock",
        "actual_crypto_operations_performed": True,
        "aggregation_method": "fedavg_paillier_secure",
        "key_status": "ready",
        "key_size_bits": key_size_bits,
        "model_parameter_count": parameter_count,
        "encrypted_parameter_count": encrypted_parameter_count,
        "ciphertext_aggregate_count": parameter_count,
        "ciphertext_scalar_multiplications": parameter_count * len(valid),
        "ciphertext_additions": parameter_count * max(0, len(valid) - 1),
        "ciphertext_payload_bytes": int(ciphertext_payload_bytes),
        "quantization_scale": scale,
        "encryption_time_ms": round(encryption_time_ms, 2),
        "aggregation_time_ms": round(aggregation_time_ms, 2),
        "decryption_time_ms": round(decryption_time_ms, 2),
        "elapsed_ms": round(encryption_time_ms + aggregation_time_ms + decryption_time_ms, 2),
        "max_abs_weight_delta": max_abs_delta,
        "individual_updates_decrypted": False,
        "server_plaintext_node_updates_observable": True,
        "cross_institution_key_isolation": False,
        "trust_boundary": "single_host_logical_nodes",
        "status": "secure_aggregation_completed",
        "note": (
            "节点权重已执行 Paillier 定点量化、逐参数加密、密态加权求和，并且只解密最终聚合权重。"
            "当前四节点仍在同一进程内，聚合前的节点权重对平台进程可见，因此不等同于跨机构端到端密钥隔离。"
        ),
    }
    return aggregated, metrics


class FedAvgServer:
    """FedAvg聚合服务器"""

    def __init__(self):
        self.global_weights = None
        self.round = 0
        self._accuracy_history = []
        self.context_id = None
        self._lock = threading.RLock()

    def ensure_context(self, context_id: str, force_reset: bool = False) -> bool:
        """Reset aggregation state when the prepared dataset revision changes."""
        normalized = str(context_id or "unversioned")
        with self._lock:
            changed = bool(force_reset or self.context_id != normalized)
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
            valid = _valid_client_results(client_results)
            if not valid:
                logger.warning("FedAvg: 无有效客户端结果")
                return self.global_weights
            total_samples = sum(int(r.get("samples") or 0) for r in valid)
            if total_samples <= 0:
                return self.global_weights

            weighted_sum = np.zeros(np.asarray(valid[0]["weights"]).shape, dtype=np.float64)
            for result in valid:
                samples = int(result.get("samples") or 0)
                ratio = samples / total_samples
                weighted_sum += np.asarray(result["weights"], dtype=np.float64) * ratio
            return self._record_round_locked(weighted_sum, valid, "plain")

    def aggregate_paillier(self, client_results: List[Dict], paillier) -> Tuple[np.ndarray, Dict]:
        """Aggregate one round through bounded Paillier ciphertext operations."""
        with self._lock:
            valid = _valid_client_results(client_results)
            aggregated, crypto_metrics = paillier_weighted_average(valid, paillier)
            weights = self._record_round_locked(aggregated, valid, "fedavg_paillier_secure")
            crypto_metrics["round"] = self.round
            return weights, crypto_metrics

    def _record_round_locked(
        self,
        aggregated_weights: np.ndarray,
        valid: List[Dict],
        aggregation_method: str,
    ) -> np.ndarray:
        total_samples = sum(int(result.get("samples") or 0) for result in valid)
        weighted_accuracy = 0.0
        weighted_loss = 0.0
        loss_samples = 0
        for result in valid:
            samples = int(result.get("samples") or 0)
            weighted_accuracy += float(result.get("accuracy") or 0.0) * (samples / float(total_samples))
            if result.get("loss") is not None:
                weighted_loss += float(result.get("loss") or 0.0) * samples
                loss_samples += samples

        self.global_weights = np.asarray(aggregated_weights, dtype=np.float64)
        self.round += 1
        avg_loss = weighted_loss / loss_samples if loss_samples else 0.0
        self._accuracy_history.append({
            "round": self.round,
            "accuracy": round(weighted_accuracy, 4),
            "display_accuracy": round(weighted_accuracy, 4),
            "loss": round(avg_loss, 4),
            "context_id": self.context_id,
            "samples": total_samples,
            "aggregation_method": aggregation_method,
        })

        logger.info(
            "FedAvg round={} clients={} method={} weighted_accuracy={:.4f} weighted_loss={:.4f}",
            self.round,
            len(valid),
            aggregation_method,
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
    """Compatibility wrapper for legacy encrypted-gradient callers."""

    def __init__(self, key_size: int = 2048, quantization_scale: int = 1000000):
        self._paillier = None
        self.key_size = max(128, int(key_size))
        self.quantization_scale = max(1, int(quantization_scale))

    def _get_paillier(self):
        if self._paillier is None:
            try:
                from src.encryption.paillier import Paillier
                self._paillier = Paillier(key_size=self.key_size)
                self._paillier.generate_keys()
                logger.info("Paillier梯度加密器已初始化")
            except Exception as e:
                logger.warning("Paillier初始化失败: {}", e)
        return self._paillier

    def encrypt_gradient(self, gradient: np.ndarray) -> np.ndarray:
        """加密梯度向量"""
        p = self._get_paillier()
        if p is None:
            raise RuntimeError("Paillier 梯度加密器初始化失败")
        scaled = np.rint(np.asarray(gradient, dtype=np.float64) * self.quantization_scale).astype(object)
        encrypted = [p.encrypt(int(value) % p.n) for value in scaled.flatten()]
        return np.asarray(encrypted, dtype=object).reshape(scaled.shape)

    def decrypt_gradient(self, encrypted: np.ndarray, shape) -> np.ndarray:
        """解密密文梯度"""
        p = self._get_paillier()
        if p is None:
            raise RuntimeError("Paillier 梯度解密器初始化失败")
        decrypted = [
            _decode_signed(p.decrypt(int(ciphertext)), p.n) / float(self.quantization_scale)
            for ciphertext in np.asarray(encrypted, dtype=object).flatten()
        ]
        return np.asarray(decrypted, dtype=np.float64).reshape(shape)

    def aggregate_encrypted(self, encrypted_grads: List[np.ndarray], n_samples: List[int]) -> np.ndarray:
        """同态聚合加密梯度"""
        if len(encrypted_grads) == 0:
            return None
        p = self._get_paillier()
        if p is None:
            raise RuntimeError("Paillier 梯度聚合器初始化失败")
        total = sum(max(0, int(value)) for value in n_samples)
        if total <= 0:
            raise ValueError("节点样本权重必须大于 0")
        arrays = [np.asarray(value, dtype=object) for value in encrypted_grads]
        shape = arrays[0].shape
        if any(value.shape != shape for value in arrays):
            raise ValueError("加密梯度形状不一致")
        output = []
        for parameter_index in range(arrays[0].size):
            encrypted_total = p.multiply(int(arrays[0].flat[parameter_index]), int(n_samples[0]))
            for client_index in range(1, len(arrays)):
                weighted = p.multiply(
                    int(arrays[client_index].flat[parameter_index]),
                    int(n_samples[client_index]),
                )
                encrypted_total = p.add(encrypted_total, weighted)
            signed_total = _decode_signed(p.decrypt(encrypted_total), p.n)
            encoded_average = int(round(signed_total / float(total))) % p.n
            output.append(p.encrypt(encoded_average))
        return np.asarray(output, dtype=object).reshape(shape)


fedavg_server = FedAvgServer()
paillier_encryptor = PaillierGradientEncryptor()
