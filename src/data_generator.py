"""虚拟数据生成器

生成带标签的攻击检测训练数据集，支持4种攻击类型 + 正常流量。
用于系统演示、模型预训练和功能测试。
"""

import os
import csv
import random
import numpy as np
from datetime import datetime
from loguru import logger

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)


def _normal_sample():
    """生成正常流量样本（18维特征）"""
    return {
        "key_generation_time": round(random.uniform(0.02, 0.10), 4),
        "ciphertext_entropy": round(random.uniform(6.0, 7.8), 4),
        "hash_collision_count": random.randint(0, 2),
        "request_frequency": round(random.uniform(5, 80), 1),
        "response_time": round(random.uniform(0.01, 0.08), 4),
        "payload_size": random.randint(100, 2000),
        "connection_duration": round(random.uniform(0.5, 30), 1),
        "packet_interarrival": round(random.uniform(0.01, 0.5), 4),
        "failed_attempts": random.randint(0, 1),
        "session_duration": round(random.uniform(10, 500), 1),
        "request_size_variance": round(random.uniform(5, 200), 2),
        "encryption_rounds": random.randint(1, 2),
        "decryption_success_rate": round(random.uniform(0.98, 1.0), 4),
        "memory_usage": round(random.uniform(0.05, 0.3), 3),
        "cpu_usage": round(random.uniform(0.02, 0.2), 3),
        "network_latency": round(random.uniform(0.001, 0.02), 4),
        "protocol_violations": random.randint(0, 1),
        "anomaly_score": round(random.uniform(0.0, 0.15), 4),
        "is_attack": 0,
        "attack_type": "正常",
    }


def _brute_force_sample():
    """暴力破解攻击样本"""
    return {
        "key_generation_time": round(random.uniform(0.15, 0.5), 4),
        "ciphertext_entropy": round(random.uniform(3.0, 5.5), 4),
        "hash_collision_count": random.randint(5, 50),
        "request_frequency": round(random.uniform(200, 1000), 1),
        "response_time": round(random.uniform(0.1, 0.5), 4),
        "payload_size": random.randint(50, 500),
        "connection_duration": round(random.uniform(0.1, 2), 1),
        "packet_interarrival": round(random.uniform(0.001, 0.01), 4),
        "failed_attempts": random.randint(5, 50),
        "session_duration": round(random.uniform(1, 30), 1),
        "request_size_variance": round(random.uniform(1, 10), 2),
        "encryption_rounds": random.randint(1, 2),
        "decryption_success_rate": round(random.uniform(0.3, 0.7), 4),
        "memory_usage": round(random.uniform(0.3, 0.8), 3),
        "cpu_usage": round(random.uniform(0.4, 0.9), 3),
        "network_latency": round(random.uniform(0.01, 0.05), 4),
        "protocol_violations": random.randint(3, 15),
        "anomaly_score": round(random.uniform(0.6, 0.95), 4),
        "is_attack": 1,
        "attack_type": "暴力破解",
    }


def _side_channel_sample():
    """侧信道攻击样本"""
    return {
        "key_generation_time": round(random.uniform(0.3, 0.8), 4),
        "ciphertext_entropy": round(random.uniform(4.0, 6.0), 4),
        "hash_collision_count": random.randint(1, 10),
        "request_frequency": round(random.uniform(30, 150), 1),
        "response_time": round(random.uniform(0.15, 0.6), 4),
        "payload_size": random.randint(500, 3000),
        "connection_duration": round(random.uniform(30, 300), 1),
        "packet_interarrival": round(random.uniform(0.01, 0.05), 4),
        "failed_attempts": random.randint(0, 5),
        "session_duration": round(random.uniform(100, 1000), 1),
        "request_size_variance": round(random.uniform(50, 500), 2),
        "encryption_rounds": random.randint(1, 3),
        "decryption_success_rate": round(random.uniform(0.7, 0.95), 4),
        "memory_usage": round(random.uniform(0.2, 0.6), 3),
        "cpu_usage": round(random.uniform(0.1, 0.4), 3),
        "network_latency": round(random.uniform(0.02, 0.08), 4),
        "protocol_violations": random.randint(0, 3),
        "anomaly_score": round(random.uniform(0.4, 0.8), 4),
        "is_attack": 1,
        "attack_type": "侧信道攻击",
    }


def _ciphertext_analysis_sample():
    """密文分析攻击样本"""
    return {
        "key_generation_time": round(random.uniform(0.05, 0.2), 4),
        "ciphertext_entropy": round(random.uniform(2.0, 4.5), 4),
        "hash_collision_count": random.randint(10, 80),
        "request_frequency": round(random.uniform(50, 200), 1),
        "response_time": round(random.uniform(0.05, 0.2), 4),
        "payload_size": random.randint(2000, 10000),
        "connection_duration": round(random.uniform(5, 60), 1),
        "packet_interarrival": round(random.uniform(0.005, 0.02), 4),
        "failed_attempts": random.randint(1, 10),
        "session_duration": round(random.uniform(30, 200), 1),
        "request_size_variance": round(random.uniform(100, 1000), 2),
        "encryption_rounds": random.randint(2, 4),
        "decryption_success_rate": round(random.uniform(0.5, 0.85), 4),
        "memory_usage": round(random.uniform(0.3, 0.7), 3),
        "cpu_usage": round(random.uniform(0.2, 0.6), 3),
        "network_latency": round(random.uniform(0.005, 0.03), 4),
        "protocol_violations": random.randint(1, 8),
        "anomaly_score": round(random.uniform(0.5, 0.85), 4),
        "is_attack": 1,
        "attack_type": "密文分析",
    }


def _key_recovery_sample():
    """密钥恢复攻击样本"""
    return {
        "key_generation_time": round(random.uniform(0.5, 2.0), 4),
        "ciphertext_entropy": round(random.uniform(5.0, 7.0), 4),
        "hash_collision_count": random.randint(3, 30),
        "request_frequency": round(random.uniform(10, 60), 1),
        "response_time": round(random.uniform(0.2, 1.0), 4),
        "payload_size": random.randint(100, 1000),
        "connection_duration": round(random.uniform(60, 600), 1),
        "packet_interarrival": round(random.uniform(0.02, 0.1), 4),
        "failed_attempts": random.randint(3, 20),
        "session_duration": round(random.uniform(200, 2000), 1),
        "request_size_variance": round(random.uniform(10, 100), 2),
        "encryption_rounds": random.randint(3, 5),
        "decryption_success_rate": round(random.uniform(0.2, 0.6), 4),
        "memory_usage": round(random.uniform(0.4, 0.9), 3),
        "cpu_usage": round(random.uniform(0.3, 0.8), 3),
        "network_latency": round(random.uniform(0.01, 0.04), 4),
        "protocol_violations": random.randint(2, 10),
        "anomaly_score": round(random.uniform(0.7, 0.98), 4),
        "is_attack": 1,
        "attack_type": "密钥恢复",
    }


GENERATORS = {
    0: _normal_sample,
    1: _brute_force_sample,
    2: _side_channel_sample,
    3: _ciphertext_analysis_sample,
    4: _key_recovery_sample,
}

FEATURE_NAMES = [
    "key_generation_time", "ciphertext_entropy", "hash_collision_count",
    "request_frequency", "response_time", "payload_size",
    "connection_duration", "packet_interarrival", "failed_attempts",
    "session_duration", "request_size_variance", "encryption_rounds",
    "decryption_success_rate", "memory_usage", "cpu_usage",
    "network_latency", "protocol_violations", "anomaly_score",
    "is_attack", "attack_type",
]


def generate_training_data(n_samples=2000, attack_ratio=0.35):
    """生成带标签的训练数据集

    Args:
        n_samples: 总样本数
        attack_ratio: 攻击样本比例

    Returns:
        list[dict]: 数据集
    """
    n_attacks = int(n_samples * attack_ratio)
    n_normal = n_samples - n_attacks

    samples = []

    # 正常样本
    for _ in range(n_normal):
        samples.append(_normal_sample())

    # 攻击样本（均匀分布在4种类型）
    attack_types = [1, 2, 3, 4]
    per_type = n_attacks // 4
    remainder = n_attacks % 4
    for i, at in enumerate(attack_types):
        count = per_type + (1 if i < remainder else 0)
        for _ in range(count):
            samples.append(GENERATORS[at]())

    # 打乱
    random.shuffle(samples)

    logger.info("生成训练数据: %d 样本 (正常: %d, 攻击: %d)" % (len(samples), n_normal, n_attacks))
    return samples


def save_to_csv(samples, filepath=None):
    """保存数据集到CSV文件"""
    if filepath is None:
        filepath = os.path.join(DATA_DIR, "generated_training_data.csv")

    with open(filepath, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_NAMES)
        writer.writeheader()
        writer.writerows(samples)

    logger.info("数据已保存: %s (%d 行)" % (filepath, len(samples)))
    return filepath


def generate_sequence_data(samples, seq_length=10):
    """从样本生成序列数据（用于LSTM训练）

    Args:
        samples: 特征样本列表（dict格式）
        seq_length: 序列长度

    Returns:
        X_seq: np.ndarray, shape (n_sequences, seq_length, 18)
        y_seq: np.ndarray, shape (n_sequences,)
    """
    X = np.array([[s[f] for f in FEATURE_NAMES[:18]] for s in samples], dtype=np.float32)
    y = np.array([s["is_attack"] for s in samples], dtype=np.float32)

    n_sequences = max(0, len(samples) - seq_length)
    if n_sequences == 0:
        return np.array([]), np.array([])

    X_seq = np.zeros((n_sequences, seq_length, 18), dtype=np.float32)
    y_seq = np.zeros(n_sequences, dtype=np.float32)

    for i in range(n_sequences):
        X_seq[i] = X[i:i + seq_length]
        y_seq[i] = 1.0 if np.mean(y[i:i + seq_length]) > 0.3 else 0.0

    return X_seq, y_seq


def generate_demo_dataset():
    """生成演示用CSV数据文件"""
    samples = generate_training_data(500, attack_ratio=0.3)
    filepath = os.path.join(DATA_DIR, "demo_attack_data.csv")
    return save_to_csv(samples, filepath)


def generate_and_prepare(force=False):
    """生成数据并准备为训练格式（供app.py启动时调用）

    Args:
        force: 是否强制重新生成

    Returns:
        dict: 包含训练数据的字典
    """
    demo_path = os.path.join(DATA_DIR, "demo_attack_data.csv")
    train_path = os.path.join(DATA_DIR, "generated_training_data.csv")

    if not force and os.path.exists(train_path):
        logger.info("训练数据已存在: %s" % train_path)
        # 读取已存在的数据
        try:
            import pandas as pd
            df = pd.read_csv(train_path)
            samples = df.to_dict(orient="records")
        except Exception:
            samples = generate_training_data(2000)
            save_to_csv(samples, train_path)
    else:
        samples = generate_training_data(2000)
        save_to_csv(samples, train_path)

    if not os.path.exists(demo_path):
        generate_demo_dataset()

    # 准备序列数据
    X_seq, y_seq = generate_sequence_data(samples)

    return {
        "samples": samples,
        "count": len(samples),
        "X_seq": X_seq,
        "y_seq": y_seq,
        "demo_path": demo_path,
        "train_path": train_path,
    }
