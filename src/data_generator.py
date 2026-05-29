# -*- coding: utf-8 -*-
"""虚拟数据生成器 - 增强版

生成10000条带标签的攻击检测训练数据集，按真实统计分布生成18维特征。
使用与FeatureExtractor一致的18个特征名称，可直接用于模型训练。
"""

import os
import random
from typing import Tuple, List, Dict, Any

import numpy as np
from loguru import logger

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "generated")

# 与 FeatureExtractor.FEATURE_NAMES 一致的18维特征
FEATURE_NAMES = [
    'key_generation_time', 'ciphertext_entropy', 'hash_collision_count',
    'request_frequency', 'response_time', 'payload_size',
    'connection_duration', 'packet_interarrival', 'failed_attempts',
    'session_duration', 'request_size_variance', 'encryption_rounds',
    'decryption_success_rate', 'memory_usage', 'cpu_usage',
    'network_latency', 'protocol_violations', 'anomaly_score',
]

# 每种攻击模式的特征分布 (min, max)
ATTACK_PATTERNS = {
    "normal": {
        "key_generation_time": (0.02, 0.10),
        "ciphertext_entropy": (7.0, 8.0),
        "hash_collision_count": (0, 2),
        "request_frequency": (5, 80),
        "response_time": (0.01, 0.08),
        "payload_size": (100, 2000),
        "connection_duration": (0.5, 30),
        "packet_interarrival": (0.01, 0.5),
        "failed_attempts": (0, 1),
        "session_duration": (10, 500),
        "request_size_variance": (5, 200),
        "encryption_rounds": (1, 2),
        "decryption_success_rate": (0.98, 1.0),
        "memory_usage": (0.05, 0.3),
        "cpu_usage": (0.02, 0.2),
        "network_latency": (0.001, 0.02),
        "protocol_violations": (0, 1),
        "anomaly_score": (0.0, 0.15),
    },
    "brute_force": {
        "key_generation_time": (0.15, 0.5),
        "ciphertext_entropy": (3.0, 5.5),
        "hash_collision_count": (5, 50),
        "request_frequency": (200, 1000),
        "response_time": (0.1, 0.5),
        "payload_size": (50, 500),
        "connection_duration": (0.1, 2),
        "packet_interarrival": (0.001, 0.01),
        "failed_attempts": (10, 100),
        "session_duration": (1, 30),
        "request_size_variance": (1, 10),
        "encryption_rounds": (1, 2),
        "decryption_success_rate": (0.3, 0.7),
        "memory_usage": (0.3, 0.8),
        "cpu_usage": (0.4, 0.9),
        "network_latency": (0.01, 0.05),
        "protocol_violations": (3, 15),
        "anomaly_score": (0.6, 0.95),
    },
    "side_channel": {
        "key_generation_time": (0.3, 0.8),
        "ciphertext_entropy": (4.0, 6.0),
        "hash_collision_count": (1, 10),
        "request_frequency": (30, 150),
        "response_time": (0.15, 0.6),
        "payload_size": (500, 3000),
        "connection_duration": (30, 300),
        "packet_interarrival": (0.01, 0.05),
        "failed_attempts": (0, 5),
        "session_duration": (100, 1000),
        "request_size_variance": (50, 500),
        "encryption_rounds": (1, 3),
        "decryption_success_rate": (0.7, 0.95),
        "memory_usage": (0.2, 0.6),
        "cpu_usage": (0.1, 0.4),
        "network_latency": (0.02, 0.08),
        "protocol_violations": (0, 3),
        "anomaly_score": (0.4, 0.8),
    },
    "ciphertext_analysis": {
        "key_generation_time": (0.05, 0.2),
        "ciphertext_entropy": (2.0, 4.5),
        "hash_collision_count": (10, 80),
        "request_frequency": (50, 200),
        "response_time": (0.05, 0.2),
        "payload_size": (2000, 10000),
        "connection_duration": (5, 60),
        "packet_interarrival": (0.005, 0.02),
        "failed_attempts": (1, 10),
        "session_duration": (30, 200),
        "request_size_variance": (100, 1000),
        "encryption_rounds": (2, 4),
        "decryption_success_rate": (0.5, 0.85),
        "memory_usage": (0.3, 0.7),
        "cpu_usage": (0.2, 0.6),
        "network_latency": (0.005, 0.03),
        "protocol_violations": (1, 8),
        "anomaly_score": (0.5, 0.85),
    },
    "key_recovery": {
        "key_generation_time": (0.5, 2.0),
        "ciphertext_entropy": (5.0, 7.0),
        "hash_collision_count": (3, 30),
        "request_frequency": (10, 60),
        "response_time": (0.2, 1.0),
        "payload_size": (100, 1000),
        "connection_duration": (60, 600),
        "packet_interarrival": (0.02, 0.1),
        "failed_attempts": (3, 20),
        "session_duration": (200, 2000),
        "request_size_variance": (10, 100),
        "encryption_rounds": (3, 5),
        "decryption_success_rate": (0.2, 0.6),
        "memory_usage": (0.4, 0.9),
        "cpu_usage": (0.3, 0.8),
        "network_latency": (0.01, 0.04),
        "protocol_violations": (2, 10),
        "anomaly_score": (0.7, 0.98),
    },
}

ATTACK_TYPES = ["normal", "brute_force", "side_channel", "ciphertext_analysis", "key_recovery"]
N_FEATURES = len(FEATURE_NAMES)


def _rand_between(rng: tuple) -> float:
    return random.uniform(rng[0], rng[1])


def generate_one_record(attack_type: str) -> Dict[str, Any]:
    """生成一条记录（dict，key为FEATURE_NAMES）"""
    p = ATTACK_PATTERNS[attack_type]
    vals = {}
    for fn in FEATURE_NAMES:
        if fn in ("hash_collision_count", "payload_size", "connection_duration",
                  "failed_attempts", "session_duration", "protocol_violations",
                  "encryption_rounds"):
            vals[fn] = int(_rand_between(p[fn]))
        else:
            vals[fn] = round(_rand_between(p[fn]), 6)
    vals["anomaly_score"] = round(_rand_between(p["anomaly_score"]), 6)
    return vals


def generate_training_data(n_samples: int = 10000, attack_ratio: float = 0.35) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """生成训练数据集，分2批每批5000控制内存"""
    n_attack = int(n_samples * attack_ratio)
    n_normal = n_samples - n_attack
    attack_dist = [0.35, 0.25, 0.25, 0.15]
    attack_counts = [int(n_attack * d) for d in attack_dist]
    attack_counts[-1] = n_attack - sum(attack_counts[:-1])

    records, labels, types = [], [], []
    batch_size = 5000

    for batch_start in range(0, n_samples, batch_size):
        batch_end = min(batch_start + batch_size, n_samples)
        batch_n = batch_end - batch_start
        batch_normal = int(batch_n * (1 - attack_ratio))

        for _ in range(batch_normal):
            records.append(generate_one_record("normal"))
            labels.append(0)
            types.append("正常")

        for at_idx, cnt in zip(range(1, len(ATTACK_TYPES)), attack_counts):
            assigned = max(1, cnt * batch_n // n_samples)
            for _ in range(assigned):
                records.append(generate_one_record(ATTACK_TYPES[at_idx]))
                labels.append(1)
                types.append(ATTACK_TYPES[at_idx])

    X = np.zeros((len(records), N_FEATURES), dtype=np.float64)
    y = np.array(labels, dtype=np.int32)
    for i, rec in enumerate(records):
        for j, fn in enumerate(FEATURE_NAMES):
            X[i, j] = float(rec[fn])

    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    types = [types[i] for i in idx]

    logger.info("训练数据生成完成: %d条, %d维, 攻击占比=%.2f%%", len(X), N_FEATURES, np.mean(y) * 100)
    return X, y, types


def save_dataset(X: np.ndarray, y: np.ndarray, types: List[str], prefix: str):
    """保存数据集为CSV"""
    header = ",".join(FEATURE_NAMES + ["label", "attack_type"])
    os.makedirs(DATA_DIR, exist_ok=True)
    filepath = os.path.join(DATA_DIR, "%s.csv" % prefix)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        for i in range(len(X)):
            vals = ",".join(["%.6f" % X[i, j] for j in range(N_FEATURES)])
            f.write("%s,%d,%s\n" % (vals, y[i], types[i]))
    logger.info("数据集已保存: %s (%d条)", filepath, len(X))


def ensure_data_generated():
    """确保训练数据已生成，如未生成则自动创建"""
    train_path = os.path.join(DATA_DIR, "train.csv")
    test_path = os.path.join(DATA_DIR, "test.csv")

    if os.path.exists(train_path) and os.path.exists(test_path):
        logger.info("训练数据已存在: %s", train_path)
        return _load_data()

    logger.info("生成10000条训练数据...")
    X, y, types = generate_training_data(10000, 0.35)
    split = int(len(X) * 0.8)
    X_train, y_train, t_train = X[:split], y[:split], types[:split]
    X_test, y_test, t_test = X[split:], y[split:], types[split:]

    save_dataset(X_train, y_train, t_train, "train")
    save_dataset(X_test, y_test, t_test, "test")
    logger.info("数据生成完成: 训练集%d条, 测试集%d条", len(X_train), len(X_test))
    return X_train, y_train, X_test, y_test


def _load_data():
    """加载已保存的数据"""
    result = []
    for prefix in ["train", "test"]:
        path = os.path.join(DATA_DIR, "%s.csv" % prefix)
        X_rows, y_vals = [], []
        with open(path, "r", encoding="utf-8") as f:
            next(f)
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= N_FEATURES + 2:
                    X_rows.append([float(v) for v in parts[:N_FEATURES]])
                    y_vals.append(int(parts[N_FEATURES]))
        result.append(np.array(X_rows, dtype=np.float64))
        result.append(np.array(y_vals, dtype=np.int32))
    return result[0], result[1], result[2], result[3]


def generate_and_prepare(force=False):
    """兼容旧接口（供app.py启动时调用）"""
    X_train, y_train, X_test, y_test = ensure_data_generated()
    samples = []
    for i in range(min(len(X_train), 100)):
        rec = dict(zip(FEATURE_NAMES, X_train[i]))
        rec["is_attack"] = int(y_train[i])
        rec["attack_type"] = "攻击" if y_train[i] else "正常"
        samples.append(rec)
    X_seq = None
    if len(X_train) >= 20:
        import numpy as np
        X_seq_arr = np.array([X_train[i:i+10] for i in range(len(X_train)-10)])
        y_seq_arr = np.array([1.0 if np.mean(y_train[i:i+10]) > 0.3 else 0.0 for i in range(len(y_train)-10)])
        if len(X_seq_arr) > 100:
            X_seq_arr = X_seq_arr[:100]
            y_seq_arr = y_seq_arr[:100]
        X_seq = (X_seq_arr, y_seq_arr)
    return {
        "samples": samples,
        "count": len(X_train),
        "X_seq": X_seq,
        "y_seq": None,
        "train_path": os.path.join(DATA_DIR, "train.csv"),
        "demo_path": os.path.join(DATA_DIR, "test.csv"),
    }
