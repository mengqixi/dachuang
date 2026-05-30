# -*- coding: utf-8 -*-
"""特征工程 - 统一18维特征提取与标准化"""

import numpy as np
from typing import Dict, List, Optional

FEATURE_NAMES = [
    'key_generation_time', 'ciphertext_entropy', 'hash_collision_count',
    'request_frequency', 'response_time', 'payload_size',
    'connection_duration', 'packet_interarrival', 'failed_attempts',
    'session_duration', 'request_size_variance', 'encryption_rounds',
    'decryption_success_rate', 'memory_usage', 'cpu_usage',
    'network_latency', 'protocol_violations', 'anomaly_score',
]


def extract_features_structured(row: Dict) -> np.ndarray:
    """从UNSW-NB15风格的行数据提取18维特征向量"""
    vec = np.zeros(18, dtype=np.float64)
    vec[0] = float(row.get('key_generation_time', row.get('stime', 0)))
    vec[1] = float(row.get('ciphertext_entropy', row.get('ct_ftp_cmd', 0)))
    vec[2] = float(row.get('hash_collision_count', row.get('ct_srv_src', 0)))
    vec[3] = float(row.get('request_frequency', row.get('rate', 0)))
    vec[4] = float(row.get('response_time', row.get('sload', 0)))
    vec[5] = float(row.get('payload_size', row.get('spkts', 0)))
    vec[6] = float(row.get('connection_duration', row.get('dur', 0)))
    vec[7] = float(row.get('packet_interarrival', row.get('sjit', 0)))
    vec[8] = float(row.get('failed_attempts', row.get('ct_dst_src_ltm', 0)))
    vec[9] = float(row.get('session_duration', row.get('rate', 0)))
    vec[10] = float(row.get('request_size_variance', row.get('sbytes', 0)))
    vec[11] = float(row.get('encryption_rounds', row.get('ct_srv_dst', 0)))
    vec[12] = float(row.get('decryption_success_rate', 1.0))
    vec[13] = float(row.get('memory_usage', 0.3))
    vec[14] = float(row.get('cpu_usage', 0.2))
    vec[15] = float(row.get('network_latency', row.get('trans_depth', 0)))
    vec[16] = float(row.get('protocol_violations', row.get('ct_state_ttl', 0)))
    vec[17] = float(row.get('anomaly_score', row.get('label', 0)))
    return vec


def minmax_normalize(X: np.ndarray, fit_params: Optional[Dict] = None) -> np.ndarray:
    """Min-Max归一化到[0,1]"""
    if fit_params:
        mins, maxs = fit_params['mins'], fit_params['maxs']
    else:
        mins, maxs = X.min(axis=0), X.max(axis=0)
    return np.clip((X - mins) / (maxs - mins + 1e-10), 0, 1)


def load_unsw_nb15(filepath: str) -> np.ndarray:
    """加载UNSW-NB15 CSV并提取特征"""
    import csv
    X_rows, y_vals = [], []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            vec = extract_features_structured(row)
            label = int(float(row.get('label', 0)))
            X_rows.append(vec)
            y_vals.append(label)
    return np.array(X_rows, dtype=np.float64), np.array(y_vals, dtype=np.int32)
