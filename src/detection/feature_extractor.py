import numpy as np
import hashlib
import time
from typing import Dict, List, Tuple
from scipy.stats import entropy

class FeatureExtractor:
    FEATURE_NAMES = [
        'key_generation_time',
        'ciphertext_entropy',
        'hash_collision_count',
        'request_frequency',
        'response_time',
        'payload_size',
        'connection_duration',
        'packet_interarrival',
        'failed_attempts',
        'session_duration',
        'request_size_variance',
        'encryption_rounds',
        'decryption_success_rate',
        'memory_usage',
        'cpu_usage',
        'network_latency',
        'protocol_violations',
        'anomaly_score'
    ]

    def __init__(self):
        self.feature_dim = len(self.FEATURE_NAMES)
        self.history = []

    def extract_features(self, log_entry: Dict) -> np.ndarray:
        features = []
        
        features.append(log_entry.get('key_generation_time', 0.0))
        features.append(self._calculate_entropy(log_entry.get('ciphertext', '')))
        features.append(log_entry.get('hash_collisions', 0))
        features.append(log_entry.get('request_frequency', 0.0))
        features.append(log_entry.get('response_time', 0.0))
        features.append(log_entry.get('payload_size', 0))
        features.append(log_entry.get('connection_duration', 0.0))
        features.append(log_entry.get('packet_interarrival', 0.0))
        features.append(log_entry.get('failed_attempts', 0))
        features.append(log_entry.get('session_duration', 0.0))
        features.append(log_entry.get('request_size_variance', 0.0))
        features.append(log_entry.get('encryption_rounds', 1))
        features.append(log_entry.get('decryption_success_rate', 1.0))
        features.append(log_entry.get('memory_usage', 0.0))
        features.append(log_entry.get('cpu_usage', 0.0))
        features.append(log_entry.get('network_latency', 0.0))
        features.append(log_entry.get('protocol_violations', 0))
        features.append(log_entry.get('anomaly_score', 0.0))
        
        return np.array(features, dtype=np.float32)

    def _calculate_entropy(self, ciphertext: str) -> float:
        if not ciphertext:
            return 0.0
        
        byte_data = ciphertext.encode('utf-8') if isinstance(ciphertext, str) else bytes(ciphertext)
        if len(byte_data) == 0:
            return 0.0
        
        value, counts = np.unique(np.frombuffer(byte_data, dtype=np.uint8), return_counts=True)
        return entropy(counts)

    def extract_sequence_features(self, log_entries: List[Dict], window_size: int = 10) -> np.ndarray:
        sequences = []
        for i in range(len(log_entries) - window_size + 1):
            window = log_entries[i:i+window_size]
            seq_features = []
            for entry in window:
                seq_features.append(self.extract_features(entry))
            sequences.append(np.array(seq_features))
        
        return np.array(sequences)

    def normalize_features(self, features: np.ndarray) -> np.ndarray:
        min_vals = np.array([0.0, 0.0, 0, 0.0, 0.0, 0, 0.0, 0.0, 0, 0.0, 0.0, 1, 0.0, 0.0, 0.0, 0.0, 0, 0.0])
        max_vals = np.array([10.0, 8.0, 100, 1000.0, 5.0, 1000000, 3600.0, 1.0, 100, 7200.0, 10000.0, 10, 1.0, 1.0, 1.0, 5.0, 10, 1.0])
        
        normalized = (features - min_vals) / (max_vals - min_vals + 1e-8)
        return np.clip(normalized, 0.0, 1.0)

    def extract_temporal_features(self, log_entries: List[Dict]) -> np.ndarray:
        if len(log_entries) < 2:
            return np.zeros(self.feature_dim)
        
        times = [entry.get('timestamp', 0) for entry in log_entries]
        features = []
        
        time_diff = np.diff(times)
        features.append(np.mean(time_diff))
        features.append(np.std(time_diff))
        features.append(np.min(time_diff))
        features.append(np.max(time_diff))
        
        request_counts = len(log_entries)
        features.append(request_counts)
        
        return np.array(features)

class CrossInstitutionFeatureAligner:
    def __init__(self):
        self.feature_mapping = {}
        self.normalization_params = {}

    def fit(self, datasets: List[np.ndarray]) -> None:
        all_features = np.vstack(datasets)
        
        self.normalization_params['mean'] = np.mean(all_features, axis=0)
        self.normalization_params['std'] = np.std(all_features, axis=0)
        self.normalization_params['std'][self.normalization_params['std'] < 1e-8] = 1.0

    def transform(self, dataset: np.ndarray) -> np.ndarray:
        normalized = (dataset - self.normalization_params['mean']) / self.normalization_params['std']
        return np.clip(normalized, -3, 3)

    def align_features(self, local_features: np.ndarray, feature_names: List[str]) -> np.ndarray:
        aligned = np.zeros(len(FeatureExtractor.FEATURE_NAMES))
        
        for i, global_name in enumerate(FeatureExtractor.FEATURE_NAMES):
            if global_name in feature_names:
                idx = feature_names.index(global_name)
                aligned[i] = local_features[idx]
        
        return aligned