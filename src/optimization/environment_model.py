import numpy as np
import time
from typing import Dict, Tuple, List, Any

class EncryptionEnvironment:
    def __init__(self):
        self.state = {
            'risk_level': 'low',
            'throughput': 100.0,
            'latency': 10.0,
            'memory_usage': 0.2,
            'attack_probability': 0.05
        }
        
        self.key_configs = {
            1024: {'latency': 10, 'throughput': 100, 'memory': 0.2},
            2048: {'latency': 25, 'throughput': 40, 'memory': 0.4},
            4096: {'latency': 60, 'throughput': 10, 'memory': 0.8}
        }

    def step(self, action: Tuple[int, int]) -> Tuple[Dict, float, bool, Dict]:
        key_length, num_rounds = action
        
        config = self.key_configs[key_length]
        
        base_latency = config['latency'] * num_rounds
        throughput = config['throughput'] / num_rounds
        memory_usage = config['memory'] * num_rounds
        
        attack_success_prob = self._calculate_attack_success(key_length)
        attacked = np.random.random() < self.state['attack_probability']
        
        reward = self._calculate_reward(
            key_length, num_rounds, attacked, attack_success_prob,
            throughput, base_latency, memory_usage
        )
        
        self.state.update({
            'throughput': throughput,
            'latency': base_latency,
            'memory_usage': memory_usage,
            'attack_detected': attacked and not (np.random.random() < attack_success_prob)
        })
        
        done = attacked and (np.random.random() < attack_success_prob)
        
        return self.state, reward, done, {
            'key_length': key_length,
            'rounds': num_rounds,
            'attack_success_prob': attack_success_prob
        }

    def _calculate_attack_success(self, key_length: int) -> float:
        base_probs = {1024: 0.3, 2048: 0.1, 4096: 0.01}
        return base_probs[key_length]

    def _calculate_reward(self, key_length: int, num_rounds: int, 
                         attacked: bool, attack_success_prob: float,
                         throughput: float, latency: float, memory_usage: float) -> float:
        security_reward = 0.0
        if attacked:
            security_reward = (1.0 - attack_success_prob) * 10.0
            if attack_success_prob < 0.1:
                security_reward += 5.0
        
        efficiency_penalty = (100.0 - throughput) * 0.1 + latency * 0.05 + memory_usage * 2.0
        
        cost_penalty = num_rounds * 0.5
        
        return security_reward - efficiency_penalty - cost_penalty

    def reset(self) -> Dict:
        self.state = {
            'risk_level': np.random.choice(['low', 'medium', 'high', 'critical']),
            'throughput': 100.0,
            'latency': 10.0,
            'memory_usage': 0.2,
            'attack_probability': np.random.uniform(0.01, 0.3)
        }
        return self.state

    def get_state_features(self) -> np.ndarray:
        risk_map = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        return np.array([
            risk_map[self.state['risk_level']],
            self.state['throughput'],
            self.state['latency'],
            self.state['memory_usage'],
            self.state['attack_probability']
        ])

class PerformanceMonitor:
    def __init__(self):
        self.metrics_history = []
        self.throughput_window = []
        self.latency_window = []
        self.memory_window = []
        self.window_size = 100

    def record_metrics(self, metrics: Dict) -> None:
        self.metrics_history.append({
            'timestamp': time.time(),
            'throughput': metrics.get('throughput', 0),
            'latency': metrics.get('latency', 0),
            'memory_usage': metrics.get('memory_usage', 0),
            'key_length': metrics.get('key_length', 2048),
            'rounds': metrics.get('rounds', 1),
            'attack_detected': metrics.get('attack_detected', False)
        })
        
        self.throughput_window.append(metrics.get('throughput', 0))
        self.latency_window.append(metrics.get('latency', 0))
        self.memory_window.append(metrics.get('memory_usage', 0))
        
        if len(self.throughput_window) > self.window_size:
            self.throughput_window.pop(0)
            self.latency_window.pop(0)
            self.memory_window.pop(0)

    def get_average_metrics(self) -> Dict[str, float]:
        return {
            'avg_throughput': np.mean(self.throughput_window) if self.throughput_window else 0,
            'avg_latency': np.mean(self.latency_window) if self.latency_window else 0,
            'avg_memory': np.mean(self.memory_window) if self.memory_window else 0
        }

    def get_summary(self) -> Dict[str, Any]:
        if not self.metrics_history:
            return {}
        
        attacks = sum(1 for m in self.metrics_history if m.get('attack_detected', False))
        
        return {
            'total_observations': len(self.metrics_history),
            'total_attacks': attacks,
            'attack_rate': attacks / len(self.metrics_history),
            **self.get_average_metrics(),
            'key_length_distribution': self._get_key_length_distribution()
        }

    def _get_key_length_distribution(self) -> Dict[int, int]:
        distribution = {}
        for m in self.metrics_history:
            key_len = m.get('key_length', 2048)
            distribution[key_len] = distribution.get(key_len, 0) + 1
        return distribution