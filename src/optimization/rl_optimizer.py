import numpy as np
import random
from typing import Dict, Tuple, List, Any

class QLearningAgent:
    def __init__(self, state_space: List[str], action_space: Dict[str, List[int]],
                 alpha: float = 0.1, gamma: float = 0.99, epsilon: float = 0.1):
        self.state_space = state_space
        self.action_space = action_space
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        
        self.state_to_idx = {state: idx for idx, state in enumerate(state_space)}
        
        self.key_lengths = action_space['key_lengths']
        self.rounds = action_space['rounds']
        
        self.num_states = len(state_space)
        self.num_actions = len(self.key_lengths) * len(self.rounds)
        
        self.q_table = np.zeros((self.num_states, self.num_actions))

    def get_action_idx(self, key_length: int, num_rounds: int) -> int:
        length_idx = self.key_lengths.index(key_length)
        round_idx = self.rounds.index(num_rounds)
        return length_idx * len(self.rounds) + round_idx

    def get_action_from_idx(self, action_idx: int) -> Tuple[int, int]:
        length_idx = action_idx // len(self.rounds)
        round_idx = action_idx % len(self.rounds)
        return self.key_lengths[length_idx], self.rounds[round_idx]

    def choose_action(self, state: str) -> Tuple[int, int]:
        state_idx = self.state_to_idx[state]
        
        if random.uniform(0, 1) < self.epsilon:
            action_idx = random.randint(0, self.num_actions - 1)
        else:
            action_idx = np.argmax(self.q_table[state_idx])
        
        return self.get_action_from_idx(action_idx)

    def learn(self, state: str, action: Tuple[int, int], reward: float, next_state: str) -> None:
        state_idx = self.state_to_idx[state]
        next_state_idx = self.state_to_idx[next_state]
        action_idx = self.get_action_idx(action[0], action[1])
        
        best_next_q = np.max(self.q_table[next_state_idx])
        current_q = self.q_table[state_idx][action_idx]
        
        new_q = current_q + self.alpha * (reward + self.gamma * best_next_q - current_q)
        self.q_table[state_idx][action_idx] = new_q

    def decay_epsilon(self, rate: float = 0.995) -> None:
        self.epsilon = max(0.01, self.epsilon * rate)

    def save_model(self, path: str) -> None:
        np.save(path, {
            'q_table': self.q_table,
            'state_space': self.state_space,
            'action_space': self.action_space,
            'alpha': self.alpha,
            'gamma': self.gamma,
            'epsilon': self.epsilon
        })

    def load_model(self, path: str) -> None:
        data = np.load(path, allow_pickle=True).item()
        self.q_table = data['q_table']
        self.state_space = data['state_space']
        self.action_space = data['action_space']
        self.alpha = data['alpha']
        self.gamma = data['gamma']
        self.epsilon = data['epsilon']
        self.state_to_idx = {state: idx for idx, state in enumerate(self.state_space)}

class EncryptionOptimizer:
    def __init__(self):
        self.state_space = ['low', 'medium', 'high', 'critical']
        self.action_space = {
            'key_lengths': [1024, 2048, 4096],
            'rounds': [1, 2, 3]
        }
        
        self.agent = QLearningAgent(
            state_space=self.state_space,
            action_space=self.action_space,
            alpha=0.1,
            gamma=0.99,
            epsilon=0.1
        )
        
        self.cost_model = {
            1024: {'time': 1.0, 'memory': 1.0, 'throughput': 100},
            2048: {'time': 2.5, 'memory': 2.0, 'throughput': 40},
            4096: {'time': 6.0, 'memory': 4.0, 'throughput': 10}
        }

    def get_risk_level(self, anomaly_score: float) -> str:
        if anomaly_score < 0.2:
            return 'low'
        elif anomaly_score < 0.5:
            return 'medium'
        elif anomaly_score < 0.8:
            return 'high'
        else:
            return 'critical'

    def calculate_reward(self, risk_level: str, key_length: int, 
                         actual_attack: bool, success_rate: float) -> float:
        cost = self.cost_model[key_length]['time']
        
        security_bonus = 0.0
        if risk_level == 'critical' and key_length >= 2048:
            security_bonus = 5.0
        elif risk_level == 'high' and key_length >= 2048:
            security_bonus = 3.0
        
        attack_penalty = -10.0 if actual_attack else 0.0
        efficiency_penalty = -cost * 0.1
        
        return security_bonus + attack_penalty + efficiency_penalty + success_rate * 2.0

    def optimize(self, anomaly_score: float) -> Tuple[int, int]:
        risk_level = self.get_risk_level(anomaly_score)
        key_length, num_rounds = self.agent.choose_action(risk_level)
        return key_length, num_rounds

    def train(self, episodes: int = 1000) -> List[float]:
        rewards = []
        
        for episode in range(episodes):
            total_reward = 0.0
            
            anomaly_score = random.uniform(0, 1)
            risk_level = self.get_risk_level(anomaly_score)
            
            key_length, num_rounds = self.agent.choose_action(risk_level)
            
            actual_attack = random.random() < anomaly_score * 0.5
            success_rate = self._simulate_attack_success(key_length, actual_attack)
            
            reward = self.calculate_reward(risk_level, key_length, actual_attack, success_rate)
            
            next_anomaly_score = random.uniform(0, 1)
            next_risk_level = self.get_risk_level(next_anomaly_score)
            
            self.agent.learn(risk_level, (key_length, num_rounds), reward, next_risk_level)
            
            total_reward += reward
            rewards.append(total_reward)
            
            self.agent.decay_epsilon()
            
            if (episode + 1) % 100 == 0:
                avg_reward = np.mean(rewards[-100:])
                print(f"Episode {episode+1}, Avg Reward: {avg_reward:.2f}")
        
        return rewards

    def _simulate_attack_success(self, key_length: int, under_attack: bool) -> float:
        if not under_attack:
            return 1.0
        
        base_success = {1024: 0.3, 2048: 0.1, 4096: 0.01}
        return 1.0 - base_success[key_length]

class AdaptiveEncryptionManager:
    def __init__(self):
        self.optimizer = EncryptionOptimizer()
        self.current_key_length = 2048
        self.current_rounds = 1
        self.running_reward = 0.0
        self.observation_count = 0

    def update(self, anomaly_score: float, attack_detected: bool, 
               system_metrics: Dict) -> Dict[str, Any]:
        self.observation_count += 1
        
        new_key_length, new_rounds = self.optimizer.optimize(anomaly_score)
        
        if new_key_length != self.current_key_length or new_rounds != self.current_rounds:
            self.current_key_length = new_key_length
            self.current_rounds = new_rounds
            
            return {
                'action': 'update',
                'key_length': new_key_length,
                'rounds': new_rounds,
                'reason': f"Risk level changed based on anomaly score: {anomaly_score:.2f}"
            }
        
        return {
            'action': 'maintain',
            'key_length': self.current_key_length,
            'rounds': self.current_rounds,
            'reason': "Current configuration optimal"
        }

    def get_current_config(self) -> Dict[str, int]:
        return {
            'key_length': self.current_key_length,
            'rounds': self.current_rounds
        }

    def train_agent(self, episodes: int = 1000) -> None:
        print("Training reinforcement learning agent...")
        self.optimizer.train(episodes)
        print("Training completed.")