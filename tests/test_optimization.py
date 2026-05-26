import unittest
import numpy as np
from src.optimization.rl_optimizer import QLearningAgent, EncryptionOptimizer, AdaptiveEncryptionManager

class TestQLearningAgent(unittest.TestCase):
    def setUp(self):
        self.state_space = ['low', 'medium', 'high', 'critical']
        self.action_space = {
            'key_lengths': [1024, 2048, 4096],
            'rounds': [1, 2, 3]
        }
        self.agent = QLearningAgent(self.state_space, self.action_space)

    def test_action_encoding(self):
        key_length, rounds = 2048, 2
        idx = self.agent.get_action_idx(key_length, rounds)
        decoded_length, decoded_rounds = self.agent.get_action_from_idx(idx)
        
        self.assertEqual(key_length, decoded_length)
        self.assertEqual(rounds, decoded_rounds)

    def test_choose_action(self):
        state = 'high'
        key_length, rounds = self.agent.choose_action(state)
        
        self.assertIn(key_length, self.action_space['key_lengths'])
        self.assertIn(rounds, self.action_space['rounds'])

    def test_learning(self):
        initial_q = self.agent.q_table[0, 0]
        
        self.agent.learn('low', (1024, 1), 1.0, 'medium')
        
        self.assertNotEqual(initial_q, self.agent.q_table[0, 0])

class TestEncryptionOptimizer(unittest.TestCase):
    def setUp(self):
        self.optimizer = EncryptionOptimizer()

    def test_risk_level_detection(self):
        self.assertEqual(self.optimizer.get_risk_level(0.1), 'low')
        self.assertEqual(self.optimizer.get_risk_level(0.3), 'medium')
        self.assertEqual(self.optimizer.get_risk_level(0.6), 'high')
        self.assertEqual(self.optimizer.get_risk_level(0.9), 'critical')

    def test_optimize(self):
        anomaly_score = 0.7
        key_length, rounds = self.optimizer.optimize(anomaly_score)
        
        self.assertIn(key_length, [1024, 2048, 4096])
        self.assertIn(rounds, [1, 2, 3])

class TestAdaptiveEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.manager = AdaptiveEncryptionManager()

    def test_update(self):
        result = self.manager.update(0.8, False, {})
        
        self.assertIn('action', result)
        self.assertIn('key_length', result)
        self.assertIn('rounds', result)

    def test_get_config(self):
        config = self.manager.get_current_config()
        
        self.assertIn('key_length', config)
        self.assertIn('rounds', config)
        self.assertEqual(config['key_length'], 2048)
        self.assertEqual(config['rounds'], 1)

if __name__ == '__main__':
    unittest.main()