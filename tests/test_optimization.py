"""自适应优化模块测试 - Q-learning + AdaptiveOptimizer"""

import unittest
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestQLearningAgent(unittest.TestCase):
    """新表格型Q-learning智能体测试"""

    def setUp(self):
        from src.optimization.agent import QLearningAgent
        self.agent = QLearningAgent(
            learning_rate=0.1,
            gamma=0.9,
            epsilon_start=0.3,
            epsilon_min=0.01,
            epsilon_decay=0.995,
        )

    def test_discretize_state(self):
        """测试4维连续状态离散化"""
        # 低风险, 低CPU, 低内存, 低精度
        state = np.array([0.0, 0.1, 0.2, 0.85], dtype=np.float32)
        key = self.agent.discretize_state(state)
        self.assertEqual(key, "0_0_0_0")

        # 高风险, 高CPU, 高内存, 高精度
        state = np.array([3.0, 0.9, 0.8, 0.99], dtype=np.float32)
        key = self.agent.discretize_state(state)
        self.assertEqual(key, "3_2_2_2")

        # 中风险, 中CPU, 中内存, 中精度
        state = np.array([1.0, 0.5, 0.5, 0.92], dtype=np.float32)
        key = self.agent.discretize_state(state)
        self.assertEqual(key, "1_1_1_1")

    def test_state_to_idx(self):
        """测试状态到Q-table行索引的映射"""
        key = "0_0_0_0"
        idx = self.agent._state_to_idx(key)
        self.assertEqual(idx, 0)

        key = "3_2_2_2"
        idx = self.agent._state_to_idx(key)
        self.assertEqual(idx, 107)

        # 108个状态，索引范围为[0, 108)
        all_indices = set()
        for risk in range(4):
            for cpu in range(3):
                for mem in range(3):
                    for acc in range(3):
                        key = f"{risk}_{cpu}_{mem}_{acc}"
                        idx = self.agent._state_to_idx(key)
                        self.assertGreaterEqual(idx, 0)
                        self.assertLess(idx, 108)
                        all_indices.add(idx)
        self.assertEqual(len(all_indices), 108)

    def test_predict_deterministic(self):
        """测试确定性预测"""
        state = np.array([2.0, 0.5, 0.5, 0.9], dtype=np.float32)
        action, q_val = self.agent.predict(state, deterministic=True)
        self.assertIn(action, range(9))  # 9个离散动作
        self.assertIsInstance(q_val, float)

    def test_predict_stochastic(self):
        """测试随机预测（epsilon-greedy）"""
        # 设置高epsilon确保探索
        self.agent.epsilon = 1.0
        state = np.array([1.0, 0.3, 0.4, 0.95], dtype=np.float32)
        action, q_val = self.agent.predict(state, deterministic=False)
        self.assertIn(action, range(9))

    def test_action_encoding(self):
        """测试动作编解码"""
        key_length, rounds = self.agent.decode_action(0)
        self.assertEqual(key_length, 1024)
        self.assertEqual(rounds, 10)

        key_length, rounds = self.agent.decode_action(4)
        self.assertEqual(key_length, 2048)
        self.assertEqual(rounds, 12)

        key_length, rounds = self.agent.decode_action(8)
        self.assertEqual(key_length, 4096)
        self.assertEqual(rounds, 14)

    def test_training(self):
        """测试短训练流程"""
        rewards = self.agent.train(total_timesteps=500)
        self.assertGreater(len(rewards), 0)
        self.assertTrue(self.agent.is_trained)

    def test_save_load(self):
        """测试Q-table保存和加载"""
        import tempfile
        path = tempfile.mktemp()
        self.agent.q_table[5, 3] = 1.5
        self.agent.save(path)
        self.assertTrue(os.path.exists(path + "_qtable.npz"))

        # 加载到新agent
        from src.optimization.agent import QLearningAgent
        agent2 = QLearningAgent()
        ok = agent2.load(path)
        self.assertTrue(ok)
        self.assertEqual(agent2.q_table[5, 3], 1.5)
        self.assertEqual(agent2.lr, self.agent.lr)
        self.assertEqual(agent2.gamma, self.agent.gamma)
        os.remove(path + "_qtable.npz")

    def test_q_table_stats(self):
        """测试Q-table统计信息"""
        self.agent.train(total_timesteps=200)
        stats = self.agent.get_q_table_stats()
        self.assertEqual(stats["shape"], [108, 9])
        self.assertGreater(stats["nonzero_entries"], 0)
        self.assertEqual(stats["memory_bytes"], 108 * 9 * 4)  # float32
        self.assertIn("epsilon", stats)
        self.assertIn("max_q", stats)
        self.assertIn("min_q", stats)

    def test_bin_index(self):
        """测试分箱边界"""
        self.assertEqual(self.agent._bin_index(0.0, [0.3, 0.7]), 0)
        self.assertEqual(self.agent._bin_index(0.3, [0.3, 0.7]), 0)
        self.assertEqual(self.agent._bin_index(0.5, [0.3, 0.7]), 1)
        self.assertEqual(self.agent._bin_index(0.7, [0.3, 0.7]), 1)
        self.assertEqual(self.agent._bin_index(1.0, [0.3, 0.7]), 2)


class TestAdaptiveOptimizer(unittest.TestCase):
    """自适应优化器测试"""

    def setUp(self):
        from src.optimization.optimizer import AdaptiveOptimizer
        self.opt = AdaptiveOptimizer()

    def test_update(self):
        """测试优化更新"""
        result = self.opt.update(anomaly_score=0.3)  # medium
        self.assertIn("key_length", result)
        self.assertIn("rounds", result)
        self.assertIn("risk_level", result)
        self.assertIn("reward", result)
        self.assertIn("performance_gain", result)
        self.assertEqual(result["risk_level"], "medium")

    def test_update_low_risk(self):
        """测试低风险场景"""
        result = self.opt.update(anomaly_score=0.1)
        self.assertEqual(result["risk_level"], "low")

    def test_update_high_risk(self):
        """测试高风险场景"""
        result = self.opt.update(anomaly_score=0.5)  # 0.5->high
        self.assertEqual(result["risk_level"], "high")

    def test_update_critical_risk(self):
        """测试严重风险场景"""
        result = self.opt.update(anomaly_score=0.8)  # 0.8->critical
        self.assertEqual(result["risk_level"], "critical")

    def test_history(self):
        """测试历史记录"""
        self.opt.update(anomaly_score=0.1)
        self.opt.update(anomaly_score=0.5)
        self.opt.update(anomaly_score=0.9)
        history = self.opt.get_history()
        self.assertGreaterEqual(len(history), 3)

        record = history[0]
        self.assertIn("risk_level", record)
        self.assertIn("key_length", record)
        self.assertIn("rounds", record)
        self.assertIn("reward", record)
        self.assertIn("performance_gain", record)

    def test_current_config(self):
        """测试当前配置"""
        cfg = self.opt.get_current_config()
        self.assertIn("key_length", cfg)
        self.assertIn("rounds", cfg)
        self.assertGreater(cfg["key_length"], 0)
        self.assertGreater(cfg["rounds"], 0)

    def test_get_status(self):
        """测试状态获取"""
        status = self.opt.get_status()
        self.assertIn("current_key_length", status)
        self.assertIn("current_rounds", status)
        self.assertIn("risk_level", status)
        self.assertIn("performance_gain", status)
        self.assertIn("agent_trained", status)

    def test_performance_gain_tracking(self):
        """测试性能增益累计"""
        # 多次更新应产生性能增益
        for _ in range(5):
            self.opt.update(anomaly_score=np.random.random())
        status = self.opt.get_status()
        self.assertGreaterEqual(status["performance_gain"], 0)

    def test_training(self):
        """测试短训练"""
        rewards = self.opt.train(episodes=20)
        self.assertIsInstance(rewards, list)
        self.assertGreater(len(rewards), 0)

    def test_agent_trained_flag(self):
        """测试训练标志"""
        status = self.opt.get_status()
        # 训练后标志应为True
        self.opt.train(episodes=10)
        self.assertTrue(self.opt.agent.is_trained)


if __name__ == "__main__":
    unittest.main(verbosity=2)
