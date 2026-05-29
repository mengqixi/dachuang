"""系统综合测试 - 覆盖所有核心模块"""

import unittest
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))


class TestEncryption(unittest.TestCase):
    """加密模块测试"""

    def setUp(self):
        from src.encryption.paillier import Paillier
        self.p = Paillier(key_size=128)  # 小密钥加速测试
        self.p.generate_keys()

    def test_encrypt_decrypt(self):
        plain = 42
        cipher = self.p.encrypt(plain)
        self.assertEqual(self.p.decrypt(cipher), plain)

    def test_homomorphic_add(self):
        a, b = 10, 20
        ca, cb = self.p.encrypt(a), self.p.encrypt(b)
        self.assertEqual(self.p.decrypt(self.p.add(ca, cb)), a + b)


class TestFeatureExtractor(unittest.TestCase):
    """特征提取测试"""

    def setUp(self):
        from src.detection.feature_extractor import FeatureExtractor
        self.fe = FeatureExtractor()

    def test_feature_dim(self):
        entry = {
            "key_generation_time": 0.12, "ciphertext": "test",
            "hash_collisions": 0, "request_frequency": 100.0,
            "response_time": 0.05, "payload_size": 1024,
            "connection_duration": 10.0, "packet_interarrival": 0.01,
            "failed_attempts": 0, "session_duration": 300.0,
            "request_size_variance": 100.0, "encryption_rounds": 1,
            "decryption_success_rate": 1.0, "memory_usage": 0.3,
            "cpu_usage": 0.2, "network_latency": 0.01,
            "protocol_violations": 0, "anomaly_score": 0.1,
        }
        features = self.fe.extract_features(entry)
        self.assertEqual(len(features), 18)

    def test_normalize(self):
        import numpy as np
        f = np.random.randn(18) * 2 + 0.5
        n = self.fe.normalize_features(f.reshape(1, -1))
        self.assertTrue((n >= 0).all())
        self.assertTrue((n <= 1).all())


class TestAttackDetector(unittest.TestCase):
    """攻击检测测试（HybridDetector - 加权投票）"""

    def setUp(self):
        from src.detection.detector import HybridDetector
        self.det = HybridDetector(feature_dim=18)

    def test_isolation_forest(self):
        import numpy as np
        X = np.random.randn(100, 18)
        self.det.fit_isolation_forest(X)
        preds, _, _ = self.det.predict(X[:10])
        self.assertEqual(len(preds), 10)

    def test_predict_proba(self):
        import numpy as np
        X = np.random.randn(20, 18)
        self.det.fit_isolation_forest(X)
        probs = self.det.predict_proba(X[:5])
        self.assertEqual(len(probs), 5)
        self.assertTrue(all(0 <= p <= 1 for p in probs))


class TestHybridDetector(unittest.TestCase):
    """混合检测器测试"""

    def setUp(self):
        from src.detection.detector import HybridDetector
        self.det = HybridDetector(feature_dim=18)

    def test_weighted_vote(self):
        import numpy as np
        X = np.random.randn(50, 18)
        self.det.isolation_forest.fit(X)
        preds, _, _ = self.det.predict(X[:5])
        self.assertEqual(len(preds), 5)

    def test_save_load(self):
        import numpy as np, tempfile, os
        X = np.random.randn(30, 18)
        self.det.isolation_forest.fit(X)
        path = tempfile.mktemp()
        self.det.save(path)
        self.assertTrue(os.path.exists(path + "_if.pkl"))
        os.remove(path + "_if.pkl")


class TestFederated(unittest.TestCase):
    """联邦学习模块测试"""

    def test_config_creation(self):
        from src.federated.primihub_client import FederatedTaskConfig
        cfg = FederatedTaskConfig(num_rounds=5, algorithm="logistic_regression")
        self.assertEqual(cfg.num_rounds, 5)
        self.assertEqual(cfg.algorithm, "logistic_regression")

    def test_client_submit_and_status(self):
        from src.federated.primihub_client import PrimiHubClient, FederatedTaskConfig
        client = PrimiHubClient()
        cfg = FederatedTaskConfig(num_rounds=3)
        task_id = client.submit_task(cfg)
        self.assertTrue(task_id.startswith("fl_"))
        status = client.get_task_status(task_id)
        self.assertIn(status["status"], ["pending", "running", "completed"])
        tasks = client.list_tasks()
        self.assertGreaterEqual(len(tasks), 1)

    def test_log_pull(self):
        from src.federated.primihub_client import PrimiHubClient, FederatedTaskConfig
        client = PrimiHubClient()
        task_id = client.submit_task(FederatedTaskConfig(num_rounds=2))
        logs = client.get_task_logs(task_id)
        self.assertIn("logs", logs)
        self.assertIn("status", logs)


class TestOptimization(unittest.TestCase):
    """自适应优化模块测试"""

    def test_env_reset(self):
        from src.optimization.environment import EncryptionEnv
        env = EncryptionEnv()
        state, info = env.reset()
        self.assertEqual(len(state), 4)

    def test_env_step(self):
        from src.optimization.environment import EncryptionEnv
        env = EncryptionEnv()
        env.reset()
        state, reward, term, trunc, info = env.step(0)
        self.assertEqual(len(state), 4)

    def test_qagent_discretize(self):
        import numpy as np
        from src.optimization.agent import QLearningAgent
        agent = QLearningAgent()
        state = np.array([2.0, 0.5, 0.5, 0.92], dtype=np.float32)
        key = agent.discretize_state(state)
        self.assertEqual(key, "2_1_1_1")

    def test_qagent_predict(self):
        import numpy as np
        from src.optimization.agent import QLearningAgent
        agent = QLearningAgent()
        action, q_val = agent.predict(np.array([1.0, 0.3, 0.4, 0.95], dtype=np.float32))
        self.assertIn(action, range(9))

    def test_qagent_train(self):
        from src.optimization.agent import QLearningAgent
        agent = QLearningAgent()
        rewards = agent.train(total_timesteps=200)
        self.assertGreater(len(rewards), 0)
        self.assertTrue(agent.is_trained)

    def test_optimizer_update(self):
        from src.optimization.optimizer import AdaptiveOptimizer
        opt = AdaptiveOptimizer()
        result = opt.update(anomaly_score=0.5)
        self.assertIn("key_length", result)
        self.assertIn("rounds", result)
        self.assertIn("risk_level", result)

    def test_optimizer_history(self):
        from src.optimization.optimizer import AdaptiveOptimizer
        opt = AdaptiveOptimizer()
        opt.update(anomaly_score=0.3)
        opt.update(anomaly_score=0.7)
        history = opt.get_history()
        self.assertGreaterEqual(len(history), 2)

    def test_optimizer_config(self):
        from src.optimization.optimizer import AdaptiveOptimizer
        opt = AdaptiveOptimizer()
        cfg = opt.get_current_config()
        self.assertIn("key_length", cfg)
        self.assertIn("rounds", cfg)

    def test_agent_action(self):
        from src.optimization.environment import EncryptionEnv
        env = EncryptionEnv()
        action = env.action_space.sample()
        kl, rd = env._decode_action(action)
        self.assertIn(kl, [1024, 2048, 4096])
        self.assertIn(rd, [10, 12, 14])


class TestAPI(unittest.TestCase):
    """Flask API测试"""

    @classmethod
    def setUpClass(cls):
        from app import app
        cls.app = app.test_client()

    def test_health(self):
        resp = self.app.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["code"], 200)

    def test_get_stats(self):
        resp = self.app.get("/api/get_stats")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("data", data)
        self.assertIn("total_attacks", data["data"])

    def test_generate_dataset(self):
        resp = self.app.post("/api/generate_dataset",
                             json={"n_records": 10},
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["code"], 200)
        self.assertEqual(len(data["data"]["plaintext"]), 10)
        self.assertEqual(len(data["data"]["encrypted"]), 10)

    def test_compare_encryption(self):
        resp = self.app.post("/api/compare_encryption",
                             json={"data_size_mb": 20},
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("traditional", data["data"])
        self.assertIn("homomorphic", data["data"])

    def test_train_fate(self):
        resp = self.app.post("/api/train_fate", content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(len(data["data"]["history"]), 10)

    def test_federated_submit(self):
        resp = self.app.post("/api/federated/submit",
                             json={"num_rounds": 3},
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("task_id", data["data"])

    def test_optimization_flow(self):
        resp1 = self.app.get("/api/optimization/status")
        self.assertEqual(resp1.status_code, 200)
        resp2 = self.app.post("/api/optimization/update",
                               json={"anomaly_score": 0.5},
                               content_type="application/json")
        self.assertEqual(resp2.status_code, 200)

    def test_frontend(self):
        resp = self.app.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode()
        self.assertIn("Chart", html)
        self.assertIn("glass", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
