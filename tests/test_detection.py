import unittest
import numpy as np
from src.detection.feature_extractor import FeatureExtractor
from src.detection.attack_detector import IsolationForestDetector, HybridAttackDetector

class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_extract_features_dimension(self):
        log_entry = {
            'key_generation_time': 0.1,
            'ciphertext': 'test',
            'hash_collisions': 0,
            'request_frequency': 10.0,
            'response_time': 0.05,
            'payload_size': 100,
            'connection_duration': 5.0,
            'packet_interarrival': 0.1,
            'failed_attempts': 0,
            'session_duration': 100.0,
            'request_size_variance': 50.0,
            'encryption_rounds': 1,
            'decryption_success_rate': 1.0,
            'memory_usage': 0.5,
            'cpu_usage': 0.3,
            'network_latency': 0.01,
            'protocol_violations': 0,
            'anomaly_score': 0.2
        }
        
        features = self.extractor.extract_features(log_entry)
        self.assertEqual(len(features), 18)

    def test_normalize_features(self):
        features = np.array([5.0, 4.0, 50, 500.0, 2.5, 500000, 1800.0, 0.5, 50, 3600.0, 5000.0, 5, 0.5, 0.5, 0.5, 2.5, 5, 0.5])
        normalized = self.extractor.normalize_features(features)
        
        self.assertTrue(np.all(normalized >= 0))
        self.assertTrue(np.all(normalized <= 1))

class TestAttackDetector(unittest.TestCase):
    def setUp(self):
        self.detector = HybridAttackDetector(feature_dim=18)

    def test_isolation_forest_predict(self):
        X = np.random.randn(100, 18)
        self.detector.fit_isolation_forest(X)
        
        X_test = np.random.randn(10, 18)
        predictions, _, _ = self.detector.predict(X_test)
        
        self.assertEqual(len(predictions), 10)
        self.assertTrue(all(p in [0, 1] for p in predictions))

    def test_hybrid_predict(self):
        X = np.random.randn(100, 18)
        X_seq = np.random.randn(50, 10, 18)
        
        self.detector.fit_isolation_forest(X)
        
        y_train = np.random.randint(0, 2, 50)
        self.detector.fit_lstm(X_seq, y_train, epochs=2, batch_size=10)
        
        X_test = np.random.randn(10, 18)
        X_seq_test = np.random.randn(10, 10, 18)
        
        predictions, if_preds, lstm_preds = self.detector.predict(X_test, X_seq_test)
        
        self.assertEqual(len(predictions), 10)
        self.assertEqual(len(if_preds), 10)
        self.assertEqual(len(lstm_preds), 10)

if __name__ == '__main__':
    unittest.main()